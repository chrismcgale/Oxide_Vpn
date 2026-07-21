//! Capstone M2 test, no root: control plane -> server peer reconcile -> real tunnel.
//!
//! 1. Stand up the control plane in-process.
//! 2. Register a VPN server and, under a fresh account, register a client device
//!    (which allocates its tunnel IP).
//! 3. Build a server engine with an empty peer table, then reconcile it from the
//!    control plane's peer list (exactly what `oxide-serverd`'s poll loop does).
//! 4. Build a client engine dialing the server, inject a packet at the client's
//!    tunnel side, and assert it surfaces at the server's — proving the whole M2
//!    path drives a genuine WireGuard tunnel.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use ipnet::IpNet;

use oxide_common::api::PeerEntry;
use oxide_common::keys::{generate_secret, public_from_secret};
use oxide_control_client::ControlClient;
use oxide_control_plane::{add_server, db, serve, AppState, NewServer};
use oxide_wg_core::testutil::{ipv4_packet, MockTun};
use oxide_wg_core::{Engine, PeerParams};

fn temp_db_path() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir()
        .join(format!("oxide-serverd-test-{}-{}.db", std::process::id(), n))
        .to_string_lossy()
        .into_owned()
}

/// Mirrors `oxide-serverd`'s mapping of a control-plane peer entry to engine params.
fn peer_from_entry(e: &PeerEntry) -> PeerParams {
    PeerParams {
        public_key: e.public_key,
        preshared_key: None,
        endpoint: None,
        allowed_ips: e.allowed_ips.iter().filter_map(|s| s.parse().ok()).collect(),
        persistent_keepalive: None,
    }
}

#[tokio::test]
async fn control_plane_provisions_a_working_tunnel() {
    // --- control plane ---
    let pool = db::connect(&temp_db_path()).await.unwrap();
    let server_priv = generate_secret();
    let server_pub = public_from_secret(&server_priv);
    let token = add_server(
        &pool,
        NewServer {
            id: "s1",
            public_key: &server_pub.to_base64(),
            endpoint: "127.0.0.1:51820", // endpoint value is irrelevant in this loopback test
            cidr: "10.8.0.0/24".parse().unwrap(),
            country: None,
            city: None,
            capacity: 0,
            dns: None,
        },
    )
    .await
    .unwrap();

    let state = AppState::new(pool.clone());
    let cp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cp_addr = cp_listener.local_addr().unwrap();
    tokio::spawn(async move { serve(cp_listener, state).await.unwrap() });
    let cc = ControlClient::new(&format!("http://{cp_addr}"));

    // --- account + device registration ---
    let account = cc.create_account().await.unwrap();
    let client_priv = generate_secret();
    let client_pub = public_from_secret(&client_priv);
    let reg = cc.register_device(&account, client_pub, "s1").await.unwrap();

    let assigned: IpNet = reg.assigned_ip.parse().unwrap();
    let IpAddr::V4(assigned_v4) = assigned.addr() else {
        panic!("expected v4")
    };
    let server_tunnel_v4: Ipv4Addr = reg.server.tunnel_ip.parse().unwrap();

    // --- server engine, reconciled from the control plane ---
    let server_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_udp.local_addr().unwrap();
    let (server_tun, _srv_inject, mut srv_capture) = MockTun::pair();
    let server_engine = Engine::build(&server_priv, vec![], server_udp, server_tun);
    let handle = server_engine.handle();
    tokio::spawn(server_engine.run());

    let peers = cc.fetch_peers("s1", &token).await.unwrap();
    handle.reconcile(peers.iter().map(peer_from_entry).collect());

    // --- client engine dialing the server ---
    let client_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (client_tun, client_inject, _cli_capture) = MockTun::pair();
    let client_engine = Engine::build(
        &client_priv,
        vec![PeerParams {
            public_key: server_pub,
            preshared_key: None,
            endpoint: Some(server_addr),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            persistent_keepalive: Some(5),
        }],
        client_udp,
        client_tun,
    );
    tokio::spawn(client_engine.run());

    // Inject a packet from the client's assigned IP to the server's tunnel IP.
    let packet = ipv4_packet(assigned_v4, server_tunnel_v4, b"m2 end to end");
    client_inject.send(packet.clone()).unwrap();

    let received = tokio::time::timeout(Duration::from_secs(10), srv_capture.recv())
        .await
        .expect("timed out; control-plane-provisioned tunnel never carried the packet")
        .expect("server tun channel closed");
    assert_eq!(received, packet);
}
