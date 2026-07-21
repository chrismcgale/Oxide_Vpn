//! Capstone multihop test, no root: client -> entry relay -> exit engine, real tunnel.
//!
//! Proves the Mullvad-style design end to end: the client runs ONE WireGuard session
//! keyed to the EXIT, but sends ciphertext to the ENTRY's relay endpoint (as the control
//! plane instructs). The relay forwards to the exit, which decrypts and delivers the
//! packet to its tunnel. The entry only ever sees ciphertext it can't read.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use ipnet::IpNet;

use oxide_common::keys::{generate_secret, public_from_secret};
use oxide_control_client::ControlClient;
use oxide_control_plane::{add_server, db, serve, AppState, NewServer};
use oxide_relay::Relay;
use oxide_wg_core::testutil::{ipv4_packet, MockTun};
use oxide_wg_core::{Engine, PeerParams};

fn temp_db_path() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir()
        .join(format!("oxide-mh-test-{}-{}.db", std::process::id(), n))
        .to_string_lossy()
        .into_owned()
}

#[tokio::test]
async fn multihop_client_relay_exit_carries_a_packet() {
    // Exit engine's UDP socket first, so we can advertise its address as the exit endpoint.
    let exit_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let exit_addr = exit_udp.local_addr().unwrap();

    // --- control plane: register exit + entry servers ---
    let pool = db::connect(&temp_db_path()).await.unwrap();
    let exit_priv = generate_secret();
    let exit_pub = public_from_secret(&exit_priv);
    let exit_token = add_server(
        &pool,
        NewServer {
            id: "exit",
            public_key: &exit_pub.to_base64(),
            endpoint: &exit_addr.to_string(), // relay forwards here
            cidr: "10.8.0.0/24".parse().unwrap(),
            country: Some("SE"),
            city: None,
            capacity: 0,
            dns: None,
        },
    )
    .await
    .unwrap();
    // Entry: only its host is used (for the relay endpoint returned to the client).
    add_server(
        &pool,
        NewServer {
            id: "entry",
            public_key: &public_from_secret(&generate_secret()).to_base64(),
            endpoint: "127.0.0.1:1",
            cidr: "10.9.0.0/24".parse().unwrap(),
            country: Some("DE"),
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

    // --- client registers for a multihop path (entry -> exit) ---
    let account = cc.create_account().await.unwrap();
    let client_priv = generate_secret();
    let client_pub = public_from_secret(&client_priv);
    let reg = cc
        .register_device_multihop(&account, client_pub, "entry", "exit")
        .await
        .unwrap();

    // The connection is exit-keyed but points at the entry's relay.
    assert_eq!(reg.server.public_key, exit_pub);
    let relay_endpoint: SocketAddr = reg.server.endpoint.parse().unwrap();
    let assigned: IpNet = reg.assigned_ip.parse().unwrap();
    let IpAddr::V4(assigned_v4) = assigned.addr() else {
        panic!("v4")
    };
    let exit_tunnel_v4: Ipv4Addr = reg.server.tunnel_ip.parse().unwrap();

    // --- exit engine, reconciled from the control plane ---
    let (exit_tun, _exit_inject, mut exit_capture) = MockTun::pair();
    let exit_engine = Engine::build(&exit_priv, vec![], exit_udp, exit_tun);
    let exit_handle = exit_engine.handle();
    tokio::spawn(exit_engine.run());
    let peers = cc.fetch_peers("exit", &exit_token).await.unwrap();
    exit_handle.reconcile(
        peers
            .iter()
            .map(|e| PeerParams {
                public_key: e.public_key,
                preshared_key: None,
                endpoint: None,
                allowed_ips: e
                    .allowed_ips
                    .iter()
                    .filter_map(|s| s.parse().ok())
                    .collect(),
                persistent_keepalive: None,
            })
            .collect(),
    );

    // --- entry relay: listen on the assigned relay port, forward to the exit ---
    let relay = Relay::bind(("127.0.0.1", relay_endpoint.port()), exit_addr)
        .await
        .unwrap();
    tokio::spawn(relay.run());

    // --- client engine: exit-keyed session, sent to the relay endpoint ---
    let client_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (client_tun, client_inject, _client_capture) = MockTun::pair();
    let client_engine = Engine::build(
        &client_priv,
        vec![PeerParams {
            public_key: exit_pub,
            preshared_key: None,
            endpoint: Some(relay_endpoint),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            persistent_keepalive: Some(5),
        }],
        client_udp,
        client_tun,
    );
    tokio::spawn(client_engine.run());

    // Inject a packet from the client's assigned IP to the exit's tunnel IP.
    let packet = ipv4_packet(assigned_v4, exit_tunnel_v4, b"multihop end to end");
    client_inject.send(packet.clone()).unwrap();

    let received = tokio::time::timeout(Duration::from_secs(10), exit_capture.recv())
        .await
        .expect("timed out; multihop tunnel (client->relay->exit) never delivered")
        .expect("exit tun channel closed");
    assert_eq!(received, packet);
}
