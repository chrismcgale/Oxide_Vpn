//! Capstone: post-quantum handshake negotiated through the control plane.
//!
//! The server publishes an ML-KEM public key. The client fetches it, encapsulates to it
//! (getting a shared secret + ciphertext), sends the ciphertext at registration, and
//! uses the secret as its WireGuard PSK. The server pulls the ciphertext from its peer
//! list and decapsulates it with its private seed, recovering the same PSK. A real
//! WireGuard tunnel then comes up secured by the PQ-derived PSK on both sides — all
//! driven through the control plane, no root.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ipnet::IpNet;

use oxide_common::keys::{generate_secret, public_from_secret};
use oxide_control_client::ControlClient;
use oxide_control_plane::{add_server, db, serve, AppState, NewServer};
use oxide_wg_core::testutil::{ipv4_packet, MockTun};
use oxide_wg_core::{Engine, PeerParams, Transport};

fn temp_db_path() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir()
        .join(format!("oxide-pq-test-{}-{}.db", std::process::id(), n))
        .to_string_lossy()
        .into_owned()
}

#[tokio::test]
async fn post_quantum_negotiated_through_control_plane() {
    // Server UDP first so we can advertise its address.
    let server_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_udp.local_addr().unwrap();

    // Server keys: classical WireGuard + post-quantum ML-KEM.
    let server_priv = generate_secret();
    let server_pub = public_from_secret(&server_priv);
    let (pq_seed, pq_public) = oxide_pq::generate();
    let pq_public_b64 = B64.encode(&pq_public);

    // Control plane: register the server with its PQ public key.
    let pool = db::connect(&temp_db_path()).await.unwrap();
    let server_token = add_server(
        &pool,
        NewServer {
            id: "s1",
            public_key: &server_pub.to_base64(),
            endpoint: &server_addr.to_string(),
            cidr: "10.8.0.0/24".parse().unwrap(),
            country: None,
            city: None,
            capacity: 0,
            dns: None,
            obfuscation_key: None,
            pq_public_key: Some(&pq_public_b64),
            transport: None,
            daita: false,
        },
    )
    .await
    .unwrap();

    let state = AppState::new(pool.clone());
    let cp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cp_addr = cp_listener.local_addr().unwrap();
    tokio::spawn(async move { serve(cp_listener, state).await.unwrap() });
    let cc = ControlClient::new(&format!("http://{cp_addr}"));

    // Client: fetch the server, encapsulate to its PQ public key.
    let account = cc.create_account().await.unwrap();
    let servers = cc.list_servers(&account).await.unwrap();
    let pq_pub_bytes = B64
        .decode(servers[0].pq_public_key.as_ref().unwrap())
        .unwrap();
    let (ciphertext, client_psk) = oxide_pq::encapsulate(&pq_pub_bytes).unwrap();

    let client_priv = generate_secret();
    let client_pub = public_from_secret(&client_priv);
    let reg = cc
        .register_device(&account, client_pub, "s1", Some(&B64.encode(&ciphertext)))
        .await
        .unwrap();

    // Server: pull the ciphertext from the peer list and decapsulate to the same PSK.
    let peers = cc.fetch_peers("s1", &server_token).await.unwrap();
    let ct = B64
        .decode(peers[0].pq_ciphertext.as_ref().unwrap())
        .unwrap();
    let server_psk = oxide_pq::decapsulate(&pq_seed, &ct).unwrap();
    assert_eq!(
        client_psk, server_psk,
        "PQ secrets must agree via the control plane"
    );

    // Build both engines using the PQ-derived PSK and run a real tunnel.
    let assigned: IpNet = reg.assigned_ip.parse().unwrap();
    let IpAddr::V4(assigned_v4) = assigned.addr() else {
        panic!("v4")
    };
    let server_tunnel_v4: Ipv4Addr = reg.server.tunnel_ip.parse().unwrap();

    let (server_tun, _srv_inject, mut srv_capture) = MockTun::pair();
    let server = Engine::build(
        &server_priv,
        vec![PeerParams {
            public_key: client_pub,
            preshared_key: Some(server_psk),
            endpoint: None,
            allowed_ips: vec![format!("{assigned_v4}/32").parse().unwrap()],
            persistent_keepalive: None,
        }],
        Transport::plain(server_udp),
        server_tun,
    );

    let client_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (client_tun, client_inject, _cli_capture) = MockTun::pair();
    let client = Engine::build(
        &client_priv,
        vec![PeerParams {
            public_key: server_pub,
            preshared_key: Some(client_psk),
            endpoint: Some(server_addr),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            persistent_keepalive: Some(5),
        }],
        Transport::plain(client_udp),
        client_tun,
    );

    tokio::spawn(server.run());
    tokio::spawn(client.run());

    let packet = ipv4_packet(
        assigned_v4,
        server_tunnel_v4,
        b"post-quantum via control plane",
    );
    client_inject.send(packet.clone()).unwrap();

    let received = tokio::time::timeout(Duration::from_secs(10), srv_capture.recv())
        .await
        .expect("timed out; PQ-through-control-plane tunnel never delivered")
        .expect("server tun channel closed");
    assert_eq!(received, packet);
}
