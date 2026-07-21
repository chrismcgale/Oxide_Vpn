//! Capstone: two of a user's own devices form a private mesh and talk directly.
//!
//! Both devices register into the account's mesh (reporting where they're reachable),
//! each gets a stable mesh IP, and each fetches the peer list. They configure each other
//! as WireGuard peers (allowed_ips = the other's mesh /32) and a packet flows directly
//! between them over the mesh — no VPN server, no exit. This is the "Tailscale, but
//! actually private" half of the hybrid, driven entirely by the control plane. No root.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use ipnet::IpNet;

use oxide_common::keys::{generate_secret, public_from_secret};
use oxide_control_client::ControlClient;
use oxide_control_plane::{db, serve, AppState};
use oxide_wg_core::testutil::{ipv4_packet, MockTun};
use oxide_wg_core::{Engine, PeerParams, Transport};

fn temp_db_path() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir()
        .join(format!("oxide-mesh-test-{}-{}.db", std::process::id(), n))
        .to_string_lossy()
        .into_owned()
}

fn mesh_host(ip_with_prefix_or_host: &str) -> Ipv4Addr {
    // Accepts "100.64.0.1/16" or "100.64.0.1".
    let s = ip_with_prefix_or_host
        .split('/')
        .next()
        .unwrap_or(ip_with_prefix_or_host);
    s.parse().unwrap()
}

#[tokio::test]
async fn two_devices_mesh_directly() {
    let pool = db::connect(&temp_db_path()).await.unwrap();
    let state = AppState::new(pool.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cp_addr = listener.local_addr().unwrap();
    tokio::spawn(async move { serve(listener, state).await.unwrap() });
    let cc = ControlClient::new(&format!("http://{cp_addr}"));

    let account = cc.create_account().await.unwrap();

    // Two devices, each with a WireGuard key and a reachable UDP endpoint.
    let a_priv = generate_secret();
    let a_pub = public_from_secret(&a_priv);
    let a_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a_udp.local_addr().unwrap();

    let b_priv = generate_secret();
    let b_pub = public_from_secret(&b_priv);
    let b_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b_addr = b_udp.local_addr().unwrap();

    // Both join the mesh.
    let a_reg = cc
        .mesh_register(&account, a_pub, &a_addr.to_string())
        .await
        .unwrap();
    let b_reg = cc
        .mesh_register(&account, b_pub, &b_addr.to_string())
        .await
        .unwrap();
    let a_mesh = mesh_host(&a_reg.mesh_ip);
    let b_mesh = mesh_host(&b_reg.mesh_ip);
    assert_ne!(a_mesh, b_mesh);

    // A discovers B from the mesh peer list.
    let peers = cc.mesh_list(&account).await.unwrap();
    let b_peer = peers.iter().find(|p| p.public_key == b_pub).unwrap();
    let b_peer_ip = mesh_host(&b_peer.mesh_ip);
    let b_peer_endpoint: SocketAddr = b_peer.endpoint.parse().unwrap();
    assert_eq!(b_peer_ip, b_mesh);
    assert_eq!(b_peer_endpoint, b_addr);

    // Build both engines, each with the other as a mesh peer (allowed_ips = mesh /32).
    let (a_tun, a_inject, _a_cap) = MockTun::pair();
    let a_engine = Engine::build(
        &a_priv,
        vec![PeerParams {
            public_key: b_pub,
            preshared_key: None,
            endpoint: Some(b_addr),
            allowed_ips: vec![format!("{b_mesh}/32").parse().unwrap()],
            persistent_keepalive: Some(5),
        }],
        Transport::plain(a_udp),
        a_tun,
    );

    let (b_tun, _b_inject, mut b_cap) = MockTun::pair();
    let b_engine = Engine::build(
        &b_priv,
        vec![PeerParams {
            public_key: a_pub,
            preshared_key: None,
            endpoint: Some(a_addr),
            allowed_ips: vec![format!("{a_mesh}/32").parse().unwrap()],
            persistent_keepalive: Some(5),
        }],
        Transport::plain(b_udp),
        b_tun,
    );

    tokio::spawn(a_engine.run());
    tokio::spawn(b_engine.run());

    // A sends a packet to B's mesh IP; it must arrive at B directly.
    let packet = ipv4_packet(a_mesh, b_mesh, b"hello over the private mesh");
    a_inject.send(packet.clone()).unwrap();

    let received = tokio::time::timeout(Duration::from_secs(10), b_cap.recv())
        .await
        .expect("timed out; mesh peers never connected")
        .expect("mesh tun channel closed");
    assert_eq!(received, packet);

    // Sanity: mesh IPs are in the 100.64.0.0/16 CGNAT range.
    let mesh_net: IpNet = "100.64.0.0/16".parse().unwrap();
    assert!(mesh_net.contains(&IpAddr::V4(a_mesh)));
    assert!(mesh_net.contains(&IpAddr::V4(b_mesh)));
}
