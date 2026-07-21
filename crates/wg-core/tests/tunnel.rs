//! End-to-end tunnel test with no root and no TUN device.
//!
//! Two `Engine`s (a "server" and a "client") talk to each other over loopback UDP,
//! each backed by an in-memory `MockTun` instead of a real `/dev/net/tun`. We inject a
//! plaintext IP packet at the client's tunnel side and assert it comes out — byte for
//! byte — at the server's tunnel side. This drives the real boringtun handshake,
//! ChaCha20-Poly1305 encapsulation, and allowed-IPs routing entirely in userspace.

use std::future::pending;
use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex;

use oxide_common::keys::{generate_secret, public_from_secret};
use oxide_common::TunQueue;
use oxide_wg_core::{Engine, MimicTransport, PeerParams, Transport};

/// In-memory stand-in for a TUN device. `recv` yields packets the test injected
/// (as if the OS wanted to send them out); `send` captures packets the engine wrote
/// (decapsulated inbound traffic).
struct MockTun {
    inject: Mutex<UnboundedReceiver<Vec<u8>>>,
    capture: UnboundedSender<Vec<u8>>,
}

impl MockTun {
    fn pair() -> (Self, UnboundedSender<Vec<u8>>, UnboundedReceiver<Vec<u8>>) {
        let (inject_tx, inject_rx) = unbounded_channel();
        let (capture_tx, capture_rx) = unbounded_channel();
        (
            MockTun {
                inject: Mutex::new(inject_rx),
                capture: capture_tx,
            },
            inject_tx,
            capture_rx,
        )
    }
}

impl TunQueue for MockTun {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rx = self.inject.lock().await;
        match rx.recv().await {
            Some(pkt) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            }
            // Channel closed: never yield again (returning Ok(0) would busy-loop).
            None => pending().await,
        }
    }

    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let _ = self.capture.send(buf.to_vec());
        Ok(buf.len())
    }
}

/// Build a minimal 20-byte IPv4 header + payload so `Tunn::dst_address` can route it
/// and boringtun's inbound source check can read the source address.
fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total_len = (20 + payload.len()) as u16;
    let mut p = vec![0u8; 20 + payload.len()];
    p[0] = 0x45; // version 4, IHL 5
    p[2..4].copy_from_slice(&total_len.to_be_bytes());
    p[8] = 64; // TTL
    p[9] = 17; // protocol UDP (arbitrary; not validated here)
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20..].copy_from_slice(payload);
    p
}

#[tokio::test]
async fn tunnel_carries_a_packet_end_to_end() {
    let server_priv = generate_secret();
    let server_pub = public_from_secret(&server_priv);
    let client_priv = generate_secret();
    let client_pub = public_from_secret(&client_priv);

    // Loopback UDP sockets; the client dials the server's actual bound port.
    let server_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_udp.local_addr().unwrap();
    let client_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Server: knows the client only by key + allowed_ips; endpoint is learned.
    let (server_tun, _srv_inject, mut srv_capture) = MockTun::pair();
    let server = Engine::build(
        &server_priv,
        vec![PeerParams {
            public_key: client_pub,
            preshared_key: None,
            endpoint: None,
            allowed_ips: vec!["10.8.0.2/32".parse().unwrap()],
            persistent_keepalive: None,
        }],
        Transport::plain(server_udp),
        server_tun,
    );

    // Client: dials the server, routes the tunnel subnet to it.
    let (client_tun, client_inject, _cli_capture) = MockTun::pair();
    let client = Engine::build(
        &client_priv,
        vec![PeerParams {
            public_key: server_pub,
            preshared_key: None,
            endpoint: Some(server_addr),
            allowed_ips: vec!["10.8.0.0/24".parse().unwrap()],
            persistent_keepalive: Some(5),
        }],
        Transport::plain(client_udp),
        client_tun,
    );

    tokio::spawn(server.run());
    tokio::spawn(client.run());

    // Inject a packet at the client's tunnel side, destined for the server tunnel IP.
    let payload = b"oxide tunnel works";
    let packet = ipv4_packet(
        Ipv4Addr::new(10, 8, 0, 2),
        Ipv4Addr::new(10, 8, 0, 1),
        payload,
    );
    client_inject.send(packet.clone()).unwrap();

    // It should surface at the server's tunnel side after the handshake completes.
    let received = tokio::time::timeout(Duration::from_secs(10), srv_capture.recv())
        .await
        .expect("timed out waiting for packet across tunnel")
        .expect("server tun channel closed");

    assert_eq!(
        received, packet,
        "packet must traverse the tunnel unchanged"
    );
}

#[tokio::test]
async fn tunnel_works_over_obfuscated_transport() {
    // Stealth mode: same real WireGuard handshake + data path, but both ends wrap their
    // datagrams in the obfuscation layer with a shared key. On the wire there is no
    // WireGuard fingerprint at all.
    let obfs_key = [0x5a; 32];
    let server_priv = generate_secret();
    let server_pub = public_from_secret(&server_priv);
    let client_priv = generate_secret();
    let client_pub = public_from_secret(&client_priv);

    let server_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_udp.local_addr().unwrap();
    let client_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let (server_tun, _srv_inject, mut srv_capture) = MockTun::pair();
    let server = Engine::build(
        &server_priv,
        vec![PeerParams {
            public_key: client_pub,
            preshared_key: None,
            endpoint: None,
            allowed_ips: vec!["10.8.0.2/32".parse().unwrap()],
            persistent_keepalive: None,
        }],
        Transport::obfuscated(server_udp, obfs_key),
        server_tun,
    );

    let (client_tun, client_inject, _cli_capture) = MockTun::pair();
    let client = Engine::build(
        &client_priv,
        vec![PeerParams {
            public_key: server_pub,
            preshared_key: None,
            endpoint: Some(server_addr),
            allowed_ips: vec!["10.8.0.0/24".parse().unwrap()],
            persistent_keepalive: Some(5),
        }],
        Transport::obfuscated(client_udp, obfs_key),
        client_tun,
    );

    tokio::spawn(server.run());
    tokio::spawn(client.run());

    let packet = ipv4_packet(
        Ipv4Addr::new(10, 8, 0, 2),
        Ipv4Addr::new(10, 8, 0, 1),
        b"stealth tunnel works",
    );
    client_inject.send(packet.clone()).unwrap();

    let received = tokio::time::timeout(Duration::from_secs(10), srv_capture.recv())
        .await
        .expect("timed out; obfuscated tunnel never delivered")
        .expect("server tun channel closed");
    assert_eq!(received, packet);
}

#[tokio::test]
async fn tunnel_secured_by_post_quantum_psk() {
    // Post-quantum hybrid: an ML-KEM exchange derives a shared secret that both ends use
    // as the WireGuard preshared key, layered on top of x25519. The tunnel must come up
    // with the PQ-derived PSK on both sides (a mismatch would fail the handshake).
    let (server_seed, server_pub_pq) = oxide_pq::generate();
    let (ciphertext, client_shared) = oxide_pq::encapsulate(&server_pub_pq).unwrap();
    let server_shared = oxide_pq::decapsulate(&server_seed, &ciphertext).unwrap();
    assert_eq!(client_shared, server_shared, "KEM secrets must agree");
    let psk = client_shared; // 32 bytes -> WireGuard PSK slot

    let server_priv = generate_secret();
    let server_pub = public_from_secret(&server_priv);
    let client_priv = generate_secret();
    let client_pub = public_from_secret(&client_priv);

    let server_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_udp.local_addr().unwrap();
    let client_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let (server_tun, _srv_inject, mut srv_capture) = MockTun::pair();
    let server = Engine::build(
        &server_priv,
        vec![PeerParams {
            public_key: client_pub,
            preshared_key: Some(psk),
            endpoint: None,
            allowed_ips: vec!["10.8.0.2/32".parse().unwrap()],
            persistent_keepalive: None,
        }],
        Transport::plain(server_udp),
        server_tun,
    );

    let (client_tun, client_inject, _cli_capture) = MockTun::pair();
    let client = Engine::build(
        &client_priv,
        vec![PeerParams {
            public_key: server_pub,
            preshared_key: Some(psk),
            endpoint: Some(server_addr),
            allowed_ips: vec!["10.8.0.0/24".parse().unwrap()],
            persistent_keepalive: Some(5),
        }],
        Transport::plain(client_udp),
        client_tun,
    );

    tokio::spawn(server.run());
    tokio::spawn(client.run());

    let packet = ipv4_packet(
        Ipv4Addr::new(10, 8, 0, 2),
        Ipv4Addr::new(10, 8, 0, 1),
        b"post-quantum tunnel works",
    );
    client_inject.send(packet.clone()).unwrap();

    let received = tokio::time::timeout(Duration::from_secs(10), srv_capture.recv())
        .await
        .expect("timed out; PQ-PSK tunnel never delivered")
        .expect("server tun channel closed");
    assert_eq!(received, packet);
}

#[tokio::test]
async fn tunnel_works_over_tls_mimicry() {
    // Protocol mimicry (stealth tier 2): the same real WireGuard handshake + data path,
    // but carried over a TCP flow that looks like a TLS/HTTPS session. On the wire a
    // censor sees a ClientHello with an SNI, a ServerHello, and application_data records.
    let key = [0x33u8; 32];
    let server_priv = generate_secret();
    let server_pub = public_from_secret(&server_priv);
    let client_priv = generate_secret();
    let client_pub = public_from_secret(&client_priv);

    // Server listens (mimic TLS); client connects to its address.
    let server_mimic = MimicTransport::bind("127.0.0.1:0".parse().unwrap(), key)
        .await
        .unwrap();
    let server_addr = server_mimic.local_addr().unwrap();
    let client_mimic = MimicTransport::connect(server_addr, key).await.unwrap();

    let (server_tun, _srv_inject, mut srv_capture) = MockTun::pair();
    let server = Engine::build(
        &server_priv,
        vec![PeerParams {
            public_key: client_pub,
            preshared_key: None,
            endpoint: None,
            allowed_ips: vec!["10.8.0.2/32".parse().unwrap()],
            persistent_keepalive: None,
        }],
        Transport::mimic(server_mimic),
        server_tun,
    );

    let (client_tun, client_inject, _cli_capture) = MockTun::pair();
    let client = Engine::build(
        &client_priv,
        vec![PeerParams {
            public_key: server_pub,
            preshared_key: None,
            endpoint: Some(server_addr),
            allowed_ips: vec!["10.8.0.0/24".parse().unwrap()],
            persistent_keepalive: Some(5),
        }],
        Transport::mimic(client_mimic),
        client_tun,
    );

    tokio::spawn(server.run());
    tokio::spawn(client.run());

    let packet = ipv4_packet(
        Ipv4Addr::new(10, 8, 0, 2),
        Ipv4Addr::new(10, 8, 0, 1),
        b"tunnel disguised as https",
    );
    client_inject.send(packet.clone()).unwrap();

    let received = tokio::time::timeout(Duration::from_secs(10), srv_capture.recv())
        .await
        .expect("timed out; TLS-mimicry tunnel never delivered")
        .expect("server tun channel closed");
    assert_eq!(received, packet);
}

#[tokio::test]
async fn tunnel_works_over_quic_mimicry() {
    // QUIC mimicry (UDP-native, no TCP-over-TCP): the same real WireGuard tunnel, but on
    // the wire it looks like an HTTP/3 (QUIC) session — a long-header Initial with an
    // embedded ClientHello, then short-header packets.
    let key = [0x44u8; 32];
    let server_priv = generate_secret();
    let server_pub = public_from_secret(&server_priv);
    let client_priv = generate_secret();
    let client_pub = public_from_secret(&client_priv);

    let server_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_udp.local_addr().unwrap();
    let client_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let (server_tun, _srv_inject, mut srv_capture) = MockTun::pair();
    let server = Engine::build(
        &server_priv,
        vec![PeerParams {
            public_key: client_pub,
            preshared_key: None,
            endpoint: None,
            allowed_ips: vec!["10.8.0.2/32".parse().unwrap()],
            persistent_keepalive: None,
        }],
        Transport::quic_mimic(server_udp, key),
        server_tun,
    );

    let (client_tun, client_inject, _cli_capture) = MockTun::pair();
    let client = Engine::build(
        &client_priv,
        vec![PeerParams {
            public_key: server_pub,
            preshared_key: None,
            endpoint: Some(server_addr),
            allowed_ips: vec!["10.8.0.0/24".parse().unwrap()],
            persistent_keepalive: Some(5),
        }],
        Transport::quic_mimic(client_udp, key),
        client_tun,
    );

    tokio::spawn(server.run());
    tokio::spawn(client.run());

    let packet = ipv4_packet(
        Ipv4Addr::new(10, 8, 0, 2),
        Ipv4Addr::new(10, 8, 0, 1),
        b"tunnel disguised as http3",
    );
    client_inject.send(packet.clone()).unwrap();

    let received = tokio::time::timeout(Duration::from_secs(10), srv_capture.recv())
        .await
        .expect("timed out; QUIC-mimicry tunnel never delivered")
        .expect("server tun channel closed");
    assert_eq!(received, packet);
}

#[tokio::test]
async fn peer_added_at_runtime_comes_up() {
    // Same as above, but the server starts with NO peers and the client is added
    // live through the EngineHandle after the engine is already running — the path
    // the control plane uses when a device registers.
    let server_priv = generate_secret();
    let server_pub = public_from_secret(&server_priv);
    let client_priv = generate_secret();
    let client_pub = public_from_secret(&client_priv);

    let server_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_udp.local_addr().unwrap();
    let client_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Use the rate-limited server constructor so the DoS RateLimiter path is exercised;
    // a normal handshake must still complete under it.
    let (server_tun, _srv_inject, mut srv_capture) = MockTun::pair();
    let server = Engine::build_server(
        &server_priv,
        vec![],
        Transport::plain(server_udp),
        server_tun,
        100,
    );
    let server_handle = server.handle();

    let (client_tun, client_inject, _cli_capture) = MockTun::pair();
    let client = Engine::build(
        &client_priv,
        vec![PeerParams {
            public_key: server_pub,
            preshared_key: None,
            endpoint: Some(server_addr),
            allowed_ips: vec!["10.8.0.0/24".parse().unwrap()],
            persistent_keepalive: Some(5),
        }],
        Transport::plain(client_udp),
        client_tun,
    );

    tokio::spawn(server.run());
    tokio::spawn(client.run());

    // Register the client on the running server, as the control plane would.
    server_handle.add_peer(PeerParams {
        public_key: client_pub,
        preshared_key: None,
        endpoint: None,
        allowed_ips: vec!["10.8.0.2/32".parse().unwrap()],
        persistent_keepalive: None,
    });

    let packet = ipv4_packet(
        Ipv4Addr::new(10, 8, 0, 2),
        Ipv4Addr::new(10, 8, 0, 1),
        b"added at runtime",
    );
    client_inject.send(packet.clone()).unwrap();

    let received = tokio::time::timeout(Duration::from_secs(10), srv_capture.recv())
        .await
        .expect("timed out; runtime-added peer never came up")
        .expect("server tun channel closed");

    assert_eq!(received, packet);

    // The server should now report one live peer (used for load-based selection) and
    // non-zero throughput (used for the client agent/TUI status).
    let stats = server_handle.stats();
    assert_eq!(stats.total_peers, 1);
    assert_eq!(stats.active_peers, 1);
    assert!(stats.tx_bytes > 0 || stats.rx_bytes > 0);
}
