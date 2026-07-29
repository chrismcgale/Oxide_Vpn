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
use oxide_wg_core::{Daita, Engine, MimicTransport, PeerParams, Transport};

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
async fn tunnel_works_with_daita_shaping() {
    // DAITA (traffic-analysis defence): the same real WireGuard tunnel, but the client
    // shapes its egress into a constant-rate stream of fixed-size cells (cover cells fill
    // idle slots) carried inside the obfs frame. The server speaks the cell framing and
    // drops cover before boringtun. We assert (1) a real packet still crosses, and (2)
    // once it has, the steady cover stream does NOT leak anything to the server's tunnel.
    let obfs_key = [0x7c; 32];
    let cell_size = oxide_daita::DEFAULT_CELL_SIZE;
    let slot = Duration::from_millis(2); // fast cadence so the handshake completes quickly

    let server_priv = generate_secret();
    let server_pub = public_from_secret(&server_priv);
    let client_priv = generate_secret();
    let client_pub = public_from_secret(&client_priv);

    let server_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_udp.local_addr().unwrap();
    let client_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Server: obfs transport + DAITA framing (wrap cells, drop inbound cover).
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
    )
    .with_daita(Daita::framing(cell_size));

    // Client: obfs transport + DAITA shaping (constant-rate cells + cover).
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
    )
    .with_daita(Daita::shaping(cell_size, slot));

    tokio::spawn(server.run());
    tokio::spawn(client.run());

    let packet = ipv4_packet(
        Ipv4Addr::new(10, 8, 0, 2),
        Ipv4Addr::new(10, 8, 0, 1),
        b"shaped tunnel works",
    );
    client_inject.send(packet.clone()).unwrap();

    let received = tokio::time::timeout(Duration::from_secs(10), srv_capture.recv())
        .await
        .expect("timed out; DAITA-shaped tunnel never delivered")
        .expect("server tun channel closed");
    assert_eq!(received, packet);

    // The client keeps emitting cover cells every slot even with no more real traffic.
    // The server must recognize and drop them before boringtun, so nothing further should
    // reach its tunnel side within a window spanning many cover cells.
    let leaked = tokio::time::timeout(Duration::from_millis(300), srv_capture.recv()).await;
    assert!(
        leaked.is_err(),
        "cover cells must be dropped, not surface on the server's tunnel"
    );
}

#[tokio::test]
async fn daita_counts_cover_and_real() {
    // The runtime DAITA counters (EngineStats) reflect the defence actually running: the
    // shaping client emits cover cells on idle slots and a real cell for a datagram, and the
    // framing server drops the client's inbound cover cells.
    let obfs_key = [0x3a; 32];
    let cell_size = oxide_daita::DEFAULT_CELL_SIZE;
    let slot = Duration::from_millis(2);

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
    )
    .with_daita(Daita::framing(cell_size));

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
    )
    .with_daita(Daita::shaping(cell_size, slot));

    // Grab handles BEFORE run() consumes the engines.
    let server_handle = server.handle();
    let client_handle = client.handle();
    tokio::spawn(server.run());
    tokio::spawn(client.run());

    // Drive one real datagram through so a real cell is emitted, then let cover accrue.
    let packet = ipv4_packet(
        Ipv4Addr::new(10, 8, 0, 2),
        Ipv4Addr::new(10, 8, 0, 1),
        b"counted",
    );
    client_inject.send(packet.clone()).unwrap();
    let received = tokio::time::timeout(Duration::from_secs(10), srv_capture.recv())
        .await
        .expect("timed out; DAITA tunnel never delivered")
        .expect("server tun channel closed");
    assert_eq!(received, packet);

    // Let many cover slots elapse (slot = 2ms).
    tokio::time::sleep(Duration::from_millis(200)).await;

    let cs = client_handle.stats();
    assert!(
        cs.daita_tx_real >= 1,
        "client should have emitted a real cell"
    );
    assert!(
        cs.daita_tx_cover > 0,
        "idle shaping client should emit cover cells"
    );

    let ss = server_handle.stats();
    assert!(
        ss.daita_rx_cover_dropped > 0,
        "framing server should drop the client's inbound cover cells"
    );
}

#[tokio::test]
async fn daita_shapes_bidirectionally() {
    // Bidirectional 4A: BOTH ends shape. The server no longer merely frames replies — it
    // generates its own paced cover toward each client, so server→client is protected too.
    // We assert (1) a server→client real packet still crosses the shaped path, (2) the server
    // emits its own cover cells, and (3) the client drops the server's inbound cover.
    let obfs_key = [0x5e; 32];
    let cell_size = oxide_daita::DEFAULT_CELL_SIZE;
    let slot = Duration::from_millis(2);

    let server_priv = generate_secret();
    let server_pub = public_from_secret(&server_priv);
    let client_priv = generate_secret();
    let client_pub = public_from_secret(&client_priv);

    let server_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_udp.local_addr().unwrap();
    let client_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Server ALSO shapes now (was framing-only).
    let (server_tun, srv_inject, _srv_capture) = MockTun::pair();
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
    )
    .with_daita(Daita::shaping(cell_size, slot));

    let (client_tun, client_inject, mut cli_capture) = MockTun::pair();
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
    )
    .with_daita(Daita::shaping(cell_size, slot));

    let server_handle = server.handle();
    let client_handle = client.handle();
    tokio::spawn(server.run());
    tokio::spawn(client.run());

    // Bring the tunnel up client→server first so the server learns the client's endpoint,
    // then send a real packet server→client and require it over the shaped path.
    let up = ipv4_packet(
        Ipv4Addr::new(10, 8, 0, 2),
        Ipv4Addr::new(10, 8, 0, 1),
        b"up",
    );
    client_inject.send(up).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let down = ipv4_packet(
        Ipv4Addr::new(10, 8, 0, 1),
        Ipv4Addr::new(10, 8, 0, 2),
        b"down over the shaped path",
    );
    srv_inject.send(down.clone()).unwrap();
    let received = tokio::time::timeout(Duration::from_secs(10), cli_capture.recv())
        .await
        .expect("timed out; server→client shaped path never delivered")
        .expect("client tun channel closed");
    assert_eq!(received, down);

    // Let cover accrue both ways.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let ss = server_handle.stats();
    assert!(
        ss.daita_tx_cover > 0,
        "server should emit its OWN cover cells (bidirectional shaping)"
    );
    assert!(
        ss.daita_tx_real >= 1,
        "server should have emitted a real cell for the down packet"
    );

    let cs = client_handle.stats();
    assert!(
        cs.daita_rx_cover_dropped > 0,
        "shaping client should drop the server's inbound cover cells"
    );
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

/// 2E: a busy server must resolve an established session's data packets by receiver
/// index — a direct lookup — instead of trying every peer per datagram. We stand up a
/// real tunnel, pad the server with many decoy peers so a full scan would be expensive,
/// then assert that steady-state traffic costs ~one decapsulate attempt per packet.
#[tokio::test]
async fn established_session_routes_by_index_without_scanning_all_peers() {
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
        Transport::plain(server_udp),
        server_tun,
    );
    let server_handle = server.handle();

    // Pad the server with decoy peers (distinct keys + allowed_ips). A pre-2E full scan
    // would try these before the real peer on every datagram; index routing never does.
    const DECOYS: usize = 40;
    for i in 0..DECOYS {
        let decoy = public_from_secret(&generate_secret());
        server_handle.add_peer(PeerParams {
            public_key: decoy,
            preshared_key: None,
            endpoint: None,
            allowed_ips: vec![format!("10.99.{}.{}/32", i / 256, i % 256).parse().unwrap()],
            persistent_keepalive: None,
        });
    }

    let (client_tun, client_inject, _cli_capture) = MockTun::pair();
    let client = Engine::build(
        &client_priv,
        vec![PeerParams {
            public_key: server_pub,
            preshared_key: None,
            endpoint: Some(server_addr),
            allowed_ips: vec!["10.8.0.0/24".parse().unwrap()],
            // No keepalive: keeps steady-state inbound to exactly the packets we inject,
            // so the probe delta is deterministic.
            persistent_keepalive: None,
        }],
        Transport::plain(client_udp),
        client_tun,
    );

    tokio::spawn(server.run());
    tokio::spawn(client.run());

    let send_and_await = |n: u8| {
        let inject = client_inject.clone();
        let packet = ipv4_packet(
            Ipv4Addr::new(10, 8, 0, 2),
            Ipv4Addr::new(10, 8, 0, 1),
            &[b'x', n],
        );
        inject.send(packet.clone()).unwrap();
        packet
    };

    // Warm up: the first data packet completes the handshake and pays the one-time
    // fallback scan that learns index -> peer. Everything after must route directly.
    let warm = send_and_await(0);
    let got = tokio::time::timeout(Duration::from_secs(10), srv_capture.recv())
        .await
        .expect("warmup packet never traversed the tunnel")
        .expect("server tun channel closed");
    assert_eq!(got, warm);

    let probes_before = server_handle.decap_probes();

    // Steady state: send K more packets; each should resolve on the first candidate.
    const K: u8 = 5;
    for n in 1..=K {
        let sent = send_and_await(n);
        let got = tokio::time::timeout(Duration::from_secs(5), srv_capture.recv())
            .await
            .expect("steady-state packet never traversed the tunnel")
            .expect("server tun channel closed");
        assert_eq!(got, sent);
    }

    let delta = server_handle.decap_probes() - probes_before;
    // Each of the K data packets costs exactly one probe (index hit). Allow a tiny slack
    // for any stray retransmit, but it must be nowhere near the O(peers) scan a broken
    // demux would incur (~K * DECOYS).
    assert!(
        delta >= K as u64 && delta <= K as u64 + 2,
        "expected ~{K} probes for {K} packets with {DECOYS} decoys, got {delta}"
    );
}

/// 2G: the WireGuard transport must work over an IPv6 underlay — same handshake and data
/// path, but the client dials the server over a v6 UDP socket (`[::1]`). The inner packet is
/// still IPv4, proving the tunnel is agnostic to the underlay's address family.
#[tokio::test]
async fn tunnel_carries_a_packet_over_ipv6_underlay() {
    let server_priv = generate_secret();
    let server_pub = public_from_secret(&server_priv);
    let client_priv = generate_secret();
    let client_pub = public_from_secret(&client_priv);

    // IPv6 loopback sockets — the underlay is v6 end to end.
    let server_udp = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let server_addr = server_udp.local_addr().unwrap();
    assert!(server_addr.is_ipv6(), "server must bind a v6 socket");
    let client_udp = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();

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

    let (client_tun, client_inject, _cli_capture) = MockTun::pair();
    let client = Engine::build(
        &client_priv,
        vec![PeerParams {
            public_key: server_pub,
            preshared_key: None,
            endpoint: Some(server_addr), // a v6 endpoint
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
        b"wireguard over ipv6",
    );
    client_inject.send(packet.clone()).unwrap();

    let received = tokio::time::timeout(Duration::from_secs(10), srv_capture.recv())
        .await
        .expect("timed out; tunnel never delivered over the v6 underlay")
        .expect("server tun channel closed");
    assert_eq!(
        received, packet,
        "packet must traverse the v6-underlay tunnel unchanged"
    );
}

#[tokio::test]
async fn psk_rotates_at_runtime_without_reconnect() {
    // 4B continuous rekey: rotate the preshared key on a live tunnel. boringtun fixes the PSK at
    // Tunn::new, so `replace_peer` recreates the session; when BOTH ends rotate to the same new
    // PSK a fresh handshake brings traffic back, and a one-sided rotation must break (proving the
    // PSK is actually enforced end to end). The TUN/engine stay up throughout — no reconnect.
    let psk_a = [0xA1u8; 32];
    let psk_b = [0xB2u8; 32];

    let server_priv = generate_secret();
    let server_pub = public_from_secret(&server_priv);
    let client_priv = generate_secret();
    let client_pub = public_from_secret(&client_priv);

    let server_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_udp.local_addr().unwrap();
    let client_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Peer params per end; only the PSK changes on rotation.
    let server_peer = |psk: [u8; 32]| PeerParams {
        public_key: client_pub,
        preshared_key: Some(psk),
        endpoint: None, // server learns the client's endpoint from inbound packets
        allowed_ips: vec!["10.8.0.2/32".parse().unwrap()],
        persistent_keepalive: None,
    };
    let client_peer = |psk: [u8; 32]| PeerParams {
        public_key: server_pub,
        preshared_key: Some(psk),
        endpoint: Some(server_addr),
        allowed_ips: vec!["10.8.0.0/24".parse().unwrap()],
        persistent_keepalive: Some(5),
    };

    let (server_tun, _srv_inject, mut srv_capture) = MockTun::pair();
    let server = Engine::build(
        &server_priv,
        vec![server_peer(psk_a)],
        Transport::plain(server_udp),
        server_tun,
    );
    let (client_tun, client_inject, _cli_capture) = MockTun::pair();
    let client = Engine::build(
        &client_priv,
        vec![client_peer(psk_a)],
        Transport::plain(client_udp),
        client_tun,
    );

    let server_h = server.handle();
    let client_h = client.handle();
    tokio::spawn(server.run());
    tokio::spawn(client.run());

    // Helper: inject a packet at the client and wait (bounded) for it at the server.
    async fn crosses(
        inject: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        capture: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
        within: Duration,
    ) -> bool {
        let pkt = ipv4_packet(
            Ipv4Addr::new(10, 8, 0, 2),
            Ipv4Addr::new(10, 8, 0, 1),
            b"rekey probe",
        );
        // Send a few times so a handshake has slots to complete within the window.
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let _ = inject.send(pkt.clone());
            match tokio::time::timeout(Duration::from_millis(250), capture.recv()).await {
                Ok(Some(got)) => return got == pkt,
                _ if tokio::time::Instant::now() >= deadline => return false,
                _ => continue,
            }
        }
    }

    // PSK_A works.
    assert!(
        crosses(&client_inject, &mut srv_capture, Duration::from_secs(10)).await,
        "tunnel must work with the initial PSK"
    );

    // Rotate BOTH ends to PSK_B → a fresh handshake resumes traffic.
    client_h.replace_peer(client_peer(psk_b));
    server_h.replace_peer(server_peer(psk_b));
    assert!(
        crosses(&client_inject, &mut srv_capture, Duration::from_secs(10)).await,
        "tunnel must resume after both ends rotate to the new PSK"
    );

    // Rotate ONLY the client (server still on PSK_B) → mismatch, no traffic.
    client_h.replace_peer(client_peer([0xC3u8; 32]));
    assert!(
        !crosses(&client_inject, &mut srv_capture, Duration::from_secs(2)).await,
        "a one-sided PSK rotation must break the tunnel (PSK is enforced)"
    );
}

#[tokio::test]
async fn tunnel_works_with_adaptive_daita_pacing() {
    // 4A: the client shapes egress with the ADAPTIVE pacer (jittered timing + idle taper) instead
    // of a fixed slot. Same real WireGuard tunnel; assert a packet still crosses and the server
    // still drops the (now adaptively-paced) cover cells.
    let obfs_key = [0x9d; 32];
    let cell_size = oxide_daita::DEFAULT_CELL_SIZE;
    let slot = Duration::from_millis(2); // fast base cadence so the handshake completes quickly

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
    )
    .with_daita(Daita::framing(cell_size));

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
    )
    .with_daita(Daita::shaping_adaptive(cell_size, slot));

    tokio::spawn(server.run());
    tokio::spawn(client.run());

    let packet = ipv4_packet(
        Ipv4Addr::new(10, 8, 0, 2),
        Ipv4Addr::new(10, 8, 0, 1),
        b"adaptive daita works",
    );
    client_inject.send(packet.clone()).unwrap();

    let received = tokio::time::timeout(Duration::from_secs(10), srv_capture.recv())
        .await
        .expect("timed out; adaptively-paced DAITA tunnel never delivered")
        .expect("server tun channel closed");
    assert_eq!(received, packet);

    // Cover cells (now adaptively paced) must still be recognized and dropped, not surfaced.
    let leaked = tokio::time::timeout(Duration::from_millis(300), srv_capture.recv()).await;
    assert!(
        leaked.is_err(),
        "adaptive cover must be dropped, not leak to the tunnel"
    );
}
