//! The datagram transport the engine sends/receives WireGuard packets over.
//!
//! Abstracts the UDP socket so the engine's logic is identical whether traffic is sent
//! in the clear or through the obfuscation layer ("stealth mode"). Keeping this an enum
//! (rather than a generic) avoids threading another type parameter through the engine.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;

use oxide_mimicry::quic::{self, Nonce, AUTH_WINDOW_SECS};
use oxide_obfs::{deobfuscate, obfuscate};

use crate::decoy::DecoyForwarder;
use crate::mimic::MimicTransport;

/// Scratch buffer for an obfuscated datagram (WireGuard max + obfs overhead).
const OBFS_BUF: usize = 2048;

/// Current Unix time in seconds, used to timestamp and freshness-check QUIC Initials.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Runtime counters for the stealth transports — observability that the defenses are firing.
/// Cheap `Relaxed` atomics; snapshot via [`Transport::counters`].
#[derive(Default)]
pub struct TransportCounters {
    /// Undecodable inbound datagrams dropped by the obfs layer (scans/probes/junk on the port).
    pub obfs_decode_failures: AtomicU64,
    /// Unauthenticated first-contact Initials spliced to the decoy backend (active-probe
    /// deflections). Server-side only (decoy runs on the server).
    pub decoy_forwards: AtomicU64,
}

/// A snapshot of [`TransportCounters`].
#[derive(Debug, Clone, Copy, Default)]
pub struct TransportStats {
    pub obfs_decode_failures: u64,
    pub decoy_forwards: u64,
}

/// The datagram transport: a wire backend plus runtime counters. Kept a concrete type (not a
/// generic) so the engine's `Shared` doesn't grow a type parameter.
pub struct Transport {
    wire: Wire,
    counters: Arc<TransportCounters>,
}

enum Wire {
    /// Plain UDP — standard WireGuard on the wire.
    Plain(UdpSocket),
    /// Obfuscated UDP: each datagram is wrapped so DPI can't fingerprint it.
    Obfuscated { socket: UdpSocket, key: [u8; 32] },
    /// TLS-mimicry over TCP: the flow looks like an HTTPS session ("stealth tier 2").
    Mimic(MimicTransport),
    /// QUIC-mimicry over UDP: the flow looks like an HTTP/3 (QUIC) session. UDP-native,
    /// so no TCP-over-TCP penalty. First packet to each peer is an **authenticated** QUIC
    /// Initial (keyed MAC + timestamp + nonce), the rest short-header packets. The Initial
    /// authentication makes the endpoint resist active probing: forged, stale, or replayed
    /// Initials are dropped in silence, so the port looks dead to a prober.
    QuicMimic {
        socket: Arc<UdpSocket>,
        key: [u8; 32],
        sent_initial: Mutex<HashSet<SocketAddr>>,
        /// Anti-replay cache: nonce → the Initial's timestamp. Entries older than the
        /// freshness window are pruned, so a replayed Initial either matches a live entry
        /// (dropped) or has already aged out of the window (also dropped).
        seen_initials: Mutex<HashMap<Nonce, u64>>,
        /// Optional decoy-forwarding: when set, an unauthenticated first-contact Initial
        /// (forged/stale/replayed) is spliced to a real backend instead of being dropped,
        /// so the port answers like an ordinary QUIC server under active probing.
        decoy: Option<Arc<DecoyForwarder>>,
    },
}

impl Transport {
    fn wrap(wire: Wire) -> Self {
        Transport {
            wire,
            counters: Arc::new(TransportCounters::default()),
        }
    }

    pub fn plain(socket: UdpSocket) -> Self {
        Self::wrap(Wire::Plain(socket))
    }

    pub fn obfuscated(socket: UdpSocket, key: [u8; 32]) -> Self {
        Self::wrap(Wire::Obfuscated { socket, key })
    }

    pub fn mimic(transport: MimicTransport) -> Self {
        Self::wrap(Wire::Mimic(transport))
    }

    pub fn quic_mimic(socket: UdpSocket, key: [u8; 32]) -> Self {
        Self::wrap(Wire::QuicMimic {
            socket: Arc::new(socket),
            key,
            sent_initial: Mutex::new(HashSet::new()),
            seen_initials: Mutex::new(HashMap::new()),
            decoy: None,
        })
    }

    /// QUIC mimicry with **decoy-forwarding**: unauthenticated first-contact Initials are
    /// proxied to `decoy_backend` (a real TLS/QUIC endpoint) rather than dropped, so the
    /// port answers like an ordinary web server under active probing. See [`crate::decoy`].
    pub fn quic_mimic_with_decoy(
        socket: UdpSocket,
        key: [u8; 32],
        decoy_backend: SocketAddr,
    ) -> Self {
        let socket = Arc::new(socket);
        let decoy = DecoyForwarder::new(socket.clone(), decoy_backend);
        Self::wrap(Wire::QuicMimic {
            socket,
            key,
            sent_initial: Mutex::new(HashSet::new()),
            seen_initials: Mutex::new(HashMap::new()),
            decoy: Some(decoy),
        })
    }

    /// Snapshot the stealth-defense counters (undecodable-datagram drops + decoy deflections).
    pub fn counters(&self) -> TransportStats {
        TransportStats {
            obfs_decode_failures: self.counters.obfs_decode_failures.load(Ordering::Relaxed),
            decoy_forwards: self.counters.decoy_forwards.load(Ordering::Relaxed),
        }
    }

    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        match &self.wire {
            Wire::Plain(s) => s.send_to(buf, addr).await,
            Wire::Obfuscated { socket, key } => {
                let framed = obfuscate(key, buf);
                socket.send_to(&framed, addr).await?;
                Ok(buf.len())
            }
            Wire::Mimic(m) => m.send_to(buf, addr).await,
            Wire::QuicMimic {
                socket,
                key,
                sent_initial,
                ..
            } => {
                let obf = obfuscate(key, buf);
                // The first datagram to a peer is an authenticated QUIC Initial (long
                // header + embedded ClientHello + keyed token); subsequent ones are
                // short-header 1-RTT packets.
                let first = sent_initial.lock().unwrap().insert(addr);
                let dg = if first {
                    quic::initial_packet(&obf, key, now_secs())
                } else {
                    quic::short_packet(&obf)
                };
                socket.send_to(&dg, addr).await?;
                Ok(buf.len())
            }
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match &self.wire {
            Wire::Plain(s) => s.recv_from(buf).await,
            Wire::Obfuscated { socket, key } => {
                let mut raw = [0u8; OBFS_BUF];
                loop {
                    let (n, addr) = socket.recv_from(&mut raw).await?;
                    // Undecodable datagrams (scans/probes) are silently dropped: giving
                    // no response is itself part of resisting active detection. Counted so the
                    // operator can see junk/probe volume on the port.
                    if let Some(plain) = deobfuscate(key, &raw[..n]) {
                        let m = plain.len().min(buf.len());
                        buf[..m].copy_from_slice(&plain[..m]);
                        return Ok((m, addr));
                    }
                    self.counters
                        .obfs_decode_failures
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            Wire::Mimic(m) => m.recv_from(buf).await,
            Wire::QuicMimic {
                socket,
                key,
                seen_initials,
                decoy,
                ..
            } => {
                let mut raw = [0u8; OBFS_BUF];
                loop {
                    let (n, addr) = socket.recv_from(&mut raw).await?;
                    let dg = &raw[..n];

                    // A source already classified as a prober keeps getting spliced to the
                    // decoy backend for the flow's lifetime — it only ever sees a real server.
                    if let Some(d) = decoy {
                        if d.is_decoy(&addr).await {
                            d.forward(dg, addr).await;
                            self.counters.decoy_forwards.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    }

                    // A long header must be a well-keyed, fresh, non-replayed Initial.
                    // Short-header packets carry no authenticator — their payload is still
                    // gated by the WireGuard AEAD after deobfuscation.
                    let payload = if dg.first().is_some_and(|b| b & 0x80 != 0) {
                        match quic::verify_initial(dg, key, now_secs()) {
                            Some((nonce, payload)) if accept_initial(seen_initials, nonce) => {
                                payload
                            }
                            // Unauthenticated Initial (forged/stale/replayed) — the active-
                            // probe vector. With a decoy configured, splice the source to a
                            // real backend so the port answers; otherwise drop in silence.
                            _ => {
                                if let Some(d) = decoy {
                                    d.forward(dg, addr).await;
                                    self.counters.decoy_forwards.fetch_add(1, Ordering::Relaxed);
                                }
                                continue;
                            }
                        }
                    } else {
                        match quic::parse_short(dg) {
                            Some(p) => p,
                            None => continue,
                        }
                    };
                    if let Some(plain) = deobfuscate(key, &payload) {
                        let m = plain.len().min(buf.len());
                        buf[..m].copy_from_slice(&plain[..m]);
                        return Ok((m, addr));
                    }
                    self.counters
                        .obfs_decode_failures
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

/// Record a verified Initial's nonce and report whether it's fresh (`true`) or a replay
/// (`false`). Prunes entries older than the freshness window first, so the cache stays
/// bounded and a replay of an Initial that has aged out is caught by the timestamp window
/// in `verify_initial` before it ever reaches here.
fn accept_initial(cache: &Mutex<HashMap<Nonce, u64>>, nonce: Nonce) -> bool {
    let now = now_secs();
    let mut map = cache.lock().unwrap();
    map.retain(|_, &mut ts| now.saturating_sub(ts) <= AUTH_WINDOW_SECS);
    // The nonce is unknown to the caller's clock here, so stamp it with `now`; the entry
    // lives at least one full window, which covers any in-window replay.
    map.insert(nonce, now).is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn quic_pair() -> (Transport, Transport, SocketAddr) {
        let key = [42u8; 32];
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = Transport::quic_mimic(server_sock, key);
        let client = Transport::quic_mimic(client_sock, key);
        (client, server, server_addr)
    }

    #[tokio::test]
    async fn authenticated_initial_then_short_deliver() {
        let (client, server, server_addr) = quic_pair().await;

        // First datagram to the server is an authenticated Initial.
        client
            .send_to(b"handshake init", server_addr)
            .await
            .unwrap();
        let mut buf = [0u8; 2048];
        let (n, _from) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"handshake init");

        // The next datagram to the same peer is a short-header packet and still delivers.
        client.send_to(b"data packet", server_addr).await.unwrap();
        let (n, _from) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"data packet");
    }

    #[tokio::test]
    async fn forged_initial_from_wrong_key_is_ignored() {
        let key = [42u8; 32];
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let server = Transport::quic_mimic(server_sock, key);

        // An attacker without the key sends a QUIC Initial built with the wrong key.
        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forged = quic::initial_packet(&obfuscate(&[9u8; 32], b"probe"), &[9u8; 32], now_secs());
        attacker.send_to(&forged, server_addr).await.unwrap();

        // The server must not surface it — a genuine Initial arriving right after should be
        // the first thing recv_from returns.
        let genuine_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let genuine = Transport::quic_mimic(genuine_sock, key);
        genuine.send_to(b"real", server_addr).await.unwrap();

        let mut buf = [0u8; 2048];
        let (n, _from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            server.recv_from(&mut buf),
        )
        .await
        .expect("recv should not hang")
        .unwrap();
        assert_eq!(&buf[..n], b"real");
    }

    /// A UDP stub standing in for a real co-hosted TLS/QUIC site: it replies to anything
    /// with a recognizable marker so the test can see the decoy answer come back.
    async fn spawn_decoy_backend() -> SocketAddr {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = backend.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            while let Ok((n, src)) = backend.recv_from(&mut b).await {
                let mut resp = b"decoy-backend:".to_vec();
                resp.extend_from_slice(&b[..n]);
                let _ = backend.send_to(&resp, src).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn forged_probe_is_answered_by_the_decoy_backend() {
        // With decoy-forwarding on, a prober's forged Initial must not be dropped: it is
        // spliced to the backend, whose response returns to the prober from the server's
        // own port — so the port looks alive and ordinary, not dead.
        let backend_addr = spawn_decoy_backend().await;

        let key = [42u8; 32];
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let server = Arc::new(Transport::quic_mimic_with_decoy(
            server_sock,
            key,
            backend_addr,
        ));

        // Drive the server's recv loop; it must never surface the forged probe as a payload.
        tokio::spawn({
            let server = server.clone();
            async move {
                let mut buf = [0u8; 2048];
                let _ = server.recv_from(&mut buf).await;
            }
        });

        // A prober without the key crafts a QUIC Initial and waits for a response.
        let prober = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forged = quic::initial_packet(&obfuscate(&[9u8; 32], b"probe"), &[9u8; 32], now_secs());
        prober.send_to(&forged, server_addr).await.unwrap();

        let mut b = [0u8; 2048];
        let (n, from) =
            tokio::time::timeout(std::time::Duration::from_secs(2), prober.recv_from(&mut b))
                .await
                .expect("decoy must answer the probe (the port must look alive)")
                .unwrap();
        assert_eq!(
            from, server_addr,
            "response must appear to come from the server's port"
        );
        assert!(b[..n].starts_with(b"decoy-backend:"));
        // The deflection is counted for observability (2H).
        assert!(
            server.counters().decoy_forwards >= 1,
            "the decoy forward must be counted"
        );
    }

    #[tokio::test]
    async fn obfs_decode_failures_are_counted() {
        // Undecodable inbound datagrams (scans/probes) are dropped silently but counted, so an
        // operator can see junk volume on the port.
        let key = [7u8; 32];
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let server = Transport::obfuscated(server_sock, key);

        // From one socket (ordered on loopback): a junk byte, then a valid obfuscated datagram.
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(b"x", server_addr).await.unwrap(); // too short to decode
        sender
            .send_to(&obfuscate(&key, b"hello"), server_addr)
            .await
            .unwrap();

        let mut buf = [0u8; 2048];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            server.recv_from(&mut buf),
        )
        .await
        .expect("recv should return on the valid datagram")
        .unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert!(
            server.counters().obfs_decode_failures >= 1,
            "the junk datagram must be counted as a decode failure"
        );
    }

    #[tokio::test]
    async fn genuine_tunnels_while_forged_is_decoyed() {
        // The acceptance capstone: with decoy on, a genuine authenticated Initial still
        // tunnels normally *while* a concurrent forged probe is decoy-forwarded.
        let backend_addr = spawn_decoy_backend().await;

        let key = [42u8; 32];
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let server = Arc::new(Transport::quic_mimic_with_decoy(
            server_sock,
            key,
            backend_addr,
        ));

        // Server recv loop pushes any *real* delivered payloads to a channel.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn({
            let server = server.clone();
            async move {
                let mut buf = [0u8; 2048];
                while let Ok((n, _)) = server.recv_from(&mut buf).await {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        });

        // Prober: forged Initial (wrong key). Genuine client: correct key.
        let prober = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forged = quic::initial_packet(&obfuscate(&[9u8; 32], b"probe"), &[9u8; 32], now_secs());
        prober.send_to(&forged, server_addr).await.unwrap();

        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = Transport::quic_mimic(client_sock, key);
        client
            .send_to(b"genuine handshake", server_addr)
            .await
            .unwrap();

        // The genuine payload is delivered to the tunnel; the forged probe never surfaces.
        let delivered = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("genuine Initial should still tunnel with decoy on")
            .expect("channel closed");
        assert_eq!(delivered, b"genuine handshake");

        // ...and the prober still gets a decoy answer, concurrently.
        let mut b = [0u8; 2048];
        let (n, from) =
            tokio::time::timeout(std::time::Duration::from_secs(2), prober.recv_from(&mut b))
                .await
                .expect("decoy must answer the probe concurrently")
                .unwrap();
        assert_eq!(from, server_addr);
        assert!(b[..n].starts_with(b"decoy-backend:"));
    }

    #[tokio::test]
    async fn replayed_initial_is_dropped() {
        let key = [42u8; 32];
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let server = Transport::quic_mimic(server_sock, key);

        // Capture a genuine Initial on the wire and replay it verbatim, twice.
        let initial = quic::initial_packet(&obfuscate(&key, b"captured"), &key, now_secs());
        let replayer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        replayer.send_to(&initial, server_addr).await.unwrap();

        let mut buf = [0u8; 2048];
        let (n, _) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"captured"); // first copy accepted

        // Replay the identical bytes; the nonce is now cached, so it's dropped. A fresh
        // Initial sent afterwards is what recv_from returns next.
        replayer.send_to(&initial, server_addr).await.unwrap();
        let fresh_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fresh = Transport::quic_mimic(fresh_sock, key);
        fresh.send_to(b"fresh", server_addr).await.unwrap();
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            server.recv_from(&mut buf),
        )
        .await
        .expect("recv should not hang")
        .unwrap();
        assert_eq!(&buf[..n], b"fresh");
    }
}
