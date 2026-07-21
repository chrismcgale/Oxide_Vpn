//! The datagram transport the engine sends/receives WireGuard packets over.
//!
//! Abstracts the UDP socket so the engine's logic is identical whether traffic is sent
//! in the clear or through the obfuscation layer ("stealth mode"). Keeping this an enum
//! (rather than a generic) avoids threading another type parameter through the engine.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;

use oxide_mimicry::quic::{self, Nonce, AUTH_WINDOW_SECS};
use oxide_obfs::{deobfuscate, obfuscate};

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

pub enum Transport {
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
        socket: UdpSocket,
        key: [u8; 32],
        sent_initial: Mutex<HashSet<SocketAddr>>,
        /// Anti-replay cache: nonce → the Initial's timestamp. Entries older than the
        /// freshness window are pruned, so a replayed Initial either matches a live entry
        /// (dropped) or has already aged out of the window (also dropped).
        seen_initials: Mutex<HashMap<Nonce, u64>>,
    },
}

impl Transport {
    pub fn plain(socket: UdpSocket) -> Self {
        Transport::Plain(socket)
    }

    pub fn obfuscated(socket: UdpSocket, key: [u8; 32]) -> Self {
        Transport::Obfuscated { socket, key }
    }

    pub fn mimic(transport: MimicTransport) -> Self {
        Transport::Mimic(transport)
    }

    pub fn quic_mimic(socket: UdpSocket, key: [u8; 32]) -> Self {
        Transport::QuicMimic {
            socket,
            key,
            sent_initial: Mutex::new(HashSet::new()),
            seen_initials: Mutex::new(HashMap::new()),
        }
    }

    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        match self {
            Transport::Plain(s) => s.send_to(buf, addr).await,
            Transport::Obfuscated { socket, key } => {
                let framed = obfuscate(key, buf);
                socket.send_to(&framed, addr).await?;
                Ok(buf.len())
            }
            Transport::Mimic(m) => m.send_to(buf, addr).await,
            Transport::QuicMimic {
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
        match self {
            Transport::Plain(s) => s.recv_from(buf).await,
            Transport::Obfuscated { socket, key } => {
                let mut raw = [0u8; OBFS_BUF];
                loop {
                    let (n, addr) = socket.recv_from(&mut raw).await?;
                    // Undecodable datagrams (scans/probes) are silently dropped: giving
                    // no response is itself part of resisting active detection.
                    if let Some(plain) = deobfuscate(key, &raw[..n]) {
                        let m = plain.len().min(buf.len());
                        buf[..m].copy_from_slice(&plain[..m]);
                        return Ok((m, addr));
                    }
                }
            }
            Transport::Mimic(m) => m.recv_from(buf).await,
            Transport::QuicMimic {
                socket,
                key,
                seen_initials,
                ..
            } => {
                let mut raw = [0u8; OBFS_BUF];
                loop {
                    let (n, addr) = socket.recv_from(&mut raw).await?;
                    let dg = &raw[..n];
                    // A long header must be a well-keyed, fresh, non-replayed Initial;
                    // anything else (forged/stale/replayed probe) is dropped in silence.
                    // Short-header packets carry no authenticator — their payload is still
                    // gated by the WireGuard AEAD after deobfuscation.
                    let payload = if dg.first().is_some_and(|b| b & 0x80 != 0) {
                        match quic::verify_initial(dg, key, now_secs()) {
                            Some((nonce, payload)) if accept_initial(seen_initials, nonce) => {
                                payload
                            }
                            _ => continue,
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
