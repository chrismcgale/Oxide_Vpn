//! The data-plane engine: a WireGuard tunnel built on boringtun.
//!
//! Three tokio tasks share one `Arc<Shared<T>>`:
//!
//!   * **outbound** — read a plaintext IP packet from the TUN device, pick the peer
//!     by destination address (cryptokey routing), `encapsulate`, send the ciphertext
//!     over UDP to that peer's endpoint.
//!   * **inbound** — receive a UDP datagram, `decapsulate` it, and either write the
//!     decrypted inner packet to the TUN device (after a source-address anti-spoof
//!     check) or send handshake/cookie replies back out.
//!   * **timers** — every 250 ms call `update_timers` on each peer, which drives
//!     handshake retransmission, rekeying, and persistent keepalives.
//!
//! Two boringtun contracts we honour deliberately:
//!   1. `update_timers` MUST be called on a ticker or handshakes never retry.
//!   2. After `decapsulate` returns `WriteToNetwork`, we MUST keep calling
//!      `decapsulate(None, &[], buf)` until it returns `Done`, sending each datagram,
//!      or the handshake stalls.
//!
//! `Tunn` is not `Sync` and is mutated by every call, so it lives behind a blocking
//! `std::sync::Mutex`. We only hold that lock to run one boringtun call into a stack
//! buffer and copy the bytes out — never across an `.await`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey as XPublicKey, StaticSecret};
use ipnet::IpNet;
use tokio::net::UdpSocket;
use tokio::time::interval;
use tracing::{debug, trace, warn};

use oxide_common::{PublicKey, SecretKey, TunQueue};

use crate::peer::Peer;
use crate::router::AllowedIps;

/// Max datagram/packet we buffer. Tunnel MTU is 1420; WireGuard adds ~32 bytes of
/// overhead. 2048 leaves comfortable headroom without being wasteful.
const MAX_PKT: usize = 2048;

/// Timer granularity. WireGuard's timers have second-level resolution; 250 ms keeps
/// handshake retransmit and keepalive latency low without busy-spinning.
const TIMER_TICK: Duration = Duration::from_millis(250);

/// Parameters describing one peer, mapped from config by the caller.
pub struct PeerParams {
    pub public_key: PublicKey,
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpNet>,
    pub persistent_keepalive: Option<u16>,
}

impl PeerParams {
    /// Build engine peer parameters from a parsed config peer.
    pub fn from_config(p: &oxide_common::PeerConfig) -> Self {
        PeerParams {
            public_key: p.public_key,
            preshared_key: p.preshared_key.as_ref().map(|k| *k.as_bytes()),
            endpoint: p.endpoint,
            allowed_ips: p.allowed_ips.clone(),
            persistent_keepalive: p.persistent_keepalive,
        }
    }
}

struct Shared<T: TunQueue> {
    udp: UdpSocket,
    tun: T,
    peers: Vec<Peer>,
    router: AllowedIps,
    /// Source-address -> peer index cache, learned as datagrams arrive. Lets the
    /// inbound path route directly instead of trying every peer. (A proper
    /// receiver-index table is an M2 refinement.)
    addr_to_peer: Mutex<HashMap<SocketAddr, usize>>,
}

pub struct Engine<T: TunQueue> {
    shared: Arc<Shared<T>>,
}

impl<T: TunQueue> Engine<T> {
    /// Build an engine from key material and peer parameters.
    pub fn build(private_key: &SecretKey, peers: Vec<PeerParams>, udp: UdpSocket, tun: T) -> Self {
        let static_private = StaticSecret::from(*private_key.as_bytes());

        let mut router = AllowedIps::new();
        let mut peer_vec = Vec::with_capacity(peers.len());

        for (idx, p) in peers.into_iter().enumerate() {
            let peer_public = XPublicKey::from(*p.public_key.as_bytes());
            // rate_limiter=None in M1; cookie/DoS defense is M6 work.
            let tunn = Tunn::new(
                static_private.clone(),
                peer_public,
                p.preshared_key,
                p.persistent_keepalive,
                idx as u32,
                None,
            );
            for net in &p.allowed_ips {
                router.insert(*net, idx);
            }
            peer_vec.push(Peer::new(tunn, p.endpoint, p.allowed_ips, p.public_key));
        }

        Engine {
            shared: Arc::new(Shared {
                udp,
                tun,
                peers: peer_vec,
                router,
                addr_to_peer: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Run the three data-plane tasks until one of them fails.
    pub async fn run(self) -> std::io::Result<()> {
        let shared = self.shared;

        // Proactively initiate handshakes toward any peer we have an endpoint for
        // (i.e. the client dialing its server) so the tunnel comes up before user
        // traffic and keepalives start flowing.
        Self::init_handshakes(&shared).await;

        let out = tokio::spawn(Self::outbound_loop(shared.clone()));
        let inb = tokio::spawn(Self::inbound_loop(shared.clone()));
        let tim = tokio::spawn(Self::timer_loop(shared.clone()));

        let res = tokio::select! {
            r = out => r,
            r = inb => r,
            r = tim => r,
        };
        match res {
            Ok(inner) => inner,
            Err(join) => Err(std::io::Error::other(join)),
        }
    }

    async fn init_handshakes(shared: &Arc<Shared<T>>) {
        for (idx, peer) in shared.peers.iter().enumerate() {
            let Some(endpoint) = peer.endpoint() else {
                continue;
            };
            // Encapsulating an empty packet with no live session yields a handshake
            // initiation; there's nothing to queue, so this just kicks the handshake.
            let datagram = {
                let mut buf = [0u8; MAX_PKT];
                let mut tunn = peer.tunn.lock().unwrap();
                match tunn.encapsulate(&[], &mut buf) {
                    TunnResult::WriteToNetwork(d) => Some(d.to_vec()),
                    _ => None,
                }
            };
            if let Some(d) = datagram {
                debug!(peer = idx, %endpoint, "initiating handshake");
                let _ = shared.udp.send_to(&d, endpoint).await;
            }
        }
    }

    async fn outbound_loop(shared: Arc<Shared<T>>) -> std::io::Result<()> {
        let mut buf = [0u8; MAX_PKT];
        loop {
            let n = shared.tun.recv(&mut buf).await?;
            if n == 0 {
                continue;
            }
            let packet = &buf[..n];

            let Some(dst) = Tunn::dst_address(packet) else {
                trace!("dropping non-IP / short packet from tun");
                continue;
            };
            let Some(idx) = shared.router.lookup(dst) else {
                trace!(%dst, "no peer owns destination; dropping");
                continue;
            };
            let peer = &shared.peers[idx];

            let (datagram, endpoint) = {
                let mut out = [0u8; MAX_PKT];
                let mut tunn = peer.tunn.lock().unwrap();
                match tunn.encapsulate(packet, &mut out) {
                    TunnResult::WriteToNetwork(d) => (Some(d.to_vec()), peer.endpoint()),
                    TunnResult::Done => (None, None),
                    TunnResult::Err(e) => {
                        warn!(peer = idx, ?e, "encapsulate error");
                        (None, None)
                    }
                    // encapsulate only ever yields WriteToNetwork or Done/Err.
                    _ => (None, None),
                }
            };

            match (datagram, endpoint) {
                (Some(d), Some(ep)) => {
                    shared.udp.send_to(&d, ep).await?;
                }
                (Some(_), None) => {
                    trace!(peer = idx, "have datagram but no endpoint yet; dropping");
                }
                _ => {}
            }
        }
    }

    async fn inbound_loop(shared: Arc<Shared<T>>) -> std::io::Result<()> {
        let mut buf = [0u8; MAX_PKT];
        loop {
            let (n, src) = shared.udp.recv_from(&mut buf).await?;
            let datagram = buf[..n].to_vec();
            Self::handle_incoming(&shared, datagram, src).await;
        }
    }

    /// Decapsulate one datagram and act on the result. Tries the cached peer for
    /// `src` first, falling back to every peer (a handshake from a new endpoint has
    /// no cache entry yet). The first peer that decapsulates without error owns it.
    async fn handle_incoming(shared: &Arc<Shared<T>>, datagram: Vec<u8>, src: SocketAddr) {
        let candidates: Vec<usize> = match shared.addr_to_peer.lock().unwrap().get(&src) {
            Some(&idx) => vec![idx],
            None => (0..shared.peers.len()).collect(),
        };

        for idx in candidates {
            let peer = &shared.peers[idx];

            // Collect boringtun's outputs while holding the lock, then act after
            // releasing it (we must not .await while the Tunn mutex is held).
            let mut to_network: Vec<Vec<u8>> = Vec::new();
            let mut to_tun: Option<Vec<u8>> = None;
            let mut errored = false;

            {
                let mut tunn = peer.tunn.lock().unwrap();
                let mut buf = [0u8; MAX_PKT];
                match tunn.decapsulate(Some(src.ip()), &datagram, &mut buf) {
                    TunnResult::Done => {}
                    TunnResult::Err(_) => errored = true,
                    TunnResult::WriteToNetwork(d) => {
                        to_network.push(d.to_vec());
                        // Drain any further queued datagrams (handshake follow-ups).
                        loop {
                            let mut b2 = [0u8; MAX_PKT];
                            match tunn.decapsulate(None, &[], &mut b2) {
                                TunnResult::WriteToNetwork(d2) => to_network.push(d2.to_vec()),
                                _ => break,
                            }
                        }
                    }
                    TunnResult::WriteToTunnelV4(pkt, addr) => {
                        if shared.router.is_allowed_for(addr.into(), idx) {
                            to_tun = Some(pkt.to_vec());
                        } else {
                            warn!(peer = idx, %addr, "inbound source not in allowed_ips; dropping");
                        }
                    }
                    TunnResult::WriteToTunnelV6(pkt, addr) => {
                        if shared.router.is_allowed_for(addr.into(), idx) {
                            to_tun = Some(pkt.to_vec());
                        } else {
                            warn!(peer = idx, %addr, "inbound source not in allowed_ips; dropping");
                        }
                    }
                }
            }

            if errored {
                // Wrong peer (or a genuinely bad packet): try the next candidate.
                continue;
            }

            // This peer owns the datagram. Learn/refresh its endpoint (roaming) and
            // cache the source -> peer mapping.
            if peer.set_endpoint(src) {
                debug!(peer = idx, %src, "learned/updated peer endpoint");
            }
            shared.addr_to_peer.lock().unwrap().insert(src, idx);

            for d in to_network {
                let _ = shared.udp.send_to(&d, src).await;
            }
            if let Some(pkt) = to_tun {
                if let Err(e) = shared.tun.send(&pkt).await {
                    warn!(peer = idx, ?e, "tun write failed");
                }
            }
            return;
        }
    }

    async fn timer_loop(shared: Arc<Shared<T>>) -> std::io::Result<()> {
        let mut tick = interval(TIMER_TICK);
        loop {
            tick.tick().await;
            for (idx, peer) in shared.peers.iter().enumerate() {
                let datagram = {
                    let mut buf = [0u8; MAX_PKT];
                    let mut tunn = peer.tunn.lock().unwrap();
                    match tunn.update_timers(&mut buf) {
                        TunnResult::WriteToNetwork(d) => Some(d.to_vec()),
                        TunnResult::Err(e) => {
                            debug!(peer = idx, ?e, "timer tick error (likely connection reset)");
                            None
                        }
                        _ => None,
                    }
                };
                if let Some(d) = datagram {
                    if let Some(ep) = peer.endpoint() {
                        let _ = shared.udp.send_to(&d, ep).await;
                    }
                }
            }
        }
    }
}
