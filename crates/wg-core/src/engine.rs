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
//! Peers live in a runtime-mutable [`PeerTable`] behind an `RwLock` so the control
//! plane can add/remove them on a live server (see [`EngineHandle`]).
//!
//! Two boringtun contracts we honour deliberately:
//!   1. `update_timers` MUST be called on a ticker or handshakes never retry.
//!   2. After `decapsulate` returns `WriteToNetwork`, we MUST keep calling
//!      `decapsulate(None, &[], buf)` until it returns `Done`, sending each datagram.
//!
//! `Tunn` is not `Sync` and is mutated by every call, so it lives behind a blocking
//! `std::sync::Mutex`. We only hold that lock to run one boringtun call into a stack
//! buffer and copy the bytes out — never across an `.await`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::StaticSecret;
use ipnet::IpNet;
use tokio::time::interval;
use tracing::{debug, trace, warn};

use oxide_common::{PublicKey, SecretKey, TunQueue};

use crate::daita::Daita;
use crate::peer::Peer;
use crate::table::{PeerId, PeerTable};
use crate::transport::Transport;

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

fn private_static(key: &SecretKey) -> StaticSecret {
    StaticSecret::from(*key.as_bytes())
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
    transport: Transport,
    tun: T,
    table: RwLock<PeerTable>,
    /// Source-address -> peer id cache, learned as datagrams arrive. Lets the inbound
    /// path route directly instead of trying every peer. (A proper receiver-index
    /// table is a later refinement.)
    addr_to_peer: Mutex<HashMap<SocketAddr, PeerId>>,
    /// Optional DAITA traffic shaping. When set, outbound datagrams are wrapped in
    /// fixed-size cells (and, on the shaping/client side, drained at a constant rate with
    /// cover traffic), and inbound cover cells are dropped before boringtun. See
    /// [`crate::daita`].
    daita: Option<Arc<Daita>>,
}

pub struct Engine<T: TunQueue> {
    shared: Arc<Shared<T>>,
}

/// A peer is counted as "active" if it completed a handshake within this window.
/// WireGuard rekeys about every 2 minutes, so 3 minutes catches live sessions
/// without counting long-idle ones.
const ACTIVE_WINDOW: Duration = Duration::from_secs(180);

/// A snapshot of engine load/throughput, for the control plane (server selection) and
/// the client agent/TUI (live status).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EngineStats {
    pub total_peers: usize,
    pub active_peers: usize,
    /// Total bytes encrypted and sent to peers.
    pub tx_bytes: u64,
    /// Total bytes received and decrypted from peers.
    pub rx_bytes: u64,
}

/// A cheap, cloneable handle for mutating a running engine's peer set. The control
/// plane loop on the server uses this to reconcile peers as devices come and go.
#[derive(Clone)]
pub struct EngineHandle<T: TunQueue> {
    shared: Arc<Shared<T>>,
}

impl<T: TunQueue> Engine<T> {
    /// Build an engine from key material and an initial peer set (no DoS rate limiting).
    /// `transport` is plain UDP or the obfuscated ("stealth") transport.
    pub fn build(
        private_key: &SecretKey,
        peers: Vec<PeerParams>,
        transport: Transport,
        tun: T,
    ) -> Self {
        Self::from_table(
            PeerTable::new(private_static(private_key)),
            peers,
            transport,
            tun,
        )
    }

    /// Build a server engine with a shared handshake rate limiter (DoS defense). `limit`
    /// is handshake messages/second before cookie challenges engage.
    pub fn build_server(
        private_key: &SecretKey,
        peers: Vec<PeerParams>,
        transport: Transport,
        tun: T,
        handshake_limit: u64,
    ) -> Self {
        let table = PeerTable::new_rate_limited(private_static(private_key), handshake_limit);
        Self::from_table(table, peers, transport, tun)
    }

    fn from_table(
        mut table: PeerTable,
        peers: Vec<PeerParams>,
        transport: Transport,
        tun: T,
    ) -> Self {
        for p in peers {
            table.add(p);
        }
        Engine {
            shared: Arc::new(Shared {
                transport,
                tun,
                table: RwLock::new(table),
                addr_to_peer: Mutex::new(HashMap::new()),
                daita: None,
            }),
        }
    }

    /// Enable DAITA traffic shaping on this engine. Must be called before [`Self::run`] or
    /// [`Self::handle`] (while the engine still uniquely owns its shared state). Use
    /// [`Daita::shaping`]/[`Daita::client`] on the client to shape egress at a constant
    /// rate with cover traffic, and [`Daita::framing`]/[`Daita::server`] on the peer that
    /// only needs to speak the cell framing. DAITA requires a stealth transport (the cells
    /// ride inside the obfs frame).
    pub fn with_daita(mut self, daita: Daita) -> Self {
        Arc::get_mut(&mut self.shared)
            .expect("with_daita must be called before handle()/run()")
            .daita = Some(Arc::new(daita));
        self
    }

    /// A handle for adding/removing peers while the engine runs.
    pub fn handle(&self) -> EngineHandle<T> {
        EngineHandle {
            shared: self.shared.clone(),
        }
    }

    /// Run the three data-plane tasks until one of them fails.
    pub async fn run(self) -> std::io::Result<()> {
        let shared = self.shared;

        // If a handshake rate limiter is configured (server), tick its reset once a
        // second per the WireGuard spec so the cookie challenge window advances.
        if let Some(rl) = shared.table.read().unwrap().rate_limiter() {
            tokio::spawn(async move {
                let mut tick = interval(Duration::from_secs(1));
                loop {
                    tick.tick().await;
                    rl.reset_count();
                }
            });
        }

        // Proactively initiate handshakes toward any peer we have an endpoint for
        // (i.e. the client dialing its server) so the tunnel comes up before user
        // traffic and keepalives start flowing.
        Self::init_handshakes(&shared).await;

        // If DAITA shaping is on (client), drive the constant-rate cell stream: one cell
        // per slot, cover when idle. Detached like the timer/limiter tasks.
        if let Some(daita) = shared.daita.clone() {
            if daita.shape_egress {
                tokio::spawn(Self::shaper_loop(shared.clone(), daita));
            }
        }

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
        let peers = shared.table.read().unwrap().snapshot();
        for (id, peer) in peers {
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
                debug!(peer = %PublicKey(id).to_base64(), %endpoint, "initiating handshake");
                let _ = Self::send_egress(shared, d, endpoint).await;
            }
        }
    }

    /// Send one WireGuard datagram toward a peer, applying DAITA if enabled:
    ///   * shaping (client): enqueue for the constant-rate shaper (`endpoint` is ignored;
    ///     the shaper sends to the single peer's endpoint each slot);
    ///   * framing (server): wrap as a fixed-size real cell and send now;
    ///   * no DAITA: send the raw datagram.
    async fn send_egress(
        shared: &Arc<Shared<T>>,
        datagram: Vec<u8>,
        endpoint: SocketAddr,
    ) -> std::io::Result<()> {
        match shared.daita.as_deref() {
            Some(d) if d.shape_egress => {
                if !d.shaper.enqueue(datagram) {
                    trace!("daita: outbound datagram dropped (queue full or oversized)");
                }
                Ok(())
            }
            Some(d) => match oxide_daita::frame_real(&datagram, d.cell_size) {
                Some(cell) => shared.transport.send_to(&cell, endpoint).await.map(|_| ()),
                None => {
                    trace!("daita: datagram too large for a cell; dropping");
                    Ok(())
                }
            },
            None => shared
                .transport
                .send_to(&datagram, endpoint)
                .await
                .map(|_| ()),
        }
    }

    /// The DAITA shaper task (client): every slot, send exactly one cell — a queued real
    /// datagram if any, else a cover cell — to the single peer's endpoint. This is what
    /// makes the client→server flow a constant-rate, constant-size, contentless stream.
    async fn shaper_loop(shared: Arc<Shared<T>>, daita: Arc<Daita>) {
        let mut tick = interval(daita.slot);
        loop {
            tick.tick().await;
            // v1 targets the single-peer client: find the one peer we have an endpoint for.
            let endpoint = shared
                .table
                .read()
                .unwrap()
                .snapshot()
                .into_iter()
                .find_map(|(_, p)| p.endpoint());
            let Some(ep) = endpoint else {
                // No endpoint yet (not configured/learned) — nothing to send toward.
                continue;
            };
            let cell = daita.shaper.next_cell();
            let _ = shared.transport.send_to(&cell, ep).await;
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
            let Some(peer) = shared.table.read().unwrap().route(dst) else {
                trace!(%dst, "no peer owns destination; dropping");
                continue;
            };

            let (datagram, endpoint) = {
                let mut out = [0u8; MAX_PKT];
                let mut tunn = peer.tunn.lock().unwrap();
                match tunn.encapsulate(packet, &mut out) {
                    TunnResult::WriteToNetwork(d) => (Some(d.to_vec()), peer.endpoint()),
                    TunnResult::Done => (None, None),
                    TunnResult::Err(e) => {
                        warn!(?e, "encapsulate error");
                        (None, None)
                    }
                    _ => (None, None),
                }
            };

            match (datagram, endpoint) {
                (Some(d), Some(ep)) => {
                    Self::send_egress(&shared, d, ep).await?;
                }
                (Some(_), None) => {
                    trace!("have datagram but no endpoint yet; dropping");
                }
                _ => {}
            }
        }
    }

    async fn inbound_loop(shared: Arc<Shared<T>>) -> std::io::Result<()> {
        let mut buf = [0u8; MAX_PKT];
        loop {
            let (n, src) = shared.transport.recv_from(&mut buf).await?;
            // Under DAITA, each datagram is a cell: unwrap a real WireGuard datagram, or
            // drop a cover cell (and any malformed cell) before boringtun ever sees it.
            let datagram = match shared.daita.as_deref() {
                Some(_) => match oxide_daita::parse(&buf[..n]) {
                    Some(oxide_daita::Cell::Real(wg)) => wg,
                    Some(oxide_daita::Cell::Cover) => continue,
                    None => continue,
                },
                None => buf[..n].to_vec(),
            };
            Self::handle_incoming(&shared, datagram, src).await;
        }
    }

    /// Decapsulate one datagram and act on the result. Tries the cached peer for
    /// `src` first, falling back to every peer (a handshake from a new endpoint has
    /// no cache entry yet). The first peer that decapsulates without error owns it.
    async fn handle_incoming(shared: &Arc<Shared<T>>, datagram: Vec<u8>, src: SocketAddr) {
        let candidates: Vec<(PeerId, Arc<Peer>)> = {
            let cached = shared.addr_to_peer.lock().unwrap().get(&src).copied();
            let table = shared.table.read().unwrap();
            match cached.and_then(|id| table.get(&id).map(|p| (id, p))) {
                Some(hit) => vec![hit],
                None => table.snapshot(),
            }
        };

        for (id, peer) in candidates {
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
                        if shared.table.read().unwrap().source_ok(addr.into(), &id) {
                            to_tun = Some(pkt.to_vec());
                        } else {
                            warn!(%addr, "inbound source not in allowed_ips; dropping");
                        }
                    }
                    TunnResult::WriteToTunnelV6(pkt, addr) => {
                        if shared.table.read().unwrap().source_ok(addr.into(), &id) {
                            to_tun = Some(pkt.to_vec());
                        } else {
                            warn!(%addr, "inbound source not in allowed_ips; dropping");
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
                debug!(peer = %PublicKey(id).to_base64(), %src, "learned/updated peer endpoint");
            }
            shared.addr_to_peer.lock().unwrap().insert(src, id);

            for d in to_network {
                let _ = Self::send_egress(shared, d, src).await;
            }
            if let Some(pkt) = to_tun {
                if let Err(e) = shared.tun.send(&pkt).await {
                    warn!(?e, "tun write failed");
                }
            }
            return;
        }
    }

    async fn timer_loop(shared: Arc<Shared<T>>) -> std::io::Result<()> {
        let mut tick = interval(TIMER_TICK);
        loop {
            tick.tick().await;
            let peers = shared.table.read().unwrap().snapshot();
            for (_id, peer) in peers {
                let datagram = {
                    let mut buf = [0u8; MAX_PKT];
                    let mut tunn = peer.tunn.lock().unwrap();
                    match tunn.update_timers(&mut buf) {
                        TunnResult::WriteToNetwork(d) => Some(d.to_vec()),
                        TunnResult::Err(e) => {
                            debug!(?e, "timer tick error (likely connection reset)");
                            None
                        }
                        _ => None,
                    }
                };
                if let Some(d) = datagram {
                    if let Some(ep) = peer.endpoint() {
                        let _ = Self::send_egress(&shared, d, ep).await;
                    }
                }
            }
        }
    }
}

impl<T: TunQueue> EngineHandle<T> {
    /// Add a peer (no-op if its public key is already present).
    pub fn add_peer(&self, params: PeerParams) {
        self.shared.table.write().unwrap().add(params);
    }

    /// Remove a peer by public key and forget any cached endpoint mapping for it.
    pub fn remove_peer(&self, public_key: &PublicKey) {
        let id = public_key.0;
        self.shared.table.write().unwrap().remove(&id);
        self.shared
            .addr_to_peer
            .lock()
            .unwrap()
            .retain(|_, v| *v != id);
    }

    /// Current load and throughput: peer counts plus total bytes tx/rx across peers.
    pub fn stats(&self) -> EngineStats {
        let peers = self.shared.table.read().unwrap().snapshot();
        let total_peers = peers.len();
        let mut active_peers = 0;
        let mut tx_bytes = 0u64;
        let mut rx_bytes = 0u64;
        for (_, p) in &peers {
            let (since, tx, rx, _, _) = p.tunn.lock().unwrap().stats();
            if matches!(since, Some(d) if d < ACTIVE_WINDOW) {
                active_peers += 1;
            }
            tx_bytes += tx as u64;
            rx_bytes += rx as u64;
        }
        EngineStats {
            total_peers,
            active_peers,
            tx_bytes,
            rx_bytes,
        }
    }

    /// Reconcile the peer set to exactly `desired`: add newcomers, remove absentees,
    /// and leave existing peers (and their live sessions) untouched.
    pub fn reconcile(&self, desired: Vec<PeerParams>) {
        let desired_ids: std::collections::HashSet<PeerId> =
            desired.iter().map(|p| p.public_key.0).collect();

        let current = self.shared.table.read().unwrap().ids();
        for id in current {
            if !desired_ids.contains(&id) {
                self.remove_peer(&PublicKey(id));
            }
        }
        let mut table = self.shared.table.write().unwrap();
        for p in desired {
            table.add(p);
        }
    }
}
