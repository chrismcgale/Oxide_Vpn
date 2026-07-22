//! Decoy-forwarding: make an Oxide server byte-for-byte indistinguishable from an ordinary
//! QUIC/HTTP-3 endpoint under **active probing**.
//!
//! The authenticated QUIC Initial (see [`oxide_mimicry::quic`]) already makes forged, stale,
//! and replayed Initials get *no response* — the port looks dead to a prober. But *silence
//! itself* can be a weak signal: a real QUIC server answers a well-formed Initial (with a
//! handshake or a Retry), so a port that never answers *anything* is at least suspicious.
//!
//! Decoy-forwarding closes that gap. Instead of dropping an unauthenticated first-contact
//! datagram, the server **splices that source to a configured decoy backend** — ideally a
//! real TLS/QUIC site co-hosted on the box — and relays both directions transparently. The
//! prober's crafted Initial reaches a genuine server and comes back with a genuine response,
//! so the port answers exactly like the ordinary web endpoint it is pretending to be. A
//! source classified as a prober stays spliced for the flow's lifetime.
//!
//! Mechanically this is the [`oxide_relay`] pattern, triggered by an auth failure rather
//! than a routing table: one private upstream UDP socket per prober source, and a pump task
//! that copies backend replies back to the prober **through the main listen socket**, so the
//! answer appears to come from the server's own port. Pure tokio UDP; no root.
//!
//! Threat model: the disguise is strongest when `backend` is a *real* service you actually
//! host (so the response is a genuine one for that endpoint). Caveats: our mimicry Initial
//! is not a byte-perfect QUIC Initial, so a strict backend may reject it (still a *response*,
//! just an error one); and a global observer could in principle compare timing/behaviour of
//! authenticated vs decoyed flows. This defeats the common case — an active prober poking the
//! port to distinguish a circumvention server from a web server.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, warn};

const BUF: usize = 2048;
/// Drop a prober's decoy flow after this much inactivity (bounds state under a probe flood).
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// How often to sweep idle flows.
const REAP_INTERVAL: Duration = Duration::from_secs(30);

struct Flow {
    upstream: Arc<UdpSocket>,
    pump: tokio::task::AbortHandle,
    last_seen: Instant,
}

impl Drop for Flow {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

/// Proxies unauthenticated first-contact traffic to a real backend so the server answers
/// like an ordinary QUIC/HTTP-3 endpoint. Held behind an `Arc` by the transport.
pub struct DecoyForwarder {
    /// The server's main listen socket — decoy responses go back out through it, so a
    /// prober sees answers from the server's own port.
    listen: Arc<UdpSocket>,
    /// The decoy backend to splice probers to (a real TLS/QUIC service is ideal).
    backend: SocketAddr,
    flows: Arc<Mutex<HashMap<SocketAddr, Flow>>>,
}

impl DecoyForwarder {
    /// Create a forwarder over the given listen socket and backend, and start the idle-flow
    /// reaper. `listen` must be the same socket the transport receives on.
    pub fn new(listen: Arc<UdpSocket>, backend: SocketAddr) -> Arc<Self> {
        let flows: Arc<Mutex<HashMap<SocketAddr, Flow>>> = Arc::new(Mutex::new(HashMap::new()));
        spawn_reaper(flows.clone());
        Arc::new(DecoyForwarder {
            listen,
            backend,
            flows,
        })
    }

    /// Whether `src` has already been classified as a prober (has a live decoy flow), so the
    /// transport keeps forwarding it instead of trying to authenticate it again.
    pub async fn is_decoy(&self, src: &SocketAddr) -> bool {
        self.flows.lock().await.contains_key(src)
    }

    /// Forward one datagram from a prober `src` to the decoy backend, opening the flow (and
    /// its reply pump) on first contact.
    pub async fn forward(&self, datagram: &[u8], src: SocketAddr) {
        let upstream = {
            let mut map = self.flows.lock().await;
            match map.get_mut(&src) {
                Some(flow) => {
                    flow.last_seen = Instant::now();
                    flow.upstream.clone()
                }
                None => match self.new_flow(src, &mut map).await {
                    Some(up) => up,
                    None => return,
                },
            }
        };
        if let Err(e) = upstream.send(datagram).await {
            warn!(%src, ?e, "decoy: forward to backend failed");
        }
    }

    /// Open a private upstream socket to the backend for `src` and spawn a pump copying the
    /// backend's replies back to `src` through the listen socket.
    async fn new_flow(
        &self,
        src: SocketAddr,
        map: &mut HashMap<SocketAddr, Flow>,
    ) -> Option<Arc<UdpSocket>> {
        let upstream = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                warn!(?e, "decoy: upstream bind failed");
                return None;
            }
        };
        if let Err(e) = upstream.connect(self.backend).await {
            warn!(backend = %self.backend, ?e, "decoy: upstream connect failed");
            return None;
        }
        let upstream = Arc::new(upstream);

        let listen = self.listen.clone();
        let up = upstream.clone();
        let pump = tokio::spawn(async move {
            let mut b = [0u8; BUF];
            // Reply through the LISTEN socket so the prober sees the server's own port.
            while let Ok(m) = up.recv(&mut b).await {
                let _ = listen.send_to(&b[..m], src).await;
            }
        });

        map.insert(
            src,
            Flow {
                upstream: upstream.clone(),
                pump: pump.abort_handle(),
                last_seen: Instant::now(),
            },
        );
        debug!(%src, backend = %self.backend, "decoy: unauthenticated source spliced to backend");
        Some(upstream)
    }
}

fn spawn_reaper(flows: Arc<Mutex<HashMap<SocketAddr, Flow>>>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(REAP_INTERVAL);
        loop {
            tick.tick().await;
            // Dropping a Flow aborts its pump task.
            flows
                .lock()
                .await
                .retain(|_, flow| flow.last_seen.elapsed() < IDLE_TIMEOUT);
        }
    });
}
