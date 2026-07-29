//! Shared client tunnel logic, used by both the `oxide-client` CLI and the privileged
//! `oxide-agentd`.
//!
//! Two phases:
//!   * [`resolve_connection`] — talk to the control plane (select server, post-quantum
//!     encapsulation, device registration) and produce a local interface config + peer.
//!     No privileges needed.
//!   * [`run_tunnel`] — bring up the TUN device, install routing/kill-switch/DNS, run the
//!     engine until a caller-supplied `stop` future resolves, then tear everything down.
//!     Requires `CAP_NET_ADMIN`. A `on_ready` callback hands back the [`EngineHandle`] so
//!     a supervisor (the agent) can read live stats.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ipnet::IpNet;
use tracing::{debug, info, warn};

use oxide_common::api::RegisterDeviceResponse;
use oxide_common::{keys, InterfaceConfig, PublicKey, SecretKey, TransportKind};
use oxide_control_client::ControlClient;
use oxide_net::{bring_up_interface, dns, killswitch, netlink, Netlink, TunDevice};
use oxide_wg_core::{Daita, Engine, EngineHandle, MimicTransport, PeerParams, Transport};

pub mod latency;
pub mod reconnect;
pub mod split;
pub use reconnect::{ConnEvent, ConnInfo, ReconnectPolicy, TunnelOutcome};

/// The tunnel interface name.
pub const IFNAME: &str = "oxide0";

/// A control-plane connection request.
#[derive(Debug, Clone)]
pub struct ConnectRequest {
    pub control_plane: String,
    pub account: String,
    /// Explicit single-hop server id (else auto-select).
    pub server: Option<String>,
    /// Multihop exit id (implies multihop).
    pub exit: Option<String>,
    /// Multihop entry id (else auto-selected).
    pub entry: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub key_file: PathBuf,
    pub mtu: Option<u32>,
    /// Server ids to avoid when auto-selecting (used on reconnect to skip a just-failed
    /// server). Ignored when an explicit `server`/`exit` is set.
    pub exclude: Vec<String>,
    /// If set (and the connection is post-quantum + single-hop), rotate the PQ-derived PSK on
    /// this interval for forward secrecy — re-encapsulate to the server's PQ key, re-register
    /// the fresh ciphertext, and swap the peer's PSK in place (no reconnect). `None` = off.
    pub rekey_interval: Option<Duration>,
}

/// The resolved local config for a connection.
pub struct Resolved {
    pub iface: InterfaceConfig,
    pub peers: Vec<PeerParams>,
    pub server_id: Option<String>,
    pub exit_id: Option<String>,
    /// The server's post-quantum public key (base64), if it runs PQ — kept so the rekey driver
    /// can re-encapsulate to it. Only populated for single-hop (rekey targets single-hop).
    pub pq_public_key: Option<String>,
}

impl Resolved {
    pub fn stealth(&self) -> bool {
        self.iface.obfuscation_key.is_some()
    }
    pub fn post_quantum(&self) -> bool {
        self.peers.iter().any(|p| p.preshared_key.is_some())
    }
    pub fn assigned_ip(&self) -> String {
        self.iface.address.to_string()
    }
}

/// Resolve a connection via the control plane (no privileges required).
pub async fn resolve_connection(req: &ConnectRequest) -> Result<Resolved> {
    let account = req.account.replace(' ', "");
    let device_key = load_or_create_key(&req.key_file)?;
    let device_pub = keys::public_from_secret(&device_key);
    let cc = ControlClient::new(&req.control_plane);

    // The single-hop server's PQ public key (base64), captured so the rekey driver can
    // re-encapsulate. `None` for multihop (rekey targets single-hop in v1).
    let (reg, psk, server_id, exit_id, pq_public_key) = if let Some(exit_id) = &req.exit {
        let entry_id = match &req.entry {
            Some(e) => e.clone(),
            None => pick_entry(&cc, &account, exit_id).await?,
        };
        info!(entry = %entry_id, exit = %exit_id, "multihop path");
        let (pq_ct, psk) = match cc
            .list_servers(&account)
            .await
            .context("listing servers")?
            .into_iter()
            .find(|s| &s.id == exit_id)
            .and_then(|s| s.pq_public_key)
        {
            Some(pk_b64) => {
                let pk = B64.decode(&pk_b64).context("bad PQ public key")?;
                let (ct, shared) =
                    oxide_pq::encapsulate(&pk).context("post-quantum encapsulation failed")?;
                info!("post-quantum handshake enabled (multihop)");
                (Some(B64.encode(ct)), Some(shared))
            }
            None => (None, None),
        };
        let reg = cc
            .register_device_multihop(&account, device_pub, &entry_id, exit_id, pq_ct.as_deref())
            .await
            .context("registering device (multihop)")?;
        (reg, psk, None, Some(exit_id.clone()), None)
    } else {
        let chosen = match &req.server {
            Some(id) => cc
                .list_servers(&account)
                .await
                .context("listing servers")?
                .into_iter()
                .find(|s| &s.id == id)
                .with_context(|| format!("no such server: {id}"))?,
            None if req.exclude.is_empty() => cc
                .best_server(&account, req.country.as_deref(), req.city.as_deref())
                .await
                .context("selecting best server")?,
            // On reconnect we avoid the just-failed server(s): pick client-side from the list.
            None => {
                let servers = cc.list_servers(&account).await.context("listing servers")?;
                reconnect::select_best(
                    &servers,
                    req.country.as_deref(),
                    req.city.as_deref(),
                    &req.exclude,
                )
                .cloned()
                .context("no healthy server available (all excluded / down)")?
            }
        };
        info!(server = %chosen.id, endpoint = %chosen.endpoint, "selected server");
        let (pq_ct, psk) = match &chosen.pq_public_key {
            Some(pk_b64) => {
                let pk = B64.decode(pk_b64).context("bad PQ public key")?;
                let (ct, shared) =
                    oxide_pq::encapsulate(&pk).context("post-quantum encapsulation failed")?;
                info!("post-quantum handshake enabled");
                (Some(B64.encode(ct)), Some(shared))
            }
            None => (None, None),
        };
        let id = chosen.id.clone();
        let server_pq = chosen.pq_public_key.clone();
        let reg = cc
            .register_device(&account, device_pub, &id, pq_ct.as_deref())
            .await
            .context("registering device")?;
        (reg, psk, Some(id), None, server_pq)
    };
    info!(assigned_ip = %reg.assigned_ip, endpoint = %reg.server.endpoint, "device registered");

    let (iface, peer) = resolve_registration(device_key, &reg, req.mtu, psk)?;
    Ok(Resolved {
        iface,
        peers: vec![peer],
        server_id,
        exit_id,
        pq_public_key,
    })
}

/// A mesh-join request (the private overlay of the account's own devices).
#[derive(Debug, Clone)]
pub struct MeshRequest {
    pub control_plane: String,
    pub account: String,
    /// The UDP endpoint (host:port) other mesh devices can reach this one at. If the
    /// port is 0, an ephemeral port is bound and its real number reported.
    pub endpoint: SocketAddr,
    pub key_file: PathBuf,
    pub mtu: Option<u32>,
}

/// Join the account's private mesh and resolve a local config: our mesh IP plus one
/// WireGuard peer per other device (each pinned to its mesh `/32`). No privileges needed.
///
/// Unlike [`resolve_connection`], no peer carries a default route — the interface holds
/// the mesh subnet (`address` is a `/16`), so only mesh traffic crosses the tunnel and
/// normal internet egress is untouched. This is the "Tailscale, but actually private"
/// side of the hybrid; combine with a `connect` for an anonymous exit.
pub async fn resolve_mesh(req: &MeshRequest) -> Result<Resolved> {
    let account = req.account.replace(' ', "");
    let device_key = load_or_create_key(&req.key_file)?;
    let device_pub = keys::public_from_secret(&device_key);
    let cc = ControlClient::new(&req.control_plane);

    let reg = cc
        .mesh_register(&account, device_pub, &req.endpoint.to_string())
        .await
        .context("registering device in mesh")?;
    let address: IpNet = reg
        .mesh_ip
        .parse()
        .with_context(|| format!("bad mesh_ip from control plane: {}", reg.mesh_ip))?;
    info!(mesh_ip = %address, peers = reg.peers.len(), "joined mesh");

    let mut peers = Vec::with_capacity(reg.peers.len());
    for p in &reg.peers {
        if p.public_key == device_pub {
            continue; // never peer with ourselves
        }
        let peer_ip: IpAddr = p
            .mesh_ip
            .split('/')
            .next()
            .unwrap_or(&p.mesh_ip)
            .parse()
            .with_context(|| format!("bad mesh peer ip: {}", p.mesh_ip))?;
        let endpoint: SocketAddr = p
            .endpoint
            .parse()
            .with_context(|| format!("bad mesh peer endpoint: {}", p.endpoint))?;
        peers.push(PeerParams {
            public_key: p.public_key,
            preshared_key: None,
            endpoint: Some(endpoint),
            allowed_ips: vec![IpNet::from(peer_ip)],
            persistent_keepalive: Some(25),
        });
    }

    let iface = InterfaceConfig {
        private_key: device_key,
        address,
        address6: None,
        listen_port: Some(req.endpoint.port()),
        mtu: req.mtu,
        dns: None,
        obfuscation_key: None,
        pq_private_seed: None,
        decoy_backend: None,
        transport: TransportKind::default(),
        daita: false,
        split_include: Vec::new(),
        split_exclude: Vec::new(),
    };
    Ok(Resolved {
        iface,
        peers,
        server_id: None,
        exit_id: None,
        pq_public_key: None, // mesh has no exit server to rekey against
    })
}

/// Auto-pick an entry server for multihop: the least-loaded server that isn't the exit.
pub async fn pick_entry(cc: &ControlClient, account: &str, exit_id: &str) -> Result<String> {
    if let Ok(b) = cc.best_server(account, None, None).await {
        if b.id != exit_id {
            return Ok(b.id);
        }
    }
    cc.list_servers(account)
        .await
        .context("listing servers for entry selection")?
        .into_iter()
        .find(|s| s.id != exit_id)
        .map(|s| s.id)
        .context("no server available to act as a multihop entry")
}

/// Turn a control-plane registration into a local interface config + server peer.
pub fn resolve_registration(
    device_key: SecretKey,
    reg: &RegisterDeviceResponse,
    mtu: Option<u32>,
    psk: Option<[u8; 32]>,
) -> Result<(InterfaceConfig, PeerParams)> {
    let address: IpNet = reg
        .assigned_ip
        .parse()
        .with_context(|| format!("bad assigned_ip: {}", reg.assigned_ip))?;
    let endpoint: SocketAddr = reg
        .server
        .endpoint
        .parse()
        .with_context(|| format!("bad server endpoint: {}", reg.server.endpoint))?;

    let obfuscation_key = match &reg.obfuscation_key {
        Some(k) => Some(
            k.parse()
                .context("bad obfuscation key from control plane")?,
        ),
        None => None,
    };
    // The server tells us which transport it expects; an unknown/absent value falls back to
    // the config back-compat rule (obfs if a key is present, else plain) via `transport_kind`.
    let transport = match reg.transport.as_deref() {
        Some("plain") => TransportKind::Plain,
        Some("obfs") => TransportKind::Obfs,
        Some("quic") => TransportKind::Quic,
        Some("mimic") => TransportKind::Mimic,
        _ => TransportKind::default(),
    };
    let iface = InterfaceConfig {
        private_key: device_key,
        address,
        address6: None,
        listen_port: None,
        mtu,
        dns: reg.dns.as_ref().and_then(|s| s.parse().ok()),
        obfuscation_key,
        pq_private_seed: None,
        decoy_backend: None,
        transport,
        daita: reg.daita,
        split_include: Vec::new(),
        split_exclude: Vec::new(),
    };
    let peer = PeerParams {
        public_key: reg.server.public_key,
        preshared_key: psk,
        endpoint: Some(endpoint),
        allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
        persistent_keepalive: Some(25),
    };
    Ok((iface, peer))
}

/// Bring up the interface, install routing/kill-switch/DNS, run the engine until `stop`
/// resolves, then tear everything down. `on_ready` receives the engine handle once it's
/// running (for live stats).
/// Build the client-side [`Transport`] the config selects. Stealth transports need the
/// shared `key`; the TLS-mimicry (TCP) transport connects to a peer's endpoint. The QUIC
/// transport is used without decoy-forwarding client-side (decoy is a server concern).
async fn build_client_transport(
    kind: TransportKind,
    bind_port: u16,
    peers: &[PeerParams],
    key: Option<[u8; 32]>,
) -> Result<Transport> {
    let req_key = || key.context("this transport requires interface.obfuscation_key");
    // Dual-stack bind ([::]:port, IPV6_V6ONLY off) so the client can dial a v4 or v6 server
    // endpoint from one socket (falls back to 0.0.0.0 if IPv6 is disabled).
    let bind_udp = || async {
        let std_sock =
            oxide_net::bind_dual_stack(bind_port).context("binding client UDP socket")?;
        tokio::net::UdpSocket::from_std(std_sock).context("binding client UDP socket")
    };
    match kind {
        TransportKind::Plain => Ok(Transport::plain(bind_udp().await?)),
        TransportKind::Obfs => {
            info!("stealth: obfuscated transport");
            Ok(Transport::obfuscated(bind_udp().await?, req_key()?))
        }
        TransportKind::Quic => {
            info!("stealth: QUIC mimicry");
            Ok(Transport::quic_mimic(bind_udp().await?, req_key()?))
        }
        TransportKind::Mimic => {
            let server = peers
                .iter()
                .find_map(|p| p.endpoint)
                .context("TLS-mimicry client needs a peer with an endpoint")?;
            info!(%server, "stealth: TLS mimicry (TCP)");
            let m = MimicTransport::connect(server, req_key()?)
                .await
                .context("connecting TLS-mimicry transport")?;
            Ok(Transport::mimic(m))
        }
    }
}

/// Resolve the original default gateway (and its egress ifindex) for `ip`'s address family,
/// so a route can be pinned around the tunnel through the correct-family gateway — a v6
/// endpoint/exclude must pin via the v6 default, not the v4 one.
async fn default_gw_for(nl: &Netlink, ip: IpAddr) -> Result<(IpAddr, u32)> {
    let v6 = ip.is_ipv6();
    let (gw, dev) = netlink::default_route_family(v6)?.with_context(|| {
        format!(
            "no {} default route found; cannot pin routes around the tunnel",
            if v6 { "IPv6" } else { "IPv4" }
        )
    })?;
    let dev_idx = nl
        .link_index(&dev)
        .await
        .context("resolving egress interface index")?;
    Ok((gw, dev_idx))
}

#[allow(clippy::too_many_arguments)]
pub async fn run_tunnel<Stop, Ready>(
    iface: &InterfaceConfig,
    peers: Vec<PeerParams>,
    kill_switch: bool,
    // Liveness watchdog policy. `Some` = detect a dead link and return `LinkDead` (used by
    // `run_supervised`); `None` = run until the engine ends or `stop` fires (mesh / static
    // `up`, where there's nothing to fail over to and a peerless mesh is legitimate).
    policy: Option<ReconnectPolicy>,
    stop: Stop,
    on_ready: Ready,
) -> Result<TunnelOutcome>
where
    Stop: Future<Output = ()>,
    Ready: FnOnce(EngineHandle<TunDevice>),
{
    let nl = Netlink::connect().context("opening netlink")?;
    let (tun, tun_idx) = bring_up_interface(&nl, IFNAME, iface)
        .await
        .context("bringing up tun interface")?;
    info!(iface = IFNAME, addr = %iface.address, mtu = iface.mtu(), "interface up");

    // Plan routing from the peers' allowed_ips + the interface's split config: which family
    // (if any) is full-tunnel, which CIDRs route via the tunnel (include), and which are
    // pinned around it (exclude). See `split::plan_routes`.
    let allowed: Vec<IpNet> = peers
        .iter()
        .flat_map(|p| p.allowed_ips.iter().copied())
        .collect();
    let plan = split::plan_routes(&allowed, &iface.split_include, &iface.split_exclude);
    // Fail before touching the routing table: the kill switch permits only the tunnel + the
    // server endpoint, so excluded CIDRs (which must reach the underlay) can't coexist.
    if kill_switch && !plan.via_gateway.is_empty() {
        anyhow::bail!(
            "--kill-switch is incompatible with split_exclude: excluded CIDRs route around \
             the tunnel and the kill switch would block them"
        );
    }

    let mut routed_v4 = false;
    let mut routed_v6 = false;
    let mut full_tunnel_endpoint: Option<SocketAddr> = None;
    let mut pinned: Option<(IpAddr, IpAddr, u32)> = None;
    // Split-tunnel routes we install, tracked so teardown removes exactly what we added.
    let mut tunnel_routes: Vec<IpNet> = Vec::new();
    let mut gateway_pins: Vec<(IpNet, IpAddr, u32)> = Vec::new();

    // Full-tunnel: pin the server endpoint via the current default gateway BEFORE swinging
    // the default, or the encrypted UDP would recurse into the tunnel. The gateway is
    // resolved for the endpoint's own family (a v6 endpoint pins via the v6 default).
    if plan.is_full_tunnel() {
        let endpoint = peers
            .iter()
            .find_map(|p| p.endpoint)
            .context("full-tunnel peer must have an endpoint")?;
        let (gw, dev_idx) = default_gw_for(&nl, endpoint.ip()).await?;
        nl.add_host_route_via(endpoint.ip(), gw, dev_idx)
            .await
            .context("pinning server endpoint route")?;
        if plan.full_tunnel_v4 {
            nl.set_default_v4_via_dev(tun_idx)
                .await
                .context("swinging IPv4 default into tunnel")?;
            routed_v4 = true;
        }
        if plan.full_tunnel_v6 {
            nl.set_default_v6_via_dev(tun_idx)
                .await
                .context("swinging IPv6 default into tunnel")?;
            routed_v6 = true;
        }
        info!(server = %endpoint.ip(), via = %gw, "default route swung into tunnel");
        full_tunnel_endpoint = Some(endpoint);
        pinned = Some((endpoint.ip(), gw, dev_idx));
    }

    // Include-mode CIDRs: route each on-link via the tunnel device. This is what used to
    // require a manual `ip route add <cidr> dev oxide0`.
    for cidr in &plan.via_tunnel {
        match nl.add_route_dev(*cidr, tun_idx).await {
            Ok(()) => {
                tunnel_routes.push(*cidr);
                info!(%cidr, "routed via tunnel (split include)");
            }
            // The interface subnet is auto-routed when its address is assigned; a duplicate
            // route is not an error we should fail the connect over.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                debug!(%cidr, "tunnel route already present; leaving it in place");
            }
            Err(e) => return Err(e).context("installing split-include tunnel route"),
        }
    }

    // Exclude-mode CIDRs: pin around the tunnel via the original default gateway of each
    // CIDR's own family (v6 excludes pin via the v6 default).
    for cidr in &plan.via_gateway {
        let (gw, dev_idx) = default_gw_for(&nl, cidr.addr()).await?;
        nl.add_route_via(*cidr, gw, dev_idx)
            .await
            .context("pinning split-exclude route")?;
        gateway_pins.push((*cidr, gw, dev_idx));
        info!(%cidr, via = %gw, "pinned around tunnel (split exclude)");
    }

    let dns_guard = match iface.dns {
        Some(d) => {
            let guard = dns::set_dns(IFNAME, &[d]).context("setting tunnel DNS")?;
            info!(dns = %d, backend = ?dns::detect_backend(), "tunnel DNS installed");
            Some(guard)
        }
        None => None,
    };

    if kill_switch {
        let ep = full_tunnel_endpoint
            .context("--kill-switch requires a full-tunnel (0.0.0.0/0) peer with an endpoint")?;
        killswitch::enable(ep.ip(), ep.port(), IFNAME).context("enabling kill switch")?;
        info!(server = %ep, "kill switch enabled");
    }

    let bind_port = iface.listen_port.unwrap_or(0);
    let kind = iface.transport_kind();
    if iface.daita && !kind.is_stealth() {
        anyhow::bail!("daita = true requires a stealth transport (obfs / quic / mimic)");
    }
    let key = iface.obfuscation_key.as_ref().map(|k| *k.as_bytes());
    let transport = build_client_transport(kind, bind_port, &peers, key).await?;

    let engine = Engine::build(&iface.private_key, peers, transport, tun);
    // DAITA (traffic-analysis defense): shape client egress to a constant rate + cover.
    let engine = if iface.daita {
        info!("DAITA enabled (client shaping mode)");
        engine.with_daita(Daita::client())
    } else {
        engine
    };
    let handle = engine.handle();
    on_ready(handle.clone());
    info!("connecting");

    // Liveness watchdog: resolves (yielding `was_up`) once the link is deemed dead, so a
    // supervisor can tear down and reconnect. Never fires while handshakes stay fresh; a
    // `None` policy disables it entirely (the future stays pending).
    let watchdog = {
        let handle = handle.clone();
        async move {
            let Some(policy) = policy else {
                return std::future::pending::<bool>().await;
            };
            let start = std::time::Instant::now();
            let mut ever_up = false;
            let mut tick = tokio::time::interval(policy.poll);
            loop {
                tick.tick().await;
                let s = handle.stats();
                if reconnect::is_up(&s, &policy) {
                    ever_up = true;
                }
                if reconnect::link_dead(&s, ever_up, start.elapsed(), &policy) {
                    return ever_up;
                }
            }
        }
    };

    let outcome = tokio::select! {
        r = engine.run() => { r.context("engine stopped")?; TunnelOutcome::Disconnected }
        _ = stop => { info!("shutting down"); TunnelOutcome::Disconnected }
        was_up = watchdog => {
            warn!("tunnel link is dead (no handshake); tearing down for reconnect");
            TunnelOutcome::LinkDead { was_up }
        }
    };

    // Teardown in reverse order.
    if kill_switch {
        if let Err(e) = killswitch::disable() {
            warn!(?e, "failed to remove kill switch");
        }
    }
    if let Some(guard) = dns_guard {
        dns::restore(guard);
    }
    for (cidr, gw, dev_idx) in &gateway_pins {
        let _ = nl.del_route_via(*cidr, *gw, *dev_idx).await;
    }
    for cidr in &tunnel_routes {
        let _ = nl.del_route_dev(*cidr, tun_idx).await;
    }
    if let Some((host, gw, dev_idx)) = pinned {
        let _ = nl.del_host_route_via(host, gw, dev_idx).await;
    }
    if routed_v4 || routed_v6 {
        nl.clear_default_via_dev(tun_idx, routed_v6).await;
    }
    Ok(outcome)
}

/// Everything the rekey driver needs to rotate the PQ PSK on a live single-hop connection.
struct RekeyContext {
    control_plane: String,
    account: String,
    device_pub: PublicKey,
    server_id: String,
    /// The server's decoded PQ public key, to re-encapsulate against.
    server_pq_public_key: Vec<u8>,
    /// The peer to rotate — endpoint/allowed-ips/keepalive are preserved; only the PSK changes.
    peer: PeerParams,
}

/// Build the rekey context if this connection can rotate its PQ PSK: single-hop (`server_id`
/// set), the server runs PQ (`pq_public_key`), and the sole peer already uses a PSK. Returns
/// `None` otherwise (multihop, no PQ, or a mesh) — the driver simply won't run. Pure.
fn build_rekey_context(req: &ConnectRequest, resolved: &Resolved) -> Option<RekeyContext> {
    let server_id = resolved.server_id.clone()?;
    let server_pq_public_key = B64.decode(resolved.pq_public_key.as_ref()?).ok()?;
    // Single-peer client whose peer already has a PSK (post-quantum actually in use).
    let [peer] = resolved.peers.as_slice() else {
        return None;
    };
    peer.preshared_key?;
    Some(RekeyContext {
        control_plane: req.control_plane.clone(),
        account: req.account.replace(' ', ""),
        device_pub: keys::public_from_secret(&resolved.iface.private_key),
        server_id,
        server_pq_public_key,
        peer: peer.clone(),
    })
}

/// After pushing the new ciphertext, wait this long before swapping the local PSK. This lets the
/// **server apply the new PSK first** (it does so on its next control-plane poll), so when we
/// swap and our fresh handshake initiation goes out, the server already has the matching PSK and
/// answers immediately — instead of failing and waiting ~5s for boringtun's next retry (a long
/// data-plane blip). Our *current* session keeps carrying traffic during this grace. It should
/// comfortably exceed the server's poll interval; `rekey_interval` in turn should exceed this.
const REKEY_SERVER_GRACE: Duration = Duration::from_secs(3);

/// Rotate the PQ PSK every `interval`: re-encapsulate to the server's PQ key, push the fresh
/// ciphertext to the control plane, wait a grace so the server applies it first, then swap the
/// local peer's PSK in place — no reconnect, the TUN stays up. Runs for the tunnel's lifetime
/// (cancelled when the tunnel ends). A failed rotation is logged and retried next interval; the
/// current PSK keeps working meanwhile.
async fn rekey_loop(
    ctx: RekeyContext,
    handle_rx: tokio::sync::watch::Receiver<Option<EngineHandle<TunDevice>>>,
    interval: Duration,
) {
    let cc = ControlClient::new(&ctx.control_plane);
    let mut tick = tokio::time::interval(interval);
    tick.tick().await; // the first tick fires immediately; skip it
    loop {
        tick.tick().await;
        let Some(handle) = handle_rx.borrow().clone() else {
            continue; // engine not ready yet
        };
        let Some((ct, psk)) = oxide_pq::encapsulate(&ctx.server_pq_public_key) else {
            warn!("rekey: PQ encapsulation failed");
            continue;
        };
        if let Err(e) = cc
            .register_device(
                &ctx.account,
                ctx.device_pub,
                &ctx.server_id,
                Some(&B64.encode(&ct)),
            )
            .await
        {
            warn!(error = %e, "rekey: re-registration failed; keeping the current PSK");
            continue;
        }
        // Let the server pick up the new ciphertext and rotate first (see the grace note); the
        // current session keeps working until we swap.
        tokio::time::sleep(REKEY_SERVER_GRACE).await;
        let mut peer = ctx.peer.clone();
        peer.preshared_key = Some(psk);
        handle.replace_peer(peer);
        info!("rekey: rotated the post-quantum PSK");
    }
}

/// Run an **always-on** connection: resolve → tunnel → (on link death) re-select a
/// different server and reconnect, with capped backoff, until `stop` fires. This is the
/// classic-VPN reliability loop — it survives server death and network changes.
///
/// `stop` is a `watch` channel (send `true` to disconnect). `on_ready` is called with a
/// fresh [`EngineHandle`] on every (re)connect so a supervisor can read live stats;
/// `on_event` receives [`ConnEvent`]s for status display.
pub async fn run_supervised<Ready, Event>(
    mut req: ConnectRequest,
    kill_switch: bool,
    policy: ReconnectPolicy,
    mut stop: tokio::sync::watch::Receiver<bool>,
    new_identity: tokio::sync::watch::Receiver<u64>,
    on_ready: Ready,
    on_event: Event,
) -> Result<()>
where
    Ready: Fn(EngineHandle<TunDevice>) + Clone,
    Event: Fn(ConnEvent),
{
    let mut attempt: u32 = 0;
    // Servers that recently failed, with when — avoided until the cooldown lapses.
    let mut failed: Vec<(String, std::time::Instant)> = Vec::new();
    // The last new-identity generation we acted on, and the exit we left doing so (excluded
    // from the next selection so a "new identity" always lands on a different server).
    let mut id_gen = *new_identity.borrow();
    let mut identity_exclude: Option<String> = None;

    loop {
        if *stop.borrow() {
            break;
        }
        failed.retain(|(_, t)| t.elapsed() < policy.server_cooldown);
        let mut exclude: Vec<String> = failed.iter().map(|(id, _)| id.clone()).collect();
        if let Some(s) = &identity_exclude {
            if !exclude.contains(s) {
                exclude.push(s.clone());
            }
        }
        req.exclude = exclude;

        on_event(ConnEvent::Selecting);
        let resolved = match resolve_connection(&req).await {
            Ok(r) => r,
            Err(e) => {
                attempt = attempt.saturating_add(1);
                let wait = reconnect::backoff(attempt, &policy);
                warn!(error = %e, ?wait, "could not resolve a server; retrying");
                if sleep_or_stop(wait, &mut stop).await {
                    break;
                }
                continue;
            }
        };
        let server = resolved
            .server_id
            .clone()
            .or_else(|| resolved.exit_id.clone())
            .unwrap_or_default();
        on_event(ConnEvent::Connecting(ConnInfo {
            server_id: resolved.server_id.clone(),
            exit_id: resolved.exit_id.clone(),
            assigned_ip: resolved.assigned_ip(),
            stealth: resolved.stealth(),
            post_quantum: resolved.post_quantum(),
            transport: resolved.iface.transport_kind().label().to_string(),
            daita: resolved.iface.daita,
        }));

        // Tear the tunnel down on either a stop or a new-identity request; the two are told
        // apart afterward by re-reading `stop` / the identity generation.
        let teardown = {
            let stop = stop.clone();
            let ni = new_identity.clone();
            async move {
                tokio::select! {
                    _ = reconnect::stopped(stop) => {}
                    _ = reconnect::signalled(ni, id_gen) => {}
                }
            }
        };
        // Optional PQ-PSK rotation for this connection. The driver runs alongside the tunnel and
        // is cancelled when the tunnel ends; it needs the engine handle, so wrap `on_ready` to
        // publish it into a watch channel the driver reads.
        let rekey_ctx = req
            .rekey_interval
            .and_then(|_| build_rekey_context(&req, &resolved));
        let (handle_tx, handle_rx) =
            tokio::sync::watch::channel::<Option<EngineHandle<TunDevice>>>(None);
        let on_ready_attempt = {
            let outer = on_ready.clone();
            move |h: EngineHandle<TunDevice>| {
                let _ = handle_tx.send(Some(h.clone()));
                outer(h);
            }
        };
        let outcome = match (rekey_ctx, req.rekey_interval) {
            (Some(ctx), Some(interval)) => {
                tokio::select! {
                    o = run_tunnel(&resolved.iface, resolved.peers, kill_switch, Some(policy), teardown, on_ready_attempt) => o?,
                    _ = rekey_loop(ctx, handle_rx, interval) => {
                        unreachable!("rekey loop runs until the tunnel future cancels it")
                    }
                }
            }
            _ => {
                run_tunnel(
                    &resolved.iface,
                    resolved.peers,
                    kill_switch,
                    Some(policy),
                    teardown,
                    on_ready_attempt,
                )
                .await?
            }
        };

        match outcome {
            TunnelOutcome::Disconnected => {
                if *stop.borrow() {
                    on_event(ConnEvent::Stopped);
                    break;
                }
                // Not a stop: a new-identity request tore the tunnel down. Rotate the device
                // key, exclude the exit we just left, and loop to reconnect elsewhere.
                let gen = *new_identity.borrow();
                if gen == id_gen {
                    // No stop and no new generation — nothing to reconnect to; treat as stop.
                    on_event(ConnEvent::Stopped);
                    break;
                }
                id_gen = gen;
                let (_key, excl) = rotate_identity(
                    &req.key_file,
                    (!server.is_empty()).then_some(server.as_str()),
                )?;
                identity_exclude = excl.into_iter().next();
                attempt = 0;
                on_event(ConnEvent::NewIdentity);
            }
            TunnelOutcome::LinkDead { was_up } => {
                if !server.is_empty() {
                    failed.push((server.clone(), std::time::Instant::now()));
                }
                // A session that was established and dropped retries promptly; one that never
                // connected backs off progressively (the endpoint may be blocked/down).
                attempt = if was_up { 1 } else { attempt.saturating_add(1) };
                let wait = reconnect::backoff(attempt, &policy);
                on_event(ConnEvent::Reconnecting { server, wait });
                if sleep_or_stop(wait, &mut stop).await {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Sleep for `wait`, or return early (`true`) if `stop` fires first.
async fn sleep_or_stop(wait: Duration, stop: &mut tokio::sync::watch::Receiver<bool>) -> bool {
    if *stop.borrow() {
        return true;
    }
    tokio::select! {
        _ = tokio::time::sleep(wait) => false,
        _ = reconnect::stopped(stop.clone()) => true,
    }
}

/// Load the device private key from `path`, or generate and persist one (0600).
pub fn load_or_create_key(path: &Path) -> Result<SecretKey> {
    if path.exists() {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading key file {}", path.display()))?;
        return text.trim().parse().context("parsing device key");
    }
    let key = keys::generate_secret();
    std::fs::write(path, key.to_base64())
        .with_context(|| format!("writing key file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    info!(path = %path.display(), "generated new device key");
    Ok(key)
}

/// Generate a fresh device key and **atomically** replace the key file (0600), returning the
/// new key. Written to a sibling temp file then renamed, so a crash never leaves a truncated
/// key. Used by "new identity" to make each session cryptographically unlinkable from the last.
pub fn rotate_device_key(path: &Path) -> Result<SecretKey> {
    let key = keys::generate_secret();
    let tmp = path.with_extension("key.tmp");
    std::fs::write(&tmp, key.to_base64())
        .with_context(|| format!("writing new key file {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("replacing key file {}", path.display()))?;
    info!(path = %path.display(), "rotated device key (new identity)");
    Ok(key)
}

/// Perform a "new identity": rotate the device key (see [`rotate_device_key`]) and return the
/// new key together with the exclude set that forces the *next* server selection onto a
/// different exit than `current_server`. Only the just-left server is excluded, so repeated
/// switches can't exhaust the pool. A fresh key means the new device registers as unrelated
/// to the old one — Tor-style "new circuit" unlinkability.
pub fn rotate_identity(
    key_file: &Path,
    current_server: Option<&str>,
) -> Result<(SecretKey, Vec<String>)> {
    let key = rotate_device_key(key_file)?;
    let excludes = current_server
        .filter(|s| !s.is_empty())
        .map(|s| vec![s.to_string()])
        .unwrap_or_default();
    Ok((key, excludes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxide_common::api::ServerConnection;

    #[test]
    fn resolve_registration_builds_full_tunnel_peer() {
        let device = keys::generate_secret();
        let server_pub = keys::public_from_secret(&keys::generate_secret());
        let reg = RegisterDeviceResponse {
            assigned_ip: "10.8.0.5/24".into(),
            server: ServerConnection {
                public_key: server_pub,
                endpoint: "203.0.113.7:51820".into(),
                tunnel_ip: "10.8.0.1".into(),
            },
            dns: Some("10.8.0.1".into()),
            obfuscation_key: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into()),
            transport: Some("quic".into()),
            daita: true,
        };

        let (iface, peer) =
            resolve_registration(device, &reg, Some(1400), Some([9u8; 32])).unwrap();
        assert_eq!(peer.preshared_key, Some([9u8; 32]));
        assert_eq!(iface.address.to_string(), "10.8.0.5/24");
        assert_eq!(iface.mtu(), 1400);
        assert!(iface.obfuscation_key.is_some());
        // 2A-2: the control-plane transport choice flows into the interface config.
        assert_eq!(iface.transport_kind(), TransportKind::Quic);
        assert!(iface.daita);
        assert_eq!(peer.endpoint.unwrap().to_string(), "203.0.113.7:51820");
        assert!(peer
            .allowed_ips
            .iter()
            .any(|n| matches!(n, IpNet::V4(v) if v.prefix_len() == 0)));
    }

    #[test]
    fn rekey_context_built_only_for_single_hop_pq() {
        let server_pub = keys::public_from_secret(&keys::generate_secret());
        let reg = RegisterDeviceResponse {
            assigned_ip: "10.8.0.5/24".into(),
            server: ServerConnection {
                public_key: server_pub,
                endpoint: "203.0.113.7:51820".into(),
                tunnel_ip: "10.8.0.1".into(),
            },
            dns: None,
            obfuscation_key: None,
            transport: None,
            daita: false,
        };
        let req = ConnectRequest {
            control_plane: "http://cp".into(),
            account: "1234 5678 9012 3456".into(),
            server: Some("us-1".into()),
            exit: None,
            entry: None,
            country: None,
            city: None,
            key_file: "device.key".into(),
            mtu: None,
            exclude: Vec::new(),
            rekey_interval: Some(Duration::from_secs(60)),
        };
        let pq_b64 = B64.encode([7u8; 32]);
        let resolved = |psk: Option<[u8; 32]>, server_id: Option<&str>, pq: Option<String>| {
            let (iface, peer) =
                resolve_registration(keys::generate_secret(), &reg, None, psk).unwrap();
            Resolved {
                iface,
                peers: vec![peer],
                server_id: server_id.map(str::to_string),
                exit_id: None,
                pq_public_key: pq,
            }
        };

        // Single-hop + PQ (peer has a PSK) + server PQ key → a context.
        let ctx = build_rekey_context(
            &req,
            &resolved(Some([9u8; 32]), Some("us-1"), Some(pq_b64.clone())),
        )
        .expect("single-hop PQ should build a rekey context");
        assert_eq!(ctx.server_id, "us-1");
        assert_eq!(ctx.account, "1234567890123456"); // spaces stripped
        assert_eq!(ctx.server_pq_public_key, [7u8; 32]);
        assert_eq!(ctx.peer.preshared_key, Some([9u8; 32]));

        // No PSK (not post-quantum) → no rekey.
        assert!(
            build_rekey_context(&req, &resolved(None, Some("us-1"), Some(pq_b64.clone())))
                .is_none()
        );
        // No server PQ key → no rekey.
        assert!(
            build_rekey_context(&req, &resolved(Some([9u8; 32]), Some("us-1"), None)).is_none()
        );
        // Multihop (no single-hop server_id) → no rekey.
        assert!(
            build_rekey_context(&req, &resolved(Some([9u8; 32]), None, Some(pq_b64))).is_none()
        );
    }

    #[test]
    fn new_identity_rotates_key_and_excludes_prior_exit() {
        let dir = std::env::temp_dir().join(format!("oxide-newid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key_file = dir.join("device.key");

        // Start from a known device key.
        let original = load_or_create_key(&key_file).unwrap();
        let original_pub = keys::public_from_secret(&original);

        // New identity away from exit "us-3".
        let (new_key, exclude) = rotate_identity(&key_file, Some("us-3")).unwrap();
        let new_pub = keys::public_from_secret(&new_key);

        // Fresh key (unlinkable), persisted to the file, and the prior exit is excluded.
        assert_ne!(
            new_pub.to_base64(),
            original_pub.to_base64(),
            "key must change"
        );
        let on_disk = load_or_create_key(&key_file).unwrap();
        assert_eq!(
            keys::public_from_secret(&on_disk).to_base64(),
            new_pub.to_base64(),
            "rotated key must be the one persisted"
        );
        assert_eq!(exclude, vec!["us-3".to_string()]);

        // With no current server (never connected), the exclude set is empty.
        let (_k, empty) = rotate_identity(&key_file, None).unwrap();
        assert!(empty.is_empty());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "rotated key file must be 0600");
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
