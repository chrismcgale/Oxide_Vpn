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

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ipnet::IpNet;
use tracing::{info, warn};

use oxide_common::api::RegisterDeviceResponse;
use oxide_common::{keys, InterfaceConfig, SecretKey, TransportKind};
use oxide_control_client::ControlClient;
use oxide_net_linux::{bring_up_interface, dns, killswitch, netlink, Netlink, TunDevice};
use oxide_wg_core::{Daita, Engine, EngineHandle, MimicTransport, PeerParams, Transport};

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
}

/// The resolved local config for a connection.
pub struct Resolved {
    pub iface: InterfaceConfig,
    pub peers: Vec<PeerParams>,
    pub server_id: Option<String>,
    pub exit_id: Option<String>,
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

    let (reg, psk, server_id, exit_id) = if let Some(exit_id) = &req.exit {
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
        (reg, psk, None, Some(exit_id.clone()))
    } else {
        let chosen = match &req.server {
            Some(id) => cc
                .list_servers(&account)
                .await
                .context("listing servers")?
                .into_iter()
                .find(|s| &s.id == id)
                .with_context(|| format!("no such server: {id}"))?,
            None => cc
                .best_server(&account, req.country.as_deref(), req.city.as_deref())
                .await
                .context("selecting best server")?,
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
        let reg = cc
            .register_device(&account, device_pub, &id, pq_ct.as_deref())
            .await
            .context("registering device")?;
        (reg, psk, Some(id), None)
    };
    info!(assigned_ip = %reg.assigned_ip, endpoint = %reg.server.endpoint, "device registered");

    let (iface, peer) = resolve_registration(device_key, &reg, req.mtu, psk)?;
    Ok(Resolved {
        iface,
        peers: vec![peer],
        server_id,
        exit_id,
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
    };
    Ok(Resolved {
        iface,
        peers,
        server_id: None,
        exit_id: None,
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
        transport: TransportKind::default(),
        daita: false,
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
    let bind_udp = || async {
        tokio::net::UdpSocket::bind(("0.0.0.0", bind_port))
            .await
            .context("binding client UDP socket")
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

pub async fn run_tunnel<Stop, Ready>(
    iface: &InterfaceConfig,
    peers: Vec<PeerParams>,
    kill_switch: bool,
    stop: Stop,
    on_ready: Ready,
) -> Result<()>
where
    Stop: Future<Output = ()>,
    Ready: FnOnce(EngineHandle<TunDevice>),
{
    let nl = Netlink::connect().context("opening netlink")?;
    let (tun, tun_idx) = bring_up_interface(&nl, IFNAME, iface)
        .await
        .context("bringing up tun interface")?;
    info!(iface = IFNAME, addr = %iface.address, mtu = iface.mtu(), "interface up");

    // Full-tunnel routing: pin the server endpoint via the current default gateway BEFORE
    // swinging the default, or the encrypted UDP would recurse into the tunnel.
    let mut routed_v4 = false;
    let mut routed_v6 = false;
    let mut full_tunnel_endpoint: Option<SocketAddr> = None;
    let mut pinned: Option<(IpAddr, IpAddr, u32)> = None;
    for peer in &peers {
        let has_v4 = peer
            .allowed_ips
            .iter()
            .any(|n| matches!(n, IpNet::V4(v) if v.prefix_len() == 0));
        let has_v6 = peer
            .allowed_ips
            .iter()
            .any(|n| matches!(n, IpNet::V6(v) if v.prefix_len() == 0));
        if has_v4 || has_v6 {
            let endpoint = peer
                .endpoint
                .context("full-tunnel peer must have an endpoint")?;
            let (gw, dev) = netlink::default_route()?
                .context("no default route found; cannot pin server endpoint")?;
            let dev_idx = nl
                .link_index(&dev)
                .await
                .context("resolving egress interface index")?;
            nl.add_host_route_via(endpoint.ip(), gw, dev_idx)
                .await
                .context("pinning server endpoint route")?;
            if has_v4 {
                nl.set_default_v4_via_dev(tun_idx)
                    .await
                    .context("swinging IPv4 default into tunnel")?;
                routed_v4 = true;
            }
            if has_v6 {
                nl.set_default_v6_via_dev(tun_idx)
                    .await
                    .context("swinging IPv6 default into tunnel")?;
                routed_v6 = true;
            }
            info!(server = %endpoint.ip(), via = %gw, "default route swung into tunnel");
            full_tunnel_endpoint = Some(endpoint);
            pinned = Some((endpoint.ip(), gw, dev_idx));
            break;
        }
    }

    let dns_guard = match iface.dns {
        Some(d) => {
            let guard = dns::set_dns(&[d]).context("setting tunnel DNS")?;
            info!(dns = %d, "tunnel DNS installed");
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
    on_ready(engine.handle());
    info!("connecting");

    tokio::select! {
        r = engine.run() => { r.context("engine stopped")?; }
        _ = stop => { info!("shutting down"); }
    }

    // Teardown in reverse order.
    if kill_switch {
        if let Err(e) = killswitch::disable() {
            warn!(?e, "failed to remove kill switch");
        }
    }
    if let Some(guard) = dns_guard {
        dns::restore(guard);
    }
    if let Some((host, gw, dev_idx)) = pinned {
        let _ = nl.del_host_route_via(host, gw, dev_idx).await;
    }
    if routed_v4 || routed_v6 {
        nl.clear_default_via_dev(tun_idx, routed_v6).await;
    }
    Ok(())
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
        };

        let (iface, peer) =
            resolve_registration(device, &reg, Some(1400), Some([9u8; 32])).unwrap();
        assert_eq!(peer.preshared_key, Some([9u8; 32]));
        assert_eq!(iface.address.to_string(), "10.8.0.5/24");
        assert_eq!(iface.mtu(), 1400);
        assert!(iface.obfuscation_key.is_some());
        assert_eq!(peer.endpoint.unwrap().to_string(), "203.0.113.7:51820");
        assert!(peer
            .allowed_ips
            .iter()
            .any(|n| matches!(n, IpNet::V4(v) if v.prefix_len() == 0)));
    }
}
