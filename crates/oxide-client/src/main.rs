//! Oxide VPN client daemon.
//!
//! Two ways to connect:
//!   * `up --config client.toml` — static WireGuard-style config (M1).
//!   * `connect --control-plane <url> --account <n>` — register this device with the
//!     control plane, receive an assigned tunnel IP and server details, and connect
//!     (M2). The device keypair is generated and cached locally on first use.
//!
//! For a full-tunnel peer (`allowed_ips = 0.0.0.0/0`) the client swings the default
//! route into the tunnel, pinning the server endpoint through the original gateway
//! first so the tunnel's own UDP doesn't recurse into itself.
//!
//! Requires `CAP_NET_ADMIN` (run as root) for the actual connect.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ipnet::IpNet;
use tracing::{info, warn};

use oxide_common::api::RegisterDeviceResponse;
use oxide_common::{keys, Config, InterfaceConfig, SecretKey};
use oxide_control_client::ControlClient;
use oxide_net_linux::{bring_up_interface, dns, killswitch, netlink};
use oxide_wg_core::{Engine, PeerParams};

const IFNAME: &str = "oxide0";

#[derive(Parser)]
#[command(name = "oxide-client", about = "Oxide VPN client")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Connect using a static config file.
    Up {
        #[arg(short, long, default_value = "client.toml")]
        config: PathBuf,
        /// Block all non-tunnel traffic while connected (prevents leaks on drop).
        #[arg(long)]
        kill_switch: bool,
    },
    /// Register with the control plane and connect.
    Connect {
        /// Control-plane base URL, e.g. http://cp.example:8080
        #[arg(long)]
        control_plane: String,
        /// Account number (16 digits, spaces ignored).
        #[arg(long)]
        account: String,
        /// Explicit server id (single-hop). If omitted, the least-loaded server is
        /// auto-selected (optionally filtered by --country/--city).
        #[arg(long)]
        server: Option<String>,
        /// Exit server id for MULTIHOP. When set, traffic tunnels to this exit through
        /// an entry relay, so no single server sees both your IP and your destination.
        #[arg(long)]
        exit: Option<String>,
        /// Entry server id for multihop (defaults to an auto-selected server != exit).
        #[arg(long)]
        entry: Option<String>,
        /// Auto-select only servers in this country.
        #[arg(long)]
        country: Option<String>,
        /// Auto-select only servers in this city.
        #[arg(long)]
        city: Option<String>,
        /// Where to cache this device's private key.
        #[arg(long, default_value = "device.key")]
        key_file: PathBuf,
        /// Tunnel MTU (defaults to 1420).
        #[arg(long)]
        mtu: Option<u32>,
        /// Block all non-tunnel traffic while connected (prevents leaks on drop).
        #[arg(long)]
        kill_switch: bool,
    },
    /// Create a new anonymous account via the control plane and print it.
    Account {
        #[arg(long)]
        control_plane: String,
    },
    /// Print a fresh private key (base64), like `wg genkey`.
    Genkey,
    /// Read a private key (base64) on stdin, print its public key, like `wg pubkey`.
    Pubkey,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    match Cli::parse().cmd {
        Cmd::Genkey => {
            println!("{}", keys::generate_secret().to_base64());
            Ok(())
        }
        Cmd::Pubkey => {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            let sk: SecretKey = line
                .trim()
                .parse()
                .context("invalid private key on stdin")?;
            println!("{}", keys::public_from_secret(&sk).to_base64());
            Ok(())
        }
        Cmd::Account { control_plane } => {
            let number = ControlClient::new(&control_plane).create_account().await?;
            println!("{}", oxide_common::account::format_grouped(&number));
            eprintln!("Save this account number — it is your only credential.");
            Ok(())
        }
        Cmd::Up {
            config,
            kill_switch,
        } => run_static(config, kill_switch).await,
        Cmd::Connect {
            control_plane,
            account,
            server,
            exit,
            entry,
            country,
            city,
            key_file,
            mtu,
            kill_switch,
        } => {
            let sel = ServerSelection {
                server,
                exit,
                entry,
                country,
                city,
            };
            connect(&control_plane, &account, sel, &key_file, mtu, kill_switch).await
        }
    }
}

/// How the client chooses a server: an explicit id, a multihop exit (+ optional entry),
/// or auto (least-loaded) with optional location filters.
struct ServerSelection {
    server: Option<String>,
    exit: Option<String>,
    entry: Option<String>,
    country: Option<String>,
    city: Option<String>,
}

async fn run_static(config_path: PathBuf, kill_switch: bool) -> Result<()> {
    let cfg =
        Config::load(&config_path).with_context(|| format!("loading {}", config_path.display()))?;
    let peers = cfg.peers.iter().map(PeerParams::from_config).collect();
    run_tunnel(&cfg.interface, peers, kill_switch).await
}

async fn connect(
    cp_url: &str,
    account: &str,
    sel: ServerSelection,
    key_file: &Path,
    mtu: Option<u32>,
    kill_switch: bool,
) -> Result<()> {
    let account = account.replace(' ', "");
    let device_key = load_or_create_key(key_file)?;
    let device_pub = keys::public_from_secret(&device_key);

    let cc = ControlClient::new(cp_url);

    let reg = if let Some(exit_id) = &sel.exit {
        // Multihop: tunnel to the exit through an entry relay.
        let entry_id = match &sel.entry {
            Some(e) => e.clone(),
            None => pick_entry(&cc, &account, exit_id).await?,
        };
        info!(entry = %entry_id, exit = %exit_id, "multihop path");
        cc.register_device_multihop(&account, device_pub, &entry_id, exit_id)
            .await
            .context("registering device (multihop)")?
    } else {
        // Single-hop.
        let chosen = match &sel.server {
            Some(id) => cc
                .list_servers(&account)
                .await
                .context("listing servers")?
                .into_iter()
                .find(|s| &s.id == id)
                .with_context(|| format!("no such server: {id}"))?,
            None => cc
                .best_server(&account, sel.country.as_deref(), sel.city.as_deref())
                .await
                .context("selecting best server")?,
        };
        info!(server = %chosen.id, endpoint = %chosen.endpoint, active_peers = chosen.active_peers, "selected server");
        cc.register_device(&account, device_pub, &chosen.id)
            .await
            .context("registering device")?
    };
    info!(assigned_ip = %reg.assigned_ip, endpoint = %reg.server.endpoint, "device registered");

    let (iface, peer) = resolve_registration(device_key, &reg, mtu)?;
    run_tunnel(&iface, vec![peer], kill_switch).await
}

/// Auto-pick an entry server for multihop: the least-loaded server that isn't the exit.
async fn pick_entry(cc: &ControlClient, account: &str, exit_id: &str) -> Result<String> {
    let best = cc.best_server(account, None, None).await.ok();
    if let Some(b) = best {
        if b.id != exit_id {
            return Ok(b.id);
        }
    }
    // Best was the exit (or unavailable): fall back to the first different server.
    cc.list_servers(account)
        .await
        .context("listing servers for entry selection")?
        .into_iter()
        .find(|s| s.id != exit_id)
        .map(|s| s.id)
        .context("no server available to act as a multihop entry")
}

/// Turn a control-plane registration into a local interface config + server peer.
/// Pure/testable: no I/O, no privileges.
fn resolve_registration(
    device_key: SecretKey,
    reg: &RegisterDeviceResponse,
    mtu: Option<u32>,
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

    let iface = InterfaceConfig {
        private_key: device_key,
        address,
        listen_port: None,
        mtu,
        dns: reg.dns.as_ref().and_then(|s| s.parse().ok()),
    };
    let peer = PeerParams {
        public_key: reg.server.public_key,
        preshared_key: None,
        endpoint: Some(endpoint),
        allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
        persistent_keepalive: Some(25),
    };
    Ok((iface, peer))
}

/// Bring up the interface, install routing, optional kill switch + DNS, run the engine
/// until Ctrl-C, then tear everything down (in reverse order) so the host is left clean.
async fn run_tunnel(
    iface: &InterfaceConfig,
    peers: Vec<PeerParams>,
    kill_switch: bool,
) -> Result<()> {
    let tun = bring_up_interface(IFNAME, iface).context("bringing up tun interface")?;
    info!(iface = IFNAME, addr = %iface.address, mtu = iface.mtu(), "interface up");

    // Full-tunnel routing: pin the server endpoint via the current default gateway
    // BEFORE swinging the default, or the encrypted UDP would recurse into the tunnel.
    let mut default_swung = false;
    let mut full_tunnel_endpoint: Option<SocketAddr> = None;
    for peer in &peers {
        if is_full_tunnel(&peer.allowed_ips) {
            let endpoint = peer
                .endpoint
                .context("full-tunnel peer must have an endpoint")?;
            let (gw, dev) = netlink::default_route()?
                .context("no default route found; cannot pin server endpoint")?;
            netlink::add_host_route_via(endpoint.ip(), gw, &dev)
                .context("pinning server endpoint route")?;
            netlink::set_default_via_dev(IFNAME).context("swinging default route into tunnel")?;
            info!(server = %endpoint.ip(), via = %gw, "default route swung into tunnel");
            default_swung = true;
            full_tunnel_endpoint = Some(endpoint);
            break;
        }
    }

    // DNS leak protection: point the resolver at the tunnel DNS while connected.
    let dns_guard = match iface.dns {
        Some(dns) => {
            let guard = dns::set_dns(&[dns]).context("setting tunnel DNS")?;
            info!(%dns, "tunnel DNS installed");
            Some(guard)
        }
        None => None,
    };

    // Kill switch: block everything except loopback, the tunnel, and the encrypted UDP
    // to the server. Installed after routing so the server endpoint is known; it keeps
    // working across reconnects and prevents leaks if the tunnel drops.
    if kill_switch {
        let ep = full_tunnel_endpoint
            .context("--kill-switch requires a full-tunnel (0.0.0.0/0) peer with an endpoint")?;
        killswitch::enable(ep.ip(), ep.port(), IFNAME).context("enabling kill switch")?;
        info!(server = %ep, "kill switch enabled");
    }

    let bind_port = iface.listen_port.unwrap_or(0);
    let udp = tokio::net::UdpSocket::bind(("0.0.0.0", bind_port))
        .await
        .context("binding client UDP socket")?;

    let engine = Engine::build(&iface.private_key, peers, udp, tun);
    info!("connecting");

    tokio::select! {
        r = engine.run() => { r.context("engine stopped")?; }
        _ = tokio::signal::ctrl_c() => { info!("shutting down"); }
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
    if default_swung {
        for half in ["0.0.0.0/1", "128.0.0.0/1"] {
            if let Err(e) = netlink::del_route(half) {
                warn!(route = half, ?e, "failed to remove split-default route");
            }
        }
    }
    Ok(())
}

/// Is this a full-tunnel peer (routes the entire IPv4 default)?
fn is_full_tunnel(allowed: &[IpNet]) -> bool {
    allowed
        .iter()
        .any(|n| matches!(n, IpNet::V4(v4) if v4.prefix_len() == 0))
}

/// Load the device private key from `path`, or generate and persist one (0600).
fn load_or_create_key(path: &Path) -> Result<SecretKey> {
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
        };

        let (iface, peer) = resolve_registration(device, &reg, Some(1400)).unwrap();
        assert_eq!(iface.address.to_string(), "10.8.0.5/24");
        assert_eq!(iface.mtu(), 1400);
        assert_eq!(peer.endpoint.unwrap().to_string(), "203.0.113.7:51820");
        assert_eq!(peer.public_key, server_pub);
        assert!(is_full_tunnel(&peer.allowed_ips));
        assert_eq!(peer.persistent_keepalive, Some(25));
    }
}
