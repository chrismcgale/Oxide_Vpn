//! Oxide VPN server daemon (Milestone 1).
//!
//! Terminates WireGuard tunnels from clients and, when configured, NATs their traffic
//! to the internet (full-tunnel egress). Static config only — no control plane, DB, or
//! auth yet (that is M2).
//!
//! Requires `CAP_NET_ADMIN` (run as root in M1): it creates a TUN device, edits
//! routes/sysctls, and installs an nftables masquerade table.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ipnet::IpNet;
use tracing::{info, warn};

use oxide_common::api::PeerEntry;
use oxide_common::{keys, Config, ControlPlaneConfig, SecretKey};
use oxide_control_client::ControlClient;
use oxide_net_linux::{bring_up_interface, nat, netlink, sysctl};
use oxide_wg_core::{Engine, EngineHandle, PeerParams, TunQueue};

const IFNAME: &str = "oxide0";

#[derive(Parser)]
#[command(name = "oxide-serverd", about = "Oxide VPN server daemon")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Bring the tunnel up and serve clients.
    Up {
        #[arg(short, long, default_value = "server.toml")]
        config: PathBuf,
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
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
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
            let sk: SecretKey = line.trim().parse().context("invalid private key on stdin")?;
            println!("{}", keys::public_from_secret(&sk).to_base64());
            Ok(())
        }
        Cmd::Up { config } => run(config).await,
    }
}

async fn run(config_path: PathBuf) -> Result<()> {
    let cfg = Config::load(&config_path)
        .with_context(|| format!("loading {}", config_path.display()))?;
    let listen_port = cfg
        .interface
        .listen_port
        .context("server config must set interface.listen_port")?;

    // Interface: TUN + address + MTU + up.
    let tun = bring_up_interface(IFNAME, &cfg.interface).context("bringing up tun interface")?;
    info!(iface = IFNAME, addr = %cfg.interface.address, mtu = cfg.interface.mtu(), "interface up");

    // Full-tunnel egress: forwarding + relaxed rp_filter + masquerade.
    let mut nat_egress: Option<String> = None;
    if let Some(natcfg) = &cfg.nat {
        let egress = match &natcfg.egress {
            Some(e) => e.clone(),
            None => netlink::default_route()?
                .map(|(_, dev)| dev)
                .context("could not auto-detect egress interface; set [nat] egress")?,
        };
        sysctl::enable_ip_forward().context("enabling ip_forward")?;
        sysctl::relax_rp_filter(&egress).context("relaxing rp_filter")?;
        nat::enable_masquerade(IFNAME, &egress).context("installing nftables masquerade")?;
        info!(egress = %egress, "NAT masquerade enabled (full-tunnel egress)");
        nat_egress = Some(egress);
    }

    // UDP listener + engine.
    let udp = tokio::net::UdpSocket::bind(("0.0.0.0", listen_port))
        .await
        .with_context(|| format!("binding UDP :{listen_port}"))?;
    info!(port = listen_port, peers = cfg.peers.len(), "listening");

    let peers = cfg.peers.iter().map(PeerParams::from_config).collect();
    let engine = Engine::build(&cfg.interface.private_key, peers, udp, tun);

    // If configured, pull the peer list from the control plane and keep it in sync.
    // The engine's peer table is runtime-mutable, so this reconciles live and the
    // data plane keeps peer state in RAM only (no on-disk peer store).
    if let Some(cp) = cfg.control_plane {
        let handle = engine.handle();
        tokio::spawn(poll_control_plane(handle, cp));
    }

    // Run until Ctrl-C, then tear down host state (leave-no-trace).
    tokio::select! {
        r = engine.run() => { r.context("engine stopped")?; }
        _ = tokio::signal::ctrl_c() => { info!("shutting down"); }
    }

    if nat_egress.is_some() {
        if let Err(e) = nat::disable_masquerade() {
            warn!(?e, "failed to remove nftables table");
        }
    }
    // TUN device is dropped here, removing the interface and its routes.
    Ok(())
}

/// Periodically fetch this server's peer list from the control plane, reconcile it into
/// the running engine, and report live load back via a heartbeat. tokio's interval
/// fires immediately, so peers load at once.
async fn poll_control_plane<T: TunQueue>(handle: EngineHandle<T>, cp: ControlPlaneConfig) {
    let client = ControlClient::new(&cp.url);
    let mut tick = tokio::time::interval(Duration::from_secs(cp.poll_interval_secs.max(1)));
    loop {
        tick.tick().await;
        match client.fetch_peers(&cp.server_id, &cp.token).await {
            Ok(entries) => {
                let desired: Vec<PeerParams> = entries.iter().filter_map(peer_from_entry).collect();
                info!(peers = desired.len(), "reconciled peers from control plane");
                handle.reconcile(desired);
            }
            Err(e) => warn!(error = %e, "failed to fetch peers from control plane"),
        }

        // Report live load so the control plane can balance new clients across servers.
        let stats = handle.stats();
        if let Err(e) = client
            .heartbeat(&cp.server_id, &cp.token, stats.active_peers as u32)
            .await
        {
            warn!(error = %e, "heartbeat failed");
        }
    }
}

/// Map a control-plane peer entry to engine params (server peers have no endpoint —
/// it's learned from the handshake).
fn peer_from_entry(entry: &PeerEntry) -> Option<PeerParams> {
    let allowed_ips: Vec<IpNet> = entry
        .allowed_ips
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    if allowed_ips.is_empty() {
        warn!(peer = %entry.public_key.to_base64(), "peer has no valid allowed_ips; skipping");
        return None;
    }
    Some(PeerParams {
        public_key: entry.public_key,
        preshared_key: None,
        endpoint: None,
        allowed_ips,
        persistent_keepalive: None,
    })
}
