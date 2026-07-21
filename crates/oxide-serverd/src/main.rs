//! Oxide VPN server daemon (Milestone 1).
//!
//! Terminates WireGuard tunnels from clients and, when configured, NATs their traffic
//! to the internet (full-tunnel egress). Static config only — no control plane, DB, or
//! auth yet (that is M2).
//!
//! Requires `CAP_NET_ADMIN` (run as root in M1): it creates a TUN device, edits
//! routes/sysctls, and installs an nftables masquerade table.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use clap::{Parser, Subcommand};
use ipnet::IpNet;
use oxide_relay::Relay;
use tracing::{info, warn};

use oxide_common::api::PeerEntry;
use oxide_common::{keys, Config, ControlPlaneConfig, SecretKey};
use oxide_control_client::ControlClient;
use oxide_net_linux::{bring_up_interface, nat, netlink, shutdown_signal, sysctl, Netlink};
use oxide_wg_core::{Engine, EngineHandle, PeerParams, Transport, TunQueue};

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
    /// Generate a post-quantum (ML-KEM) keypair: prints the private seed and public key.
    /// Put the seed in the server config (`pq_private_seed`) and register the public key
    /// with the control plane (`add-server --pq-public-key`).
    PqGenkey,
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
        Cmd::PqGenkey => {
            let (seed, public_key) = oxide_pq::generate();
            println!("pq_private_seed (server config): {}", B64.encode(&seed));
            println!(
                "pq_public_key  (add-server):     {}",
                B64.encode(&public_key)
            );
            Ok(())
        }
        Cmd::Up { config } => run(config).await,
    }
}

async fn run(config_path: PathBuf) -> Result<()> {
    let cfg =
        Config::load(&config_path).with_context(|| format!("loading {}", config_path.display()))?;
    let listen_port = cfg
        .interface
        .listen_port
        .context("server config must set interface.listen_port")?;

    // Interface: TUN + address + MTU + up (over netlink).
    let nl = Netlink::connect().context("opening netlink")?;
    let (tun, _idx) = bring_up_interface(&nl, IFNAME, &cfg.interface)
        .await
        .context("bringing up tun interface")?;
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

    // Stealth mode: wrap the socket in the obfuscation transport if a key is configured.
    let transport = match &cfg.interface.obfuscation_key {
        Some(k) => {
            info!("stealth mode enabled (obfuscated transport)");
            Transport::obfuscated(udp, *k.as_bytes())
        }
        None => Transport::plain(udp),
    };

    // Server-side handshake rate limit (DoS defense): cookie challenges engage above
    // this many handshake messages/second across all peers.
    const HANDSHAKE_LIMIT: u64 = 100;
    let peers = cfg.peers.iter().map(PeerParams::from_config).collect();
    let engine = Engine::build_server(
        &cfg.interface.private_key,
        peers,
        transport,
        tun,
        HANDSHAKE_LIMIT,
    );

    // Decode the post-quantum private seed (if any) so we can decapsulate each device's
    // ciphertext into its PSK during reconcile.
    let pq_seed: Option<Vec<u8>> = cfg
        .interface
        .pq_private_seed
        .as_ref()
        .and_then(|s| B64.decode(s).ok());
    if pq_seed.is_some() {
        info!("post-quantum enabled (server will derive per-peer PSKs)");
    }

    // If configured, pull the peer list from the control plane and keep it in sync.
    // The engine's peer table is runtime-mutable, so this reconciles live and the
    // data plane keeps peer state in RAM only (no on-disk peer store).
    if let Some(cp) = cfg.control_plane {
        let handle = engine.handle();
        tokio::spawn(poll_control_plane(handle, cp, pq_seed));
    }

    // Run until Ctrl-C / SIGTERM, then tear down host state (leave-no-trace).
    tokio::select! {
        r = engine.run() => { r.context("engine stopped")?; }
        _ = shutdown_signal() => { info!("shutting down"); }
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
async fn poll_control_plane<T: TunQueue>(
    handle: EngineHandle<T>,
    cp: ControlPlaneConfig,
    pq_seed: Option<Vec<u8>>,
) {
    let client = ControlClient::new(&cp.url);
    let mut tick = tokio::time::interval(Duration::from_secs(cp.poll_interval_secs.max(1)));
    // Relay listen ports we've already started (this server acting as a multihop entry).
    let mut running_relays: HashSet<u16> = HashSet::new();
    loop {
        tick.tick().await;
        match client.fetch_peers(&cp.server_id, &cp.token).await {
            Ok(entries) => {
                let desired: Vec<PeerParams> = entries
                    .iter()
                    .filter_map(|e| peer_from_entry(e, pq_seed.as_deref()))
                    .collect();
                info!(peers = desired.len(), "reconciled peers from control plane");
                handle.reconcile(desired);
            }
            Err(e) => warn!(error = %e, "failed to fetch peers from control plane"),
        }

        // Start any new relay routes for which this server is the entry.
        match client.fetch_relays(&cp.server_id, &cp.token).await {
            Ok(relays) => {
                for r in relays {
                    if running_relays.insert(r.listen_port) {
                        spawn_relay(r.listen_port, r.exit_endpoint).await;
                    }
                }
            }
            Err(e) => warn!(error = %e, "failed to fetch relay routes"),
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

/// Bind and spawn a relay forwarding `listen_port` to `exit_endpoint` (host:port).
async fn spawn_relay(listen_port: u16, exit_endpoint: String) {
    let exit = match tokio::net::lookup_host(&exit_endpoint)
        .await
        .ok()
        .and_then(|mut a| a.next())
    {
        Some(addr) => addr,
        None => {
            warn!(exit = %exit_endpoint, "relay: cannot resolve exit endpoint");
            return;
        }
    };
    match Relay::bind(("0.0.0.0", listen_port), exit).await {
        Ok(relay) => {
            info!(listen_port, exit = %exit, "relay started (multihop entry)");
            tokio::spawn(async move {
                if let Err(e) = relay.run().await {
                    warn!(listen_port, error = %e, "relay stopped");
                }
            });
        }
        Err(e) => warn!(listen_port, error = %e, "relay: failed to bind"),
    }
}

/// Map a control-plane peer entry to engine params (server peers have no endpoint —
/// it's learned from the handshake). If the peer registered with post-quantum and we
/// have the PQ private seed, decapsulate its ciphertext into the peer's PSK.
fn peer_from_entry(entry: &PeerEntry, pq_seed: Option<&[u8]>) -> Option<PeerParams> {
    let allowed_ips: Vec<IpNet> = entry
        .allowed_ips
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    if allowed_ips.is_empty() {
        warn!(peer = %entry.public_key.to_base64(), "peer has no valid allowed_ips; skipping");
        return None;
    }
    let preshared_key = entry
        .pq_ciphertext
        .as_ref()
        .zip(pq_seed)
        .and_then(|(ct_b64, seed)| oxide_pq::decapsulate(seed, &B64.decode(ct_b64).ok()?));
    Some(PeerParams {
        public_key: entry.public_key,
        preshared_key,
        endpoint: None,
        allowed_ips,
        persistent_keepalive: None,
    })
}
