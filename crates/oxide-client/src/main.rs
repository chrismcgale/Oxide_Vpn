//! Oxide VPN client daemon (Milestone 1).
//!
//! Dials a configured server endpoint, brings up a TUN interface, and (for a
//! full-tunnel peer, `allowed_ips = 0.0.0.0/0`) swings the default route into the
//! tunnel — pinning the server endpoint through the original gateway first so the
//! tunnel's own UDP doesn't route into itself.
//!
//! Requires `CAP_NET_ADMIN` (run as root in M1).

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ipnet::IpNet;
use tracing::{info, warn};

use oxide_common::{keys, Config, SecretKey};
use oxide_net_linux::{bring_up_interface, netlink};
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
    /// Connect to the server and route traffic through the tunnel.
    Up {
        #[arg(short, long, default_value = "client.toml")]
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

/// Is this a full-tunnel peer (routes the entire IPv4 default)?
fn is_full_tunnel(allowed: &[IpNet]) -> bool {
    allowed
        .iter()
        .any(|n| matches!(n, IpNet::V4(v4) if v4.prefix_len() == 0))
}

async fn run(config_path: PathBuf) -> Result<()> {
    let cfg = Config::load(&config_path)
        .with_context(|| format!("loading {}", config_path.display()))?;

    // Interface: TUN + address + MTU + up.
    let tun = bring_up_interface(IFNAME, &cfg.interface).context("bringing up tun interface")?;
    info!(iface = IFNAME, addr = %cfg.interface.address, mtu = cfg.interface.mtu(), "interface up");

    // Set up full-tunnel routing if any peer asks for 0.0.0.0/0. Pin the server
    // endpoint via the current default gateway BEFORE swinging the default, or the
    // encrypted UDP to the server would recurse into the tunnel.
    let mut default_swung = false;
    for peer in &cfg.peers {
        if is_full_tunnel(&peer.allowed_ips) {
            let endpoint = peer
                .endpoint
                .context("full-tunnel peer must set an endpoint")?;
            let (gw, dev) = netlink::default_route()?
                .context("no default route found; cannot pin server endpoint")?;
            netlink::add_host_route_via(endpoint.ip(), gw, &dev)
                .context("pinning server endpoint route")?;
            netlink::set_default_via_dev(IFNAME).context("swinging default route into tunnel")?;
            info!(server = %endpoint.ip(), via = %gw, "default route swung into tunnel");
            default_swung = true;
            break;
        }
    }

    // UDP socket (ephemeral source port unless the config pins one).
    let bind_port = cfg.interface.listen_port.unwrap_or(0);
    let udp = tokio::net::UdpSocket::bind(("0.0.0.0", bind_port))
        .await
        .context("binding client UDP socket")?;

    let peers = cfg.peers.iter().map(PeerParams::from_config).collect();
    let engine = Engine::build(&cfg.interface.private_key, peers, udp, tun);
    info!("connecting");

    tokio::select! {
        r = engine.run() => { r.context("engine stopped")?; }
        _ = tokio::signal::ctrl_c() => { info!("shutting down"); }
    }

    // Remove the split-default routes we added; the pinned host route and the TUN
    // interface (and its on-link routes) go away when the interface is dropped, but
    // the split-default routes are attached to the interface too, so this is mostly
    // belt-and-suspenders.
    if default_swung {
        for half in ["0.0.0.0/1", "128.0.0.0/1"] {
            if let Err(e) = netlink::del_route(half) {
                warn!(route = half, ?e, "failed to remove split-default route");
            }
        }
    }
    Ok(())
}
