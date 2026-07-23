//! Oxide VPN client CLI.
//!
//! Thin command-line front-end over `oxide-client-core` (the shared tunnel logic, also
//! used by the privileged agent). Requires `CAP_NET_ADMIN` (run as root) for `up`/
//! `connect`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{info, warn};

use oxide_client_core::{
    resolve_mesh, run_supervised, run_tunnel, ConnEvent, ConnectRequest, MeshRequest,
    ReconnectPolicy,
};
use oxide_common::{keys, Config, SecretKey};
use oxide_control_client::ControlClient;
use oxide_net_linux::shutdown_signal;
use oxide_wg_core::PeerParams;

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
        #[arg(long)]
        control_plane: String,
        #[arg(long)]
        account: String,
        /// Explicit server id (single-hop). Omit to auto-select the least-loaded.
        #[arg(long)]
        server: Option<String>,
        /// Exit server id for MULTIHOP (traffic tunnels to it through an entry relay).
        #[arg(long)]
        exit: Option<String>,
        /// Entry server id for multihop (defaults to an auto-selected server != exit).
        #[arg(long)]
        entry: Option<String>,
        #[arg(long)]
        country: Option<String>,
        #[arg(long)]
        city: Option<String>,
        #[arg(long, default_value = "device.key")]
        key_file: PathBuf,
        #[arg(long)]
        mtu: Option<u32>,
        /// Block all non-tunnel traffic while connected.
        #[arg(long)]
        kill_switch: bool,
    },
    /// Join the account's private mesh (P2P overlay of your own devices) and connect.
    Mesh {
        #[arg(long)]
        control_plane: String,
        #[arg(long)]
        account: String,
        /// The endpoint other devices reach this one at, `host:port` (e.g. your public
        /// IP and a forwarded UDP port). This is what peers dial to mesh with you.
        #[arg(long)]
        endpoint: String,
        #[arg(long, default_value = "device.key")]
        key_file: PathBuf,
        #[arg(long)]
        mtu: Option<u32>,
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
        Cmd::Mesh {
            control_plane,
            account,
            endpoint,
            key_file,
            mtu,
        } => {
            let endpoint = endpoint
                .parse()
                .with_context(|| format!("invalid --endpoint (want host:port): {endpoint}"))?;
            let req = MeshRequest {
                control_plane,
                account,
                endpoint,
                key_file,
                mtu,
            };
            let resolved = resolve_mesh(&req).await?;
            // Mesh is peer-to-peer within your own devices; no kill switch (it carries
            // only mesh traffic, not your default route).
            run_tunnel(
                &resolved.iface,
                resolved.peers,
                false,
                None, // mesh: no liveness watchdog (a peerless mesh is legitimate)
                shutdown_signal(),
                |_| {},
            )
            .await
            .map(|_| ())
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
        } => {
            let cfg =
                Config::load(&config).with_context(|| format!("loading {}", config.display()))?;
            let peers = cfg.peers.iter().map(PeerParams::from_config).collect();
            run_tunnel(
                &cfg.interface,
                peers,
                kill_switch,
                None, // static config: one server, nothing to fail over to
                shutdown_signal(),
                |_| {},
            )
            .await
            .map(|_| ())
        }
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
            let req = ConnectRequest {
                control_plane,
                account,
                server,
                exit,
                entry,
                country,
                city,
                key_file,
                mtu,
                exclude: Vec::new(),
            };
            // Always-on: keep the tunnel up across server death / network changes until the
            // user interrupts. A pinned --server just reconnects to the same one.
            let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            tokio::spawn(async move {
                shutdown_signal().await;
                let _ = stop_tx.send(true);
            });
            // SIGUSR1 = "new identity" (Tor-style new circuit): rotate the device key and
            // reconnect to a different exit. `kill -USR1 <pid>` from a script or shell.
            let (new_id_tx, new_id_rx) = tokio::sync::watch::channel(0u64);
            tokio::spawn(async move {
                let mut usr1 = match tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::user_defined1(),
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(error = %e, "cannot install SIGUSR1 handler; new-identity disabled");
                        return;
                    }
                };
                while usr1.recv().await.is_some() {
                    info!("SIGUSR1: new identity requested");
                    new_id_tx.send_modify(|v| *v += 1);
                }
            });
            run_supervised(
                req,
                kill_switch,
                ReconnectPolicy::default(),
                stop_rx,
                new_id_rx,
                |_| {},
                |ev| match ev {
                    ConnEvent::Selecting => info!("selecting a server"),
                    ConnEvent::Connecting(i) => {
                        info!(server = ?i.server_id.or(i.exit_id), ip = %i.assigned_ip, "connecting")
                    }
                    ConnEvent::Reconnecting { server, wait } => {
                        warn!(server = %server, ?wait, "link dropped; reconnecting")
                    }
                    ConnEvent::NewIdentity => info!("new identity: rotated key, switching exit"),
                    ConnEvent::Stopped => info!("disconnected"),
                },
            )
            .await
        }
    }
}
