//! Oxide VPN client CLI.
//!
//! Thin command-line front-end over `oxide-client-core` (the shared tunnel logic, also
//! used by the privileged agent). Requires `CAP_NET_ADMIN` (run as root) for `up`/
//! `connect`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use oxide_client_core::{
    resolve_connection, resolve_mesh, run_tunnel, ConnectRequest, MeshRequest,
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
                shutdown_signal(),
                |_| {},
            )
            .await
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
                shutdown_signal(),
                |_| {},
            )
            .await
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
            };
            let resolved = resolve_connection(&req).await?;
            run_tunnel(
                &resolved.iface,
                resolved.peers,
                kill_switch,
                shutdown_signal(),
                |_| {},
            )
            .await
        }
    }
}
