//! Oxide control-plane daemon + admin CLI.
//!
//! `serve` runs the API; `add-server` registers a VPN server node and prints the auth
//! token that node uses to fetch its peer list. No privileges required — this is a
//! plain web service, so it builds and runs anywhere (no TUN, no root).

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ipnet::IpNet;
use tracing::info;

use oxide_common::account::format_grouped;
use oxide_control_plane::{add_server, db, rotate_server_token, serve, AppState, NewServer};

#[derive(Parser)]
#[command(name = "oxide-control-plane", about = "Oxide VPN control plane")]
struct Cli {
    /// SQLite database path (file created if missing).
    #[arg(long, default_value = "oxide.db", global = true)]
    db: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
// The `add-server` variant carries many optional flags; boxing a one-shot CLI command
// buys nothing.
#[allow(clippy::large_enum_variant)]
enum Cmd {
    /// Run the API server.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: String,
        /// Enable the admin API (remote `add-server` for provisioning) with this bearer
        /// token. Also read from `OXIDE_ADMIN_TOKEN`. Omit to disable the admin API.
        #[arg(long, env = "OXIDE_ADMIN_TOKEN")]
        admin_token: Option<String>,
    },
    /// Register a VPN server node and print its auth token.
    AddServer {
        #[arg(long)]
        id: String,
        /// The server's WireGuard public key (base64).
        #[arg(long)]
        public_key: String,
        /// Public UDP endpoint, host:port.
        #[arg(long)]
        endpoint: String,
        /// Tunnel subnet the server hands out, e.g. 10.8.0.0/24.
        #[arg(long, default_value = "10.8.0.0/24")]
        cidr: String,
        /// Country code/name for location-based selection.
        #[arg(long)]
        country: Option<String>,
        /// City for location-based selection.
        #[arg(long)]
        city: Option<String>,
        /// Soft capacity (max peers) for load-based selection. 0 = unlimited.
        #[arg(long, default_value_t = 0)]
        capacity: u32,
        /// DNS server handed to clients for leak protection (e.g. the tunnel IP 10.8.0.1).
        #[arg(long)]
        dns: Option<String>,
        /// Stealth-mode obfuscation key (base64) this server runs. Generate with `genkey`.
        #[arg(long)]
        obfuscation_key: Option<String>,
        /// Post-quantum public key (base64) this server runs (from `oxide-serverd pq-genkey`).
        #[arg(long)]
        pq_public_key: Option<String>,
        /// Wire transport this server expects: plain | obfs | quic | mimic. Handed to
        /// clients so they connect with the matching transport (stealth kinds need
        /// `--obfuscation-key`). Defaults to the client's back-compat rule when omitted.
        #[arg(long)]
        transport: Option<String>,
        /// This server runs DAITA (traffic-analysis defense); clients shape egress to match.
        #[arg(long)]
        daita: bool,
    },
    /// Rotate a server's auth token; the old one stays valid for a grace window (no downtime).
    RotateToken {
        #[arg(long)]
        id: String,
    },
    /// Create an account from the CLI (handy for testing/seeding).
    NewAccount,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let pool = db::connect(&cli.db).await?;

    match cli.cmd {
        Cmd::Serve {
            listen,
            admin_token,
        } => {
            let admin_on = admin_token.is_some();
            let state = AppState::new(pool).with_admin_token(admin_token);
            let listener = tokio::net::TcpListener::bind(&listen)
                .await
                .with_context(|| format!("binding {listen}"))?;
            info!(%listen, db = %cli.db, admin_api = admin_on, "control plane listening");
            serve(listener, state).await?;
        }
        Cmd::AddServer {
            id,
            public_key,
            endpoint,
            cidr,
            country,
            city,
            capacity,
            dns,
            obfuscation_key,
            pq_public_key,
            transport,
            daita,
        } => {
            let cidr: IpNet = cidr.parse().context("invalid --cidr")?;
            let token = add_server(
                &pool,
                NewServer {
                    id: &id,
                    public_key: &public_key,
                    endpoint: &endpoint,
                    cidr,
                    country: country.as_deref(),
                    city: city.as_deref(),
                    capacity,
                    dns: dns.as_deref(),
                    obfuscation_key: obfuscation_key.as_deref(),
                    pq_public_key: pq_public_key.as_deref(),
                    transport: transport.as_deref(),
                    daita,
                },
            )
            .await?;
            let server_ip = cidr.hosts().next().expect("cidr has hosts");
            println!("Registered server '{id}'.");
            println!("  endpoint:   {endpoint}");
            println!("  tunnel_ip:  {server_ip}  (server's address inside the tunnel)");
            println!("  auth_token: {token}");
            println!();
            println!("Add this to the server's config:");
            println!("  [control_plane]");
            println!("  url = \"http://<control-plane-host>:8080\"");
            println!("  server_id = \"{id}\"");
            println!("  token = \"{token}\"");
        }
        Cmd::RotateToken { id } => match rotate_server_token(&pool, &id).await? {
            Some((token, grace)) => {
                println!("Rotated auth token for server '{id}'.");
                println!("  new token:     {token}");
                println!("  old token valid for another {grace}s (grace) — update the server's");
                println!("  [control_plane] token and reload within that window for no downtime.");
            }
            None => anyhow::bail!("no such server: {id}"),
        },
        Cmd::NewAccount => {
            let state = AppState::new(pool);
            // Reuse the HTTP handler path via a direct DB insert for simplicity.
            let number = oxide_common::account::generate_account_number();
            state
                .pool
                .execute(
                    "INSERT INTO accounts (number, created_at) VALUES (?, ?)",
                    &[
                        db::Val::from(number.as_str()),
                        db::Val::from(db::now_unix()),
                    ],
                )
                .await?;
            println!("Account: {}", format_grouped(&number));
        }
    }
    Ok(())
}
