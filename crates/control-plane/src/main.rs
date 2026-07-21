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
use oxide_control_plane::{add_server, app, db, AppState};

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
enum Cmd {
    /// Run the API server.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: String,
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
        Cmd::Serve { listen } => {
            let state = AppState::new(pool);
            let listener = tokio::net::TcpListener::bind(&listen)
                .await
                .with_context(|| format!("binding {listen}"))?;
            info!(%listen, db = %cli.db, "control plane listening");
            axum::serve(listener, app(state)).await?;
        }
        Cmd::AddServer {
            id,
            public_key,
            endpoint,
            cidr,
        } => {
            let cidr: IpNet = cidr.parse().context("invalid --cidr")?;
            let token = add_server(&pool, &id, &public_key, &endpoint, cidr).await?;
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
        Cmd::NewAccount => {
            let state = AppState::new(pool);
            // Reuse the HTTP handler path via a direct DB insert for simplicity.
            let number = oxide_common::account::generate_account_number();
            sqlx::query("INSERT INTO accounts (number, created_at) VALUES (?, ?)")
                .bind(&number)
                .bind(db::now_unix())
                .execute(&state.pool)
                .await?;
            println!("Account: {}", format_grouped(&number));
        }
    }
    Ok(())
}
