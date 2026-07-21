//! Oxide VPN privileged agent.
//!
//! Runs as root, owns the tunnel, and serves a Unix-socket control API so an
//! unprivileged UI (the TUI) can connect/disconnect and read live status. The tunnel
//! runs *embedded* (via `oxide-client-core`), so status includes real throughput.
//!
//! Protocol: newline-delimited JSON, one request → one response (see `common::agent`).

use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use oxide_client_core::{resolve_connection, run_tunnel, ConnectRequest};
use oxide_common::agent::{AgentRequest, AgentResponse, TunnelStatus, DEFAULT_SOCKET};
use oxide_net_linux::TunDevice;
use oxide_wg_core::EngineHandle;

#[derive(Parser)]
#[command(name = "oxide-agentd", about = "Oxide VPN privileged agent")]
struct Cli {
    /// Unix socket to listen on.
    #[arg(long, default_value = DEFAULT_SOCKET)]
    socket: PathBuf,
    /// Where the device key is cached.
    #[arg(long, default_value = "/etc/oxide/device.key")]
    key_file: PathBuf,
}

/// Metadata about the current connection, known at connect time.
struct ConnMeta {
    server_id: Option<String>,
    exit_id: Option<String>,
    assigned_ip: String,
    stealth: bool,
    post_quantum: bool,
    started: Instant,
}

/// The active tunnel, if any.
struct Active {
    meta: ConnMeta,
    /// Set by the tunnel task's `on_ready` once the engine is up.
    handle: Arc<StdMutex<Option<EngineHandle<TunDevice>>>>,
    stop: Arc<Notify>,
    task: JoinHandle<Result<()>>,
}

#[derive(Default)]
struct Agent {
    active: Option<Active>,
}

type State = Arc<Mutex<Agent>>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();

    if let Some(dir) = cli.socket.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::remove_file(&cli.socket); // clear a stale socket
    let listener = UnixListener::bind(&cli.socket)
        .with_context(|| format!("binding {}", cli.socket.display()))?;
    info!(socket = %cli.socket.display(), "agent listening");

    let state: State = Arc::new(Mutex::new(Agent::default()));
    let key_file = Arc::new(cli.key_file);

    loop {
        let (stream, _addr) = listener.accept().await?;
        let state = state.clone();
        let key_file = key_file.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, state, key_file).await {
                warn!(error = %e, "connection ended");
            }
        });
    }
}

async fn handle_conn(stream: UnixStream, state: State, key_file: Arc<PathBuf>) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<AgentRequest>(&line) {
            Ok(req) => dispatch(req, &state, &key_file).await,
            Err(e) => AgentResponse::Error {
                message: format!("bad request: {e}"),
            },
        };
        write.write_all(resp.to_line().as_bytes()).await?;
    }
    Ok(())
}

async fn dispatch(req: AgentRequest, state: &State, key_file: &Arc<PathBuf>) -> AgentResponse {
    match req {
        AgentRequest::Status => AgentResponse::Status(status(state).await),
        AgentRequest::Disconnect => match disconnect(state).await {
            Ok(()) => AgentResponse::Ok,
            Err(e) => AgentResponse::Error {
                message: e.to_string(),
            },
        },
        AgentRequest::Connect {
            control_plane,
            account,
            server,
            exit,
            country,
            kill_switch,
        } => {
            let req = ConnectRequest {
                control_plane,
                account,
                server,
                exit,
                entry: None,
                country,
                city: None,
                key_file: (**key_file).clone(),
                mtu: None,
            };
            match connect(state, req, kill_switch).await {
                Ok(()) => AgentResponse::Ok,
                Err(e) => AgentResponse::Error {
                    message: e.to_string(),
                },
            }
        }
    }
}

async fn status(state: &State) -> TunnelStatus {
    let mut guard = state.lock().await;
    // If the tunnel task has exited on its own, drop it.
    if let Some(a) = &guard.active {
        if a.task.is_finished() {
            guard.active = None;
        }
    }
    match &guard.active {
        None => TunnelStatus::default(),
        Some(a) => {
            let stats = a
                .handle
                .lock()
                .unwrap()
                .as_ref()
                .map(|h| h.stats())
                .unwrap_or_default();
            TunnelStatus {
                connected: true,
                server_id: a.meta.server_id.clone(),
                exit_id: a.meta.exit_id.clone(),
                assigned_ip: Some(a.meta.assigned_ip.clone()),
                uptime_secs: a.meta.started.elapsed().as_secs(),
                tx_bytes: stats.tx_bytes,
                rx_bytes: stats.rx_bytes,
                active_peers: stats.active_peers,
                stealth: a.meta.stealth,
                post_quantum: a.meta.post_quantum,
            }
        }
    }
}

async fn connect(state: &State, req: ConnectRequest, kill_switch: bool) -> Result<()> {
    disconnect(state).await.ok();

    // Control-plane resolution (unprivileged) before we touch the device.
    let resolved = resolve_connection(&req)
        .await
        .context("resolving connection")?;
    let meta = ConnMeta {
        server_id: resolved.server_id.clone(),
        exit_id: resolved.exit_id.clone(),
        assigned_ip: resolved.assigned_ip(),
        stealth: resolved.stealth(),
        post_quantum: resolved.post_quantum(),
        started: Instant::now(),
    };

    let iface = resolved.iface;
    let peers = resolved.peers;
    let stop = Arc::new(Notify::new());
    let handle: Arc<StdMutex<Option<EngineHandle<TunDevice>>>> = Arc::new(StdMutex::new(None));

    let stop_task = stop.clone();
    let handle_task = handle.clone();
    let task = tokio::spawn(async move {
        run_tunnel(
            &iface,
            peers,
            kill_switch,
            async move { stop_task.notified().await },
            move |h| *handle_task.lock().unwrap() = Some(h),
        )
        .await
    });

    state.lock().await.active = Some(Active {
        meta,
        handle,
        stop,
        task,
    });
    Ok(())
}

async fn disconnect(state: &State) -> Result<()> {
    let active = state.lock().await.active.take();
    if let Some(a) = active {
        a.stop.notify_one();
        // Give teardown a moment; then ensure the task is done.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), a.task).await;
        info!("disconnected");
    }
    Ok(())
}
