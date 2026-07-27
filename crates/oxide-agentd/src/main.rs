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
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use oxide_client_core::{run_supervised, ConnEvent, ConnectRequest, ReconnectPolicy};
use oxide_common::agent::{AgentRequest, AgentResponse, ConnPhase, TunnelStatus, DEFAULT_SOCKET};
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
    transport: Option<String>,
    daita: bool,
    kill_switch: bool,
    started: Instant,
}

/// The active (always-on) tunnel, if any. `meta`, `handle`, and `phase` are shared cells the
/// supervised task updates on every (re)connect, so status reflects the *current* server.
struct Active {
    meta: Arc<StdMutex<Option<ConnMeta>>>,
    /// Lifecycle phase, updated from the supervisor's `ConnEvent` stream.
    phase: Arc<StdMutex<ConnPhase>>,
    handle: Arc<StdMutex<Option<EngineHandle<TunDevice>>>>,
    stop: watch::Sender<bool>,
    /// New-identity generation counter; bumping it makes the supervisor rotate the device
    /// key and reconnect to a different exit.
    new_id: watch::Sender<u64>,
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
        AgentRequest::NewIdentity => match new_identity(state).await {
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
                exclude: Vec::new(),
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
            // Refine the event-driven phase with live handshake state: a `Connecting` phase is
            // promoted to `Connected` once the engine reports a completed handshake.
            let raw_phase = *a.phase.lock().unwrap();
            let phase = match raw_phase {
                ConnPhase::Connecting if stats.handshake_age_secs.is_some() => ConnPhase::Connected,
                other => other,
            };

            let meta = a.meta.lock().unwrap();
            let Some(m) = meta.as_ref() else {
                // Active but between attempts (selecting / reconnecting): report the phase so
                // the UI can show progress, but there's no connection detail yet.
                return TunnelStatus {
                    phase,
                    ..Default::default()
                };
            };
            TunnelStatus {
                connected: phase.is_connected(),
                phase,
                server_id: m.server_id.clone(),
                exit_id: m.exit_id.clone(),
                assigned_ip: Some(m.assigned_ip.clone()),
                uptime_secs: m.started.elapsed().as_secs(),
                tx_bytes: stats.tx_bytes,
                rx_bytes: stats.rx_bytes,
                active_peers: stats.active_peers,
                handshake_age_secs: stats.handshake_age_secs,
                transport: m.transport.clone(),
                daita: m.daita,
                kill_switch: m.kill_switch,
                stealth: m.stealth,
                post_quantum: m.post_quantum,
            }
        }
    }
}

async fn connect(state: &State, req: ConnectRequest, kill_switch: bool) -> Result<()> {
    disconnect(state).await.ok();

    // Always-on: the supervisor keeps the tunnel up across server death / network changes,
    // re-resolving and reconnecting as needed. `meta` and `handle` are shared cells it
    // updates on each (re)connect so `status` reflects the current server and throughput.
    let meta: Arc<StdMutex<Option<ConnMeta>>> = Arc::new(StdMutex::new(None));
    let phase: Arc<StdMutex<ConnPhase>> = Arc::new(StdMutex::new(ConnPhase::Selecting));
    let handle: Arc<StdMutex<Option<EngineHandle<TunDevice>>>> = Arc::new(StdMutex::new(None));
    let (stop_tx, stop_rx) = watch::channel(false);
    let (new_id_tx, new_id_rx) = watch::channel(0u64);

    let meta_task = meta.clone();
    let phase_task = phase.clone();
    let handle_task = handle.clone();
    let task = tokio::spawn(async move {
        run_supervised(
            req,
            kill_switch,
            ReconnectPolicy::default(),
            stop_rx,
            new_id_rx,
            move |h| *handle_task.lock().unwrap() = Some(h),
            move |ev| {
                // Track the lifecycle phase for the UI, and cache per-connection metadata.
                let mut phase = phase_task.lock().unwrap();
                match ev {
                    ConnEvent::Selecting => *phase = ConnPhase::Selecting,
                    ConnEvent::Connecting(i) => {
                        *phase = ConnPhase::Connecting;
                        *meta_task.lock().unwrap() = Some(ConnMeta {
                            server_id: i.server_id,
                            exit_id: i.exit_id,
                            assigned_ip: i.assigned_ip,
                            stealth: i.stealth,
                            post_quantum: i.post_quantum,
                            transport: Some(i.transport),
                            daita: i.daita,
                            kill_switch,
                            started: Instant::now(),
                        });
                    }
                    ConnEvent::Reconnecting { .. } => *phase = ConnPhase::Reconnecting,
                    ConnEvent::NewIdentity => *phase = ConnPhase::Selecting,
                    ConnEvent::Stopped => {
                        *phase = ConnPhase::Disconnected;
                        *meta_task.lock().unwrap() = None;
                    }
                }
            },
        )
        .await
    });

    state.lock().await.active = Some(Active {
        meta,
        phase,
        handle,
        stop: stop_tx,
        new_id: new_id_tx,
        task,
    });
    Ok(())
}

/// Trigger a "new identity" on the active connection: the supervisor rotates the device key
/// and reconnects to a different exit. Errors if nothing is connected.
async fn new_identity(state: &State) -> Result<()> {
    let guard = state.lock().await;
    let active = guard.active.as_ref().context("not connected")?;
    active.new_id.send_modify(|v| *v += 1);
    info!("new identity requested");
    Ok(())
}

async fn disconnect(state: &State) -> Result<()> {
    let active = state.lock().await.active.take();
    if let Some(a) = active {
        let _ = a.stop.send(true);
        // Give the supervisor time to tear down the current tunnel, then ensure it's done.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(6), a.task).await;
        info!("disconnected");
    }
    Ok(())
}
