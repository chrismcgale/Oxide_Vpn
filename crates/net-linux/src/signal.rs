//! Graceful shutdown signal handling.
//!
//! Daemons receive `SIGTERM` from init systems (systemd, Docker, Kubernetes) — not just
//! `SIGINT`/Ctrl-C from a terminal. Awaiting both means host state (routes, nftables
//! tables, the TUN device) is always torn down cleanly on a managed stop.

/// Resolve when the process is asked to stop (Ctrl-C or `SIGTERM`).
pub async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => {
            // If we can't install a SIGTERM handler, fall back to Ctrl-C only.
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}
