//! Shutdown signal — Ctrl-C, portable via tokio (Windows delivers CTRL_C_EVENT here).

/// Resolve on the first Ctrl-C.
pub async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
