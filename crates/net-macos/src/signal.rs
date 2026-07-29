//! Shutdown signal — portable (SIGINT/SIGTERM via tokio), same as the Linux backend.

use tokio::signal::unix::{signal, SignalKind};

/// Resolve on the first SIGINT or SIGTERM.
pub async fn shutdown_signal() {
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}
