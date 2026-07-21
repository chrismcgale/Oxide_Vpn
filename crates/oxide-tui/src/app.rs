//! TUI application state and (testable) state transitions. Rendering lives in `main`.

use std::path::PathBuf;

use oxide_common::agent::TunnelStatus;
use oxide_common::api::ServerInfo;

pub struct App {
    pub cp_url: String,
    pub account: String,
    pub socket: PathBuf,
    pub servers: Vec<ServerInfo>,
    pub selected: usize,
    pub status: TunnelStatus,
    pub message: String,
    pub should_quit: bool,
}

impl App {
    pub fn new(cp_url: String, account: String, socket: PathBuf) -> Self {
        App {
            cp_url,
            account,
            socket,
            servers: Vec::new(),
            selected: 0,
            status: TunnelStatus::default(),
            message: String::new(),
            should_quit: false,
        }
    }

    pub fn select_next(&mut self) {
        if !self.servers.is_empty() {
            self.selected = (self.selected + 1) % self.servers.len();
        }
    }

    pub fn select_prev(&mut self) {
        if !self.servers.is_empty() {
            self.selected = (self.selected + self.servers.len() - 1) % self.servers.len();
        }
    }

    pub fn selected_server(&self) -> Option<&ServerInfo> {
        self.servers.get(self.selected)
    }

    pub fn set_servers(&mut self, servers: Vec<ServerInfo>) {
        self.servers = servers;
        if self.selected >= self.servers.len() {
            self.selected = 0;
        }
    }

    pub fn set_status(&mut self, status: TunnelStatus) {
        self.status = status;
    }
}

/// Human-readable byte count for the status line.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_with(n: usize) -> App {
        let mut a = App::new("http://cp".into(), "acct".into(), "/tmp/s".into());
        a.set_servers(
            (0..n)
                .map(|i| ServerInfo {
                    id: format!("s{i}"),
                    public_key: oxide_common::keys::public_from_secret(
                        &oxide_common::keys::generate_secret(),
                    ),
                    endpoint: "1.2.3.4:51820".into(),
                    country: None,
                    city: None,
                    active_peers: 0,
                    capacity: 0,
                    healthy: true,
                    pq_public_key: None,
                })
                .collect(),
        );
        a
    }

    #[test]
    fn selection_wraps() {
        let mut a = app_with(3);
        assert_eq!(a.selected, 0);
        a.select_prev();
        assert_eq!(a.selected, 2);
        a.select_next();
        assert_eq!(a.selected, 0);
        a.select_next();
        assert_eq!(a.selected, 1);
    }

    #[test]
    fn set_servers_clamps_selection() {
        let mut a = app_with(5);
        a.selected = 4;
        a.set_servers(Vec::new());
        assert_eq!(a.selected, 0);
        assert!(a.selected_server().is_none());
    }

    #[test]
    fn human_bytes_scales() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2048), "2.0 KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MiB");
    }
}
