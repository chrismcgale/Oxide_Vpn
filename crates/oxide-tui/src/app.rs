//! TUI application state and (testable) state transitions. Rendering lives in `main`.

use std::path::PathBuf;

use oxide_common::agent::TunnelStatus;
use oxide_common::api::ServerInfo;

/// How many throughput samples the sparkline keeps.
const HISTORY_LEN: usize = 48;

/// Link health derived from the WireGuard handshake age.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkHealth {
    /// No completed handshake yet (still coming up, or gone quiet).
    Unknown,
    /// A fresh handshake — traffic is flowing.
    Live,
    /// The last handshake is older than the rekey window — the link may be dead.
    Stale,
}

/// WireGuard rekeys well within a few minutes; a handshake older than this is suspect.
const HANDSHAKE_STALE_SECS: u64 = 180;

/// Classify link health from the handshake age (seconds since the freshest handshake).
pub fn link_health(handshake_age_secs: Option<u64>) -> LinkHealth {
    match handshake_age_secs {
        None => LinkHealth::Unknown,
        Some(a) if a <= HANDSHAKE_STALE_SECS => LinkHealth::Live,
        Some(_) => LinkHealth::Stale,
    }
}

pub struct App {
    pub cp_url: String,
    pub account: String,
    pub socket: PathBuf,
    pub servers: Vec<ServerInfo>,
    pub selected: usize,
    pub status: TunnelStatus,
    pub message: String,
    pub should_quit: bool,
    /// Per-poll tx/rx byte deltas (≈ bytes/sec at the 1 Hz poll), for the throughput sparkline.
    pub tx_rate: Vec<u64>,
    pub rx_rate: Vec<u64>,
    prev_tx: u64,
    prev_rx: u64,
    /// Animation frame for the "working" spinner.
    pub spinner: usize,
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
            tx_rate: Vec::new(),
            rx_rate: Vec::new(),
            prev_tx: 0,
            prev_rx: 0,
            spinner: 0,
        }
    }

    /// Advance the spinner one frame (called each render tick).
    pub fn tick_spinner(&mut self) {
        self.spinner = self.spinner.wrapping_add(1);
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
        // Record a throughput sample from the byte deltas since the last poll. On disconnect or
        // reconnect the counters can reset (go down); `saturating_sub` floors those at 0.
        if status.connected {
            let dtx = status.tx_bytes.saturating_sub(self.prev_tx);
            let drx = status.rx_bytes.saturating_sub(self.prev_rx);
            push_capped(&mut self.tx_rate, dtx);
            push_capped(&mut self.rx_rate, drx);
        } else if !self.tx_rate.is_empty() {
            // Fade the graph out while disconnected.
            self.tx_rate.clear();
            self.rx_rate.clear();
        }
        self.prev_tx = status.tx_bytes;
        self.prev_rx = status.rx_bytes;
        self.status = status;
    }

    /// Current link health, from the handshake age in the last status.
    pub fn link_health(&self) -> LinkHealth {
        link_health(self.status.handshake_age_secs)
    }
}

/// Push `v` onto `buf`, dropping the oldest sample past [`HISTORY_LEN`].
fn push_capped(buf: &mut Vec<u64>, v: u64) {
    buf.push(v);
    if buf.len() > HISTORY_LEN {
        buf.remove(0);
    }
}

/// Render `samples` as a unicode sparkline, scaled to the local maximum.
pub fn sparkline(samples: &[u64]) -> String {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let max = samples.iter().copied().max().unwrap_or(0);
    if max == 0 {
        return "▁".repeat(samples.len());
    }
    samples
        .iter()
        .map(|&v| {
            let idx = ((v as f64 / max as f64) * (BARS.len() - 1) as f64).round() as usize;
            BARS[idx.min(BARS.len() - 1)]
        })
        .collect()
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

    #[test]
    fn link_health_tracks_handshake_age() {
        assert_eq!(link_health(None), LinkHealth::Unknown);
        assert_eq!(link_health(Some(5)), LinkHealth::Live);
        assert_eq!(link_health(Some(600)), LinkHealth::Stale);
    }

    #[test]
    fn set_status_records_throughput_deltas() {
        let mut a = App::new("http://cp".into(), "acct".into(), "/tmp/s".into());
        let connected = |tx, rx| TunnelStatus {
            connected: true,
            tx_bytes: tx,
            rx_bytes: rx,
            ..Default::default()
        };
        a.set_status(connected(1000, 500));
        a.set_status(connected(1500, 900)); // +500 tx, +400 rx
        assert_eq!(a.tx_rate.last(), Some(&500));
        assert_eq!(a.rx_rate.last(), Some(&400));
        // A counter reset (reconnect) floors the delta at 0 rather than underflowing.
        a.set_status(connected(100, 50));
        assert_eq!(a.tx_rate.last(), Some(&0));
        // Disconnecting clears the graph.
        a.set_status(TunnelStatus::default());
        assert!(a.tx_rate.is_empty());
    }

    #[test]
    fn sparkline_scales_to_local_max() {
        assert_eq!(sparkline(&[]), "");
        assert_eq!(sparkline(&[0, 0, 0]), "▁▁▁"); // all-zero → flat baseline
        let s = sparkline(&[0, 5, 10]);
        let chars: Vec<char> = s.chars().collect();
        assert_eq!(chars.len(), 3);
        assert_eq!(chars[0], '▁'); // min
        assert_eq!(chars[2], '█'); // max
    }
}
