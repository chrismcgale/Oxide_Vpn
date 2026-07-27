//! Admin-console state and pure, testable helpers. Rendering lives in `main`.
//!
//! The admin TUI is a read-only operator view over the control plane's admin API
//! (`/v1/admin/overview` + `/v1/admin/servers`): fleet health, feature adoption, and
//! bandwidth turned into an estimated cost. It shows only fleet-level aggregates — no
//! per-account data — so it never sees who is connected, only how much the fleet is doing.

use oxide_common::api::{AdminOverview, AdminServerInfo};

/// Bytes in a "GB" for billing (cloud egress is priced per 10^9 bytes, not GiB).
const GB: f64 = 1_000_000_000.0;

/// The three panels of the console.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Overview,
    Servers,
    Features,
}

impl Tab {
    pub const ALL: [Tab; 3] = [Tab::Overview, Tab::Servers, Tab::Features];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Servers => "Servers",
            Tab::Features => "Features",
        }
    }

    pub fn index(self) -> usize {
        Tab::ALL.iter().position(|&t| t == self).unwrap_or(0)
    }

    pub fn next(self) -> Tab {
        Tab::ALL[(self.index() + 1) % Tab::ALL.len()]
    }

    pub fn prev(self) -> Tab {
        Tab::ALL[(self.index() + Tab::ALL.len() - 1) % Tab::ALL.len()]
    }
}

/// A simple, transparent cost model: bandwidth is billed per GB of **egress** (server→out),
/// plus a flat per-server-hour rate for the running fleet. Both rates are operator-set. This
/// is an estimate for capacity planning, not an invoice.
#[derive(Clone, Copy)]
pub struct CostModel {
    pub per_gb: f64,
    pub per_server_hour: f64,
}

impl CostModel {
    /// Cost of `egress_bytes` of egress at the configured per-GB rate.
    pub fn bandwidth_cost(&self, egress_bytes: u64) -> f64 {
        egress_bytes as f64 / GB * self.per_gb
    }

    /// Cost of running servers for `server_hours` combined hours.
    pub fn server_cost(&self, server_hours: f64) -> f64 {
        server_hours * self.per_server_hour
    }

    /// Bandwidth + server-time cost together.
    pub fn total(&self, egress_bytes: u64, server_hours: f64) -> f64 {
        self.bandwidth_cost(egress_bytes) + self.server_cost(server_hours)
    }
}

/// Hours elapsed since `created_at` (unix seconds) as of `now`, clamped at 0.
pub fn hours_since(created_at: i64, now: i64) -> f64 {
    (now - created_at).max(0) as f64 / 3600.0
}

/// Fraction of capacity in use, `None` when capacity is unset (unlimited).
pub fn load_fraction(active_peers: u32, capacity: u32) -> Option<f64> {
    if capacity == 0 {
        None
    } else {
        Some(active_peers as f64 / capacity as f64)
    }
}

/// Load above this fraction of capacity raises a "nearly full" alert.
pub const HIGH_LOAD: f64 = 0.80;

/// An operational alert about a server that wants an operator's attention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alert {
    /// No recent heartbeat — the server may be down.
    Stale,
    /// Running hot: at or above [`HIGH_LOAD`] of capacity.
    HighLoad,
}

impl Alert {
    pub fn label(self) -> &'static str {
        match self {
            Alert::Stale => "STALE",
            Alert::HighLoad => "HIGH LOAD",
        }
    }
}

/// The most pressing alert for a server, if any. A dead server outranks a busy one.
pub fn server_alert(s: &AdminServerInfo) -> Option<Alert> {
    if !s.healthy {
        Some(Alert::Stale)
    } else if load_fraction(s.active_peers, s.capacity).is_some_and(|f| f >= HIGH_LOAD) {
        Some(Alert::HighLoad)
    } else {
        None
    }
}

/// Fraction of the fleet that has a feature enabled (0.0 when there are no servers).
pub fn adoption(count: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        count as f64 / total as f64
    }
}

/// How many bandwidth samples the fleet sparkline keeps.
const HISTORY_LEN: usize = 60;

/// Push `v` onto `buf`, dropping the oldest sample past [`HISTORY_LEN`].
fn push_capped(buf: &mut Vec<u64>, v: u64) {
    buf.push(v);
    if buf.len() > HISTORY_LEN {
        buf.remove(0);
    }
}

/// Render `samples` as a unicode sparkline scaled to the local maximum.
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

/// Human-readable byte count.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
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

pub struct App {
    pub cp_url: String,
    pub admin_token: String,
    pub cost: CostModel,
    pub overview: Option<AdminOverview>,
    pub servers: Vec<AdminServerInfo>,
    pub selected: usize,
    pub tab: Tab,
    pub message: String,
    /// Unix time captured at the last successful refresh (for uptime/cost math).
    pub now: i64,
    /// A server id whose token rotation is armed and awaiting confirmation (destructive action).
    pub confirm_rotate: Option<String>,
    /// Per-refresh fleet byte deltas (bytes moved between the last two refreshes), for the
    /// bandwidth-over-time sparkline. Derived from successive cumulative totals.
    pub tx_rate: Vec<u64>,
    pub rx_rate: Vec<u64>,
    /// Last cumulative (tx, rx) totals seen, to difference against — `None` until the first
    /// sample establishes a baseline.
    prev_bytes: Option<(u64, u64)>,
    /// Seconds between refreshes, so a per-refresh delta can be shown as a per-second rate.
    pub refresh_secs: u64,
    pub should_quit: bool,
}

impl App {
    pub fn new(cp_url: String, admin_token: String, cost: CostModel) -> Self {
        App {
            cp_url,
            admin_token,
            cost,
            overview: None,
            servers: Vec::new(),
            selected: 0,
            tab: Tab::Overview,
            message: "loading…".into(),
            now: 0,
            confirm_rotate: None,
            tx_rate: Vec::new(),
            rx_rate: Vec::new(),
            prev_bytes: None,
            refresh_secs: 3,
            should_quit: false,
        }
    }

    /// Fold a fresh pair of cumulative fleet totals into the bandwidth history. The first call
    /// only sets the baseline (no bar yet); later calls push the delta since the previous one.
    /// Totals are monotonic (the control plane accumulates), so `saturating_sub` just guards
    /// the degenerate case.
    pub fn record_bandwidth(&mut self, tx_total: u64, rx_total: u64) {
        if let Some((ptx, prx)) = self.prev_bytes {
            push_capped(&mut self.tx_rate, tx_total.saturating_sub(ptx));
            push_capped(&mut self.rx_rate, rx_total.saturating_sub(prx));
        }
        self.prev_bytes = Some((tx_total, rx_total));
    }

    /// The most recent per-second rate for a history series (latest delta / refresh interval).
    pub fn latest_rate(&self, series: &[u64]) -> u64 {
        series.last().copied().unwrap_or(0) / self.refresh_secs.max(1)
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

    pub fn set_servers(&mut self, servers: Vec<AdminServerInfo>) {
        self.servers = servers;
        if self.selected >= self.servers.len() {
            self.selected = 0;
        }
    }

    /// The currently-selected server, if any.
    pub fn selected_server(&self) -> Option<&AdminServerInfo> {
        self.servers.get(self.selected)
    }

    /// How many servers currently have an operational alert (stale or overloaded).
    pub fn alert_count(&self) -> usize {
        self.servers
            .iter()
            .filter(|s| server_alert(s).is_some())
            .count()
    }

    /// Combined server-hours across the fleet (for the flat-rate part of the cost).
    pub fn fleet_server_hours(&self) -> f64 {
        self.servers
            .iter()
            .map(|s| hours_since(s.created_at, self.now))
            .sum()
    }

    /// Estimated total fleet cost = egress bandwidth + server-time.
    pub fn fleet_cost(&self) -> f64 {
        let egress = self
            .overview
            .as_ref()
            .map(|o| o.tx_bytes_total)
            .unwrap_or(0);
        self.cost.total(egress, self.fleet_server_hours())
    }

    /// Estimated cost attributed to one server (its egress + its uptime).
    pub fn server_cost(&self, s: &AdminServerInfo) -> f64 {
        self.cost.bandwidth_cost(s.tx_bytes_total)
            + self.cost.server_cost(hours_since(s.created_at, self.now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tab_cycles_both_ways() {
        assert_eq!(Tab::Overview.next(), Tab::Servers);
        assert_eq!(Tab::Features.next(), Tab::Overview);
        assert_eq!(Tab::Overview.prev(), Tab::Features);
    }

    #[test]
    fn cost_splits_bandwidth_and_server_time() {
        let m = CostModel {
            per_gb: 0.10,
            per_server_hour: 0.02,
        };
        // 5 GB egress → $0.50; 100 server-hours → $2.00.
        assert!((m.bandwidth_cost(5_000_000_000) - 0.50).abs() < 1e-9);
        assert!((m.server_cost(100.0) - 2.00).abs() < 1e-9);
        assert!((m.total(5_000_000_000, 100.0) - 2.50).abs() < 1e-9);
    }

    #[test]
    fn hours_since_clamps_and_scales() {
        assert!((hours_since(0, 7200) - 2.0).abs() < 1e-9);
        assert_eq!(hours_since(100, 50), 0.0); // future created_at → clamped
    }

    #[test]
    fn load_fraction_handles_unlimited() {
        assert_eq!(load_fraction(50, 100), Some(0.5));
        assert_eq!(load_fraction(9, 0), None);
    }

    #[test]
    fn adoption_is_zero_for_empty_fleet() {
        assert_eq!(adoption(0, 0), 0.0);
        assert!((adoption(3, 4) - 0.75).abs() < 1e-9);
    }

    #[test]
    fn human_bytes_scales() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2048), "2.0 KiB");
    }

    #[test]
    fn fleet_cost_uses_egress_and_uptime() {
        let m = CostModel {
            per_gb: 0.10,
            per_server_hour: 1.0,
        };
        let mut app = App::new("http://cp".into(), "tok".into(), m);
        app.now = 3600; // 1h since epoch
        app.overview = Some(AdminOverview {
            accounts: 0,
            servers: 1,
            devices: 0,
            healthy_servers: 1,
            active_peers: 0,
            tx_bytes_total: 1_000_000_000, // 1 GB egress → $0.10
            rx_bytes_total: 0,
            stealth_servers: 0,
            quic_servers: 0,
            daita_servers: 0,
            pq_servers: 0,
        });
        app.set_servers(vec![sample_server("s1", 0)]); // created at epoch → 1 server-hour → $1.00
        assert!((app.fleet_server_hours() - 1.0).abs() < 1e-9);
        assert!((app.fleet_cost() - 1.10).abs() < 1e-9);
    }

    #[test]
    fn alerts_flag_stale_and_overloaded() {
        let mut s = sample_server("s1", 0); // healthy, 10/100 load → no alert
        assert_eq!(server_alert(&s), None);
        s.active_peers = 85; // ≥80% → high load
        assert_eq!(server_alert(&s), Some(Alert::HighLoad));
        s.healthy = false; // stale outranks high load
        assert_eq!(server_alert(&s), Some(Alert::Stale));
    }

    #[test]
    fn record_bandwidth_differences_cumulative_totals() {
        let m = CostModel {
            per_gb: 0.0,
            per_server_hour: 0.0,
        };
        let mut app = App::new("http://cp".into(), "tok".into(), m);
        app.refresh_secs = 2;
        // First sample only sets the baseline — no bar yet.
        app.record_bandwidth(1_000, 500);
        assert!(app.tx_rate.is_empty());
        // Later samples push the delta since the previous cumulative reading.
        app.record_bandwidth(3_000, 1_500); // +2_000 tx, +1_000 rx
        app.record_bandwidth(3_000, 4_500); // +0 tx, +3_000 rx
        assert_eq!(app.tx_rate, vec![2_000, 0]);
        assert_eq!(app.rx_rate, vec![1_000, 3_000]);
        // latest_rate divides the last delta by the refresh interval (2s).
        assert_eq!(app.latest_rate(&app.tx_rate), 0);
        assert_eq!(app.latest_rate(&app.rx_rate), 1_500);
    }

    #[test]
    fn sparkline_scales_and_handles_flat() {
        assert_eq!(sparkline(&[]), "");
        assert_eq!(sparkline(&[0, 0]), "▁▁");
        let s: Vec<char> = sparkline(&[0, 5, 10]).chars().collect();
        assert_eq!(s[0], '▁');
        assert_eq!(s[2], '█');
    }

    #[test]
    fn alert_count_sums_flagged_servers() {
        let m = CostModel {
            per_gb: 0.0,
            per_server_hour: 0.0,
        };
        let mut app = App::new("http://cp".into(), "tok".into(), m);
        let mut hot = sample_server("hot", 0);
        hot.active_peers = 95;
        let mut down = sample_server("down", 0);
        down.healthy = false;
        app.set_servers(vec![sample_server("ok", 0), hot, down]);
        assert_eq!(app.alert_count(), 2);
    }

    fn sample_server(id: &str, created_at: i64) -> AdminServerInfo {
        AdminServerInfo {
            id: id.into(),
            endpoint: "1.2.3.4:51820".into(),
            country: Some("US".into()),
            city: None,
            capacity: 100,
            active_peers: 10,
            healthy: true,
            transport: Some("quic".into()),
            daita: true,
            post_quantum: true,
            stealth: false,
            tx_bytes_total: 2_000_000_000,
            rx_bytes_total: 1_000_000_000,
            last_heartbeat_secs: Some(5),
            created_at,
        }
    }
}
