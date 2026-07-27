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

/// Fraction of the fleet that has a feature enabled (0.0 when there are no servers).
pub fn adoption(count: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        count as f64 / total as f64
    }
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

    pub fn set_servers(&mut self, servers: Vec<AdminServerInfo>) {
        self.servers = servers;
        if self.selected >= self.servers.len() {
            self.selected = 0;
        }
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
