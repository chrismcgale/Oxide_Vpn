//! Reliability: liveness detection + reconnect policy for a classic always-on VPN.
//!
//! A real VPN survives server death and network changes. The pieces here are **pure** so
//! they're unit-tested without a tunnel; [`crate::run_supervised`] wires them to the real
//! engine. The signal is the freshest WireGuard handshake age ([`EngineStats::handshake_age_secs`]):
//! WireGuard rekeys every ~2 minutes, so an age that keeps growing past the rekey window means
//! the peer is gone (server down, or our network changed and keepalives no longer land).

use std::time::Duration;

use oxide_common::api::ServerInfo;
use oxide_wg_core::EngineStats;

/// Tunables for detecting a dead link and pacing reconnects.
#[derive(Debug, Clone, Copy)]
pub struct ReconnectPolicy {
    /// If no handshake completes within this after a (re)connect, the endpoint is unreachable.
    pub connect_timeout: Duration,
    /// Once established, a handshake age beyond this (rekey failed repeatedly) means dead.
    /// Kept above WireGuard's ~120 s rekey + retransmits so a healthy tunnel is never flagged.
    pub stale_after: Duration,
    /// How often the watchdog samples engine stats.
    pub poll: Duration,
    /// Reconnect backoff floor and ceiling.
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    /// Don't re-select a server that just failed for at least this long.
    pub server_cooldown: Duration,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        ReconnectPolicy {
            connect_timeout: Duration::from_secs(20),
            stale_after: Duration::from_secs(150),
            poll: Duration::from_secs(2),
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
            server_cooldown: Duration::from_secs(120),
        }
    }
}

/// Connection-lifecycle events emitted by [`crate::run_supervised`] so a UI/agent can show
/// status (selecting a server, connected, reconnecting after a drop, stopped).
#[derive(Debug, Clone)]
pub enum ConnEvent {
    /// Selecting a server (auto or after a failure).
    Selecting,
    /// Bringing up the tunnel — carries what a UI needs to show for this connection.
    Connecting(ConnInfo),
    /// The link died; reconnecting after `wait`.
    Reconnecting { server: String, wait: Duration },
    /// A "new identity" was requested: the device key was rotated and we're reconnecting
    /// to a *different* exit for per-session unlinkability.
    NewIdentity,
    /// The user asked to stop.
    Stopped,
}

/// Details of the connection being (re)established, for status display.
#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub server_id: Option<String>,
    pub exit_id: Option<String>,
    pub assigned_ip: String,
    pub stealth: bool,
    pub post_quantum: bool,
    /// Wire transport label (`plain`|`obfs`|`quic`|`mimic`).
    pub transport: String,
    /// Whether DAITA is shaping this connection.
    pub daita: bool,
}

/// Why a single tunnel attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelOutcome {
    /// The caller asked to stop (user disconnect / shutdown). Terminal.
    Disconnected,
    /// The link died. `was_up` distinguishes "an established session dropped" (retry fast)
    /// from "never connected" (back off — the endpoint may be blocked/dead).
    LinkDead { was_up: bool },
}

/// Whether the latest stats show a currently-live handshake (within the rekey window).
pub fn is_up(stats: &EngineStats, p: &ReconnectPolicy) -> bool {
    stats
        .handshake_age_secs
        .is_some_and(|a| a <= p.stale_after.as_secs())
}

/// Pure liveness decision. `ever_up` = a live handshake was seen at least once this attempt;
/// `since_start` = elapsed since this attempt began.
pub fn link_dead(
    stats: &EngineStats,
    ever_up: bool,
    since_start: Duration,
    p: &ReconnectPolicy,
) -> bool {
    if is_up(stats, p) {
        return false; // a fresh handshake means the link is alive right now
    }
    if ever_up {
        return true; // was established, handshake has gone stale => dead
    }
    since_start >= p.connect_timeout // never established: dead once the connect times out
}

/// Exponential backoff (capped) for the Nth consecutive failed attempt (1-based).
pub fn backoff(attempt: u32, p: &ReconnectPolicy) -> Duration {
    let shift = attempt.saturating_sub(1).min(16);
    let mult = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let secs = p.backoff_min.as_secs().saturating_mul(mult);
    Duration::from_secs(secs.clamp(p.backoff_min.as_secs(), p.backoff_max.as_secs()))
}

/// Client-side least-loaded server pick, used on reconnect to avoid a just-failed server
/// (mirrors the control plane's server-side selection). Filters to healthy, location-matching,
/// non-excluded servers and returns the one with the fewest live peers.
pub fn select_best<'a>(
    servers: &'a [ServerInfo],
    country: Option<&str>,
    city: Option<&str>,
    exclude: &[String],
) -> Option<&'a ServerInfo> {
    servers
        .iter()
        .filter(|s| s.healthy)
        .filter(|s| !exclude.iter().any(|e| e == &s.id))
        .filter(|s| country.is_none_or(|c| loc_eq(&s.country, c)))
        .filter(|s| city.is_none_or(|c| loc_eq(&s.city, c)))
        .min_by_key(|s| s.active_peers)
}

fn loc_eq(field: &Option<String>, want: &str) -> bool {
    field
        .as_deref()
        .is_some_and(|v| v.eq_ignore_ascii_case(want))
}

/// A future that resolves once `stop` is set to `true` (or its sender is dropped). Created
/// fresh each call so it can be awaited once per reconnect attempt.
pub async fn stopped(mut stop: tokio::sync::watch::Receiver<bool>) {
    if *stop.borrow() {
        return;
    }
    while stop.changed().await.is_ok() {
        if *stop.borrow() {
            return;
        }
    }
}

/// A future that resolves once `signal`'s value moves away from `last` — a "new identity"
/// request bumps a generation counter. Created fresh per reconnect attempt so the supervisor
/// can await it once per connection and compare the new generation afterward.
pub async fn signalled(mut signal: tokio::sync::watch::Receiver<u64>, last: u64) {
    if *signal.borrow() != last {
        return;
    }
    while signal.changed().await.is_ok() {
        if *signal.borrow() != last {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats_with_age(age: Option<u64>) -> EngineStats {
        EngineStats {
            handshake_age_secs: age,
            ..Default::default()
        }
    }

    #[test]
    fn fresh_handshake_is_alive() {
        let p = ReconnectPolicy::default();
        let s = stats_with_age(Some(3));
        assert!(is_up(&s, &p));
        assert!(!link_dead(&s, true, Duration::from_secs(999), &p));
        assert!(!link_dead(&s, false, Duration::from_secs(999), &p));
    }

    #[test]
    fn never_connected_is_dead_only_after_connect_timeout() {
        let p = ReconnectPolicy::default();
        let s = stats_with_age(None); // no handshake yet
        assert!(!link_dead(&s, false, Duration::from_secs(5), &p)); // still trying
        assert!(link_dead(&s, false, p.connect_timeout, &p)); // timed out
    }

    #[test]
    fn established_then_stale_is_dead() {
        let p = ReconnectPolicy::default();
        // Was up, but the handshake has aged past the rekey window.
        let stale = stats_with_age(Some(p.stale_after.as_secs() + 1));
        assert!(!is_up(&stale, &p));
        assert!(link_dead(&stale, true, Duration::from_secs(600), &p));
        // Within the window it's still considered up.
        let ok = stats_with_age(Some(p.stale_after.as_secs()));
        assert!(!link_dead(&ok, true, Duration::from_secs(600), &p));
    }

    #[test]
    fn backoff_grows_and_caps() {
        let p = ReconnectPolicy::default();
        assert_eq!(backoff(1, &p), p.backoff_min);
        assert!(backoff(2, &p) > backoff(1, &p));
        assert!(backoff(3, &p) > backoff(2, &p));
        assert_eq!(backoff(99, &p), p.backoff_max); // capped
    }

    fn server(id: &str, active: u32, healthy: bool, country: Option<&str>) -> ServerInfo {
        ServerInfo {
            id: id.into(),
            public_key: oxide_common::keys::public_from_secret(
                &oxide_common::keys::generate_secret(),
            ),
            endpoint: "203.0.113.1:51820".into(),
            country: country.map(str::to_string),
            city: None,
            active_peers: active,
            capacity: 100,
            healthy,
            pq_public_key: None,
        }
    }

    #[test]
    fn select_best_avoids_failed_and_picks_least_loaded() {
        let servers = vec![
            server("a", 50, true, Some("US")),
            server("b", 10, true, Some("US")), // least-loaded healthy overall
            server("c", 1, false, Some("US")), // unhealthy — skip despite lowest load
            server("d", 80, true, Some("DE")),
        ];
        // Least-loaded healthy overall is "b" (c is unhealthy and skipped).
        assert_eq!(select_best(&servers, None, None, &[]).unwrap().id, "b");
        // Excluding "b" (just died) falls back to the next-least-loaded healthy, "a".
        assert_eq!(
            select_best(&servers, None, None, &["b".into()]).unwrap().id,
            "a"
        );
        // Country filter honored.
        assert_eq!(
            select_best(&servers, Some("DE"), None, &[]).unwrap().id,
            "d"
        );
        // Everything excluded/unhealthy => None.
        assert!(select_best(&servers, Some("US"), None, &["a".into(), "b".into()]).is_none());
    }
}
