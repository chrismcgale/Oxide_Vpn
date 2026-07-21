//! Kill switch: block all outbound traffic that doesn't go through the tunnel.
//!
//! If the tunnel drops, the OS would normally fall back to the default route and
//! leak plaintext to the ISP. The kill switch prevents that with an nftables `output`
//! chain whose policy is `drop`, permitting only:
//!   * loopback,
//!   * traffic out the tunnel interface,
//!   * the encrypted WireGuard UDP to the server endpoint (so the tunnel itself and
//!     its handshake/rekeys keep working).
//!
//! Everything else is dropped, so nothing escapes in the clear even mid-reconnect.
//! Applied in a dedicated table so teardown is a single `nft delete table` and the
//! host's other firewall rules are untouched.

use std::io;
use std::net::IpAddr;

use crate::cmd::{apply_nft_ruleset, run};

const TABLE: &str = "oxide-ks";

/// Build the kill-switch ruleset for a server reachable at `server_ip:server_port`
/// with the tunnel on `tun_if`.
pub fn build_ruleset(server_ip: IpAddr, server_port: u16, tun_if: &str) -> String {
    // Match the server address in the right family.
    let server_rule = match server_ip {
        IpAddr::V4(v4) => format!("ip daddr {v4} udp dport {server_port} accept"),
        IpAddr::V6(v6) => format!("ip6 daddr {v6} udp dport {server_port} accept"),
    };
    format!(
        "table inet {TABLE} {{
            chain output {{
                type filter hook output priority filter; policy drop;
                oif \"lo\" accept
                oifname \"{tun_if}\" accept
                {server_rule}
            }}
        }}"
    )
}

/// Install the kill switch. Safe to call repeatedly (replaces any existing table).
pub fn enable(server_ip: IpAddr, server_port: u16, tun_if: &str) -> io::Result<()> {
    let _ = disable();
    apply_nft_ruleset(&build_ruleset(server_ip, server_port, tun_if))
}

/// Remove the kill switch. Idempotent.
pub fn disable() -> io::Result<()> {
    let _ = run("nft", &["delete", "table", "inet", TABLE]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_permits_only_lo_tunnel_and_server() {
        let rs = build_ruleset("203.0.113.7".parse().unwrap(), 51820, "oxide0");
        assert!(rs.contains("policy drop"));
        assert!(rs.contains("oif \"lo\" accept"));
        assert!(rs.contains("oifname \"oxide0\" accept"));
        assert!(rs.contains("ip daddr 203.0.113.7 udp dport 51820 accept"));
        // No blanket accept that would defeat the switch.
        assert!(!rs.contains("policy accept"));
    }

    #[test]
    fn ipv6_server_uses_ip6_match() {
        let rs = build_ruleset("2001:db8::1".parse().unwrap(), 51820, "oxide0");
        assert!(rs.contains("ip6 daddr 2001:db8::1 udp dport 51820 accept"));
    }
}
