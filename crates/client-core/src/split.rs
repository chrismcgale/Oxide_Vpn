//! Split-tunnelling route planning (per-destination).
//!
//! Given the peers' `allowed_ips` plus optional `split_include` / `split_exclude` config,
//! [`plan_routes`] produces the concrete set of OS routes the client should install:
//!
//!   * **full-tunnel** — a `0.0.0.0/0` / `::/0` peer swings that family's default into the
//!     tunnel (the existing behaviour), and specific CIDRs for that family are subsumed.
//!   * **include** — with no default for a family, each specific `allowed_ips` CIDR (and any
//!     `split_include`) is routed on-link **via the tunnel device**. This is what previously
//!     required a manual `ip route add <cidr> dev oxide0`.
//!   * **exclude** — `split_exclude` CIDRs are pinned to the **original default gateway** so
//!     they bypass the tunnel; a more specific exclude wins over the tunnel default by
//!     longest-prefix match.
//!
//! This module is pure (no netlink): `run_tunnel` consumes the plan and installs/removes the
//! routes, tracking them for teardown. Kept separate so the planning is unit-testable
//! without root.

use ipnet::IpNet;

/// The routes a split-tunnel configuration implies. Consumed by `run_tunnel`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutePlan {
    /// Swing the IPv4 default into the tunnel (a `0.0.0.0/0` peer).
    pub full_tunnel_v4: bool,
    /// Swing the IPv6 default into the tunnel (a `::/0` peer).
    pub full_tunnel_v6: bool,
    /// CIDRs to route on-link **via the tunnel device** (include mode / explicit includes).
    pub via_tunnel: Vec<IpNet>,
    /// CIDRs to pin **around** the tunnel via the original default gateway (exclude mode).
    pub via_gateway: Vec<IpNet>,
}

impl RoutePlan {
    /// True if any family's default is swung into the tunnel.
    pub fn is_full_tunnel(&self) -> bool {
        self.full_tunnel_v4 || self.full_tunnel_v6
    }
}

/// True for a default route (`0.0.0.0/0` or `::/0`).
pub fn is_default(n: &IpNet) -> bool {
    n.prefix_len() == 0
}

fn is_default_v4(n: &IpNet) -> bool {
    matches!(n, IpNet::V4(v) if v.prefix_len() == 0)
}

fn is_default_v6(n: &IpNet) -> bool {
    matches!(n, IpNet::V6(v) if v.prefix_len() == 0)
}

fn push_unique(v: &mut Vec<IpNet>, n: IpNet) {
    if !v.contains(&n) {
        v.push(n);
    }
}

/// Build the [`RoutePlan`] from the union of the peers' `allowed_ips` and the split config.
///
/// `allowed_ips` should be every peer's allowed CIDRs flattened; `split_include` /
/// `split_exclude` come from `[interface]`. The plan is per-family: a `0.0.0.0/0` peer makes
/// IPv4 full-tunnel while a specific-only IPv6 set still routes its CIDRs via the tunnel.
pub fn plan_routes(
    allowed_ips: &[IpNet],
    split_include: &[IpNet],
    split_exclude: &[IpNet],
) -> RoutePlan {
    let full_tunnel_v4 = allowed_ips.iter().any(is_default_v4);
    let full_tunnel_v6 = allowed_ips.iter().any(is_default_v6);

    let mut via_tunnel: Vec<IpNet> = Vec::new();
    // Explicit includes always route through the tunnel.
    for n in split_include {
        push_unique(&mut via_tunnel, *n);
    }
    // Include mode: a specific allowed_ips CIDR gets its own on-link tunnel route unless that
    // family is already full-tunnel (the default swing subsumes it).
    for n in allowed_ips {
        if is_default(n) {
            continue;
        }
        let family_full = match n {
            IpNet::V4(_) => full_tunnel_v4,
            IpNet::V6(_) => full_tunnel_v6,
        };
        if !family_full {
            push_unique(&mut via_tunnel, *n);
        }
    }

    let mut via_gateway: Vec<IpNet> = Vec::new();
    for n in split_exclude {
        push_unique(&mut via_gateway, *n);
    }
    // An exact-match exclude wins over an include: drop it from the tunnel set.
    via_tunnel.retain(|n| !via_gateway.contains(n));

    RoutePlan {
        full_tunnel_v4,
        full_tunnel_v6,
        via_tunnel,
        via_gateway,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn full_tunnel_peer_swings_default_and_subsumes_specifics() {
        let plan = plan_routes(&[net("0.0.0.0/0"), net("10.8.0.0/24")], &[], &[]);
        assert!(plan.full_tunnel_v4);
        assert!(!plan.full_tunnel_v6);
        // The specific v4 CIDR is subsumed by the default swing — no extra route.
        assert!(plan.via_tunnel.is_empty());
        assert!(plan.via_gateway.is_empty());
    }

    #[test]
    fn include_mode_routes_specific_cidrs_via_tunnel() {
        // No default: each specific allowed_ips CIDR becomes an on-link tunnel route
        // (the manual `ip route add ... dev oxide0` this removes).
        let plan = plan_routes(&[net("10.8.0.0/24"), net("192.168.9.0/24")], &[], &[]);
        assert!(!plan.is_full_tunnel());
        assert_eq!(
            plan.via_tunnel,
            vec![net("10.8.0.0/24"), net("192.168.9.0/24")]
        );
        assert!(plan.via_gateway.is_empty());
    }

    #[test]
    fn explicit_include_adds_a_route_and_dedups() {
        let plan = plan_routes(
            &[net("10.8.0.0/24")],
            &[net("172.16.0.0/16"), net("10.8.0.0/24")],
            &[],
        );
        // Explicit include first, then the (deduped) allowed_ips CIDR.
        assert_eq!(
            plan.via_tunnel,
            vec![net("172.16.0.0/16"), net("10.8.0.0/24")]
        );
    }

    #[test]
    fn exclude_under_full_tunnel_pins_via_gateway() {
        let plan = plan_routes(&[net("0.0.0.0/0")], &[], &[net("1.2.3.0/24")]);
        assert!(plan.full_tunnel_v4);
        assert_eq!(plan.via_gateway, vec![net("1.2.3.0/24")]);
        assert!(plan.via_tunnel.is_empty());
    }

    #[test]
    fn exclude_wins_over_an_exact_include() {
        let plan = plan_routes(&[net("10.0.0.0/8")], &[], &[net("10.0.0.0/8")]);
        assert!(
            plan.via_tunnel.is_empty(),
            "exact exclude removes the include"
        );
        assert_eq!(plan.via_gateway, vec![net("10.0.0.0/8")]);
    }

    #[test]
    fn dual_stack_default_v4_specific_v6() {
        // v4 full-tunnel, v6 specific -> v6 CIDR routes via the tunnel, v4 specific subsumed.
        let plan = plan_routes(
            &[net("0.0.0.0/0"), net("10.8.0.0/24"), net("2001:db8::/48")],
            &[],
            &[],
        );
        assert!(plan.full_tunnel_v4 && !plan.full_tunnel_v6);
        assert_eq!(plan.via_tunnel, vec![net("2001:db8::/48")]);
    }
}
