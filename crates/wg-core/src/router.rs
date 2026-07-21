//! Allowed-IPs routing: map a tunnel-side destination IP to the peer that owns it.
//!
//! WireGuard's cryptokey routing works both ways:
//!   * Outbound (TUN -> network): pick the peer whose `allowed_ips` contains the
//!     packet's destination address.
//!   * Inbound (network -> TUN): after decapsulation, verify the packet's *source*
//!     address falls within the sending peer's `allowed_ips`, else drop it
//!     (anti-spoofing).
//!
//! M1 has a small number of peers, so a linear longest-prefix scan is fine. This is
//! the structure a future trie would replace without changing the public API.

use std::net::IpAddr;

use ipnet::IpNet;

/// Index into the engine's peer table.
pub type PeerIdx = usize;

#[derive(Default)]
pub struct AllowedIps {
    /// (network, peer index), searched for the longest matching prefix.
    entries: Vec<(IpNet, PeerIdx)>,
}

impl AllowedIps {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, net: IpNet, peer: PeerIdx) {
        self.entries.push((net, peer));
    }

    /// Return the peer owning `addr` by longest-prefix match, if any.
    pub fn lookup(&self, addr: IpAddr) -> Option<PeerIdx> {
        self.entries
            .iter()
            .filter(|(net, _)| net.contains(&addr))
            .max_by_key(|(net, _)| net.prefix_len())
            .map(|(_, peer)| *peer)
    }

    /// True if `addr` is within any prefix assigned to `peer` (source check).
    pub fn is_allowed_for(&self, addr: IpAddr, peer: PeerIdx) -> bool {
        self.entries
            .iter()
            .any(|(net, p)| *p == peer && net.contains(&addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_prefix_wins() {
        let mut a = AllowedIps::new();
        a.insert("0.0.0.0/0".parse().unwrap(), 0);
        a.insert("10.8.0.0/24".parse().unwrap(), 1);
        assert_eq!(a.lookup("10.8.0.5".parse().unwrap()), Some(1));
        assert_eq!(a.lookup("1.1.1.1".parse().unwrap()), Some(0));
    }

    #[test]
    fn source_check() {
        let mut a = AllowedIps::new();
        a.insert("10.8.0.2/32".parse().unwrap(), 3);
        assert!(a.is_allowed_for("10.8.0.2".parse().unwrap(), 3));
        assert!(!a.is_allowed_for("10.8.0.3".parse().unwrap(), 3));
        assert!(!a.is_allowed_for("10.8.0.2".parse().unwrap(), 4));
    }
}
