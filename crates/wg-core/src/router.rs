//! Allowed-IPs routing: map a tunnel-side IP to the peer that owns it.
//!
//! WireGuard's cryptokey routing works both ways:
//!   * Outbound (TUN -> network): pick the peer whose `allowed_ips` contains the
//!     packet's destination address.
//!   * Inbound (network -> TUN): after decapsulation, verify the packet's *source*
//!     address falls within the sending peer's `allowed_ips`, else drop it
//!     (anti-spoofing).
//!
//! Generic over the value type so the engine can key by a stable peer id (public key)
//! rather than a positional index — indices would shift as peers are added/removed at
//! runtime. A linear longest-prefix scan is fine for the peer counts M2 targets; a
//! trie would replace this without changing the API.

use std::net::IpAddr;

use ipnet::IpNet;

#[derive(Default)]
pub struct AllowedIps<V> {
    /// (network, value), searched for the longest matching prefix.
    entries: Vec<(IpNet, V)>,
}

impl<V: Copy + PartialEq> AllowedIps<V> {
    pub fn new() -> Self {
        AllowedIps {
            entries: Vec::new(),
        }
    }

    pub fn insert(&mut self, net: IpNet, value: V) {
        self.entries.push((net, value));
    }

    /// Return the value owning `addr` by longest-prefix match, if any.
    pub fn lookup(&self, addr: IpAddr) -> Option<V> {
        self.entries
            .iter()
            .filter(|(net, _)| net.contains(&addr))
            .max_by_key(|(net, _)| net.prefix_len())
            .map(|(_, v)| *v)
    }

    /// True if `addr` is within any prefix assigned to `value` (source check).
    pub fn is_allowed_for(&self, addr: IpAddr, value: V) -> bool {
        self.entries
            .iter()
            .any(|(net, v)| *v == value && net.contains(&addr))
    }

    /// Drop every entry pointing at `value` (peer removal).
    pub fn retain_not(&mut self, value: V) {
        self.entries.retain(|(_, v)| *v != value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_prefix_wins() {
        let mut a: AllowedIps<usize> = AllowedIps::new();
        a.insert("0.0.0.0/0".parse().unwrap(), 0);
        a.insert("10.8.0.0/24".parse().unwrap(), 1);
        assert_eq!(a.lookup("10.8.0.5".parse().unwrap()), Some(1));
        assert_eq!(a.lookup("1.1.1.1".parse().unwrap()), Some(0));
    }

    #[test]
    fn source_check() {
        let mut a: AllowedIps<usize> = AllowedIps::new();
        a.insert("10.8.0.2/32".parse().unwrap(), 3);
        assert!(a.is_allowed_for("10.8.0.2".parse().unwrap(), 3));
        assert!(!a.is_allowed_for("10.8.0.3".parse().unwrap(), 3));
        assert!(!a.is_allowed_for("10.8.0.2".parse().unwrap(), 4));
    }

    #[test]
    fn retain_not_removes_value() {
        let mut a: AllowedIps<usize> = AllowedIps::new();
        a.insert("10.8.0.2/32".parse().unwrap(), 3);
        a.insert("10.8.0.3/32".parse().unwrap(), 4);
        a.retain_not(3);
        assert_eq!(a.lookup("10.8.0.2".parse().unwrap()), None);
        assert_eq!(a.lookup("10.8.0.3".parse().unwrap()), Some(4));
    }
}
