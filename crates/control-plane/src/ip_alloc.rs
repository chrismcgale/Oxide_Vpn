//! Tunnel-IP allocation within a server's subnet.

use std::collections::HashSet;
use std::net::IpAddr;

use ipnet::IpNet;

/// Pick the lowest usable host address in `cidr` that isn't the server's own tunnel
/// IP and isn't already assigned. Returns `None` if the subnet is exhausted.
pub fn allocate(cidr: IpNet, server_ip: IpAddr, used: &HashSet<IpAddr>) -> Option<IpAddr> {
    cidr.hosts().find(|h| *h != server_ip && !used.contains(h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_lowest_free_skipping_server() {
        let cidr: IpNet = "10.8.0.0/24".parse().unwrap();
        let server: IpAddr = "10.8.0.1".parse().unwrap();
        let mut used = HashSet::new();

        // First allocation skips .0 (network) and .1 (server) -> .2
        let a = allocate(cidr, server, &used).unwrap();
        assert_eq!(a, "10.8.0.2".parse::<IpAddr>().unwrap());
        used.insert(a);

        let b = allocate(cidr, server, &used).unwrap();
        assert_eq!(b, "10.8.0.3".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn exhaustion_returns_none() {
        let cidr: IpNet = "10.8.0.0/30".parse().unwrap(); // hosts: .1, .2
        let server: IpAddr = "10.8.0.1".parse().unwrap();
        let mut used = HashSet::new();
        used.insert("10.8.0.2".parse().unwrap());
        assert_eq!(allocate(cidr, server, &used), None);
    }
}
