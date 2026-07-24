//! Kill switch: block all outbound traffic that doesn't go through the tunnel.
//!
//! If the tunnel drops, the OS would normally fall back to the default route and leak
//! plaintext to the ISP. The kill switch prevents that with an nftables `output` chain whose
//! policy is `drop`, permitting only:
//!   * loopback,
//!   * traffic out the tunnel interface,
//!   * the encrypted WireGuard UDP to the server endpoint (so the tunnel itself and its
//!     handshake/rekeys keep working).
//!
//! Everything else is dropped, so nothing escapes in the clear even mid-reconnect. Installed
//! in a dedicated `inet oxide-ks` table so teardown is a single table delete and the host's
//! other firewall rules are untouched.
//!
//! **2F:** this is built over **netlink** (via `rustables`) — no `nft` binary shell-out. The
//! permit set is described as pure data ([`permits`]) so the policy stays unit-testable
//! without touching the kernel; [`apply`] turns it into an nftables transaction. (Server NAT
//! still uses `nft` — see [`crate::nat`] — because its MSS-clamp rule isn't expressible in
//! rustables.)

use std::io;
use std::net::IpAddr;

use rustables::{
    Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType, Protocol, ProtocolFamily, Rule,
    Table,
};

const TABLE: &str = "oxide-ks";
const CHAIN: &str = "output";

/// A single permit in the kill-switch `output` chain. Everything not matched by a permit is
/// dropped by the chain's `drop` policy. Pure data so the policy is testable without the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Permit {
    /// Allow traffic leaving via this interface (by name): loopback and the tunnel.
    OutInterface(String),
    /// Allow the encrypted WireGuard UDP to the server endpoint, so the tunnel itself (and
    /// its handshakes/rekeys) keeps working even while everything else is blocked.
    ServerEndpoint(IpAddr, u16),
}

/// The permit set for a server reachable at `server_ip:server_port` with the tunnel on
/// `tun_if`: loopback, the tunnel interface, and the encrypted WG UDP to the server. Order is
/// irrelevant (all are `accept`); the chain's `drop` policy blocks the rest.
pub fn permits(server_ip: IpAddr, server_port: u16, tun_if: &str) -> Vec<Permit> {
    vec![
        Permit::OutInterface("lo".to_string()),
        Permit::OutInterface(tun_if.to_string()),
        Permit::ServerEndpoint(server_ip, server_port),
    ]
}

/// Install the kill switch. Safe to call repeatedly (drops any existing table first).
pub fn enable(server_ip: IpAddr, server_port: u16, tun_if: &str) -> io::Result<()> {
    let _ = disable();
    apply(&permits(server_ip, server_port, tun_if))
        .map_err(|e| io::Error::other(format!("installing kill switch via netlink: {e}")))
}

/// Build the `inet oxide-ks` table + `drop`-policy output chain + one accept rule per permit,
/// and send it as one netlink transaction.
fn apply(permits: &[Permit]) -> Result<(), Box<dyn std::error::Error>> {
    let mut batch = Batch::new();

    let table = Table::new(ProtocolFamily::Inet).with_name(TABLE);
    batch.add(&table, MsgType::Add);

    // output chain, default drop: only the permits below get through.
    let chain = Chain::new(&table)
        .with_name(CHAIN)
        .with_hook(Hook::new(HookClass::Out, 0))
        .with_type(ChainType::Filter)
        .with_policy(ChainPolicy::Drop);
    batch.add(&chain, MsgType::Add);

    for p in permits {
        let rule = match p {
            Permit::OutInterface(name) => Rule::new(&chain)?.oiface(name)?.accept(),
            Permit::ServerEndpoint(ip, port) => Rule::new(&chain)?
                .daddr(*ip)
                .dport(*port, Protocol::UDP)
                .accept(),
        };
        batch.add(&rule, MsgType::Add);
    }

    batch.send()?;
    Ok(())
}

/// Remove the kill switch. Idempotent — deleting a table that isn't there is ignored.
pub fn disable() -> io::Result<()> {
    let mut batch = Batch::new();
    let table = Table::new(ProtocolFamily::Inet).with_name(TABLE);
    batch.add(&table, MsgType::Del);
    // A `Del` of a non-existent table errors (ENOENT); teardown must stay idempotent.
    let _ = batch.send();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permits_lo_tunnel_and_server_only() {
        let ps = permits("203.0.113.7".parse().unwrap(), 51820, "oxide0");
        assert_eq!(
            ps,
            vec![
                Permit::OutInterface("lo".into()),
                Permit::OutInterface("oxide0".into()),
                Permit::ServerEndpoint("203.0.113.7".parse().unwrap(), 51820),
            ]
        );
    }

    #[test]
    fn server_permit_carries_the_endpoint_family() {
        // v4 and v6 endpoints both round-trip through the permit (apply picks ip/ip6 daddr).
        let v6 = permits("2001:db8::1".parse().unwrap(), 51820, "oxide0");
        assert!(matches!(
            v6[2],
            Permit::ServerEndpoint(IpAddr::V6(_), 51820)
        ));
    }
}
