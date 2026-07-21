//! Interface addressing and routing via iproute2 (`ip`).
//!
//! Named `netlink` because that is the kernel API it fronts; the M5 roadmap swaps the
//! shell-outs here for a real rtnetlink socket without changing callers.

use std::io;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::cmd::{output, run};

/// Bring an interface administratively up.
pub fn set_up(ifname: &str) -> io::Result<()> {
    run("ip", &["link", "set", "dev", ifname, "up"])
}

/// Set the interface MTU. WireGuard's default of 1420 avoids fragmentation under a
/// 1500-byte path (this is the #1 "ping works, curl hangs" fix).
pub fn set_mtu(ifname: &str, mtu: u32) -> io::Result<()> {
    run(
        "ip",
        &["link", "set", "dev", ifname, "mtu", &mtu.to_string()],
    )
}

/// Assign a tunnel address (with prefix) to the interface.
pub fn add_address(ifname: &str, addr: IpNet) -> io::Result<()> {
    run("ip", &["addr", "add", &addr.to_string(), "dev", ifname])
}

/// Route a destination prefix out through the interface (on-link).
pub fn add_route_dev(dst: IpNet, ifname: &str) -> io::Result<()> {
    run("ip", &["route", "add", &dst.to_string(), "dev", ifname])
}

/// Delete a route by destination CIDR string (teardown).
pub fn del_route(cidr: &str) -> io::Result<()> {
    run("ip", &["route", "del", cidr])
}

/// Add a `/32` (or `/128`) host route to `host` via a specific gateway. Used to pin
/// the route to the VPN server's endpoint through the *original* default gateway
/// before we swing the default route into the tunnel — otherwise the tunnel's own
/// UDP would recursively route into itself.
pub fn add_host_route_via(host: IpAddr, gateway: IpAddr, ifname: &str) -> io::Result<()> {
    let host_cidr = match host {
        IpAddr::V4(v4) => format!("{v4}/32"),
        IpAddr::V6(v6) => format!("{v6}/128"),
    };
    run(
        "ip",
        &[
            "route",
            "add",
            &host_cidr,
            "via",
            &gateway.to_string(),
            "dev",
            ifname,
        ],
    )
}

/// Capture all traffic into the tunnel using the two-halves trick
/// (`0.0.0.0/1` + `128.0.0.0/1`), which outranks the existing `0.0.0.0/0` default by
/// longest-prefix match without deleting it. This is what `wg-quick`'s
/// `AllowedIPs = 0.0.0.0/0` does under the hood.
pub fn set_default_via_dev(ifname: &str) -> io::Result<()> {
    add_route_dev("0.0.0.0/1".parse().unwrap(), ifname)?;
    add_route_dev("128.0.0.0/1".parse().unwrap(), ifname)?;
    Ok(())
}

/// The current default route as `(gateway, egress interface)`, parsed from
/// `ip route show default`. Needed to pin the server-endpoint host route and to
/// auto-detect the NAT egress interface.
pub fn default_route() -> io::Result<Option<(IpAddr, String)>> {
    let text = output("ip", &["route", "show", "default"])?;
    // Example: "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
    for line in text.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        let via = toks
            .iter()
            .position(|t| *t == "via")
            .and_then(|i| toks.get(i + 1));
        let dev = toks
            .iter()
            .position(|t| *t == "dev")
            .and_then(|i| toks.get(i + 1));
        if let (Some(gw), Some(dev)) = (via, dev) {
            if let Ok(ip) = gw.parse::<IpAddr>() {
                return Ok(Some((ip, dev.to_string())));
            }
        }
    }
    Ok(None)
}
