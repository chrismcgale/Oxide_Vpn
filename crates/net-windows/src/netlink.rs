//! Interface addressing + routing on Windows.
//!
//! **Scaffold.** The Linux backend drives these over rtnetlink; the Windows equivalent is the
//! **IP Helper API** (`CreateUnicastIpAddressEntry` for addressing, `CreateIpForwardEntry2` /
//! `DeleteIpForwardEntry2` for routes, `GetBestRoute2` for the default gateway) or `netsh`. That
//! needs on-Windows implementation + verification, which this Linux box can't do — so every
//! method is stubbed to return `ErrorKind::Unsupported` and marked `TODO(windows)`. The methods
//! exist (matching the Linux `Netlink` surface) so the client crates link and cross-compile; a
//! Windows client won't route until they're implemented.

use std::io;
use std::net::IpAddr;

use ipnet::IpNet;

fn unsupported(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("Windows {what}: not yet implemented (TODO: IP Helper API / netsh)"),
    )
}

/// Handle for interface/route configuration. On Windows this will wrap IP Helper API state; for
/// now it's a marker so the client links.
pub struct Netlink {
    _private: (),
}

impl Netlink {
    pub fn connect() -> io::Result<Self> {
        Ok(Netlink { _private: () })
    }

    pub async fn link_index(&self, _name: &str) -> io::Result<u32> {
        Err(unsupported("resolve interface index"))
    }

    pub async fn set_up_mtu(&self, _index: u32, _mtu: u32) -> io::Result<()> {
        Err(unsupported("set MTU / bring interface up"))
    }

    pub async fn add_address(&self, _index: u32, _addr: IpNet) -> io::Result<()> {
        Err(unsupported("add interface address"))
    }

    pub async fn add_route_dev(&self, _dst: IpNet, _index: u32) -> io::Result<()> {
        Err(unsupported("add on-link route"))
    }

    pub async fn del_route_dev(&self, _dst: IpNet, _index: u32) -> io::Result<()> {
        Err(unsupported("delete on-link route"))
    }

    pub async fn add_host_route_via(
        &self,
        _host: IpAddr,
        _gateway: IpAddr,
        _index: u32,
    ) -> io::Result<()> {
        Err(unsupported("add host route via gateway"))
    }

    pub async fn del_host_route_via(
        &self,
        _host: IpAddr,
        _gateway: IpAddr,
        _index: u32,
    ) -> io::Result<()> {
        Err(unsupported("delete host route via gateway"))
    }

    pub async fn add_route_via(
        &self,
        _dst: IpNet,
        _gateway: IpAddr,
        _index: u32,
    ) -> io::Result<()> {
        Err(unsupported("add route via gateway"))
    }

    pub async fn del_route_via(
        &self,
        _dst: IpNet,
        _gateway: IpAddr,
        _index: u32,
    ) -> io::Result<()> {
        Err(unsupported("delete route via gateway"))
    }

    pub async fn set_default_v4_via_dev(&self, _index: u32) -> io::Result<()> {
        Err(unsupported("set IPv4 default route"))
    }

    pub async fn set_default_v6_via_dev(&self, _index: u32) -> io::Result<()> {
        Err(unsupported("set IPv6 default route"))
    }

    /// Idempotent teardown; a no-op stub for now (matches the Linux signature: no `Result`).
    pub async fn clear_default_via_dev(&self, _index: u32, _v6: bool) {}
}

/// The system default route's gateway + interface name for the given family. (Real impl:
/// IP Helper `GetBestRoute2`, or parse `route print`.)
pub fn default_route_family(_v6: bool) -> io::Result<Option<(IpAddr, String)>> {
    Err(unsupported("read default route"))
}
