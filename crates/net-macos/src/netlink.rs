//! Interface addressing + routing on macOS.
//!
//! **Scaffold.** The Linux backend drives these over rtnetlink; the macOS equivalent is the BSD
//! routing socket (`PF_ROUTE`, `rt_msghdr` + packed sockaddrs) plus `SIOCAIFADDR` for addressing.
//! That's fiddly, byte-layout-sensitive code that must be **live-verified on a Mac**, which this
//! Linux box can't do — so every mutating method is stubbed to return `ErrorKind::Unsupported`
//! and marked `TODO(macos)`. The methods exist (matching the Linux `Netlink` surface) so the
//! client crates link and cross-compile; a macOS client won't route until they're implemented.
//!
//! `link_index` and the type surface are real, so the portable call sites work.

use std::ffi::CString;
use std::io;
use std::net::IpAddr;

use ipnet::IpNet;

fn unsupported(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("macOS {what}: not yet implemented (TODO: BSD route socket)"),
    )
}

/// Handle for interface/route configuration. On macOS this will wrap a `PF_ROUTE` socket; for
/// now it's a marker so the client links.
pub struct Netlink {
    _private: (),
}

impl Netlink {
    /// Open the routing handle. (Real impl: open a `PF_ROUTE` socket.)
    pub fn connect() -> io::Result<Self> {
        Ok(Netlink { _private: () })
    }

    /// Interface index for `name` — portable via `if_nametoindex`.
    pub async fn link_index(&self, name: &str) -> io::Result<u32> {
        let cname = CString::new(name).map_err(|_| unsupported("interface name"))?;
        // SAFETY: `cname` is a valid NUL-terminated string for the duration of the call.
        let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if idx == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(idx)
        }
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
/// `PF_ROUTE` RTM_GET, or parse `route -n get default`.)
pub fn default_route_family(_v6: bool) -> io::Result<Option<(IpAddr, String)>> {
    Err(unsupported("read default route"))
}
