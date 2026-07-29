//! DNS leak protection on Windows.
//!
//! **Scaffold.** Windows has no `/etc/resolv.conf`; DNS is configured per-interface via the IP
//! Helper API (`SetInterfaceDnsSettings`) or `netsh interface ip set dns`. Not yet implemented —
//! `set_dns` returns `ErrorKind::Unsupported`; `restore` is a safe no-op. `TODO(windows)`.

use std::io;
use std::net::IpAddr;

/// Which DNS mechanism is in use (kept as an enum to mirror the other backends' API).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsBackend {
    IpHelper,
}

/// Detect the backend on this host.
pub fn detect_backend() -> DnsBackend {
    DnsBackend::IpHelper
}

/// Restores DNS state on teardown. (No fields yet — `set_dns` is unimplemented.)
pub struct DnsGuard;

/// Point the resolver at `servers` for the tunnel on `iface`. Not yet implemented on Windows.
pub fn set_dns(_iface: &str, _servers: &[IpAddr]) -> io::Result<DnsGuard> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows DNS: not yet implemented (TODO: SetInterfaceDnsSettings / netsh)",
    ))
}

/// Restore the resolver state captured in `guard`. A no-op since `set_dns` never installed
/// anything — safe to call in teardown paths unconditionally.
pub fn restore(_guard: DnsGuard) {}
