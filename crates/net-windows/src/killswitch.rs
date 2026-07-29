//! Kill switch on Windows.
//!
//! **Scaffold.** The Linux backend builds an nftables `output` drop chain over netlink; the
//! Windows equivalent is the **Windows Filtering Platform** (WFP) — block-outbound filters with
//! permits for loopback, the tunnel interface, and the encrypted UDP to the server — or
//! `netsh advfirewall`. Not yet implemented: `enable` returns `ErrorKind::Unsupported` and
//! `disable` is a safe no-op. `TODO(windows)`.

use std::io;
use std::net::IpAddr;

/// Arm the kill switch: block all outbound except loopback, the tunnel, and the WG server
/// endpoint. Not yet implemented on Windows (see module note).
pub fn enable(_server_ip: IpAddr, _server_port: u16, _tun_if: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows kill switch: not yet implemented (TODO: WFP filters / netsh advfirewall)",
    ))
}

/// Remove the kill switch. A no-op since `enable` never installed anything — safe to call in
/// teardown paths unconditionally.
pub fn disable() -> io::Result<()> {
    Ok(())
}
