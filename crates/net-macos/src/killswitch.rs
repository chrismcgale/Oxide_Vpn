//! Kill switch on macOS.
//!
//! **Scaffold.** The Linux backend builds an nftables `output` drop chain over netlink; the macOS
//! equivalent is **pf** (packet filter) — an anchor with a default-block-out policy plus passes
//! for loopback, the tunnel interface, and the encrypted UDP to the server, loaded via `pfctl`
//! or the `/dev/pf` ioctl API. That needs on-device verification, so `enable` returns
//! `ErrorKind::Unsupported` for now and `disable` is a safe no-op. `TODO(macos)`.

use std::io;
use std::net::IpAddr;

/// Arm the kill switch: block all outbound except loopback, the tunnel, and the WG server
/// endpoint. Not yet implemented on macOS (see module note).
pub fn enable(_server_ip: IpAddr, _server_port: u16, _tun_if: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "macOS kill switch: not yet implemented (TODO: pf anchor via pfctl)",
    ))
}

/// Remove the kill switch. A no-op since `enable` never installed anything — safe to call in
/// teardown paths unconditionally.
pub fn disable() -> io::Result<()> {
    Ok(())
}
