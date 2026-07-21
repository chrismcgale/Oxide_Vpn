//! Kernel sysctl toggles needed for routing/NAT, with save/restore.
//!
//! Two settings matter for a full-tunnel server:
//!   * `net.ipv4.ip_forward` must be 1 to forward tunnel traffic to the internet.
//!   * `rp_filter` (reverse-path filtering) must not be in strict mode, or the NAT
//!     return path is silently dropped because replies arrive on a different
//!     interface than the kernel expects. We set it to loose (2).
//!
//! Each setter returns the previous value so the daemon can restore host state on
//! shutdown (leave-no-trace).

use std::io;

fn path(key: &str) -> String {
    format!("/proc/sys/{}", key.replace('.', "/"))
}

pub fn read(key: &str) -> io::Result<String> {
    Ok(std::fs::read_to_string(path(key))?.trim().to_string())
}

pub fn write(key: &str, value: &str) -> io::Result<()> {
    std::fs::write(path(key), value)
}

/// Enable IPv4 forwarding; returns the previous value for restore.
pub fn enable_ip_forward() -> io::Result<String> {
    let prev = read("net.ipv4.ip_forward")?;
    write("net.ipv4.ip_forward", "1")?;
    Ok(prev)
}

/// Set reverse-path filtering to loose mode on `all` and the egress interface;
/// returns the previous `all` value.
pub fn relax_rp_filter(egress: &str) -> io::Result<String> {
    let prev = read("net.ipv4.conf.all.rp_filter").unwrap_or_else(|_| "1".into());
    write("net.ipv4.conf.all.rp_filter", "2")?;
    // Per-interface knob; best-effort (interface may use the `all` value).
    let _ = write(&format!("net.ipv4.conf.{egress}.rp_filter"), "2");
    Ok(prev)
}
