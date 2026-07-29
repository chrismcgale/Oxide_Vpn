//! DNS leak protection on macOS.
//!
//! Scaffold: rewrites `/etc/resolv.conf` (portable, the same fallback the Linux backend uses),
//! restoring the original on teardown. **TODO(macos):** the *correct* macOS mechanism is the
//! System Configuration framework via `scutil` (`State:/Network/Service/…/DNS`), because
//! `mDNSResponder` may ignore/overwrite `/etc/resolv.conf`. That needs on-device verification.

use std::io::{self, Write};
use std::net::IpAddr;
use std::path::Path;

const RESOLV_CONF: &str = "/etc/resolv.conf";

/// Which DNS mechanism is in use. macOS has no `systemd-resolved`, so this is always
/// [`DnsBackend::ResolvConf`] for now (kept as an enum to mirror the Linux backend's API).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsBackend {
    ResolvConf,
}

/// Detect the backend on this host.
pub fn detect_backend() -> DnsBackend {
    DnsBackend::ResolvConf
}

/// Render a `resolv.conf` body for the given nameservers.
pub fn build_resolv_conf(servers: &[IpAddr]) -> String {
    let mut s = String::from("# written by oxide-vpn\n");
    for ns in servers {
        s.push_str(&format!("nameserver {ns}\n"));
    }
    s
}

/// Restores DNS state on drop/teardown.
pub enum DnsGuard {
    ResolvConf {
        path: String,
        original: Option<Vec<u8>>,
    },
}

/// Point the resolver at `servers` for the tunnel on `iface`, returning a guard that restores
/// the prior state. (`iface` is accepted for API parity with the Linux backend; the
/// resolv.conf path is interface-agnostic.)
pub fn set_dns(_iface: &str, servers: &[IpAddr]) -> io::Result<DnsGuard> {
    set_dns_at(RESOLV_CONF, servers)
}

/// Testable core: write `servers` to `path`, capturing the original for restore.
pub fn set_dns_at(path: impl AsRef<Path>, servers: &[IpAddr]) -> io::Result<DnsGuard> {
    let path = path.as_ref();
    let original = std::fs::read(path).ok();
    let mut f = std::fs::File::create(path)?;
    f.write_all(build_resolv_conf(servers).as_bytes())?;
    Ok(DnsGuard::ResolvConf {
        path: path.to_string_lossy().into_owned(),
        original,
    })
}

/// Restore the resolver state captured in `guard`.
pub fn restore(guard: DnsGuard) {
    match guard {
        DnsGuard::ResolvConf { path, original } => match original {
            Some(bytes) => {
                let _ = std::fs::write(&path, bytes);
            }
            // There was no resolv.conf before us — remove ours.
            None => {
                let _ = std::fs::remove_file(&path);
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_conf_lists_each_server() {
        let body = build_resolv_conf(&["10.8.0.1".parse().unwrap(), "1.1.1.1".parse().unwrap()]);
        assert!(body.contains("nameserver 10.8.0.1"));
        assert!(body.contains("nameserver 1.1.1.1"));
    }
}
