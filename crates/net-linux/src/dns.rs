//! DNS leak protection: point the system resolver at the tunnel's DNS while connected.
//!
//! Without this, the OS keeps using the ISP-provided resolver, so DNS queries leak
//! outside the tunnel (revealing every domain visited) even when all other traffic is
//! routed through the VPN. We rewrite `/etc/resolv.conf` to the tunnel DNS and restore
//! the original on disconnect.
//!
//! Caveat: on systems where `/etc/resolv.conf` is managed by `systemd-resolved` or
//! NetworkManager, that daemon may rewrite the file. A resolved-aware backend is a
//! future refinement; this direct approach covers the common case and is easy to audit.

use std::io;
use std::net::IpAddr;
use std::path::Path;

const RESOLV_CONF: &str = "/etc/resolv.conf";

/// Render a `resolv.conf` body for the given nameservers.
pub fn build_resolv_conf(servers: &[IpAddr]) -> String {
    let mut s = String::from("# Managed by oxide-vpn while the tunnel is up.\n");
    for ip in servers {
        s.push_str(&format!("nameserver {ip}\n"));
    }
    s
}

/// A restore token holding the previous `resolv.conf` contents (if any).
#[must_use = "hold the guard until disconnect, then call restore()"]
pub struct DnsGuard {
    original: Option<Vec<u8>>,
    path: String,
}

/// Replace the system resolver with `servers`, returning a guard that restores it.
pub fn set_dns(servers: &[IpAddr]) -> io::Result<DnsGuard> {
    set_dns_at(RESOLV_CONF, servers)
}

/// Restore the resolver to its pre-connect state.
pub fn restore(guard: DnsGuard) {
    match guard.original {
        Some(bytes) => {
            let _ = std::fs::write(&guard.path, bytes);
        }
        // There was no file before; remove ours so we don't leave a stale resolver.
        None => {
            let _ = std::fs::remove_file(&guard.path);
        }
    }
}

/// Testable variant that operates on an arbitrary path.
pub fn set_dns_at(path: impl AsRef<Path>, servers: &[IpAddr]) -> io::Result<DnsGuard> {
    let path = path.as_ref();
    let original = std::fs::read(path).ok();
    std::fs::write(path, build_resolv_conf(servers))?;
    Ok(DnsGuard {
        original,
        path: path.to_string_lossy().into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_nameservers() {
        let body = build_resolv_conf(&["10.8.0.1".parse().unwrap(), "1.1.1.1".parse().unwrap()]);
        assert!(body.contains("nameserver 10.8.0.1"));
        assert!(body.contains("nameserver 1.1.1.1"));
    }

    #[test]
    fn set_and_restore_roundtrip() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("oxide-resolv-{}.conf", std::process::id()));
        std::fs::write(&path, b"nameserver 192.168.1.1\n").unwrap();

        let guard = set_dns_at(&path, &["10.8.0.1".parse().unwrap()]).unwrap();
        let during = std::fs::read_to_string(&path).unwrap();
        assert!(during.contains("nameserver 10.8.0.1"));
        assert!(!during.contains("192.168.1.1"));

        restore(guard);
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after, "nameserver 192.168.1.1\n");
        let _ = std::fs::remove_file(&path);
    }
}
