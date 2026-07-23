//! DNS leak protection: point the system resolver at the tunnel's DNS while connected.
//!
//! Without this the OS keeps using the LAN/ISP resolver, so DNS queries leak outside the
//! tunnel (revealing every domain visited) even when all other traffic is routed through
//! the VPN. On modern Linux `/etc/resolv.conf` is usually a symlink managed by
//! **systemd-resolved**, which would clobber a direct rewrite — so we pick a backend:
//!
//!   * **systemd-resolved** (the common case): set the tunnel's DNS *on the interface* and a
//!     `~.` **routing domain** via `resolvectl`, so resolved sends *all* queries to the tunnel
//!     DNS (no leak to other links). Reverted per-interface with `resolvectl revert`.
//!   * **resolv.conf** (fallback, when resolved isn't running): rewrite `/etc/resolv.conf`
//!     directly and restore it on disconnect.
//!
//! The choice, the `resolvectl` argument vectors, and the file body are pure and unit-tested;
//! applying them (running `resolvectl` / writing the file) needs root and is netns/live-tested.
//!
//! Caveat: a NetworkManager deployment that manages DNS itself (without resolved) may still
//! reassert its own settings on a network change — a NM-D-Bus backend is a future refinement.

use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

const RESOLV_CONF: &str = "/etc/resolv.conf";

/// systemd-resolved's stub resolv.conf. Its presence means resolved is running and (almost
/// always) owns `/etc/resolv.conf`, so per-link `resolvectl` is the correct tool.
const RESOLVED_STUB: &str = "/run/systemd/resolve/stub-resolv.conf";

/// Which DNS management backend to drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsBackend {
    SystemdResolved,
    ResolvConf,
}

/// Pure backend choice given whether systemd-resolved's stub is present.
pub fn choose_backend(resolved_stub_present: bool) -> DnsBackend {
    if resolved_stub_present {
        DnsBackend::SystemdResolved
    } else {
        DnsBackend::ResolvConf
    }
}

/// Detect the backend on this host.
pub fn detect_backend() -> DnsBackend {
    choose_backend(Path::new(RESOLVED_STUB).exists())
}

/// Render a `resolv.conf` body for the given nameservers.
pub fn build_resolv_conf(servers: &[IpAddr]) -> String {
    let mut s = String::from("# Managed by oxide-vpn while the tunnel is up.\n");
    for ip in servers {
        s.push_str(&format!("nameserver {ip}\n"));
    }
    s
}

/// `resolvectl dns <iface> <ip>...` — set the interface's DNS servers.
pub fn resolvectl_dns_args(iface: &str, servers: &[IpAddr]) -> Vec<String> {
    let mut a = vec!["dns".to_string(), iface.to_string()];
    a.extend(servers.iter().map(|s| s.to_string()));
    a
}

/// `resolvectl domain <iface> ~.` — a **routing-only** default domain, so resolved routes
/// *every* query to this interface's DNS (this is what actually prevents leaks).
pub fn resolvectl_domain_args(iface: &str) -> Vec<String> {
    vec!["domain".to_string(), iface.to_string(), "~.".to_string()]
}

/// `resolvectl revert <iface>` — drop the per-interface DNS/domain settings.
pub fn resolvectl_revert_args(iface: &str) -> Vec<String> {
    vec!["revert".to_string(), iface.to_string()]
}

/// A restore token: either revert the interface (resolved) or rewrite the file (resolv.conf).
#[must_use = "hold the guard until disconnect, then call restore()"]
pub enum DnsGuard {
    Resolved {
        iface: String,
    },
    ResolvConf {
        path: String,
        original: Option<Vec<u8>>,
    },
}

/// Install `servers` as the resolver for the tunnel on `iface`, returning a guard that
/// restores the prior state. Picks the systemd-resolved or resolv.conf backend automatically.
pub fn set_dns(iface: &str, servers: &[IpAddr]) -> io::Result<DnsGuard> {
    match detect_backend() {
        DnsBackend::SystemdResolved => set_dns_resolved(iface, servers),
        DnsBackend::ResolvConf => set_dns_at(RESOLV_CONF, servers),
    }
}

/// Restore the resolver to its pre-connect state.
pub fn restore(guard: DnsGuard) {
    match guard {
        DnsGuard::Resolved { iface } => {
            let _ = run_resolvectl(&resolvectl_revert_args(&iface));
        }
        DnsGuard::ResolvConf { path, original } => match original {
            Some(bytes) => {
                let _ = std::fs::write(&path, bytes);
            }
            // There was no file before; remove ours so we don't leave a stale resolver.
            None => {
                let _ = std::fs::remove_file(&path);
            }
        },
    }
}

fn set_dns_resolved(iface: &str, servers: &[IpAddr]) -> io::Result<DnsGuard> {
    run_resolvectl(&resolvectl_dns_args(iface, servers))?;
    run_resolvectl(&resolvectl_domain_args(iface))?;
    Ok(DnsGuard::Resolved {
        iface: iface.to_string(),
    })
}

fn run_resolvectl(args: &[String]) -> io::Result<()> {
    let status = Command::new("resolvectl").args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("resolvectl {args:?} failed")))
    }
}

/// Testable resolv.conf variant that operates on an arbitrary path.
pub fn set_dns_at(path: impl AsRef<Path>, servers: &[IpAddr]) -> io::Result<DnsGuard> {
    let path = path.as_ref();
    let original = std::fs::read(path).ok();
    std::fs::write(path, build_resolv_conf(servers))?;
    Ok(DnsGuard::ResolvConf {
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
    fn backend_choice() {
        assert_eq!(choose_backend(true), DnsBackend::SystemdResolved);
        assert_eq!(choose_backend(false), DnsBackend::ResolvConf);
    }

    #[test]
    fn resolvectl_args_are_well_formed() {
        let dns = resolvectl_dns_args(
            "oxide0",
            &["10.8.0.1".parse().unwrap(), "1.1.1.1".parse().unwrap()],
        );
        assert_eq!(dns, vec!["dns", "oxide0", "10.8.0.1", "1.1.1.1"]);
        // The `~.` routing domain is what forces ALL queries through the tunnel DNS.
        assert_eq!(
            resolvectl_domain_args("oxide0"),
            vec!["domain", "oxide0", "~."]
        );
        assert_eq!(resolvectl_revert_args("oxide0"), vec!["revert", "oxide0"]);
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
