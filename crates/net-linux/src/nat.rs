//! Server-side NAT (masquerade) for full-tunnel internet egress, via nftables.
//!
//! We install a dedicated `inet oxide` table so teardown is a single
//! `nft delete table` and we never disturb the host's other firewall rules. The
//! postrouting rule masquerades tunnel traffic leaving the egress interface; the
//! forward rule permits forwarding to/from the tunnel interface.

use std::io;

use crate::cmd::run;

const TABLE: &str = "oxide";

/// Install masquerade + forward rules: tunnel `tun_if` traffic egresses via `egress`.
pub fn enable_masquerade(tun_if: &str, egress: &str) -> io::Result<()> {
    // Start clean in case a previous run left the table behind.
    let _ = disable_masquerade();

    let ruleset = format!(
        "table inet {TABLE} {{
            chain postrouting {{
                type nat hook postrouting priority srcnat; policy accept;
                oifname \"{egress}\" masquerade
            }}
            chain forward {{
                type filter hook forward priority filter; policy accept;
                iifname \"{tun_if}\" accept
                oifname \"{tun_if}\" accept
            }}
        }}"
    );

    // Apply the ruleset atomically from stdin: `nft -f -`.
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(ruleset.as_bytes())?;
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other("nft failed to load oxide ruleset"))
    }
}

/// Remove the `oxide` nftables table. Idempotent; ignores "no such table".
pub fn disable_masquerade() -> io::Result<()> {
    // Best-effort: deleting a non-existent table is not an error we care about.
    let _ = run("nft", &["delete", "table", "inet", TABLE]);
    Ok(())
}
