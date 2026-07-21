//! Server-side NAT (masquerade) for full-tunnel internet egress, via nftables.
//!
//! We install a dedicated `inet oxide` table so teardown is a single
//! `nft delete table` and we never disturb the host's other firewall rules. The
//! postrouting rule masquerades tunnel traffic leaving the egress interface; the
//! forward rule permits forwarding to/from the tunnel interface.

use std::io;

use crate::cmd::{apply_nft_ruleset, run};

const TABLE: &str = "oxide";

/// The masquerade + forward ruleset for tunnel `tun_if` egressing via `egress`.
pub fn build_ruleset(tun_if: &str, egress: &str) -> String {
    format!(
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
    )
}

/// Install masquerade + forward rules: tunnel `tun_if` traffic egresses via `egress`.
pub fn enable_masquerade(tun_if: &str, egress: &str) -> io::Result<()> {
    // Start clean in case a previous run left the table behind.
    let _ = disable_masquerade();
    apply_nft_ruleset(&build_ruleset(tun_if, egress))
}

/// Remove the `oxide` nftables table. Idempotent; ignores "no such table".
pub fn disable_masquerade() -> io::Result<()> {
    // Best-effort: deleting a non-existent table is not an error we care about.
    let _ = run("nft", &["delete", "table", "inet", TABLE]);
    Ok(())
}
