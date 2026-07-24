//! Server-side NAT (masquerade) for full-tunnel internet egress, via nftables.
//!
//! We install a dedicated `inet oxide` table so teardown is a single
//! `nft delete table` and we never disturb the host's other firewall rules. The
//! postrouting rule masquerades tunnel traffic leaving the egress interface; the
//! forward rule permits forwarding to/from the tunnel interface.
//!
//! **2F note:** unlike the kill switch (ported to netlink via `rustables` — see
//! [`crate::killswitch`]), NAT still shells out to the `nft` binary. Its forward chain does
//! **MSS clamping** (`tcp option maxseg size set rt mtu`), an `exthdr`-mangle statement that
//! `rustables` 0.8 can't express (it has no `exthdr` expression). Dropping MSS clamping would
//! reopen the "ping works, curl hangs" PMTU black hole, so NAT keeps the shell-out until we
//! either adopt `nftnl`/libnftnl (a C dependency that *can* express exthdr) or `rustables`
//! grows the expression. NAT runs on servers, which already have `nft` present.

use std::io;

use crate::cmd::{apply_nft_ruleset, run};

const TABLE: &str = "oxide";

/// The masquerade + forward ruleset for tunnel `tun_if` egressing via `egress`.
///
/// The forward chain also clamps TCP MSS to the path MTU on SYN packets. Without this,
/// a TCP connection through the tunnel negotiates an MSS for a 1500-byte path but the
/// tunnel MTU is smaller (1420, or lower under stealth), so large segments get dropped
/// and connections stall — the classic "ping works, curl hangs" PMTU black hole. `rt
/// mtu` adapts automatically to whatever the tunnel MTU is set to.
pub fn build_ruleset(tun_if: &str, egress: &str) -> String {
    format!(
        "table inet {TABLE} {{
            chain postrouting {{
                type nat hook postrouting priority srcnat; policy accept;
                oifname \"{egress}\" masquerade
            }}
            chain forward {{
                type filter hook forward priority filter; policy accept;
                tcp flags syn tcp option maxseg size set rt mtu
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_masquerades_and_clamps_mss() {
        let rs = build_ruleset("oxide0", "eth0");
        assert!(rs.contains("oifname \"eth0\" masquerade"));
        assert!(rs.contains("iifname \"oxide0\" accept"));
        // MSS clamp adapts to the route (tunnel) MTU.
        assert!(rs.contains("tcp flags syn tcp option maxseg size set rt mtu"));
    }
}
