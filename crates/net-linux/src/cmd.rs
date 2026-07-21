//! Tiny helper for shelling out to `ip`/`nft`/`sysctl`.
//!
//! M1 configures addressing, routing, and NAT by invoking the standard iproute2 /
//! nftables tools — exactly what `wg-quick` does. The M5 roadmap replaces this with
//! netlink/nftables libraries; keeping every call behind this one helper makes that
//! swap mechanical.

use std::io;
use std::process::Command;

use tracing::debug;

/// Run `program args...`, returning an error if it exits non-zero.
pub fn run(program: &str, args: &[&str]) -> io::Result<()> {
    debug!(cmd = %format!("{program} {}", args.join(" ")), "exec");
    let output = Command::new(program).args(args).output()?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(io::Error::other(format!(
            "`{program} {}` failed: {}",
            args.join(" "),
            stderr.trim()
        )))
    }
}

/// Load an nftables ruleset by piping it to `nft -f -`.
pub fn apply_nft_ruleset(ruleset: &str) -> io::Result<()> {
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
    if child.wait()?.success() {
        Ok(())
    } else {
        Err(io::Error::other("nft failed to load ruleset"))
    }
}

/// Run and capture stdout as a string (for parsing, e.g. `ip route show`).
pub fn output(program: &str, args: &[&str]) -> io::Result<String> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(format!(
            "`{program} {}` failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
