//! Bakes build identity into the binary for the signed build manifest (`oxide-attest`):
//! the git commit and a build timestamp. The timestamp honors `SOURCE_DATE_EPOCH` so a
//! reproducible build produces an identical value.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let commit = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=OXIDE_GIT_COMMIT={commit}");

    // Prefer SOURCE_DATE_EPOCH (set by reproducible-build tooling) so the manifest's
    // build_time is deterministic; otherwise stamp the current time.
    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });
    println!("cargo:rustc-env=OXIDE_BUILD_TIME={epoch}");

    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
}
