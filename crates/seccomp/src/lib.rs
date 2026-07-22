//! Enforced no-logs: a seccomp-BPF filter that makes a process **unable to write to disk**.
//!
//! The no-logs posture is otherwise a *promise* (we audited that the data plane opens no
//! files). This makes it an *enforcement*: after [`apply_no_disk_writes`] the kernel refuses
//! any syscall that could create or write a file, so the server cannot log to disk even if
//! it is compromised or coerced into trying. It is the strongest, concretely verifiable
//! layer of "verifiable no-logs" — it doesn't ask you to trust us, it removes the capability.
//!
//! ## Why we filter `openat` flags, not `write`
//! seccomp matches on the syscall number and its **register arguments** only — it cannot
//! dereference pointers, so it cannot tell whether an fd passed to `write()` points at a
//! file, a socket, or stdout. Blocking `write` would therefore also break the UDP data path
//! and stdout/journald logging. Instead we block the syscalls that *open a file for writing
//! or create one*, inspecting the `flags` argument (a register value seccomp **can** read):
//! any `openat`/`open` requesting write access (`O_WRONLY`/`O_RDWR`), creation (`O_CREAT`,
//! `O_TMPFILE`), plus the filesystem-mutating calls (`creat`, `unlinkat`, `renameat2`,
//! `mkdirat`, `truncate`, …). With no writable fd ever obtainable, a later `write()` to a
//! file is impossible — while sockets (created by `socket`, not `open`) and read-only opens
//! keep working. Denied calls return `EPERM` (not a kill), so the process degrades safely
//! rather than crashing on an unexpected attempt; a stricter kill-on-violation posture is a
//! one-line change ([`SeccompAction::KillProcess`]).
//!
//! ## Ordering
//! Apply this **after** the process has opened everything it legitimately needs (TUN device,
//! sockets, config read) and right before entering the packet loop — the daemon opens
//! `/dev/net/tun` with `O_RDWR` at startup, which this policy (correctly) forbids, so the
//! gate must close only once setup is done. From that point on, no disk writes are possible.
//!
//! Verifiable **without root**: `seccompiler` installs the filter under `PR_SET_NO_NEW_PRIVS`
//! (no privilege needed), and the test forks a child, applies the filter, and asserts a file
//! create is refused with `EPERM` while a socket and a read-only open still succeed.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use seccompiler::{
    apply_filter_all_threads, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp,
    SeccompCondition, SeccompFilter, SeccompRule, TargetArch,
};

#[cfg(target_arch = "x86_64")]
const TARGET_ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const TARGET_ARCH: TargetArch = TargetArch::aarch64;

/// Rules that match an `open`/`openat` requesting write access, creation, or a tmpfile —
/// i.e. any open that could put bytes on disk. `flags_arg` is the index of the `flags`
/// argument (2 for `openat(dirfd, path, flags, mode)`, 1 for `open(path, flags, mode)`).
/// Matching rules are ORed, so a read-only open (`O_RDONLY`, no create bits) matches none
/// and is allowed.
fn write_open_rules(flags_arg: u8) -> Result<Vec<SeccompRule>> {
    let acc = libc::O_ACCMODE as u64;
    let cond = |op: SeccompCmpOp, val: u64| -> Result<SeccompRule> {
        Ok(SeccompRule::new(vec![SeccompCondition::new(
            flags_arg,
            SeccompCmpArgLen::Dword,
            op,
            val,
        )?])?)
    };
    Ok(vec![
        // (flags & O_ACCMODE) == O_WRONLY  — write-only.
        cond(SeccompCmpOp::MaskedEq(acc), libc::O_WRONLY as u64)?,
        // (flags & O_ACCMODE) == O_RDWR    — read-write.
        cond(SeccompCmpOp::MaskedEq(acc), libc::O_RDWR as u64)?,
        // O_CREAT set — creates the file if absent.
        cond(
            SeccompCmpOp::MaskedEq(libc::O_CREAT as u64),
            libc::O_CREAT as u64,
        )?,
        // O_TMPFILE set — creates an unnamed file that can later be linked in.
        cond(
            SeccompCmpOp::MaskedEq(libc::O_TMPFILE as u64),
            libc::O_TMPFILE as u64,
        )?,
    ])
}

/// Build the "no disk writes" BPF program: default-allow, but deny (with `EPERM`) any
/// write-intent file open and any filesystem-mutating syscall.
pub fn no_disk_writes_program() -> Result<BpfProgram> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Opens: allow read-only, deny write/create (inspecting the flags argument).
    rules.insert(libc::SYS_openat, write_open_rules(2)?);
    #[cfg(target_arch = "x86_64")]
    rules.insert(libc::SYS_open, write_open_rules(1)?);

    // Syscalls we deny unconditionally (an empty rule vector always matches). `openat2`
    // passes its flags inside a struct pointer seccomp can't read, so we deny it outright
    // (callers fall back to `openat`, which we filter precisely). The rest create, delete,
    // move, or resize files — all disk mutations.
    let mut deny: Vec<i64> = vec![
        libc::SYS_openat2,
        libc::SYS_unlinkat,
        libc::SYS_renameat2,
        libc::SYS_mkdirat,
        libc::SYS_linkat,
        libc::SYS_symlinkat,
        libc::SYS_mknodat,
        libc::SYS_ftruncate,
        libc::SYS_truncate,
    ];
    // Legacy non-`*at` variants exist on x86_64 (not on aarch64).
    #[cfg(target_arch = "x86_64")]
    deny.extend_from_slice(&[
        libc::SYS_creat,
        libc::SYS_unlink,
        libc::SYS_rename,
        libc::SYS_mkdir,
        libc::SYS_link,
        libc::SYS_symlink,
        libc::SYS_mknod,
    ]);
    for sc in deny {
        rules.insert(sc, vec![]);
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow, // default: allow unlisted syscalls
        SeccompAction::Errno(libc::EPERM as u32), // on match: refuse with EPERM
        TARGET_ARCH,
    )
    .context("building seccomp filter")?;

    BpfProgram::try_from(filter).context("compiling seccomp filter to BPF")
}

/// Install the no-disk-writes filter on every thread of the calling process. Call this once,
/// after all legitimate file setup is done and before the packet loop. Irreversible for the
/// process lifetime (that is the point). Works without root (`PR_SET_NO_NEW_PRIVS`).
pub fn apply_no_disk_writes() -> Result<()> {
    let program = no_disk_writes_program()?;
    apply_filter_all_threads(&program).context("applying seccomp filter")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exit codes the forked child uses to report which check failed (0 = all passed).
    const OK: i32 = 0;
    const FILE_CREATE_NOT_BLOCKED: i32 = 2;
    const READONLY_OPEN_FAILED: i32 = 3;
    const SOCKET_FAILED: i32 = 4;
    const WRONLY_OPEN_NOT_BLOCKED: i32 = 5;

    /// Runs entirely in the forked child, after the filter is applied. Uses only raw libc
    /// (no allocation) since the parent is multi-threaded. Returns an exit code.
    ///
    /// # Safety
    /// Must be called in a freshly forked child; performs raw syscalls and `_exit`.
    unsafe fn child_checks(program: &BpfProgram) -> i32 {
        if apply_filter_all_threads(program).is_err() {
            return 90;
        }
        let eperm = libc::EPERM;

        // Creating a file must be refused with EPERM.
        let create = libc::openat(
            libc::AT_FDCWD,
            c"/tmp/oxide-seccomp-test-should-not-exist".as_ptr(),
            libc::O_CREAT | libc::O_WRONLY,
            0o600,
        );
        if create >= 0 {
            libc::close(create);
            return FILE_CREATE_NOT_BLOCKED;
        }
        if *libc::__errno_location() != eperm {
            return FILE_CREATE_NOT_BLOCKED;
        }

        // Opening an existing file for writing must also be refused.
        let wr = libc::openat(libc::AT_FDCWD, c"/dev/null".as_ptr(), libc::O_WRONLY, 0);
        if wr >= 0 {
            libc::close(wr);
            return WRONLY_OPEN_NOT_BLOCKED;
        }

        // A read-only open must still work (config reads, /etc/hosts, etc.).
        let ro = libc::openat(
            libc::AT_FDCWD,
            c"/proc/self/cmdline".as_ptr(),
            libc::O_RDONLY,
            0,
        );
        if ro < 0 {
            return READONLY_OPEN_FAILED;
        }
        libc::close(ro);

        // Creating a socket must still work (the data path lives on sockets).
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return SOCKET_FAILED;
        }
        libc::close(sock);

        OK
    }

    #[test]
    fn no_disk_writes_blocks_file_creation_but_not_sockets() {
        // Build the program in the (multi-threaded) parent, then fork: the child applies it
        // and runs the checks in isolation, so the test process itself stays unfiltered.
        let program = no_disk_writes_program().expect("build filter");

        // SAFETY: fork in a test; the child only runs async-signal-safe libc calls and _exit.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let code = unsafe { child_checks(&program) };
            unsafe { libc::_exit(code) };
        }

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid, "waitpid failed");
        assert!(
            libc::WIFEXITED(status),
            "child did not exit normally (status {status:#x})"
        );
        let code = libc::WEXITSTATUS(status);
        assert_eq!(
            code, OK,
            "child check failed with code {code} (2=create-not-blocked, 3=ro-open-failed, \
             4=socket-failed, 5=wronly-not-blocked, 90=apply-failed)"
        );
    }

    #[test]
    fn program_builds_for_this_arch() {
        assert!(no_disk_writes_program().is_ok());
    }
}
