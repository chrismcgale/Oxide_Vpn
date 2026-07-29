//! macOS platform layer for Oxide VPN — the sibling to `oxide-net-linux`.
//!
//! **Status: scaffold.** The whole crate is `#![cfg(target_os = "macos")]`, so on Linux (this
//! project's primary target) it compiles to nothing and just holds a place in the workspace;
//! the real code is exercised by a macOS build / `cargo check --target *-apple-darwin`.
//!
//! It mirrors the **client contract** `oxide-net` re-exports (`TunDevice`, `Netlink`,
//! `bring_up_interface`, `bind_dual_stack`, `shutdown_signal`, `dns`, `killswitch`), so it is a
//! drop-in for the Linux backend on the client crates. What's done vs. what needs a real Mac:
//!
//! - **Done + cross-compile-checked:** `bind_dual_stack` (portable `socket2`), `shutdown_signal`
//!   (portable tokio), `dns` (`/etc/resolv.conf` rewrite — no `resolvectl` on macOS), and the
//!   **utun** `TunDevice` (open via `PF_SYSTEM`/`SYSPROTO_CONTROL`, non-blocking `AsyncFd`, and
//!   the mandatory 4-byte address-family header that utun prepends/expects — the detail that
//!   makes or breaks a macOS TUN).
//! - **Stubbed, needs on-device completion** (return `ErrorKind::Unsupported`, marked
//!   `TODO(macos)`): the `Netlink` routing methods (BSD `PF_ROUTE` socket) and the `killswitch`
//!   (pf). These compile so the client links, but a macOS client can't route/kill-switch until
//!   they're implemented and **live-verified on a Mac** — this box can't run macOS binaries.
#![cfg(target_os = "macos")]

pub mod dns;
pub mod killswitch;
pub mod netlink;
pub mod setup;
pub mod signal;
pub mod tun;
pub mod udp;

pub use netlink::Netlink;
pub use setup::bring_up_interface;
pub use signal::shutdown_signal;
pub use tun::TunDevice;
pub use udp::bind_dual_stack;
