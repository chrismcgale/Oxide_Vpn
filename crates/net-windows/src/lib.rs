//! Windows platform layer for Oxide VPN — the sibling to `oxide-net-linux` / `oxide-net-macos`.
//!
//! **Status: scaffold.** The whole crate is `#![cfg(target_os = "windows")]`, so on Linux (this
//! project's primary target) it compiles to nothing and just holds a place in the workspace; the
//! real code is exercised by a Windows build / `cargo check --target x86_64-pc-windows-gnu`.
//!
//! It mirrors the **client contract** `oxide-net` re-exports (`TunDevice`, `Netlink`,
//! `bring_up_interface`, `bind_dual_stack`, `shutdown_signal`, `dns`, `killswitch`), so it is a
//! drop-in for the Linux/macOS backends on the client crates. Windows diverges more than macOS —
//! there is no TUN fd to wrap and no `resolv.conf`:
//!
//! - **Done + cross-compile-checked:** `bind_dual_stack` (portable `socket2`) and
//!   `shutdown_signal` (portable `tokio::signal::ctrl_c`).
//! - **Stubbed, needs on-Windows implementation** (return `ErrorKind::Unsupported`, marked
//!   `TODO(windows)`):
//!     * `TunDevice` — Windows has no `/dev/net/tun`; the standard is **Wintun** (WireGuard's
//!       userspace TUN DLL): load `wintun.dll`, create an adapter, open a session, and read/write
//!       packets via its ring buffers. Reads block on an event, so the async `TunQueue` needs a
//!       dedicated blocking thread bridged to tokio (or IOCP). Use the `wintun` crate.
//!     * `Netlink` (routing/addressing) — the **IP Helper API** (`CreateUnicastIpAddressEntry`,
//!       `CreateIpForwardEntry2`, …) or `netsh`.
//!     * `dns` — the IP Helper API (`SetInterfaceDnsSettings`) or `netsh interface ip set dns`.
//!     * `killswitch` — the **Windows Filtering Platform** (WFP) or `netsh advfirewall`.
//!
//! These compile so the client links + cross-compiles, but a Windows client can't run until they
//! are implemented and **live-verified on Windows** — this Linux box can't run Windows binaries.
#![cfg(target_os = "windows")]

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
