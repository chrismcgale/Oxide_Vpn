//! Platform-selecting facade over the privileged OS network backend.
//!
//! `wg-core` is OS-agnostic (it talks to the TUN through the [`oxide_common::TunQueue`] trait);
//! everything that needs `CAP_NET_ADMIN` — the TUN device, interface addressing/routing, DNS
//! leak protection, the kill switch, the dual-stack UDP bind — lives in a per-OS crate. This
//! facade re-exports whichever backend matches the build target, so the client crates
//! (`client-core`, `oxide-agentd`, `oxide-client`) depend only on `oxide-net` and a new OS is a
//! new sibling crate wired in here, not an edit to every caller.
//!
//! The re-exported surface is the **client contract** every backend must provide. (Server-only
//! pieces — NAT masquerade, `sysctl` forwarding — stay in `oxide-net-linux`, which `oxide-serverd`
//! depends on directly; servers run on Linux.)

#[cfg(target_os = "linux")]
pub use oxide_net_linux::{
    bind_dual_stack, bring_up_interface, dns, killswitch, netlink, shutdown_signal, Netlink,
    TunDevice,
};

// A future macOS/Windows arm re-exports the same names from `oxide-net-macos` / `oxide-net-windows`
// under their own `#[cfg(target_os = ...)]`.
