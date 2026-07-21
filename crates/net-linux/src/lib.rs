//! Linux platform layer for Oxide VPN: the privileged, OS-specific bits the
//! data-plane engine deliberately doesn't know about — the TUN device, interface
//! addressing/routing, nftables masquerade, and sysctl toggles.
//!
//! Every syscall/tool invocation that needs `CAP_NET_ADMIN` lives here, isolated so
//! `wg-core` stays testable without root and a future `net-macos` can be a sibling.

pub mod cmd;
pub mod dns;
pub mod killswitch;
pub mod nat;
pub mod netlink;
pub mod setup;
pub mod sysctl;
pub mod tun;

pub use netlink::Netlink;
pub use setup::bring_up_interface;
pub use tun::TunDevice;
