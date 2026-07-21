//! Oxide WireGuard data-plane engine.
//!
//! Wraps boringtun's `Tunn` state machine and drives the TUN <-> UDP packet flow. It
//! is intentionally OS-agnostic: it talks to the tunnel device through the
//! [`oxide_common::TunQueue`] trait and to the network through a tokio `UdpSocket`,
//! and knows nothing about netlink, nftables, config files, or a control plane.
//!
//! Peers are runtime-mutable via [`EngineHandle`], so a control plane can add and
//! remove them on a live server.

pub mod engine;
pub mod peer;
pub mod router;
pub mod table;

#[cfg(feature = "test-util")]
pub mod testutil;

pub use engine::{Engine, EngineHandle, PeerParams};
pub use table::PeerId;

pub use oxide_common::{PublicKey, SecretKey, TunQueue};
