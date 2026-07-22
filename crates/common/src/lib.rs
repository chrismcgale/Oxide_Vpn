//! Shared types for the Oxide VPN workspace: key material, on-disk config, and the
//! crate-wide error. Deliberately dependency-light and OS-agnostic so it can be
//! shared by the data plane (`wg-core`), the platform layer (`net-linux`), and a
//! future control plane without pulling any of them in.

pub mod account;
pub mod agent;
pub mod api;
pub mod config;
pub mod error;
pub mod keys;
pub mod tun;

pub use config::{
    Config, ControlPlaneConfig, HardeningConfig, InterfaceConfig, NatConfig, PeerConfig,
    TransportKind,
};
pub use error::{Error, Result};
pub use keys::{PublicKey, SecretKey};
pub use tun::TunQueue;
