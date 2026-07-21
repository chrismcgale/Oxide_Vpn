//! On-disk TOML configuration, modeled on `wg-quick`/`wg` semantics.
//!
//! One `Config` describes a local interface plus its peers. The same shape is used
//! by both the server daemon and the client; the differences (a server listens and
//! NATs, a client dials an endpoint and swings its default route) are expressed
//! through which fields are populated, not through separate types.
//!
//! Example server config:
//! ```toml
//! [interface]
//! private_key = "..."
//! address = "10.8.0.1/24"
//! listen_port = 51820
//! mtu = 1420
//!
//! [nat]
//! egress = "eth0"        # omit to auto-detect the default-route interface
//!
//! [[peer]]
//! public_key = "..."
//! allowed_ips = ["10.8.0.2/32"]
//! ```

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::keys::{PublicKey, SecretKey};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub interface: InterfaceConfig,

    /// Server-side NAT/masquerade for full-tunnel egress. Absent on clients.
    #[serde(default)]
    pub nat: Option<NatConfig>,

    /// If present, the server pulls its peer list from the control plane instead of
    /// (or in addition to) any static `[[peer]]` entries.
    #[serde(default)]
    pub control_plane: Option<ControlPlaneConfig>,

    #[serde(default, rename = "peer")]
    pub peers: Vec<PeerConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ControlPlaneConfig {
    /// Base URL of the control plane, e.g. `http://cp.example:8080`.
    pub url: String,
    /// This server's id as registered with the control plane.
    pub server_id: String,
    /// This server's auth token (from `oxide-control-plane add-server`).
    pub token: String,
    /// How often to re-fetch the peer list, in seconds.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
}

fn default_poll_interval() -> u64 {
    15
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InterfaceConfig {
    pub private_key: SecretKey,

    /// Tunnel address of this interface, with prefix (e.g. `10.8.0.1/24`).
    pub address: IpNet,

    /// Optional second tunnel address for dual-stack (typically an IPv6 prefix).
    #[serde(default)]
    pub address6: Option<IpNet>,

    /// UDP port to listen on. Required for the server; optional (ephemeral) for a client.
    #[serde(default)]
    pub listen_port: Option<u16>,

    /// Tunnel MTU. Defaults to 1420 (WireGuard's standard, leaving headroom under 1500).
    #[serde(default)]
    pub mtu: Option<u32>,

    /// DNS server to install while the tunnel is up (client-side; used from M4 on).
    #[serde(default)]
    pub dns: Option<IpAddr>,

    /// Stealth mode: a 32-byte pre-shared obfuscation key (base64). When set, all
    /// WireGuard datagrams are wrapped by the obfuscation layer so DPI can't fingerprint
    /// them. Client and server must share the same key. Reduces effective MTU — lower
    /// `mtu` (e.g. to 1380) when using it.
    #[serde(default)]
    pub obfuscation_key: Option<SecretKey>,

    /// Server-side post-quantum private key, as its base64 64-byte ML-KEM seed. When set,
    /// the server decapsulates each device's PQ ciphertext to derive that peer's PSK.
    /// Generate with `oxide-serverd pq-genkey`.
    #[serde(default)]
    pub pq_private_seed: Option<String>,
}

impl InterfaceConfig {
    pub const DEFAULT_MTU: u32 = 1420;

    pub fn mtu(&self) -> u32 {
        self.mtu.unwrap_or(Self::DEFAULT_MTU)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NatConfig {
    /// Egress interface to masquerade through. If absent, the daemon auto-detects
    /// the interface owning the default route.
    #[serde(default)]
    pub egress: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerConfig {
    pub public_key: PublicKey,

    #[serde(default)]
    pub preshared_key: Option<SecretKey>,

    /// Remote UDP endpoint to send to. Absent on a server peer (learned from the
    /// handshake source address, which also enables roaming).
    #[serde(default)]
    pub endpoint: Option<SocketAddr>,

    /// CIDRs this peer is allowed to send from and that we route to it.
    /// `0.0.0.0/0` on a client peer means full-tunnel.
    pub allowed_ips: Vec<IpNet>,

    /// Send a keepalive every N seconds to hold NAT state open (typically 25 on clients).
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,
}

impl Config {
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::from_toml_str(&text)
    }

    fn validate(&self) -> Result<()> {
        if self.peers.is_empty() && self.control_plane.is_none() {
            return Err(Error::Config(
                "at least one [[peer]] or a [control_plane] section is required".into(),
            ));
        }
        for p in &self.peers {
            if p.allowed_ips.is_empty() {
                return Err(Error::Config(
                    "each peer needs at least one allowed_ips entry".into(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_server_config() {
        let toml = r#"
            [interface]
            private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            address = "10.8.0.1/24"
            listen_port = 51820

            [nat]
            egress = "eth0"

            [[peer]]
            public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            allowed_ips = ["10.8.0.2/32"]
        "#;
        let cfg = Config::from_toml_str(toml).unwrap();
        assert_eq!(cfg.interface.listen_port, Some(51820));
        assert_eq!(cfg.interface.mtu(), 1420);
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.nat.unwrap().egress.as_deref(), Some("eth0"));
    }

    #[test]
    fn parses_dual_stack_address6() {
        let toml = r#"
            [interface]
            private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            address = "10.8.0.2/24"
            address6 = "fd00::2/64"

            [[peer]]
            public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            allowed_ips = ["0.0.0.0/0", "::/0"]
        "#;
        let cfg = Config::from_toml_str(toml).unwrap();
        assert_eq!(cfg.interface.address6.unwrap().to_string(), "fd00::2/64");
        assert_eq!(cfg.peers[0].allowed_ips.len(), 2);
    }

    #[test]
    fn rejects_no_peers() {
        let toml = r#"
            [interface]
            private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            address = "10.8.0.1/24"
        "#;
        assert!(Config::from_toml_str(toml).is_err());
    }
}
