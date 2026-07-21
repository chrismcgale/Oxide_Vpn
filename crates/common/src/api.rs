//! Control-plane HTTP API DTOs, shared by the service and its clients.
//!
//! Kept here in `common` so the `control-plane` service, the `control-client` library,
//! and the daemons all agree on the wire format. Public keys serialize as base64
//! (see [`crate::keys::PublicKey`]); IPs/CIDRs and endpoints travel as strings.

use serde::{Deserialize, Serialize};

use crate::keys::PublicKey;

/// Response to creating a new anonymous account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccountResponse {
    pub account_number: String,
}

/// A VPN server as advertised to clients, with location and live load for selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub id: String,
    pub public_key: PublicKey,
    /// Public UDP endpoint, `host:port`.
    pub endpoint: String,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    /// Peers with a live session, as last reported by the server's heartbeat.
    #[serde(default)]
    pub active_peers: u32,
    /// Soft capacity (max peers) used to compute a load factor. 0 = unset/unlimited.
    #[serde(default)]
    pub capacity: u32,
    /// Whether the server has heartbeated recently enough to be considered up.
    #[serde(default = "default_true")]
    pub healthy: bool,
}

fn default_true() -> bool {
    true
}

/// Server-reported live load (server-authenticated heartbeat).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub active_peers: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerListResponse {
    pub servers: Vec<ServerInfo>,
}

/// Register (or re-register) a device's public key on a chosen server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDeviceRequest {
    pub public_key: PublicKey,
    pub server_id: String,
}

/// Everything a client needs to build a working tunnel config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDeviceResponse {
    /// The device's assigned tunnel address with prefix, e.g. `10.8.0.5/24`.
    pub assigned_ip: String,
    pub server: ServerConnection,
    /// DNS server to use while connected (defaults applied client-side if absent).
    #[serde(default)]
    pub dns: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConnection {
    pub public_key: PublicKey,
    pub endpoint: String,
    /// The server's own tunnel address (its IP inside the tunnel subnet).
    pub tunnel_ip: String,
}

/// One peer entry in a server's peer list (internal, server-facing endpoint).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    pub public_key: PublicKey,
    /// CIDRs allowed for / routed to this peer, e.g. `["10.8.0.5/32"]`.
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerListResponse {
    pub peers: Vec<PeerEntry>,
}

/// Standard JSON error body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}
