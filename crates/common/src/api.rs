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
    /// Post-quantum public (ML-KEM encapsulation) key, base64, if the server runs PQ.
    /// The client encapsulates to it and sends the ciphertext at registration.
    #[serde(default)]
    pub pq_public_key: Option<String>,
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
    /// Post-quantum KEM ciphertext (base64) the client encapsulated to the server's PQ
    /// public key. The server decapsulates it to recover the shared PSK.
    #[serde(default)]
    pub pq_ciphertext: Option<String>,
}

/// Register a device for a multihop path: the tunnel terminates at `exit_id`, but
/// traffic is sent via `entry_id`, which relays it. The returned
/// [`RegisterDeviceResponse`] has the exit's public key and tunnel IP but the entry's
/// relay endpoint, so the client's single WireGuard session runs exit-keyed through the
/// entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultihopRegisterRequest {
    pub public_key: PublicKey,
    pub entry_id: String,
    pub exit_id: String,
    /// PQ KEM ciphertext (base64) encapsulated to the *exit's* PQ key — the tunnel
    /// terminates at the exit, so that's where post-quantum keys.
    #[serde(default)]
    pub pq_ciphertext: Option<String>,
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
    /// Stealth-mode obfuscation key (base64), if the server runs stealth. The client
    /// uses it to obfuscate the tunnel. For multihop this is the *exit's* key (the
    /// tunnel terminates there; the entry relays the obfuscated bytes untouched).
    #[serde(default)]
    pub obfuscation_key: Option<String>,
    /// Wire transport the server expects (`plain`|`obfs`|`quic`|`mimic`). Absent means the
    /// client applies the back-compat rule (obfs if an `obfuscation_key` is present, else
    /// plain). For multihop this is the *exit's* transport.
    #[serde(default)]
    pub transport: Option<String>,
    /// Whether the server runs DAITA (traffic-analysis defense); the client then shapes its
    /// egress and frames cells to match. Requires a stealth transport.
    #[serde(default)]
    pub daita: bool,
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
    /// The device's PQ KEM ciphertext (base64), if it registered with post-quantum. The
    /// server decapsulates it to derive this peer's preshared key.
    #[serde(default)]
    pub pq_ciphertext: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerListResponse {
    pub peers: Vec<PeerEntry>,
}

/// One relay this (entry) server should run: listen on `listen_port` and forward to the
/// exit server's WireGuard endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayEntry {
    pub listen_port: u16,
    pub exit_endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayListResponse {
    pub relays: Vec<RelayEntry>,
}

/// Register this device into the account's private mesh (a Tailscale-style overlay of
/// the user's own devices), reporting where it's reachable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshRegisterRequest {
    pub public_key: PublicKey,
    /// The UDP endpoint (host:port) other devices can reach this one at.
    pub endpoint: String,
}

/// One device in the mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshPeer {
    pub public_key: PublicKey,
    /// Stable mesh address (a `/32` in the mesh subnet, e.g. `100.64.0.5`).
    pub mesh_ip: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshRegisterResponse {
    /// This device's assigned mesh address, with the mesh prefix (e.g. `100.64.0.5/16`).
    pub mesh_ip: String,
    /// The other devices in the account's mesh.
    pub peers: Vec<MeshPeer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshListResponse {
    pub peers: Vec<MeshPeer>,
}

/// Standard JSON error body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}
