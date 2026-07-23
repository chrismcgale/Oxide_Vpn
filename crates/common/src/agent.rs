//! Control protocol between the unprivileged UI (TUI/GUI) and the privileged agent.
//!
//! The agent (`oxide-agentd`) runs as root and owns the tunnel; the UI runs as a normal
//! user and drives it over a local Unix socket. This split means the UI never needs
//! privileges. Messages are newline-delimited JSON (one request → one response).

use serde::{Deserialize, Serialize};

/// Default Unix socket the agent listens on.
pub const DEFAULT_SOCKET: &str = "/run/oxide/agent.sock";

/// A request from the UI to the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum AgentRequest {
    /// Report the current tunnel status.
    Status,
    /// Connect via the control plane. `server` empty = auto-select.
    Connect {
        control_plane: String,
        account: String,
        #[serde(default)]
        server: Option<String>,
        #[serde(default)]
        exit: Option<String>,
        #[serde(default)]
        country: Option<String>,
        #[serde(default)]
        kill_switch: bool,
    },
    /// Tear down the tunnel.
    Disconnect,
    /// Rotate to a new identity: fresh device key + reconnect to a different exit, for
    /// per-session unlinkability. No-op error if not connected.
    NewIdentity,
}

/// A response from the agent to the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "resp", rename_all = "snake_case")]
pub enum AgentResponse {
    Status(TunnelStatus),
    /// A command was accepted.
    Ok,
    /// A command failed, with a human-readable reason.
    Error {
        message: String,
    },
}

/// The current state of the tunnel, shown in the UI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunnelStatus {
    pub connected: bool,
    /// Server id we're connected to (or connecting to), if any.
    #[serde(default)]
    pub server_id: Option<String>,
    /// The multihop exit id, if this is a multihop connection.
    #[serde(default)]
    pub exit_id: Option<String>,
    /// Assigned tunnel address, e.g. `10.8.0.5/24`.
    #[serde(default)]
    pub assigned_ip: Option<String>,
    /// Seconds since the tunnel came up.
    #[serde(default)]
    pub uptime_secs: u64,
    /// Bytes sent / received through the tunnel.
    #[serde(default)]
    pub tx_bytes: u64,
    #[serde(default)]
    pub rx_bytes: u64,
    /// Peers with a live session (typically 1 for a client).
    #[serde(default)]
    pub active_peers: usize,
    /// Whether stealth (obfuscation) is active.
    #[serde(default)]
    pub stealth: bool,
    /// Whether the post-quantum PSK is in use.
    #[serde(default)]
    pub post_quantum: bool,
}

impl AgentRequest {
    /// Encode as a single newline-terminated JSON line.
    pub fn to_line(&self) -> String {
        let mut s = serde_json::to_string(self).expect("serialize AgentRequest");
        s.push('\n');
        s
    }
}

impl AgentResponse {
    pub fn to_line(&self) -> String {
        let mut s = serde_json::to_string(self).expect("serialize AgentResponse");
        s.push('\n');
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let req = AgentRequest::Connect {
            control_plane: "http://cp:8080".into(),
            account: "1234567890123456".into(),
            server: Some("us-1".into()),
            exit: None,
            country: None,
            kill_switch: true,
        };
        let line = req.to_line();
        assert!(line.ends_with('\n'));
        let back: AgentRequest = serde_json::from_str(line.trim()).unwrap();
        assert!(matches!(
            back,
            AgentRequest::Connect {
                kill_switch: true,
                ..
            }
        ));
    }

    #[test]
    fn new_identity_request_roundtrip() {
        let line = AgentRequest::NewIdentity.to_line();
        assert_eq!(line.trim(), r#"{"cmd":"new_identity"}"#);
        let back: AgentRequest = serde_json::from_str(line.trim()).unwrap();
        assert!(matches!(back, AgentRequest::NewIdentity));
    }

    #[test]
    fn status_response_roundtrip() {
        let resp = AgentResponse::Status(TunnelStatus {
            connected: true,
            server_id: Some("se-3".into()),
            assigned_ip: Some("10.8.0.9/24".into()),
            tx_bytes: 4096,
            rx_bytes: 8192,
            active_peers: 1,
            post_quantum: true,
            ..Default::default()
        });
        let back: AgentResponse = serde_json::from_str(resp.to_line().trim()).unwrap();
        match back {
            AgentResponse::Status(s) => {
                assert!(s.connected);
                assert_eq!(s.rx_bytes, 8192);
                assert!(s.post_quantum);
            }
            _ => panic!("expected status"),
        }
    }
}
