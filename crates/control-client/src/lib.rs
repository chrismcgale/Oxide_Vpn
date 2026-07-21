//! HTTP client for the Oxide control plane.
//!
//! Shared by `oxide-client` (account/device registration) and `oxide-serverd`
//! (fetching its peer list). Thin wrapper over `reqwest` returning the shared DTOs
//! from [`oxide_common::api`].

use anyhow::{bail, Context, Result};
use reqwest::StatusCode;

use oxide_common::api::{
    CreateAccountResponse, PeerEntry, PeerListResponse, RegisterDeviceRequest,
    RegisterDeviceResponse, ServerInfo, ServerListResponse,
};
use oxide_common::PublicKey;

pub struct ControlClient {
    base: String,
    http: reqwest::Client,
}

impl ControlClient {
    pub fn new(base_url: &str) -> Self {
        ControlClient {
            base: base_url.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    /// Create a new anonymous account; returns the account number.
    pub async fn create_account(&self) -> Result<String> {
        let resp = self
            .http
            .post(self.url("/v1/accounts"))
            .send()
            .await
            .context("POST /v1/accounts")?;
        let resp = check(resp).await?;
        let body: CreateAccountResponse = resp.json().await?;
        Ok(body.account_number)
    }

    /// List available servers (authenticated with the account number).
    pub async fn list_servers(&self, account: &str) -> Result<Vec<ServerInfo>> {
        let resp = self
            .http
            .get(self.url("/v1/servers"))
            .bearer_auth(account)
            .send()
            .await
            .context("GET /v1/servers")?;
        let resp = check(resp).await?;
        let body: ServerListResponse = resp.json().await?;
        Ok(body.servers)
    }

    /// Register this device's public key on `server_id`; returns connection details.
    pub async fn register_device(
        &self,
        account: &str,
        public_key: PublicKey,
        server_id: &str,
    ) -> Result<RegisterDeviceResponse> {
        let req = RegisterDeviceRequest {
            public_key,
            server_id: server_id.to_string(),
        };
        let resp = self
            .http
            .post(self.url("/v1/devices"))
            .bearer_auth(account)
            .json(&req)
            .send()
            .await
            .context("POST /v1/devices")?;
        let resp = check(resp).await?;
        Ok(resp.json().await?)
    }

    /// Server-facing: fetch the peer list for `server_id` (authenticated with the
    /// server's auth token).
    pub async fn fetch_peers(&self, server_id: &str, server_token: &str) -> Result<Vec<PeerEntry>> {
        let resp = self
            .http
            .get(self.url(&format!("/v1/internal/servers/{server_id}/peers")))
            .bearer_auth(server_token)
            .send()
            .await
            .context("GET peer list")?;
        let resp = check(resp).await?;
        let body: PeerListResponse = resp.json().await?;
        Ok(body.peers)
    }
}

/// Turn a non-2xx response into an error carrying the server's message.
async fn check(resp: reqwest::Response) -> Result<reqwest::Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().await.unwrap_or_default();
    if status == StatusCode::UNAUTHORIZED {
        bail!("unauthorized (check account number / server token)");
    }
    bail!("control plane returned {status}: {body}");
}
