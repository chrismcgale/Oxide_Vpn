//! HTTP client for the Oxide control plane.
//!
//! Shared by `oxide-client` (account/device registration) and `oxide-serverd`
//! (fetching its peer list). Thin wrapper over `reqwest` returning the shared DTOs
//! from [`oxide_common::api`].

use anyhow::{bail, Context, Result};
use reqwest::StatusCode;

use oxide_common::api::{
    AdminAddServerRequest, AdminAddServerResponse, AdminOverview, AdminServerInfo,
    AdminServersResponse, CreateAccountResponse, HeartbeatRequest, MeshListResponse, MeshPeer,
    MeshRegisterRequest, MeshRegisterResponse, MultihopRegisterRequest, PeerEntry,
    PeerListResponse, RegisterDeviceRequest, RegisterDeviceResponse, RelayEntry, RelayListResponse,
    RotateTokenResponse, ServerInfo, ServerListResponse, VersionResponse, API_VERSION,
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

    /// Pick the least-loaded healthy server, optionally filtered by country/city.
    pub async fn best_server(
        &self,
        account: &str,
        country: Option<&str>,
        city: Option<&str>,
    ) -> Result<ServerInfo> {
        let mut query: Vec<(&str, &str)> = Vec::new();
        if let Some(c) = country {
            query.push(("country", c));
        }
        if let Some(c) = city {
            query.push(("city", c));
        }
        let resp = self
            .http
            .get(self.url("/v1/servers/best"))
            .query(&query)
            .bearer_auth(account)
            .send()
            .await
            .context("GET /v1/servers/best")?;
        let resp = check(resp).await?;
        Ok(resp.json().await?)
    }

    /// Report live load + cumulative bandwidth/defense counters to the control plane
    /// (server-authenticated heartbeat). The `report`'s byte + DAITA fields are the engine's
    /// counters since the server started; the control plane folds bytes into reset-safe totals
    /// and records the latest defense counters. Callers build the [`HeartbeatRequest`] from
    /// their `EngineStats` (see `oxide-serverd`).
    pub async fn heartbeat(
        &self,
        server_id: &str,
        token: &str,
        report: &HeartbeatRequest,
    ) -> Result<()> {
        let resp = self
            .http
            .post(self.url(&format!("/v1/internal/servers/{server_id}/heartbeat")))
            .bearer_auth(token)
            .json(report)
            .send()
            .await
            .context("POST heartbeat")?;
        check(resp).await?;
        Ok(())
    }

    /// Register a VPN server node remotely (admin-authenticated); returns its auth token.
    /// Used by `oxide-serverd provision` to stand a server up in one command.
    pub async fn admin_add_server(
        &self,
        admin_token: &str,
        req: &AdminAddServerRequest,
    ) -> Result<String> {
        let resp = self
            .http
            .post(self.url("/v1/admin/servers"))
            .bearer_auth(admin_token)
            .json(req)
            .send()
            .await
            .context("POST admin add-server")?;
        let resp = check(resp).await?;
        let body: AdminAddServerResponse = resp.json().await.context("parsing admin response")?;
        Ok(body.auth_token)
    }

    /// The control plane's API version + build (unauthenticated).
    pub async fn version(&self) -> Result<VersionResponse> {
        let resp = self
            .http
            .get(self.url("/version"))
            .send()
            .await
            .context("GET version")?;
        check(resp).await?.json().await.context("parsing version")
    }

    /// Whether this client speaks the same API contract version as the control plane. A
    /// mismatch means the client is too old/new for that control plane (talk to a matching
    /// one, or upgrade). Additive changes within a version stay compatible.
    pub async fn is_compatible(&self) -> Result<bool> {
        Ok(self.version().await?.api == API_VERSION)
    }

    /// Rotate a server's auth token (admin-authenticated). Returns the new token and how long
    /// the previous one stays valid (grace), so the operator can update the server config
    /// without downtime.
    pub async fn admin_rotate_token(
        &self,
        admin_token: &str,
        server_id: &str,
    ) -> Result<RotateTokenResponse> {
        let resp = self
            .http
            .post(self.url(&format!("/v1/admin/servers/{server_id}/rotate-token")))
            .bearer_auth(admin_token)
            .send()
            .await
            .context("POST rotate-token")?;
        let resp = check(resp).await?;
        resp.json().await.context("parsing rotate-token response")
    }

    /// List the full fleet with operational detail (admin-authenticated). Powers the admin TUI.
    pub async fn admin_list_servers(&self, admin_token: &str) -> Result<Vec<AdminServerInfo>> {
        let resp = self
            .http
            .get(self.url("/v1/admin/servers"))
            .bearer_auth(admin_token)
            .send()
            .await
            .context("GET admin servers")?;
        let body: AdminServersResponse = check(resp)
            .await?
            .json()
            .await
            .context("parsing admin servers")?;
        Ok(body.servers)
    }

    /// Fleet-wide aggregates for the admin dashboard (admin-authenticated).
    pub async fn admin_overview(&self, admin_token: &str) -> Result<AdminOverview> {
        let resp = self
            .http
            .get(self.url("/v1/admin/overview"))
            .bearer_auth(admin_token)
            .send()
            .await
            .context("GET admin overview")?;
        check(resp)
            .await?
            .json()
            .await
            .context("parsing admin overview")
    }

    /// Register this device's public key on `server_id`; returns connection details.
    /// `pq_ciphertext` carries a post-quantum KEM ciphertext (base64) when the server
    /// runs PQ; pass `None` otherwise.
    pub async fn register_device(
        &self,
        account: &str,
        public_key: PublicKey,
        server_id: &str,
        pq_ciphertext: Option<&str>,
    ) -> Result<RegisterDeviceResponse> {
        let req = RegisterDeviceRequest {
            public_key,
            server_id: server_id.to_string(),
            pq_ciphertext: pq_ciphertext.map(String::from),
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

    /// Register this device for a multihop path (tunnel to `exit_id`, via `entry_id`).
    /// The returned connection has the exit's key/tunnel-IP but the entry's relay endpoint.
    pub async fn register_device_multihop(
        &self,
        account: &str,
        public_key: PublicKey,
        entry_id: &str,
        exit_id: &str,
        pq_ciphertext: Option<&str>,
    ) -> Result<RegisterDeviceResponse> {
        let req = MultihopRegisterRequest {
            public_key,
            entry_id: entry_id.to_string(),
            exit_id: exit_id.to_string(),
            pq_ciphertext: pq_ciphertext.map(String::from),
        };
        let resp = self
            .http
            .post(self.url("/v1/devices/multihop"))
            .bearer_auth(account)
            .json(&req)
            .send()
            .await
            .context("POST /v1/devices/multihop")?;
        let resp = check(resp).await?;
        Ok(resp.json().await?)
    }

    /// Server-facing: fetch the relay routes this (entry) server should run.
    pub async fn fetch_relays(
        &self,
        server_id: &str,
        server_token: &str,
    ) -> Result<Vec<RelayEntry>> {
        let resp = self
            .http
            .get(self.url(&format!("/v1/internal/servers/{server_id}/relays")))
            .bearer_auth(server_token)
            .send()
            .await
            .context("GET relay list")?;
        let resp = check(resp).await?;
        let body: RelayListResponse = resp.json().await?;
        Ok(body.relays)
    }

    /// Join the account's private mesh, reporting the endpoint others can reach us at.
    /// Returns our assigned mesh IP and the current peer list.
    pub async fn mesh_register(
        &self,
        account: &str,
        public_key: PublicKey,
        endpoint: &str,
    ) -> Result<MeshRegisterResponse> {
        let req = MeshRegisterRequest {
            public_key,
            endpoint: endpoint.to_string(),
        };
        let resp = self
            .http
            .post(self.url("/v1/mesh/register"))
            .bearer_auth(account)
            .json(&req)
            .send()
            .await
            .context("POST /v1/mesh/register")?;
        let resp = check(resp).await?;
        Ok(resp.json().await?)
    }

    /// Poll the account's current mesh peer list.
    pub async fn mesh_list(&self, account: &str) -> Result<Vec<MeshPeer>> {
        let resp = self
            .http
            .get(self.url("/v1/mesh"))
            .bearer_auth(account)
            .send()
            .await
            .context("GET /v1/mesh")?;
        let resp = check(resp).await?;
        let body: MeshListResponse = resp.json().await?;
        Ok(body.peers)
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
