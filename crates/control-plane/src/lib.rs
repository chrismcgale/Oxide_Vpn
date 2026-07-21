//! Oxide control plane: the account/device/server registry and API.
//!
//! Clients create an anonymous account, list servers, and register a device public key
//! (getting an assigned tunnel IP back). Servers poll their peer list. This is the
//! "Nord-scale" layer — the tunnel crypto itself lives in `wg-core`.
//!
//! The router is built by [`app`] so integration tests can mount it in-process without
//! binding a socket.

pub mod db;
pub mod error;
pub mod ip_alloc;

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ipnet::IpNet;
use rand_core::{OsRng, RngCore};
use sqlx::{Row, SqlitePool};
use tokio::sync::Mutex;

use oxide_common::account::{generate_account_number, is_valid_account_number};
use oxide_common::api::{
    CreateAccountResponse, PeerEntry, PeerListResponse, RegisterDeviceRequest,
    RegisterDeviceResponse, ServerConnection, ServerInfo, ServerListResponse,
};
use oxide_common::PublicKey;

use error::{ApiResult, AppError};

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    /// Serializes device registration so IP allocation can't race under SQLite.
    reg_lock: Arc<Mutex<()>>,
}

impl AppState {
    pub fn new(pool: SqlitePool) -> Self {
        AppState {
            pool,
            reg_lock: Arc::new(Mutex::new(())),
        }
    }
}

/// Build the API router.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/v1/accounts", post(create_account))
        .route("/v1/servers", get(list_servers))
        .route("/v1/devices", post(register_device))
        .route(
            "/v1/internal/servers/:id/peers",
            get(list_peers),
        )
        .with_state(state)
}

/// Serve the API on an already-bound listener until the process exits. Convenience
/// so callers (and tests) don't need to depend on `axum` directly.
pub async fn serve(listener: tokio::net::TcpListener, state: AppState) -> std::io::Result<()> {
    axum::serve(listener, app(state)).await
}

/// A random opaque token (server auth). base64 of 24 random bytes.
pub fn random_token() -> String {
    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);
    B64.encode(bytes)
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|s| s.trim().to_string())
}

/// Require a valid, existing account number as bearer; return it.
async fn auth_account(state: &AppState, headers: &HeaderMap) -> ApiResult<String> {
    let token = bearer(headers).ok_or(AppError::Unauthorized)?;
    if !is_valid_account_number(&token) {
        return Err(AppError::Unauthorized);
    }
    let exists: Option<String> =
        sqlx::query_scalar("SELECT number FROM accounts WHERE number = ?")
            .bind(&token)
            .fetch_optional(&state.pool)
            .await?;
    exists.ok_or(AppError::Unauthorized)
}

// POST /v1/accounts
async fn create_account(State(state): State<AppState>) -> ApiResult<Json<CreateAccountResponse>> {
    // Collisions are astronomically unlikely; retry a few times to be safe.
    for _ in 0..5 {
        let number = generate_account_number();
        let res = sqlx::query("INSERT INTO accounts (number, created_at) VALUES (?, ?)")
            .bind(&number)
            .bind(db::now_unix())
            .execute(&state.pool)
            .await;
        match res {
            Ok(_) => return Ok(Json(CreateAccountResponse { account_number: number })),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(AppError::Internal(anyhow::anyhow!(
        "could not allocate a unique account number"
    )))
}

// GET /v1/servers
async fn list_servers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ServerListResponse>> {
    auth_account(&state, &headers).await?;

    let rows = sqlx::query("SELECT id, public_key, endpoint FROM servers ORDER BY id")
        .fetch_all(&state.pool)
        .await?;
    let mut servers = Vec::with_capacity(rows.len());
    for row in rows {
        let pk: String = row.get("public_key");
        let public_key = PublicKey::from_str(&pk)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("bad stored key: {e}")))?;
        servers.push(ServerInfo {
            id: row.get("id"),
            public_key,
            endpoint: row.get("endpoint"),
            location: None,
        });
    }
    Ok(Json(ServerListResponse { servers }))
}

// POST /v1/devices
async fn register_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterDeviceRequest>,
) -> ApiResult<Json<RegisterDeviceResponse>> {
    let account = auth_account(&state, &headers).await?;

    // Load the target server.
    let server = sqlx::query(
        "SELECT public_key, endpoint, tunnel_cidr, tunnel_ip FROM servers WHERE id = ?",
    )
    .bind(&req.server_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("no such server: {}", req.server_id)))?;

    let server_pk: String = server.get("public_key");
    let server_endpoint: String = server.get("endpoint");
    let tunnel_cidr: String = server.get("tunnel_cidr");
    let server_tunnel_ip: String = server.get("tunnel_ip");
    let cidr: IpNet = tunnel_cidr
        .parse()
        .map_err(|_| AppError::Internal(anyhow::anyhow!("bad stored cidr")))?;

    let device_pk = req.public_key.to_base64();

    // Serialize allocation + insert so two registrations can't grab the same IP.
    let _guard = state.reg_lock.lock().await;

    // Idempotent re-registration: same pubkey already registered.
    if let Some(existing) = sqlx::query(
        "SELECT account_number, tunnel_ip FROM devices WHERE public_key = ?",
    )
    .bind(&device_pk)
    .fetch_optional(&state.pool)
    .await?
    {
        let owner: String = existing.get("account_number");
        if owner != account {
            return Err(AppError::Conflict("device key already registered".into()));
        }
        let ip: String = existing.get("tunnel_ip");
        return Ok(Json(response_for(
            ip, cidr, server_pk, server_endpoint, server_tunnel_ip,
        )?));
    }

    // Allocate the lowest free host in the subnet.
    let used = used_ips(&state.pool, &req.server_id).await?;
    let server_ip: IpAddr = server_tunnel_ip
        .parse()
        .map_err(|_| AppError::Internal(anyhow::anyhow!("bad stored server ip")))?;
    let assigned = ip_alloc::allocate(cidr, server_ip, &used)
        .ok_or_else(|| AppError::Conflict("server subnet exhausted".into()))?;

    sqlx::query(
        "INSERT INTO devices (account_number, public_key, server_id, tunnel_ip, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&account)
    .bind(&device_pk)
    .bind(&req.server_id)
    .bind(assigned.to_string())
    .bind(db::now_unix())
    .execute(&state.pool)
    .await?;

    Ok(Json(response_for(
        assigned.to_string(),
        cidr,
        server_pk,
        server_endpoint,
        server_tunnel_ip,
    )?))
}

// GET /v1/internal/servers/:id/peers  (server-authenticated)
async fn list_peers(
    State(state): State<AppState>,
    Path(server_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<PeerListResponse>> {
    let token = bearer(&headers).ok_or(AppError::Unauthorized)?;
    let expected: Option<String> =
        sqlx::query_scalar("SELECT auth_token FROM servers WHERE id = ?")
            .bind(&server_id)
            .fetch_optional(&state.pool)
            .await?;
    match expected {
        Some(t) if t == token => {}
        _ => return Err(AppError::Unauthorized),
    }

    let rows = sqlx::query("SELECT public_key, tunnel_ip FROM devices WHERE server_id = ?")
        .bind(&server_id)
        .fetch_all(&state.pool)
        .await?;
    let peers = rows
        .into_iter()
        .map(|row| {
            let pk: String = row.get("public_key");
            let ip: String = row.get("tunnel_ip");
            PeerEntry {
                public_key: PublicKey::from_str(&pk).expect("stored key valid"),
                allowed_ips: vec![format!("{ip}/32")],
            }
        })
        .collect();
    Ok(Json(PeerListResponse { peers }))
}

async fn used_ips(pool: &SqlitePool, server_id: &str) -> ApiResult<HashSet<IpAddr>> {
    let rows = sqlx::query("SELECT tunnel_ip FROM devices WHERE server_id = ?")
        .bind(server_id)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| r.get::<String, _>("tunnel_ip").parse().ok())
        .collect())
}

fn response_for(
    assigned_ip: String,
    cidr: IpNet,
    server_pk: String,
    server_endpoint: String,
    server_tunnel_ip: String,
) -> ApiResult<RegisterDeviceResponse> {
    let public_key = PublicKey::from_str(&server_pk)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("bad stored key: {e}")))?;
    Ok(RegisterDeviceResponse {
        assigned_ip: format!("{}/{}", assigned_ip, cidr.prefix_len()),
        server: ServerConnection {
            public_key,
            endpoint: server_endpoint,
            tunnel_ip: server_tunnel_ip,
        },
        dns: None,
    })
}

/// Insert a server row (used by the `add-server` CLI). Returns the generated auth token.
pub async fn add_server(
    pool: &SqlitePool,
    id: &str,
    public_key: &str,
    endpoint: &str,
    cidr: IpNet,
) -> anyhow::Result<String> {
    // The server takes the first usable host of its subnet as its own tunnel IP.
    let server_ip = cidr
        .hosts()
        .next()
        .ok_or_else(|| anyhow::anyhow!("cidr has no usable hosts"))?;
    let token = random_token();
    sqlx::query(
        "INSERT INTO servers (id, public_key, endpoint, tunnel_cidr, tunnel_ip, auth_token, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(public_key)
    .bind(endpoint)
    .bind(cidr.to_string())
    .bind(server_ip.to_string())
    .bind(&token)
    .bind(db::now_unix())
    .execute(pool)
    .await?;
    Ok(token)
}
