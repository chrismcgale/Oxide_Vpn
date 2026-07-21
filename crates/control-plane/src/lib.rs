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

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ipnet::IpNet;
use rand_core::{OsRng, RngCore};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqlitePool};
use tokio::sync::Mutex;
use tower_http::timeout::TimeoutLayer;

use oxide_common::account::{generate_account_number, is_valid_account_number};
use oxide_common::api::{
    ApiError, CreateAccountResponse, HeartbeatRequest, MultihopRegisterRequest, PeerEntry,
    PeerListResponse, RegisterDeviceRequest, RegisterDeviceResponse, RelayEntry, RelayListResponse,
    ServerConnection, ServerInfo, ServerListResponse,
};
use oxide_common::PublicKey;

use error::{ApiResult, AppError};

/// A server is considered unhealthy if its last heartbeat is older than this. A server
/// that has *never* heartbeated is treated as healthy (it may not run the heartbeat
/// loop); once it starts, staleness applies.
const SERVER_STALE_SECS: i64 = 90;

/// Columns selected when building a [`ServerInfo`].
const SERVER_COLUMNS: &str =
    "id, public_key, endpoint, country, city, capacity, active_peers, last_heartbeat";

/// Max requests per source IP per [`RATE_WINDOW`]. Protects the account-number bearer
/// auth from brute force and the account-creation endpoint from abuse.
const RATE_MAX: u32 = 60;
const RATE_WINDOW: Duration = Duration::from_secs(60);
/// Reject request bodies larger than this (JSON API — nothing is big).
const MAX_BODY_BYTES: usize = 64 * 1024;
/// Drop requests that take longer than this.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

struct RateWindow {
    start: Instant,
    count: u32,
}

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    /// Serializes device registration so IP allocation can't race under SQLite.
    reg_lock: Arc<Mutex<()>>,
    /// Fixed-window per-IP request counters.
    rate: Arc<StdMutex<HashMap<IpAddr, RateWindow>>>,
}

impl AppState {
    pub fn new(pool: SqlitePool) -> Self {
        AppState {
            pool,
            reg_lock: Arc::new(Mutex::new(())),
            rate: Arc::new(StdMutex::new(HashMap::new())),
        }
    }

    /// Fixed-window rate check: true if this IP is under the limit (and counts it).
    fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut map = self.rate.lock().unwrap();
        let w = map.entry(ip).or_insert(RateWindow {
            start: now,
            count: 0,
        });
        if now.duration_since(w.start) > RATE_WINDOW {
            *w = RateWindow {
                start: now,
                count: 0,
            };
        }
        if w.count >= RATE_MAX {
            false
        } else {
            w.count += 1;
            true
        }
    }
}

/// Per-IP rate-limiting middleware. Skips limiting when no peer address is available
/// (e.g. tests that mount the router without connect info).
async fn rate_limit(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if let Some(ci) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        if !state.allow(ci.0.ip()) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ApiError {
                    error: "rate limit exceeded".into(),
                }),
            )
                .into_response();
        }
    }
    next.run(req).await
}

/// Build the API router.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/v1/accounts", post(create_account))
        .route("/v1/servers", get(list_servers))
        .route("/v1/servers/best", get(best_server))
        .route("/v1/devices", post(register_device))
        .route("/v1/devices/multihop", post(register_device_multihop))
        .route("/v1/internal/servers/:id/peers", get(list_peers))
        .route("/v1/internal/servers/:id/relays", get(list_relays))
        .route("/v1/internal/servers/:id/heartbeat", post(server_heartbeat))
        // Outer-to-inner: rate limit, then body-size cap, then request timeout.
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .with_state(state)
}

/// Serve the API on an already-bound listener until the process exits. Uses connect
/// info so the per-IP rate limiter can see the client address. Convenience so callers
/// (and tests) don't need to depend on `axum` directly.
pub async fn serve(listener: tokio::net::TcpListener, state: AppState) -> std::io::Result<()> {
    axum::serve(
        listener,
        app(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
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
    let exists: Option<String> = sqlx::query_scalar("SELECT number FROM accounts WHERE number = ?")
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
            Ok(_) => {
                return Ok(Json(CreateAccountResponse {
                    account_number: number,
                }))
            }
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
    let servers = load_servers(&state).await?;
    Ok(Json(ServerListResponse { servers }))
}

// GET /v1/servers/best?country=..&city=..
// Picks the least-loaded healthy server, optionally filtered by location.
async fn best_server(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<Json<ServerInfo>> {
    auth_account(&state, &headers).await?;
    let country = params.get("country");
    let city = params.get("city");

    let candidate = load_servers(&state)
        .await?
        .into_iter()
        .filter(|s| s.healthy)
        .filter(|s| country.is_none_or(|c| eq_ci(&s.country, c)))
        .filter(|s| city.is_none_or(|c| eq_ci(&s.city, c)))
        .min_by(|a, b| {
            load_factor(a)
                .partial_cmp(&load_factor(b))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.active_peers.cmp(&b.active_peers))
        });

    candidate
        .map(Json)
        .ok_or_else(|| AppError::NotFound("no server matches the requested criteria".into()))
}

/// Fraction of capacity in use (lower is better). Uncapped servers compare by raw
/// active-peer count.
fn load_factor(s: &ServerInfo) -> f64 {
    if s.capacity > 0 {
        s.active_peers as f64 / s.capacity as f64
    } else {
        s.active_peers as f64
    }
}

fn eq_ci(field: &Option<String>, want: &str) -> bool {
    field
        .as_deref()
        .is_some_and(|v| v.eq_ignore_ascii_case(want))
}

async fn load_servers(state: &AppState) -> ApiResult<Vec<ServerInfo>> {
    let sql = format!("SELECT {SERVER_COLUMNS} FROM servers ORDER BY id");
    let rows = sqlx::query(&sql).fetch_all(&state.pool).await?;
    rows.iter().map(server_info_from_row).collect()
}

fn server_info_from_row(row: &SqliteRow) -> ApiResult<ServerInfo> {
    let pk: String = row.get("public_key");
    let public_key = PublicKey::from_str(&pk)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("bad stored key: {e}")))?;
    let last_hb: Option<i64> = row.get("last_heartbeat");
    let healthy = match last_hb {
        None => true,
        Some(t) => db::now_unix() - t <= SERVER_STALE_SECS,
    };
    Ok(ServerInfo {
        id: row.get("id"),
        public_key,
        endpoint: row.get("endpoint"),
        country: row.get("country"),
        city: row.get("city"),
        active_peers: row.get::<i64, _>("active_peers") as u32,
        capacity: row.get::<i64, _>("capacity") as u32,
        healthy,
    })
}

// POST /v1/devices
async fn register_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterDeviceRequest>,
) -> ApiResult<Json<RegisterDeviceResponse>> {
    let account = auth_account(&state, &headers).await?;
    let resp = register_core(&state, &account, &req.public_key, &req.server_id).await?;
    Ok(Json(resp))
}

// POST /v1/devices/multihop
// Register the device on the EXIT server, ensure a relay route on the ENTRY, and return
// a connection whose key/tunnel-IP are the exit's but whose endpoint is the entry relay.
async fn register_device_multihop(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<MultihopRegisterRequest>,
) -> ApiResult<Json<RegisterDeviceResponse>> {
    let account = auth_account(&state, &headers).await?;
    if req.entry_id == req.exit_id {
        return Err(AppError::BadRequest(
            "entry and exit must be different servers".into(),
        ));
    }

    // The tunnel terminates at the exit, so the device is a peer of the exit.
    let mut resp = register_core(&state, &account, &req.public_key, &req.exit_id).await?;

    // The entry's public host, on which it relays. Reuse its stored endpoint's host.
    let entry_endpoint: String = sqlx::query_scalar("SELECT endpoint FROM servers WHERE id = ?")
        .bind(&req.entry_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no such server: {}", req.entry_id)))?;
    let entry_host = host_of(&entry_endpoint);

    // Ensure a relay route entry->exit and learn its listen port.
    let listen_port = ensure_relay(&state, &req.entry_id, &req.exit_id).await?;

    // Point the client at the entry relay instead of the exit directly.
    resp.server.endpoint = format!("{entry_host}:{listen_port}");
    Ok(Json(resp))
}

/// Core device registration on `server_id`: idempotent by public key, allocates a tunnel
/// IP, returns the connection details (with the server's own endpoint).
async fn register_core(
    state: &AppState,
    account: &str,
    public_key: &PublicKey,
    server_id: &str,
) -> ApiResult<RegisterDeviceResponse> {
    let server = sqlx::query(
        "SELECT public_key, endpoint, tunnel_cidr, tunnel_ip, dns FROM servers WHERE id = ?",
    )
    .bind(server_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("no such server: {server_id}")))?;

    let server_pk: String = server.get("public_key");
    let server_endpoint: String = server.get("endpoint");
    let tunnel_cidr: String = server.get("tunnel_cidr");
    let server_tunnel_ip: String = server.get("tunnel_ip");
    let server_dns: Option<String> = server.get("dns");
    let cidr: IpNet = tunnel_cidr
        .parse()
        .map_err(|_| AppError::Internal(anyhow::anyhow!("bad stored cidr")))?;

    let device_pk = public_key.to_base64();

    // Serialize allocation + insert so two registrations can't grab the same IP.
    let _guard = state.reg_lock.lock().await;

    // Idempotent re-registration: same pubkey already registered on this server.
    if let Some(existing) =
        sqlx::query("SELECT account_number, tunnel_ip, server_id FROM devices WHERE public_key = ?")
            .bind(&device_pk)
            .fetch_optional(&state.pool)
            .await?
    {
        let owner: String = existing.get("account_number");
        if owner != account {
            return Err(AppError::Conflict("device key already registered".into()));
        }
        let ip: String = existing.get("tunnel_ip");
        return response_for(
            ip,
            cidr,
            server_pk,
            server_endpoint,
            server_tunnel_ip,
            server_dns,
        );
    }

    // Allocate the lowest free host in the subnet.
    let used = used_ips(&state.pool, server_id).await?;
    let server_ip: IpAddr = server_tunnel_ip
        .parse()
        .map_err(|_| AppError::Internal(anyhow::anyhow!("bad stored server ip")))?;
    let assigned = ip_alloc::allocate(cidr, server_ip, &used)
        .ok_or_else(|| AppError::Conflict("server subnet exhausted".into()))?;

    sqlx::query(
        "INSERT INTO devices (account_number, public_key, server_id, tunnel_ip, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(account)
    .bind(&device_pk)
    .bind(server_id)
    .bind(assigned.to_string())
    .bind(db::now_unix())
    .execute(&state.pool)
    .await?;

    response_for(
        assigned.to_string(),
        cidr,
        server_pk,
        server_endpoint,
        server_tunnel_ip,
        server_dns,
    )
}

/// Base UDP port for relay listeners on an entry server.
const RELAY_PORT_BASE: i64 = 51900;

/// Ensure a relay route entry->exit exists; return its listen port. Allocates the next
/// free port on the entry if the route is new.
async fn ensure_relay(state: &AppState, entry_id: &str, exit_id: &str) -> ApiResult<u16> {
    let _guard = state.reg_lock.lock().await;

    if let Some(port) = sqlx::query_scalar::<_, i64>(
        "SELECT listen_port FROM relays WHERE entry_id = ? AND exit_id = ?",
    )
    .bind(entry_id)
    .bind(exit_id)
    .fetch_optional(&state.pool)
    .await?
    {
        return Ok(port as u16);
    }

    let max: Option<i64> =
        sqlx::query_scalar("SELECT MAX(listen_port) FROM relays WHERE entry_id = ?")
            .bind(entry_id)
            .fetch_one(&state.pool)
            .await?;
    let port = max.map(|m| m + 1).unwrap_or(RELAY_PORT_BASE);

    sqlx::query(
        "INSERT INTO relays (entry_id, exit_id, listen_port, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(entry_id)
    .bind(exit_id)
    .bind(port)
    .bind(db::now_unix())
    .execute(&state.pool)
    .await?;
    Ok(port as u16)
}

/// Split `host:port` (or `[v6]:port`) into just the host part.
fn host_of(endpoint: &str) -> String {
    match endpoint.rsplit_once(':') {
        Some((host, _port)) => host.trim_matches(['[', ']']).to_string(),
        None => endpoint.to_string(),
    }
}

/// Require the correct server auth token for `server_id`.
async fn auth_server(state: &AppState, server_id: &str, headers: &HeaderMap) -> ApiResult<()> {
    let token = bearer(headers).ok_or(AppError::Unauthorized)?;
    let expected: Option<String> =
        sqlx::query_scalar("SELECT auth_token FROM servers WHERE id = ?")
            .bind(server_id)
            .fetch_optional(&state.pool)
            .await?;
    match expected {
        Some(t) if t == token => Ok(()),
        _ => Err(AppError::Unauthorized),
    }
}

// GET /v1/internal/servers/:id/peers  (server-authenticated)
async fn list_peers(
    State(state): State<AppState>,
    Path(server_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<PeerListResponse>> {
    auth_server(&state, &server_id, &headers).await?;

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

// GET /v1/internal/servers/:id/relays  (server-authenticated: the entry server)
async fn list_relays(
    State(state): State<AppState>,
    Path(entry_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<RelayListResponse>> {
    auth_server(&state, &entry_id, &headers).await?;
    let rows = sqlx::query(
        "SELECT r.listen_port AS listen_port, s.endpoint AS exit_endpoint
         FROM relays r JOIN servers s ON s.id = r.exit_id
         WHERE r.entry_id = ?",
    )
    .bind(&entry_id)
    .fetch_all(&state.pool)
    .await?;
    let relays = rows
        .iter()
        .map(|row| RelayEntry {
            listen_port: row.get::<i64, _>("listen_port") as u16,
            exit_endpoint: row.get("exit_endpoint"),
        })
        .collect();
    Ok(Json(RelayListResponse { relays }))
}

// POST /v1/internal/servers/:id/heartbeat  (server-authenticated)
async fn server_heartbeat(
    State(state): State<AppState>,
    Path(server_id): Path<String>,
    headers: HeaderMap,
    Json(hb): Json<HeartbeatRequest>,
) -> ApiResult<StatusCode> {
    auth_server(&state, &server_id, &headers).await?;
    sqlx::query("UPDATE servers SET active_peers = ?, last_heartbeat = ? WHERE id = ?")
        .bind(hb.active_peers as i64)
        .bind(db::now_unix())
        .bind(&server_id)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
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
    dns: Option<String>,
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
        dns,
    })
}

/// Server metadata for registration.
pub struct NewServer<'a> {
    pub id: &'a str,
    pub public_key: &'a str,
    pub endpoint: &'a str,
    pub cidr: IpNet,
    pub country: Option<&'a str>,
    pub city: Option<&'a str>,
    pub capacity: u32,
    /// DNS server handed to clients for leak protection (e.g. the server's tunnel IP).
    pub dns: Option<&'a str>,
}

/// Insert a server row (used by the `add-server` CLI). Returns the generated auth token.
pub async fn add_server(pool: &SqlitePool, s: NewServer<'_>) -> anyhow::Result<String> {
    // The server takes the first usable host of its subnet as its own tunnel IP.
    let server_ip = s
        .cidr
        .hosts()
        .next()
        .ok_or_else(|| anyhow::anyhow!("cidr has no usable hosts"))?;
    let token = random_token();
    sqlx::query(
        "INSERT INTO servers
            (id, public_key, endpoint, tunnel_cidr, tunnel_ip, auth_token,
             country, city, capacity, active_peers, last_heartbeat, dns, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?)",
    )
    .bind(s.id)
    .bind(s.public_key)
    .bind(s.endpoint)
    .bind(s.cidr.to_string())
    .bind(server_ip.to_string())
    .bind(&token)
    .bind(s.country)
    .bind(s.city)
    .bind(s.capacity)
    .bind(s.dns)
    .bind(db::now_unix())
    .execute(pool)
    .await?;
    Ok(token)
}
