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
use tower_http::timeout::TimeoutLayer;

use oxide_common::account::{generate_account_number, is_valid_account_number};
use oxide_common::api::{
    ApiError, CreateAccountResponse, HeartbeatRequest, MeshListResponse, MeshPeer,
    MeshRegisterRequest, MeshRegisterResponse, MultihopRegisterRequest, PeerEntry,
    PeerListResponse, RegisterDeviceRequest, RegisterDeviceResponse, RelayEntry, RelayListResponse,
    ServerConnection, ServerInfo, ServerListResponse,
};
use oxide_common::PublicKey;

use db::{Db, DbRow, Val};
use error::{ApiResult, AppError};

/// A server is considered unhealthy if its last heartbeat is older than this. A server
/// that has *never* heartbeated is treated as healthy (it may not run the heartbeat
/// loop); once it starts, staleness applies.
const SERVER_STALE_SECS: i64 = 90;

/// Columns selected when building a [`ServerInfo`].
const SERVER_COLUMNS: &str =
    "id, public_key, endpoint, country, city, capacity, active_peers, last_heartbeat, pq_public_key";

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
    pub pool: Db,
    /// Fixed-window per-IP request counters.
    rate: Arc<StdMutex<HashMap<IpAddr, RateWindow>>>,
}

impl AppState {
    pub fn new(pool: Db) -> Self {
        AppState {
            pool,
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
        .route("/metrics", get(metrics))
        .route("/v1/accounts", post(create_account))
        .route("/v1/servers", get(list_servers))
        .route("/v1/servers/best", get(best_server))
        .route("/v1/devices", post(register_device))
        .route("/v1/devices/multihop", post(register_device_multihop))
        .route("/v1/mesh/register", post(mesh_register))
        .route("/v1/mesh", get(mesh_list))
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

// GET /metrics — Prometheus text format. Unauthenticated aggregate counts (no secrets);
// firewall/scrape it internally in production.
async fn metrics(State(state): State<AppState>) -> ApiResult<String> {
    render_metrics(&state.pool).await
}

/// Render the Prometheus metrics text from the database. Separated out so it's testable
/// without an HTTP round-trip.
pub async fn render_metrics(pool: &Db) -> ApiResult<String> {
    let accounts = pool
        .scalar_i64("SELECT COUNT(*) FROM accounts", &[])
        .await?;
    let servers = pool.scalar_i64("SELECT COUNT(*) FROM servers", &[]).await?;
    let devices = pool.scalar_i64("SELECT COUNT(*) FROM devices", &[]).await?;

    let mut out = String::new();
    let gauge = |out: &mut String, name: &str, help: &str, value: i64| {
        out.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n"
        ));
    };
    gauge(
        &mut out,
        "oxide_accounts_total",
        "Registered accounts.",
        accounts,
    );
    gauge(
        &mut out,
        "oxide_servers_total",
        "Registered servers.",
        servers,
    );
    gauge(
        &mut out,
        "oxide_devices_total",
        "Registered devices.",
        devices,
    );

    // Per-server live load (last heartbeat) and capacity.
    let rows = pool
        .fetch_all(
            "SELECT id, active_peers, capacity FROM servers ORDER BY id",
            &[],
        )
        .await?;
    out.push_str("# HELP oxide_server_active_peers Live peers per server (last heartbeat).\n");
    out.push_str("# TYPE oxide_server_active_peers gauge\n");
    for row in &rows {
        let id = row.text("id");
        let ap = row.int("active_peers");
        out.push_str(&format!(
            "oxide_server_active_peers{{server=\"{id}\"}} {ap}\n"
        ));
    }
    out.push_str("# HELP oxide_server_capacity Soft capacity per server (0 = unlimited).\n");
    out.push_str("# TYPE oxide_server_capacity gauge\n");
    for row in &rows {
        let id = row.text("id");
        let cap = row.int("capacity");
        out.push_str(&format!("oxide_server_capacity{{server=\"{id}\"}} {cap}\n"));
    }
    Ok(out)
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
    let exists = state
        .pool
        .scalar_opt_string(
            "SELECT number FROM accounts WHERE number = ?",
            &[Val::from(token.as_str())],
        )
        .await?;
    exists.ok_or(AppError::Unauthorized)
}

// POST /v1/accounts
async fn create_account(State(state): State<AppState>) -> ApiResult<Json<CreateAccountResponse>> {
    // Collisions are astronomically unlikely; retry a few times to be safe.
    for _ in 0..5 {
        let number = generate_account_number();
        let res = state
            .pool
            .execute(
                "INSERT INTO accounts (number, created_at) VALUES (?, ?)",
                &[Val::from(number.as_str()), Val::from(db::now_unix())],
            )
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
    let rows = state.pool.fetch_all(&sql, &[]).await?;
    rows.iter().map(server_info_from_row).collect()
}

fn server_info_from_row(row: &DbRow) -> ApiResult<ServerInfo> {
    let pk = row.text("public_key");
    let public_key = PublicKey::from_str(&pk)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("bad stored key: {e}")))?;
    let healthy = match row.opt_int("last_heartbeat") {
        // Never heartbeated → treat as healthy; otherwise apply the staleness window.
        None => true,
        Some(t) => db::now_unix() - t <= SERVER_STALE_SECS,
    };
    Ok(ServerInfo {
        id: row.text("id"),
        public_key,
        endpoint: row.text("endpoint"),
        country: row.opt_text("country"),
        city: row.opt_text("city"),
        active_peers: row.int("active_peers") as u32,
        capacity: row.int("capacity") as u32,
        healthy,
        pq_public_key: row.opt_text("pq_public_key"),
    })
}

// POST /v1/devices
async fn register_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterDeviceRequest>,
) -> ApiResult<Json<RegisterDeviceResponse>> {
    let account = auth_account(&state, &headers).await?;
    let resp = register_core(
        &state,
        &account,
        &req.public_key,
        &req.server_id,
        req.pq_ciphertext.as_deref(),
    )
    .await?;
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

    // The tunnel terminates at the exit, so the device is a peer of the exit (and PQ,
    // if present, keys to the exit).
    let mut resp = register_core(
        &state,
        &account,
        &req.public_key,
        &req.exit_id,
        req.pq_ciphertext.as_deref(),
    )
    .await?;

    // The entry's public host, on which it relays. Reuse its stored endpoint's host.
    let entry_endpoint = state
        .pool
        .scalar_opt_string(
            "SELECT endpoint FROM servers WHERE id = ?",
            &[Val::from(req.entry_id.as_str())],
        )
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
    pq_ciphertext: Option<&str>,
) -> ApiResult<RegisterDeviceResponse> {
    let server = state
        .pool
        .fetch_optional(
            "SELECT public_key, endpoint, tunnel_cidr, tunnel_ip, dns, obfuscation_key
             FROM servers WHERE id = ?",
            &[Val::from(server_id)],
        )
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no such server: {server_id}")))?;

    let server_pk = server.text("public_key");
    let server_endpoint = server.text("endpoint");
    let tunnel_cidr = server.text("tunnel_cidr");
    let server_tunnel_ip = server.text("tunnel_ip");
    let server_dns = server.opt_text("dns");
    let server_obfs = server.opt_text("obfuscation_key");
    let cidr: IpNet = tunnel_cidr
        .parse()
        .map_err(|_| AppError::Internal(anyhow::anyhow!("bad stored cidr")))?;

    let device_pk = public_key.to_base64();
    let server_ip: IpAddr = server_tunnel_ip
        .parse()
        .map_err(|_| AppError::Internal(anyhow::anyhow!("bad stored server ip")))?;

    // Concurrency-safe allocation with NO cross-node lock: re-check idempotency, allocate
    // the lowest free host, and try to insert. A UNIQUE(server_id, tunnel_ip) (and the
    // UNIQUE public_key) turn a race into a violation, which we retry — the loser re-reads
    // and either returns the winner's row (same device) or allocates the next free IP. This
    // is what lets multiple API nodes share one database.
    for _ in 0..ALLOC_RETRIES {
        // Idempotent re-registration: same pubkey already registered on this server.
        if let Some(existing) = state
            .pool
            .fetch_optional(
                "SELECT account_number, tunnel_ip, server_id FROM devices WHERE public_key = ?",
                &[Val::from(device_pk.as_str())],
            )
            .await?
        {
            let owner = existing.text("account_number");
            if owner != account {
                return Err(AppError::Conflict("device key already registered".into()));
            }
            return response_for(
                existing.text("tunnel_ip"),
                cidr,
                server_pk,
                server_endpoint,
                server_tunnel_ip,
                server_dns,
                server_obfs,
            );
        }

        let used = used_ips(&state.pool, server_id).await?;
        let assigned = ip_alloc::allocate(cidr, server_ip, &used)
            .ok_or_else(|| AppError::Conflict("server subnet exhausted".into()))?;

        match state
            .pool
            .execute(
                "INSERT INTO devices
                    (account_number, public_key, server_id, tunnel_ip, pq_ciphertext, created_at)
                 VALUES (?, ?, ?, ?, ?, ?)",
                &[
                    Val::from(account),
                    Val::from(device_pk.as_str()),
                    Val::from(server_id),
                    Val::from(assigned.to_string()),
                    Val::from(pq_ciphertext),
                    Val::from(db::now_unix()),
                ],
            )
            .await
        {
            Ok(()) => {
                return response_for(
                    assigned.to_string(),
                    cidr,
                    server_pk,
                    server_endpoint,
                    server_tunnel_ip,
                    server_dns,
                    server_obfs,
                );
            }
            // Lost the race (this IP or this pubkey was just taken): loop to re-check/re-pick.
            Err(e) if db::is_unique_violation(&e) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(AppError::Conflict(
        "could not allocate a tunnel IP under contention".into(),
    ))
}

/// Base UDP port for relay listeners on an entry server.
const RELAY_PORT_BASE: i64 = 51900;

/// How many times an allocator retries when a concurrent writer wins the race for its row
/// (a fresh candidate is computed each attempt). Comfortably above realistic contention.
const ALLOC_RETRIES: usize = 16;

/// The mesh overlay subnet (Tailscale-style CGNAT space). Devices get a stable `/32` here.
const MESH_CIDR: &str = "100.64.0.0/16";

// POST /v1/mesh/register — join the account's private mesh, get a mesh IP + the peer list.
async fn mesh_register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<MeshRegisterRequest>,
) -> ApiResult<Json<MeshRegisterResponse>> {
    let account = auth_account(&state, &headers).await?;
    let device_pk = req.public_key.to_base64();
    let cidr: IpNet = MESH_CIDR.parse().unwrap();

    // Same lock-free, retry-on-conflict allocation as device registration (mesh_ip and
    // public_key are UNIQUE), so multiple API nodes can register mesh devices concurrently.
    let mesh_ip = 'alloc: loop {
        if let Some(row) = state
            .pool
            .fetch_optional(
                "SELECT account_number, mesh_ip FROM mesh_devices WHERE public_key = ?",
                &[Val::from(device_pk.as_str())],
            )
            .await?
        {
            let owner = row.text("account_number");
            if owner != account {
                return Err(AppError::Conflict("device already in another mesh".into()));
            }
            // Refresh the reachable endpoint.
            state
                .pool
                .execute(
                    "UPDATE mesh_devices SET endpoint = ? WHERE public_key = ?",
                    &[
                        Val::from(req.endpoint.as_str()),
                        Val::from(device_pk.as_str()),
                    ],
                )
                .await?;
            break 'alloc row.text("mesh_ip");
        }

        let used = mesh_used_ips(&state.pool).await?;
        let assigned = ip_alloc::allocate(cidr, cidr.network(), &used)
            .ok_or_else(|| AppError::Conflict("mesh subnet exhausted".into()))?;
        match state
            .pool
            .execute(
                "INSERT INTO mesh_devices (account_number, public_key, mesh_ip, endpoint, created_at)
                 VALUES (?, ?, ?, ?, ?)",
                &[
                    Val::from(account.as_str()),
                    Val::from(device_pk.as_str()),
                    Val::from(assigned.to_string()),
                    Val::from(req.endpoint.as_str()),
                    Val::from(db::now_unix()),
                ],
            )
            .await
        {
            Ok(()) => break 'alloc assigned.to_string(),
            Err(e) if db::is_unique_violation(&e) => continue 'alloc,
            Err(e) => return Err(e.into()),
        }
    };

    Ok(Json(MeshRegisterResponse {
        mesh_ip: format!("{}/{}", mesh_ip, cidr.prefix_len()),
        peers: mesh_peers(&state.pool, &account).await?,
    }))
}

// GET /v1/mesh — the account's mesh peer list (poll for changes).
async fn mesh_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<MeshListResponse>> {
    let account = auth_account(&state, &headers).await?;
    Ok(Json(MeshListResponse {
        peers: mesh_peers(&state.pool, &account).await?,
    }))
}

async fn mesh_used_ips(pool: &Db) -> ApiResult<HashSet<IpAddr>> {
    let rows = pool
        .fetch_all("SELECT mesh_ip FROM mesh_devices", &[])
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| r.text("mesh_ip").parse().ok())
        .collect())
}

/// All devices in an account's mesh. The client filters out its own key.
async fn mesh_peers(pool: &Db, account: &str) -> ApiResult<Vec<MeshPeer>> {
    let rows = pool
        .fetch_all(
            "SELECT public_key, mesh_ip, endpoint FROM mesh_devices WHERE account_number = ?",
            &[Val::from(account)],
        )
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let pk = row.text("public_key");
            Some(MeshPeer {
                public_key: PublicKey::from_str(&pk).ok()?,
                mesh_ip: row.text("mesh_ip"),
                endpoint: row.text("endpoint"),
            })
        })
        .collect())
}

/// Ensure a relay route entry->exit exists; return its listen port. Allocates the next
/// free port on the entry if the route is new.
async fn ensure_relay(state: &AppState, entry_id: &str, exit_id: &str) -> ApiResult<u16> {
    // Lock-free with retry: UNIQUE(entry_id, exit_id) makes a duplicate route idempotent, and
    // UNIQUE(entry_id, listen_port) prevents two concurrent routes grabbing the same port —
    // a violation just means re-read (existing route) or re-pick the next free port.
    for _ in 0..ALLOC_RETRIES {
        if let Some(port) = state
            .pool
            .scalar_opt_i64(
                "SELECT listen_port FROM relays WHERE entry_id = ? AND exit_id = ?",
                &[Val::from(entry_id), Val::from(exit_id)],
            )
            .await?
        {
            return Ok(port as u16);
        }

        let max = state
            .pool
            .scalar_nullable_i64(
                "SELECT MAX(listen_port) FROM relays WHERE entry_id = ?",
                &[Val::from(entry_id)],
            )
            .await?;
        let port = max.map(|m| m + 1).unwrap_or(RELAY_PORT_BASE);

        match state
            .pool
            .execute(
                "INSERT INTO relays (entry_id, exit_id, listen_port, created_at) VALUES (?, ?, ?, ?)",
                &[
                    Val::from(entry_id),
                    Val::from(exit_id),
                    Val::from(port),
                    Val::from(db::now_unix()),
                ],
            )
            .await
        {
            Ok(()) => return Ok(port as u16),
            Err(e) if db::is_unique_violation(&e) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(AppError::Conflict(
        "could not allocate a relay port under contention".into(),
    ))
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
    let expected = state
        .pool
        .scalar_opt_string(
            "SELECT auth_token FROM servers WHERE id = ?",
            &[Val::from(server_id)],
        )
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

    let rows = state
        .pool
        .fetch_all(
            "SELECT public_key, tunnel_ip, pq_ciphertext FROM devices WHERE server_id = ?",
            &[Val::from(server_id.as_str())],
        )
        .await?;
    let peers = rows
        .into_iter()
        .map(|row| {
            let pk = row.text("public_key");
            let ip = row.text("tunnel_ip");
            PeerEntry {
                public_key: PublicKey::from_str(&pk).expect("stored key valid"),
                allowed_ips: vec![format!("{ip}/32")],
                pq_ciphertext: row.opt_text("pq_ciphertext"),
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
    let rows = state
        .pool
        .fetch_all(
            "SELECT r.listen_port AS listen_port, s.endpoint AS exit_endpoint
             FROM relays r JOIN servers s ON s.id = r.exit_id
             WHERE r.entry_id = ?",
            &[Val::from(entry_id.as_str())],
        )
        .await?;
    let relays = rows
        .iter()
        .map(|row| RelayEntry {
            listen_port: row.int("listen_port") as u16,
            exit_endpoint: row.text("exit_endpoint"),
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
    state
        .pool
        .execute(
            "UPDATE servers SET active_peers = ?, last_heartbeat = ? WHERE id = ?",
            &[
                Val::from(hb.active_peers as i64),
                Val::from(db::now_unix()),
                Val::from(server_id.as_str()),
            ],
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn used_ips(pool: &Db, server_id: &str) -> ApiResult<HashSet<IpAddr>> {
    let rows = pool
        .fetch_all(
            "SELECT tunnel_ip FROM devices WHERE server_id = ?",
            &[Val::from(server_id)],
        )
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| r.text("tunnel_ip").parse().ok())
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn response_for(
    assigned_ip: String,
    cidr: IpNet,
    server_pk: String,
    server_endpoint: String,
    server_tunnel_ip: String,
    dns: Option<String>,
    obfuscation_key: Option<String>,
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
        obfuscation_key,
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
    /// Stealth-mode obfuscation key (base64) this server expects; handed to clients.
    pub obfuscation_key: Option<&'a str>,
    /// Post-quantum public (ML-KEM) key (base64) this server runs; handed to clients.
    pub pq_public_key: Option<&'a str>,
}

/// Insert a server row (used by the `add-server` CLI). Returns the generated auth token.
pub async fn add_server(pool: &Db, s: NewServer<'_>) -> anyhow::Result<String> {
    // The server takes the first usable host of its subnet as its own tunnel IP.
    let server_ip = s
        .cidr
        .hosts()
        .next()
        .ok_or_else(|| anyhow::anyhow!("cidr has no usable hosts"))?;
    let token = random_token();
    pool.execute(
        "INSERT INTO servers
            (id, public_key, endpoint, tunnel_cidr, tunnel_ip, auth_token, country, city,
             capacity, active_peers, last_heartbeat, dns, obfuscation_key, pq_public_key, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, ?, ?)",
        &[
            Val::from(s.id),
            Val::from(s.public_key),
            Val::from(s.endpoint),
            Val::from(s.cidr.to_string()),
            Val::from(server_ip.to_string()),
            Val::from(token.as_str()),
            Val::from(s.country),
            Val::from(s.city),
            Val::from(s.capacity as i64),
            Val::from(s.dns),
            Val::from(s.obfuscation_key),
            Val::from(s.pq_public_key),
            Val::from(db::now_unix()),
        ],
    )
    .await?;
    Ok(token)
}
