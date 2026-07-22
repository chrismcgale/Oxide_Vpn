//! Storage for the control plane — SQLite (default, zero-infra) or Postgres (multi-node).
//!
//! sqlx is compile-time DB-typed, so we abstract over the two backends with a small dialect
//! layer instead of a generic-over-`Database` soup (which fights sqlx's trait bounds):
//!
//!   * [`Db`] wraps the concrete pool (`SqlitePool` | `PgPool`);
//!   * [`DbRow`] wraps a fetched row and exposes typed getters that dispatch `try_get`
//!     (which is implemented for both `SqliteRow` and `PgRow`);
//!   * [`Val`] is a bind parameter; the query methods rewrite `?` placeholders to `$n` for
//!     Postgres and run the branch with the concrete pool.
//!
//! All application code goes through [`Db`]'s methods and [`DbRow`]'s getters, so the SQL is
//! written once (SQLite `?` style) and the schema DDL is the only place that branches.
//!
//! No-logs note: we store only what's needed to route — account numbers, device public
//! keys, and IP assignments. No traffic, no timestamps beyond creation, no PII.

use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use sqlx::postgres::{PgPoolOptions, PgRow};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow};
use sqlx::{PgPool, Row, SqlitePool};

/// A bind parameter for a query, backend-agnostic.
#[derive(Debug, Clone)]
pub enum Val {
    Text(String),
    OptText(Option<String>),
    Int(i64),
}

impl From<&str> for Val {
    fn from(s: &str) -> Self {
        Val::Text(s.to_string())
    }
}
impl From<String> for Val {
    fn from(s: String) -> Self {
        Val::Text(s)
    }
}
impl From<Option<&str>> for Val {
    fn from(s: Option<&str>) -> Self {
        Val::OptText(s.map(str::to_string))
    }
}
impl From<Option<String>> for Val {
    fn from(s: Option<String>) -> Self {
        Val::OptText(s)
    }
}
impl From<i64> for Val {
    fn from(i: i64) -> Self {
        Val::Int(i)
    }
}

/// Bind every [`Val`] in `$params` onto `$q` (works for either backend's query type).
macro_rules! bind_all {
    ($q:expr, $params:expr) => {{
        let mut q = $q;
        for v in $params {
            q = match v {
                Val::Text(s) => q.bind(s.as_str()),
                Val::OptText(o) => q.bind(o.as_deref()),
                Val::Int(i) => q.bind(*i),
            };
        }
        q
    }};
}

/// Rewrite `?` placeholders into Postgres `$1`, `$2`, … (our SQL never contains a literal
/// `?`, so a straight scan is safe).
fn pg_sql(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len() + 8);
    let mut n = 0;
    for c in sql.chars() {
        if c == '?' {
            n += 1;
            out.push('$');
            out.push_str(&n.to_string());
        } else {
            out.push(c);
        }
    }
    out
}

/// A fetched row from either backend, with typed getters. Missing/mistyped columns yield a
/// default (required getters) or `None` (optional getters) rather than panicking.
pub enum DbRow {
    Sqlite(SqliteRow),
    Postgres(PgRow),
}

impl DbRow {
    pub fn text(&self, col: &str) -> String {
        match self {
            DbRow::Sqlite(r) => r.try_get(col).unwrap_or_default(),
            DbRow::Postgres(r) => r.try_get(col).unwrap_or_default(),
        }
    }
    pub fn opt_text(&self, col: &str) -> Option<String> {
        match self {
            DbRow::Sqlite(r) => r.try_get(col).ok(),
            DbRow::Postgres(r) => r.try_get(col).ok(),
        }
    }
    pub fn int(&self, col: &str) -> i64 {
        match self {
            DbRow::Sqlite(r) => r.try_get(col).unwrap_or_default(),
            DbRow::Postgres(r) => r.try_get(col).unwrap_or_default(),
        }
    }
    pub fn opt_int(&self, col: &str) -> Option<i64> {
        match self {
            DbRow::Sqlite(r) => r.try_get::<Option<i64>, _>(col).ok().flatten(),
            DbRow::Postgres(r) => r.try_get::<Option<i64>, _>(col).ok().flatten(),
        }
    }
}

/// The control-plane database: a concrete SQLite or Postgres pool behind a dialect layer.
#[derive(Clone)]
pub enum Db {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

impl Db {
    /// Run a statement (INSERT/UPDATE). Returns the raw `sqlx::Error` so callers can inspect
    /// e.g. `is_unique_violation()` (which works for both backends).
    pub async fn execute(&self, sql: &str, params: &[Val]) -> std::result::Result<(), sqlx::Error> {
        match self {
            Db::Sqlite(p) => {
                bind_all!(sqlx::query(sql), params).execute(p).await?;
            }
            Db::Postgres(p) => {
                let sql = pg_sql(sql);
                bind_all!(sqlx::query(&sql), params).execute(p).await?;
            }
        }
        Ok(())
    }

    /// Fetch at most one row.
    pub async fn fetch_optional(
        &self,
        sql: &str,
        params: &[Val],
    ) -> std::result::Result<Option<DbRow>, sqlx::Error> {
        Ok(match self {
            Db::Sqlite(p) => bind_all!(sqlx::query(sql), params)
                .fetch_optional(p)
                .await?
                .map(DbRow::Sqlite),
            Db::Postgres(p) => {
                let sql = pg_sql(sql);
                bind_all!(sqlx::query(&sql), params)
                    .fetch_optional(p)
                    .await?
                    .map(DbRow::Postgres)
            }
        })
    }

    /// Fetch all matching rows.
    pub async fn fetch_all(
        &self,
        sql: &str,
        params: &[Val],
    ) -> std::result::Result<Vec<DbRow>, sqlx::Error> {
        Ok(match self {
            Db::Sqlite(p) => bind_all!(sqlx::query(sql), params)
                .fetch_all(p)
                .await?
                .into_iter()
                .map(DbRow::Sqlite)
                .collect(),
            Db::Postgres(p) => {
                let sql = pg_sql(sql);
                bind_all!(sqlx::query(&sql), params)
                    .fetch_all(p)
                    .await?
                    .into_iter()
                    .map(DbRow::Postgres)
                    .collect()
            }
        })
    }

    /// A single non-null `i64` (e.g. `COUNT(*)`).
    pub async fn scalar_i64(
        &self,
        sql: &str,
        params: &[Val],
    ) -> std::result::Result<i64, sqlx::Error> {
        Ok(match self {
            Db::Sqlite(p) => {
                bind_all!(sqlx::query_scalar(sql), params)
                    .fetch_one(p)
                    .await?
            }
            Db::Postgres(p) => {
                let sql = pg_sql(sql);
                bind_all!(sqlx::query_scalar(&sql), params)
                    .fetch_one(p)
                    .await?
            }
        })
    }

    /// A single row whose scalar value may be NULL (e.g. `MAX(col)` over no rows).
    pub async fn scalar_nullable_i64(
        &self,
        sql: &str,
        params: &[Val],
    ) -> std::result::Result<Option<i64>, sqlx::Error> {
        Ok(match self {
            Db::Sqlite(p) => {
                bind_all!(sqlx::query_scalar::<_, Option<i64>>(sql), params)
                    .fetch_one(p)
                    .await?
            }
            Db::Postgres(p) => {
                let sql = pg_sql(sql);
                bind_all!(sqlx::query_scalar::<_, Option<i64>>(&sql), params)
                    .fetch_one(p)
                    .await?
            }
        })
    }

    /// An `i64` scalar from a row that may not exist.
    pub async fn scalar_opt_i64(
        &self,
        sql: &str,
        params: &[Val],
    ) -> std::result::Result<Option<i64>, sqlx::Error> {
        Ok(match self {
            Db::Sqlite(p) => {
                bind_all!(sqlx::query_scalar::<_, i64>(sql), params)
                    .fetch_optional(p)
                    .await?
            }
            Db::Postgres(p) => {
                let sql = pg_sql(sql);
                bind_all!(sqlx::query_scalar::<_, i64>(&sql), params)
                    .fetch_optional(p)
                    .await?
            }
        })
    }

    /// A `String` scalar from a row that may not exist.
    pub async fn scalar_opt_string(
        &self,
        sql: &str,
        params: &[Val],
    ) -> std::result::Result<Option<String>, sqlx::Error> {
        Ok(match self {
            Db::Sqlite(p) => {
                bind_all!(sqlx::query_scalar::<_, String>(sql), params)
                    .fetch_optional(p)
                    .await?
            }
            Db::Postgres(p) => {
                let sql = pg_sql(sql);
                bind_all!(sqlx::query_scalar::<_, String>(&sql), params)
                    .fetch_optional(p)
                    .await?
            }
        })
    }
}

/// Open the control-plane database and apply its schema. A `postgres://` (or `postgresql://`)
/// URL opens Postgres; anything else is treated as a SQLite path/URL (created if missing).
pub async fn connect(database_url: &str) -> Result<Db> {
    if database_url.starts_with("postgres://") || database_url.starts_with("postgresql://") {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
            .context("opening postgres database")?;
        init_schema_pg(&pool).await?;
        Ok(Db::Postgres(pool))
    } else {
        let path = database_url
            .strip_prefix("sqlite://")
            .or_else(|| database_url.strip_prefix("sqlite:"))
            .unwrap_or(database_url);
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{path}"))
            .context("parsing sqlite url")?
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await
            .context("opening sqlite database")?;
        init_schema_sqlite(&pool).await?;
        Ok(Db::Sqlite(pool))
    }
}

async fn init_schema_sqlite(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS accounts (
            number     TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS servers (
            id             TEXT PRIMARY KEY,
            public_key     TEXT NOT NULL,
            endpoint       TEXT NOT NULL,
            tunnel_cidr    TEXT NOT NULL,
            tunnel_ip      TEXT NOT NULL,
            auth_token     TEXT NOT NULL,
            country        TEXT,
            city           TEXT,
            capacity       INTEGER NOT NULL DEFAULT 0,
            active_peers   INTEGER NOT NULL DEFAULT 0,
            last_heartbeat INTEGER,
            dns            TEXT,
            obfuscation_key TEXT,
            pq_public_key  TEXT,
            created_at     INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS devices (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            account_number TEXT NOT NULL REFERENCES accounts(number),
            public_key     TEXT NOT NULL UNIQUE,
            server_id      TEXT NOT NULL REFERENCES servers(id),
            tunnel_ip      TEXT NOT NULL,
            pq_ciphertext  TEXT,
            created_at     INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS mesh_devices (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            account_number TEXT NOT NULL REFERENCES accounts(number),
            public_key     TEXT NOT NULL UNIQUE,
            mesh_ip        TEXT NOT NULL UNIQUE,
            endpoint       TEXT NOT NULL,
            created_at     INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS relays (
            entry_id    TEXT NOT NULL REFERENCES servers(id),
            exit_id     TEXT NOT NULL REFERENCES servers(id),
            listen_port INTEGER NOT NULL,
            created_at  INTEGER NOT NULL,
            PRIMARY KEY (entry_id, exit_id)
        );
        "#,
    )
    .execute(pool)
    .await
    .context("initializing sqlite schema")?;

    // Idempotent migrations for databases created before the M3 server columns. SQLite has
    // no "ADD COLUMN IF NOT EXISTS", so we run each and ignore the "duplicate column" error.
    for stmt in [
        "ALTER TABLE servers ADD COLUMN country TEXT",
        "ALTER TABLE servers ADD COLUMN city TEXT",
        "ALTER TABLE servers ADD COLUMN capacity INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE servers ADD COLUMN active_peers INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE servers ADD COLUMN last_heartbeat INTEGER",
        "ALTER TABLE servers ADD COLUMN dns TEXT",
        "ALTER TABLE servers ADD COLUMN obfuscation_key TEXT",
        "ALTER TABLE servers ADD COLUMN pq_public_key TEXT",
        "ALTER TABLE devices ADD COLUMN pq_ciphertext TEXT",
    ] {
        let _ = sqlx::query(stmt).execute(pool).await;
    }
    Ok(())
}

async fn init_schema_pg(pool: &PgPool) -> Result<()> {
    // Postgres uses BIGINT (so `try_get::<i64>` decodes) and BIGSERIAL for autoincrement.
    // Each statement runs separately (the extended protocol is one-statement-per-query).
    let statements = [
        r#"CREATE TABLE IF NOT EXISTS accounts (
            number     TEXT PRIMARY KEY,
            created_at BIGINT NOT NULL
        )"#,
        r#"CREATE TABLE IF NOT EXISTS servers (
            id             TEXT PRIMARY KEY,
            public_key     TEXT NOT NULL,
            endpoint       TEXT NOT NULL,
            tunnel_cidr    TEXT NOT NULL,
            tunnel_ip      TEXT NOT NULL,
            auth_token     TEXT NOT NULL,
            country        TEXT,
            city           TEXT,
            capacity       BIGINT NOT NULL DEFAULT 0,
            active_peers   BIGINT NOT NULL DEFAULT 0,
            last_heartbeat BIGINT,
            dns            TEXT,
            obfuscation_key TEXT,
            pq_public_key  TEXT,
            created_at     BIGINT NOT NULL
        )"#,
        r#"CREATE TABLE IF NOT EXISTS devices (
            id             BIGSERIAL PRIMARY KEY,
            account_number TEXT NOT NULL REFERENCES accounts(number),
            public_key     TEXT NOT NULL UNIQUE,
            server_id      TEXT NOT NULL REFERENCES servers(id),
            tunnel_ip      TEXT NOT NULL,
            pq_ciphertext  TEXT,
            created_at     BIGINT NOT NULL
        )"#,
        r#"CREATE TABLE IF NOT EXISTS mesh_devices (
            id             BIGSERIAL PRIMARY KEY,
            account_number TEXT NOT NULL REFERENCES accounts(number),
            public_key     TEXT NOT NULL UNIQUE,
            mesh_ip        TEXT NOT NULL UNIQUE,
            endpoint       TEXT NOT NULL,
            created_at     BIGINT NOT NULL
        )"#,
        r#"CREATE TABLE IF NOT EXISTS relays (
            entry_id    TEXT NOT NULL REFERENCES servers(id),
            exit_id     TEXT NOT NULL REFERENCES servers(id),
            listen_port BIGINT NOT NULL,
            created_at  BIGINT NOT NULL,
            PRIMARY KEY (entry_id, exit_id)
        )"#,
    ];
    for stmt in statements {
        sqlx::query(stmt)
            .execute(pool)
            .await
            .context("initializing postgres schema")?;
    }
    Ok(())
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
