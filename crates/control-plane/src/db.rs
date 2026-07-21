//! SQLite storage for the control plane.
//!
//! SQLite is the v0 backend: zero-infra, single-node, easy to run and test. The schema
//! is applied at startup with `CREATE TABLE IF NOT EXISTS` (no migration tooling yet).
//! All access goes through sqlx runtime queries, so moving to Postgres for a multi-node
//! fleet (M6) is a connection-string + dialect change, not a rewrite.
//!
//! No-logs note: we store only what's needed to route — account numbers, device public
//! keys, and IP assignments. No traffic, no timestamps beyond creation, no PII.

use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;

pub async fn connect(database_url: &str) -> Result<SqlitePool> {
    // Accept either a bare path or a `sqlite:` URL; create the file if missing.
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
    init_schema(&pool).await?;
    Ok(pool)
}

async fn init_schema(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS accounts (
            number     TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS servers (
            id          TEXT PRIMARY KEY,
            public_key  TEXT NOT NULL,
            endpoint    TEXT NOT NULL,
            tunnel_cidr TEXT NOT NULL,
            tunnel_ip   TEXT NOT NULL,
            auth_token  TEXT NOT NULL,
            created_at  INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS devices (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            account_number TEXT NOT NULL REFERENCES accounts(number),
            public_key     TEXT NOT NULL UNIQUE,
            server_id      TEXT NOT NULL REFERENCES servers(id),
            tunnel_ip      TEXT NOT NULL,
            created_at     INTEGER NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await
    .context("initializing schema")?;
    Ok(())
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
