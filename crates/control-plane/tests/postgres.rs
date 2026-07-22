//! Postgres backend verification. The same account/device flow as `api.rs`, but driven
//! against a live Postgres instead of SQLite — this is what proves the dialect layer
//! (placeholders, BIGINT types, BIGSERIAL, schema DDL) actually works on Postgres.
//!
//! Gated on `OXIDE_TEST_PG_URL` so CI without Postgres skips it cleanly. Run locally with:
//!   OXIDE_TEST_PG_URL='postgres:///oxide_cp?host=/run/postgresql' \
//!     cargo test -p oxide-control-plane --test postgres -- --nocapture
//!
//! Uses a unique server id per run, so it's safe to re-run against a shared dev database.

use std::sync::atomic::{AtomicU32, Ordering};

use oxide_common::account::is_valid_account_number;
use oxide_common::keys::{generate_secret, public_from_secret};
use oxide_control_client::ControlClient;
use oxide_control_plane::{add_server, app, db, render_metrics, AppState, NewServer};

#[tokio::test]
async fn full_flow_on_postgres() {
    let Ok(url) = std::env::var("OXIDE_TEST_PG_URL") else {
        eprintln!("skipping: set OXIDE_TEST_PG_URL to run the Postgres backend test");
        return;
    };

    static N: AtomicU32 = AtomicU32::new(0);
    let uniq = format!(
        "{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    );
    let server_id = format!("pg-test-{uniq}");

    // connect() detects the postgres:// URL and applies the Postgres schema.
    let pool = db::connect(&url).await.expect("connect to postgres");

    let server_pub = public_from_secret(&generate_secret()).to_base64();
    add_server(
        &pool,
        NewServer {
            id: &server_id,
            public_key: &server_pub,
            endpoint: "203.0.113.9:51820",
            cidr: "10.9.0.0/24".parse().unwrap(),
            country: Some("US"),
            city: Some("Chicago"),
            capacity: 50,
            dns: Some("10.9.0.1"),
            obfuscation_key: Some("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="),
            pq_public_key: None,
        },
    )
    .await
    .expect("add_server on postgres");

    let state = AppState::new(pool.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });

    let cc = ControlClient::new(&format!("http://{addr}"));

    // Account (INSERT + unique-violation retry path) and auth (SELECT scalar).
    let account = cc.create_account().await.unwrap();
    assert!(is_valid_account_number(&account));

    // Our server is present (SELECT of the SERVER_COLUMNS row, BIGINT capacity/active_peers).
    let servers = cc.list_servers(&account).await.unwrap();
    let ours = servers
        .iter()
        .find(|s| s.id == server_id)
        .expect("our server listed");
    assert_eq!(ours.endpoint, "203.0.113.9:51820");
    assert_eq!(ours.capacity, 50);
    assert!(ours.healthy); // never heartbeated -> healthy

    // Register a device: first free host in this server's subnet is .2 (.1 is the server).
    let dev = public_from_secret(&generate_secret());
    let reg = cc
        .register_device(&account, dev, &server_id, None)
        .await
        .unwrap();
    assert_eq!(reg.assigned_ip, "10.9.0.2/24");
    assert_eq!(reg.server.tunnel_ip, "10.9.0.1");
    assert_eq!(
        reg.obfuscation_key.as_deref(),
        Some("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
    );

    // Idempotent re-registration returns the same IP (device-exists SELECT path).
    let reg2 = cc
        .register_device(&account, dev, &server_id, None)
        .await
        .unwrap();
    assert_eq!(reg2.assigned_ip, "10.9.0.2/24");

    // Metrics (COUNT scalars + per-server rows) render against Postgres too.
    let metrics = render_metrics(&pool).await.unwrap();
    assert!(metrics.contains("oxide_accounts_total"));
    assert!(metrics.contains(&format!(
        "oxide_server_capacity{{server=\"{server_id}\"}} 50"
    )));
}
