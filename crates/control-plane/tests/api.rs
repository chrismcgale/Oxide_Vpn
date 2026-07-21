//! End-to-end control-plane API test: mount the real router on an ephemeral port and
//! drive it through the actual `ControlClient` HTTP path. No root, no external infra.

use std::sync::atomic::{AtomicU32, Ordering};

use oxide_common::account::is_valid_account_number;
use oxide_common::keys::{generate_secret, public_from_secret};
use oxide_control_client::ControlClient;
use oxide_control_plane::{add_server, app, db, AppState, NewServer};

fn temp_db_path() -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!("oxide-cp-test-{}-{}.db", std::process::id(), n));
    let _ = std::fs::remove_file(&p);
    p.to_string_lossy().into_owned()
}

#[tokio::test]
async fn full_account_device_flow() {
    // Seed a server directly, then serve the API.
    let pool = db::connect(&temp_db_path()).await.unwrap();
    let server_pub = public_from_secret(&generate_secret()).to_base64();
    let token = add_server(
        &pool,
        NewServer {
            id: "us-nyc-1",
            public_key: &server_pub,
            endpoint: "203.0.113.7:51820",
            cidr: "10.8.0.0/24".parse().unwrap(),
            country: Some("US"),
            city: Some("New York"),
            capacity: 100,
        },
    )
    .await
    .unwrap();

    let state = AppState::new(pool.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });

    let cc = ControlClient::new(&format!("http://{addr}"));

    // Create an anonymous account.
    let account = cc.create_account().await.unwrap();
    assert!(is_valid_account_number(&account));

    // List servers (authenticated).
    let servers = cc.list_servers(&account).await.unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].id, "us-nyc-1");
    assert_eq!(servers[0].endpoint, "203.0.113.7:51820");
    assert_eq!(servers[0].public_key.to_base64(), server_pub);

    // Register a device: first free host is .2 (.1 is the server).
    let dev1 = public_from_secret(&generate_secret());
    let reg = cc.register_device(&account, dev1, "us-nyc-1").await.unwrap();
    assert_eq!(reg.assigned_ip, "10.8.0.2/24");
    assert_eq!(reg.server.tunnel_ip, "10.8.0.1");
    assert_eq!(reg.server.public_key.to_base64(), server_pub);

    // Re-registering the same device is idempotent (same IP).
    let reg_again = cc.register_device(&account, dev1, "us-nyc-1").await.unwrap();
    assert_eq!(reg_again.assigned_ip, "10.8.0.2/24");

    // A second device gets the next IP.
    let dev2 = public_from_secret(&generate_secret());
    let reg2 = cc.register_device(&account, dev2, "us-nyc-1").await.unwrap();
    assert_eq!(reg2.assigned_ip, "10.8.0.3/24");

    // The server fetches its peer list with its token: both devices present.
    let peers = cc.fetch_peers("us-nyc-1", &token).await.unwrap();
    assert_eq!(peers.len(), 2);
    let allowed: Vec<String> = peers.iter().flat_map(|p| p.allowed_ips.clone()).collect();
    assert!(allowed.contains(&"10.8.0.2/32".to_string()));
    assert!(allowed.contains(&"10.8.0.3/32".to_string()));
}

#[tokio::test]
async fn auth_is_enforced() {
    let pool = db::connect(&temp_db_path()).await.unwrap();
    let server_pub = public_from_secret(&generate_secret()).to_base64();
    let token = add_server(
        &pool,
        NewServer {
            id: "eu-1",
            public_key: &server_pub,
            endpoint: "198.51.100.5:51820",
            cidr: "10.9.0.0/24".parse().unwrap(),
            country: Some("DE"),
            city: None,
            capacity: 0,
        },
    )
    .await
    .unwrap();

    let state = AppState::new(pool.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });
    let cc = ControlClient::new(&format!("http://{addr}"));

    // Unknown account can't list servers.
    assert!(cc.list_servers("0000000000000000").await.is_err());

    // Wrong server token can't fetch peers; the right one can.
    assert!(cc.fetch_peers("eu-1", "not-the-token").await.is_err());
    assert!(cc.fetch_peers("eu-1", &token).await.is_ok());
}

#[tokio::test]
async fn best_server_selection_balances_by_load_and_location() {
    let pool = db::connect(&temp_db_path()).await.unwrap();
    let pk = |()| public_from_secret(&generate_secret()).to_base64();

    // Two US servers and one DE server, each with capacity 100.
    let mut tokens = std::collections::HashMap::new();
    for (id, country) in [("us-a", "US"), ("us-b", "US"), ("de-a", "DE")] {
        let t = add_server(
            &pool,
            NewServer {
                id,
                public_key: &pk(()),
                endpoint: "203.0.113.1:51820",
                cidr: "10.8.0.0/24".parse().unwrap(),
                country: Some(country),
                city: None,
                capacity: 100,
            },
        )
        .await
        .unwrap();
        tokens.insert(id, t);
    }

    let state = AppState::new(pool.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });
    let cc = ControlClient::new(&format!("http://{addr}"));
    let account = cc.create_account().await.unwrap();

    // Report load: us-a heavy, us-b light, de-a lightest.
    cc.heartbeat("us-a", &tokens["us-a"], 50).await.unwrap();
    cc.heartbeat("us-b", &tokens["us-b"], 10).await.unwrap();
    cc.heartbeat("de-a", &tokens["de-a"], 5).await.unwrap();

    // Global best = lowest load factor = de-a.
    let best = cc.best_server(&account, None, None).await.unwrap();
    assert_eq!(best.id, "de-a");
    assert_eq!(best.active_peers, 5);
    assert!(best.healthy);

    // Best in the US = us-b (10 < 50).
    let best_us = cc.best_server(&account, Some("US"), None).await.unwrap();
    assert_eq!(best_us.id, "us-b");

    // A new heartbeat shifts the balance: now us-b is heavier than us-a.
    cc.heartbeat("us-b", &tokens["us-b"], 90).await.unwrap();
    let best_us = cc.best_server(&account, Some("us"), None).await.unwrap(); // case-insensitive
    assert_eq!(best_us.id, "us-a");

    // No server in the requested country -> error.
    assert!(cc.best_server(&account, Some("FR"), None).await.is_err());

    // The enriched server list carries location + load.
    let servers = cc.list_servers(&account).await.unwrap();
    assert_eq!(servers.len(), 3);
    let de = servers.iter().find(|s| s.id == "de-a").unwrap();
    assert_eq!(de.country.as_deref(), Some("DE"));
    assert_eq!(de.capacity, 100);
}
