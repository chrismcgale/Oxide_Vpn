//! End-to-end control-plane API test: mount the real router on an ephemeral port and
//! drive it through the actual `ControlClient` HTTP path. No root, no external infra.

use std::sync::atomic::{AtomicU32, Ordering};

use oxide_common::account::is_valid_account_number;
use oxide_common::keys::{generate_secret, public_from_secret};
use oxide_control_client::ControlClient;
use oxide_control_plane::{add_server, app, db, serve, AppState, NewServer};

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
            dns: Some("10.8.0.1"),
            obfuscation_key: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            pq_public_key: None,
            transport: None,
            daita: false,
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
    let reg = cc
        .register_device(&account, dev1, "us-nyc-1", None)
        .await
        .unwrap();
    assert_eq!(reg.assigned_ip, "10.8.0.2/24");
    assert_eq!(reg.server.tunnel_ip, "10.8.0.1");
    assert_eq!(reg.server.public_key.to_base64(), server_pub);
    assert_eq!(reg.dns.as_deref(), Some("10.8.0.1")); // DNS handed out for leak protection
    assert_eq!(
        reg.obfuscation_key.as_deref(),
        Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    ); // stealth key handed out

    // Re-registering the same device is idempotent (same IP).
    let reg_again = cc
        .register_device(&account, dev1, "us-nyc-1", None)
        .await
        .unwrap();
    assert_eq!(reg_again.assigned_ip, "10.8.0.2/24");

    // A second device gets the next IP.
    let dev2 = public_from_secret(&generate_secret());
    let reg2 = cc
        .register_device(&account, dev2, "us-nyc-1", None)
        .await
        .unwrap();
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
            dns: None,
            obfuscation_key: None,
            pq_public_key: None,
            transport: None,
            daita: false,
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
                dns: None,
                obfuscation_key: None,
                pq_public_key: None,
                transport: None,
                daita: false,
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

    // Multihop registration: the connection is exit-keyed but points at the entry relay,
    // and the entry server sees a relay route to the exit.
    let device = public_from_secret(&generate_secret());
    let mh = cc
        .register_device_multihop(&account, device, "us-a", "de-a", None)
        .await
        .unwrap();
    // Exit is de-a: its subnet is 10.9.0.0/24, so the assigned IP is in it.
    // (us-a/us-b/de-a were all created with 10.8.0.0/24 above — same subnet here.)
    assert!(mh.assigned_ip.ends_with("/24"));
    // Endpoint host is the entry (us-a) with a relay port in the 519xx range.
    let mh_ep: std::net::SocketAddr = mh.server.endpoint.parse().unwrap();
    assert!(mh_ep.port() >= 51900);
    // The entry server's relay list now contains a route (with the exit's endpoint).
    let relays = cc.fetch_relays("us-a", &tokens["us-a"]).await.unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].listen_port, mh_ep.port());

    // entry == exit is rejected.
    let d2 = public_from_secret(&generate_secret());
    assert!(cc
        .register_device_multihop(&account, d2, "us-a", "us-a", None)
        .await
        .is_err());

    // The enriched server list carries location + load.
    let servers = cc.list_servers(&account).await.unwrap();
    assert_eq!(servers.len(), 3);
    let de = servers.iter().find(|s| s.id == "de-a").unwrap();
    assert_eq!(de.country.as_deref(), Some("DE"));
    assert_eq!(de.capacity, 100);
}

#[tokio::test]
async fn per_ip_rate_limit_kicks_in() {
    // Serve via `serve()` so connect-info (and thus the per-IP limiter) is active.
    let pool = db::connect(&temp_db_path()).await.unwrap();
    let state = AppState::new(pool);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { serve(listener, state).await.unwrap() });

    // Hammer account creation from one IP; within the window it must eventually be
    // rejected. ControlClient surfaces the 429 as an error carrying the status.
    let cc = ControlClient::new(&format!("http://{addr}"));
    let mut saw_limit = false;
    for _ in 0..80 {
        if let Err(e) = cc.create_account().await {
            if e.to_string().contains("429") {
                saw_limit = true;
                break;
            }
        }
    }
    assert!(
        saw_limit,
        "expected a 429 after exceeding the per-IP rate limit"
    );
}

#[tokio::test]
async fn metrics_report_counts_and_load() {
    use oxide_control_plane::render_metrics;
    let pool = db::connect(&temp_db_path()).await.unwrap();
    let server_pub = public_from_secret(&generate_secret()).to_base64();
    add_server(
        &pool,
        NewServer {
            id: "m-1",
            public_key: &server_pub,
            endpoint: "203.0.113.9:51820",
            cidr: "10.8.0.0/24".parse().unwrap(),
            country: Some("US"),
            city: None,
            capacity: 250,
            dns: None,
            obfuscation_key: None,
            pq_public_key: None,
            transport: None,
            daita: false,
        },
    )
    .await
    .unwrap();

    let state = AppState::new(pool.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { serve(listener, state).await.unwrap() });
    let cc = ControlClient::new(&format!("http://{addr}"));

    // Seed some state: one account + one device.
    let account = cc.create_account().await.unwrap();
    let dev = public_from_secret(&generate_secret());
    cc.register_device(&account, dev, "m-1", None)
        .await
        .unwrap();

    let text = render_metrics(&pool).await.unwrap();
    assert!(text.contains("oxide_accounts_total 1"));
    assert!(text.contains("oxide_servers_total 1"));
    assert!(text.contains("oxide_devices_total 1"));
    assert!(text.contains("oxide_server_capacity{server=\"m-1\"} 250"));
    assert!(text.contains("oxide_server_active_peers{server=\"m-1\"}"));
    // Prometheus format sanity: HELP/TYPE headers present.
    assert!(text.contains("# TYPE oxide_accounts_total gauge"));
}

#[tokio::test]
async fn concurrent_registrations_get_distinct_ips() {
    // 2C multi-node correctness: with the in-process registration lock removed, N concurrent
    // device registrations must still each get a distinct tunnel IP — the DB-side
    // UNIQUE(server_id, tunnel_ip) constraint + insert-retry does the serialization, so this
    // holds even across separate API nodes sharing one database.
    let pool = db::connect(&temp_db_path()).await.unwrap();
    let server_pub = public_from_secret(&generate_secret()).to_base64();
    add_server(
        &pool,
        NewServer {
            id: "us-1",
            public_key: &server_pub,
            endpoint: "203.0.113.1:51820",
            cidr: "10.8.0.0/28".parse().unwrap(), // .1 server, .2..=.14 assignable
            country: None,
            city: None,
            capacity: 100,
            dns: None,
            obfuscation_key: None,
            pq_public_key: None,
            transport: None,
            daita: false,
        },
    )
    .await
    .unwrap();

    let state = AppState::new(pool.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });

    let base = format!("http://{addr}");
    let account = ControlClient::new(&base).create_account().await.unwrap();

    // Fire N concurrent registrations of distinct device keys through the running API.
    let n = 10usize;
    let mut handles = Vec::new();
    for _ in 0..n {
        let account = account.clone();
        let base = base.clone();
        handles.push(tokio::spawn(async move {
            let cc = ControlClient::new(&base);
            let dev = public_from_secret(&generate_secret());
            cc.register_device(&account, dev, "us-1", None)
                .await
                .map(|r| r.assigned_ip)
        }));
    }

    let mut ips = std::collections::HashSet::new();
    for h in handles {
        let ip = h
            .await
            .unwrap()
            .expect("concurrent registration should succeed");
        assert!(
            ips.insert(ip),
            "two devices were assigned the same tunnel IP"
        );
    }
    assert_eq!(
        ips.len(),
        n,
        "each concurrent device must get a distinct tunnel IP"
    );
}

#[tokio::test]
async fn transport_choice_is_distributed_to_clients() {
    // 2A-2: a server registered as quic + daita must tell the client so, in the
    // registration response — the client then builds the matching transport (not just obfs).
    let pool = db::connect(&temp_db_path()).await.unwrap();
    let server_pub = public_from_secret(&generate_secret()).to_base64();
    add_server(
        &pool,
        NewServer {
            id: "q-1",
            public_key: &server_pub,
            endpoint: "203.0.113.5:51820",
            cidr: "10.8.0.0/24".parse().unwrap(),
            country: None,
            city: None,
            capacity: 100,
            dns: None,
            obfuscation_key: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            pq_public_key: None,
            transport: Some("quic"),
            daita: true,
        },
    )
    .await
    .unwrap();

    let state = AppState::new(pool.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });
    let cc = ControlClient::new(&format!("http://{addr}"));

    let account = cc.create_account().await.unwrap();
    let dev = public_from_secret(&generate_secret());
    let reg = cc
        .register_device(&account, dev, "q-1", None)
        .await
        .unwrap();
    assert_eq!(reg.transport.as_deref(), Some("quic"));
    assert!(reg.daita);
    assert!(reg.obfuscation_key.is_some()); // quic needs the shared key too

    // Re-registration (idempotent path) carries the same transport metadata.
    let reg2 = cc
        .register_device(&account, dev, "q-1", None)
        .await
        .unwrap();
    assert_eq!(reg2.transport.as_deref(), Some("quic"));
    assert!(reg2.daita);
}

#[tokio::test]
async fn admin_provisioning_endpoint() {
    use oxide_common::api::AdminAddServerRequest;

    // Admin API enabled with a token.
    let pool = db::connect(&temp_db_path()).await.unwrap();
    let state = AppState::new(pool).with_admin_token(Some("s3cr3t".into()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });
    let cc = ControlClient::new(&format!("http://{addr}"));

    let server_pub = public_from_secret(&generate_secret()).to_base64();
    let req = AdminAddServerRequest {
        id: "prov-1".into(),
        public_key: server_pub.clone(),
        endpoint: "203.0.113.9:51820".into(),
        cidr: "10.8.0.0/24".into(),
        country: Some("US".into()),
        city: None,
        capacity: 50,
        dns: Some("10.8.0.1".into()),
        obfuscation_key: None,
        pq_public_key: None,
        transport: Some("quic".into()),
        daita: true,
    };

    // Wrong token is rejected.
    assert!(cc.admin_add_server("wrong", &req).await.is_err());

    // Correct token registers the server and returns its auth token.
    let token = cc.admin_add_server("s3cr3t", &req).await.unwrap();
    assert!(!token.is_empty());

    // The server is now selectable, with the transport metadata provisioned.
    let account = cc.create_account().await.unwrap();
    let servers = cc.list_servers(&account).await.unwrap();
    let s = servers
        .iter()
        .find(|s| s.id == "prov-1")
        .expect("registered");
    assert_eq!(s.public_key.to_base64(), server_pub);
    let reg = cc
        .register_device(
            &account,
            public_from_secret(&generate_secret()),
            "prov-1",
            None,
        )
        .await
        .unwrap();
    assert_eq!(reg.transport.as_deref(), Some("quic"));
    assert!(reg.daita);
}

#[tokio::test]
async fn admin_endpoint_disabled_without_token() {
    use oxide_common::api::AdminAddServerRequest;
    // No admin token configured => the endpoint is forbidden entirely.
    let pool = db::connect(&temp_db_path()).await.unwrap();
    let state = AppState::new(pool); // no with_admin_token
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });
    let cc = ControlClient::new(&format!("http://{addr}"));

    let req = AdminAddServerRequest {
        id: "nope".into(),
        public_key: public_from_secret(&generate_secret()).to_base64(),
        endpoint: "203.0.113.9:51820".into(),
        cidr: "10.8.0.0/24".into(),
        country: None,
        city: None,
        capacity: 0,
        dns: None,
        obfuscation_key: None,
        pq_public_key: None,
        transport: None,
        daita: false,
    };
    assert!(cc.admin_add_server("anything", &req).await.is_err());
}
