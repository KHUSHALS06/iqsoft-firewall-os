mod api;
mod app_state;
mod database;
mod dhcp;
mod dns;
mod firewall;
mod models;
mod monitor;
mod repository;
mod routing;
mod services;
mod wireguard;

use axum::{
    middleware,
    routing::{get, post, put},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;

use api::{
    address as address_api,
    audit as audit_api,
    auth as auth_api,
    dhcp as dhcp_api,
    dns as dns_api,
    firewall as firewall_api,
    health,
    monitor as monitor_api,
    network_config as network_config_api,
    one_to_one_nat as one_to_one_nat_api,
    port_forward as port_forward_api,
    route as route_api,
    wireguard as wireguard_api,
};
use app_state::AppState;
use database::{
    connection::create_pool,
    init::initialize_database,
};
use firewall::{commit::FirewallCommit, safe_commit::SafeCommit};
use routing::commit::RouteCommit;
use services::{auth_service::AuthService, login_throttle::LoginThrottle};
use wireguard::commit::WireguardCommit;

fn build_router(state: AppState) -> Router {
    let public = Router::new()
        .route("/health", get(health::health))
        .route("/api/auth/login", post(auth_api::login));

    let protected = Router::new()
        .route("/api/auth/logout", post(auth_api::logout))
        .route(
            "/api/auth/change-password",
            post(auth_api::change_password),
        )
        .route("/api/audit", get(audit_api::list_audit))
        .route(
            "/api/rules",
            get(firewall_api::list_rules)
                .post(firewall_api::add_rule),
        )
        .route(
            "/api/rules/{id}",
            put(firewall_api::update_rule)
                .delete(firewall_api::delete_rule),
        )
        .route(
            "/api/generate",
            get(firewall_api::generate_config),
        )
        .route(
            "/api/network",
            get(network_config_api::get_network_config)
                .put(network_config_api::set_network_config),
        )
        .route(
            "/api/commit",
            post(firewall_api::commit),
        )
        .route(
            "/api/commit/confirm",
            post(firewall_api::confirm_commit),
        )
        .route(
            "/api/commit/status",
            get(firewall_api::commit_status),
        )
        .route(
            "/api/rollback",
            post(firewall_api::rollback),
        )
        .route(
            "/api/dhcp/config",
            get(dhcp_api::get_config)
                .put(dhcp_api::set_config),
        )
        .route(
            "/api/dhcp/reservations",
            get(dhcp_api::list_reservations)
                .post(dhcp_api::add_reservation),
        )
        .route(
            "/api/dhcp/reservations/{id}",
            put(dhcp_api::update_reservation)
                .delete(dhcp_api::delete_reservation),
        )
        .route(
            "/api/dhcp/generate",
            get(dhcp_api::generate_config),
        )
        .route(
            "/api/dhcp/leases",
            get(dhcp_api::leases),
        )
        .route(
            "/api/dhcp/commit",
            post(dhcp_api::commit),
        )
        .route(
            "/api/dhcp/rollback",
            post(dhcp_api::rollback),
        )
        .route(
            "/api/dns/config",
            get(dns_api::get_config)
                .put(dns_api::set_config),
        )
        .route(
            "/api/dns/records",
            get(dns_api::list_records)
                .post(dns_api::add_record),
        )
        .route(
            "/api/dns/records/{id}",
            put(dns_api::update_record)
                .delete(dns_api::delete_record),
        )
        .route(
            "/api/dns/generate",
            get(dns_api::generate_config),
        )
        .route(
            "/api/dns/commit",
            post(dns_api::commit),
        )
        .route(
            "/api/dns/rollback",
            post(dns_api::rollback),
        )
        .route(
            "/api/port-forwards",
            get(port_forward_api::list_rules)
                .post(port_forward_api::add_rule),
        )
        .route(
            "/api/port-forwards/{id}",
            put(port_forward_api::update_rule)
                .delete(port_forward_api::delete_rule),
        )
        .route(
            "/api/one-to-one-nat",
            get(one_to_one_nat_api::list_rules)
                .post(one_to_one_nat_api::add_rule),
        )
        .route(
            "/api/one-to-one-nat/{id}",
            put(one_to_one_nat_api::update_rule)
                .delete(one_to_one_nat_api::delete_rule),
        )
        .route(
            "/api/routes",
            get(route_api::list_routes)
                .post(route_api::add_route),
        )
        .route(
            "/api/routes/{id}",
            put(route_api::update_route)
                .delete(route_api::delete_route),
        )
        .route(
            "/api/routes/generate",
            get(route_api::generate_script),
        )
        .route(
            "/api/routes/commit",
            post(route_api::commit),
        )
        .route(
            "/api/routes/rollback",
            post(route_api::rollback),
        )
        .route(
            "/api/address-objects",
            get(address_api::list_objects)
                .post(address_api::add_object),
        )
        .route(
            "/api/address-objects/{id}",
            put(address_api::update_object)
                .delete(address_api::delete_object),
        )
        .route(
            "/api/address-groups",
            get(address_api::list_groups)
                .post(address_api::add_group),
        )
        .route(
            "/api/address-groups/{id}",
            put(address_api::update_group)
                .delete(address_api::delete_group),
        )
        .route(
            "/api/wireguard/config",
            get(wireguard_api::get_config)
                .put(wireguard_api::set_config),
        )
        .route(
            "/api/wireguard/peers",
            get(wireguard_api::list_peers)
                .post(wireguard_api::add_peer),
        )
        .route(
            "/api/wireguard/peers/{id}",
            put(wireguard_api::update_peer)
                .delete(wireguard_api::delete_peer),
        )
        .route(
            "/api/wireguard/generate",
            get(wireguard_api::generate_config),
        )
        .route(
            "/api/wireguard/status",
            get(wireguard_api::status),
        )
        .route(
            "/api/wireguard/commit",
            post(wireguard_api::commit),
        )
        .route(
            "/api/wireguard/rollback",
            post(wireguard_api::rollback),
        )
        .route(
            "/api/monitor/interfaces",
            get(monitor_api::get_interfaces),
        )
        .route(
            "/api/monitor/connections",
            get(monitor_api::get_connections),
        )
        .route(
            "/api/monitor/conntrack-usage",
            get(monitor_api::get_conntrack_usage),
        )
        .route(
            "/api/monitor/rule-counters",
            get(monitor_api::get_rule_counters),
        )
        .route(
            "/api/monitor/logs",
            get(monitor_api::get_logs),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_api::require_auth,
        ));

    public.merge(protected).with_state(state)
}

#[tokio::main]
async fn main() {
    println!("==================================");
    println!("     IQSOFT Firewall OS");
    println!("==================================");

    let db = create_pool()
        .await
        .expect("Failed to connect to database");

    initialize_database(&db)
        .await
        .expect("Failed to initialize database");

    AuthService::ensure_admin(&db)
        .await
        .expect("Failed to initialize admin user");

    let commit_lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));

    match FirewallCommit::restore_on_boot(&commit_lock).await {
        Ok(message) => println!("{}", message),
        Err(e) => {
            eprintln!(
                "ERROR: could not restore the saved firewall configuration: {}",
                e
            );
            eprintln!(
                "ERROR: the firewall may be running with an empty ruleset until a commit succeeds"
            );
        }
    }

    match RouteCommit::restore_on_boot(&commit_lock).await {
        Ok(message) => println!("{}", message),
        Err(e) => {
            eprintln!(
                "ERROR: could not restore the saved routing configuration: {}",
                e
            );
            eprintln!(
                "ERROR: static routes may be missing until a routing commit succeeds"
            );
        }
    }

    match WireguardCommit::restore_on_boot(&commit_lock).await {
        Ok(message) => println!("{}", message),
        Err(e) => {
            eprintln!(
                "ERROR: could not restore the saved WireGuard configuration: {}",
                e
            );
            eprintln!(
                "ERROR: the VPN tunnel may be down until a WireGuard commit succeeds"
            );
        }
    }

    let safe_commit = SafeCommit::new();

    match safe_commit.recover_on_boot(&db, &commit_lock).await {
        Ok(message) => println!("{}", message),
        Err(e) => eprintln!("ERROR: {}", e),
    }

    let state = AppState {
        db,
        commit_lock,
        login_throttle: LoginThrottle::new(),
        safe_commit,
    };

    let app = build_router(state);

    let bind =
        std::env::var("IQSOFT_BIND").unwrap_or_else(|_| "127.0.0.1:3000".to_string());

    let addr: SocketAddr = bind
        .parse()
        .expect("IQSOFT_BIND must look like 192.168.1.1:3443");

    let tls_cert = std::env::var("IQSOFT_TLS_CERT").ok();
    let tls_key = std::env::var("IQSOFT_TLS_KEY").ok();

    match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => {
            let _ = rustls::crypto::ring::default_provider().install_default();

            let config = RustlsConfig::from_pem_file(&cert, &key)
                .await
                .expect("Failed to load TLS certificate/key");

            println!("Server running on https://{}", addr);

            axum_server::bind_rustls(addr, config)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("Server failed");
        }
        _ => {
            println!("Server running on http://{}", addr);

            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .expect("Failed to bind server");

            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
                .expect("Server failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        repository::{audit_repository::AuditFilter, auth_repository::AuthRepository},
        services::audit_service::AuditService,
    };
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };
    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{header, Method, Request, StatusCode},
    };
    use serde_json::{json, Value};
    use sqlx::sqlite::SqlitePoolOptions;
    use tower::ServiceExt;

    async fn test_app() -> (Router, AppState) {
        // One connection, otherwise every connection would get its own empty in-memory database.
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        initialize_database(&db).await.unwrap();

        let state = AppState {
            db,
            commit_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            login_throttle: LoginThrottle::new(),
            safe_commit: SafeCommit::new(),
        };

        (build_router(state.clone()), state)
    }

    async fn add_user(state: &AppState, name: &str, password: &str, role: &str) {
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
            .unwrap()
            .to_string();

        AuthRepository::create_user(&state.db, name, &hash, role, 0)
            .await
            .unwrap();
    }

    /// Sends one request through the real router, as if it came from 10.9.8.7.
    async fn send(
        app: &Router,
        method: Method,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(uri);

        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {}", token));
        }

        let request_body = match body {
            Some(value) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };

        let mut request = builder.body(request_body).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo::<SocketAddr>("10.9.8.7:4321".parse().unwrap()));

        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn log_in(app: &Router, name: &str, password: &str) -> String {
        let (status, body) = send(
            app,
            Method::POST,
            "/api/auth/login",
            None,
            Some(json!({ "username": name, "password": password })),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{}", body);
        body["token"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn the_audit_route_is_behind_the_login() {
        let (app, _state) = test_app().await;

        let (status, _) = send(&app, Method::GET, "/api/audit", None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _) = send(&app, Method::GET, "/api/audit", Some("not-a-real-token"), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_then_a_rule_change_then_reading_the_trail() {
        let (app, state) = test_app().await;
        add_user(&state, "admin", "correct-horse-battery", "admin").await;

        // A wrong password, then the right one.
        let (status, _) = send(
            &app,
            Method::POST,
            "/api/auth/login",
            None,
            Some(json!({ "username": "admin", "password": "wrong-password-here" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let token = log_in(&app, "admin", "correct-horse-battery").await;

        // A real change through the real route.
        let (status, body) = send(
            &app,
            Method::POST,
            "/api/rules",
            Some(&token),
            Some(json!({
                "name": "web in",
                "enabled": true,
                "priority": 100,
                "chain_name": "FORWARD",
                "action": "accept",
                "protocol": "tcp",
                "dst_port": 443,
                "port_any": false,
                "log_enabled": false
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", body);

        // Read the trail back through the API.
        let (status, body) = send(&app, Method::GET, "/api/audit", Some(&token), None).await;
        assert_eq!(status, StatusCode::OK, "{}", body);
        assert_eq!(body["total"], 3);

        let entries = body["entries"].as_array().unwrap();
        let actions: Vec<&str> = entries.iter().map(|e| e["action"].as_str().unwrap()).collect();
        assert_eq!(actions, vec!["rule.create", "auth.login", "auth.login"]);

        let successes: Vec<bool> = entries.iter().map(|e| e["success"].as_bool().unwrap()).collect();
        assert_eq!(successes, vec![true, true, false]);

        // Every event knows where it came from, and none of them holds a password.
        for entry in entries {
            assert_eq!(entry["source_ip"], "10.9.8.7");
        }
        let everything = body.to_string();
        assert!(!everything.contains("correct-horse-battery"));
        assert!(!everything.contains("wrong-password-here"));
        assert!(!everything.contains(&token));
    }

    #[tokio::test]
    async fn a_user_who_is_not_an_admin_cannot_read_the_trail() {
        let (app, state) = test_app().await;
        add_user(&state, "viewer", "viewer-password-1", "viewer").await;

        let token = log_in(&app, "viewer", "viewer-password-1").await;

        let (status, body) = send(&app, Method::GET, "/api/audit", Some(&token), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.get("entries").is_none());
    }

    #[tokio::test]
    async fn logging_out_ends_the_session_and_is_recorded() {
        let (app, state) = test_app().await;
        add_user(&state, "admin", "correct-horse-battery", "admin").await;

        let token = log_in(&app, "admin", "correct-horse-battery").await;

        let (status, _) = send(&app, Method::POST, "/api/auth/logout", Some(&token), None).await;
        assert_eq!(status, StatusCode::OK);

        // The same token no longer works.
        let (status, _) = send(&app, Method::GET, "/api/audit", Some(&token), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let logout_events = AuditService::list(
            &state.db,
            &AuditFilter {
                action: Some("auth.logout".into()),
                ..AuditFilter::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(logout_events.len(), 1);
        assert_eq!(logout_events[0].username.as_deref(), Some("admin"));
        assert_eq!(logout_events[0].source_ip.as_deref(), Some("10.9.8.7"));
    }
}
