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
            eprintln!("ERROR: could not restore the saved firewall configuration: {}", e);
            eprintln!("ERROR: the firewall may be running with an empty ruleset until a commit succeeds");
        }
    }

    match RouteCommit::restore_on_boot(&commit_lock).await {
        Ok(message) => println!("{}", message),
        Err(e) => {
            eprintln!("ERROR: could not restore the saved routing configuration: {}", e);
            eprintln!("ERROR: static routes may be missing until a routing commit succeeds");
        }
    }

    match WireguardCommit::restore_on_boot(&commit_lock).await {
        Ok(message) => println!("{}", message),
        Err(e) => {
            eprintln!("ERROR: could not restore the saved WireGuard configuration: {}", e);
            eprintln!("ERROR: the VPN tunnel may be down until a WireGuard commit succeeds");
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

    let public = Router::new()
        .route("/health", get(health::health))
        .route("/api/auth/login", post(auth_api::login));

    let protected = Router::new()
        .route("/api/auth/logout", post(auth_api::logout))
        .route(
            "/api/auth/change-password",
            post(auth_api::change_password),
        )
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

    let app = public.merge(protected).with_state(state);

    let bind = std::env::var("IQSOFT_BIND").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
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
                .unwrap();
        }
        (None, None) => {
            if !addr.ip().is_loopback() {
                println!("WARNING: TLS is not configured and the API is reachable from the network.");
                println!("WARNING: passwords and session tokens will travel unencrypted.");
                println!("WARNING: set IQSOFT_TLS_CERT and IQSOFT_TLS_KEY.");
            }

            println!("Server running on http://{}", addr);

            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .unwrap();

            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        }
        _ => {
            panic!("Set both IQSOFT_TLS_CERT and IQSOFT_TLS_KEY, or neither");
        }
    }
}
