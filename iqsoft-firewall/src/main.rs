mod api;
mod app_state;
mod database;
mod dhcp;
mod dns;
mod firewall;
mod models;
mod repository;
mod services;
use axum::{
    routing::{get, post, put},
    Router,
};
use std::net::SocketAddr;
use api::{
    dhcp as dhcp_api,
    dns as dns_api,
    firewall as firewall_api,
    health,
    network_config as network_config_api,
};
use app_state::AppState;
use database::{
    connection::create_pool,
    init::initialize_database,
};
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
    let state = AppState {
        db,
        commit_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
    };
    let app = Router::new()
        .route("/health", get(health::health))
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
        .with_state(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Server running on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap();
    axum::serve(listener, app)
        .await
        .unwrap();
}
