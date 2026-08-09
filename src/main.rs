mod api;
mod app_state;
mod database;
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
    firewall as firewall_api,
    health,
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
    let state = AppState { db };
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
            "/api/commit",
            post(firewall_api::commit),
        )
        .route(
            "/api/rollback",
            post(firewall_api::rollback),
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
