use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;
use crate::{
    app_state::AppState,
    firewall::{
        commit::FirewallCommit,
        generator::FirewallGenerator,
    },
    models::firewall_rule::FirewallRule,
    services::firewall_service::FirewallService,
};
pub async fn list_rules(
    State(state): State<AppState>,
) -> impl IntoResponse {
        match FirewallService::list_rules(&state.db).await {
        Ok(rules) => (
            StatusCode::OK,
            Json(json!(rules)),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": e
            })),
        ),
    }
}
pub async fn add_rule(
    State(state): State<AppState>,
    Json(rule): Json<FirewallRule>,
) -> impl IntoResponse {
        match FirewallService::add_rule(&state.db, rule).await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok"
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": e
            })),
        ),
    }
}
pub async fn update_rule(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(rule): Json<FirewallRule>,
) -> impl IntoResponse {
    match FirewallService::update_rule(&state.db, id, rule).await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok"
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": e
            })),
        ),
    }
}
pub async fn delete_rule(
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match FirewallService::delete_rule(&state.db, id).await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok"
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": e
            })),
        ),
    }
}
pub async fn generate_config(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match FirewallGenerator::generate(&state.db).await {
        Ok(config) => (
            StatusCode::OK,
            Json(json!({
                "config": config
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": e
            })),
        ),
    }
}
pub async fn commit(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match FirewallCommit::commit(&state.db, &state.commit_lock).await {
        Ok(message) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "message": message
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "error",
                "message": e
            })),
        ),
    }
}
pub async fn rollback(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match FirewallCommit::rollback(&state.db, &state.commit_lock).await {
        Ok(message) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "message": message
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "error",
                "message": e
            })),
        ),
    }
}
