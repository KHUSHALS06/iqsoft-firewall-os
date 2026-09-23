use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::{
    app_state::AppState,
    models::port_forward::PortForwardRule,
    services::port_forward_service::PortForwardService,
};

pub async fn list_rules(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match PortForwardService::list_rules(&state.db).await {
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
    Json(rule): Json<PortForwardRule>,
) -> impl IntoResponse {
    match PortForwardService::add_rule(&state.db, rule).await {
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
    Json(rule): Json<PortForwardRule>,
) -> impl IntoResponse {
    match PortForwardService::update_rule(&state.db, id, rule).await {
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
    match PortForwardService::delete_rule(&state.db, id).await {
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
