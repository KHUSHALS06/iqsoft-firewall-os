use crate::{
    app_state::AppState,
    models::interface_config::InterfaceConfig,
    netconfig::{commit::InterfaceCommit, generator::InterfaceGenerator, live},
    services::interface_config_service::InterfaceConfigService,
};
use axum::{
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;
use std::net::SocketAddr;

/// GET /api/interfaces - saved settings of every port
pub async fn list(State(state): State<AppState>) -> impl IntoResponse {
    match InterfaceConfigService::list(&state.db).await {
        Ok(list) => (StatusCode::OK, Json(json!(list))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))),
    }
}

/// GET /api/interfaces/live - what the ports have right now
pub async fn live_state() -> impl IntoResponse {
    match live::read_live().await {
        Ok(list) => (StatusCode::OK, Json(json!(list))),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": e }))),
    }
}

/// PUT /api/interfaces/{name} - save settings (not live until commit)
pub async fn save(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(cfg): Json<InterfaceConfig>,
) -> impl IntoResponse {
    match InterfaceConfigService::save(&state.db, &name, cfg).await {
        Ok(saved) => (StatusCode::OK, Json(json!(saved))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

/// DELETE /api/interfaces/{name}
pub async fn remove(State(state): State<AppState>, Path(name): Path<String>) -> impl IntoResponse {
    match InterfaceConfigService::delete(&state.db, &name).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e }))),
    }
}

/// GET /api/interfaces/generate - preview of the files that will be written
pub async fn generate(State(state): State<AppState>) -> impl IntoResponse {
    match InterfaceConfigService::list(&state.db).await {
        Ok(list) => (
            StatusCode::OK,
            Json(json!({ "script": InterfaceGenerator::render_all(&list) })),
        ),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))),
    }
}

/// POST /api/interfaces/commit
pub async fn commit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    match InterfaceCommit::commit(&state.db, &state.commit_lock, Some(addr.ip())).await {
        Ok(outcome) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "message": outcome.message,
                "confirm_seconds": outcome.confirm_seconds
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": e })),
        ),
    }
}

/// POST /api/interfaces/confirm
pub async fn confirm() -> impl IntoResponse {
    match InterfaceCommit::confirm() {
        Ok(message) => (StatusCode::OK, Json(json!({ "status": "ok", "message": message }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "status": "error", "message": e }))),
    }
}

/// GET /api/interfaces/status - is a change waiting for confirmation?
pub async fn status() -> impl IntoResponse {
    let left = InterfaceCommit::seconds_left();
    (
        StatusCode::OK,
        Json(json!({ "pending": left.is_some(), "seconds_left": left })),
    )
}

/// POST /api/interfaces/rollback
pub async fn rollback(State(state): State<AppState>) -> impl IntoResponse {
    match InterfaceCommit::rollback(&state.db, &state.commit_lock).await {
        Ok(message) => (StatusCode::OK, Json(json!({ "status": "ok", "message": message }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "status": "error", "message": e }))),
    }
}
