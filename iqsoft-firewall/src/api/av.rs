use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    app_state::AppState,
    models::av::{AvException, AvSettings},
    services::av_service::AvService,
};

// The scanning proxy (antivirus/proxy.rs) re-reads these settings every few
// seconds, so changes to the mode, limits, port and exceptions apply by
// themselves. The redirect of web traffic to the proxy is part of the firewall
// ruleset, so switching antivirus on or off takes full effect at the next
// firewall commit.

// ---------- settings ----------

pub async fn get_settings(State(state): State<AppState>) -> impl IntoResponse {
    match AvService::get_settings(&state.db).await {
        Ok(settings) => (StatusCode::OK, Json(json!(settings))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn set_settings(
    State(state): State<AppState>,
    Json(settings): Json<AvSettings>,
) -> impl IntoResponse {
    match AvService::set_settings(&state.db, settings).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

// ---------- exceptions (sites and networks that are never scanned) ----------

pub async fn list_exceptions(State(state): State<AppState>) -> impl IntoResponse {
    match AvService::list_exceptions(&state.db).await {
        Ok(exceptions) => (StatusCode::OK, Json(json!(exceptions))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn add_exception(
    State(state): State<AppState>,
    Json(exception): Json<AvException>,
) -> impl IntoResponse {
    match AvService::add_exception(&state.db, exception).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn delete_exception(
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match AvService::delete_exception(&state.db, id).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

// ---------- events ----------

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub action: Option<String>,
}

pub async fn list_events(
    State(state): State<AppState>,
    Query(query): Query<EventsQuery>,
) -> impl IntoResponse {
    match AvService::list_events(&state.db, query.limit, query.offset, query.action).await {
        Ok(events) => (StatusCode::OK, Json(json!(events))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn clear_events(State(state): State<AppState>) -> impl IntoResponse {
    match AvService::clear_events(&state.db).await {
        Ok(deleted) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "deleted": deleted })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn summary(State(state): State<AppState>) -> impl IntoResponse {
    match AvService::summary(&state.db).await {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

// ---------- status ----------

/// Live health: proxy listening, clamd answering, and whether clamd really
/// detected the test file in its last self-test.
pub async fn status(State(state): State<AppState>) -> impl IntoResponse {
    match AvService::get_settings(&state.db).await {
        Ok(settings) => (
            StatusCode::OK,
            Json(json!(crate::antivirus::health::snapshot(settings.enabled))),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}
