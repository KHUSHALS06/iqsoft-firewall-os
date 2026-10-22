use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::{
    app_state::AppState,
    models::sni::{SniRule, SniSettings},
    services::sni_service::SniService,
};

// ---------- settings ----------

pub async fn get_settings(State(state): State<AppState>) -> impl IntoResponse {
    match SniService::get_settings(&state.db).await {
        Ok(settings) => (StatusCode::OK, Json(json!(settings))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn set_settings(
    State(state): State<AppState>,
    Json(settings): Json<SniSettings>,
) -> impl IntoResponse {
    match SniService::set_settings(&state.db, settings).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

// ---------- your own block / allow rules ----------

pub async fn list_rules(State(state): State<AppState>) -> impl IntoResponse {
    match SniService::list_rules(&state.db).await {
        Ok(rules) => (StatusCode::OK, Json(json!(rules))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn add_rule(
    State(state): State<AppState>,
    Json(rule): Json<SniRule>,
) -> impl IntoResponse {
    match SniService::add_rule(&state.db, rule).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn update_rule(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(rule): Json<SniRule>,
) -> impl IntoResponse {
    match SniService::update_rule(&state.db, id, rule).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn delete_rule(
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match SniService::delete_rule(&state.db, id).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}
