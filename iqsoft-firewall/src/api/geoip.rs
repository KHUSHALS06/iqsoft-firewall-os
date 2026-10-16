use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::{
    app_state::AppState,
    models::geoip::{GeoipImportRequest, GeoipPolicy},
    services::geoip_service::GeoipService,
};

// ---------- policies ----------

pub async fn list_policies(State(state): State<AppState>) -> impl IntoResponse {
    match GeoipService::list_policies(&state.db).await {
        Ok(policies) => (StatusCode::OK, Json(json!(policies))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn add_policy(
    State(state): State<AppState>,
    Json(policy): Json<GeoipPolicy>,
) -> impl IntoResponse {
    match GeoipService::add_policy(&state.db, policy).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn update_policy(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(policy): Json<GeoipPolicy>,
) -> impl IntoResponse {
    match GeoipService::update_policy(&state.db, id, policy).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn delete_policy(
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match GeoipService::delete_policy(&state.db, id).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

// ---------- country network lists ----------

pub async fn list_datasets(State(state): State<AppState>) -> impl IntoResponse {
    match GeoipService::list_datasets(&state.db).await {
        Ok(datasets) => (StatusCode::OK, Json(json!(datasets))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn import_dataset(
    Path(country): Path<String>,
    State(state): State<AppState>,
    Json(request): Json<GeoipImportRequest>,
) -> impl IntoResponse {
    match GeoipService::import_dataset(&state.db, &country, request).await {
        Ok(result) => (StatusCode::OK, Json(json!(result))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn delete_dataset(
    Path(country): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match GeoipService::delete_dataset(&state.db, &country).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}
