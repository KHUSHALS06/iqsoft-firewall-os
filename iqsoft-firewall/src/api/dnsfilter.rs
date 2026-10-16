use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::{
    app_state::AppState,
    models::dnsfilter::{
        DnsFilterCategory, DnsFilterImportRequest, DnsFilterRule, DnsFilterSettings,
    },
    services::dnsfilter_service::DnsFilterService,
};

// ---------- settings ----------

pub async fn get_settings(State(state): State<AppState>) -> impl IntoResponse {
    match DnsFilterService::get_settings(&state.db).await {
        Ok(settings) => (StatusCode::OK, Json(json!(settings))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn set_settings(
    State(state): State<AppState>,
    Json(settings): Json<DnsFilterSettings>,
) -> impl IntoResponse {
    match DnsFilterService::set_settings(&state.db, settings).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

// ---------- categories ----------

pub async fn list_categories(State(state): State<AppState>) -> impl IntoResponse {
    match DnsFilterService::list_categories(&state.db).await {
        Ok(categories) => (StatusCode::OK, Json(json!(categories))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn add_category(
    State(state): State<AppState>,
    Json(category): Json<DnsFilterCategory>,
) -> impl IntoResponse {
    match DnsFilterService::add_category(&state.db, category).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn update_category(
    Path(name): Path<String>,
    State(state): State<AppState>,
    Json(category): Json<DnsFilterCategory>,
) -> impl IntoResponse {
    match DnsFilterService::update_category(&state.db, &name, category).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn delete_category(
    Path(name): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match DnsFilterService::delete_category(&state.db, &name).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn import_domains(
    Path(name): Path<String>,
    State(state): State<AppState>,
    Json(request): Json<DnsFilterImportRequest>,
) -> impl IntoResponse {
    match DnsFilterService::import_domains(&state.db, &name, request).await {
        Ok(result) => (StatusCode::OK, Json(json!(result))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

// ---------- your own block / allow rules ----------

pub async fn list_rules(State(state): State<AppState>) -> impl IntoResponse {
    match DnsFilterService::list_rules(&state.db).await {
        Ok(rules) => (StatusCode::OK, Json(json!(rules))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn add_rule(
    State(state): State<AppState>,
    Json(rule): Json<DnsFilterRule>,
) -> impl IntoResponse {
    match DnsFilterService::add_rule(&state.db, rule).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn update_rule(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(rule): Json<DnsFilterRule>,
) -> impl IntoResponse {
    match DnsFilterService::update_rule(&state.db, id, rule).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn delete_rule(
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match DnsFilterService::delete_rule(&state.db, id).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}
