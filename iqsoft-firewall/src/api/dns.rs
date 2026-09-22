use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;
use crate::{
    app_state::AppState,
    dns::{commit::DnsCommit, generator::DnsGenerator},
    models::dns::{DnsConfig, DnsStaticRecord},
    repository::dns_repository::DnsRepository,
    services::dns_service::DnsService,
};

pub async fn get_config(State(state): State<AppState>) -> impl IntoResponse {
    match DnsService::get_config(&state.db).await {
        Ok(config) => (StatusCode::OK, Json(json!(config))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn set_config(
    State(state): State<AppState>,
    Json(config): Json<DnsConfig>,
) -> impl IntoResponse {
    match DnsService::set_config(&state.db, config).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn list_records(State(state): State<AppState>) -> impl IntoResponse {
    match DnsService::list_records(&state.db).await {
        Ok(records) => (StatusCode::OK, Json(json!(records))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn add_record(
    State(state): State<AppState>,
    Json(record): Json<DnsStaticRecord>,
) -> impl IntoResponse {
    match DnsService::add_record(&state.db, record).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn update_record(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(record): Json<DnsStaticRecord>,
) -> impl IntoResponse {
    match DnsService::update_record(&state.db, id, record).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn delete_record(
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match DnsService::delete_record(&state.db, id).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn generate_config(State(state): State<AppState>) -> impl IntoResponse {
    let config = match DnsRepository::get_config(&state.db).await {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        }
    };
    let records = match DnsRepository::list_records(&state.db).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        }
    };

    match DnsGenerator::render(&config, &records) {
        Ok(rendered) => (StatusCode::OK, Json(json!({ "config": rendered }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn commit(State(state): State<AppState>) -> impl IntoResponse {
    match DnsCommit::commit(&state.db, &state.commit_lock).await {
        Ok(message) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "message": message })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": e })),
        ),
    }
}

pub async fn rollback(State(state): State<AppState>) -> impl IntoResponse {
    match DnsCommit::rollback(&state.db, &state.commit_lock).await {
        Ok(message) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "message": message })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": e })),
        ),
    }
}
