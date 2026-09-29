use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::{
    app_state::AppState,
    models::one_to_one_nat::OneToOneNatRule,
    services::one_to_one_nat_service::OneToOneNatService,
};

pub async fn list_rules(State(state): State<AppState>) -> impl IntoResponse {
    match OneToOneNatService::list_rules(&state.db).await {
        Ok(rules) => (StatusCode::OK, Json(json!(rules))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn add_rule(
    State(state): State<AppState>,
    Json(rule): Json<OneToOneNatRule>,
) -> impl IntoResponse {
    match OneToOneNatService::add_rule(&state.db, rule).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn update_rule(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(rule): Json<OneToOneNatRule>,
) -> impl IntoResponse {
    match OneToOneNatService::update_rule(&state.db, id, rule).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn delete_rule(
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match OneToOneNatService::delete_rule(&state.db, id).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}
