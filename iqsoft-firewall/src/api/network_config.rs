use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde_json::json;
use crate::{app_state::AppState, models::network_config::NetworkConfig, services::network_config_service::NetworkConfigService};

pub async fn get_network_config(State(state): State<AppState>) -> impl IntoResponse {
    match NetworkConfigService::get(&state.db).await {
        Ok(config) => (StatusCode::OK, Json(json!(config))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))),
    }
}

pub async fn set_network_config(State(state): State<AppState>, Json(config): Json<NetworkConfig>) -> impl IntoResponse {
    match NetworkConfigService::set(&state.db, config).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}
