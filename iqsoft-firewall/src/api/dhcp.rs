use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;
use crate::{
    app_state::AppState,
    dhcp::{
        commit::DhcpCommit,
        generator::DhcpGenerator,
        leases::DhcpLeases,
    },
    models::dhcp::{DhcpConfig, DhcpReservation},
    repository::dhcp_repository::DhcpRepository,
    services::dhcp_service::DhcpService,
};

pub async fn get_config(State(state): State<AppState>) -> impl IntoResponse {
    match DhcpService::get_config(&state.db).await {
        Ok(config) => (StatusCode::OK, Json(json!(config))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn set_config(
    State(state): State<AppState>,
    Json(config): Json<DhcpConfig>,
) -> impl IntoResponse {
    match DhcpService::set_config(&state.db, config).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn list_reservations(State(state): State<AppState>) -> impl IntoResponse {
    match DhcpService::list_reservations(&state.db).await {
        Ok(reservations) => (StatusCode::OK, Json(json!(reservations))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn add_reservation(
    State(state): State<AppState>,
    Json(reservation): Json<DhcpReservation>,
) -> impl IntoResponse {
    match DhcpService::add_reservation(&state.db, reservation).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn update_reservation(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(reservation): Json<DhcpReservation>,
) -> impl IntoResponse {
    match DhcpService::update_reservation(&state.db, id, reservation).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn delete_reservation(
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match DhcpService::delete_reservation(&state.db, id).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn generate_config(State(state): State<AppState>) -> impl IntoResponse {
    let config = match DhcpRepository::get_config(&state.db).await {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        }
    };
    let reservations = match DhcpRepository::list_reservations(&state.db).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        }
    };

    match DhcpGenerator::render(&config, &reservations) {
        Ok(rendered) => (StatusCode::OK, Json(json!({ "config": rendered }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn leases() -> impl IntoResponse {
    match DhcpLeases::read() {
        Ok(leases) => (StatusCode::OK, Json(json!(leases))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn commit(State(state): State<AppState>) -> impl IntoResponse {
    match DhcpCommit::commit(&state.db, &state.commit_lock).await {
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
    match DhcpCommit::rollback(&state.db, &state.commit_lock).await {
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
