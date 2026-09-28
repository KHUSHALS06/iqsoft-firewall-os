use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::{
    app_state::AppState,
    models::route::Route,
    routing::{commit::RouteCommit, generator::RouteGenerator},
    services::route_service::RouteService,
};

pub async fn list_routes(State(state): State<AppState>) -> impl IntoResponse {
    match RouteService::list_routes(&state.db).await {
        Ok(routes) => (StatusCode::OK, Json(json!(routes))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn add_route(
    State(state): State<AppState>,
    Json(route): Json<Route>,
) -> impl IntoResponse {
    match RouteService::add_route(&state.db, route).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn update_route(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(route): Json<Route>,
) -> impl IntoResponse {
    match RouteService::update_route(&state.db, id, route).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn delete_route(
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match RouteService::delete_route(&state.db, id).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn generate_script(State(state): State<AppState>) -> impl IntoResponse {
    match RouteService::list_routes(&state.db).await {
        Ok(routes) => (
            StatusCode::OK,
            Json(json!({ "script": RouteGenerator::render(&routes) })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn commit(State(state): State<AppState>) -> impl IntoResponse {
    match RouteCommit::commit(&state.db, &state.commit_lock).await {
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
    match RouteCommit::rollback(&state.db, &state.commit_lock).await {
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
