use crate::{
    app_state::AppState,
    models::auth::{ChangePasswordRequest, LoginRequest, User},
    services::auth_service::{AuthError, AuthService},
};
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::{json, Value};
use std::net::SocketAddr;

#[derive(Clone)]
pub struct AuthToken(pub String);

fn error_response(e: AuthError) -> (StatusCode, Json<Value>) {
    match e {
        AuthError::InvalidCredentials => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid credentials" })),
        ),
        AuthError::BadRequest(message) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": message })),
        ),
        AuthError::Internal(message) => {
            eprintln!("auth internal error: {}", message);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal error" })),
            )
        }
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "Authentication required" })),
    )
        .into_response()
}

pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v.trim().to_string());

    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => return unauthorized(),
    };

    match AuthService::authenticate(&state.db, &token).await {
        Ok(Some(user)) => {
            req.extensions_mut().insert(user);
            req.extensions_mut().insert(AuthToken(token));
            next.run(req).await
        }
        Ok(None) => unauthorized(),
        Err(e) => error_response(e).into_response(),
    }
}

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    let ip = addr.ip();

    if let Err(retry_after) = state.login_throttle.check(ip).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "Too many failed login attempts",
                "retry_after_seconds": retry_after
            })),
        );
    }

    match AuthService::login(&state.db, &req.username, &req.password).await {
        Ok(response) => {
            state.login_throttle.record_success(ip).await;
            (StatusCode::OK, Json(json!(response)))
        }
        Err(AuthError::InvalidCredentials) => {
            state.login_throttle.record_failure(ip).await;
            error_response(AuthError::InvalidCredentials)
        }
        Err(e) => error_response(e),
    }
}

pub async fn logout(
    State(state): State<AppState>,
    Extension(token): Extension<AuthToken>,
) -> impl IntoResponse {
    match AuthService::logout(&state.db, &token.0).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => error_response(e),
    }
}

pub async fn change_password(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Json(req): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    match AuthService::change_password(
        &state.db,
        &user,
        &req.current_password,
        &req.new_password,
    )
    .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "message": "Password changed. Please log in again." })),
        ),
        Err(e) => error_response(e),
    }
}
