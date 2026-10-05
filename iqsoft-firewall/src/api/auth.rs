use crate::{
    app_state::AppState,
    models::auth::{ChangePasswordRequest, LoginRequest, User},
    services::{
        audit_service::{actions, AuditEvent, AuditService},
        auth_service::{AuthError, AuthService},
    },
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

/// A short, fixed reason for the audit trail. It deliberately says nothing that
/// came from the request (no passwords, no echoed input) and nothing internal.
fn failure_reason(e: &AuthError) -> &'static str {
    match e {
        AuthError::InvalidCredentials => "invalid credentials",
        AuthError::BadRequest(_) => "request rejected",
        AuthError::Internal(_) => "internal error",
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

    // Requests refused by the throttle are not written to the audit trail one by
    // one. The failed attempts that caused the block are already there, and an
    // attacker who keeps hammering a blocked address must not be able to fill the table.
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

            AuditService::record(
                &state.db,
                AuditEvent::new(actions::LOGIN)
                    .username(&req.username)
                    .source_ip(ip),
            )
            .await;

            (StatusCode::OK, Json(json!(response)))
        }
        Err(AuthError::InvalidCredentials) => {
            state.login_throttle.record_failure(ip).await;

            AuditService::record(
                &state.db,
                AuditEvent::new(actions::LOGIN)
                    .username(&req.username)
                    .source_ip(ip)
                    .detail(failure_reason(&AuthError::InvalidCredentials))
                    .failed(),
            )
            .await;

            error_response(AuthError::InvalidCredentials)
        }
        Err(e) => {
            AuditService::record(
                &state.db,
                AuditEvent::new(actions::LOGIN)
                    .username(&req.username)
                    .source_ip(ip)
                    .detail(failure_reason(&e))
                    .failed(),
            )
            .await;

            error_response(e)
        }
    }
}

pub async fn logout(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
    Extension(token): Extension<AuthToken>,
) -> impl IntoResponse {
    match AuthService::logout(&state.db, &token.0).await {
        Ok(_) => {
            AuditService::record(
                &state.db,
                AuditEvent::new(actions::LOGOUT)
                    .user(&user)
                    .source_ip(addr.ip()),
            )
            .await;

            (StatusCode::OK, Json(json!({ "status": "ok" })))
        }
        Err(e) => error_response(e),
    }
}

pub async fn change_password(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
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
        Ok(_) => {
            AuditService::record(
                &state.db,
                AuditEvent::new(actions::PASSWORD_CHANGE)
                    .user(&user)
                    .source_ip(addr.ip()),
            )
            .await;

            (
                StatusCode::OK,
                Json(json!({ "status": "ok", "message": "Password changed. Please log in again." })),
            )
        }
        Err(e) => {
            AuditService::record(
                &state.db,
                AuditEvent::new(actions::PASSWORD_CHANGE)
                    .user(&user)
                    .source_ip(addr.ip())
                    .detail(failure_reason(&e))
                    .failed(),
            )
            .await;

            error_response(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::init::initialize_database,
        firewall::safe_commit::SafeCommit,
        repository::audit_repository::{AuditEntry, AuditFilter},
        services::login_throttle::LoginThrottle,
    };
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;

    async fn test_state() -> AppState {
        // One connection, otherwise every connection would get its own empty in-memory database.
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        initialize_database(&db).await.unwrap();

        AppState {
            db,
            commit_lock: Arc::new(tokio::sync::Mutex::new(())),
            login_throttle: LoginThrottle::new(),
            safe_commit: SafeCommit::new(),
        }
    }

    fn peer() -> ConnectInfo<SocketAddr> {
        ConnectInfo("10.1.2.3:5555".parse().unwrap())
    }

    fn user() -> User {
        User {
            id: 7,
            username: "admin".into(),
            password_hash: "not-a-real-hash".into(),
            role: "admin".into(),
        }
    }

    async fn trail(state: &AppState) -> Vec<AuditEntry> {
        AuditService::list(&state.db, &AuditFilter::default())
            .await
            .unwrap()
    }

    fn assert_no_secret_in(entry: &AuditEntry, secrets: &[&str]) {
        let everything = format!("{:?}", entry);
        for secret in secrets {
            assert!(!everything.contains(secret), "{} leaked into {}", secret, everything);
        }
    }

    #[test]
    fn failure_reasons_are_fixed_text() {
        assert_eq!(failure_reason(&AuthError::InvalidCredentials), "invalid credentials");
        assert_eq!(
            failure_reason(&AuthError::BadRequest("my-new-password-is-here".into())),
            "request rejected"
        );
        assert_eq!(
            failure_reason(&AuthError::Internal("database is on fire".into())),
            "internal error"
        );
    }

    #[tokio::test]
    async fn a_failed_login_is_audited_without_the_password() {
        let state = test_state().await;

        let response = login(
            State(state.clone()),
            peer(),
            Json(LoginRequest {
                username: "nobody".into(),
                password: "hunter2-secret".into(),
            }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let rows = trail(&state).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "auth.login");
        assert_eq!(rows[0].username.as_deref(), Some("nobody"));
        assert_eq!(rows[0].source_ip.as_deref(), Some("10.1.2.3"));
        assert_eq!(rows[0].detail.as_deref(), Some("invalid credentials"));
        assert!(!rows[0].success);
        assert_no_secret_in(&rows[0], &["hunter2-secret"]);
    }

    #[tokio::test]
    async fn logout_is_audited_with_the_user() {
        let state = test_state().await;

        let response = logout(
            State(state.clone()),
            peer(),
            Extension(user()),
            Extension(AuthToken("some-session-token".into())),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);

        let rows = trail(&state).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "auth.logout");
        assert_eq!(rows[0].user_id, Some(7));
        assert_eq!(rows[0].username.as_deref(), Some("admin"));
        assert!(rows[0].success);
        assert_no_secret_in(&rows[0], &["some-session-token"]);
    }

    #[tokio::test]
    async fn a_wrong_current_password_is_audited_as_a_failure_without_either_password() {
        let state = test_state().await;

        let response = change_password(
            State(state.clone()),
            peer(),
            Extension(user()),
            Json(ChangePasswordRequest {
                current_password: "old-secret-value".into(),
                new_password: "brand-new-secret-value".into(),
            }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let rows = trail(&state).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "auth.password_change");
        assert_eq!(rows[0].user_id, Some(7));
        assert_eq!(rows[0].detail.as_deref(), Some("invalid credentials"));
        assert!(!rows[0].success);
        assert_no_secret_in(&rows[0], &["old-secret-value", "brand-new-secret-value"]);
    }

    #[tokio::test]
    async fn a_too_short_new_password_is_audited_as_a_failure() {
        let state = test_state().await;

        let response = change_password(
            State(state.clone()),
            peer(),
            Extension(user()),
            Json(ChangePasswordRequest {
                current_password: "whatever".into(),
                new_password: "x".into(),
            }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let rows = trail(&state).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].detail.as_deref(), Some("request rejected"));
        assert!(!rows[0].success);
    }
}
