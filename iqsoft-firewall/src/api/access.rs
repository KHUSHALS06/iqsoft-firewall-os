use crate::{
    app_state::AppState,
    models::auth::User,
    services::{
        audit_service::{actions, AuditEvent, AuditService},
        permissions::{self, Requirement},
    },
};
use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::net::SocketAddr;

/// Runs after sign-in. Looks up which permission the request needs (see
/// `services::permissions`) and lets it through only if the signed-in user's role has it.
///
/// This is the real gate. Hiding menu entries in the web pages is only a convenience.
pub async fn require_permission(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let user = match req.extensions().get::<User>() {
        Some(u) => u.clone(),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Authentication required" })),
            )
                .into_response()
        }
    };

    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let missing: Option<String> = match permissions::required_for(&method, &path) {
        Requirement::Open | Requirement::HandlerChecked => None,
        Requirement::AnyOf(list) => {
            if user.can_any(&list) {
                None
            } else {
                Some(list.first().cloned().unwrap_or_default())
            }
        }
        Requirement::SuperAdminOnly => {
            if user.is_super_admin() {
                None
            } else {
                Some("super_admin".to_string())
            }
        }
    };

    let Some(wanted) = missing else {
        return next.run(req).await;
    };

    let mut event = AuditEvent::new(actions::ACCESS_DENIED)
        .user(&user)
        .target(&path)
        .detail(&format!("{} needs {}", method, wanted))
        .failed();

    if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        event = event.source_ip(addr.ip());
    }

    AuditService::record(&state.db, event).await;

    (
        StatusCode::FORBIDDEN,
        Json(json!({ "error": "Your role does not allow this action" })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::init::initialize_database, firewall::safe_commit::SafeCommit,
        services::login_throttle::LoginThrottle,
    };
    use axum::{
        body::Body,
        http::{Method, Request as HttpRequest},
        routing::{delete, get, post},
        Extension, Router,
    };
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn state() -> AppState {
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

    fn user(role: &str, perms: &[&str]) -> User {
        User {
            id: 3,
            username: "tester".into(),
            password_hash: "x".into(),
            role: role.into(),
            permissions: perms.iter().map(|p| p.to_string()).collect(),
        }
    }

    async fn status(state: &AppState, who: User, method: Method, path: &str) -> StatusCode {
        async fn ok() -> &'static str {
            "ok"
        }

        let app = Router::new()
            .route("/api/rules", get(ok).post(ok))
            .route("/api/rules/{id}", delete(ok))
            .route("/api/commit", post(ok))
            .route("/api/auth/me", get(ok))
            .route("/api/users", get(ok))
            .route("/api/something-new", get(ok))
            .route_layer(middleware::from_fn_with_state(state.clone(), require_permission))
            .layer(Extension(who));

        app.oneshot(HttpRequest::builder().method(method).uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    use axum::middleware;

    #[tokio::test]
    async fn each_action_needs_its_own_permission() {
        let state = state().await;
        let viewer = || user("Viewer", &["firewall.view"]);

        assert_eq!(status(&state, viewer(), Method::GET, "/api/rules").await, StatusCode::OK);
        assert_eq!(status(&state, viewer(), Method::POST, "/api/rules").await, StatusCode::FORBIDDEN);
        assert_eq!(status(&state, viewer(), Method::DELETE, "/api/rules/4").await, StatusCode::FORBIDDEN);
        assert_eq!(status(&state, viewer(), Method::POST, "/api/commit").await, StatusCode::FORBIDDEN);

        let editor = user("Editor", &["firewall.view", "firewall.edit"]);
        assert_eq!(status(&state, editor, Method::POST, "/api/commit").await, StatusCode::OK);

        let deleter = user("Deleter", &["firewall.view", "firewall.delete"]);
        assert_eq!(status(&state, deleter, Method::DELETE, "/api/rules/4").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn the_dashboard_may_read_what_it_shows_but_not_change_it() {
        let state = state().await;
        let dash = || user("Dash", &["dashboard.view"]);

        assert_eq!(status(&state, dash(), Method::GET, "/api/rules").await, StatusCode::OK);
        assert_eq!(status(&state, dash(), Method::POST, "/api/rules").await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn the_super_admin_passes_everywhere_and_unknown_routes_are_closed_to_others() {
        let state = state().await;

        assert_eq!(status(&state, user("super_admin", &[]), Method::DELETE, "/api/rules/1").await, StatusCode::OK);
        assert_eq!(status(&state, user("super_admin", &[]), Method::GET, "/api/something-new").await, StatusCode::OK);

        let everything: Vec<&str> = vec!["firewall.view", "firewall.create", "firewall.edit", "firewall.delete"];
        assert_eq!(status(&state, user("Powerful", &everything), Method::GET, "/api/something-new").await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn own_account_and_management_routes_are_not_blocked_by_the_route_check() {
        let state = state().await;
        let nobody = || user("Empty", &[]);

        assert_eq!(status(&state, nobody(), Method::GET, "/api/auth/me").await, StatusCode::OK);
        // The users handlers check for themselves, so the route check passes them along.
        assert_eq!(status(&state, nobody(), Method::GET, "/api/users").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_refusal_is_written_to_the_audit_trail() {
        let state = state().await;

        let code = status(&state, user("Viewer", &["firewall.view"]), Method::DELETE, "/api/rules/9").await;
        assert_eq!(code, StatusCode::FORBIDDEN);

        let rows = AuditService::list(&state.db, &Default::default()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "auth.access_denied");
        assert_eq!(rows[0].username.as_deref(), Some("tester"));
        assert_eq!(rows[0].target.as_deref(), Some("/api/rules/9"));
        assert!(!rows[0].success);
    }
}
