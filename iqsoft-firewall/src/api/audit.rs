use crate::{
    app_state::AppState,
    models::auth::User,
    repository::audit_repository::{AuditFilter, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE},
    services::audit_service::AuditService,
};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;

/// Query string for `GET /api/audit`. Every field is optional.
#[derive(Debug, Deserialize)]
pub struct AuditParams {
    /// Only events by this user name.
    pub username: Option<String>,
    /// Only this kind of event, for example `firewall.commit`.
    pub action: Option<String>,
    /// `true` for successes only, `false` for failures only.
    pub success: Option<bool>,
    /// Only events at or after this time (unix seconds).
    pub since: Option<i64>,
    /// Only events at or before this time (unix seconds).
    pub until: Option<i64>,
    /// Page size. Default 100, maximum 500.
    pub limit: Option<i64>,
    /// How many matching events to skip.
    pub offset: Option<i64>,
}

/// `?username=` with nothing after the equals sign means "no filter", not "match nothing".
fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

impl AuditParams {
    fn into_filter(self) -> AuditFilter {
        AuditFilter {
            username: non_empty(self.username),
            action: non_empty(self.action),
            success: self.success,
            since: self.since,
            until: self.until,
            limit: self.limit,
            offset: self.offset,
        }
    }
}

/// GET /api/audit?username=admin&action=firewall.commit&success=false&limit=50
///
/// Read-only on purpose: there is no way to edit or delete audit events through the API.
///
/// Until role-based access control exists, only the `admin` role may read the trail.
pub async fn list_audit(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Query(params): Query<AuditParams>,
) -> impl IntoResponse {
    if user.role != "admin" {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Only administrators can read the audit trail" })),
        );
    }

    if let (Some(since), Some(until)) = (params.since, params.until) {
        if since > until {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "'since' must not be later than 'until'" })),
            );
        }
    }

    let filter = params.into_filter();

    // Report the page size that was really used, not the one that was asked for.
    let limit = filter
        .limit
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE);
    let offset = filter.offset.unwrap_or(0).max(0);

    let total = match AuditService::count(&state.db, &filter).await {
        Ok(total) => total,
        Err(e) => return internal_error(e),
    };

    match AuditService::list(&state.db, &filter).await {
        Ok(entries) => (
            StatusCode::OK,
            Json(json!({
                "total": total,
                "limit": limit,
                "offset": offset,
                "entries": entries
            })),
        ),
        Err(e) => internal_error(e),
    }
}

fn internal_error(e: sqlx::Error) -> (StatusCode, Json<serde_json::Value>) {
    eprintln!("audit: could not read the trail: {}", e);

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": "Internal error" })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::init::initialize_database,
        firewall::safe_commit::SafeCommit,
        services::{
            audit_service::{actions, AuditEvent},
            login_throttle::LoginThrottle,
        },
    };
    use axum::response::Response;
    use serde_json::Value;
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

    fn user_with_role(role: &str) -> Extension<User> {
        Extension(User {
            id: 1,
            username: "someone".into(),
            password_hash: "not-a-real-hash".into(),
            role: role.into(),
        })
    }

    fn params() -> AuditParams {
        AuditParams {
            username: None,
            action: None,
            success: None,
            since: None,
            until: None,
            limit: None,
            offset: None,
        }
    }

    async fn body_json(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn add(state: &AppState, event: AuditEvent) {
        AuditService::try_record(&state.db, event).await.unwrap();
    }

    async fn call(state: &AppState, params: AuditParams) -> Response {
        list_audit(State(state.clone()), user_with_role("admin"), Query(params))
            .await
            .into_response()
    }

    #[tokio::test]
    async fn an_admin_gets_entries_newest_first_with_the_total() {
        let state = test_state().await;
        add(&state, AuditEvent::new(actions::LOGIN).username("a")).await;
        add(&state, AuditEvent::new(actions::COMMIT).username("a")).await;
        add(&state, AuditEvent::new(actions::ROLLBACK).username("a")).await;

        let response = call(&state, params()).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = body_json(response).await;
        assert_eq!(body["total"], 3);
        assert_eq!(body["limit"], 100);
        assert_eq!(body["offset"], 0);

        let order: Vec<&str> = body["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["action"].as_str().unwrap())
            .collect();
        assert_eq!(order, vec!["firewall.rollback", "firewall.commit", "auth.login"]);
    }

    #[tokio::test]
    async fn a_non_admin_is_refused_and_sees_nothing() {
        let state = test_state().await;
        add(&state, AuditEvent::new(actions::LOGIN).username("a")).await;

        let response = list_audit(
            State(state.clone()),
            user_with_role("viewer"),
            Query(params()),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let body = body_json(response).await;
        assert!(body.get("entries").is_none());
        assert!(body["error"].as_str().unwrap().contains("administrators"));
    }

    #[tokio::test]
    async fn filters_by_user_and_by_failure() {
        let state = test_state().await;
        add(&state, AuditEvent::new(actions::LOGIN).username("alice")).await;
        add(&state, AuditEvent::new(actions::LOGIN).username("alice").failed()).await;
        add(&state, AuditEvent::new(actions::LOGIN).username("bob").failed()).await;

        let mut p = params();
        p.username = Some("alice".into());
        let body = body_json(call(&state, p).await).await;
        assert_eq!(body["total"], 2);

        let mut p = params();
        p.success = Some(false);
        let body = body_json(call(&state, p).await).await;
        assert_eq!(body["total"], 2);

        let mut p = params();
        p.username = Some("alice".into());
        p.success = Some(false);
        p.action = Some("auth.login".into());
        let body = body_json(call(&state, p).await).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["entries"][0]["success"], false);
    }

    #[tokio::test]
    async fn paging_returns_a_slice_but_the_total_of_everything() {
        let state = test_state().await;
        for _ in 0..5 {
            add(&state, AuditEvent::new(actions::LOGIN)).await;
        }

        let mut p = params();
        p.limit = Some(2);
        p.offset = Some(4);
        let body = body_json(call(&state, p).await).await;

        assert_eq!(body["total"], 5);
        assert_eq!(body["limit"], 2);
        assert_eq!(body["offset"], 4);
        assert_eq!(body["entries"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn the_reported_page_size_is_the_one_actually_used() {
        let state = test_state().await;

        let mut p = params();
        p.limit = Some(100_000);
        p.offset = Some(-9);
        let body = body_json(call(&state, p).await).await;

        assert_eq!(body["limit"], 500);
        assert_eq!(body["offset"], 0);
    }

    #[tokio::test]
    async fn a_time_range_that_runs_backwards_is_a_bad_request() {
        let state = test_state().await;

        let mut p = params();
        p.since = Some(2_000);
        p.until = Some(1_000);

        let response = call(&state, p).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn empty_filter_values_mean_no_filter() {
        let state = test_state().await;
        add(&state, AuditEvent::new(actions::LOGIN).username("alice")).await;

        let mut p = params();
        p.username = Some("".into());
        p.action = Some("   ".into());
        let body = body_json(call(&state, p).await).await;

        assert_eq!(body["total"], 1);
    }

    #[test]
    fn the_query_string_is_read_the_way_the_docs_say() {
        let parsed: AuditParams = serde_json::from_value(json!({
            "username": "admin",
            "success": false,
            "limit": 25
        }))
        .unwrap();

        let filter = parsed.into_filter();
        assert_eq!(filter.username.as_deref(), Some("admin"));
        assert_eq!(filter.success, Some(false));
        assert_eq!(filter.limit, Some(25));
        assert_eq!(filter.action, None);
    }
}
