use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use crate::{
    app_state::AppState,
    firewall::{
        generator::FirewallGenerator,
        safe_commit::SafeCommitError,
    },
    models::{auth::User, firewall_rule::FirewallRule},
    services::{
        audit_service::{actions, AuditEvent, AuditService},
        firewall_service::FirewallService,
    },
};

/// The start of every audit event from this file: what happened, who did it, from where.
fn event(action: &str, user: &User, addr: SocketAddr) -> AuditEvent {
    AuditEvent::new(action).user(user).source_ip(addr.ip())
}

/// One line saying what a rule does, for the audit trail.
fn describe_rule(rule: &FirewallRule) -> String {
    let port = if rule.port_any {
        "any".to_string()
    } else {
        rule.dst_port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".to_string())
    };

    format!(
        "'{}' {} {} {} src={} dst={} dport={}{}",
        rule.name,
        rule.chain_name,
        rule.action,
        rule.protocol,
        rule.src_ip.as_deref().unwrap_or("any"),
        rule.dst_ip.as_deref().unwrap_or("any"),
        port,
        if rule.enabled { "" } else { " (disabled)" }
    )
}

pub async fn list_rules(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match FirewallService::list_rules(&state.db).await {
        Ok(rules) => (
            StatusCode::OK,
            Json(json!(rules)),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": e
            })),
        ),
    }
}

pub async fn add_rule(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
    Json(rule): Json<FirewallRule>,
) -> impl IntoResponse {
    let description = describe_rule(&rule);

    match FirewallService::add_rule(&state.db, rule).await {
        Ok(_) => {
            AuditService::record(
                &state.db,
                event(actions::RULE_CREATE, &user, addr).detail(&description),
            )
            .await;

            (
                StatusCode::OK,
                Json(json!({
                    "status": "ok"
                })),
            )
        }
        Err(e) => {
            AuditService::record(
                &state.db,
                event(actions::RULE_CREATE, &user, addr)
                    .detail(&format!("{} - refused: {}", description, e))
                    .failed(),
            )
            .await;

            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": e
                })),
            )
        }
    }
}

pub async fn update_rule(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
    Json(rule): Json<FirewallRule>,
) -> impl IntoResponse {
    let description = describe_rule(&rule);
    let target = format!("rule:{}", id);

    match FirewallService::update_rule(&state.db, id, rule).await {
        Ok(_) => {
            AuditService::record(
                &state.db,
                event(actions::RULE_UPDATE, &user, addr)
                    .target(&target)
                    .detail(&format!("now {}", description)),
            )
            .await;

            (
                StatusCode::OK,
                Json(json!({
                    "status": "ok"
                })),
            )
        }
        Err(e) => {
            AuditService::record(
                &state.db,
                event(actions::RULE_UPDATE, &user, addr)
                    .target(&target)
                    .detail(&format!("{} - refused: {}", description, e))
                    .failed(),
            )
            .await;

            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": e
                })),
            )
        }
    }
}

pub async fn delete_rule(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
) -> impl IntoResponse {
    let target = format!("rule:{}", id);

    // Look the rule up first: once it is deleted, the trail would otherwise only
    // say "rule:7 was deleted" and nobody could tell what rule 7 used to be.
    let before = match FirewallService::list_rules(&state.db).await {
        Ok(rules) => match rules.iter().find(|r| r.id == Some(id)) {
            Some(rule) => format!("removed {}", describe_rule(rule)),
            None => "no rule with this id existed".to_string(),
        },
        Err(_) => "could not look up the rule before deleting".to_string(),
    };

    match FirewallService::delete_rule(&state.db, id).await {
        Ok(_) => {
            AuditService::record(
                &state.db,
                event(actions::RULE_DELETE, &user, addr)
                    .target(&target)
                    .detail(&before),
            )
            .await;

            (
                StatusCode::OK,
                Json(json!({
                    "status": "ok"
                })),
            )
        }
        Err(e) => {
            AuditService::record(
                &state.db,
                event(actions::RULE_DELETE, &user, addr)
                    .target(&target)
                    .detail(&format!("refused: {}", e))
                    .failed(),
            )
            .await;

            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": e
                })),
            )
        }
    }
}

pub async fn generate_config(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match FirewallGenerator::generate(&state.db).await {
        Ok(config) => (
            StatusCode::OK,
            Json(json!({
                "config": config
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": e
            })),
        ),
    }
}

#[derive(Deserialize)]
pub struct CommitParams {
    pub confirm_within: Option<u64>,
}

pub async fn commit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
    Query(params): Query<CommitParams>,
) -> impl IntoResponse {
    let window = match params.confirm_within {
        Some(seconds) => format!("confirm within {}s", seconds),
        None => "no confirmation window".to_string(),
    };

    match state
        .safe_commit
        .commit(&state.db, &state.commit_lock, params.confirm_within)
        .await
    {
        Ok(message) => {
            AuditService::record(
                &state.db,
                event(actions::COMMIT, &user, addr).detail(&window),
            )
            .await;

            (
                StatusCode::OK,
                Json(json!({
                    "status": "ok",
                    "message": message
                })),
            )
        }
        Err(SafeCommitError::Pending(seconds_left)) => {
            AuditService::record(
                &state.db,
                event(actions::COMMIT, &user, addr)
                    .detail("refused: another commit is still waiting for confirmation")
                    .failed(),
            )
            .await;

            (
                StatusCode::CONFLICT,
                Json(json!({
                    "status": "error",
                    "message": "A commit is waiting for confirmation. Confirm it or wait for the automatic rollback.",
                    "seconds_left": seconds_left
                })),
            )
        }
        Err(SafeCommitError::Invalid(message)) | Err(SafeCommitError::Failed(message)) => {
            AuditService::record(
                &state.db,
                event(actions::COMMIT, &user, addr)
                    .detail(&format!("{} - failed: {}", window, message))
                    .failed(),
            )
            .await;

            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": "error",
                    "message": message
                })),
            )
        }
    }
}

pub async fn confirm_commit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
) -> impl IntoResponse {
    match state.safe_commit.confirm().await {
        Ok(message) => {
            AuditService::record(&state.db, event(actions::COMMIT_CONFIRM, &user, addr)).await;

            (
                StatusCode::OK,
                Json(json!({
                    "status": "ok",
                    "message": message
                })),
            )
        }
        Err(e) => {
            AuditService::record(
                &state.db,
                event(actions::COMMIT_CONFIRM, &user, addr)
                    .detail(&e)
                    .failed(),
            )
            .await;

            (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "status": "error",
                    "message": e
                })),
            )
        }
    }
}

pub async fn commit_status(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.safe_commit.seconds_left().await {
        Some(seconds_left) => Json(json!({
            "pending": true,
            "seconds_left": seconds_left
        })),
        None => Json(json!({
            "pending": false
        })),
    }
}

pub async fn rollback(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
) -> impl IntoResponse {
    match state
        .safe_commit
        .rollback(&state.db, &state.commit_lock)
        .await
    {
        Ok(message) => {
            AuditService::record(&state.db, event(actions::ROLLBACK, &user, addr)).await;

            (
                StatusCode::OK,
                Json(json!({
                    "status": "ok",
                    "message": message
                })),
            )
        }
        Err(e) => {
            AuditService::record(
                &state.db,
                event(actions::ROLLBACK, &user, addr)
                    .detail(&e)
                    .failed(),
            )
            .await;

            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": "error",
                    "message": e
                })),
            )
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

    fn admin() -> Extension<User> {
        Extension(User {
            id: 7,
            username: "admin".into(),
            password_hash: "not-a-real-hash".into(),
            role: "admin".into(),
        })
    }

    fn rule(src: Option<&str>) -> FirewallRule {
        FirewallRule {
            id: None,
            name: "web in".into(),
            enabled: true,
            priority: 100,
            chain_name: "FORWARD".into(),
            action: "accept".into(),
            protocol: "tcp".into(),
            src_ip: src.map(String::from),
            dst_ip: None,
            src_port: None,
            dst_port: Some(443),
            port_any: false,
            interface_name: None,
            src_mac: None,
            time_start: None,
            time_end: None,
            days: None,
            rate_limit: None,
            log_enabled: false,
            comment: None,
        }
    }

    async fn trail(state: &AppState) -> Vec<AuditEntry> {
        AuditService::list(&state.db, &AuditFilter::default())
            .await
            .unwrap()
    }

    async fn first_rule_id(state: &AppState) -> i64 {
        FirewallService::list_rules(&state.db).await.unwrap()[0]
            .id
            .unwrap()
    }

    #[test]
    fn a_rule_is_described_in_one_readable_line() {
        let mut r = rule(Some("10.0.0.0/24"));
        assert_eq!(
            describe_rule(&r),
            "'web in' FORWARD accept tcp src=10.0.0.0/24 dst=any dport=443"
        );

        r.enabled = false;
        r.port_any = true;
        r.dst_port = None;
        assert_eq!(
            describe_rule(&r),
            "'web in' FORWARD accept tcp src=10.0.0.0/24 dst=any dport=any (disabled)"
        );

        r.port_any = false;
        assert!(describe_rule(&r).contains("dport=-"));
    }

    #[tokio::test]
    async fn adding_a_rule_is_audited_with_who_and_what() {
        let state = test_state().await;

        let response = add_rule(State(state.clone()), peer(), admin(), Json(rule(None)))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let rows = trail(&state).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "rule.create");
        assert_eq!(rows[0].user_id, Some(7));
        assert_eq!(rows[0].source_ip.as_deref(), Some("10.1.2.3"));
        assert!(rows[0].success);
        assert!(rows[0].detail.as_deref().unwrap().contains("'web in' FORWARD accept tcp"));
    }

    #[tokio::test]
    async fn a_refused_rule_is_audited_as_a_failure_with_the_reason() {
        let state = test_state().await;

        let response = add_rule(
            State(state.clone()),
            peer(),
            admin(),
            Json(rule(Some("10.0.0.256"))),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let rows = trail(&state).await;
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].success);
        assert!(rows[0].detail.as_deref().unwrap().contains("refused"));
        assert!(rows[0].detail.as_deref().unwrap().contains("10.0.0.256"));
        assert!(FirewallService::list_rules(&state.db).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn updating_a_rule_is_audited_against_its_id() {
        let state = test_state().await;
        FirewallService::add_rule(&state.db, rule(None)).await.unwrap();
        let id = first_rule_id(&state).await;

        let response = update_rule(
            Path(id),
            State(state.clone()),
            peer(),
            admin(),
            Json(rule(Some("192.168.1.0/24"))),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let rows = trail(&state).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "rule.update");
        assert_eq!(rows[0].target, Some(format!("rule:{}", id)));
        assert!(rows[0].detail.as_deref().unwrap().contains("src=192.168.1.0/24"));
    }

    #[tokio::test]
    async fn a_refused_update_is_audited_as_a_failure() {
        let state = test_state().await;
        FirewallService::add_rule(&state.db, rule(None)).await.unwrap();
        let id = first_rule_id(&state).await;

        let response = update_rule(
            Path(id),
            State(state.clone()),
            peer(),
            admin(),
            Json(rule(Some("nonsense"))),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let rows = trail(&state).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "rule.update");
        assert!(!rows[0].success);
    }

    #[tokio::test]
    async fn deleting_a_rule_records_what_the_rule_was() {
        let state = test_state().await;
        FirewallService::add_rule(&state.db, rule(Some("10.0.0.5"))).await.unwrap();
        let id = first_rule_id(&state).await;

        let response = delete_rule(Path(id), State(state.clone()), peer(), admin())
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(FirewallService::list_rules(&state.db).await.unwrap().is_empty());

        let rows = trail(&state).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "rule.delete");
        assert_eq!(rows[0].target, Some(format!("rule:{}", id)));
        let detail = rows[0].detail.as_deref().unwrap();
        assert!(detail.starts_with("removed 'web in'"), "{}", detail);
        assert!(detail.contains("src=10.0.0.5"), "{}", detail);
    }

    #[tokio::test]
    async fn deleting_a_missing_rule_says_so_in_the_trail() {
        let state = test_state().await;

        let response = delete_rule(Path(999), State(state.clone()), peer(), admin())
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let rows = trail(&state).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].detail.as_deref(), Some("no rule with this id existed"));
    }

    #[tokio::test]
    async fn confirming_when_nothing_is_pending_is_audited_as_a_failure() {
        let state = test_state().await;

        let response = confirm_commit(State(state.clone()), peer(), admin())
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let rows = trail(&state).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "firewall.commit_confirm");
        assert_eq!(rows[0].user_id, Some(7));
        assert!(!rows[0].success);
        assert_eq!(
            rows[0].detail.as_deref(),
            Some("No commit is waiting for confirmation")
        );
    }
}
