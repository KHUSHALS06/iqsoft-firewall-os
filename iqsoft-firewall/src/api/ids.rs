use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    app_state::AppState,
    ids::{
        commit::{self, SuricataStatus},
        config::SuricataFiles,
        rules::{self, RuleFileInfo, RuleUpdateStatus},
        scheduler,
    },
    models::ids::{IdsRuleOverride, IdsSettings},
    services::ids_service::IdsService,
};

// Saving the settings only stores them. Nothing about Suricata or the IPS queue rules changes
// until `POST /api/ids/apply` is called, the same way firewall rules wait for a commit.
// The same goes for rule overrides: they are written into Suricata's rule files the next time
// the signatures are updated (`POST /api/ids/rules/update`) or settings are applied.

/// Applying can take a minute or more (Suricata loads its signatures), so two at once would
/// only fight each other.
static APPLY_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn server_error(e: String) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": e })),
    )
}

fn bad_request(e: String) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": e })))
}

// ---------- settings ----------

pub async fn get_settings(State(state): State<AppState>) -> impl IntoResponse {
    match IdsService::get_settings(&state.db).await {
        Ok(settings) => (StatusCode::OK, Json(json!(settings))),
        Err(e) => server_error(e),
    }
}

pub async fn set_settings(
    State(state): State<AppState>,
    Json(settings): Json<IdsSettings>,
) -> impl IntoResponse {
    match IdsService::set_settings(&state.db, settings).await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "note": "Settings saved. Apply them to put them into effect."
            })),
        ),
        Err(e) => bad_request(e),
    }
}

// ---------- rule overrides (switch single signatures off, to alert-only, or to drop) ----------

pub async fn list_overrides(State(state): State<AppState>) -> impl IntoResponse {
    match IdsService::list_overrides(&state.db).await {
        Ok(overrides) => (StatusCode::OK, Json(json!(overrides))),
        Err(e) => server_error(e),
    }
}

pub async fn add_override(
    State(state): State<AppState>,
    Json(rule): Json<IdsRuleOverride>,
) -> impl IntoResponse {
    match IdsService::add_override(&state.db, rule).await {
        Ok(id) => (StatusCode::OK, Json(json!({ "status": "ok", "id": id }))),
        Err(e) => bad_request(e),
    }
}

pub async fn delete_override(
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match IdsService::delete_override(&state.db, id).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => bad_request(e),
    }
}

// ---------- events ----------

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub action: Option<String>,
    pub sid: Option<i64>,
}

pub async fn list_events(
    State(state): State<AppState>,
    Query(query): Query<EventsQuery>,
) -> impl IntoResponse {
    match IdsService::list_events(&state.db, query.limit, query.offset, query.action, query.sid)
        .await
    {
        Ok(events) => (StatusCode::OK, Json(json!(events))),
        Err(e) => bad_request(e),
    }
}

pub async fn clear_events(State(state): State<AppState>) -> impl IntoResponse {
    match IdsService::clear_events(&state.db).await {
        Ok(deleted) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "deleted": deleted })),
        ),
        Err(e) => server_error(e),
    }
}

pub async fn summary(State(state): State<AppState>) -> impl IntoResponse {
    match IdsService::summary(&state.db).await {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))),
        Err(e) => server_error(e),
    }
}

// ---------- status ----------

#[derive(Debug, Serialize)]
struct IdsStatus {
    enabled: bool,
    mode: String,
    suricata: SuricataStatus,
    rules: RuleFileInfo,
    last_rule_update: Option<RuleUpdateStatus>,
}

/// Live health: is Suricata installed, running and ready, how many signatures are loaded,
/// and how the last signature update went.
pub async fn status(State(state): State<AppState>) -> impl IntoResponse {
    let settings = match IdsService::get_settings(&state.db).await {
        Ok(settings) => settings,
        Err(e) => return server_error(e),
    };

    let suricata = commit::status().await;
    let rules = rules::rule_file_info(&SuricataFiles::default()).await;

    let report = IdsStatus {
        enabled: settings.enabled,
        mode: settings.mode,
        suricata,
        rules,
        last_rule_update: rules::last_update(),
    };

    (StatusCode::OK, Json(json!(report)))
}

// ---------- actions ----------

/// Puts the saved settings into effect: writes and tests the Suricata configuration,
/// (re)starts Suricata and applies the IPS queue rules. Can take a minute or more.
pub async fn apply(State(state): State<AppState>) -> impl IntoResponse {
    let Ok(_guard) = APPLY_LOCK.try_lock() else {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "IDS/IPS is already being applied" })),
        );
    };

    match commit::apply(&state.db, &state.commit_lock).await {
        Ok(message) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "message": message })),
        ),
        Err(e) => server_error(e),
    }
}

/// Downloads the newest signatures and tells a running Suricata to load them.
pub async fn update_rules(State(state): State<AppState>) -> impl IntoResponse {
    match scheduler::update_and_reload(&state.db).await {
        Ok(status) => (StatusCode::OK, Json(json!(status))),
        Err(e) if e.contains("already running") => (
            StatusCode::CONFLICT,
            Json(json!({ "error": e })),
        ),
        Err(e) => server_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::init::initialize_database,
        firewall::safe_commit::SafeCommit,
        models::ids::IdsEvent,
        services::login_throttle::LoginThrottle,
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

    async fn body_json(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn defaults() -> IdsSettings {
        serde_json::from_str("{}").unwrap()
    }

    fn event(sid: i64, action: &str) -> IdsEvent {
        IdsEvent {
            id: None,
            ts: 0,
            src_ip: "10.0.0.5".into(),
            src_port: Some(51_000),
            dest_ip: "203.0.113.9".into(),
            dest_port: Some(80),
            proto: "TCP".into(),
            app_proto: Some("http".into()),
            sid,
            signature: format!("Signature {}", sid),
            category: None,
            severity: 2,
            action: action.into(),
        }
    }

    fn rule(sid: i64, action: &str) -> IdsRuleOverride {
        IdsRuleOverride {
            id: None,
            sid,
            action: action.into(),
            comment: None,
        }
    }

    fn query(action: Option<&str>, sid: Option<i64>) -> EventsQuery {
        EventsQuery {
            limit: None,
            offset: None,
            action: action.map(str::to_string),
            sid,
        }
    }

    #[tokio::test]
    async fn settings_start_switched_off_and_can_be_changed() {
        let state = test_state().await;

        let response = get_settings(State(state.clone())).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["enabled"], false);
        assert_eq!(body["mode"], "ids");

        let mut settings = defaults();
        settings.enabled = true;
        settings.mode = "ips".into();
        settings.interfaces = "eth0".into();

        let response = set_settings(State(state.clone()), Json(settings))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = body_json(get_settings(State(state)).await.into_response()).await;
        assert_eq!(body["enabled"], true);
        assert_eq!(body["mode"], "ips");
        assert_eq!(body["interfaces"], "eth0");
    }

    #[tokio::test]
    async fn bad_settings_are_refused_with_a_message() {
        let state = test_state().await;

        let mut settings = defaults();
        settings.mode = "block".into();

        let response = set_settings(State(state.clone()), Json(settings))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(body_json(response).await["error"]
            .as_str()
            .unwrap()
            .contains("Mode"));

        let body = body_json(get_settings(State(state)).await.into_response()).await;
        assert_eq!(body["mode"], "ids");
    }

    #[tokio::test]
    async fn rule_overrides_can_be_added_listed_and_removed() {
        let state = test_state().await;

        let response = add_override(State(state.clone()), Json(rule(2_100_498, "disable")))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let id = body_json(response).await["id"].as_i64().unwrap();

        let duplicate = add_override(State(state.clone()), Json(rule(2_100_498, "drop")))
            .await
            .into_response();
        assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);

        let invalid = add_override(State(state.clone()), Json(rule(0, "drop")))
            .await
            .into_response();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

        let list = body_json(list_overrides(State(state.clone())).await.into_response()).await;
        assert_eq!(list.as_array().unwrap().len(), 1);
        assert_eq!(list[0]["sid"], 2_100_498);
        assert_eq!(list[0]["action"], "disable");

        let response = delete_override(Path(id), State(state.clone()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let missing = delete_override(Path(id), State(state.clone()))
            .await
            .into_response();
        assert_eq!(missing.status(), StatusCode::BAD_REQUEST);

        let list = body_json(list_overrides(State(state)).await.into_response()).await;
        assert!(list.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn events_can_be_filtered_summarised_and_cleared() {
        let state = test_state().await;

        IdsService::record_events(
            &state.db,
            vec![event(1, "allowed"), event(2, "blocked"), event(2, "blocked")],
        )
        .await
        .unwrap();

        let all = body_json(
            list_events(State(state.clone()), Query(query(None, None)))
                .await
                .into_response(),
        )
        .await;
        assert_eq!(all.as_array().unwrap().len(), 3);

        let blocked = body_json(
            list_events(State(state.clone()), Query(query(Some("blocked"), None)))
                .await
                .into_response(),
        )
        .await;
        assert_eq!(blocked.as_array().unwrap().len(), 2);

        let one_signature = body_json(
            list_events(State(state.clone()), Query(query(None, Some(1))))
                .await
                .into_response(),
        )
        .await;
        assert_eq!(one_signature.as_array().unwrap().len(), 1);

        let bad = list_events(State(state.clone()), Query(query(Some("dropped"), None)))
            .await
            .into_response();
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

        let summary_body = body_json(summary(State(state.clone())).await.into_response()).await;
        assert_eq!(summary_body["total_events"], 3);
        assert_eq!(summary_body["blocked_24h"], 2);
        assert_eq!(summary_body["alerted_24h"], 1);

        let cleared = body_json(clear_events(State(state.clone())).await.into_response()).await;
        assert_eq!(cleared["deleted"], 3);

        let all = body_json(
            list_events(State(state), Query(query(None, None)))
                .await
                .into_response(),
        )
        .await;
        assert!(all.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_status_report_has_every_part() {
        let state = test_state().await;

        let response = status(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = body_json(response).await;
        assert_eq!(body["enabled"], false);
        assert_eq!(body["mode"], "ids");
        assert!(body["suricata"].get("installed").is_some());
        assert!(body["suricata"].get("running").is_some());
        assert!(body["suricata"].get("ready").is_some());
        assert!(body["rules"].get("rule_count").is_some());
        assert!(body.get("last_rule_update").is_some());
    }

    #[tokio::test]
    async fn applying_reports_errors_and_never_runs_twice_at_once() {
        let state = test_state().await;

        // In test builds nothing touches nft or systemd, so the apply fails with a clear message.
        let response = apply(State(state.clone())).await.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body_json(response).await["error"].as_str().is_some());

        let _held = APPLY_LOCK.lock().await;

        let busy = apply(State(state)).await.into_response();
        assert_eq!(busy.status(), StatusCode::CONFLICT);
    }
}
