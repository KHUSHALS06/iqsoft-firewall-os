use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::{
    app_state::AppState,
    models::sdwan::{SdwanLink, SdwanRule, SdwanSettings},
    sdwan::{commit::SdwanCommit, generator::SdwanGenerator, monitor},
    services::sdwan_service::SdwanService,
};

// Everything here only changes the saved configuration. Nothing about the live routing changes
// until `POST /api/sdwan/commit`, the same way firewall rules wait for a commit. After the first
// commit the health monitor (sdwan/monitor.rs) keeps the routing in step with link failures by
// itself, so a link going down does not need anyone to press a button.

fn server_error(e: String) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": e })),
    )
}

fn bad_request(e: String) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": e })))
}

// ---------- settings (the master switch) ----------

pub async fn get_settings(State(state): State<AppState>) -> impl IntoResponse {
    match SdwanService::get_settings(&state.db).await {
        Ok(settings) => (StatusCode::OK, Json(json!(settings))),
        Err(e) => server_error(e),
    }
}

pub async fn set_settings(
    State(state): State<AppState>,
    Json(settings): Json<SdwanSettings>,
) -> impl IntoResponse {
    match SdwanService::set_enabled(&state.db, settings.enabled).await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "note": "Saved. Commit SD-WAN to put it into effect."
            })),
        ),
        Err(e) => bad_request(e),
    }
}

// ---------- WAN links ----------

pub async fn list_links(State(state): State<AppState>) -> impl IntoResponse {
    match SdwanService::list_links(&state.db).await {
        Ok(links) => (StatusCode::OK, Json(json!(links))),
        Err(e) => server_error(e),
    }
}

pub async fn add_link(
    State(state): State<AppState>,
    Json(link): Json<SdwanLink>,
) -> impl IntoResponse {
    match SdwanService::add_link(&state.db, link).await {
        Ok(id) => (StatusCode::OK, Json(json!({ "status": "ok", "id": id }))),
        Err(e) => bad_request(e),
    }
}

pub async fn update_link(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(link): Json<SdwanLink>,
) -> impl IntoResponse {
    match SdwanService::update_link(&state.db, id, link).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => bad_request(e),
    }
}

pub async fn delete_link(
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match SdwanService::delete_link(&state.db, id).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => bad_request(e),
    }
}

// ---------- rules (which traffic goes out of which link) ----------

pub async fn list_rules(State(state): State<AppState>) -> impl IntoResponse {
    match SdwanService::list_rules(&state.db).await {
        Ok(rules) => (StatusCode::OK, Json(json!(rules))),
        Err(e) => server_error(e),
    }
}

pub async fn add_rule(
    State(state): State<AppState>,
    Json(rule): Json<SdwanRule>,
) -> impl IntoResponse {
    match SdwanService::add_rule(&state.db, rule).await {
        Ok(id) => (StatusCode::OK, Json(json!({ "status": "ok", "id": id }))),
        Err(e) => bad_request(e),
    }
}

pub async fn update_rule(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(rule): Json<SdwanRule>,
) -> impl IntoResponse {
    match SdwanService::update_rule(&state.db, id, rule).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => bad_request(e),
    }
}

pub async fn delete_rule(
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match SdwanService::delete_rule(&state.db, id).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => bad_request(e),
    }
}

// ---------- live view ----------

/// The master switch, every link with its live health (up, down or unknown, latency, loss,
/// last check) and how many rules there are.
pub async fn status(State(state): State<AppState>) -> impl IntoResponse {
    let settings = match SdwanService::get_settings(&state.db).await {
        Ok(settings) => settings,
        Err(e) => return server_error(e),
    };

    let links = match SdwanService::list_links(&state.db).await {
        Ok(links) => links,
        Err(e) => return server_error(e),
    };

    let rules = match SdwanService::list_rules(&state.db).await {
        Ok(rules) => rules,
        Err(e) => return server_error(e),
    };

    let count = |wanted: &str| {
        links
            .iter()
            .filter(|link| link.enabled && link.state == wanted)
            .count()
    };

    let report = json!({
        "enabled": settings.enabled,
        "links_up": count("up"),
        "links_down": count("down"),
        "links_unknown": count("unknown"),
        "rules_total": rules.len(),
        "rules_enabled": rules.iter().filter(|rule| rule.enabled).count(),
        "links": links,
    });

    (StatusCode::OK, Json(report))
}

/// Shows what a commit would put into effect: the nftables table and the routing script.
pub async fn generate(State(state): State<AppState>) -> impl IntoResponse {
    match SdwanGenerator::load_input(&state.db).await {
        Ok(input) => (
            StatusCode::OK,
            Json(json!({
                "enabled": input.enabled,
                "marking": SdwanGenerator::render_table(&input),
                "routing": SdwanGenerator::render_ip_apply(&input),
            })),
        ),
        Err(e) => server_error(e),
    }
}

/// "Test the links now": pings every enabled link at once, whatever its interval, and saves
/// the result. Does nothing while SD-WAN is switched off.
pub async fn probe_now(State(state): State<AppState>) -> impl IntoResponse {
    match monitor::probe_now(&state.db).await {
        Ok(result) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "probed": result.probed,
                "changed": result.changed,
            })),
        ),
        Err(e) => server_error(e),
    }
}

// ---------- commit and rollback ----------

pub async fn commit(State(state): State<AppState>) -> impl IntoResponse {
    match SdwanCommit::commit(&state.db, &state.commit_lock).await {
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
    match SdwanCommit::rollback(&state.db, &state.commit_lock).await {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::init::initialize_database,
        firewall::safe_commit::SafeCommit,
        sdwan::generator::TABLE_NAME,
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

    /// Missing fields take their defaults, exactly like a request from the dashboard.
    fn link(name: &str, interface: &str) -> SdwanLink {
        serde_json::from_value(json!({
            "name": name,
            "interface_name": interface,
            "gateway": "10.1.0.1",
        }))
        .unwrap()
    }

    fn web_rule(link_id: i64) -> SdwanRule {
        serde_json::from_value(json!({
            "name": "web",
            "protocol": "tcp",
            "dport_start": 443,
            "dport_end": 443,
            "strategy": "link",
            "link_id": link_id,
        }))
        .unwrap()
    }

    async fn add_link_ok(state: &AppState, name: &str, interface: &str) -> i64 {
        let response = add_link(State(state.clone()), Json(link(name, interface)))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        body_json(response).await["id"].as_i64().unwrap()
    }

    #[tokio::test]
    async fn sdwan_starts_off_and_needs_a_link_before_it_can_be_switched_on() {
        let state = test_state().await;

        let body = body_json(get_settings(State(state.clone())).await.into_response()).await;
        assert_eq!(body["enabled"], false);

        let refused = set_settings(State(state.clone()), Json(SdwanSettings { enabled: true }))
            .await
            .into_response();
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert!(body_json(refused).await["error"]
            .as_str()
            .unwrap()
            .contains("at least one enabled WAN link"));

        add_link_ok(&state, "ISP1", "eth0").await;

        let accepted = set_settings(State(state.clone()), Json(SdwanSettings { enabled: true }))
            .await
            .into_response();
        assert_eq!(accepted.status(), StatusCode::OK);

        let body = body_json(get_settings(State(state.clone())).await.into_response()).await;
        assert_eq!(body["enabled"], true);

        // Switching off is always allowed.
        let off = set_settings(State(state), Json(SdwanSettings { enabled: false }))
            .await
            .into_response();
        assert_eq!(off.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn links_can_be_added_listed_changed_and_removed() {
        let state = test_state().await;

        let id = add_link_ok(&state, "ISP1", "eth0").await;

        let same_name = add_link(State(state.clone()), Json(link("ISP1", "eth2")))
            .await
            .into_response();
        assert_eq!(same_name.status(), StatusCode::BAD_REQUEST);

        let same_interface = add_link(State(state.clone()), Json(link("ISP2", "eth0")))
            .await
            .into_response();
        assert_eq!(same_interface.status(), StatusCode::BAD_REQUEST);

        let list = body_json(list_links(State(state.clone())).await.into_response()).await;
        assert_eq!(list.as_array().unwrap().len(), 1);
        assert_eq!(list[0]["name"], "ISP1");
        assert_eq!(list[0]["state"], "unknown");
        assert_eq!(list[0]["priority"], 10);

        let mut changed = link("ISP1", "eth0");
        changed.priority = 5;

        let response = update_link(Path(id), State(state.clone()), Json(changed))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let list = body_json(list_links(State(state.clone())).await.into_response()).await;
        assert_eq!(list[0]["priority"], 5);

        let missing = update_link(Path(id + 100), State(state.clone()), Json(link("X", "eth5")))
            .await
            .into_response();
        assert_eq!(missing.status(), StatusCode::BAD_REQUEST);

        let response = delete_link(Path(id), State(state.clone())).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let list = body_json(list_links(State(state)).await.into_response()).await;
        assert!(list.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_bad_link_is_refused_with_a_message() {
        let state = test_state().await;

        let mut bad = link("ISP1", "eth0");
        bad.probe_target = "not-an-address".to_string();

        let response = add_link(State(state.clone()), Json(bad)).await.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(body_json(response).await["error"]
            .as_str()
            .unwrap()
            .contains("Probe target"));

        let list = body_json(list_links(State(state)).await.into_response()).await;
        assert!(list.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn rules_can_be_managed_and_protect_the_link_they_use() {
        let state = test_state().await;
        let link_id = add_link_ok(&state, "ISP1", "eth0").await;

        let response = add_rule(State(state.clone()), Json(web_rule(link_id)))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let rule_id = body_json(response).await["id"].as_i64().unwrap();

        // A "link" rule must name a link that exists, and ports only go with tcp or udp.
        let mut no_link = web_rule(link_id);
        no_link.link_id = None;
        let response = add_rule(State(state.clone()), Json(no_link)).await.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut icmp_ports = web_rule(link_id);
        icmp_ports.name = "icmp".to_string();
        icmp_ports.protocol = "icmp".to_string();
        let response = add_rule(State(state.clone()), Json(icmp_ports)).await.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let list = body_json(list_rules(State(state.clone())).await.into_response()).await;
        assert_eq!(list.as_array().unwrap().len(), 1);
        assert_eq!(list[0]["name"], "web");
        assert_eq!(list[0]["dport_start"], 443);

        // The link cannot be deleted while a rule uses it.
        let blocked = delete_link(Path(link_id), State(state.clone())).await.into_response();
        assert_eq!(blocked.status(), StatusCode::BAD_REQUEST);
        assert!(body_json(blocked).await["error"]
            .as_str()
            .unwrap()
            .contains("used by"));

        let mut renamed = web_rule(link_id);
        renamed.name = "web-secure".to_string();
        let response = update_rule(Path(rule_id), State(state.clone()), Json(renamed))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let list = body_json(list_rules(State(state.clone())).await.into_response()).await;
        assert_eq!(list[0]["name"], "web-secure");

        let response = delete_rule(Path(rule_id), State(state.clone())).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let missing = delete_rule(Path(rule_id), State(state.clone())).await.into_response();
        assert_eq!(missing.status(), StatusCode::BAD_REQUEST);

        let response = delete_link(Path(link_id), State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn the_status_report_counts_links_by_state() {
        let state = test_state().await;

        let body = body_json(status(State(state.clone())).await.into_response()).await;
        assert_eq!(body["enabled"], false);
        assert_eq!(body["links_up"], 0);
        assert_eq!(body["rules_total"], 0);

        let first = add_link_ok(&state, "ISP1", "eth0").await;
        add_link_ok(&state, "ISP2", "eth2").await;

        let mut spare = link("Spare", "eth3");
        spare.enabled = false;
        add_link(State(state.clone()), Json(spare)).await.into_response();

        add_rule(State(state.clone()), Json(web_rule(first))).await.into_response();

        let body = body_json(status(State(state)).await.into_response()).await;
        assert_eq!(body["links"].as_array().unwrap().len(), 3);
        // Only enabled links are counted, and none has been pinged yet.
        assert_eq!(body["links_unknown"], 2);
        assert_eq!(body["links_up"], 0);
        assert_eq!(body["links_down"], 0);
        assert_eq!(body["rules_total"], 1);
        assert_eq!(body["rules_enabled"], 1);
    }

    #[tokio::test]
    async fn the_preview_is_empty_while_off_and_shows_the_table_once_on() {
        let state = test_state().await;
        add_link_ok(&state, "ISP1", "eth0").await;

        let body = body_json(generate(State(state.clone())).await.into_response()).await;
        assert_eq!(body["enabled"], false);
        assert_eq!(body["marking"], "");

        set_settings(State(state.clone()), Json(SdwanSettings { enabled: true }))
            .await
            .into_response();

        let body = body_json(generate(State(state)).await.into_response()).await;
        assert_eq!(body["enabled"], true);
        assert!(body["marking"].as_str().unwrap().contains(TABLE_NAME));
        assert!(!body["routing"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn testing_the_links_does_nothing_while_sdwan_is_off() {
        let state = test_state().await;
        add_link_ok(&state, "ISP1", "eth0").await;

        let body = body_json(probe_now(State(state)).await.into_response()).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["probed"], 0);
        assert_eq!(body["changed"], 0);
    }
}
