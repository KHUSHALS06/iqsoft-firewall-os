use axum::{extract::Query, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::json;

use crate::monitor::{conntrack, counters, interfaces, logs};

#[derive(Debug, Deserialize)]
pub struct ConnectionQuery {
    /// How many connections to return. Default 100, maximum 1000.
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct LogQuery {
    /// How many log entries to return. Default 100, maximum 1000.
    pub limit: Option<usize>,
    /// Only show entries from this firewall rule.
    pub rule_id: Option<i64>,
}

/// GET /api/monitor/interfaces
pub async fn get_interfaces() -> impl IntoResponse {
    match interfaces::read_interfaces() {
        Ok(list) => (StatusCode::OK, Json(json!(list))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

/// GET /api/monitor/connections?limit=50
pub async fn get_connections(Query(query): Query<ConnectionQuery>) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);

    // The connection table can be large, so read it off the async threads.
    let result = tokio::task::spawn_blocking(move || conntrack::read_connections(limit)).await;

    match result {
        Ok(Ok(list)) => (StatusCode::OK, Json(json!(list))),
        Ok(Err(e)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": e })),
        ),
        Err(e) => {
            eprintln!("monitor: connection read task failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal error" })),
            )
        }
    }
}

/// GET /api/monitor/conntrack-usage
pub async fn get_conntrack_usage() -> impl IntoResponse {
    (StatusCode::OK, Json(json!(conntrack::read_usage())))
}

/// GET /api/monitor/rule-counters
pub async fn get_rule_counters() -> impl IntoResponse {
    // Runs the `nft` command, so keep it off the async threads.
    let result = tokio::task::spawn_blocking(counters::read_rule_counters).await;

    match result {
        Ok(Ok(list)) => (StatusCode::OK, Json(json!(list))),
        Ok(Err(e)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": e })),
        ),
        Err(e) => {
            eprintln!("monitor: rule counter read task failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal error" })),
            )
        }
    }
}

/// GET /api/monitor/logs?limit=50&rule_id=15
pub async fn get_logs(Query(query): Query<LogQuery>) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let rule_id = query.rule_id;

    // Runs the `journalctl` command, so keep it off the async threads.
    let result = tokio::task::spawn_blocking(move || logs::read_logs(limit, rule_id)).await;

    match result {
        Ok(Ok(list)) => (StatusCode::OK, Json(json!(list))),
        Ok(Err(e)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": e })),
        ),
        Err(e) => {
            eprintln!("monitor: log read task failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal error" })),
            )
        }
    }
}
