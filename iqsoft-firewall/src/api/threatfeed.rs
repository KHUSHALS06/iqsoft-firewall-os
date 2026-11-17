use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;

use crate::{
    app_state::AppState,
    models::{
        auth::User,
        threatfeed::{ThreatFeed, ThreatImportRequest, PRESETS},
    },
    services::{
        audit_service::{AuditEvent, AuditService},
        threatfeed_service::ThreatFeedService,
    },
    threatintel::{generator, refresh},
};

const FEED_CREATE: &str = "threatfeed.create";
const FEED_UPDATE: &str = "threatfeed.update";
const FEED_DELETE: &str = "threatfeed.delete";
const FEED_IMPORT: &str = "threatfeed.import";
const FEED_REFRESH: &str = "threatfeed.refresh";
const FEED_APPLY: &str = "threatfeed.apply";

fn event(action: &str, user: &User, addr: SocketAddr) -> AuditEvent {
    AuditEvent::new(action).user(user).source_ip(addr.ip())
}

fn bad_request(message: String) -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": message })))
}

fn not_found_or_bad(message: String) -> (StatusCode, Json<Value>) {
    if message.contains("does not exist") {
        (StatusCode::NOT_FOUND, Json(json!({ "error": message })))
    } else {
        bad_request(message)
    }
}

/// Puts the current blocklists into the kernel and says how that went. A failure here never fails
/// the request: the change is saved, and the next full commit or refresh applies it.
async fn apply(state: &AppState) -> (bool, Option<String>) {
    match generator::apply_live(&state.db, &state.commit_lock).await {
        Ok(()) => (true, None),
        Err(e) => {
            eprintln!("threat feeds: could not apply the blocklists: {}", e);
            (false, Some(e))
        }
    }
}

/// GET /api/threatfeeds
pub async fn list_feeds(State(state): State<AppState>) -> impl IntoResponse {
    match ThreatFeedService::list(&state.db).await {
        Ok(feeds) => (StatusCode::OK, Json(json!(feeds))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

/// GET /api/threatfeeds/presets
/// Well-known free blocklists, ready to be added as a normal feed.
pub async fn list_presets() -> impl IntoResponse {
    (StatusCode::OK, Json(json!(PRESETS)))
}

/// POST /api/threatfeeds
pub async fn add_feed(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
    Json(feed): Json<ThreatFeed>,
) -> impl IntoResponse {
    let description = format!(
        "'{}' {} {}",
        feed.name.trim(),
        feed.kind.trim(),
        feed.url.as_deref().unwrap_or("")
    );

    match ThreatFeedService::add(&state.db, feed).await {
        Ok(id) => {
            AuditService::record(
                &state.db,
                event(FEED_CREATE, &user, addr)
                    .target(&format!("threatfeed:{}", id))
                    .detail(&description),
            )
            .await;

            (StatusCode::OK, Json(json!({ "status": "ok", "id": id })))
        }
        Err(e) => {
            AuditService::record(
                &state.db,
                event(FEED_CREATE, &user, addr)
                    .detail(&format!("{} - refused: {}", description, e))
                    .failed(),
            )
            .await;

            bad_request(e)
        }
    }
}

/// PUT /api/threatfeeds/{id}
/// Changes the settings of a feed. Switching a feed on or off takes effect at once.
pub async fn update_feed(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
    Json(feed): Json<ThreatFeed>,
) -> impl IntoResponse {
    let description = format!(
        "'{}' {}{}",
        feed.name.trim(),
        feed.direction.trim(),
        if feed.enabled { "" } else { " (disabled)" }
    );

    match ThreatFeedService::update(&state.db, id, feed).await {
        Ok(()) => {
            AuditService::record(
                &state.db,
                event(FEED_UPDATE, &user, addr)
                    .target(&format!("threatfeed:{}", id))
                    .detail(&description),
            )
            .await;

            let (applied, apply_error) = apply(&state).await;

            (
                StatusCode::OK,
                Json(json!({ "status": "ok", "applied": applied, "apply_error": apply_error })),
            )
        }
        Err(e) => {
            AuditService::record(
                &state.db,
                event(FEED_UPDATE, &user, addr)
                    .target(&format!("threatfeed:{}", id))
                    .detail(&format!("{} - refused: {}", description, e))
                    .failed(),
            )
            .await;

            not_found_or_bad(e)
        }
    }
}

/// DELETE /api/threatfeeds/{id}
pub async fn delete_feed(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
) -> impl IntoResponse {
    match ThreatFeedService::delete(&state.db, id).await {
        Ok(()) => {
            AuditService::record(
                &state.db,
                event(FEED_DELETE, &user, addr).target(&format!("threatfeed:{}", id)),
            )
            .await;

            let (applied, apply_error) = apply(&state).await;

            (
                StatusCode::OK,
                Json(json!({ "status": "ok", "applied": applied, "apply_error": apply_error })),
            )
        }
        Err(e) => {
            AuditService::record(
                &state.db,
                event(FEED_DELETE, &user, addr)
                    .target(&format!("threatfeed:{}", id))
                    .detail(&format!("refused: {}", e))
                    .failed(),
            )
            .await;

            not_found_or_bad(e)
        }
    }
}

/// POST /api/threatfeeds/{id}/refresh
/// Downloads the feed now instead of waiting for its schedule.
pub async fn refresh_feed(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
) -> impl IntoResponse {
    match refresh::refresh_feed(&state.db, &state.commit_lock, id).await {
        Ok(outcome) => {
            AuditService::record(
                &state.db,
                event(FEED_REFRESH, &user, addr)
                    .target(&format!("threatfeed:{}", id))
                    .detail(&format!(
                        "{} IPv4, {} IPv6 networks",
                        outcome.result.ipv4_imported, outcome.result.ipv6_imported
                    )),
            )
            .await;

            (
                StatusCode::OK,
                Json(json!({
                    "status": "ok",
                    "ipv4_imported": outcome.result.ipv4_imported,
                    "ipv6_imported": outcome.result.ipv6_imported,
                    "skipped": outcome.result.skipped,
                    "applied": outcome.applied,
                    "apply_error": outcome.apply_error
                })),
            )
        }
        Err(e) => {
            AuditService::record(
                &state.db,
                event(FEED_REFRESH, &user, addr)
                    .target(&format!("threatfeed:{}", id))
                    .detail(&format!("failed: {}", e))
                    .failed(),
            )
            .await;

            not_found_or_bad(e)
        }
    }
}

/// PUT /api/threatfeeds/{id}/entries   body: {"data": "<one address or network per line>", "mode": "append" | "replace"}
/// Manual IOC import into a manual feed.
pub async fn import_entries(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
    Json(request): Json<ThreatImportRequest>,
) -> impl IntoResponse {
    match ThreatFeedService::import(&state.db, id, request).await {
        Ok(result) => {
            AuditService::record(
                &state.db,
                event(FEED_IMPORT, &user, addr)
                    .target(&format!("threatfeed:{}", id))
                    .detail(&format!(
                        "{} IPv4, {} IPv6 networks imported, {} skipped",
                        result.ipv4_imported, result.ipv6_imported, result.skipped
                    )),
            )
            .await;

            let (applied, apply_error) = apply(&state).await;

            let mut body = json!(result);
            body["applied"] = json!(applied);
            body["apply_error"] = json!(apply_error);

            (StatusCode::OK, Json(body))
        }
        Err(e) => {
            AuditService::record(
                &state.db,
                event(FEED_IMPORT, &user, addr)
                    .target(&format!("threatfeed:{}", id))
                    .detail(&format!("refused: {}", e))
                    .failed(),
            )
            .await;

            not_found_or_bad(e)
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct EntriesParams {
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// GET /api/threatfeeds/{id}/entries?search=1.2.&limit=100&offset=0
pub async fn list_entries(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Query(params): Query<EntriesParams>,
) -> impl IntoResponse {
    match ThreatFeedService::entries(&state.db, id, params.search, params.limit, params.offset).await
    {
        Ok((total, limit, offset, entries)) => (
            StatusCode::OK,
            Json(json!({
                "total": total,
                "limit": limit,
                "offset": offset,
                "entries": entries
            })),
        ),
        Err(e) => not_found_or_bad(e),
    }
}

/// POST /api/threatfeeds/apply
/// Puts the stored blocklists into the kernel again, for example after an error.
pub async fn apply_now(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
) -> impl IntoResponse {
    let (applied, apply_error) = apply(&state).await;

    let mut audit = event(FEED_APPLY, &user, addr);
    if let Some(error) = &apply_error {
        audit = audit.detail(error).failed();
    }
    AuditService::record(&state.db, audit).await;

    if applied {
        (StatusCode::OK, Json(json!({ "status": "ok", "applied": true })))
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": apply_error.unwrap_or_default(), "applied": false })),
        )
    }
}
