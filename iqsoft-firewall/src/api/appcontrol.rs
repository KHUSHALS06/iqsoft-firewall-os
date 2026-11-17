use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::{
    app_state::AppState,
    models::appcontrol::{find_app, AppActionRequest},
    services::appcontrol_service::AppControlService,
    sni::queue,
};

async fn apply_policy(state: &AppState) {
    if let Err(e) = queue::reload(&state.db).await {
        eprintln!("ERROR: could not reload the SNI filter policy: {}", e);
    }
}

/// GET /api/sni/apps
/// The whole catalog, each app with its current choice
/// ("block", "allow" or "default").
pub async fn list_apps(State(state): State<AppState>) -> impl IntoResponse {
    match AppControlService::list_apps(&state.db).await {
        Ok(apps) => (StatusCode::OK, Json(json!(apps))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

/// PUT /api/sni/apps/{id}   body: {"action": "block" | "allow" | "default"}
/// Changes one app and answers with the app as it now looks.
pub async fn set_app(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(request): Json<AppActionRequest>,
) -> impl IntoResponse {
    if find_app(&id).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("Unknown app '{}'", id.trim()) })),
        );
    }

    match AppControlService::set_app_action(&state.db, &id, &request.action).await {
        Ok(app) => {
            apply_policy(&state).await;
            (StatusCode::OK, Json(json!(app)))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}
