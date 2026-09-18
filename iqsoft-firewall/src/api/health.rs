use crate::app_state::AppState;
use axum::{
    extract::State,
    Json,
};
use serde_json::{json, Value};

pub async fn health(State(state): State<AppState>) -> Json<Value> {
    let connected = sqlx::query("SELECT 1")
        .execute(&state.db)
        .await
        .is_ok();

    Json(json!({
        "status": "ok",
        "database": connected,
        "product": "IQSOFT Firewall OS",
        "version": "0.1.0"
    }))
}
