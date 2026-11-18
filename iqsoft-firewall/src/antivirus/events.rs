
use sqlx::SqlitePool;

use crate::{
    models::av::AvEvent as DatabaseAvEvent,
    services::av_service::AvService,
};

use super::scanner::{ScanAction, ScannerOutcome};

pub struct ScanEventContext {
    pub client_ip: String,
    pub host: String,
    pub url: String,
    pub file_name: Option<String>,
    pub file_size: u64,
}

pub async fn record_scan_event(
    pool: &SqlitePool,
    context: ScanEventContext,
    outcome: &ScannerOutcome,
) -> Result<bool, String> {
    // Do not create database events for clean files.
    let action = if outcome.infected {
        match &outcome.action {
            ScanAction::Block => "blocked",
            ScanAction::Allow => "monitored",
        }
    } else if outcome.reason.contains("scanning failed") {
        "error"
    } else if outcome.action == ScanAction::Block {
        // For example, an oversized file configured to be blocked.
        "blocked"
    } else {
        return Ok(false);
    };

    let size_bytes = i64::try_from(context.file_size)
        .unwrap_or(i64::MAX);

    let event = DatabaseAvEvent {
        id: None,
        ts: 0,
        client_ip: context.client_ip,
        host: context.host,
        url: context.url,
        file_name: context.file_name,
        size_bytes,
        engine: "clamav".to_string(),
        signature: outcome.signature.clone(),
        action: action.to_string(),
    };

    AvService::record_event(pool, event).await?;

    Ok(true)
}

