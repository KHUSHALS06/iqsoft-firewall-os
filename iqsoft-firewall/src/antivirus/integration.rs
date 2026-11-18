
use std::time::Duration;

use sqlx::SqlitePool;

use crate::{
    models::av::AvSettings,
    services::av_service::AvService,
};

use super::{
    clamav::ClamAvClient,
    events::{record_scan_event, ScanEventContext},
    scanner::{
        AntivirusScanner,
        FailMode,
        OversizeAction,
        ScanMode,
        ScannerConfig,
        ScannerOutcome,
    },
};

fn build_scanner_config(settings: &AvSettings) -> ScannerConfig {
    let mode = match settings.mode.as_str() {
        "monitor" => ScanMode::Monitor,
        _ => ScanMode::Block,
    };

    let fail_mode = match settings.fail_mode.as_str() {
        "open" => FailMode::Open,
        _ => FailMode::Closed,
    };

    let oversize_action = match settings.over_size_action.as_str() {
        "allow" => OversizeAction::Allow,
        _ => OversizeAction::Block,
    };

    ScannerConfig {
        enabled: settings.enabled,
        mode,
        fail_mode,
        max_scan_bytes: (settings.max_scan_mb as usize)
            .saturating_mul(1024 * 1024),
        oversize_action,
        scan_timeout: Duration::from_secs(30),
    }
}

pub async fn scan_and_record(
    pool: &SqlitePool,
    mut context: ScanEventContext,
    data: &[u8],
) -> Result<ScannerOutcome, String> {
    // Read the current settings from the existing database.
    let settings = AvService::get_settings(pool).await?;

    // Ensure event size reflects the actual scanned data.
    context.file_size = data.len() as u64;

    // Build the scanner using the configured ClamAV socket.
    let client = ClamAvClient::with_socket(
        settings.clamd_socket.clone(),
    );

    let config = build_scanner_config(&settings);

    let scanner = AntivirusScanner::with_client(
        client,
        config,
    );

    // Scan the file.
    let outcome = scanner.scan(data).await;

    // Save relevant events to the existing AV database.
    record_scan_event(
        pool,
        context,
        &outcome,
    )
    .await?;

    Ok(outcome)
}

