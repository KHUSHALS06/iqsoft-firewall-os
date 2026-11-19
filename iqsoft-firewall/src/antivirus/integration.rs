use std::time::Duration;

use sqlx::SqlitePool;

use crate::{
    models::av::AvSettings,
    services::av_service::AvService,
};

use super::{
    cache::{CachedVerdict, VerdictCache},
    clamav::ClamAvClient,
    events::{record_scan_event, ScanEventContext},
    scanner::{
        AntivirusScanner,
        FailMode,
        OversizeAction,
        ScanAction,
        ScanMode,
        ScannerConfig,
        ScannerOutcome,
    },
    stream::{StreamingScan, DEFAULT_HOLDBACK_BYTES},
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

fn outcome_from_cache(verdict: CachedVerdict, config: &ScannerConfig) -> ScannerOutcome {
    match verdict {
        CachedVerdict::Clean => ScannerOutcome {
            action: ScanAction::Allow,
            infected: false,
            signature: None,
            reason: "File is clean (cached verdict)".to_string(),
            scanned: true,
        },
        CachedVerdict::Infected(signature) => ScannerOutcome {
            // The cache stores the detection, not the decision: the current
            // block/monitor mode still applies.
            action: match config.mode {
                ScanMode::Block => ScanAction::Block,
                ScanMode::Monitor => ScanAction::Allow,
            },
            infected: true,
            signature: Some(signature),
            reason: "Malware detected (cached verdict)".to_string(),
            scanned: true,
        },
    }
}

/// Like `scan_and_record`, but a file whose hash was already scanned recently
/// skips clamd. Detections are still recorded as events every time.
/// Call `cache.clear()` after each signature update.
pub async fn scan_and_record_cached(
    pool: &SqlitePool,
    cache: &VerdictCache,
    mut context: ScanEventContext,
    data: &[u8],
) -> Result<ScannerOutcome, String> {
    let settings = AvService::get_settings(pool).await?;
    let config = build_scanner_config(&settings);

    context.file_size = data.len() as u64;

    let key = VerdictCache::hash(data);

    let cached = if settings.enabled { cache.get(&key) } else { None };

    let outcome = match cached {
        Some(verdict) => outcome_from_cache(verdict, &config),
        None => {
            let client = ClamAvClient::with_socket(settings.clamd_socket.clone());
            let scanner = AntivirusScanner::with_client(client, config);
            let outcome = scanner.scan(data).await;

            // Cache real verdicts only; never errors or skipped files.
            if outcome.scanned {
                let verdict = if outcome.infected {
                    CachedVerdict::Infected(outcome.signature.clone().unwrap_or_default())
                } else {
                    CachedVerdict::Clean
                };
                cache.put(key, verdict);
            }

            outcome
        }
    };

    record_scan_event(pool, context, &outcome).await?;

    Ok(outcome)
}

/// Start a streaming scan for one download, using the current settings.
/// Returns `None` when AV is switched off (nothing to scan).
/// Record the result afterwards with `events::record_scan_event`.
pub async fn start_stream_scan(pool: &SqlitePool) -> Result<Option<StreamingScan>, String> {
    let settings = AvService::get_settings(pool).await?;

    if !settings.enabled {
        return Ok(None);
    }

    Ok(Some(StreamingScan::new(
        ClamAvClient::with_socket(settings.clamd_socket.clone()),
        build_scanner_config(&settings),
        DEFAULT_HOLDBACK_BYTES,
    )))
}
