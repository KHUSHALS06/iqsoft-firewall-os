//! The IDS/IPS background worker.
//!
//! At start-up it brings the saved state back (the nft queue table does not survive a reboot
//! by itself). After that, in a loop, it:
//!   - copies new alerts from Suricata's eve.json into the database (every few seconds)
//!   - deletes events older than the retention setting (every hour)
//!   - downloads new signatures when the update interval has passed (checked every few minutes)

use crate::{
    ids::{
        commit,
        config::SuricataFiles,
        eve::EveTailer,
        generator,
        rules::{self, RuleFileInfo, RuleUpdateStatus},
    },
    services::ids_service::{IdsIngestResult, IdsService},
};
use sqlx::SqlitePool;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

const TICK: Duration = Duration::from_secs(5);
const PRUNE_EVERY_SECS: i64 = 3_600;
const RULE_CHECK_EVERY_SECS: i64 = 300;

/// After an update attempt (good or bad) the next automatic one waits at least this long,
/// so a box without internet access does not retry every few minutes.
const RETRY_AFTER_SECS: i64 = 3_600;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------- alerts ----------

/// Reads whatever Suricata has written since the last call and stores it.
pub async fn ingest_once(
    pool: &SqlitePool,
    tailer: &mut EveTailer,
) -> Result<IdsIngestResult, String> {
    let events = tailer.read_new().await?;

    if events.is_empty() {
        return Ok(IdsIngestResult {
            saved: 0,
            skipped: 0,
        });
    }

    IdsService::record_events(pool, events).await
}

// ---------- signatures ----------

/// Decides whether the signatures should be downloaded now.
///
/// `reference` is when the signatures were last refreshed (the newer of the file's age and the
/// last successful update). `last_attempt` is when the worker last tried, successful or not.
/// An interval of 0 hours means "never update by itself".
pub fn rules_due(
    now: i64,
    hours: i64,
    file: &RuleFileInfo,
    reference: Option<i64>,
    last_attempt: Option<i64>,
) -> bool {
    if hours <= 0 {
        return false;
    }

    if let Some(attempt) = last_attempt {
        if now - attempt < RETRY_AFTER_SECS {
            return false;
        }
    }

    if !file.exists || file.rule_count == 0 {
        return true;
    }

    match reference {
        None => true,
        Some(refreshed) => now - refreshed >= hours * 3_600,
    }
}

/// Downloads the newest signatures and tells the running Suricata to load them.
/// Used by the worker and by the "update rules now" button.
pub async fn update_and_reload(pool: &SqlitePool) -> Result<RuleUpdateStatus, String> {
    let files = SuricataFiles::default();

    let mut status = rules::update_rules(pool, &files).await?;

    let note = match commit::reload_rules().await {
        Ok(()) => "Suricata was told to load the new signatures.".to_string(),
        Err(_) => "Suricata is not running; the new signatures load the next time it starts."
            .to_string(),
    };

    status.message = format!("{}\n{}", status.message, note);

    Ok(status)
}

async fn check_rules(pool: &SqlitePool, last_attempt: &mut Option<i64>) {
    let settings = match IdsService::get_settings(pool).await {
        Ok(settings) => settings,
        Err(e) => {
            eprintln!("ids: could not read the settings: {}", e);
            return;
        }
    };

    // Nothing to update while the feature is off: there is no configuration file to read yet.
    if !settings.enabled {
        return;
    }

    let files = SuricataFiles::default();
    let info = rules::rule_file_info(&files).await;

    let reference = [
        info.modified_at,
        rules::last_update()
            .filter(|status| status.success)
            .map(|status| status.finished_at),
    ]
    .into_iter()
    .flatten()
    .max();

    let moment = now();

    if !rules_due(
        moment,
        settings.rule_update_hours,
        &info,
        reference,
        *last_attempt,
    ) {
        return;
    }

    *last_attempt = Some(moment);

    println!("ids: updating the signatures");

    match update_and_reload(pool).await {
        Ok(status) => println!(
            "ids: signatures updated ({} total, {} enabled)",
            status
                .total_rules
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".into()),
            status
                .enabled_rules
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".into()),
        ),
        Err(e) => eprintln!("ids: signature update failed: {}", e),
    }
}

// ---------- start-up and the loop ----------

/// Brings the saved IDS/IPS state back after a boot.
///
/// If Suricata already came up by itself (its service is enabled), only the nft queue table is
/// restored. Otherwise the whole commit runs. When the feature is off, any leftover queue
/// table is removed.
pub async fn restore_on_boot(pool: &SqlitePool, lock: &Arc<Mutex<()>>) -> Result<String, String> {
    let settings = IdsService::get_settings(pool).await?;

    if !settings.enabled {
        generator::apply_live(pool, lock).await?;
        return Ok("IDS/IPS is switched off".to_string());
    }

    if commit::status().await.ready {
        generator::apply_live(pool, lock).await?;
        return Ok("IDS/IPS: Suricata is already running, rules restored".to_string());
    }

    commit::apply(pool, lock).await
}

/// Starts the background worker. Never blocks the caller.
pub fn spawn(pool: SqlitePool, lock: Arc<Mutex<()>>) {
    tokio::spawn(async move {
        match restore_on_boot(&pool, &lock).await {
            Ok(message) => println!("{}", message),
            Err(e) => {
                eprintln!("ERROR: could not restore IDS/IPS: {}", e);
                eprintln!("ERROR: intrusion detection may be off until it is switched on again");
            }
        }

        let mut tailer = EveTailer::new(SuricataFiles::default().eve_path());

        let mut last_prune = 0i64;
        let mut last_rule_check = 0i64;
        let mut last_attempt: Option<i64> = None;
        let mut last_error = String::new();

        loop {
            tokio::time::sleep(TICK).await;

            match ingest_once(&pool, &mut tailer).await {
                Ok(_) => last_error.clear(),
                Err(e) => {
                    // Print a problem once, not every few seconds.
                    if e != last_error {
                        eprintln!("ids: could not read the alerts: {}", e);
                        last_error = e;
                    }
                }
            }

            let moment = now();

            if moment - last_prune >= PRUNE_EVERY_SECS {
                last_prune = moment;

                match IdsService::prune_events(&pool).await {
                    Ok(0) => {}
                    Ok(removed) => println!("ids: removed {} old events", removed),
                    Err(e) => eprintln!("ids: could not remove old events: {}", e),
                }
            }

            if moment - last_rule_check >= RULE_CHECK_EVERY_SECS {
                last_rule_check = moment;
                check_rules(&pool, &mut last_attempt).await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::ids_schema::create_ids_tables;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::{
        io::Write,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    const HOUR: i64 = 3_600;
    const NOW: i64 = 1_795_000_000;

    fn temp_path() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);

        std::env::temp_dir().join(format!(
            "iqsoft-scheduler-test-{}-{}.json",
            std::process::id(),
            n
        ))
    }

    fn append(path: &Path, text: &str) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();

        file.write_all(text.as_bytes()).unwrap();
    }

    fn alert_line(sid: i64, src_ip: &str, action: &str) -> String {
        format!(
            "{{\"timestamp\":\"2026-11-19T10:15:30.123456+0000\",\"event_type\":\"alert\",\
             \"src_ip\":\"{}\",\"src_port\":51000,\"dest_ip\":\"203.0.113.9\",\
             \"dest_port\":80,\"proto\":\"TCP\",\"app_proto\":\"http\",\
             \"alert\":{{\"action\":\"{}\",\"signature_id\":{},\
             \"signature\":\"Test signature {}\",\"category\":\"Potentially Bad Traffic\",\
             \"severity\":2}}}}\n",
            src_ip, action, sid, sid
        )
    }

    async fn memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        create_ids_tables(&pool).await.unwrap();
        pool
    }

    fn file(exists: bool, rule_count: i64) -> RuleFileInfo {
        RuleFileInfo {
            path: "/var/lib/suricata/rules/suricata.rules".into(),
            exists,
            size_bytes: 0,
            modified_at: None,
            rule_count,
        }
    }

    #[test]
    fn an_interval_of_zero_never_updates_by_itself() {
        assert!(!rules_due(NOW, 0, &file(false, 0), None, None));
        assert!(!rules_due(NOW, 0, &file(true, 0), None, None));
    }

    #[test]
    fn a_missing_or_empty_signature_file_is_updated_right_away() {
        assert!(rules_due(NOW, 24, &file(false, 0), None, None));
        assert!(rules_due(NOW, 24, &file(true, 0), Some(NOW - 60), None));
    }

    #[test]
    fn fresh_signatures_are_left_alone() {
        let info = file(true, 40_000);

        assert!(!rules_due(NOW, 24, &info, Some(NOW - 23 * HOUR), None));
    }

    #[test]
    fn old_signatures_are_updated_once_the_interval_has_passed() {
        let info = file(true, 40_000);

        assert!(rules_due(NOW, 24, &info, Some(NOW - 24 * HOUR), None));
        assert!(rules_due(NOW, 24, &info, Some(NOW - 30 * HOUR), None));
        assert!(rules_due(NOW, 24, &info, None, None));
    }

    #[test]
    fn a_recent_attempt_blocks_another_one() {
        let empty = file(true, 0);

        assert!(!rules_due(NOW, 24, &empty, None, Some(NOW - 10 * 60)));
        assert!(rules_due(NOW, 24, &empty, None, Some(NOW - 2 * HOUR)));

        let old = file(true, 40_000);
        assert!(!rules_due(NOW, 24, &old, Some(NOW - 48 * HOUR), Some(NOW - 600)));
    }

    #[tokio::test]
    async fn alerts_are_copied_into_the_database() {
        let pool = memory_pool().await;

        let path = temp_path();
        append(&path, &alert_line(1, "10.0.0.5", "allowed"));
        append(&path, &alert_line(2, "10.0.0.6", "blocked"));
        append(&path, &alert_line(3, "not-an-address", "allowed"));
        append(&path, "{\"event_type\":\"dns\"}\n");

        let mut tailer = EveTailer::from_start(&path);

        let result = ingest_once(&pool, &mut tailer).await.unwrap();

        assert_eq!(result.saved, 2);
        assert_eq!(result.skipped, 1);

        let events = IdsService::list_events(&pool, None, None, None, None)
            .await
            .unwrap();

        let mut sids: Vec<i64> = events.iter().map(|e| e.sid).collect();
        sids.sort_unstable();

        assert_eq!(sids, vec![1, 2]);
        assert!(events.iter().any(|e| e.sid == 2 && e.action == "blocked"));

        let again = ingest_once(&pool, &mut tailer).await.unwrap();
        assert_eq!((again.saved, again.skipped), (0, 0));

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn later_alerts_are_picked_up_and_old_ones_are_not_stored_twice() {
        let pool = memory_pool().await;

        let path = temp_path();
        append(&path, &alert_line(1, "10.0.0.5", "allowed"));

        let mut tailer = EveTailer::new(&path);

        let first = ingest_once(&pool, &mut tailer).await.unwrap();
        assert_eq!(first.saved, 0);

        append(&path, &alert_line(2, "10.0.0.5", "allowed"));

        let second = ingest_once(&pool, &mut tailer).await.unwrap();
        assert_eq!(second.saved, 1);

        let events = IdsService::list_events(&pool, None, None, None, None)
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sid, 2);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn a_missing_log_file_is_not_an_error() {
        let pool = memory_pool().await;

        let path = temp_path();
        let _ = std::fs::remove_file(&path);

        let mut tailer = EveTailer::new(&path);
        let result = ingest_once(&pool, &mut tailer).await.unwrap();

        assert_eq!((result.saved, result.skipped), (0, 0));
    }
}
