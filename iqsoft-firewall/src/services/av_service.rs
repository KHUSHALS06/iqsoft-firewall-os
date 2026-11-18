use crate::{
    models::av::{clean_exception, clean_settings, AvEvent, AvException, AvSettings},
    repository::av_repository::AvRepository,
};
use serde::Serialize;
use sqlx::SqlitePool;
use std::time::{SystemTime, UNIX_EPOCH};

/// The newest this many events are kept. Older ones are deleted.
pub const MAX_EVENTS_KEPT: i64 = 10_000;

/// The most events one request can ask for.
pub const MAX_EVENTS_PER_PAGE: i64 = 500;

const MAX_HOST_LEN: usize = 253;
const MAX_URL_LEN: usize = 2048;
const MAX_FILE_NAME_LEN: usize = 255;
const MAX_SIGNATURE_LEN: usize = 200;
const MAX_CLIENT_IP_LEN: usize = 64;

/// Old events are cleaned up once for every this many events saved.
const PRUNE_EVERY: i64 = 100;

const DAY_SECONDS: i64 = 86_400;

/// Numbers for the dashboard.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct AvSummary {
    pub total_events: i64,
    pub blocked_24h: i64,
    pub monitored_24h: i64,
    pub errors_24h: i64,
}

pub struct AvService;

impl AvService {
    // ---------- settings ----------

    pub async fn get_settings(pool: &SqlitePool) -> Result<AvSettings, String> {
        AvRepository::get_settings(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn set_settings(pool: &SqlitePool, settings: AvSettings) -> Result<(), String> {
        let settings = clean_settings(settings)?;

        AvRepository::set_settings(pool, &settings)
            .await
            .map_err(|e| e.to_string())
    }

    // ---------- exceptions (never scanned) ----------

    pub async fn list_exceptions(pool: &SqlitePool) -> Result<Vec<AvException>, String> {
        AvRepository::list_exceptions(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn add_exception(pool: &SqlitePool, exception: AvException) -> Result<(), String> {
        let exception = clean_exception(exception)?;

        let existing = AvRepository::get_exception(pool, &exception.kind, &exception.value)
            .await
            .map_err(|e| e.to_string())?;

        if existing.is_some() {
            return Err(format!("An exception for {} already exists", exception.value));
        }

        AvRepository::add_exception(pool, &exception)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub async fn delete_exception(pool: &SqlitePool, id: i64) -> Result<(), String> {
        let changed = AvRepository::delete_exception(pool, id)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("Antivirus exception {} does not exist", id));
        }

        Ok(())
    }

    // ---------- events ----------

    /// Used by the scanner. Cleans the event, saves it, and now and then
    /// removes the oldest events so the table cannot grow forever.
    pub async fn record_event(pool: &SqlitePool, event: AvEvent) -> Result<(), String> {
        let event = Self::clean_event(event)?;

        let id = AvRepository::add_event(pool, &event)
            .await
            .map_err(|e| e.to_string())?;

        if id % PRUNE_EVERY == 0 {
            AvRepository::prune_events(pool, MAX_EVENTS_KEPT)
                .await
                .map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    pub async fn list_events(
        pool: &SqlitePool,
        limit: Option<i64>,
        offset: Option<i64>,
        action: Option<String>,
    ) -> Result<Vec<AvEvent>, String> {
        let limit = limit.unwrap_or(100).clamp(1, MAX_EVENTS_PER_PAGE);
        let offset = offset.unwrap_or(0).max(0);

        let action = match action.map(|a| a.trim().to_ascii_lowercase()) {
            None => None,
            Some(a) if a.is_empty() => None,
            Some(a) => Some(
                normalize_event_action(&a)
                    .ok_or("Action must be 'blocked', 'monitored' or 'error'")?,
            ),
        };

        AvRepository::list_events(pool, limit, offset, action.as_deref())
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn clear_events(pool: &SqlitePool) -> Result<u64, String> {
        AvRepository::clear_events(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn summary(pool: &SqlitePool) -> Result<AvSummary, String> {
        let since = Self::now() - DAY_SECONDS;

        let total_events = AvRepository::count_events(pool)
            .await
            .map_err(|e| e.to_string())?;

        let blocked_24h = AvRepository::count_events_since(pool, "blocked", since)
            .await
            .map_err(|e| e.to_string())?;

        let monitored_24h = AvRepository::count_events_since(pool, "monitored", since)
            .await
            .map_err(|e| e.to_string())?;

        let errors_24h = AvRepository::count_events_since(pool, "error", since)
            .await
            .map_err(|e| e.to_string())?;

        Ok(AvSummary {
            total_events,
            blocked_24h,
            monitored_24h,
            errors_24h,
        })
    }

    // ---------- helpers ----------

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    fn clean_event(mut event: AvEvent) -> Result<AvEvent, String> {
        event.engine = match event.engine.trim().to_ascii_lowercase().as_str() {
            "clamav" => "clamav".to_string(),
            "hash" => "hash".to_string(),
            "url" => "url".to_string(),
            _ => return Err("Engine must be 'clamav', 'hash' or 'url'".into()),
        };

        event.action = normalize_event_action(&event.action)
            .ok_or("Action must be 'blocked', 'monitored' or 'error'")?;

        event.client_ip = truncate(event.client_ip.trim(), MAX_CLIENT_IP_LEN);
        event.host = truncate(event.host.trim(), MAX_HOST_LEN);
        event.url = truncate(event.url.trim(), MAX_URL_LEN);

        if event.client_ip.is_empty() || event.host.is_empty() || event.url.is_empty() {
            return Err("An event needs a client address, a host and a URL".into());
        }

        event.file_name = event
            .file_name
            .map(|f| truncate(f.trim(), MAX_FILE_NAME_LEN))
            .filter(|f| !f.is_empty());

        event.signature = event
            .signature
            .map(|s| truncate(s.trim(), MAX_SIGNATURE_LEN))
            .filter(|s| !s.is_empty());

        if event.size_bytes < 0 {
            event.size_bytes = 0;
        }

        if event.ts < 0 {
            event.ts = 0;
        }

        Ok(event)
    }
}

fn normalize_event_action(value: &str) -> Option<String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "blocked" => Some("blocked".to_string()),
        "monitored" => Some("monitored".to_string()),
        "error" => Some("error".to_string()),
        _ => None,
    }
}

/// Cuts text to at most `max` characters without splitting a character.
fn truncate(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::av_schema::create_av_tables;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        create_av_tables(&pool).await.unwrap();
        pool
    }

    fn exception(kind: &str, value: &str) -> AvException {
        AvException {
            id: None,
            kind: kind.into(),
            value: value.into(),
            comment: None,
        }
    }

    fn event(host: &str, action: &str) -> AvEvent {
        AvEvent {
            id: None,
            ts: 0,
            client_ip: "10.0.0.5".into(),
            host: host.into(),
            url: format!("http://{}/a.exe", host),
            file_name: Some("a.exe".into()),
            size_bytes: 68,
            engine: "clamav".into(),
            signature: Some("Eicar-Signature".into()),
            action: action.into(),
        }
    }

    #[tokio::test]
    async fn settings_are_cleaned_and_bad_values_refused() {
        let pool = memory_pool().await;

        let mut wanted = AvService::get_settings(&pool).await.unwrap();
        wanted.enabled = true;
        wanted.mode = " Monitor ".into();
        wanted.fail_mode = "CLOSED".into();
        AvService::set_settings(&pool, wanted).await.unwrap();

        let saved = AvService::get_settings(&pool).await.unwrap();
        assert!(saved.enabled);
        assert_eq!(saved.mode, "monitor");
        assert_eq!(saved.fail_mode, "closed");

        let mut bad = saved.clone();
        bad.max_scan_mb = 0;
        assert!(AvService::set_settings(&pool, bad).await.is_err());

        let mut bad = saved.clone();
        bad.proxy_port = 80;
        assert!(AvService::set_settings(&pool, bad).await.is_err());

        // A refused save changes nothing.
        assert_eq!(AvService::get_settings(&pool).await.unwrap(), saved);
    }

    #[tokio::test]
    async fn exceptions_are_cleaned_and_unique() {
        let pool = memory_pool().await;

        AvService::add_exception(&pool, exception("domain", "*.Updates.Example.COM."))
            .await
            .unwrap();
        AvService::add_exception(&pool, exception("cidr", "10.1.2.3/16"))
            .await
            .unwrap();

        let saved = AvService::list_exceptions(&pool).await.unwrap();
        let values: Vec<&str> = saved.iter().map(|e| e.value.as_str()).collect();
        assert_eq!(values, vec!["10.1.0.0/16", "updates.example.com"]);

        assert!(AvService::add_exception(&pool, exception("domain", "updates.example.com"))
            .await
            .is_err());
        assert!(AvService::add_exception(&pool, exception("cidr", "10.1.9.9/16"))
            .await
            .is_err());
        assert!(AvService::add_exception(&pool, exception("domain", "localhost"))
            .await
            .is_err());
        assert!(AvService::add_exception(&pool, exception("cidr", "10.0.0.0/40"))
            .await
            .is_err());
        assert!(AvService::add_exception(&pool, exception("mac", "aa:bb"))
            .await
            .is_err());

        assert_eq!(AvService::list_exceptions(&pool).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn an_exception_can_be_deleted_once() {
        let pool = memory_pool().await;
        AvService::add_exception(&pool, exception("domain", "example.com"))
            .await
            .unwrap();

        let id = AvService::list_exceptions(&pool).await.unwrap()[0].id.unwrap();

        AvService::delete_exception(&pool, id).await.unwrap();
        assert!(AvService::delete_exception(&pool, id).await.is_err());
    }

    #[tokio::test]
    async fn events_are_cleaned_before_saving() {
        let pool = memory_pool().await;

        let mut e = event("  Example.com ", " BLOCKED ");
        e.engine = " ClamAV ".into();
        e.file_name = Some("   ".into());
        e.size_bytes = -5;
        e.url = format!("http://example.com/{}", "a".repeat(5000));

        AvService::record_event(&pool, e).await.unwrap();

        let saved = AvService::list_events(&pool, None, None, None).await.unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].host, "Example.com");
        assert_eq!(saved[0].action, "blocked");
        assert_eq!(saved[0].engine, "clamav");
        assert_eq!(saved[0].file_name, None);
        assert_eq!(saved[0].size_bytes, 0);
        assert_eq!(saved[0].url.chars().count(), 2048);
        assert!(saved[0].ts > 1_700_000_000);
    }

    #[tokio::test]
    async fn bad_events_are_refused() {
        let pool = memory_pool().await;

        let mut e = event("example.com", "blocked");
        e.engine = "magic".into();
        assert!(AvService::record_event(&pool, e).await.is_err());

        assert!(AvService::record_event(&pool, event("example.com", "deleted"))
            .await
            .is_err());

        let mut e = event("example.com", "blocked");
        e.host = "   ".into();
        assert!(AvService::record_event(&pool, e).await.is_err());

        assert!(AvService::list_events(&pool, None, None, None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn listing_clamps_the_page_and_checks_the_filter() {
        let pool = memory_pool().await;

        AvService::record_event(&pool, event("a.example.com", "blocked")).await.unwrap();
        AvService::record_event(&pool, event("b.example.com", "monitored")).await.unwrap();

        let all = AvService::list_events(&pool, Some(-3), Some(-9), None).await.unwrap();
        assert_eq!(all.len(), 1);

        let big = AvService::list_events(&pool, Some(100_000), None, None).await.unwrap();
        assert_eq!(big.len(), 2);

        let blocked = AvService::list_events(&pool, None, None, Some(" Blocked ".into()))
            .await
            .unwrap();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].host, "a.example.com");

        let no_filter = AvService::list_events(&pool, None, None, Some("  ".into()))
            .await
            .unwrap();
        assert_eq!(no_filter.len(), 2);

        assert!(AvService::list_events(&pool, None, None, Some("deleted".into()))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn the_summary_counts_the_last_day() {
        let pool = memory_pool().await;

        AvService::record_event(&pool, event("a.example.com", "blocked")).await.unwrap();
        AvService::record_event(&pool, event("b.example.com", "blocked")).await.unwrap();
        AvService::record_event(&pool, event("c.example.com", "monitored")).await.unwrap();
        AvService::record_event(&pool, event("d.example.com", "error")).await.unwrap();

        let mut old = event("old.example.com", "blocked");
        old.ts = 1_700_000_001;
        AvService::record_event(&pool, old).await.unwrap();

        assert_eq!(
            AvService::summary(&pool).await.unwrap(),
            AvSummary {
                total_events: 5,
                blocked_24h: 2,
                monitored_24h: 1,
                errors_24h: 1,
            }
        );
    }

    #[tokio::test]
    async fn events_can_be_cleared() {
        let pool = memory_pool().await;

        AvService::record_event(&pool, event("a.example.com", "blocked")).await.unwrap();
        AvService::record_event(&pool, event("b.example.com", "blocked")).await.unwrap();

        assert_eq!(AvService::clear_events(&pool).await.unwrap(), 2);
        assert!(AvService::list_events(&pool, None, None, None).await.unwrap().is_empty());
    }
}
