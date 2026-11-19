use crate::{
    models::ids::{
        clean_override, clean_settings, normalize_event_action, IdsEvent, IdsRuleOverride,
        IdsSettings,
    },
    repository::ids_repository::IdsRepository,
};
use serde::Serialize;
use sqlx::SqlitePool;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_EVENTS_KEPT: i64 = 100_000;
pub const MAX_EVENTS_PER_PAGE: i64 = 500;
pub const TOP_SIGNATURES_SHOWN: i64 = 10;

const MAX_PROTO_LEN: usize = 16;
const MAX_APP_PROTO_LEN: usize = 32;
const MAX_SIGNATURE_LEN: usize = 200;
const MAX_CATEGORY_LEN: usize = 100;
const MIN_SEVERITY: i64 = 1;
const MAX_SEVERITY: i64 = 4;
const MAX_PORT: i64 = 65_535;
const DAY_SECONDS: i64 = 86_400;

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct IdsTopSignature {
    pub sid: i64,
    pub signature: String,
    pub hits: i64,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct IdsSummary {
    pub total_events: i64,
    pub blocked_24h: i64,
    pub alerted_24h: i64,
    pub top_signatures_24h: Vec<IdsTopSignature>,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
pub struct IdsIngestResult {
    pub saved: u64,
    pub skipped: u64,
}

pub struct IdsService;

impl IdsService {
    pub async fn get_settings(pool: &SqlitePool) -> Result<IdsSettings, String> {
        IdsRepository::get_settings(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn set_settings(pool: &SqlitePool, settings: IdsSettings) -> Result<(), String> {
        let settings = clean_settings(settings)?;

        IdsRepository::set_settings(pool, &settings)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn list_overrides(pool: &SqlitePool) -> Result<Vec<IdsRuleOverride>, String> {
        IdsRepository::list_overrides(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn add_override(pool: &SqlitePool, rule: IdsRuleOverride) -> Result<i64, String> {
        let rule = clean_override(rule)?;

        let existing = IdsRepository::get_override(pool, rule.sid)
            .await
            .map_err(|e| e.to_string())?;

        if existing.is_some() {
            return Err(format!(
                "A rule override for signature {} already exists",
                rule.sid
            ));
        }

        IdsRepository::add_override(pool, &rule)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn delete_override(pool: &SqlitePool, id: i64) -> Result<(), String> {
        let changed = IdsRepository::delete_override(pool, id)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("Rule override {} does not exist", id));
        }

        Ok(())
    }

    pub async fn record_events(
        pool: &SqlitePool,
        events: Vec<IdsEvent>,
    ) -> Result<IdsIngestResult, String> {
        let total = events.len() as u64;

        let cleaned: Vec<IdsEvent> = events
            .into_iter()
            .filter_map(|event| Self::clean_event(event).ok())
            .collect();

        let saved = IdsRepository::add_events(pool, &cleaned)
            .await
            .map_err(|e| e.to_string())?;

        Ok(IdsIngestResult {
            saved,
            skipped: total - cleaned.len() as u64,
        })
    }

    pub async fn list_events(
        pool: &SqlitePool,
        limit: Option<i64>,
        offset: Option<i64>,
        action: Option<String>,
        sid: Option<i64>,
    ) -> Result<Vec<IdsEvent>, String> {
        let limit = limit.unwrap_or(100).clamp(1, MAX_EVENTS_PER_PAGE);
        let offset = offset.unwrap_or(0).max(0);

        let action = match action.map(|a| a.trim().to_ascii_lowercase()) {
            None => None,
            Some(a) if a.is_empty() => None,
            Some(a) => Some(
                normalize_event_action(&a).ok_or("Action must be 'allowed' or 'blocked'")?,
            ),
        };

        IdsRepository::list_events(pool, limit, offset, action, sid)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn clear_events(pool: &SqlitePool) -> Result<u64, String> {
        IdsRepository::clear_events(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn prune_events(pool: &SqlitePool) -> Result<u64, String> {
        let settings = Self::get_settings(pool).await?;
        let cutoff = Self::now() - settings.event_retention_days * DAY_SECONDS;

        let by_age = IdsRepository::prune_events_before(pool, cutoff)
            .await
            .map_err(|e| e.to_string())?;

        let by_count = IdsRepository::prune_events(pool, MAX_EVENTS_KEPT)
            .await
            .map_err(|e| e.to_string())?;

        Ok(by_age + by_count)
    }

    pub async fn summary(pool: &SqlitePool) -> Result<IdsSummary, String> {
        let since = Self::now() - DAY_SECONDS;

        let total_events = IdsRepository::count_events(pool)
            .await
            .map_err(|e| e.to_string())?;

        let blocked_24h = IdsRepository::count_events_since(pool, "blocked", since)
            .await
            .map_err(|e| e.to_string())?;

        let alerted_24h = IdsRepository::count_events_since(pool, "allowed", since)
            .await
            .map_err(|e| e.to_string())?;

        let top_signatures_24h = IdsRepository::top_signatures(pool, since, TOP_SIGNATURES_SHOWN)
            .await
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|(sid, signature, hits)| IdsTopSignature { sid, signature, hits })
            .collect();

        Ok(IdsSummary {
            total_events,
            blocked_24h,
            alerted_24h,
            top_signatures_24h,
        })
    }

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    fn clean_event(mut event: IdsEvent) -> Result<IdsEvent, String> {
        event.action = normalize_event_action(&event.action)
            .ok_or("Action must be 'allowed' or 'blocked'")?
            .to_string();

        event.src_ip = event
            .src_ip
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| "Source address is not a valid IP address".to_string())?
            .to_string();

        event.dest_ip = event
            .dest_ip
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| "Destination address is not a valid IP address".to_string())?
            .to_string();

        event.src_port = event.src_port.filter(|p| (0..=MAX_PORT).contains(p));
        event.dest_port = event.dest_port.filter(|p| (0..=MAX_PORT).contains(p));

        event.proto = truncate(event.proto.trim(), MAX_PROTO_LEN).to_ascii_uppercase();

        if event.proto.is_empty() {
            return Err("An event needs a protocol".into());
        }

        event.app_proto = event
            .app_proto
            .map(|p| truncate(p.trim(), MAX_APP_PROTO_LEN).to_ascii_lowercase())
            .filter(|p| !p.is_empty());

        if event.sid < 0 {
            return Err("Signature ID cannot be negative".into());
        }

        event.signature = truncate(event.signature.trim(), MAX_SIGNATURE_LEN);

        if event.signature.is_empty() {
            return Err("An event needs a signature name".into());
        }

        event.category = event
            .category
            .map(|c| truncate(c.trim(), MAX_CATEGORY_LEN))
            .filter(|c| !c.is_empty());

        event.severity = event.severity.clamp(MIN_SEVERITY, MAX_SEVERITY);

        if event.ts < 0 {
            event.ts = 0;
        }

        Ok(event)
    }
}

fn truncate(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::ids_schema::create_ids_tables;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        create_ids_tables(&pool).await.unwrap();
        pool
    }

    fn event(sid: i64, action: &str, ts: i64) -> IdsEvent {
        IdsEvent {
            id: None,
            ts,
            src_ip: "10.0.0.5".into(),
            src_port: Some(51_000),
            dest_ip: "203.0.113.9".into(),
            dest_port: Some(80),
            proto: "TCP".into(),
            app_proto: Some("http".into()),
            sid,
            signature: format!("Signature {}", sid),
            category: Some("Potentially Bad Traffic".into()),
            severity: 2,
            action: action.into(),
        }
    }

    fn rule(sid: i64, action: &str) -> IdsRuleOverride {
        IdsRuleOverride {
            id: None,
            sid,
            action: action.into(),
            comment: None,
        }
    }

    #[tokio::test]
    async fn settings_are_cleaned_before_they_are_saved() {
        let pool = memory_pool().await;

        let mut settings = IdsService::get_settings(&pool).await.unwrap();
        settings.enabled = true;
        settings.mode = " IPS ".into();
        settings.interfaces = " eth0 , eth1 ".into();

        IdsService::set_settings(&pool, settings).await.unwrap();

        let saved = IdsService::get_settings(&pool).await.unwrap();
        assert!(saved.enabled);
        assert_eq!(saved.mode, "ips");
        assert_eq!(saved.interfaces, "eth0,eth1");
    }

    #[tokio::test]
    async fn bad_settings_are_refused_and_nothing_changes() {
        let pool = memory_pool().await;

        let mut settings = IdsService::get_settings(&pool).await.unwrap();
        settings.enabled = true;
        settings.queue_num = 100;

        assert!(IdsService::set_settings(&pool, settings).await.is_err());

        let saved = IdsService::get_settings(&pool).await.unwrap();
        assert!(!saved.enabled);
        assert_eq!(saved.queue_num, 200);
    }

    #[tokio::test]
    async fn overrides_are_cleaned_unique_and_deletable() {
        let pool = memory_pool().await;

        let id = IdsService::add_override(&pool, rule(2_000_001, " Disable ")).await.unwrap();

        let list = IdsService::list_overrides(&pool).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].action, "disable");

        let again = IdsService::add_override(&pool, rule(2_000_001, "drop")).await;
        assert!(again.unwrap_err().contains("already exists"));

        assert!(IdsService::add_override(&pool, rule(0, "drop")).await.is_err());
        assert!(IdsService::add_override(&pool, rule(5, "pass")).await.is_err());

        IdsService::delete_override(&pool, id).await.unwrap();
        assert!(IdsService::delete_override(&pool, id).await.is_err());
    }

    #[tokio::test]
    async fn events_are_cleaned_and_bad_ones_are_skipped() {
        let pool = memory_pool().await;

        let mut messy = event(1, " Blocked ", 0);
        messy.src_ip = " 2001:DB8::1 ".into();
        messy.proto = " tcp ".into();
        messy.app_proto = Some(" HTTP ".into());
        messy.src_port = Some(70_000);
        messy.dest_port = Some(-1);
        messy.severity = 9;
        messy.signature = format!("  {}  ", "x".repeat(300));
        messy.category = Some("  ".into());

        let mut bad_ip = event(2, "allowed", 10);
        bad_ip.src_ip = "not-an-ip".into();

        let mut bad_action = event(3, "allowed", 10);
        bad_action.action = "dropped".into();

        let mut no_signature = event(4, "allowed", 10);
        no_signature.signature = "   ".into();

        let mut negative_sid = event(-1, "allowed", 10);
        negative_sid.sid = -1;

        let mut no_proto = event(5, "allowed", 10);
        no_proto.proto = " ".into();

        let result = IdsService::record_events(
            &pool,
            vec![messy, bad_ip, bad_action, no_signature, negative_sid, no_proto, event(6, "allowed", 20)],
        )
        .await
        .unwrap();

        assert_eq!(result, IdsIngestResult { saved: 2, skipped: 5 });

        let saved = IdsService::list_events(&pool, None, None, None, None).await.unwrap();
        assert_eq!(saved.len(), 2);

        let cleaned = saved.iter().find(|e| e.sid == 1).unwrap();
        assert_eq!(cleaned.action, "blocked");
        assert_eq!(cleaned.src_ip, "2001:db8::1");
        assert_eq!(cleaned.proto, "TCP");
        assert_eq!(cleaned.app_proto.as_deref(), Some("http"));
        assert_eq!(cleaned.src_port, None);
        assert_eq!(cleaned.dest_port, None);
        assert_eq!(cleaned.severity, 4);
        assert_eq!(cleaned.signature.chars().count(), 200);
        assert_eq!(cleaned.category, None);
        assert!(cleaned.ts > 1_700_000_000);
    }

    #[tokio::test]
    async fn an_empty_batch_saves_nothing() {
        let pool = memory_pool().await;

        let result = IdsService::record_events(&pool, vec![]).await.unwrap();
        assert_eq!(result, IdsIngestResult { saved: 0, skipped: 0 });
    }

    #[tokio::test]
    async fn listing_validates_filters_and_clamps_paging() {
        let pool = memory_pool().await;

        let now = IdsService::now();
        IdsService::record_events(
            &pool,
            vec![event(1, "allowed", now - 20), event(2, "blocked", now - 10)],
        )
        .await
        .unwrap();

        let blocked = IdsService::list_events(&pool, None, None, Some(" BLOCKED ".into()), None)
            .await
            .unwrap();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].sid, 2);

        let blank = IdsService::list_events(&pool, None, None, Some("  ".into()), None).await.unwrap();
        assert_eq!(blank.len(), 2);

        assert!(IdsService::list_events(&pool, None, None, Some("dropped".into()), None).await.is_err());

        let by_sid = IdsService::list_events(&pool, None, None, None, Some(1)).await.unwrap();
        assert_eq!(by_sid.len(), 1);

        let one = IdsService::list_events(&pool, Some(0), Some(-5), None, None).await.unwrap();
        assert_eq!(one.len(), 1);

        let wide = IdsService::list_events(&pool, Some(1_000_000), None, None, None).await.unwrap();
        assert_eq!(wide.len(), 2);
    }

    #[tokio::test]
    async fn summary_counts_the_last_day_and_ranks_signatures() {
        let pool = memory_pool().await;

        let now = IdsService::now();
        let old = now - 3 * DAY_SECONDS;

        let mut events = vec![
            event(20, "allowed", now - 100),
            event(20, "allowed", now - 90),
            event(20, "blocked", now - 80),
            event(10, "allowed", now - 70),
            event(30, "blocked", old),
        ];
        events.push(event(30, "allowed", old));

        IdsService::record_events(&pool, events).await.unwrap();

        let summary = IdsService::summary(&pool).await.unwrap();

        assert_eq!(summary.total_events, 6);
        assert_eq!(summary.blocked_24h, 1);
        assert_eq!(summary.alerted_24h, 3);
        assert_eq!(
            summary.top_signatures_24h,
            vec![
                IdsTopSignature { sid: 20, signature: "Signature 20".into(), hits: 3 },
                IdsTopSignature { sid: 10, signature: "Signature 10".into(), hits: 1 },
            ]
        );
    }

    #[tokio::test]
    async fn pruning_follows_the_retention_setting() {
        let pool = memory_pool().await;

        let mut settings = IdsService::get_settings(&pool).await.unwrap();
        settings.event_retention_days = 2;
        IdsService::set_settings(&pool, settings).await.unwrap();

        let now = IdsService::now();
        IdsService::record_events(
            &pool,
            vec![
                event(1, "allowed", now - 5 * DAY_SECONDS),
                event(2, "allowed", now - 3 * DAY_SECONDS),
                event(3, "allowed", now - 60),
            ],
        )
        .await
        .unwrap();

        assert_eq!(IdsService::prune_events(&pool).await.unwrap(), 2);

        let left = IdsService::list_events(&pool, None, None, None, None).await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].sid, 3);

        assert_eq!(IdsService::prune_events(&pool).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn clearing_removes_all_events() {
        let pool = memory_pool().await;

        IdsService::record_events(&pool, vec![event(1, "allowed", 10), event(2, "blocked", 20)])
            .await
            .unwrap();

        assert_eq!(IdsService::clear_events(&pool).await.unwrap(), 2);
        assert_eq!(IdsService::summary(&pool).await.unwrap().total_events, 0);
    }
}
