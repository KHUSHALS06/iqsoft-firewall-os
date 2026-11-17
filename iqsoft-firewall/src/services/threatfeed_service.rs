use crate::{
    models::threatfeed::{
        normalize_direction, normalize_import_mode, normalize_kind, parse_feed_text,
        validate_comment, validate_name, validate_refresh_hours, validate_url, ThreatFeed,
        ThreatImportRequest, ThreatImportResult, MAX_FEED_ENTRIES,
    },
    repository::threatfeed_repository::{now_seconds, ThreatFeedRepository},
};
use sqlx::SqlitePool;

pub const DEFAULT_PAGE_SIZE: i64 = 100;
pub const MAX_PAGE_SIZE: i64 = 1000;

pub struct ThreatFeedService;

impl ThreatFeedService {
    pub async fn list(pool: &SqlitePool) -> Result<Vec<ThreatFeed>, String> {
        ThreatFeedRepository::list_feeds(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn get(pool: &SqlitePool, id: i64) -> Result<ThreatFeed, String> {
        ThreatFeedRepository::get_feed(pool, id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("Threat feed {} does not exist", id))
    }

    /// Checks everything a client sent and returns the cleaned feed. The status fields are reset,
    /// because only the server decides those.
    fn clean(feed: ThreatFeed, kind: &str) -> Result<ThreatFeed, String> {
        let name = validate_name(&feed.name)?;

        let direction = normalize_direction(&feed.direction)
            .ok_or("Direction must be 'inbound', 'outbound' or 'both'")?
            .to_string();

        let refresh_hours = validate_refresh_hours(feed.refresh_hours)?;
        let comment = validate_comment(&feed.comment)?;

        let url = match kind {
            "url" => {
                let url = feed
                    .url
                    .as_deref()
                    .ok_or("A download feed needs a URL")?;
                Some(validate_url(url)?)
            }
            _ => {
                if feed.url.as_deref().map(|u| !u.trim().is_empty()).unwrap_or(false) {
                    return Err("A manual feed cannot have a URL".into());
                }
                None
            }
        };

        Ok(ThreatFeed {
            id: None,
            name,
            kind: kind.to_string(),
            url,
            enabled: feed.enabled,
            direction,
            refresh_hours,
            log_enabled: feed.log_enabled,
            comment,
            last_updated: None,
            last_attempt: None,
            last_error: None,
            ipv4_count: 0,
            ipv6_count: 0,
        })
    }

    async fn ensure_name_is_free(
        pool: &SqlitePool,
        name: &str,
        own_id: Option<i64>,
    ) -> Result<(), String> {
        let existing = ThreatFeedRepository::get_feed_by_name(pool, name)
            .await
            .map_err(|e| e.to_string())?;

        match existing {
            Some(other) if other.id != own_id => {
                Err(format!("A threat feed named '{}' already exists", name))
            }
            _ => Ok(()),
        }
    }

    pub async fn add(pool: &SqlitePool, feed: ThreatFeed) -> Result<i64, String> {
        let kind = normalize_kind(&feed.kind).ok_or("Kind must be 'url' or 'manual'")?;
        let feed = Self::clean(feed, kind)?;

        Self::ensure_name_is_free(pool, &feed.name, None).await?;

        ThreatFeedRepository::add_feed(pool, &feed)
            .await
            .map_err(|e| e.to_string())
    }

    /// The kind of a feed is fixed when it is created: a download feed stays a download feed and a manual
    /// feed stays manual, whatever `kind` an update carries.
    pub async fn update(pool: &SqlitePool, id: i64, feed: ThreatFeed) -> Result<(), String> {
        let current = Self::get(pool, id).await?;

        let mut feed = feed;
        if current.kind == "manual" {
            feed.url = None;
        }

        let cleaned = Self::clean(feed, &current.kind)?;

        Self::ensure_name_is_free(pool, &cleaned.name, Some(id)).await?;

        let changed = ThreatFeedRepository::update_feed(pool, id, &cleaned)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("Threat feed {} does not exist", id));
        }

        Ok(())
    }

    pub async fn delete(pool: &SqlitePool, id: i64) -> Result<(), String> {
        let changed = ThreatFeedRepository::delete_feed(pool, id)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("Threat feed {} does not exist", id));
        }

        Ok(())
    }

    /// Manual IOC import. Only manual feeds take pasted lists, because a download feed would
    /// overwrite them at its next refresh.
    pub async fn import(
        pool: &SqlitePool,
        id: i64,
        request: ThreatImportRequest,
    ) -> Result<ThreatImportResult, String> {
        let feed = Self::get(pool, id).await?;

        if feed.kind != "manual" {
            return Err(
                "Only manual feeds take imported lists, a download feed is refreshed from its URL"
                    .into(),
            );
        }

        let mode = normalize_import_mode(&request.mode)
            .ok_or("Mode must be 'append' or 'replace'")?;

        let parsed = parse_feed_text(&request.data)?;

        if mode == "append" {
            let stored = ThreatFeedRepository::count_entries(pool, id)
                .await
                .map_err(|e| e.to_string())? as usize;

            if stored + parsed.ipv4.len() + parsed.ipv6.len() > MAX_FEED_ENTRIES {
                return Err(format!(
                    "The feed would hold more than {} networks, which is more than one feed may hold",
                    MAX_FEED_ENTRIES
                ));
            }

            ThreatFeedRepository::append_entries(pool, id, &parsed, now_seconds())
                .await
                .map_err(|e| e.to_string())?;
        } else {
            ThreatFeedRepository::replace_entries(pool, id, &parsed, now_seconds())
                .await
                .map_err(|e| e.to_string())?;
        }

        let after = Self::get(pool, id).await?;

        Ok(ThreatImportResult {
            feed_id: id,
            ipv4_imported: parsed.ipv4.len(),
            ipv6_imported: parsed.ipv6.len(),
            skipped: parsed.skipped,
            ipv4_total: after.ipv4_count,
            ipv6_total: after.ipv6_count,
        })
    }

    /// One page of a feed's networks. `search` matches any part of the address text.
    pub async fn entries(
        pool: &SqlitePool,
        id: i64,
        search: Option<String>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<(i64, i64, i64, Vec<String>), String> {
        Self::get(pool, id).await?;

        let limit = limit.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);
        let offset = offset.unwrap_or(0).max(0);

        let search = search
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        if let Some(text) = &search {
            if text.chars().count() > 64 || text.chars().any(|c| c.is_control()) {
                return Err("Search text is too long or has control characters".into());
            }
        }

        let (total, entries) =
            ThreatFeedRepository::page_entries(pool, id, search.as_deref(), limit, offset)
                .await
                .map_err(|e| e.to_string())?;

        Ok((total, limit, offset, entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::init::initialize_database;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        initialize_database(&pool).await.unwrap();
        pool
    }

    fn url_feed(name: &str, url: &str) -> ThreatFeed {
        serde_json::from_value(serde_json::json!({ "name": name, "url": url })).unwrap()
    }

    fn manual_feed(name: &str) -> ThreatFeed {
        serde_json::from_value(serde_json::json!({ "name": name, "kind": "manual" })).unwrap()
    }

    fn import(data: &str, mode: Option<&str>) -> ThreatImportRequest {
        ThreatImportRequest {
            data: data.to_string(),
            mode: mode.map(|m| m.to_string()),
        }
    }

    #[tokio::test]
    async fn a_download_feed_is_cleaned_and_stored() {
        let pool = memory_pool().await;

        let mut feed = url_feed("  Feodo  ", " https://feodotracker.abuse.ch/downloads/ipblocklist.txt ");
        feed.direction = " INBOUND ".into();
        feed.comment = Some("  c2 servers ".into());
        feed.last_error = Some("client tried to set this".into());
        feed.ipv4_count = 99;

        let id = ThreatFeedService::add(&pool, feed).await.unwrap();
        let stored = ThreatFeedService::get(&pool, id).await.unwrap();

        assert_eq!(stored.name, "Feodo");
        assert_eq!(stored.kind, "url");
        assert_eq!(
            stored.url.as_deref(),
            Some("https://feodotracker.abuse.ch/downloads/ipblocklist.txt")
        );
        assert_eq!(stored.direction, "inbound");
        assert_eq!(stored.comment.as_deref(), Some("c2 servers"));
        assert_eq!(stored.last_error, None);
        assert_eq!(stored.ipv4_count, 0);
    }

    #[tokio::test]
    async fn bad_feeds_are_refused() {
        let pool = memory_pool().await;

        let mut bad_direction = url_feed("a", "https://example.com/l.txt");
        bad_direction.direction = "sideways".into();

        let mut bad_interval = url_feed("b", "https://example.com/l.txt");
        bad_interval.refresh_hours = 0;

        let mut bad_kind = url_feed("c", "https://example.com/l.txt");
        bad_kind.kind = "ftp".into();

        let mut manual_with_url = manual_feed("d");
        manual_with_url.url = Some("https://example.com/l.txt".into());

        for feed in [
            url_feed("", "https://example.com/l.txt"),
            url_feed("bad;name", "https://example.com/l.txt"),
            url_feed("e", "http://127.0.0.1/list"),
            url_feed("f", "ftp://example.com/l.txt"),
            serde_json::from_value(serde_json::json!({ "name": "g" })).unwrap(),
            bad_direction,
            bad_interval,
            bad_kind,
            manual_with_url,
        ] {
            let name = feed.name.clone();
            assert!(ThreatFeedService::add(&pool, feed).await.is_err(), "accepted {:?}", name);
        }

        assert!(ThreatFeedService::list(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn names_are_unique_ignoring_case() {
        let pool = memory_pool().await;

        ThreatFeedService::add(&pool, manual_feed("IOCs")).await.unwrap();
        let error = ThreatFeedService::add(&pool, manual_feed("iocs")).await.unwrap_err();
        assert!(error.contains("already exists"));
    }

    #[tokio::test]
    async fn update_changes_settings_but_never_the_kind() {
        let pool = memory_pool().await;

        let id = ThreatFeedService::add(&pool, url_feed("f", "https://example.com/a.txt")).await.unwrap();

        let mut changed = url_feed("renamed", "https://example.com/b.txt");
        changed.enabled = false;
        changed.refresh_hours = 24;
        ThreatFeedService::update(&pool, id, changed).await.unwrap();

        let stored = ThreatFeedService::get(&pool, id).await.unwrap();
        assert_eq!(stored.name, "renamed");
        assert_eq!(stored.url.as_deref(), Some("https://example.com/b.txt"));
        assert!(!stored.enabled);
        assert_eq!(stored.refresh_hours, 24);

        let mut to_manual = url_feed("renamed", "https://example.com/b.txt");
        to_manual.kind = "manual".into();
        ThreatFeedService::update(&pool, id, to_manual).await.unwrap();
        assert_eq!(ThreatFeedService::get(&pool, id).await.unwrap().kind, "url");

        let mut no_url = manual_feed("renamed");
        no_url.kind = "url".into();
        no_url.url = None;
        assert!(ThreatFeedService::update(&pool, id, no_url).await.is_err());

        assert!(ThreatFeedService::update(&pool, 99, url_feed("x", "https://example.com/c.txt")).await.is_err());
    }

    #[tokio::test]
    async fn renaming_onto_another_feeds_name_is_refused_but_keeping_your_own_is_fine() {
        let pool = memory_pool().await;

        let a = ThreatFeedService::add(&pool, manual_feed("a")).await.unwrap();
        ThreatFeedService::add(&pool, manual_feed("b")).await.unwrap();

        assert!(ThreatFeedService::update(&pool, a, manual_feed("B")).await.is_err());
        assert!(ThreatFeedService::update(&pool, a, manual_feed("A")).await.is_ok());
    }

    #[tokio::test]
    async fn a_manual_feed_ignores_a_url_sent_on_update() {
        let pool = memory_pool().await;
        let id = ThreatFeedService::add(&pool, manual_feed("iocs")).await.unwrap();

        let mut update = manual_feed("iocs");
        update.url = Some("https://example.com/l.txt".into());
        ThreatFeedService::update(&pool, id, update).await.unwrap();

        assert_eq!(ThreatFeedService::get(&pool, id).await.unwrap().url, None);
    }

    #[tokio::test]
    async fn manual_import_appends_by_default_and_can_replace() {
        let pool = memory_pool().await;
        let id = ThreatFeedService::add(&pool, manual_feed("iocs")).await.unwrap();

        let first = ThreatFeedService::import(&pool, id, import("1.2.3.4\n5.6.7.0/24\n10.0.0.1\n", None))
            .await
            .unwrap();
        assert_eq!(first.ipv4_imported, 2);
        assert_eq!(first.skipped, 1);
        assert_eq!(first.ipv4_total, 2);

        let second = ThreatFeedService::import(&pool, id, import("1.2.3.4\n9.9.9.9\n2001:4860::1\n", Some("append")))
            .await
            .unwrap();
        assert_eq!(second.ipv4_total, 3);
        assert_eq!(second.ipv6_total, 1);

        let replaced = ThreatFeedService::import(&pool, id, import("8.8.4.4\n", Some("replace")))
            .await
            .unwrap();
        assert_eq!(replaced.ipv4_total, 1);
        assert_eq!(replaced.ipv6_total, 0);

        let stored = ThreatFeedService::get(&pool, id).await.unwrap();
        assert!(stored.last_updated.is_some());
    }

    #[tokio::test]
    async fn import_refuses_download_feeds_bad_modes_empty_lists_and_missing_feeds() {
        let pool = memory_pool().await;
        let manual = ThreatFeedService::add(&pool, manual_feed("iocs")).await.unwrap();
        let download = ThreatFeedService::add(&pool, url_feed("dl", "https://example.com/l.txt")).await.unwrap();

        assert!(ThreatFeedService::import(&pool, download, import("1.2.3.4\n", None)).await.is_err());
        assert!(ThreatFeedService::import(&pool, manual, import("1.2.3.4\n", Some("merge"))).await.is_err());
        assert!(ThreatFeedService::import(&pool, manual, import("# nothing here\n", None)).await.is_err());
        assert!(ThreatFeedService::import(&pool, 99, import("1.2.3.4\n", None)).await.is_err());

        assert_eq!(ThreatFeedService::get(&pool, manual).await.unwrap().ipv4_count, 0);
    }

    #[tokio::test]
    async fn a_failed_replace_import_keeps_the_old_list() {
        let pool = memory_pool().await;
        let id = ThreatFeedService::add(&pool, manual_feed("iocs")).await.unwrap();

        ThreatFeedService::import(&pool, id, import("1.2.3.4\n", None)).await.unwrap();
        assert!(ThreatFeedService::import(&pool, id, import("garbage\n", Some("replace"))).await.is_err());

        assert_eq!(ThreatFeedService::get(&pool, id).await.unwrap().ipv4_count, 1);
    }

    #[tokio::test]
    async fn delete_removes_the_feed_and_complains_about_a_missing_one() {
        let pool = memory_pool().await;
        let id = ThreatFeedService::add(&pool, manual_feed("iocs")).await.unwrap();

        ThreatFeedService::delete(&pool, id).await.unwrap();
        assert!(ThreatFeedService::delete(&pool, id).await.is_err());
        assert!(ThreatFeedService::get(&pool, id).await.is_err());
    }

    #[tokio::test]
    async fn entries_are_paged_clamped_and_searchable() {
        let pool = memory_pool().await;
        let id = ThreatFeedService::add(&pool, manual_feed("iocs")).await.unwrap();

        ThreatFeedService::import(&pool, id, import("1.2.3.4\n1.2.9.9\n5.6.7.8\n", None)).await.unwrap();

        let (total, limit, offset, page) = ThreatFeedService::entries(&pool, id, None, Some(2), Some(0)).await.unwrap();
        assert_eq!((total, limit, offset, page.len()), (3, 2, 0, 2));

        let (_, limit, offset, _) = ThreatFeedService::entries(&pool, id, None, Some(99999), Some(-4)).await.unwrap();
        assert_eq!((limit, offset), (MAX_PAGE_SIZE, 0));

        let (total, _, _, hits) = ThreatFeedService::entries(&pool, id, Some(" 1.2. ".into()), None, None).await.unwrap();
        assert_eq!(total, 2);
        assert_eq!(hits, vec!["1.2.3.4/32", "1.2.9.9/32"]);

        let (total, _, _, _) = ThreatFeedService::entries(&pool, id, Some("   ".into()), None, None).await.unwrap();
        assert_eq!(total, 3);

        assert!(ThreatFeedService::entries(&pool, id, Some("x".repeat(65)), None, None).await.is_err());
        assert!(ThreatFeedService::entries(&pool, 99, None, None, None).await.is_err());
    }
}
