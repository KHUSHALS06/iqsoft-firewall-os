use crate::models::threatfeed::{ParsedFeed, ThreatFeed};
use sqlx::{
    sqlite::{Sqlite, SqliteRow},
    QueryBuilder, Row, SqlitePool,
};
use std::time::{SystemTime, UNIX_EPOCH};

const INSERT_CHUNK: usize = 300;

/// After a failed download the feed is tried again after this long, not after its full interval.
const RETRY_AFTER_FAILURE_SECONDS: i64 = 900;

const FEED_COLUMNS: &str = r#"
    f.id, f.name, f.kind, f.url, f.enabled, f.direction, f.refresh_hours, f.log_enabled,
    f.comment, f.last_updated, f.last_attempt, f.last_error,
    (SELECT COUNT(*) FROM threat_feed_entries e WHERE e.feed_id = f.id AND e.family = 'ipv4') AS ipv4_count,
    (SELECT COUNT(*) FROM threat_feed_entries e WHERE e.feed_id = f.id AND e.family = 'ipv6') AS ipv6_count
"#;

pub fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub struct ThreatFeedRepository;

impl ThreatFeedRepository {
    fn row_to_feed(row: &SqliteRow) -> ThreatFeed {
        ThreatFeed {
            id: Some(row.get("id")),
            name: row.get("name"),
            kind: row.get("kind"),
            url: row.get("url"),
            enabled: row.get::<i64, _>("enabled") != 0,
            direction: row.get("direction"),
            refresh_hours: row.get("refresh_hours"),
            log_enabled: row.get::<i64, _>("log_enabled") != 0,
            comment: row.get("comment"),
            last_updated: row.get("last_updated"),
            last_attempt: row.get("last_attempt"),
            last_error: row.get("last_error"),
            ipv4_count: row.get("ipv4_count"),
            ipv6_count: row.get("ipv6_count"),
        }
    }

    pub async fn list_feeds(pool: &SqlitePool) -> Result<Vec<ThreatFeed>, sqlx::Error> {
        let sql = format!(
            "SELECT {} FROM threat_feeds f ORDER BY f.name COLLATE NOCASE ASC, f.id ASC",
            FEED_COLUMNS
        );

        let rows = sqlx::query(&sql).fetch_all(pool).await?;
        Ok(rows.iter().map(Self::row_to_feed).collect())
    }

    pub async fn list_enabled_feeds(pool: &SqlitePool) -> Result<Vec<ThreatFeed>, sqlx::Error> {
        let sql = format!(
            "SELECT {} FROM threat_feeds f WHERE f.enabled = 1 ORDER BY f.id ASC",
            FEED_COLUMNS
        );

        let rows = sqlx::query(&sql).fetch_all(pool).await?;
        Ok(rows.iter().map(Self::row_to_feed).collect())
    }

    /// Enabled download feeds whose next refresh time has come.
    pub async fn list_due_feeds(pool: &SqlitePool, now: i64) -> Result<Vec<ThreatFeed>, sqlx::Error> {
        let sql = format!(
            r#"
            SELECT {} FROM threat_feeds f
            WHERE f.enabled = 1
              AND f.kind = 'url'
              AND (
                    f.last_attempt IS NULL
                    OR f.last_attempt + (CASE WHEN f.last_error IS NULL
                                              THEN f.refresh_hours * 3600
                                              ELSE ? END) <= ?
                  )
            ORDER BY f.id ASC
            "#,
            FEED_COLUMNS
        );

        let rows = sqlx::query(&sql)
            .bind(RETRY_AFTER_FAILURE_SECONDS)
            .bind(now)
            .fetch_all(pool)
            .await?;

        Ok(rows.iter().map(Self::row_to_feed).collect())
    }

    pub async fn get_feed(pool: &SqlitePool, id: i64) -> Result<Option<ThreatFeed>, sqlx::Error> {
        let sql = format!("SELECT {} FROM threat_feeds f WHERE f.id = ?", FEED_COLUMNS);

        let row = sqlx::query(&sql).bind(id).fetch_optional(pool).await?;
        Ok(row.as_ref().map(Self::row_to_feed))
    }

    pub async fn get_feed_by_name(
        pool: &SqlitePool,
        name: &str,
    ) -> Result<Option<ThreatFeed>, sqlx::Error> {
        let sql = format!(
            "SELECT {} FROM threat_feeds f WHERE f.name = ? COLLATE NOCASE",
            FEED_COLUMNS
        );

        let row = sqlx::query(&sql).bind(name).fetch_optional(pool).await?;
        Ok(row.as_ref().map(Self::row_to_feed))
    }

    pub async fn add_feed(pool: &SqlitePool, feed: &ThreatFeed) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO threat_feeds (name, kind, url, enabled, direction, refresh_hours, log_enabled, comment)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&feed.name)
        .bind(&feed.kind)
        .bind(&feed.url)
        .bind(feed.enabled as i64)
        .bind(&feed.direction)
        .bind(feed.refresh_hours)
        .bind(feed.log_enabled as i64)
        .bind(&feed.comment)
        .execute(pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    /// The kind never changes. Changing the address forgets the old failure, so the new address is tried at once.
    pub async fn update_feed(
        pool: &SqlitePool,
        id: i64,
        feed: &ThreatFeed,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE threat_feeds
            SET name = ?,
                url = ?,
                enabled = ?,
                direction = ?,
                refresh_hours = ?,
                log_enabled = ?,
                comment = ?,
                last_attempt = CASE WHEN url IS NOT ? THEN NULL ELSE last_attempt END,
                last_error   = CASE WHEN url IS NOT ? THEN NULL ELSE last_error END
            WHERE id = ?
            "#,
        )
        .bind(&feed.name)
        .bind(&feed.url)
        .bind(feed.enabled as i64)
        .bind(&feed.direction)
        .bind(feed.refresh_hours)
        .bind(feed.log_enabled as i64)
        .bind(&feed.comment)
        .bind(&feed.url)
        .bind(&feed.url)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn delete_feed(pool: &SqlitePool, id: i64) -> Result<u64, sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query("DELETE FROM threat_feed_entries WHERE feed_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        let result = sqlx::query("DELETE FROM threat_feeds WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok(result.rows_affected())
    }

    /// Throws the old list away and stores the new one, all or nothing.
    /// Also marks the feed as freshly and successfully updated.
    pub async fn replace_entries(
        pool: &SqlitePool,
        id: i64,
        parsed: &ParsedFeed,
        now: i64,
    ) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query("DELETE FROM threat_feed_entries WHERE feed_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        Self::insert_entries(&mut tx, id, parsed).await?;

        sqlx::query(
            "UPDATE threat_feeds SET last_updated = ?, last_attempt = ?, last_error = NULL WHERE id = ?",
        )
        .bind(now)
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(())
    }

    /// Adds to the stored list; networks already there are left alone.
    pub async fn append_entries(
        pool: &SqlitePool,
        id: i64,
        parsed: &ParsedFeed,
        now: i64,
    ) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;

        Self::insert_entries(&mut tx, id, parsed).await?;

        sqlx::query(
            "UPDATE threat_feeds SET last_updated = ?, last_attempt = ?, last_error = NULL WHERE id = ?",
        )
        .bind(now)
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(())
    }

    async fn insert_entries(
        tx: &mut sqlx::Transaction<'_, Sqlite>,
        id: i64,
        parsed: &ParsedFeed,
    ) -> Result<(), sqlx::Error> {
        for (family, networks) in [("ipv4", &parsed.ipv4), ("ipv6", &parsed.ipv6)] {
            for chunk in networks.chunks(INSERT_CHUNK) {
                let mut builder: QueryBuilder<Sqlite> = QueryBuilder::new(
                    "INSERT OR IGNORE INTO threat_feed_entries (feed_id, family, cidr) ",
                );

                builder.push_values(chunk.iter(), |mut row, cidr| {
                    row.push_bind(id).push_bind(family).push_bind(cidr.as_str());
                });

                builder.build().execute(&mut **tx).await?;
            }
        }

        Ok(())
    }

    /// A failed download keeps the old list and only records what went wrong.
    pub async fn record_failure(
        pool: &SqlitePool,
        id: i64,
        now: i64,
        error: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE threat_feeds SET last_attempt = ?, last_error = ? WHERE id = ?")
            .bind(now)
            .bind(error)
            .bind(id)
            .execute(pool)
            .await?;

        Ok(())
    }

    pub async fn list_networks(
        pool: &SqlitePool,
        id: i64,
        family: &str,
    ) -> Result<Vec<String>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT cidr FROM threat_feed_entries WHERE feed_id = ? AND family = ? ORDER BY cidr ASC",
        )
        .bind(id)
        .bind(family)
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(|row| row.get::<String, _>("cidr")).collect())
    }

    pub async fn count_entries(pool: &SqlitePool, id: i64) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT COUNT(*) FROM threat_feed_entries WHERE feed_id = ?")
            .bind(id)
            .fetch_one(pool)
            .await
    }

    /// One page of a feed's networks, optionally only those that contain `search`.
    pub async fn page_entries(
        pool: &SqlitePool,
        id: i64,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(i64, Vec<String>), sqlx::Error> {
        let pattern = search.map(|s| {
            let escaped = s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
            format!("%{}%", escaped)
        });

        let total: i64 = match &pattern {
            Some(p) => sqlx::query_scalar(
                "SELECT COUNT(*) FROM threat_feed_entries WHERE feed_id = ? AND cidr LIKE ? ESCAPE '\\'",
            )
            .bind(id)
            .bind(p)
            .fetch_one(pool)
            .await?,
            None => Self::count_entries(pool, id).await?,
        };

        let rows = match &pattern {
            Some(p) => {
                sqlx::query(
                    r#"
                    SELECT cidr FROM threat_feed_entries
                    WHERE feed_id = ? AND cidr LIKE ? ESCAPE '\'
                    ORDER BY family ASC, cidr ASC
                    LIMIT ? OFFSET ?
                    "#,
                )
                .bind(id)
                .bind(p)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?
            }
            None => {
                sqlx::query(
                    r#"
                    SELECT cidr FROM threat_feed_entries
                    WHERE feed_id = ?
                    ORDER BY family ASC, cidr ASC
                    LIMIT ? OFFSET ?
                    "#,
                )
                .bind(id)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?
            }
        };

        Ok((
            total,
            rows.iter().map(|row| row.get::<String, _>("cidr")).collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::threatfeed_schema::create_threatfeed_tables;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        create_threatfeed_tables(&pool).await.unwrap();
        pool
    }

    fn feed(name: &str, kind: &str, url: Option<&str>) -> ThreatFeed {
        ThreatFeed {
            id: None,
            name: name.to_string(),
            kind: kind.to_string(),
            url: url.map(|u| u.to_string()),
            enabled: true,
            direction: "both".to_string(),
            refresh_hours: 6,
            log_enabled: false,
            comment: None,
            last_updated: None,
            last_attempt: None,
            last_error: None,
            ipv4_count: 0,
            ipv6_count: 0,
        }
    }

    fn parsed(v4: &[&str], v6: &[&str]) -> ParsedFeed {
        ParsedFeed {
            ipv4: v4.iter().map(|s| s.to_string()).collect(),
            ipv6: v6.iter().map(|s| s.to_string()).collect(),
            skipped: 0,
        }
    }

    #[tokio::test]
    async fn a_feed_can_be_added_read_back_and_found_by_name_ignoring_case() {
        let pool = memory_pool().await;

        let id = ThreatFeedRepository::add_feed(&pool, &feed("Spam", "url", Some("https://example.com/l.txt")))
            .await
            .unwrap();

        let stored = ThreatFeedRepository::get_feed(&pool, id).await.unwrap().unwrap();
        assert_eq!(stored.name, "Spam");
        assert_eq!(stored.kind, "url");
        assert_eq!(stored.url.as_deref(), Some("https://example.com/l.txt"));
        assert!(stored.enabled);
        assert_eq!(stored.ipv4_count, 0);
        assert_eq!(stored.last_updated, None);

        let by_name = ThreatFeedRepository::get_feed_by_name(&pool, "SPAM").await.unwrap();
        assert_eq!(by_name.unwrap().id, Some(id));

        assert!(ThreatFeedRepository::get_feed(&pool, 99).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn replacing_entries_swaps_the_list_and_stamps_the_feed() {
        let pool = memory_pool().await;
        let id = ThreatFeedRepository::add_feed(&pool, &feed("iocs", "manual", None)).await.unwrap();

        ThreatFeedRepository::record_failure(&pool, id, 50, "boom").await.unwrap();

        ThreatFeedRepository::replace_entries(
            &pool,
            id,
            &parsed(&["1.2.3.4/32", "5.6.7.0/24"], &["2001:4860::/32"]),
            1000,
        )
        .await
        .unwrap();

        let stored = ThreatFeedRepository::get_feed(&pool, id).await.unwrap().unwrap();
        assert_eq!(stored.ipv4_count, 2);
        assert_eq!(stored.ipv6_count, 1);
        assert_eq!(stored.last_updated, Some(1000));
        assert_eq!(stored.last_attempt, Some(1000));
        assert_eq!(stored.last_error, None);

        ThreatFeedRepository::replace_entries(&pool, id, &parsed(&["9.9.9.9/32"], &[]), 2000)
            .await
            .unwrap();

        assert_eq!(
            ThreatFeedRepository::list_networks(&pool, id, "ipv4").await.unwrap(),
            vec!["9.9.9.9/32"]
        );
        assert!(ThreatFeedRepository::list_networks(&pool, id, "ipv6").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn appending_keeps_the_old_entries_and_ignores_duplicates() {
        let pool = memory_pool().await;
        let id = ThreatFeedRepository::add_feed(&pool, &feed("iocs", "manual", None)).await.unwrap();

        ThreatFeedRepository::append_entries(&pool, id, &parsed(&["1.2.3.4/32"], &[]), 10)
            .await
            .unwrap();
        ThreatFeedRepository::append_entries(&pool, id, &parsed(&["1.2.3.4/32", "5.6.7.8/32"], &[]), 20)
            .await
            .unwrap();

        assert_eq!(
            ThreatFeedRepository::list_networks(&pool, id, "ipv4").await.unwrap(),
            vec!["1.2.3.4/32", "5.6.7.8/32"]
        );
        assert_eq!(ThreatFeedRepository::count_entries(&pool, id).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn a_big_list_goes_in_across_several_inserts() {
        let pool = memory_pool().await;
        let id = ThreatFeedRepository::add_feed(&pool, &feed("big", "manual", None)).await.unwrap();

        let many: Vec<String> = (0..1000u32)
            .map(|i| format!("{}/32", std::net::Ipv4Addr::from(0x0B00_0000u32 + i)))
            .collect();
        let list = ParsedFeed { ipv4: many, ipv6: vec![], skipped: 0 };

        ThreatFeedRepository::replace_entries(&pool, id, &list, 1).await.unwrap();

        assert_eq!(ThreatFeedRepository::count_entries(&pool, id).await.unwrap(), 1000);
    }

    #[tokio::test]
    async fn a_failure_keeps_the_old_list_and_records_the_error() {
        let pool = memory_pool().await;
        let id = ThreatFeedRepository::add_feed(&pool, &feed("f", "url", Some("https://example.com/l")))
            .await
            .unwrap();

        ThreatFeedRepository::replace_entries(&pool, id, &parsed(&["1.2.3.4/32"], &[]), 100)
            .await
            .unwrap();
        ThreatFeedRepository::record_failure(&pool, id, 200, "HTTP 503").await.unwrap();

        let stored = ThreatFeedRepository::get_feed(&pool, id).await.unwrap().unwrap();
        assert_eq!(stored.ipv4_count, 1);
        assert_eq!(stored.last_updated, Some(100));
        assert_eq!(stored.last_attempt, Some(200));
        assert_eq!(stored.last_error.as_deref(), Some("HTTP 503"));
    }

    #[tokio::test]
    async fn update_changes_settings_and_a_new_url_clears_the_old_failure() {
        let pool = memory_pool().await;
        let id = ThreatFeedRepository::add_feed(&pool, &feed("f", "url", Some("https://example.com/old")))
            .await
            .unwrap();

        ThreatFeedRepository::record_failure(&pool, id, 200, "HTTP 404").await.unwrap();

        let mut changed = feed("renamed", "url", Some("https://example.com/old"));
        changed.enabled = false;
        changed.direction = "inbound".into();
        changed.refresh_hours = 12;
        changed.log_enabled = true;
        changed.comment = Some("note".into());

        assert_eq!(ThreatFeedRepository::update_feed(&pool, id, &changed).await.unwrap(), 1);

        let stored = ThreatFeedRepository::get_feed(&pool, id).await.unwrap().unwrap();
        assert_eq!(stored.name, "renamed");
        assert!(!stored.enabled);
        assert_eq!(stored.direction, "inbound");
        assert_eq!(stored.refresh_hours, 12);
        assert!(stored.log_enabled);
        assert_eq!(stored.comment.as_deref(), Some("note"));
        assert_eq!(stored.last_error.as_deref(), Some("HTTP 404"));
        assert_eq!(stored.last_attempt, Some(200));

        changed.url = Some("https://example.com/new".into());
        ThreatFeedRepository::update_feed(&pool, id, &changed).await.unwrap();

        let stored = ThreatFeedRepository::get_feed(&pool, id).await.unwrap().unwrap();
        assert_eq!(stored.url.as_deref(), Some("https://example.com/new"));
        assert_eq!(stored.last_error, None);
        assert_eq!(stored.last_attempt, None);

        assert_eq!(ThreatFeedRepository::update_feed(&pool, 99, &changed).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn deleting_a_feed_removes_its_entries() {
        let pool = memory_pool().await;
        let id = ThreatFeedRepository::add_feed(&pool, &feed("iocs", "manual", None)).await.unwrap();
        let other = ThreatFeedRepository::add_feed(&pool, &feed("other", "manual", None)).await.unwrap();

        ThreatFeedRepository::replace_entries(&pool, id, &parsed(&["1.2.3.4/32"], &[]), 1).await.unwrap();
        ThreatFeedRepository::replace_entries(&pool, other, &parsed(&["5.6.7.8/32"], &[]), 1).await.unwrap();

        assert_eq!(ThreatFeedRepository::delete_feed(&pool, id).await.unwrap(), 1);
        assert_eq!(ThreatFeedRepository::delete_feed(&pool, id).await.unwrap(), 0);

        assert_eq!(ThreatFeedRepository::count_entries(&pool, id).await.unwrap(), 0);
        assert_eq!(ThreatFeedRepository::count_entries(&pool, other).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn lists_are_sorted_by_name_and_enabled_feeds_are_filtered() {
        let pool = memory_pool().await;

        ThreatFeedRepository::add_feed(&pool, &feed("beta", "manual", None)).await.unwrap();
        let mut off = feed("Alpha", "manual", None);
        off.enabled = false;
        ThreatFeedRepository::add_feed(&pool, &off).await.unwrap();

        let names: Vec<String> = ThreatFeedRepository::list_feeds(&pool)
            .await
            .unwrap()
            .into_iter()
            .map(|f| f.name)
            .collect();
        assert_eq!(names, vec!["Alpha", "beta"]);

        let enabled = ThreatFeedRepository::list_enabled_feeds(&pool).await.unwrap();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].name, "beta");
    }

    #[tokio::test]
    async fn due_feeds_are_enabled_url_feeds_past_their_interval() {
        let pool = memory_pool().await;

        let never = ThreatFeedRepository::add_feed(&pool, &feed("never", "url", Some("https://e.com/1"))).await.unwrap();
        let fresh = ThreatFeedRepository::add_feed(&pool, &feed("fresh", "url", Some("https://e.com/2"))).await.unwrap();
        let stale = ThreatFeedRepository::add_feed(&pool, &feed("stale", "url", Some("https://e.com/3"))).await.unwrap();
        let failed_recently = ThreatFeedRepository::add_feed(&pool, &feed("failed-recently", "url", Some("https://e.com/4"))).await.unwrap();
        let failed_long_ago = ThreatFeedRepository::add_feed(&pool, &feed("failed-long-ago", "url", Some("https://e.com/5"))).await.unwrap();
        ThreatFeedRepository::add_feed(&pool, &feed("manual", "manual", None)).await.unwrap();
        let mut disabled = feed("disabled", "url", Some("https://e.com/6"));
        disabled.enabled = false;
        ThreatFeedRepository::add_feed(&pool, &disabled).await.unwrap();

        let now = 1_000_000;
        let hour = 3600;

        ThreatFeedRepository::replace_entries(&pool, fresh, &parsed(&["1.2.3.4/32"], &[]), now - hour).await.unwrap();
        ThreatFeedRepository::replace_entries(&pool, stale, &parsed(&["1.2.3.4/32"], &[]), now - 7 * hour).await.unwrap();
        ThreatFeedRepository::record_failure(&pool, failed_recently, now - 600, "x").await.unwrap();
        ThreatFeedRepository::record_failure(&pool, failed_long_ago, now - 1000, "x").await.unwrap();

        let due: Vec<i64> = ThreatFeedRepository::list_due_feeds(&pool, now)
            .await
            .unwrap()
            .into_iter()
            .filter_map(|f| f.id)
            .collect();

        assert_eq!(due, vec![never, stale, failed_long_ago]);
    }

    #[tokio::test]
    async fn entries_can_be_paged_and_searched() {
        let pool = memory_pool().await;
        let id = ThreatFeedRepository::add_feed(&pool, &feed("iocs", "manual", None)).await.unwrap();

        ThreatFeedRepository::replace_entries(
            &pool,
            id,
            &parsed(&["1.2.3.4/32", "1.2.9.0/24", "5.6.7.8/32"], &["2001:4860::/32"]),
            1,
        )
        .await
        .unwrap();

        let (total, page) = ThreatFeedRepository::page_entries(&pool, id, None, 2, 0).await.unwrap();
        assert_eq!(total, 4);
        assert_eq!(page.len(), 2);

        let (_, rest) = ThreatFeedRepository::page_entries(&pool, id, None, 10, 2).await.unwrap();
        assert_eq!(rest.len(), 2);

        let (total, hits) = ThreatFeedRepository::page_entries(&pool, id, Some("1.2."), 10, 0).await.unwrap();
        assert_eq!(total, 2);
        assert_eq!(hits, vec!["1.2.3.4/32", "1.2.9.0/24"]);

        let (total, hits) = ThreatFeedRepository::page_entries(&pool, id, Some("%"), 10, 0).await.unwrap();
        assert_eq!(total, 0);
        assert!(hits.is_empty());

        let (total, hits) = ThreatFeedRepository::page_entries(&pool, id, Some("2001:"), 10, 0).await.unwrap();
        assert_eq!(total, 1);
        assert_eq!(hits, vec!["2001:4860::/32"]);
    }
}
