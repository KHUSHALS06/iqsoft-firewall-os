use crate::models::ids::{IdsEvent, IdsRuleOverride, IdsSettings};
use sqlx::{sqlite::SqliteRow, Row, SqlitePool};

pub struct IdsRepository;

const INSERT_EVENT: &str = r#"
    INSERT INTO ids_events
        (ts, src_ip, src_port, dest_ip, dest_port, proto, app_proto,
         sid, signature, category, severity, action)
    VALUES
        (COALESCE(NULLIF(?, 0), CAST(strftime('%s', 'now') AS INTEGER)),
         ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"#;

impl IdsRepository {
    fn row_to_override(row: &SqliteRow) -> IdsRuleOverride {
        IdsRuleOverride {
            id: Some(row.get("id")),
            sid: row.get("sid"),
            action: row.get("action"),
            comment: row.get("comment"),
        }
    }

    fn row_to_event(row: &SqliteRow) -> IdsEvent {
        IdsEvent {
            id: Some(row.get("id")),
            ts: row.get("ts"),
            src_ip: row.get("src_ip"),
            src_port: row.get("src_port"),
            dest_ip: row.get("dest_ip"),
            dest_port: row.get("dest_port"),
            proto: row.get("proto"),
            app_proto: row.get("app_proto"),
            sid: row.get("sid"),
            signature: row.get("signature"),
            category: row.get("category"),
            severity: row.get("severity"),
            action: row.get("action"),
        }
    }

    pub async fn get_settings(pool: &SqlitePool) -> Result<IdsSettings, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT enabled, mode, interfaces, queue_num, fail_mode, home_net,
                   rule_update_hours, event_retention_days
            FROM ids_settings
            WHERE id = 1
            "#,
        )
        .fetch_one(pool)
        .await?;

        Ok(IdsSettings {
            enabled: row.get::<i64, _>("enabled") != 0,
            mode: row.get("mode"),
            interfaces: row.get("interfaces"),
            queue_num: row.get("queue_num"),
            fail_mode: row.get("fail_mode"),
            home_net: row.get("home_net"),
            rule_update_hours: row.get("rule_update_hours"),
            event_retention_days: row.get("event_retention_days"),
        })
    }

    pub async fn set_settings(
        pool: &SqlitePool,
        settings: &IdsSettings,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE ids_settings
            SET enabled = ?,
                mode = ?,
                interfaces = ?,
                queue_num = ?,
                fail_mode = ?,
                home_net = ?,
                rule_update_hours = ?,
                event_retention_days = ?
            WHERE id = 1
            "#,
        )
        .bind(settings.enabled)
        .bind(&settings.mode)
        .bind(&settings.interfaces)
        .bind(settings.queue_num)
        .bind(&settings.fail_mode)
        .bind(&settings.home_net)
        .bind(settings.rule_update_hours)
        .bind(settings.event_retention_days)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn list_overrides(pool: &SqlitePool) -> Result<Vec<IdsRuleOverride>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, sid, action, comment FROM ids_rule_overrides ORDER BY sid ASC",
        )
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_override).collect())
    }

    pub async fn get_override(
        pool: &SqlitePool,
        sid: i64,
    ) -> Result<Option<IdsRuleOverride>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, sid, action, comment FROM ids_rule_overrides WHERE sid = ?",
        )
        .bind(sid)
        .fetch_optional(pool)
        .await?;

        Ok(row.as_ref().map(Self::row_to_override))
    }

    pub async fn add_override(
        pool: &SqlitePool,
        rule: &IdsRuleOverride,
    ) -> Result<i64, sqlx::Error> {
        let result =
            sqlx::query("INSERT INTO ids_rule_overrides (sid, action, comment) VALUES (?, ?, ?)")
                .bind(rule.sid)
                .bind(&rule.action)
                .bind(&rule.comment)
                .execute(pool)
                .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn delete_override(pool: &SqlitePool, id: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM ids_rule_overrides WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }

    pub async fn add_event(pool: &SqlitePool, event: &IdsEvent) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(INSERT_EVENT)
            .bind(event.ts)
            .bind(&event.src_ip)
            .bind(event.src_port)
            .bind(&event.dest_ip)
            .bind(event.dest_port)
            .bind(&event.proto)
            .bind(&event.app_proto)
            .bind(event.sid)
            .bind(&event.signature)
            .bind(&event.category)
            .bind(event.severity)
            .bind(&event.action)
            .execute(pool)
            .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn add_events(pool: &SqlitePool, events: &[IdsEvent]) -> Result<u64, sqlx::Error> {
        if events.is_empty() {
            return Ok(0);
        }

        let mut tx = pool.begin().await?;

        for event in events {
            sqlx::query(INSERT_EVENT)
                .bind(event.ts)
                .bind(&event.src_ip)
                .bind(event.src_port)
                .bind(&event.dest_ip)
                .bind(event.dest_port)
                .bind(&event.proto)
                .bind(&event.app_proto)
                .bind(event.sid)
                .bind(&event.signature)
                .bind(&event.category)
                .bind(event.severity)
                .bind(&event.action)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;

        Ok(events.len() as u64)
    }

    pub async fn list_events(
        pool: &SqlitePool,
        limit: i64,
        offset: i64,
        action: Option<&str>,
        sid: Option<i64>,
    ) -> Result<Vec<IdsEvent>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, ts, src_ip, src_port, dest_ip, dest_port, proto, app_proto,
                   sid, signature, category, severity, action
            FROM ids_events
            WHERE (? IS NULL OR action = ?)
              AND (? IS NULL OR sid = ?)
            ORDER BY ts DESC, id DESC
            LIMIT ? OFFSET ?
            "#,
        )
        .bind(action)
        .bind(action)
        .bind(sid)
        .bind(sid)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_event).collect())
    }

    pub async fn count_events(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT COUNT(*) FROM ids_events")
            .fetch_one(pool)
            .await
    }

    pub async fn count_events_since(
        pool: &SqlitePool,
        action: &str,
        since: i64,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT COUNT(*) FROM ids_events WHERE action = ? AND ts >= ?")
            .bind(action)
            .bind(since)
            .fetch_one(pool)
            .await
    }

    pub async fn top_signatures(
        pool: &SqlitePool,
        since: i64,
        limit: i64,
    ) -> Result<Vec<(i64, String, i64)>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT sid, MAX(signature) AS signature, COUNT(*) AS hits
            FROM ids_events
            WHERE ts >= ?
            GROUP BY sid
            ORDER BY hits DESC, sid ASC
            LIMIT ?
            "#,
        )
        .bind(since)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(rows
            .iter()
            .map(|row| (row.get("sid"), row.get("signature"), row.get("hits")))
            .collect())
    }

    pub async fn prune_events_before(pool: &SqlitePool, cutoff: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM ids_events WHERE ts < ?")
            .bind(cutoff)
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }

    pub async fn prune_events(pool: &SqlitePool, keep: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM ids_events
            WHERE id NOT IN (
                SELECT id FROM ids_events ORDER BY ts DESC, id DESC LIMIT ?
            )
            "#,
        )
        .bind(keep)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn clear_events(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM ids_events").execute(pool).await?;

        Ok(result.rows_affected())
    }
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
            comment: Some("test".into()),
        }
    }

    #[tokio::test]
    async fn settings_start_at_defaults_and_round_trip() {
        let pool = memory_pool().await;

        let defaults = IdsRepository::get_settings(&pool).await.unwrap();
        assert!(!defaults.enabled);
        assert_eq!(defaults.mode, "ids");
        assert_eq!(defaults.queue_num, 200);

        let changed = IdsSettings {
            enabled: true,
            mode: "ips".into(),
            interfaces: "eth0,eth1".into(),
            queue_num: 300,
            fail_mode: "closed".into(),
            home_net: "[10.0.0.0/8]".into(),
            rule_update_hours: 12,
            event_retention_days: 7,
        };

        IdsRepository::set_settings(&pool, &changed).await.unwrap();

        assert_eq!(IdsRepository::get_settings(&pool).await.unwrap(), changed);
    }

    #[tokio::test]
    async fn settings_the_database_refuses_are_not_saved() {
        let pool = memory_pool().await;

        let mut bad = IdsRepository::get_settings(&pool).await.unwrap();
        bad.queue_num = 100;

        assert!(IdsRepository::set_settings(&pool, &bad).await.is_err());
        assert_eq!(IdsRepository::get_settings(&pool).await.unwrap().queue_num, 200);
    }

    #[tokio::test]
    async fn overrides_can_be_added_found_listed_and_deleted() {
        let pool = memory_pool().await;

        let first = IdsRepository::add_override(&pool, &rule(2_000_002, "drop")).await.unwrap();
        IdsRepository::add_override(&pool, &rule(2_000_001, "disable")).await.unwrap();

        let list = IdsRepository::list_overrides(&pool).await.unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].sid, 2_000_001);
        assert_eq!(list[1].sid, 2_000_002);

        let found = IdsRepository::get_override(&pool, 2_000_002).await.unwrap().unwrap();
        assert_eq!(found.id, Some(first));
        assert_eq!(found.action, "drop");

        assert!(IdsRepository::get_override(&pool, 1).await.unwrap().is_none());

        assert_eq!(IdsRepository::delete_override(&pool, first).await.unwrap(), 1);
        assert_eq!(IdsRepository::delete_override(&pool, first).await.unwrap(), 0);
        assert_eq!(IdsRepository::list_overrides(&pool).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_second_override_for_the_same_signature_is_refused() {
        let pool = memory_pool().await;

        IdsRepository::add_override(&pool, &rule(2_000_001, "disable")).await.unwrap();

        assert!(IdsRepository::add_override(&pool, &rule(2_000_001, "drop")).await.is_err());
    }

    #[tokio::test]
    async fn events_list_newest_first_and_filter() {
        let pool = memory_pool().await;

        IdsRepository::add_event(&pool, &event(1, "allowed", 100)).await.unwrap();
        IdsRepository::add_event(&pool, &event(2, "blocked", 300)).await.unwrap();
        IdsRepository::add_event(&pool, &event(1, "blocked", 200)).await.unwrap();

        let all = IdsRepository::list_events(&pool, 10, 0, None, None).await.unwrap();
        assert_eq!(all.iter().map(|e| e.ts).collect::<Vec<_>>(), vec![300, 200, 100]);

        let blocked = IdsRepository::list_events(&pool, 10, 0, Some("blocked"), None).await.unwrap();
        assert_eq!(blocked.len(), 2);

        let sid_one = IdsRepository::list_events(&pool, 10, 0, None, Some(1)).await.unwrap();
        assert_eq!(sid_one.len(), 2);

        let both = IdsRepository::list_events(&pool, 10, 0, Some("blocked"), Some(1)).await.unwrap();
        assert_eq!(both.len(), 1);
        assert_eq!(both[0].ts, 200);

        let page = IdsRepository::list_events(&pool, 1, 1, None, None).await.unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].ts, 200);
    }

    #[tokio::test]
    async fn a_zero_timestamp_means_now() {
        let pool = memory_pool().await;

        IdsRepository::add_event(&pool, &event(1, "allowed", 0)).await.unwrap();

        let saved = IdsRepository::list_events(&pool, 1, 0, None, None).await.unwrap();
        assert!(saved[0].ts > 1_700_000_000);
    }

    #[tokio::test]
    async fn events_round_trip_with_missing_optional_fields() {
        let pool = memory_pool().await;

        let mut icmp = event(7, "allowed", 50);
        icmp.src_port = None;
        icmp.dest_port = None;
        icmp.app_proto = None;
        icmp.category = None;
        icmp.proto = "ICMP".into();

        IdsRepository::add_event(&pool, &icmp).await.unwrap();

        let saved = IdsRepository::list_events(&pool, 1, 0, None, None).await.unwrap();
        assert_eq!(saved[0].src_port, None);
        assert_eq!(saved[0].dest_port, None);
        assert_eq!(saved[0].app_proto, None);
        assert_eq!(saved[0].category, None);
        assert_eq!(saved[0].proto, "ICMP");
    }

    #[tokio::test]
    async fn batches_are_all_saved_or_none() {
        let pool = memory_pool().await;

        let good = vec![event(1, "allowed", 10), event(2, "blocked", 20)];
        assert_eq!(IdsRepository::add_events(&pool, &good).await.unwrap(), 2);
        assert_eq!(IdsRepository::add_events(&pool, &[]).await.unwrap(), 0);

        let mut broken = vec![event(3, "allowed", 30), event(4, "allowed", 40)];
        broken[1].severity = 9;
        assert!(IdsRepository::add_events(&pool, &broken).await.is_err());

        assert_eq!(IdsRepository::count_events(&pool).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn counts_respect_action_and_time() {
        let pool = memory_pool().await;

        IdsRepository::add_event(&pool, &event(1, "blocked", 100)).await.unwrap();
        IdsRepository::add_event(&pool, &event(1, "blocked", 200)).await.unwrap();
        IdsRepository::add_event(&pool, &event(1, "allowed", 200)).await.unwrap();

        assert_eq!(IdsRepository::count_events(&pool).await.unwrap(), 3);
        assert_eq!(IdsRepository::count_events_since(&pool, "blocked", 150).await.unwrap(), 1);
        assert_eq!(IdsRepository::count_events_since(&pool, "blocked", 0).await.unwrap(), 2);
        assert_eq!(IdsRepository::count_events_since(&pool, "allowed", 300).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn top_signatures_are_ranked_by_hits() {
        let pool = memory_pool().await;

        for _ in 0..3 {
            IdsRepository::add_event(&pool, &event(20, "allowed", 100)).await.unwrap();
        }
        IdsRepository::add_event(&pool, &event(10, "allowed", 100)).await.unwrap();
        IdsRepository::add_event(&pool, &event(30, "allowed", 10)).await.unwrap();

        let top = IdsRepository::top_signatures(&pool, 50, 5).await.unwrap();

        assert_eq!(
            top,
            vec![
                (20, "Signature 20".to_string(), 3),
                (10, "Signature 10".to_string(), 1),
            ]
        );

        let limited = IdsRepository::top_signatures(&pool, 0, 1).await.unwrap();
        assert_eq!(limited.len(), 1);
        assert_eq!(limited[0].0, 20);
    }

    #[tokio::test]
    async fn old_events_are_pruned_by_age_and_by_count() {
        let pool = memory_pool().await;

        for ts in [100, 200, 300, 400] {
            IdsRepository::add_event(&pool, &event(1, "allowed", ts)).await.unwrap();
        }

        assert_eq!(IdsRepository::prune_events_before(&pool, 250).await.unwrap(), 2);
        assert_eq!(IdsRepository::count_events(&pool).await.unwrap(), 2);

        assert_eq!(IdsRepository::prune_events(&pool, 1).await.unwrap(), 1);

        let left = IdsRepository::list_events(&pool, 10, 0, None, None).await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].ts, 400);
    }

    #[tokio::test]
    async fn clearing_removes_every_event_but_keeps_overrides() {
        let pool = memory_pool().await;

        IdsRepository::add_override(&pool, &rule(1, "disable")).await.unwrap();
        IdsRepository::add_event(&pool, &event(1, "allowed", 10)).await.unwrap();
        IdsRepository::add_event(&pool, &event(2, "allowed", 20)).await.unwrap();

        assert_eq!(IdsRepository::clear_events(&pool).await.unwrap(), 2);
        assert_eq!(IdsRepository::count_events(&pool).await.unwrap(), 0);
        assert_eq!(IdsRepository::list_overrides(&pool).await.unwrap().len(), 1);
    }
}
