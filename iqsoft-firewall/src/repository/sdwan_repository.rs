use crate::models::sdwan::{SdwanLink, SdwanLinkStatus, SdwanRule, SdwanSettings};
use sqlx::{sqlite::SqliteRow, Row, SqlitePool};

const LINK_SELECT: &str = r#"
    SELECT
        l.id, l.name, l.interface_name, l.gateway, l.enabled, l.priority, l.weight,
        l.probe_target, l.probe_interval_secs, l.probe_timeout_secs,
        l.fail_threshold, l.recover_threshold, l.comment,
        COALESCE(s.state, 'unknown') AS state,
        s.latency_ms, s.loss_pct, s.last_check, s.last_change, s.last_error
    FROM sdwan_links l
    LEFT JOIN sdwan_link_status s ON s.link_id = l.id
"#;

const RULE_COLUMNS: &str = r#"
    id, name, enabled, position, src_cidr, dst_cidr, protocol,
    dport_start, dport_end, strategy, link_id, on_link_down, comment
"#;

pub struct SdwanRepository;

impl SdwanRepository {
    fn row_to_link(row: &SqliteRow) -> SdwanLink {
        SdwanLink {
            id: Some(row.get("id")),
            name: row.get("name"),
            interface_name: row.get("interface_name"),
            gateway: row.get("gateway"),
            enabled: row.get::<i64, _>("enabled") != 0,
            priority: row.get("priority"),
            weight: row.get("weight"),
            probe_target: row.get("probe_target"),
            probe_interval_secs: row.get("probe_interval_secs"),
            probe_timeout_secs: row.get("probe_timeout_secs"),
            fail_threshold: row.get("fail_threshold"),
            recover_threshold: row.get("recover_threshold"),
            comment: row.get("comment"),
            state: row.get("state"),
            latency_ms: row.get("latency_ms"),
            loss_pct: row.get("loss_pct"),
            last_check: row.get("last_check"),
            last_change: row.get("last_change"),
            last_error: row.get("last_error"),
        }
    }

    fn row_to_rule(row: &SqliteRow) -> SdwanRule {
        SdwanRule {
            id: Some(row.get("id")),
            name: row.get("name"),
            enabled: row.get::<i64, _>("enabled") != 0,
            position: row.get("position"),
            src_cidr: row.get("src_cidr"),
            dst_cidr: row.get("dst_cidr"),
            protocol: row.get("protocol"),
            dport_start: row.get("dport_start"),
            dport_end: row.get("dport_end"),
            strategy: row.get("strategy"),
            link_id: row.get("link_id"),
            on_link_down: row.get("on_link_down"),
            comment: row.get("comment"),
        }
    }

    fn row_to_status(row: &SqliteRow) -> SdwanLinkStatus {
        SdwanLinkStatus {
            link_id: row.get("link_id"),
            state: row.get("state"),
            latency_ms: row.get("latency_ms"),
            loss_pct: row.get("loss_pct"),
            consecutive_fail: row.get("consecutive_fail"),
            consecutive_ok: row.get("consecutive_ok"),
            last_check: row.get("last_check"),
            last_change: row.get("last_change"),
            last_error: row.get("last_error"),
        }
    }

    // ---------------------------------------------------------------- settings

    pub async fn get_settings(pool: &SqlitePool) -> Result<SdwanSettings, sqlx::Error> {
        let enabled: i64 = sqlx::query_scalar("SELECT enabled FROM sdwan_settings WHERE id = 1")
            .fetch_one(pool)
            .await?;

        Ok(SdwanSettings { enabled: enabled != 0 })
    }

    pub async fn set_enabled(pool: &SqlitePool, enabled: bool) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE sdwan_settings SET enabled = ? WHERE id = 1")
            .bind(enabled as i64)
            .execute(pool)
            .await?;

        Ok(())
    }

    // ------------------------------------------------------------------- links

    pub async fn list_links(pool: &SqlitePool) -> Result<Vec<SdwanLink>, sqlx::Error> {
        let sql = format!("{} ORDER BY l.priority ASC, l.id ASC", LINK_SELECT);

        let rows = sqlx::query(&sql).fetch_all(pool).await?;
        Ok(rows.iter().map(Self::row_to_link).collect())
    }

    pub async fn get_link(pool: &SqlitePool, id: i64) -> Result<Option<SdwanLink>, sqlx::Error> {
        let sql = format!("{} WHERE l.id = ?", LINK_SELECT);

        let row = sqlx::query(&sql).bind(id).fetch_optional(pool).await?;
        Ok(row.as_ref().map(Self::row_to_link))
    }

    pub async fn get_link_by_name(
        pool: &SqlitePool,
        name: &str,
    ) -> Result<Option<SdwanLink>, sqlx::Error> {
        let sql = format!("{} WHERE l.name = ? COLLATE NOCASE", LINK_SELECT);

        let row = sqlx::query(&sql).bind(name).fetch_optional(pool).await?;
        Ok(row.as_ref().map(Self::row_to_link))
    }

    pub async fn get_link_by_interface(
        pool: &SqlitePool,
        interface_name: &str,
    ) -> Result<Option<SdwanLink>, sqlx::Error> {
        let sql = format!("{} WHERE l.interface_name = ?", LINK_SELECT);

        let row = sqlx::query(&sql)
            .bind(interface_name)
            .fetch_optional(pool)
            .await?;
        Ok(row.as_ref().map(Self::row_to_link))
    }

    pub async fn count_links(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT COUNT(*) FROM sdwan_links")
            .fetch_one(pool)
            .await
    }

    /// Adds the link and its (empty, "unknown") status row together, or neither.
    pub async fn add_link(pool: &SqlitePool, link: &SdwanLink) -> Result<i64, sqlx::Error> {
        let mut tx = pool.begin().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO sdwan_links (
                name, interface_name, gateway, enabled, priority, weight,
                probe_target, probe_interval_secs, probe_timeout_secs,
                fail_threshold, recover_threshold, comment
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&link.name)
        .bind(&link.interface_name)
        .bind(&link.gateway)
        .bind(link.enabled as i64)
        .bind(link.priority)
        .bind(link.weight)
        .bind(&link.probe_target)
        .bind(link.probe_interval_secs)
        .bind(link.probe_timeout_secs)
        .bind(link.fail_threshold)
        .bind(link.recover_threshold)
        .bind(&link.comment)
        .execute(&mut *tx)
        .await?;

        let id = result.last_insert_rowid();

        sqlx::query("INSERT OR IGNORE INTO sdwan_link_status (link_id) VALUES (?)")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok(id)
    }

    /// Returns how many rows changed (0 means no link has that id).
    /// The live status is left alone, the probe task owns it.
    pub async fn update_link(
        pool: &SqlitePool,
        id: i64,
        link: &SdwanLink,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE sdwan_links
            SET
                name = ?,
                interface_name = ?,
                gateway = ?,
                enabled = ?,
                priority = ?,
                weight = ?,
                probe_target = ?,
                probe_interval_secs = ?,
                probe_timeout_secs = ?,
                fail_threshold = ?,
                recover_threshold = ?,
                comment = ?
            WHERE id = ?
            "#,
        )
        .bind(&link.name)
        .bind(&link.interface_name)
        .bind(&link.gateway)
        .bind(link.enabled as i64)
        .bind(link.priority)
        .bind(link.weight)
        .bind(&link.probe_target)
        .bind(link.probe_interval_secs)
        .bind(link.probe_timeout_secs)
        .bind(link.fail_threshold)
        .bind(link.recover_threshold)
        .bind(&link.comment)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Fails while a rule still uses the link, the service checks that first.
    pub async fn delete_link(pool: &SqlitePool, id: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM sdwan_links WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }

    // ------------------------------------------------------------------ status

    pub async fn get_status(
        pool: &SqlitePool,
        link_id: i64,
    ) -> Result<Option<SdwanLinkStatus>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT link_id, state, latency_ms, loss_pct, consecutive_fail,
                   consecutive_ok, last_check, last_change, last_error
            FROM sdwan_link_status
            WHERE link_id = ?
            "#,
        )
        .bind(link_id)
        .fetch_optional(pool)
        .await?;

        Ok(row.as_ref().map(Self::row_to_status))
    }

    pub async fn list_statuses(pool: &SqlitePool) -> Result<Vec<SdwanLinkStatus>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT link_id, state, latency_ms, loss_pct, consecutive_fail,
                   consecutive_ok, last_check, last_change, last_error
            FROM sdwan_link_status
            ORDER BY link_id ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_status).collect())
    }

    /// Saves the status of one link (creates the row if it is missing).
    pub async fn save_status(
        pool: &SqlitePool,
        status: &SdwanLinkStatus,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO sdwan_link_status (
                link_id, state, latency_ms, loss_pct, consecutive_fail,
                consecutive_ok, last_check, last_change, last_error
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(link_id) DO UPDATE SET
                state = excluded.state,
                latency_ms = excluded.latency_ms,
                loss_pct = excluded.loss_pct,
                consecutive_fail = excluded.consecutive_fail,
                consecutive_ok = excluded.consecutive_ok,
                last_check = excluded.last_check,
                last_change = excluded.last_change,
                last_error = excluded.last_error
            "#,
        )
        .bind(status.link_id)
        .bind(&status.state)
        .bind(status.latency_ms)
        .bind(status.loss_pct)
        .bind(status.consecutive_fail)
        .bind(status.consecutive_ok)
        .bind(status.last_check)
        .bind(status.last_change)
        .bind(&status.last_error)
        .execute(pool)
        .await?;

        Ok(())
    }

    // ------------------------------------------------------------------- rules

    pub async fn list_rules(pool: &SqlitePool) -> Result<Vec<SdwanRule>, sqlx::Error> {
        let sql = format!(
            "SELECT {} FROM sdwan_rules ORDER BY position ASC, id ASC",
            RULE_COLUMNS
        );

        let rows = sqlx::query(&sql).fetch_all(pool).await?;
        Ok(rows.iter().map(Self::row_to_rule).collect())
    }

    pub async fn get_rule(pool: &SqlitePool, id: i64) -> Result<Option<SdwanRule>, sqlx::Error> {
        let sql = format!("SELECT {} FROM sdwan_rules WHERE id = ?", RULE_COLUMNS);

        let row = sqlx::query(&sql).bind(id).fetch_optional(pool).await?;
        Ok(row.as_ref().map(Self::row_to_rule))
    }

    pub async fn get_rule_by_name(
        pool: &SqlitePool,
        name: &str,
    ) -> Result<Option<SdwanRule>, sqlx::Error> {
        let sql = format!(
            "SELECT {} FROM sdwan_rules WHERE name = ? COLLATE NOCASE",
            RULE_COLUMNS
        );

        let row = sqlx::query(&sql).bind(name).fetch_optional(pool).await?;
        Ok(row.as_ref().map(Self::row_to_rule))
    }

    pub async fn count_rules(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT COUNT(*) FROM sdwan_rules")
            .fetch_one(pool)
            .await
    }

    /// How many rules pin this link (used to refuse deleting a link that is in use).
    pub async fn count_rules_using_link(
        pool: &SqlitePool,
        link_id: i64,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT COUNT(*) FROM sdwan_rules WHERE link_id = ?")
            .bind(link_id)
            .fetch_one(pool)
            .await
    }

    pub async fn add_rule(pool: &SqlitePool, rule: &SdwanRule) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO sdwan_rules (
                name, enabled, position, src_cidr, dst_cidr, protocol,
                dport_start, dport_end, strategy, link_id, on_link_down, comment
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&rule.name)
        .bind(rule.enabled as i64)
        .bind(rule.position)
        .bind(&rule.src_cidr)
        .bind(&rule.dst_cidr)
        .bind(&rule.protocol)
        .bind(rule.dport_start)
        .bind(rule.dport_end)
        .bind(&rule.strategy)
        .bind(rule.link_id)
        .bind(&rule.on_link_down)
        .bind(&rule.comment)
        .execute(pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    /// Returns how many rows changed (0 means no rule has that id).
    pub async fn update_rule(
        pool: &SqlitePool,
        id: i64,
        rule: &SdwanRule,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE sdwan_rules
            SET
                name = ?,
                enabled = ?,
                position = ?,
                src_cidr = ?,
                dst_cidr = ?,
                protocol = ?,
                dport_start = ?,
                dport_end = ?,
                strategy = ?,
                link_id = ?,
                on_link_down = ?,
                comment = ?
            WHERE id = ?
            "#,
        )
        .bind(&rule.name)
        .bind(rule.enabled as i64)
        .bind(rule.position)
        .bind(&rule.src_cidr)
        .bind(&rule.dst_cidr)
        .bind(&rule.protocol)
        .bind(rule.dport_start)
        .bind(rule.dport_end)
        .bind(&rule.strategy)
        .bind(rule.link_id)
        .bind(&rule.on_link_down)
        .bind(&rule.comment)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn delete_rule(pool: &SqlitePool, id: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM sdwan_rules WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::sdwan_schema::create_sdwan_tables;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        create_sdwan_tables(&pool).await.unwrap();
        pool
    }

    fn link(name: &str, iface: &str, priority: i64) -> SdwanLink {
        SdwanLink {
            id: None,
            name: name.to_string(),
            interface_name: iface.to_string(),
            gateway: Some("192.168.1.1".to_string()),
            enabled: true,
            priority,
            weight: 1,
            probe_target: "1.1.1.1".to_string(),
            probe_interval_secs: 5,
            probe_timeout_secs: 2,
            fail_threshold: 3,
            recover_threshold: 2,
            comment: None,
            state: "unknown".to_string(),
            latency_ms: None,
            loss_pct: None,
            last_check: None,
            last_change: None,
            last_error: None,
        }
    }

    fn rule(name: &str, position: i64) -> SdwanRule {
        SdwanRule {
            id: None,
            name: name.to_string(),
            enabled: true,
            position,
            src_cidr: None,
            dst_cidr: None,
            protocol: "any".to_string(),
            dport_start: None,
            dport_end: None,
            strategy: "balance".to_string(),
            link_id: None,
            on_link_down: "fallback".to_string(),
            comment: None,
        }
    }

    #[tokio::test]
    async fn settings_start_off_and_can_be_switched() {
        let pool = memory_pool().await;

        assert!(!SdwanRepository::get_settings(&pool).await.unwrap().enabled);

        SdwanRepository::set_enabled(&pool, true).await.unwrap();
        assert!(SdwanRepository::get_settings(&pool).await.unwrap().enabled);

        SdwanRepository::set_enabled(&pool, false).await.unwrap();
        assert!(!SdwanRepository::get_settings(&pool).await.unwrap().enabled);
    }

    #[tokio::test]
    async fn a_new_link_starts_with_an_unknown_status() {
        let pool = memory_pool().await;

        let id = SdwanRepository::add_link(&pool, &link("ISP1", "enp3s0", 10))
            .await
            .unwrap();

        let got = SdwanRepository::get_link(&pool, id).await.unwrap().unwrap();
        assert_eq!(got.name, "ISP1");
        assert_eq!(got.interface_name, "enp3s0");
        assert_eq!(got.gateway.as_deref(), Some("192.168.1.1"));
        assert_eq!(got.state, "unknown");
        assert_eq!(got.latency_ms, None);

        let status = SdwanRepository::get_status(&pool, id).await.unwrap().unwrap();
        assert_eq!(status.state, "unknown");
        assert_eq!(status.consecutive_fail, 0);
    }

    #[tokio::test]
    async fn links_are_listed_by_priority_then_id() {
        let pool = memory_pool().await;

        SdwanRepository::add_link(&pool, &link("backup", "enp5s0", 20)).await.unwrap();
        SdwanRepository::add_link(&pool, &link("main", "enp3s0", 10)).await.unwrap();
        SdwanRepository::add_link(&pool, &link("also-main", "enp4s0", 10)).await.unwrap();

        let names: Vec<String> = SdwanRepository::list_links(&pool)
            .await
            .unwrap()
            .into_iter()
            .map(|l| l.name)
            .collect();

        assert_eq!(names, vec!["main", "also-main", "backup"]);
        assert_eq!(SdwanRepository::count_links(&pool).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn links_can_be_found_by_name_and_interface() {
        let pool = memory_pool().await;
        SdwanRepository::add_link(&pool, &link("ISP1", "enp3s0", 10)).await.unwrap();

        assert!(SdwanRepository::get_link_by_name(&pool, "isp1").await.unwrap().is_some());
        assert!(SdwanRepository::get_link_by_name(&pool, "other").await.unwrap().is_none());
        assert!(SdwanRepository::get_link_by_interface(&pool, "enp3s0").await.unwrap().is_some());
        assert!(SdwanRepository::get_link_by_interface(&pool, "enp9s0").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_duplicate_link_adds_nothing_at_all() {
        let pool = memory_pool().await;
        SdwanRepository::add_link(&pool, &link("ISP1", "enp3s0", 10)).await.unwrap();

        let duplicate = SdwanRepository::add_link(&pool, &link("isp1", "enp4s0", 10)).await;
        assert!(duplicate.is_err());

        assert_eq!(SdwanRepository::count_links(&pool).await.unwrap(), 1);
        assert_eq!(SdwanRepository::list_statuses(&pool).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn updating_a_link_keeps_its_live_status() {
        let pool = memory_pool().await;
        let id = SdwanRepository::add_link(&pool, &link("ISP1", "enp3s0", 10)).await.unwrap();

        SdwanRepository::save_status(
            &pool,
            &SdwanLinkStatus {
                link_id: id,
                state: "up".to_string(),
                latency_ms: Some(12.5),
                loss_pct: Some(0),
                consecutive_fail: 0,
                consecutive_ok: 4,
                last_check: Some(1_700_000_000),
                last_change: Some(1_699_999_000),
                last_error: None,
            },
        )
        .await
        .unwrap();

        let mut changed = link("ISP1-renamed", "enp3s0", 5);
        changed.weight = 7;
        changed.comment = Some("fibre".to_string());

        assert_eq!(SdwanRepository::update_link(&pool, id, &changed).await.unwrap(), 1);

        let got = SdwanRepository::get_link(&pool, id).await.unwrap().unwrap();
        assert_eq!(got.name, "ISP1-renamed");
        assert_eq!(got.priority, 5);
        assert_eq!(got.weight, 7);
        assert_eq!(got.comment.as_deref(), Some("fibre"));
        assert_eq!(got.state, "up");
        assert_eq!(got.latency_ms, Some(12.5));
        assert_eq!(got.loss_pct, Some(0));
        assert_eq!(got.last_check, Some(1_700_000_000));

        assert_eq!(SdwanRepository::update_link(&pool, 999, &changed).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn saving_a_status_twice_keeps_one_row_with_the_newest_values() {
        let pool = memory_pool().await;
        let id = SdwanRepository::add_link(&pool, &link("ISP1", "enp3s0", 10)).await.unwrap();

        let mut status = SdwanRepository::get_status(&pool, id).await.unwrap().unwrap();
        status.state = "down".to_string();
        status.consecutive_fail = 3;
        status.last_error = Some("no reply".to_string());
        SdwanRepository::save_status(&pool, &status).await.unwrap();

        status.state = "up".to_string();
        status.consecutive_fail = 0;
        status.consecutive_ok = 2;
        status.last_error = None;
        SdwanRepository::save_status(&pool, &status).await.unwrap();

        let all = SdwanRepository::list_statuses(&pool).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].state, "up");
        assert_eq!(all[0].consecutive_ok, 2);
        assert_eq!(all[0].last_error, None);
    }

    #[tokio::test]
    async fn deleting_a_link_removes_its_status() {
        let pool = memory_pool().await;
        let id = SdwanRepository::add_link(&pool, &link("ISP1", "enp3s0", 10)).await.unwrap();

        assert_eq!(SdwanRepository::delete_link(&pool, id).await.unwrap(), 1);
        assert_eq!(SdwanRepository::delete_link(&pool, id).await.unwrap(), 0);

        assert!(SdwanRepository::get_link(&pool, id).await.unwrap().is_none());
        assert!(SdwanRepository::list_statuses(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn rules_are_listed_by_position_then_id() {
        let pool = memory_pool().await;

        SdwanRepository::add_rule(&pool, &rule("last", 300)).await.unwrap();
        SdwanRepository::add_rule(&pool, &rule("first", 10)).await.unwrap();
        SdwanRepository::add_rule(&pool, &rule("second", 10)).await.unwrap();

        let names: Vec<String> = SdwanRepository::list_rules(&pool)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.name)
            .collect();

        assert_eq!(names, vec!["first", "second", "last"]);
        assert_eq!(SdwanRepository::count_rules(&pool).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn a_rule_round_trips_through_the_database() {
        let pool = memory_pool().await;
        let link_id = SdwanRepository::add_link(&pool, &link("ISP1", "enp3s0", 10)).await.unwrap();

        let mut voice = rule("voice", 5);
        voice.src_cidr = Some("192.168.10.0/24".to_string());
        voice.dst_cidr = Some("203.0.113.0/24".to_string());
        voice.protocol = "udp".to_string();
        voice.dport_start = Some(10000);
        voice.dport_end = Some(20000);
        voice.strategy = "link".to_string();
        voice.link_id = Some(link_id);
        voice.on_link_down = "block".to_string();
        voice.comment = Some("SIP media".to_string());

        let id = SdwanRepository::add_rule(&pool, &voice).await.unwrap();

        let got = SdwanRepository::get_rule(&pool, id).await.unwrap().unwrap();
        assert_eq!(got.name, "voice");
        assert!(got.enabled);
        assert_eq!(got.position, 5);
        assert_eq!(got.src_cidr.as_deref(), Some("192.168.10.0/24"));
        assert_eq!(got.dst_cidr.as_deref(), Some("203.0.113.0/24"));
        assert_eq!(got.protocol, "udp");
        assert_eq!(got.dport_start, Some(10000));
        assert_eq!(got.dport_end, Some(20000));
        assert_eq!(got.strategy, "link");
        assert_eq!(got.link_id, Some(link_id));
        assert_eq!(got.on_link_down, "block");
        assert_eq!(got.comment.as_deref(), Some("SIP media"));

        assert!(SdwanRepository::get_rule_by_name(&pool, "VOICE").await.unwrap().is_some());
        assert!(SdwanRepository::get_rule_by_name(&pool, "nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rules_can_be_updated_and_deleted() {
        let pool = memory_pool().await;
        let id = SdwanRepository::add_rule(&pool, &rule("web", 100)).await.unwrap();

        let mut changed = rule("web-new", 50);
        changed.enabled = false;
        changed.protocol = "tcp".to_string();
        changed.dport_start = Some(80);
        changed.dport_end = Some(443);

        assert_eq!(SdwanRepository::update_rule(&pool, id, &changed).await.unwrap(), 1);

        let got = SdwanRepository::get_rule(&pool, id).await.unwrap().unwrap();
        assert_eq!(got.name, "web-new");
        assert!(!got.enabled);
        assert_eq!(got.position, 50);
        assert_eq!(got.dport_start, Some(80));

        assert_eq!(SdwanRepository::update_rule(&pool, 999, &changed).await.unwrap(), 0);

        assert_eq!(SdwanRepository::delete_rule(&pool, id).await.unwrap(), 1);
        assert_eq!(SdwanRepository::delete_rule(&pool, id).await.unwrap(), 0);
        assert!(SdwanRepository::get_rule(&pool, id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_link_used_by_a_rule_is_counted_and_cannot_be_deleted() {
        let pool = memory_pool().await;
        let link_id = SdwanRepository::add_link(&pool, &link("ISP1", "enp3s0", 10)).await.unwrap();

        assert_eq!(SdwanRepository::count_rules_using_link(&pool, link_id).await.unwrap(), 0);

        let mut pinned = rule("voice", 10);
        pinned.strategy = "link".to_string();
        pinned.link_id = Some(link_id);
        let rule_id = SdwanRepository::add_rule(&pool, &pinned).await.unwrap();

        assert_eq!(SdwanRepository::count_rules_using_link(&pool, link_id).await.unwrap(), 1);
        assert!(SdwanRepository::delete_link(&pool, link_id).await.is_err());

        SdwanRepository::delete_rule(&pool, rule_id).await.unwrap();
        assert_eq!(SdwanRepository::delete_link(&pool, link_id).await.unwrap(), 1);
    }
}
