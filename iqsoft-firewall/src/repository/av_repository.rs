use crate::models::av::{AvEvent, AvException, AvSettings};
use sqlx::{sqlite::SqliteRow, Row, SqlitePool};

pub struct AvRepository;

impl AvRepository {
    fn row_to_exception(row: &SqliteRow) -> AvException {
        AvException {
            id: Some(row.get("id")),
            kind: row.get("kind"),
            value: row.get("value"),
            comment: row.get("comment"),
        }
    }

    fn row_to_event(row: &SqliteRow) -> AvEvent {
        AvEvent {
            id: Some(row.get("id")),
            ts: row.get("ts"),
            client_ip: row.get("client_ip"),
            host: row.get("host"),
            url: row.get("url"),
            file_name: row.get("file_name"),
            size_bytes: row.get("size_bytes"),
            engine: row.get("engine"),
            signature: row.get("signature"),
            action: row.get("action"),
        }
    }

    // ---------- settings ----------

    pub async fn get_settings(pool: &SqlitePool) -> Result<AvSettings, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT enabled, mode, max_scan_mb, over_size_action, fail_mode,
                   scan_archives, block_encrypted_archives, clamd_socket, proxy_port
            FROM av_settings
            WHERE id = 1
            "#,
        )
        .fetch_one(pool)
        .await?;

        Ok(AvSettings {
            enabled: row.get::<i64, _>("enabled") != 0,
            mode: row.get("mode"),
            max_scan_mb: row.get("max_scan_mb"),
            over_size_action: row.get("over_size_action"),
            fail_mode: row.get("fail_mode"),
            scan_archives: row.get::<i64, _>("scan_archives") != 0,
            block_encrypted_archives: row.get::<i64, _>("block_encrypted_archives") != 0,
            clamd_socket: row.get("clamd_socket"),
            proxy_port: row.get("proxy_port"),
        })
    }

    pub async fn set_settings(
        pool: &SqlitePool,
        settings: &AvSettings,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE av_settings
            SET enabled = ?,
                mode = ?,
                max_scan_mb = ?,
                over_size_action = ?,
                fail_mode = ?,
                scan_archives = ?,
                block_encrypted_archives = ?,
                clamd_socket = ?,
                proxy_port = ?
            WHERE id = 1
            "#,
        )
        .bind(settings.enabled)
        .bind(&settings.mode)
        .bind(settings.max_scan_mb)
        .bind(&settings.over_size_action)
        .bind(&settings.fail_mode)
        .bind(settings.scan_archives)
        .bind(settings.block_encrypted_archives)
        .bind(&settings.clamd_socket)
        .bind(settings.proxy_port)
        .execute(pool)
        .await?;

        Ok(())
    }

    // ---------- exceptions (sites and networks that are never scanned) ----------

    pub async fn list_exceptions(pool: &SqlitePool) -> Result<Vec<AvException>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, kind, value, comment FROM av_exceptions ORDER BY kind ASC, value ASC",
        )
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_exception).collect())
    }

    pub async fn get_exception(
        pool: &SqlitePool,
        kind: &str,
        value: &str,
    ) -> Result<Option<AvException>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, kind, value, comment FROM av_exceptions WHERE kind = ? AND value = ?",
        )
        .bind(kind)
        .bind(value)
        .fetch_optional(pool)
        .await?;

        Ok(row.as_ref().map(Self::row_to_exception))
    }

    pub async fn add_exception(
        pool: &SqlitePool,
        exception: &AvException,
    ) -> Result<i64, sqlx::Error> {
        let result =
            sqlx::query("INSERT INTO av_exceptions (kind, value, comment) VALUES (?, ?, ?)")
                .bind(&exception.kind)
                .bind(&exception.value)
                .bind(&exception.comment)
                .execute(pool)
                .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn delete_exception(pool: &SqlitePool, id: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM av_exceptions WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }

    // ---------- events (what the scanner found) ----------

    /// Saves one event. A timestamp of 0 means "now".
    pub async fn add_event(pool: &SqlitePool, event: &AvEvent) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO av_events
                (ts, client_ip, host, url, file_name, size_bytes, engine, signature, action)
            VALUES
                (COALESCE(NULLIF(?, 0), CAST(strftime('%s', 'now') AS INTEGER)),
                 ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(event.ts)
        .bind(&event.client_ip)
        .bind(&event.host)
        .bind(&event.url)
        .bind(&event.file_name)
        .bind(event.size_bytes)
        .bind(&event.engine)
        .bind(&event.signature)
        .bind(&event.action)
        .execute(pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    /// Newest first. `action` can be "blocked", "monitored" or "error" to filter.
    pub async fn list_events(
        pool: &SqlitePool,
        limit: i64,
        offset: i64,
        action: Option<&str>,
    ) -> Result<Vec<AvEvent>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, ts, client_ip, host, url, file_name, size_bytes, engine, signature, action
            FROM av_events
            WHERE (? IS NULL OR action = ?)
            ORDER BY ts DESC, id DESC
            LIMIT ? OFFSET ?
            "#,
        )
        .bind(action)
        .bind(action)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_event).collect())
    }

    pub async fn count_events(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT COUNT(*) FROM av_events")
            .fetch_one(pool)
            .await
    }

    /// How many events with this action happened at or after `since` (unix seconds).
    pub async fn count_events_since(
        pool: &SqlitePool,
        action: &str,
        since: i64,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT COUNT(*) FROM av_events WHERE action = ? AND ts >= ?")
            .bind(action)
            .bind(since)
            .fetch_one(pool)
            .await
    }

    /// Keeps only the newest `keep` events so the table cannot grow forever.
    pub async fn prune_events(pool: &SqlitePool, keep: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM av_events
            WHERE id NOT IN (
                SELECT id FROM av_events ORDER BY ts DESC, id DESC LIMIT ?
            )
            "#,
        )
        .bind(keep)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn clear_events(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM av_events").execute(pool).await?;

        Ok(result.rows_affected())
    }
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

    fn exception(kind: &str, value: &str, comment: Option<&str>) -> AvException {
        AvException {
            id: None,
            kind: kind.into(),
            value: value.into(),
            comment: comment.map(|c| c.to_string()),
        }
    }

    fn event(ts: i64, host: &str, action: &str) -> AvEvent {
        AvEvent {
            id: None,
            ts,
            client_ip: "10.0.0.5".into(),
            host: host.into(),
            url: format!("http://{}/file.exe", host),
            file_name: Some("file.exe".into()),
            size_bytes: 68,
            engine: "clamav".into(),
            signature: Some("Eicar-Signature".into()),
            action: action.into(),
        }
    }

    #[tokio::test]
    async fn settings_start_switched_off() {
        let pool = memory_pool().await;
        let settings = AvRepository::get_settings(&pool).await.unwrap();

        assert!(!settings.enabled);
        assert_eq!(settings.mode, "block");
        assert_eq!(settings.max_scan_mb, 25);
        assert_eq!(settings.over_size_action, "allow");
        assert_eq!(settings.fail_mode, "open");
        assert!(settings.scan_archives);
        assert!(!settings.block_encrypted_archives);
        assert_eq!(settings.clamd_socket, "/run/clamav/clamd.ctl");
        assert_eq!(settings.proxy_port, 3128);
    }

    #[tokio::test]
    async fn settings_round_trip() {
        let pool = memory_pool().await;

        let wanted = AvSettings {
            enabled: true,
            mode: "monitor".into(),
            max_scan_mb: 100,
            over_size_action: "block".into(),
            fail_mode: "closed".into(),
            scan_archives: false,
            block_encrypted_archives: true,
            clamd_socket: "/var/run/clamd.sock".into(),
            proxy_port: 8080,
        };

        AvRepository::set_settings(&pool, &wanted).await.unwrap();

        assert_eq!(AvRepository::get_settings(&pool).await.unwrap(), wanted);
    }

    #[tokio::test]
    async fn the_database_refuses_bad_settings() {
        let pool = memory_pool().await;

        let mut bad = AvRepository::get_settings(&pool).await.unwrap();
        bad.max_scan_mb = 0;
        assert!(AvRepository::set_settings(&pool, &bad).await.is_err());
    }

    #[tokio::test]
    async fn exceptions_are_listed_and_found() {
        let pool = memory_pool().await;

        let d = AvRepository::add_exception(&pool, &exception("domain", "windowsupdate.com", Some("updates")))
            .await
            .unwrap();
        let c = AvRepository::add_exception(&pool, &exception("cidr", "10.0.0.0/24", None))
            .await
            .unwrap();
        assert_ne!(c, d);

        let all = AvRepository::list_exceptions(&pool).await.unwrap();
        let kinds: Vec<&str> = all.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(kinds, vec!["cidr", "domain"]);

        let found = AvRepository::get_exception(&pool, "domain", "windowsupdate.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, Some(d));
        assert_eq!(found.comment.as_deref(), Some("updates"));

        assert!(AvRepository::get_exception(&pool, "domain", "nothing.example")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn the_database_refuses_a_duplicate_exception() {
        let pool = memory_pool().await;

        AvRepository::add_exception(&pool, &exception("domain", "example.com", None))
            .await
            .unwrap();

        assert!(AvRepository::add_exception(&pool, &exception("domain", "example.com", None))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn an_exception_can_be_deleted() {
        let pool = memory_pool().await;
        let id = AvRepository::add_exception(&pool, &exception("domain", "example.com", None))
            .await
            .unwrap();

        assert_eq!(AvRepository::delete_exception(&pool, 9999).await.unwrap(), 0);
        assert_eq!(AvRepository::delete_exception(&pool, id).await.unwrap(), 1);
        assert!(AvRepository::list_exceptions(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn events_come_back_newest_first_and_a_zero_time_means_now() {
        let pool = memory_pool().await;

        AvRepository::add_event(&pool, &event(1_795_000_100, "old.example.com", "blocked"))
            .await
            .unwrap();
        AvRepository::add_event(&pool, &event(1_795_000_300, "new.example.com", "blocked"))
            .await
            .unwrap();
        AvRepository::add_event(&pool, &event(0, "now.example.com", "monitored"))
            .await
            .unwrap();

        let events = AvRepository::list_events(&pool, 10, 0, None).await.unwrap();
        let hosts: Vec<&str> = events.iter().map(|e| e.host.as_str()).collect();
        assert_eq!(hosts, vec!["now.example.com", "new.example.com", "old.example.com"]);
        assert!(events[0].ts > 1_700_000_000);
        assert_eq!(events[1].signature.as_deref(), Some("Eicar-Signature"));
    }

    #[tokio::test]
    async fn events_can_be_filtered_and_paged() {
        let pool = memory_pool().await;

        AvRepository::add_event(&pool, &event(1_795_000_100, "a.example.com", "blocked")).await.unwrap();
        AvRepository::add_event(&pool, &event(1_795_000_200, "b.example.com", "monitored")).await.unwrap();
        AvRepository::add_event(&pool, &event(1_795_000_300, "c.example.com", "blocked")).await.unwrap();

        let blocked = AvRepository::list_events(&pool, 10, 0, Some("blocked")).await.unwrap();
        assert_eq!(blocked.len(), 2);

        let page = AvRepository::list_events(&pool, 1, 1, None).await.unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].host, "b.example.com");
    }

    #[tokio::test]
    async fn events_are_counted() {
        let pool = memory_pool().await;

        AvRepository::add_event(&pool, &event(1_795_000_100, "a.example.com", "blocked")).await.unwrap();
        AvRepository::add_event(&pool, &event(1_795_000_300, "b.example.com", "blocked")).await.unwrap();
        AvRepository::add_event(&pool, &event(1_795_000_400, "c.example.com", "error")).await.unwrap();

        assert_eq!(AvRepository::count_events(&pool).await.unwrap(), 3);
        assert_eq!(
            AvRepository::count_events_since(&pool, "blocked", 1_795_000_200).await.unwrap(),
            1
        );
        assert_eq!(
            AvRepository::count_events_since(&pool, "monitored", 0).await.unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn old_events_are_pruned_and_all_can_be_cleared() {
        let pool = memory_pool().await;

        for i in 1..=5 {
            AvRepository::add_event(&pool, &event(1_795_000_000 + i, "a.example.com", "blocked"))
                .await
                .unwrap();
        }

        assert_eq!(AvRepository::prune_events(&pool, 2).await.unwrap(), 3);

        let left = AvRepository::list_events(&pool, 10, 0, None).await.unwrap();
        assert_eq!(left.len(), 2);
        assert_eq!(left[0].ts, 1_795_000_005);
        assert_eq!(left[1].ts, 1_795_000_004);

        assert_eq!(AvRepository::clear_events(&pool).await.unwrap(), 2);
        assert_eq!(AvRepository::count_events(&pool).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn the_database_refuses_a_bad_event() {
        let pool = memory_pool().await;

        assert!(AvRepository::add_event(&pool, &event(1_795_000_100, "a.example.com", "deleted"))
            .await
            .is_err());
    }
}
