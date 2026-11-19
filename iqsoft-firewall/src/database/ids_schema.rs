use sqlx::SqlitePool;

pub async fn create_ids_tables(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ids_settings (
            id                    INTEGER PRIMARY KEY CHECK (id = 1),
            enabled               INTEGER NOT NULL DEFAULT 0
                                  CHECK (enabled IN (0, 1)),
            mode                  TEXT NOT NULL DEFAULT 'ids'
                                  CHECK (mode IN ('ids', 'ips')),
            interfaces            TEXT NOT NULL DEFAULT ''
                                  CHECK (length(interfaces) <= 200
                                         AND interfaces NOT GLOB '*[^a-zA-Z0-9_.,-]*'),
            queue_num             INTEGER NOT NULL DEFAULT 200
                                  CHECK (queue_num BETWEEN 1 AND 65535
                                         AND queue_num != 100),
            fail_mode             TEXT NOT NULL DEFAULT 'open'
                                  CHECK (fail_mode IN ('open', 'closed')),
            home_net              TEXT NOT NULL
                                  DEFAULT '[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]'
                                  CHECK (length(home_net) BETWEEN 2 AND 300),
            rule_update_hours     INTEGER NOT NULL DEFAULT 24
                                  CHECK (rule_update_hours BETWEEN 0 AND 720),
            event_retention_days  INTEGER NOT NULL DEFAULT 30
                                  CHECK (event_retention_days BETWEEN 1 AND 365)
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("INSERT OR IGNORE INTO ids_settings (id) VALUES (1)")
        .execute(pool)
        .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ids_rule_overrides (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            sid      INTEGER NOT NULL UNIQUE CHECK (sid > 0),
            action   TEXT NOT NULL CHECK (action IN ('disable', 'alert', 'drop')),
            comment  TEXT
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ids_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          INTEGER NOT NULL
                        DEFAULT (CAST(strftime('%s', 'now') AS INTEGER)),
            src_ip      TEXT NOT NULL,
            src_port    INTEGER,
            dest_ip     TEXT NOT NULL,
            dest_port   INTEGER,
            proto       TEXT NOT NULL,
            app_proto   TEXT,
            sid         INTEGER NOT NULL,
            signature   TEXT NOT NULL,
            category    TEXT,
            severity    INTEGER NOT NULL CHECK (severity BETWEEN 1 AND 4),
            action      TEXT NOT NULL CHECK (action IN ('allowed', 'blocked'))
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ids_events_ts ON ids_events (ts DESC)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ids_events_sid ON ids_events (sid)")
        .execute(pool)
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[tokio::test]
    async fn schema_can_be_created_twice_and_keeps_one_settings_row() {
        let pool = memory_pool().await;
        create_ids_tables(&pool).await.unwrap();

        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ids_settings")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 1);
    }

    #[tokio::test]
    async fn settings_start_switched_off_in_passive_mode() {
        let pool = memory_pool().await;

        let row: (i64, String, String, i64, String, String, i64, i64) = sqlx::query_as(
            "SELECT enabled, mode, interfaces, queue_num, fail_mode, home_net, \
             rule_update_hours, event_retention_days FROM ids_settings",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(
            row,
            (
                0,
                "ids".to_string(),
                String::new(),
                200,
                "open".to_string(),
                "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]".to_string(),
                24,
                30,
            )
        );
    }

    #[tokio::test]
    async fn queue_number_used_by_the_sni_filter_is_refused() {
        let pool = memory_pool().await;

        let result = sqlx::query("UPDATE ids_settings SET queue_num = 100")
            .execute(&pool)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn interface_list_rejects_shell_characters() {
        let pool = memory_pool().await;

        let result = sqlx::query("UPDATE ids_settings SET interfaces = 'eth0;reboot'")
            .execute(&pool)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn a_rule_override_can_only_exist_once_per_sid() {
        let pool = memory_pool().await;

        sqlx::query("INSERT INTO ids_rule_overrides (sid, action) VALUES (2100498, 'disable')")
            .execute(&pool)
            .await
            .unwrap();

        let again = sqlx::query("INSERT INTO ids_rule_overrides (sid, action) VALUES (2100498, 'drop')")
            .execute(&pool)
            .await;
        assert!(again.is_err());
    }
}
