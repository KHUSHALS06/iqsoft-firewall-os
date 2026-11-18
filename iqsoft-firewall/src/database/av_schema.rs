use sqlx::SqlitePool;

pub async fn create_av_tables(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS av_settings (
            id                       INTEGER PRIMARY KEY CHECK (id = 1),
            enabled                  INTEGER NOT NULL DEFAULT 0
                                     CHECK (enabled IN (0, 1)),
            mode                     TEXT NOT NULL DEFAULT 'block'
                                     CHECK (mode IN ('block', 'monitor')),
            max_scan_mb              INTEGER NOT NULL DEFAULT 25
                                     CHECK (max_scan_mb BETWEEN 1 AND 512),
            over_size_action         TEXT NOT NULL DEFAULT 'allow'
                                     CHECK (over_size_action IN ('allow', 'block')),
            fail_mode                TEXT NOT NULL DEFAULT 'open'
                                     CHECK (fail_mode IN ('open', 'closed')),
            scan_archives            INTEGER NOT NULL DEFAULT 1
                                     CHECK (scan_archives IN (0, 1)),
            block_encrypted_archives INTEGER NOT NULL DEFAULT 0
                                     CHECK (block_encrypted_archives IN (0, 1)),
            clamd_socket             TEXT NOT NULL DEFAULT '/run/clamav/clamd.ctl'
                                     CHECK (length(clamd_socket) BETWEEN 2 AND 200
                                            AND substr(clamd_socket, 1, 1) = '/'),
            proxy_port               INTEGER NOT NULL DEFAULT 3128
                                     CHECK (proxy_port BETWEEN 1024 AND 65535)
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("INSERT OR IGNORE INTO av_settings (id) VALUES (1)")
        .execute(pool)
        .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS av_exceptions (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            kind      TEXT NOT NULL CHECK (kind IN ('domain', 'cidr')),
            value     TEXT NOT NULL
                      CHECK (length(value) BETWEEN 3 AND 253
                             AND value NOT GLOB '*[^a-z0-9.:/-]*'),
            comment   TEXT,
            UNIQUE (kind, value)
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS av_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER)),
            client_ip   TEXT NOT NULL,
            host        TEXT NOT NULL,
            url         TEXT NOT NULL,
            file_name   TEXT,
            size_bytes  INTEGER NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),
            engine      TEXT NOT NULL CHECK (engine IN ('clamav', 'hash', 'url')),
            signature   TEXT,
            action      TEXT NOT NULL CHECK (action IN ('blocked', 'monitored', 'error'))
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_av_events_ts ON av_events (ts DESC)")
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

        create_av_tables(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn schema_can_be_created_twice_and_keeps_one_settings_row() {
        let pool = memory_pool().await;
        create_av_tables(&pool).await.unwrap();

        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM av_settings")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 1);
    }

    #[tokio::test]
    async fn settings_start_switched_off_with_safe_defaults() {
        let pool = memory_pool().await;

        let row: (i64, String, i64, String, String, i64, i64, String, i64) = sqlx::query_as(
            "SELECT enabled, mode, max_scan_mb, over_size_action, fail_mode, scan_archives, \
             block_encrypted_archives, clamd_socket, proxy_port FROM av_settings",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(
            row,
            (
                0,
                "block".to_string(),
                25,
                "allow".to_string(),
                "open".to_string(),
                1,
                0,
                "/run/clamav/clamd.ctl".to_string(),
                3128
            )
        );
    }

    #[tokio::test]
    async fn only_one_settings_row_and_valid_values() {
        let pool = memory_pool().await;

        assert!(sqlx::query("INSERT INTO av_settings (id) VALUES (2)")
            .execute(&pool)
            .await
            .is_err());

        for bad in [
            "UPDATE av_settings SET enabled = 2",
            "UPDATE av_settings SET mode = 'off'",
            "UPDATE av_settings SET max_scan_mb = 0",
            "UPDATE av_settings SET max_scan_mb = 513",
            "UPDATE av_settings SET over_size_action = 'skip'",
            "UPDATE av_settings SET fail_mode = 'maybe'",
            "UPDATE av_settings SET clamd_socket = 'relative/path'",
            "UPDATE av_settings SET proxy_port = 80",
            "UPDATE av_settings SET proxy_port = 70000",
        ] {
            assert!(sqlx::query(bad).execute(&pool).await.is_err(), "{}", bad);
        }
    }

    #[tokio::test]
    async fn exceptions_are_unique_and_restricted_to_safe_characters() {
        let pool = memory_pool().await;

        sqlx::query("INSERT INTO av_exceptions (kind, value) VALUES ('domain', 'example.com')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO av_exceptions (kind, value) VALUES ('cidr', '10.0.0.0/24')")
            .execute(&pool)
            .await
            .unwrap();

        assert!(
            sqlx::query("INSERT INTO av_exceptions (kind, value) VALUES ('domain', 'example.com')")
                .execute(&pool)
                .await
                .is_err()
        );
        assert!(
            sqlx::query("INSERT INTO av_exceptions (kind, value) VALUES ('domain', 'Bad Host;')")
                .execute(&pool)
                .await
                .is_err()
        );
        assert!(
            sqlx::query("INSERT INTO av_exceptions (kind, value) VALUES ('mac', 'aa:bb:cc')")
                .execute(&pool)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn events_validate_engine_action_and_default_timestamp() {
        let pool = memory_pool().await;

        sqlx::query(
            "INSERT INTO av_events (client_ip, host, url, engine, signature, action) \
             VALUES ('10.0.0.5', 'example.com', 'http://example.com/a.exe', 'clamav', 'Eicar-Signature', 'blocked')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let ts: i64 = sqlx::query_scalar("SELECT ts FROM av_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(ts > 1_700_000_000);

        assert!(sqlx::query(
            "INSERT INTO av_events (client_ip, host, url, engine, action) \
             VALUES ('10.0.0.5', 'h', 'u', 'magic', 'blocked')"
        )
        .execute(&pool)
        .await
        .is_err());

        assert!(sqlx::query(
            "INSERT INTO av_events (client_ip, host, url, engine, action) \
             VALUES ('10.0.0.5', 'h', 'u', 'clamav', 'deleted')"
        )
        .execute(&pool)
        .await
        .is_err());
    }
}
