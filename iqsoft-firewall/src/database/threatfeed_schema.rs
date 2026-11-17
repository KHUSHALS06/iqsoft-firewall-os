use sqlx::SqlitePool;

pub async fn create_threatfeed_tables(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS threat_feeds (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            name           TEXT NOT NULL UNIQUE COLLATE NOCASE,
            kind           TEXT NOT NULL CHECK (kind IN ('url', 'manual')),
            url            TEXT,
            enabled        INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
            direction      TEXT NOT NULL DEFAULT 'both'
                           CHECK (direction IN ('inbound', 'outbound', 'both')),
            refresh_hours  INTEGER NOT NULL DEFAULT 6
                           CHECK (refresh_hours BETWEEN 1 AND 720),
            log_enabled    INTEGER NOT NULL DEFAULT 0 CHECK (log_enabled IN (0, 1)),
            comment        TEXT,
            last_updated   INTEGER,
            last_attempt   INTEGER,
            last_error     TEXT,
            CHECK (kind = 'manual' OR url IS NOT NULL)
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS threat_feed_entries (
            feed_id  INTEGER NOT NULL,
            family   TEXT NOT NULL CHECK (family IN ('ipv4', 'ipv6')),
            cidr     TEXT NOT NULL,
            PRIMARY KEY (feed_id, cidr),
            FOREIGN KEY (feed_id) REFERENCES threat_feeds(id) ON DELETE CASCADE
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_threat_feed_entries_family ON threat_feed_entries(feed_id, family);",
    )
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

        create_threatfeed_tables(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn schema_can_be_created_twice() {
        let pool = memory_pool().await;
        create_threatfeed_tables(&pool).await.unwrap();
    }

    #[tokio::test]
    async fn defaults_are_enabled_both_directions_every_six_hours() {
        let pool = memory_pool().await;

        sqlx::query("INSERT INTO threat_feeds (name, kind) VALUES ('iocs', 'manual')")
            .execute(&pool)
            .await
            .unwrap();

        let row: (i64, String, i64, i64) = sqlx::query_as(
            "SELECT enabled, direction, refresh_hours, log_enabled FROM threat_feeds",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(row, (1, "both".to_string(), 6, 0));
    }

    #[tokio::test]
    async fn a_url_feed_needs_a_url_and_names_are_unique_ignoring_case() {
        let pool = memory_pool().await;

        let no_url = sqlx::query("INSERT INTO threat_feeds (name, kind) VALUES ('a', 'url')")
            .execute(&pool)
            .await;
        assert!(no_url.is_err());

        sqlx::query("INSERT INTO threat_feeds (name, kind) VALUES ('Spam', 'manual')")
            .execute(&pool)
            .await
            .unwrap();

        let duplicate = sqlx::query("INSERT INTO threat_feeds (name, kind) VALUES ('spam', 'manual')")
            .execute(&pool)
            .await;
        assert!(duplicate.is_err());
    }

    #[tokio::test]
    async fn bad_kind_direction_and_interval_are_rejected() {
        let pool = memory_pool().await;

        for sql in [
            "INSERT INTO threat_feeds (name, kind) VALUES ('a', 'ftp')",
            "INSERT INTO threat_feeds (name, kind, direction) VALUES ('b', 'manual', 'sideways')",
            "INSERT INTO threat_feeds (name, kind, refresh_hours) VALUES ('c', 'manual', 0)",
            "INSERT INTO threat_feeds (name, kind, refresh_hours) VALUES ('d', 'manual', 721)",
            "INSERT INTO threat_feeds (name, kind, enabled) VALUES ('e', 'manual', 2)",
        ] {
            assert!(sqlx::query(sql).execute(&pool).await.is_err(), "{}", sql);
        }
    }

    #[tokio::test]
    async fn entries_need_a_feed_and_die_with_it() {
        let pool = memory_pool().await;

        let orphan = sqlx::query(
            "INSERT INTO threat_feed_entries (feed_id, family, cidr) VALUES (99, 'ipv4', '1.2.3.4/32')",
        )
        .execute(&pool)
        .await;
        assert!(orphan.is_err());

        sqlx::query("INSERT INTO threat_feeds (name, kind) VALUES ('iocs', 'manual')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO threat_feed_entries (feed_id, family, cidr) VALUES (1, 'ipv4', '1.2.3.4/32')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let duplicate = sqlx::query(
            "INSERT INTO threat_feed_entries (feed_id, family, cidr) VALUES (1, 'ipv4', '1.2.3.4/32')",
        )
        .execute(&pool)
        .await;
        assert!(duplicate.is_err());

        sqlx::query("DELETE FROM threat_feeds WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();

        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM threat_feed_entries")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 0);
    }
}
