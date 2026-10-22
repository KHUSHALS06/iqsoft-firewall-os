use sqlx::SqlitePool;

pub async fn create_sni_tables(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // One row of global settings. The CHECK keeps it to exactly one row.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sni_settings (
            id                    INTEGER PRIMARY KEY CHECK (id = 1),
            enabled               INTEGER NOT NULL DEFAULT 0
                                  CHECK (enabled IN (0, 1)),
            -- Also block every site that the enabled DNS filter categories
            -- and DNS filter rules block, so one list protects both layers.
            use_dns_filter_lists  INTEGER NOT NULL DEFAULT 1
                                  CHECK (use_dns_filter_lists IN (0, 1)),
            -- What to do with a handshake that carries no site name.
            no_name_action        TEXT NOT NULL DEFAULT 'allow'
                                  CHECK (no_name_action IN ('allow', 'block')),
            -- A broken or tricky handshake. Real browsers never send one.
            block_malformed       INTEGER NOT NULL DEFAULT 1
                                  CHECK (block_malformed IN (0, 1)),
            -- Drop UDP 443 (QUIC / HTTP3), whose site name we cannot read,
            -- so browsers fall back to normal HTTPS that we can filter.
            block_quic            INTEGER NOT NULL DEFAULT 0
                                  CHECK (block_quic IN (0, 1))
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("INSERT OR IGNORE INTO sni_settings (id) VALUES (1)")
        .execute(pool)
        .await?;

    // Hand-written exceptions: always block, or always allow, one site name.
    // A rule for example.com also covers www.example.com and every other
    // subdomain. The matcher (a later step) does that, not the database.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sni_rules (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            domain    TEXT NOT NULL UNIQUE
                      CHECK (length(domain) BETWEEN 3 AND 253
                             AND domain NOT GLOB '*[^a-z0-9.-]*'),
            action    TEXT NOT NULL CHECK (action IN ('block', 'allow')),
            comment   TEXT
        );
        "#,
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

        create_sni_tables(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn schema_can_be_created_twice_and_keeps_one_settings_row() {
        let pool = memory_pool().await;
        create_sni_tables(&pool).await.unwrap();

        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sni_settings")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 1);
    }

    #[tokio::test]
    async fn settings_start_switched_off_with_safe_defaults() {
        let pool = memory_pool().await;

        let row: (i64, i64, String, i64, i64) = sqlx::query_as(
            "SELECT enabled, use_dns_filter_lists, no_name_action, block_malformed, block_quic FROM sni_settings",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(row, (0, 1, "allow".to_string(), 1, 0));
    }

    #[tokio::test]
    async fn only_one_settings_row_and_valid_values() {
        let pool = memory_pool().await;

        assert!(sqlx::query("INSERT INTO sni_settings (id) VALUES (2)")
            .execute(&pool)
            .await
            .is_err());

        assert!(sqlx::query("UPDATE sni_settings SET no_name_action = 'sideways'")
            .execute(&pool)
            .await
            .is_err());

        for column in ["enabled", "use_dns_filter_lists", "block_malformed", "block_quic"] {
            let sql = format!("UPDATE sni_settings SET {} = 2", column);
            assert!(sqlx::query(&sql).execute(&pool).await.is_err(), "{}", column);
        }
    }

    #[tokio::test]
    async fn rules_are_unique_per_domain_and_limited_to_block_or_allow() {
        let pool = memory_pool().await;

        sqlx::query("INSERT INTO sni_rules (domain, action) VALUES ('tiktok.com', 'block')")
            .execute(&pool)
            .await
            .unwrap();

        assert!(
            sqlx::query("INSERT INTO sni_rules (domain, action) VALUES ('tiktok.com', 'allow')")
                .execute(&pool)
                .await
                .is_err()
        );

        assert!(
            sqlx::query("INSERT INTO sni_rules (domain, action) VALUES ('x.example.com', 'maybe')")
                .execute(&pool)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn rule_domains_must_be_clean() {
        let pool = memory_pool().await;

        for bad in ["Bad.com", "ex ample.com", "a/b.com", "x;y.com", "a=b.com", "ab"] {
            let result = sqlx::query("INSERT INTO sni_rules (domain, action) VALUES (?, 'block')")
                .bind(bad)
                .execute(&pool)
                .await;
            assert!(result.is_err(), "accepted bad domain '{}'", bad);
        }

        sqlx::query("INSERT INTO sni_rules (domain, action) VALUES ('good-site.example.co.uk', 'block')")
            .execute(&pool)
            .await
            .unwrap();
    }
}
