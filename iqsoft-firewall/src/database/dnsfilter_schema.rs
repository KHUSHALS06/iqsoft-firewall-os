use sqlx::SqlitePool;

pub async fn create_dnsfilter_tables(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // One row of global settings. The CHECK keeps it to exactly one row.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS dnsfilter_settings (
            id              INTEGER PRIMARY KEY CHECK (id = 1),
            enabled         INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
            block_response  TEXT NOT NULL DEFAULT 'nxdomain'
                            CHECK (block_response IN ('nxdomain', 'sinkhole')),
            safe_search     INTEGER NOT NULL DEFAULT 0 CHECK (safe_search IN (0, 1)),
            enforce_dns     INTEGER NOT NULL DEFAULT 0 CHECK (enforce_dns IN (0, 1))
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("INSERT OR IGNORE INTO dnsfilter_settings (id) VALUES (1)")
        .execute(pool)
        .await?;

    // A category is a named block list (adult, gambling, malware ...).
    // It holds the on/off switch; its domains live in dnsfilter_domains.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS dnsfilter_categories (
            name        TEXT PRIMARY KEY
                        CHECK (length(name) BETWEEN 1 AND 40
                               AND name NOT GLOB '*[^a-z0-9_-]*'),
            enabled     INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
            comment     TEXT,
            source      TEXT,
            updated_at  TEXT
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS dnsfilter_domains (
            category  TEXT NOT NULL,
            domain    TEXT NOT NULL
                      CHECK (length(domain) BETWEEN 3 AND 253
                             AND domain NOT GLOB '*[^a-z0-9.-]*'),
            PRIMARY KEY (category, domain),
            FOREIGN KEY (category) REFERENCES dnsfilter_categories(name) ON DELETE CASCADE
        );
        "#,
    )
    .execute(pool)
    .await?;

    // Hand-written exceptions: always block, or always allow, one domain.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS dnsfilter_rules (
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

        create_dnsfilter_tables(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn schema_can_be_created_twice_and_keeps_one_settings_row() {
        let pool = memory_pool().await;
        create_dnsfilter_tables(&pool).await.unwrap();

        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dnsfilter_settings")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 1);
    }

    #[tokio::test]
    async fn settings_start_switched_off_with_nxdomain() {
        let pool = memory_pool().await;

        let row: (i64, String, i64, i64) = sqlx::query_as(
            "SELECT enabled, block_response, safe_search, enforce_dns FROM dnsfilter_settings",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(row, (0, "nxdomain".to_string(), 0, 0));
    }

    #[tokio::test]
    async fn only_one_settings_row_and_valid_values() {
        let pool = memory_pool().await;

        assert!(sqlx::query("INSERT INTO dnsfilter_settings (id) VALUES (2)")
            .execute(&pool)
            .await
            .is_err());

        assert!(sqlx::query("UPDATE dnsfilter_settings SET block_response = 'sideways'")
            .execute(&pool)
            .await
            .is_err());

        assert!(sqlx::query("UPDATE dnsfilter_settings SET enabled = 2")
            .execute(&pool)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn category_names_are_lowercase_words_only() {
        let pool = memory_pool().await;

        for good in ["adult", "social-media", "ads_2"] {
            sqlx::query("INSERT INTO dnsfilter_categories (name) VALUES (?)")
                .bind(good)
                .execute(&pool)
                .await
                .unwrap_or_else(|e| panic!("rejected '{}': {}", good, e));
        }

        for bad in ["", "Adult", "a b", "a;b", "a/b", "é", &"x".repeat(41)] {
            let result = sqlx::query("INSERT INTO dnsfilter_categories (name) VALUES (?)")
                .bind(bad)
                .execute(&pool)
                .await;
            assert!(result.is_err(), "accepted bad category '{}'", bad);
        }
    }

    #[tokio::test]
    async fn domains_need_a_category_and_a_clean_name() {
        let pool = memory_pool().await;

        let orphan = sqlx::query(
            "INSERT INTO dnsfilter_domains (category, domain) VALUES ('adult', 'bad.example.com')",
        )
        .execute(&pool)
        .await;
        assert!(orphan.is_err());

        sqlx::query("INSERT INTO dnsfilter_categories (name) VALUES ('adult')")
            .execute(&pool)
            .await
            .unwrap();

        sqlx::query(
            "INSERT INTO dnsfilter_domains (category, domain) VALUES ('adult', 'bad.example.com')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let duplicate = sqlx::query(
            "INSERT INTO dnsfilter_domains (category, domain) VALUES ('adult', 'bad.example.com')",
        )
        .execute(&pool)
        .await;
        assert!(duplicate.is_err());

        for bad in ["Bad.Example.com", "ex ample.com", "a/b.com", "x;y.com", "a=b.com", "ab"] {
            let result =
                sqlx::query("INSERT INTO dnsfilter_domains (category, domain) VALUES ('adult', ?)")
                    .bind(bad)
                    .execute(&pool)
                    .await;
            assert!(result.is_err(), "accepted bad domain '{}'", bad);
        }
    }

    #[tokio::test]
    async fn deleting_a_category_removes_its_domains() {
        let pool = memory_pool().await;

        sqlx::query("INSERT INTO dnsfilter_categories (name) VALUES ('gambling')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO dnsfilter_domains (category, domain) VALUES ('gambling', 'a.example.com'), ('gambling', 'b.example.com')",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query("DELETE FROM dnsfilter_categories WHERE name = 'gambling'")
            .execute(&pool)
            .await
            .unwrap();

        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dnsfilter_domains")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 0);
    }

    #[tokio::test]
    async fn rules_are_unique_per_domain_and_limited_to_block_or_allow() {
        let pool = memory_pool().await;

        sqlx::query("INSERT INTO dnsfilter_rules (domain, action) VALUES ('tiktok.com', 'block')")
            .execute(&pool)
            .await
            .unwrap();

        assert!(
            sqlx::query("INSERT INTO dnsfilter_rules (domain, action) VALUES ('tiktok.com', 'allow')")
                .execute(&pool)
                .await
                .is_err()
        );

        assert!(
            sqlx::query("INSERT INTO dnsfilter_rules (domain, action) VALUES ('x.example.com', 'maybe')")
                .execute(&pool)
                .await
                .is_err()
        );

        assert!(
            sqlx::query("INSERT INTO dnsfilter_rules (domain, action) VALUES ('Bad.com', 'block')")
                .execute(&pool)
                .await
                .is_err()
        );
    }
}
