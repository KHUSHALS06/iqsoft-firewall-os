use sqlx::SqlitePool;

pub async fn create_geoip_tables(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS geoip_policies (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            country_code  TEXT NOT NULL UNIQUE
                          CHECK (country_code GLOB '[A-Z][A-Z]'),
            direction     TEXT NOT NULL DEFAULT 'inbound'
                          CHECK (direction IN ('inbound', 'outbound', 'both')),
            enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
            comment       TEXT
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS geoip_datasets (
            country_code  TEXT PRIMARY KEY
                          CHECK (country_code GLOB '[A-Z][A-Z]'),
            updated_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            source        TEXT
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS geoip_networks (
            country_code  TEXT NOT NULL,
            family        TEXT NOT NULL CHECK (family IN ('ipv4', 'ipv6')),
            cidr          TEXT NOT NULL,
            PRIMARY KEY (country_code, cidr),
            FOREIGN KEY (country_code) REFERENCES geoip_datasets(country_code) ON DELETE CASCADE
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_geoip_networks_country_family ON geoip_networks(country_code, family);",
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

        create_geoip_tables(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn schema_can_be_created_twice() {
        let pool = memory_pool().await;
        create_geoip_tables(&pool).await.unwrap();
    }

    #[tokio::test]
    async fn policy_defaults_are_inbound_and_enabled() {
        let pool = memory_pool().await;

        sqlx::query("INSERT INTO geoip_policies (country_code) VALUES ('CN')")
            .execute(&pool)
            .await
            .unwrap();

        let row: (String, i64) =
            sqlx::query_as("SELECT direction, enabled FROM geoip_policies WHERE country_code = 'CN'")
                .fetch_one(&pool)
                .await
                .unwrap();

        assert_eq!(row.0, "inbound");
        assert_eq!(row.1, 1);
    }

    #[tokio::test]
    async fn country_code_must_be_two_uppercase_letters() {
        let pool = memory_pool().await;

        for bad in ["cn", "CHN", "C", "1A", "C1", ""] {
            let result = sqlx::query("INSERT INTO geoip_policies (country_code) VALUES (?)")
                .bind(bad)
                .execute(&pool)
                .await;
            assert!(result.is_err(), "accepted bad country code '{}'", bad);

            let dataset = sqlx::query("INSERT INTO geoip_datasets (country_code) VALUES (?)")
                .bind(bad)
                .execute(&pool)
                .await;
            assert!(dataset.is_err(), "dataset accepted bad country code '{}'", bad);
        }
    }

    #[tokio::test]
    async fn one_policy_per_country() {
        let pool = memory_pool().await;

        sqlx::query("INSERT INTO geoip_policies (country_code) VALUES ('RU')")
            .execute(&pool)
            .await
            .unwrap();

        let dup = sqlx::query("INSERT INTO geoip_policies (country_code, direction) VALUES ('RU', 'both')")
            .execute(&pool)
            .await;

        assert!(dup.is_err());
    }

    #[tokio::test]
    async fn bad_direction_or_enabled_is_rejected() {
        let pool = memory_pool().await;

        let bad_direction =
            sqlx::query("INSERT INTO geoip_policies (country_code, direction) VALUES ('KP', 'sideways')")
                .execute(&pool)
                .await;
        assert!(bad_direction.is_err());

        let bad_enabled =
            sqlx::query("INSERT INTO geoip_policies (country_code, enabled) VALUES ('KP', 2)")
                .execute(&pool)
                .await;
        assert!(bad_enabled.is_err());
    }

    #[tokio::test]
    async fn networks_need_a_dataset_and_a_valid_family() {
        let pool = memory_pool().await;

        let orphan = sqlx::query(
            "INSERT INTO geoip_networks (country_code, family, cidr) VALUES ('CN', 'ipv4', '1.0.1.0/24')",
        )
        .execute(&pool)
        .await;
        assert!(orphan.is_err());

        sqlx::query("INSERT INTO geoip_datasets (country_code) VALUES ('CN')")
            .execute(&pool)
            .await
            .unwrap();

        let bad_family = sqlx::query(
            "INSERT INTO geoip_networks (country_code, family, cidr) VALUES ('CN', 'ipx', '1.0.1.0/24')",
        )
        .execute(&pool)
        .await;
        assert!(bad_family.is_err());

        sqlx::query(
            "INSERT INTO geoip_networks (country_code, family, cidr) VALUES ('CN', 'ipv4', '1.0.1.0/24')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let duplicate = sqlx::query(
            "INSERT INTO geoip_networks (country_code, family, cidr) VALUES ('CN', 'ipv4', '1.0.1.0/24')",
        )
        .execute(&pool)
        .await;
        assert!(duplicate.is_err());
    }

    #[tokio::test]
    async fn deleting_a_dataset_removes_its_networks_but_not_the_policy() {
        let pool = memory_pool().await;

        sqlx::query("INSERT INTO geoip_policies (country_code) VALUES ('CN')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO geoip_datasets (country_code) VALUES ('CN')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO geoip_networks (country_code, family, cidr) VALUES ('CN', 'ipv4', '1.0.1.0/24'), ('CN', 'ipv6', '2001:250::/32')",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query("DELETE FROM geoip_datasets WHERE country_code = 'CN'")
            .execute(&pool)
            .await
            .unwrap();

        let networks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM geoip_networks")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(networks, 0);

        let policies: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM geoip_policies")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(policies, 1);
    }
}
