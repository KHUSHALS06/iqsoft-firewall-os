use crate::models::geoip::{GeoipDataset, GeoipPolicy, ParsedZone};
use sqlx::{
    sqlite::{Sqlite, SqliteRow},
    QueryBuilder, Row, SqlitePool,
};

const INSERT_CHUNK: usize = 300;

pub struct GeoipRepository;

impl GeoipRepository {
    fn row_to_policy(row: &SqliteRow) -> GeoipPolicy {
        GeoipPolicy {
            id: Some(row.get("id")),
            country_code: row.get("country_code"),
            direction: row.get("direction"),
            enabled: row.get::<i64, _>("enabled") != 0,
            comment: row.get("comment"),
        }
    }

    fn row_to_dataset(row: &SqliteRow) -> GeoipDataset {
        GeoipDataset {
            country_code: row.get("country_code"),
            updated_at: row.get("updated_at"),
            source: row.get("source"),
            ipv4_count: row.get("ipv4_count"),
            ipv6_count: row.get("ipv6_count"),
        }
    }

    pub async fn list_policies(pool: &SqlitePool) -> Result<Vec<GeoipPolicy>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, country_code, direction, enabled, comment
            FROM geoip_policies
            ORDER BY country_code ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_policy).collect())
    }

    pub async fn list_enabled_policies(pool: &SqlitePool) -> Result<Vec<GeoipPolicy>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, country_code, direction, enabled, comment
            FROM geoip_policies
            WHERE enabled = 1
            ORDER BY country_code ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_policy).collect())
    }

    pub async fn get_policy(pool: &SqlitePool, id: i64) -> Result<Option<GeoipPolicy>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT id, country_code, direction, enabled, comment
            FROM geoip_policies
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(row.as_ref().map(Self::row_to_policy))
    }

    pub async fn get_policy_by_country(
        pool: &SqlitePool,
        country_code: &str,
    ) -> Result<Option<GeoipPolicy>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT id, country_code, direction, enabled, comment
            FROM geoip_policies
            WHERE country_code = ?
            "#,
        )
        .bind(country_code)
        .fetch_optional(pool)
        .await?;

        Ok(row.as_ref().map(Self::row_to_policy))
    }

    pub async fn add_policy(pool: &SqlitePool, policy: GeoipPolicy) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO geoip_policies (country_code, direction, enabled, comment)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(policy.country_code)
        .bind(policy.direction)
        .bind(policy.enabled)
        .bind(policy.comment)
        .execute(pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn update_policy(
        pool: &SqlitePool,
        id: i64,
        policy: GeoipPolicy,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE geoip_policies
            SET
                country_code = ?,
                direction = ?,
                enabled = ?,
                comment = ?
            WHERE id = ?
            "#,
        )
        .bind(policy.country_code)
        .bind(policy.direction)
        .bind(policy.enabled)
        .bind(policy.comment)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn delete_policy(pool: &SqlitePool, id: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM geoip_policies WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }

    pub async fn list_datasets(pool: &SqlitePool) -> Result<Vec<GeoipDataset>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT
                d.country_code AS country_code,
                d.updated_at AS updated_at,
                d.source AS source,
                (SELECT COUNT(*) FROM geoip_networks n
                    WHERE n.country_code = d.country_code AND n.family = 'ipv4') AS ipv4_count,
                (SELECT COUNT(*) FROM geoip_networks n
                    WHERE n.country_code = d.country_code AND n.family = 'ipv6') AS ipv6_count
            FROM geoip_datasets d
            ORDER BY d.country_code ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_dataset).collect())
    }

    pub async fn get_dataset(
        pool: &SqlitePool,
        country_code: &str,
    ) -> Result<Option<GeoipDataset>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT
                d.country_code AS country_code,
                d.updated_at AS updated_at,
                d.source AS source,
                (SELECT COUNT(*) FROM geoip_networks n
                    WHERE n.country_code = d.country_code AND n.family = 'ipv4') AS ipv4_count,
                (SELECT COUNT(*) FROM geoip_networks n
                    WHERE n.country_code = d.country_code AND n.family = 'ipv6') AS ipv6_count
            FROM geoip_datasets d
            WHERE d.country_code = ?
            "#,
        )
        .bind(country_code)
        .fetch_optional(pool)
        .await?;

        Ok(row.as_ref().map(Self::row_to_dataset))
    }

    pub async fn replace_dataset(
        pool: &SqlitePool,
        country_code: &str,
        source: Option<&str>,
        zone: &ParsedZone,
    ) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query(
            r#"
            INSERT INTO geoip_datasets (country_code, updated_at, source)
            VALUES (?, CURRENT_TIMESTAMP, ?)
            ON CONFLICT(country_code) DO UPDATE SET
                updated_at = CURRENT_TIMESTAMP,
                source = excluded.source
            "#,
        )
        .bind(country_code)
        .bind(source)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM geoip_networks WHERE country_code = ?")
            .bind(country_code)
            .execute(&mut *tx)
            .await?;

        for (family, networks) in [("ipv4", &zone.ipv4), ("ipv6", &zone.ipv6)] {
            for chunk in networks.chunks(INSERT_CHUNK) {
                let mut builder: QueryBuilder<Sqlite> =
                    QueryBuilder::new("INSERT INTO geoip_networks (country_code, family, cidr) ");

                builder.push_values(chunk.iter(), |mut row, cidr| {
                    row.push_bind(country_code)
                        .push_bind(family)
                        .push_bind(cidr.as_str());
                });

                builder.build().execute(&mut *tx).await?;
            }
        }

        tx.commit().await?;

        Ok(())
    }

    pub async fn delete_dataset(pool: &SqlitePool, country_code: &str) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM geoip_datasets WHERE country_code = ?")
            .bind(country_code)
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }

    pub async fn list_networks(
        pool: &SqlitePool,
        country_code: &str,
        family: &str,
    ) -> Result<Vec<String>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT cidr
            FROM geoip_networks
            WHERE country_code = ? AND family = ?
            ORDER BY cidr ASC
            "#,
        )
        .bind(country_code)
        .bind(family)
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(|row| row.get::<String, _>("cidr")).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::geoip_schema::create_geoip_tables;
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

    fn policy(code: &str, direction: &str, enabled: bool) -> GeoipPolicy {
        GeoipPolicy {
            id: None,
            country_code: code.to_string(),
            direction: direction.to_string(),
            enabled,
            comment: None,
        }
    }

    fn zone(v4: &[&str], v6: &[&str]) -> ParsedZone {
        ParsedZone {
            ipv4: v4.iter().map(|s| s.to_string()).collect(),
            ipv6: v6.iter().map(|s| s.to_string()).collect(),
            skipped: 0,
        }
    }

    #[tokio::test]
    async fn policy_round_trip() {
        let pool = memory_pool().await;

        let mut input = policy("CN", "both", true);
        input.comment = Some("scan traffic".into());

        let id = GeoipRepository::add_policy(&pool, input).await.unwrap();
        let loaded = GeoipRepository::get_policy(&pool, id).await.unwrap().unwrap();

        assert_eq!(loaded.id, Some(id));
        assert_eq!(loaded.country_code, "CN");
        assert_eq!(loaded.direction, "both");
        assert!(loaded.enabled);
        assert_eq!(loaded.comment.as_deref(), Some("scan traffic"));

        let by_country = GeoipRepository::get_policy_by_country(&pool, "CN")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_country.id, Some(id));

        assert!(GeoipRepository::get_policy(&pool, id + 100).await.unwrap().is_none());
        assert!(GeoipRepository::get_policy_by_country(&pool, "RU").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn policies_are_listed_by_country_and_enabled_filter_works() {
        let pool = memory_pool().await;

        GeoipRepository::add_policy(&pool, policy("RU", "inbound", true)).await.unwrap();
        GeoipRepository::add_policy(&pool, policy("CN", "outbound", false)).await.unwrap();
        GeoipRepository::add_policy(&pool, policy("KP", "both", true)).await.unwrap();

        let all: Vec<String> = GeoipRepository::list_policies(&pool)
            .await
            .unwrap()
            .into_iter()
            .map(|p| p.country_code)
            .collect();
        assert_eq!(all, vec!["CN", "KP", "RU"]);

        let enabled: Vec<String> = GeoipRepository::list_enabled_policies(&pool)
            .await
            .unwrap()
            .into_iter()
            .map(|p| p.country_code)
            .collect();
        assert_eq!(enabled, vec!["KP", "RU"]);
    }

    #[tokio::test]
    async fn duplicate_country_is_refused_by_the_database() {
        let pool = memory_pool().await;

        GeoipRepository::add_policy(&pool, policy("CN", "inbound", true)).await.unwrap();
        let dup = GeoipRepository::add_policy(&pool, policy("CN", "both", true)).await;

        assert!(dup.is_err());
    }

    #[tokio::test]
    async fn update_and_delete_report_rows_affected() {
        let pool = memory_pool().await;

        let id = GeoipRepository::add_policy(&pool, policy("CN", "inbound", true)).await.unwrap();

        let changed = GeoipRepository::update_policy(&pool, id, policy("CN", "both", false))
            .await
            .unwrap();
        assert_eq!(changed, 1);

        let loaded = GeoipRepository::get_policy(&pool, id).await.unwrap().unwrap();
        assert_eq!(loaded.direction, "both");
        assert!(!loaded.enabled);

        assert_eq!(
            GeoipRepository::update_policy(&pool, id + 100, policy("CN", "both", true))
                .await
                .unwrap(),
            0
        );

        assert_eq!(GeoipRepository::delete_policy(&pool, id + 100).await.unwrap(), 0);
        assert_eq!(GeoipRepository::delete_policy(&pool, id).await.unwrap(), 1);
        assert!(GeoipRepository::get_policy(&pool, id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn dataset_is_stored_with_counts_and_sorted_networks() {
        let pool = memory_pool().await;

        GeoipRepository::replace_dataset(
            &pool,
            "CN",
            Some("ipdeny cn.zone"),
            &zone(&["1.0.2.0/24", "1.0.1.0/24"], &["2001:250::/32"]),
        )
        .await
        .unwrap();

        let info = GeoipRepository::get_dataset(&pool, "CN").await.unwrap().unwrap();
        assert_eq!(info.country_code, "CN");
        assert_eq!(info.source.as_deref(), Some("ipdeny cn.zone"));
        assert_eq!(info.ipv4_count, 2);
        assert_eq!(info.ipv6_count, 1);
        assert!(!info.updated_at.is_empty());

        assert_eq!(
            GeoipRepository::list_networks(&pool, "CN", "ipv4").await.unwrap(),
            vec!["1.0.1.0/24", "1.0.2.0/24"]
        );
        assert_eq!(
            GeoipRepository::list_networks(&pool, "CN", "ipv6").await.unwrap(),
            vec!["2001:250::/32"]
        );
        assert!(GeoipRepository::list_networks(&pool, "RU", "ipv4").await.unwrap().is_empty());

        let listed = GeoipRepository::list_datasets(&pool).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].ipv4_count, 2);
    }

    #[tokio::test]
    async fn replacing_a_dataset_swaps_the_old_networks_for_the_new_ones() {
        let pool = memory_pool().await;

        GeoipRepository::replace_dataset(&pool, "CN", Some("first"), &zone(&["1.0.1.0/24"], &["2001:250::/32"]))
            .await
            .unwrap();
        GeoipRepository::replace_dataset(&pool, "CN", Some("second"), &zone(&["1.0.9.0/24"], &[]))
            .await
            .unwrap();

        assert_eq!(
            GeoipRepository::list_networks(&pool, "CN", "ipv4").await.unwrap(),
            vec!["1.0.9.0/24"]
        );
        assert!(GeoipRepository::list_networks(&pool, "CN", "ipv6").await.unwrap().is_empty());

        let info = GeoipRepository::get_dataset(&pool, "CN").await.unwrap().unwrap();
        assert_eq!(info.source.as_deref(), Some("second"));
        assert_eq!(info.ipv6_count, 0);

        assert_eq!(GeoipRepository::list_datasets(&pool).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_failed_replace_leaves_the_existing_dataset_untouched() {
        let pool = memory_pool().await;

        GeoipRepository::replace_dataset(&pool, "CN", Some("good"), &zone(&["1.0.1.0/24", "1.0.2.0/24"], &[]))
            .await
            .unwrap();

        let broken = zone(&["1.0.5.0/24", "1.0.5.0/24"], &[]);
        let result = GeoipRepository::replace_dataset(&pool, "CN", Some("broken"), &broken).await;
        assert!(result.is_err());

        assert_eq!(
            GeoipRepository::list_networks(&pool, "CN", "ipv4").await.unwrap(),
            vec!["1.0.1.0/24", "1.0.2.0/24"]
        );
        let info = GeoipRepository::get_dataset(&pool, "CN").await.unwrap().unwrap();
        assert_eq!(info.source.as_deref(), Some("good"));
    }

    #[tokio::test]
    async fn datasets_for_different_countries_do_not_mix() {
        let pool = memory_pool().await;

        GeoipRepository::replace_dataset(&pool, "CN", None, &zone(&["1.0.1.0/24"], &[])).await.unwrap();
        GeoipRepository::replace_dataset(&pool, "RU", None, &zone(&["5.8.0.0/16"], &[])).await.unwrap();
        GeoipRepository::replace_dataset(&pool, "CN", None, &zone(&["1.0.7.0/24"], &[])).await.unwrap();

        assert_eq!(GeoipRepository::list_networks(&pool, "RU", "ipv4").await.unwrap(), vec!["5.8.0.0/16"]);
        assert_eq!(GeoipRepository::list_networks(&pool, "CN", "ipv4").await.unwrap(), vec!["1.0.7.0/24"]);
    }

    #[tokio::test]
    async fn deleting_a_dataset_removes_networks_but_keeps_the_policy() {
        let pool = memory_pool().await;

        GeoipRepository::add_policy(&pool, policy("CN", "inbound", true)).await.unwrap();
        GeoipRepository::replace_dataset(&pool, "CN", None, &zone(&["1.0.1.0/24"], &[])).await.unwrap();

        assert_eq!(GeoipRepository::delete_dataset(&pool, "CN").await.unwrap(), 1);
        assert_eq!(GeoipRepository::delete_dataset(&pool, "CN").await.unwrap(), 0);

        assert!(GeoipRepository::get_dataset(&pool, "CN").await.unwrap().is_none());
        assert!(GeoipRepository::list_networks(&pool, "CN", "ipv4").await.unwrap().is_empty());
        assert_eq!(GeoipRepository::list_policies(&pool).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn deleting_a_policy_keeps_the_dataset() {
        let pool = memory_pool().await;

        let id = GeoipRepository::add_policy(&pool, policy("CN", "inbound", true)).await.unwrap();
        GeoipRepository::replace_dataset(&pool, "CN", None, &zone(&["1.0.1.0/24"], &[])).await.unwrap();

        GeoipRepository::delete_policy(&pool, id).await.unwrap();

        assert!(GeoipRepository::get_dataset(&pool, "CN").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn large_datasets_are_inserted_in_chunks() {
        let pool = memory_pool().await;

        let v4: Vec<String> = (0..2000u32).map(|i| format!("{}.{}.0.0/16", 20 + i / 256, i % 256)).collect();
        let v6: Vec<String> = (0..700u32).map(|i| format!("2a00:{:x}::/32", i + 1)).collect();
        let big = ParsedZone { ipv4: v4, ipv6: v6, skipped: 0 };

        GeoipRepository::replace_dataset(&pool, "DE", Some("bulk"), &big).await.unwrap();

        let info = GeoipRepository::get_dataset(&pool, "DE").await.unwrap().unwrap();
        assert_eq!(info.ipv4_count, 2000);
        assert_eq!(info.ipv6_count, 700);
    }

    #[tokio::test]
    async fn an_invalid_country_code_cannot_create_a_dataset() {
        let pool = memory_pool().await;

        let result = GeoipRepository::replace_dataset(&pool, "cn", None, &zone(&["1.0.1.0/24"], &[])).await;
        assert!(result.is_err());
        assert!(GeoipRepository::list_datasets(&pool).await.unwrap().is_empty());
    }
}
