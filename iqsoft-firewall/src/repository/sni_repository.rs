use crate::models::sni::{SniRule, SniSettings};
use sqlx::{sqlite::SqliteRow, Row, SqlitePool};

pub struct SniRepository;

impl SniRepository {
    fn row_to_rule(row: &SqliteRow) -> SniRule {
        SniRule {
            id: Some(row.get("id")),
            domain: row.get("domain"),
            action: row.get("action"),
            comment: row.get("comment"),
        }
    }

    // ---------- settings ----------

    pub async fn get_settings(pool: &SqlitePool) -> Result<SniSettings, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT enabled, use_dns_filter_lists, no_name_action, block_malformed, block_quic
            FROM sni_settings
            WHERE id = 1
            "#,
        )
        .fetch_one(pool)
        .await?;

        Ok(SniSettings {
            enabled: row.get::<i64, _>("enabled") != 0,
            use_dns_filter_lists: row.get::<i64, _>("use_dns_filter_lists") != 0,
            no_name_action: row.get("no_name_action"),
            block_malformed: row.get::<i64, _>("block_malformed") != 0,
            block_quic: row.get::<i64, _>("block_quic") != 0,
        })
    }

    pub async fn set_settings(
        pool: &SqlitePool,
        settings: &SniSettings,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE sni_settings
            SET enabled = ?,
                use_dns_filter_lists = ?,
                no_name_action = ?,
                block_malformed = ?,
                block_quic = ?
            WHERE id = 1
            "#,
        )
        .bind(settings.enabled)
        .bind(settings.use_dns_filter_lists)
        .bind(&settings.no_name_action)
        .bind(settings.block_malformed)
        .bind(settings.block_quic)
        .execute(pool)
        .await?;

        Ok(())
    }

    // ---------- your own block / allow rules ----------

    pub async fn list_rules(pool: &SqlitePool) -> Result<Vec<SniRule>, sqlx::Error> {
        let rows = sqlx::query("SELECT id, domain, action, comment FROM sni_rules ORDER BY domain ASC")
            .fetch_all(pool)
            .await?;

        Ok(rows.iter().map(Self::row_to_rule).collect())
    }

    pub async fn get_rule_by_domain(
        pool: &SqlitePool,
        domain: &str,
    ) -> Result<Option<SniRule>, sqlx::Error> {
        let row = sqlx::query("SELECT id, domain, action, comment FROM sni_rules WHERE domain = ?")
            .bind(domain)
            .fetch_optional(pool)
            .await?;

        Ok(row.as_ref().map(Self::row_to_rule))
    }

    pub async fn add_rule(pool: &SqlitePool, rule: &SniRule) -> Result<i64, sqlx::Error> {
        let result = sqlx::query("INSERT INTO sni_rules (domain, action, comment) VALUES (?, ?, ?)")
            .bind(&rule.domain)
            .bind(&rule.action)
            .bind(&rule.comment)
            .execute(pool)
            .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn update_rule(
        pool: &SqlitePool,
        id: i64,
        rule: &SniRule,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE sni_rules
            SET domain = ?, action = ?, comment = ?
            WHERE id = ?
            "#,
        )
        .bind(&rule.domain)
        .bind(&rule.action)
        .bind(&rule.comment)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn delete_rule(pool: &SqlitePool, id: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM sni_rules WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::sni_schema::create_sni_tables;
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

    fn rule(domain: &str, action: &str, comment: Option<&str>) -> SniRule {
        SniRule {
            id: None,
            domain: domain.into(),
            action: action.into(),
            comment: comment.map(|c| c.to_string()),
        }
    }

    #[tokio::test]
    async fn settings_start_with_the_defaults() {
        let pool = memory_pool().await;
        let settings = SniRepository::get_settings(&pool).await.unwrap();

        assert_eq!(
            settings,
            SniSettings {
                enabled: false,
                use_dns_filter_lists: true,
                no_name_action: "allow".into(),
                block_malformed: true,
                block_quic: false,
            }
        );
    }

    #[tokio::test]
    async fn settings_round_trip() {
        let pool = memory_pool().await;

        let wanted = SniSettings {
            enabled: true,
            use_dns_filter_lists: false,
            no_name_action: "block".into(),
            block_malformed: false,
            block_quic: true,
        };

        SniRepository::set_settings(&pool, &wanted).await.unwrap();

        assert_eq!(SniRepository::get_settings(&pool).await.unwrap(), wanted);
    }

    #[tokio::test]
    async fn rules_are_listed_by_domain_and_found_by_domain() {
        let pool = memory_pool().await;

        let b = SniRepository::add_rule(&pool, &rule("tiktok.com", "block", Some("kids"))).await.unwrap();
        let a = SniRepository::add_rule(&pool, &rule("bank.example.com", "allow", None)).await.unwrap();
        assert_ne!(a, b);

        let rules = SniRepository::list_rules(&pool).await.unwrap();
        let domains: Vec<&str> = rules.iter().map(|r| r.domain.as_str()).collect();
        assert_eq!(domains, vec!["bank.example.com", "tiktok.com"]);

        let found = SniRepository::get_rule_by_domain(&pool, "tiktok.com").await.unwrap().unwrap();
        assert_eq!(found.id, Some(b));
        assert_eq!(found.action, "block");
        assert_eq!(found.comment.as_deref(), Some("kids"));

        assert!(SniRepository::get_rule_by_domain(&pool, "nothing.example").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_rule_can_be_updated() {
        let pool = memory_pool().await;
        let id = SniRepository::add_rule(&pool, &rule("tiktok.com", "block", None)).await.unwrap();

        let changed = SniRepository::update_rule(&pool, id, &rule("tiktok.com", "allow", Some("ok now")))
            .await
            .unwrap();
        assert_eq!(changed, 1);

        let found = SniRepository::get_rule_by_domain(&pool, "tiktok.com").await.unwrap().unwrap();
        assert_eq!(found.action, "allow");
        assert_eq!(found.comment.as_deref(), Some("ok now"));
    }

    #[tokio::test]
    async fn update_and_delete_report_how_many_rows_they_touched() {
        let pool = memory_pool().await;
        let id = SniRepository::add_rule(&pool, &rule("tiktok.com", "block", None)).await.unwrap();

        assert_eq!(SniRepository::update_rule(&pool, 9999, &rule("x.example.com", "block", None)).await.unwrap(), 0);
        assert_eq!(SniRepository::delete_rule(&pool, 9999).await.unwrap(), 0);

        assert_eq!(SniRepository::delete_rule(&pool, id).await.unwrap(), 1);
        assert!(SniRepository::list_rules(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_database_refuses_a_second_rule_for_the_same_domain() {
        let pool = memory_pool().await;
        SniRepository::add_rule(&pool, &rule("tiktok.com", "block", None)).await.unwrap();

        assert!(SniRepository::add_rule(&pool, &rule("tiktok.com", "allow", None)).await.is_err());

        let other = SniRepository::add_rule(&pool, &rule("other.example.com", "block", None)).await.unwrap();
        assert!(SniRepository::update_rule(&pool, other, &rule("tiktok.com", "block", None)).await.is_err());
    }
}
