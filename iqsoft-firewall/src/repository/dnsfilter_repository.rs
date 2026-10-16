use crate::models::dnsfilter::{
    DnsFilterCategory, DnsFilterRule, DnsFilterSettings, ParsedDomains,
};
use sqlx::{
    sqlite::{Sqlite, SqliteRow},
    QueryBuilder, Row, SqlitePool,
};

// Two bound values per row, kept well under SQLite's variable limit.
const INSERT_CHUNK: usize = 400;

pub struct DnsFilterRepository;

impl DnsFilterRepository {
    fn row_to_category(row: &SqliteRow) -> DnsFilterCategory {
        DnsFilterCategory {
            name: row.get("name"),
            enabled: row.get::<i64, _>("enabled") != 0,
            comment: row.get("comment"),
            source: row.get("source"),
            updated_at: row.get("updated_at"),
            domain_count: row.get("domain_count"),
        }
    }

    fn row_to_rule(row: &SqliteRow) -> DnsFilterRule {
        DnsFilterRule {
            id: Some(row.get("id")),
            domain: row.get("domain"),
            action: row.get("action"),
            comment: row.get("comment"),
        }
    }

    // ---------- settings ----------

    pub async fn get_settings(pool: &SqlitePool) -> Result<DnsFilterSettings, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT enabled, block_response, safe_search, enforce_dns
            FROM dnsfilter_settings
            WHERE id = 1
            "#,
        )
        .fetch_one(pool)
        .await?;

        Ok(DnsFilterSettings {
            enabled: row.get::<i64, _>("enabled") != 0,
            block_response: row.get("block_response"),
            safe_search: row.get::<i64, _>("safe_search") != 0,
            enforce_dns: row.get::<i64, _>("enforce_dns") != 0,
        })
    }

    pub async fn set_settings(
        pool: &SqlitePool,
        settings: &DnsFilterSettings,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE dnsfilter_settings
            SET enabled = ?, block_response = ?, safe_search = ?, enforce_dns = ?
            WHERE id = 1
            "#,
        )
        .bind(settings.enabled)
        .bind(&settings.block_response)
        .bind(settings.safe_search)
        .bind(settings.enforce_dns)
        .execute(pool)
        .await?;

        Ok(())
    }

    // ---------- categories ----------

    pub async fn list_categories(pool: &SqlitePool) -> Result<Vec<DnsFilterCategory>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT
                c.name AS name,
                c.enabled AS enabled,
                c.comment AS comment,
                c.source AS source,
                c.updated_at AS updated_at,
                (SELECT COUNT(*) FROM dnsfilter_domains d WHERE d.category = c.name) AS domain_count
            FROM dnsfilter_categories c
            ORDER BY c.name ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_category).collect())
    }

    pub async fn get_category(
        pool: &SqlitePool,
        name: &str,
    ) -> Result<Option<DnsFilterCategory>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT
                c.name AS name,
                c.enabled AS enabled,
                c.comment AS comment,
                c.source AS source,
                c.updated_at AS updated_at,
                (SELECT COUNT(*) FROM dnsfilter_domains d WHERE d.category = c.name) AS domain_count
            FROM dnsfilter_categories c
            WHERE c.name = ?
            "#,
        )
        .bind(name)
        .fetch_optional(pool)
        .await?;

        Ok(row.as_ref().map(Self::row_to_category))
    }

    pub async fn add_category(
        pool: &SqlitePool,
        category: &DnsFilterCategory,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO dnsfilter_categories (name, enabled, comment)
            VALUES (?, ?, ?)
            "#,
        )
        .bind(&category.name)
        .bind(category.enabled)
        .bind(&category.comment)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Changes the switch and the comment only. The name is the key, and the
    /// source / update time belong to the imported list.
    pub async fn update_category(
        pool: &SqlitePool,
        name: &str,
        enabled: bool,
        comment: &Option<String>,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE dnsfilter_categories
            SET enabled = ?, comment = ?
            WHERE name = ?
            "#,
        )
        .bind(enabled)
        .bind(comment)
        .bind(name)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Deleting a category also deletes its domains.
    pub async fn delete_category(pool: &SqlitePool, name: &str) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM dnsfilter_categories WHERE name = ?")
            .bind(name)
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }

    // ---------- category domains ----------

    /// Replaces the whole domain list of one category in a single transaction.
    /// Fails with `RowNotFound` when the category does not exist.
    pub async fn replace_domains(
        pool: &SqlitePool,
        category: &str,
        source: Option<&str>,
        parsed: &ParsedDomains,
    ) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;

        let changed = sqlx::query(
            r#"
            UPDATE dnsfilter_categories
            SET source = ?, updated_at = CURRENT_TIMESTAMP
            WHERE name = ?
            "#,
        )
        .bind(source)
        .bind(category)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        if changed == 0 {
            return Err(sqlx::Error::RowNotFound);
        }

        sqlx::query("DELETE FROM dnsfilter_domains WHERE category = ?")
            .bind(category)
            .execute(&mut *tx)
            .await?;

        for chunk in parsed.domains.chunks(INSERT_CHUNK) {
            let mut builder: QueryBuilder<Sqlite> =
                QueryBuilder::new("INSERT INTO dnsfilter_domains (category, domain) ");

            builder.push_values(chunk.iter(), |mut row, domain| {
                row.push_bind(category).push_bind(domain.as_str());
            });

            builder.build().execute(&mut *tx).await?;
        }

        tx.commit().await?;

        Ok(())
    }

    pub async fn list_domains(
        pool: &SqlitePool,
        category: &str,
    ) -> Result<Vec<String>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT domain FROM dnsfilter_domains WHERE category = ? ORDER BY domain ASC",
        )
        .bind(category)
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(|row| row.get::<String, _>("domain")).collect())
    }

    /// Every domain from every enabled category, each one once, sorted.
    pub async fn list_enabled_domains(pool: &SqlitePool) -> Result<Vec<String>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT d.domain AS domain
            FROM dnsfilter_domains d
            JOIN dnsfilter_categories c ON c.name = d.category
            WHERE c.enabled = 1
            ORDER BY d.domain ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(|row| row.get::<String, _>("domain")).collect())
    }

    // ---------- your own block / allow rules ----------

    pub async fn list_rules(pool: &SqlitePool) -> Result<Vec<DnsFilterRule>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, domain, action, comment FROM dnsfilter_rules ORDER BY domain ASC",
        )
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_rule).collect())
    }

    pub async fn get_rule_by_domain(
        pool: &SqlitePool,
        domain: &str,
    ) -> Result<Option<DnsFilterRule>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, domain, action, comment FROM dnsfilter_rules WHERE domain = ?",
        )
        .bind(domain)
        .fetch_optional(pool)
        .await?;

        Ok(row.as_ref().map(Self::row_to_rule))
    }

    pub async fn add_rule(pool: &SqlitePool, rule: &DnsFilterRule) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            "INSERT INTO dnsfilter_rules (domain, action, comment) VALUES (?, ?, ?)",
        )
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
        rule: &DnsFilterRule,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE dnsfilter_rules
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
        let result = sqlx::query("DELETE FROM dnsfilter_rules WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::dnsfilter_schema::create_dnsfilter_tables;
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

    fn category(name: &str, enabled: bool) -> DnsFilterCategory {
        DnsFilterCategory {
            name: name.into(),
            enabled,
            comment: None,
            source: None,
            updated_at: None,
            domain_count: 0,
        }
    }

    fn domains(list: &[&str]) -> ParsedDomains {
        ParsedDomains {
            domains: list.iter().map(|d| d.to_string()).collect(),
            skipped: 0,
        }
    }

    fn rule(domain: &str, action: &str) -> DnsFilterRule {
        DnsFilterRule {
            id: None,
            domain: domain.into(),
            action: action.into(),
            comment: None,
        }
    }

    #[tokio::test]
    async fn settings_start_off_and_can_be_changed() {
        let pool = memory_pool().await;

        let start = DnsFilterRepository::get_settings(&pool).await.unwrap();
        assert!(!start.enabled);
        assert_eq!(start.block_response, "nxdomain");
        assert!(!start.safe_search);
        assert!(!start.enforce_dns);

        let changed = DnsFilterSettings {
            enabled: true,
            block_response: "sinkhole".into(),
            safe_search: true,
            enforce_dns: true,
        };
        DnsFilterRepository::set_settings(&pool, &changed).await.unwrap();

        assert_eq!(DnsFilterRepository::get_settings(&pool).await.unwrap(), changed);
    }

    #[tokio::test]
    async fn settings_with_a_bad_response_are_rejected_by_the_database() {
        let pool = memory_pool().await;

        let bad = DnsFilterSettings {
            enabled: true,
            block_response: "sideways".into(),
            safe_search: false,
            enforce_dns: false,
        };

        assert!(DnsFilterRepository::set_settings(&pool, &bad).await.is_err());
        assert!(!DnsFilterRepository::get_settings(&pool).await.unwrap().enabled);
    }

    #[tokio::test]
    async fn categories_can_be_added_listed_changed_and_deleted() {
        let pool = memory_pool().await;

        DnsFilterRepository::add_category(&pool, &category("gambling", true)).await.unwrap();
        DnsFilterRepository::add_category(&pool, &category("adult", false)).await.unwrap();

        assert!(DnsFilterRepository::add_category(&pool, &category("adult", true)).await.is_err());

        let all = DnsFilterRepository::list_categories(&pool).await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].name, "adult");
        assert!(!all[0].enabled);
        assert_eq!(all[1].name, "gambling");
        assert_eq!(all[1].domain_count, 0);
        assert!(all[1].updated_at.is_none());

        let changed = DnsFilterRepository::update_category(
            &pool,
            "adult",
            true,
            &Some("kids network".into()),
        )
        .await
        .unwrap();
        assert_eq!(changed, 1);

        let adult = DnsFilterRepository::get_category(&pool, "adult").await.unwrap().unwrap();
        assert!(adult.enabled);
        assert_eq!(adult.comment.as_deref(), Some("kids network"));

        assert_eq!(
            DnsFilterRepository::update_category(&pool, "missing", true, &None).await.unwrap(),
            0
        );
        assert!(DnsFilterRepository::get_category(&pool, "missing").await.unwrap().is_none());

        assert_eq!(DnsFilterRepository::delete_category(&pool, "adult").await.unwrap(), 1);
        assert_eq!(DnsFilterRepository::delete_category(&pool, "adult").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn replacing_domains_swaps_the_list_and_records_the_source() {
        let pool = memory_pool().await;
        DnsFilterRepository::add_category(&pool, &category("ads", true)).await.unwrap();

        DnsFilterRepository::replace_domains(
            &pool,
            "ads",
            Some("first list"),
            &domains(&["a.example.com", "b.example.com"]),
        )
        .await
        .unwrap();

        let ads = DnsFilterRepository::get_category(&pool, "ads").await.unwrap().unwrap();
        assert_eq!(ads.domain_count, 2);
        assert_eq!(ads.source.as_deref(), Some("first list"));
        assert!(ads.updated_at.is_some());

        DnsFilterRepository::replace_domains(&pool, "ads", None, &domains(&["c.example.com"]))
            .await
            .unwrap();

        assert_eq!(
            DnsFilterRepository::list_domains(&pool, "ads").await.unwrap(),
            vec!["c.example.com"]
        );

        let ads = DnsFilterRepository::get_category(&pool, "ads").await.unwrap().unwrap();
        assert_eq!(ads.domain_count, 1);
        assert!(ads.source.is_none());
    }

    #[tokio::test]
    async fn replacing_domains_for_an_unknown_category_fails_and_changes_nothing() {
        let pool = memory_pool().await;

        let result = DnsFilterRepository::replace_domains(
            &pool,
            "nope",
            None,
            &domains(&["a.example.com"]),
        )
        .await;

        assert!(result.is_err());

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dnsfilter_domains")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn a_large_list_is_stored_in_chunks() {
        let pool = memory_pool().await;
        DnsFilterRepository::add_category(&pool, &category("big", true)).await.unwrap();

        let list: Vec<String> = (0..2500).map(|i| format!("host{:05}.example.com", i)).collect();
        let parsed = ParsedDomains { domains: list, skipped: 0 };

        DnsFilterRepository::replace_domains(&pool, "big", None, &parsed).await.unwrap();

        let big = DnsFilterRepository::get_category(&pool, "big").await.unwrap().unwrap();
        assert_eq!(big.domain_count, 2500);
    }

    #[tokio::test]
    async fn deleting_a_category_removes_its_domains() {
        let pool = memory_pool().await;
        DnsFilterRepository::add_category(&pool, &category("ads", true)).await.unwrap();
        DnsFilterRepository::replace_domains(&pool, "ads", None, &domains(&["a.example.com"]))
            .await
            .unwrap();

        DnsFilterRepository::delete_category(&pool, "ads").await.unwrap();

        assert!(DnsFilterRepository::list_enabled_domains(&pool).await.unwrap().is_empty());

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dnsfilter_domains")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn only_enabled_categories_count_and_shared_domains_appear_once() {
        let pool = memory_pool().await;
        DnsFilterRepository::add_category(&pool, &category("ads", true)).await.unwrap();
        DnsFilterRepository::add_category(&pool, &category("tracking", true)).await.unwrap();
        DnsFilterRepository::add_category(&pool, &category("adult", false)).await.unwrap();

        DnsFilterRepository::replace_domains(&pool, "ads", None, &domains(&["a.example.com", "shared.example.com"]))
            .await
            .unwrap();
        DnsFilterRepository::replace_domains(&pool, "tracking", None, &domains(&["shared.example.com", "t.example.com"]))
            .await
            .unwrap();
        DnsFilterRepository::replace_domains(&pool, "adult", None, &domains(&["off.example.com"]))
            .await
            .unwrap();

        assert_eq!(
            DnsFilterRepository::list_enabled_domains(&pool).await.unwrap(),
            vec!["a.example.com", "shared.example.com", "t.example.com"]
        );
    }

    #[tokio::test]
    async fn rules_can_be_added_changed_and_deleted_with_one_rule_per_domain() {
        let pool = memory_pool().await;

        let id = DnsFilterRepository::add_rule(&pool, &rule("tiktok.com", "block")).await.unwrap();
        assert!(DnsFilterRepository::add_rule(&pool, &rule("tiktok.com", "allow")).await.is_err());
        assert!(DnsFilterRepository::add_rule(&pool, &rule("x.example.com", "maybe")).await.is_err());

        DnsFilterRepository::add_rule(&pool, &rule("docs.example.com", "allow")).await.unwrap();

        let all = DnsFilterRepository::list_rules(&pool).await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].domain, "docs.example.com");
        assert_eq!(all[1].domain, "tiktok.com");

        let found = DnsFilterRepository::get_rule_by_domain(&pool, "tiktok.com").await.unwrap().unwrap();
        assert_eq!(found.id, Some(id));
        assert!(DnsFilterRepository::get_rule_by_domain(&pool, "none.example.com").await.unwrap().is_none());

        assert_eq!(
            DnsFilterRepository::update_rule(&pool, id, &rule("tiktok.com", "allow")).await.unwrap(),
            1
        );
        let found = DnsFilterRepository::get_rule_by_domain(&pool, "tiktok.com").await.unwrap().unwrap();
        assert_eq!(found.action, "allow");

        assert_eq!(DnsFilterRepository::update_rule(&pool, 9999, &rule("a.example.com", "block")).await.unwrap(), 0);

        assert_eq!(DnsFilterRepository::delete_rule(&pool, id).await.unwrap(), 1);
        assert_eq!(DnsFilterRepository::delete_rule(&pool, id).await.unwrap(), 0);
    }
}
