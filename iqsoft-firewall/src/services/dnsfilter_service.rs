use crate::{
    models::dnsfilter::{
        normalize_action, normalize_block_response, normalize_category_name, normalize_domain,
        parse_domain_list, validate_comment, validate_source, DnsFilterCategory,
        DnsFilterImportRequest, DnsFilterImportResult, DnsFilterRule, DnsFilterSettings,
    },
    repository::dnsfilter_repository::DnsFilterRepository,
};
use sqlx::SqlitePool;

const BAD_CATEGORY: &str =
    "Category name must be 1-40 characters: lowercase letters, numbers, '-' or '_'";
const BAD_DOMAIN: &str = "Domain must be a full name such as example.com";

pub struct DnsFilterService;

impl DnsFilterService {
    // ---------- settings ----------

    pub async fn get_settings(pool: &SqlitePool) -> Result<DnsFilterSettings, String> {
        DnsFilterRepository::get_settings(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn set_settings(
        pool: &SqlitePool,
        mut settings: DnsFilterSettings,
    ) -> Result<(), String> {
        settings.block_response = normalize_block_response(&settings.block_response)
            .ok_or("Block response must be 'nxdomain' or 'sinkhole'")?
            .to_string();

        DnsFilterRepository::set_settings(pool, &settings)
            .await
            .map_err(|e| e.to_string())
    }

    // ---------- categories ----------

    pub async fn list_categories(pool: &SqlitePool) -> Result<Vec<DnsFilterCategory>, String> {
        DnsFilterRepository::list_categories(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn add_category(
        pool: &SqlitePool,
        mut category: DnsFilterCategory,
    ) -> Result<(), String> {
        category.name = normalize_category_name(&category.name).ok_or(BAD_CATEGORY)?;
        category.comment = Self::clean_comment(category.comment)?;

        let existing = DnsFilterRepository::get_category(pool, &category.name)
            .await
            .map_err(|e| e.to_string())?;

        if existing.is_some() {
            return Err(format!("Category '{}' already exists", category.name));
        }

        DnsFilterRepository::add_category(pool, &category)
            .await
            .map_err(|e| e.to_string())
    }

    /// Only the on/off switch and the comment can change. The name is the key.
    pub async fn update_category(
        pool: &SqlitePool,
        name: &str,
        category: DnsFilterCategory,
    ) -> Result<(), String> {
        let name = normalize_category_name(name).ok_or(BAD_CATEGORY)?;
        let comment = Self::clean_comment(category.comment)?;

        let changed = DnsFilterRepository::update_category(pool, &name, category.enabled, &comment)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("Category '{}' does not exist", name));
        }

        Ok(())
    }

    pub async fn delete_category(pool: &SqlitePool, name: &str) -> Result<(), String> {
        let name = normalize_category_name(name).ok_or(BAD_CATEGORY)?;

        let changed = DnsFilterRepository::delete_category(pool, &name)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("Category '{}' does not exist", name));
        }

        Ok(())
    }

    /// Replaces the domain list of one category with the pasted text.
    /// The category has to exist first.
    pub async fn import_domains(
        pool: &SqlitePool,
        name: &str,
        request: DnsFilterImportRequest,
    ) -> Result<DnsFilterImportResult, String> {
        let name = normalize_category_name(name).ok_or(BAD_CATEGORY)?;

        validate_source(&request.source)?;

        let source = request
            .source
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let parsed = parse_domain_list(&request.data)?;

        match DnsFilterRepository::replace_domains(pool, &name, source.as_deref(), &parsed).await {
            Ok(()) => {}
            Err(sqlx::Error::RowNotFound) => {
                return Err(format!(
                    "Category '{}' does not exist, create it first",
                    name
                ));
            }
            Err(e) => return Err(e.to_string()),
        }

        Ok(DnsFilterImportResult {
            category: name,
            imported: parsed.domains.len(),
            skipped: parsed.skipped,
        })
    }

    // ---------- your own block / allow rules ----------

    pub async fn list_rules(pool: &SqlitePool) -> Result<Vec<DnsFilterRule>, String> {
        DnsFilterRepository::list_rules(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn add_rule(pool: &SqlitePool, rule: DnsFilterRule) -> Result<(), String> {
        let rule = Self::clean_rule(rule)?;

        let existing = DnsFilterRepository::get_rule_by_domain(pool, &rule.domain)
            .await
            .map_err(|e| e.to_string())?;

        if existing.is_some() {
            return Err(format!("A rule for {} already exists", rule.domain));
        }

        DnsFilterRepository::add_rule(pool, &rule)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub async fn update_rule(
        pool: &SqlitePool,
        id: i64,
        rule: DnsFilterRule,
    ) -> Result<(), String> {
        let rule = Self::clean_rule(rule)?;

        let existing = DnsFilterRepository::get_rule_by_domain(pool, &rule.domain)
            .await
            .map_err(|e| e.to_string())?;

        if let Some(other) = existing {
            if other.id != Some(id) {
                return Err(format!("A rule for {} already exists", rule.domain));
            }
        }

        let changed = DnsFilterRepository::update_rule(pool, id, &rule)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("DNS filter rule {} does not exist", id));
        }

        Ok(())
    }

    pub async fn delete_rule(pool: &SqlitePool, id: i64) -> Result<(), String> {
        let changed = DnsFilterRepository::delete_rule(pool, id)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("DNS filter rule {} does not exist", id));
        }

        Ok(())
    }

    // ---------- helpers ----------

    fn clean_comment(comment: Option<String>) -> Result<Option<String>, String> {
        let comment = comment
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty());

        validate_comment(&comment)?;

        Ok(comment)
    }

    fn clean_rule(mut rule: DnsFilterRule) -> Result<DnsFilterRule, String> {
        rule.domain = normalize_domain(&rule.domain).ok_or(BAD_DOMAIN)?;

        rule.action = normalize_action(&rule.action)
            .ok_or("Action must be 'block' or 'allow'")?
            .to_string();

        rule.comment = Self::clean_comment(rule.comment)?;

        Ok(rule)
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

    fn category(name: &str) -> DnsFilterCategory {
        DnsFilterCategory {
            name: name.into(),
            enabled: true,
            comment: None,
            source: None,
            updated_at: None,
            domain_count: 0,
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

    fn import(data: &str) -> DnsFilterImportRequest {
        DnsFilterImportRequest {
            data: data.into(),
            source: Some("test list".into()),
        }
    }

    #[tokio::test]
    async fn settings_are_checked_and_saved() {
        let pool = memory_pool().await;

        let mut settings = DnsFilterService::get_settings(&pool).await.unwrap();
        settings.enabled = true;
        settings.block_response = " SINKHOLE ".into();
        DnsFilterService::set_settings(&pool, settings).await.unwrap();

        let saved = DnsFilterService::get_settings(&pool).await.unwrap();
        assert!(saved.enabled);
        assert_eq!(saved.block_response, "sinkhole");

        let mut bad = saved.clone();
        bad.block_response = "refuse".into();
        assert!(DnsFilterService::set_settings(&pool, bad).await.is_err());
        assert_eq!(
            DnsFilterService::get_settings(&pool).await.unwrap().block_response,
            "sinkhole"
        );
    }

    #[tokio::test]
    async fn categories_are_cleaned_and_names_are_unique() {
        let pool = memory_pool().await;

        let mut adult = category(" Adult ");
        adult.comment = Some("  kids network  ".into());
        DnsFilterService::add_category(&pool, adult).await.unwrap();

        let saved = DnsFilterService::list_categories(&pool).await.unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].name, "adult");
        assert_eq!(saved[0].comment.as_deref(), Some("kids network"));

        assert!(DnsFilterService::add_category(&pool, category("ADULT")).await.is_err());
        assert!(DnsFilterService::add_category(&pool, category("a b")).await.is_err());
        assert!(DnsFilterService::add_category(&pool, category("")).await.is_err());

        let mut long = category("ads");
        long.comment = Some("x".repeat(500));
        assert!(DnsFilterService::add_category(&pool, long).await.is_err());
    }

    #[tokio::test]
    async fn a_category_can_be_switched_off_and_deleted() {
        let pool = memory_pool().await;
        DnsFilterService::add_category(&pool, category("gambling")).await.unwrap();

        let mut off = category("ignored-name");
        off.enabled = false;
        DnsFilterService::update_category(&pool, "Gambling", off).await.unwrap();

        let saved = DnsFilterService::list_categories(&pool).await.unwrap();
        assert_eq!(saved[0].name, "gambling");
        assert!(!saved[0].enabled);

        assert!(DnsFilterService::update_category(&pool, "missing", category("x")).await.is_err());

        DnsFilterService::delete_category(&pool, "gambling").await.unwrap();
        assert!(DnsFilterService::delete_category(&pool, "gambling").await.is_err());
        assert!(DnsFilterService::list_categories(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn import_counts_cleans_and_replaces_the_old_list() {
        let pool = memory_pool().await;
        DnsFilterService::add_category(&pool, category("ads")).await.unwrap();

        let result = DnsFilterService::import_domains(
            &pool,
            "Ads",
            import("Ads.Example.com\n0.0.0.0 track.example.net\n||pop.example.org^\ncom\n"),
        )
        .await
        .unwrap();

        assert_eq!(result.category, "ads");
        assert_eq!(result.imported, 3);
        assert_eq!(result.skipped, 1);

        DnsFilterService::import_domains(&pool, "ads", import("only.example.com\n"))
            .await
            .unwrap();

        let saved = DnsFilterService::list_categories(&pool).await.unwrap();
        assert_eq!(saved[0].domain_count, 1);
        assert_eq!(saved[0].source.as_deref(), Some("test list"));
    }

    #[tokio::test]
    async fn bad_imports_are_refused_and_leave_the_old_list_alone() {
        let pool = memory_pool().await;
        DnsFilterService::add_category(&pool, category("ads")).await.unwrap();
        DnsFilterService::import_domains(&pool, "ads", import("keep.example.com\n"))
            .await
            .unwrap();

        assert!(DnsFilterService::import_domains(&pool, "ads", import("rubbish\n")).await.is_err());
        assert!(DnsFilterService::import_domains(&pool, "ads", import("")).await.is_err());
        assert!(DnsFilterService::import_domains(&pool, "bad name", import("a.example.com\n")).await.is_err());

        let mut bad_source = import("a.example.com\n");
        bad_source.source = Some("bad\u{0007}".into());
        assert!(DnsFilterService::import_domains(&pool, "ads", bad_source).await.is_err());

        let saved = DnsFilterService::list_categories(&pool).await.unwrap();
        assert_eq!(saved[0].domain_count, 1);
    }

    #[tokio::test]
    async fn importing_into_a_category_that_does_not_exist_says_so() {
        let pool = memory_pool().await;

        let err = DnsFilterService::import_domains(&pool, "ghost", import("a.example.com\n"))
            .await
            .unwrap_err();

        assert!(err.contains("does not exist"), "{}", err);
    }

    #[tokio::test]
    async fn rules_are_cleaned_and_one_per_domain() {
        let pool = memory_pool().await;

        DnsFilterService::add_rule(&pool, rule("*.TikTok.com.", " Block ")).await.unwrap();

        let saved = DnsFilterService::list_rules(&pool).await.unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].domain, "tiktok.com");
        assert_eq!(saved[0].action, "block");

        assert!(DnsFilterService::add_rule(&pool, rule("tiktok.com", "allow")).await.is_err());
        assert!(DnsFilterService::add_rule(&pool, rule("com", "block")).await.is_err());
        assert!(DnsFilterService::add_rule(&pool, rule("1.2.3.4", "block")).await.is_err());
        assert!(DnsFilterService::add_rule(&pool, rule("x.example.com", "maybe")).await.is_err());
        assert!(DnsFilterService::add_rule(&pool, rule("a;b.com", "block")).await.is_err());
    }

    #[tokio::test]
    async fn rules_can_be_updated_without_colliding_and_deleted() {
        let pool = memory_pool().await;

        DnsFilterService::add_rule(&pool, rule("a.example.com", "block")).await.unwrap();
        DnsFilterService::add_rule(&pool, rule("b.example.com", "block")).await.unwrap();

        let saved = DnsFilterService::list_rules(&pool).await.unwrap();
        let a_id = saved.iter().find(|r| r.domain == "a.example.com").unwrap().id.unwrap();

        // Saving a rule as itself is fine, taking another rule's domain is not.
        DnsFilterService::update_rule(&pool, a_id, rule("a.example.com", "allow")).await.unwrap();
        assert!(DnsFilterService::update_rule(&pool, a_id, rule("b.example.com", "allow")).await.is_err());
        assert!(DnsFilterService::update_rule(&pool, 9999, rule("z.example.com", "block")).await.is_err());

        let saved = DnsFilterService::list_rules(&pool).await.unwrap();
        assert_eq!(saved.iter().find(|r| r.id == Some(a_id)).unwrap().action, "allow");

        DnsFilterService::delete_rule(&pool, a_id).await.unwrap();
        assert!(DnsFilterService::delete_rule(&pool, a_id).await.is_err());
    }
}
