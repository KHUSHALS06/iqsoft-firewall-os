use crate::{
    models::{
        dnsfilter::{normalize_action, normalize_domain, validate_comment},
        sni::{normalize_no_name_action, SniRule, SniSettings},
    },
    repository::sni_repository::SniRepository,
};
use sqlx::SqlitePool;

const BAD_DOMAIN: &str = "Domain must be a full name such as example.com";

pub struct SniService;

impl SniService {
    // ---------- settings ----------

    pub async fn get_settings(pool: &SqlitePool) -> Result<SniSettings, String> {
        SniRepository::get_settings(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn set_settings(pool: &SqlitePool, mut settings: SniSettings) -> Result<(), String> {
        settings.no_name_action = normalize_no_name_action(&settings.no_name_action)
            .ok_or("No-name action must be 'allow' or 'block'")?
            .to_string();

        SniRepository::set_settings(pool, &settings)
            .await
            .map_err(|e| e.to_string())
    }

    // ---------- your own block / allow rules ----------

    pub async fn list_rules(pool: &SqlitePool) -> Result<Vec<SniRule>, String> {
        SniRepository::list_rules(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn add_rule(pool: &SqlitePool, rule: SniRule) -> Result<(), String> {
        let rule = Self::clean_rule(rule)?;

        let existing = SniRepository::get_rule_by_domain(pool, &rule.domain)
            .await
            .map_err(|e| e.to_string())?;

        if existing.is_some() {
            return Err(format!("A rule for {} already exists", rule.domain));
        }

        SniRepository::add_rule(pool, &rule)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub async fn update_rule(pool: &SqlitePool, id: i64, rule: SniRule) -> Result<(), String> {
        let rule = Self::clean_rule(rule)?;

        let existing = SniRepository::get_rule_by_domain(pool, &rule.domain)
            .await
            .map_err(|e| e.to_string())?;

        if let Some(other) = existing {
            if other.id != Some(id) {
                return Err(format!("A rule for {} already exists", rule.domain));
            }
        }

        let changed = SniRepository::update_rule(pool, id, &rule)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("SNI rule {} does not exist", id));
        }

        Ok(())
    }

    pub async fn delete_rule(pool: &SqlitePool, id: i64) -> Result<(), String> {
        let changed = SniRepository::delete_rule(pool, id)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("SNI rule {} does not exist", id));
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

    fn clean_rule(mut rule: SniRule) -> Result<SniRule, String> {
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

    fn rule(domain: &str, action: &str) -> SniRule {
        SniRule {
            id: None,
            domain: domain.into(),
            action: action.into(),
            comment: None,
        }
    }

    fn settings(no_name_action: &str) -> SniSettings {
        SniSettings {
            enabled: true,
            use_dns_filter_lists: true,
            no_name_action: no_name_action.into(),
            block_malformed: true,
            block_quic: false,
        }
    }

    #[tokio::test]
    async fn settings_are_normalized_and_bad_values_refused() {
        let pool = memory_pool().await;

        SniService::set_settings(&pool, settings(" BLOCK ")).await.unwrap();
        let saved = SniService::get_settings(&pool).await.unwrap();
        assert_eq!(saved.no_name_action, "block");
        assert!(saved.enabled);

        assert!(SniService::set_settings(&pool, settings("maybe")).await.is_err());
        assert!(SniService::set_settings(&pool, settings("")).await.is_err());

        // A refused save changes nothing.
        assert_eq!(SniService::get_settings(&pool).await.unwrap().no_name_action, "block");
    }

    #[tokio::test]
    async fn rules_are_cleaned_and_one_per_domain() {
        let pool = memory_pool().await;

        SniService::add_rule(&pool, rule("*.TikTok.com.", " Block ")).await.unwrap();

        let saved = SniService::list_rules(&pool).await.unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].domain, "tiktok.com");
        assert_eq!(saved[0].action, "block");

        assert!(SniService::add_rule(&pool, rule("tiktok.com", "allow")).await.is_err());
        assert!(SniService::add_rule(&pool, rule("com", "block")).await.is_err());
        assert!(SniService::add_rule(&pool, rule("1.2.3.4", "block")).await.is_err());
        assert!(SniService::add_rule(&pool, rule("x.example.com", "maybe")).await.is_err());
        assert!(SniService::add_rule(&pool, rule("a;b.com", "block")).await.is_err());

        assert_eq!(SniService::list_rules(&pool).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn rules_can_be_updated_without_colliding_and_deleted() {
        let pool = memory_pool().await;

        SniService::add_rule(&pool, rule("a.example.com", "block")).await.unwrap();
        SniService::add_rule(&pool, rule("b.example.com", "block")).await.unwrap();

        let saved = SniService::list_rules(&pool).await.unwrap();
        let a_id = saved[0].id.unwrap();

        // Saving a rule as itself is fine, taking another rule's domain is not.
        SniService::update_rule(&pool, a_id, rule("a.example.com", "allow")).await.unwrap();
        assert!(SniService::update_rule(&pool, a_id, rule("b.example.com", "allow")).await.is_err());
        assert!(SniService::update_rule(&pool, 9999, rule("z.example.com", "block")).await.is_err());

        SniService::delete_rule(&pool, a_id).await.unwrap();
        assert!(SniService::delete_rule(&pool, a_id).await.is_err());
        assert_eq!(SniService::list_rules(&pool).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn comments_are_trimmed_and_checked() {
        let pool = memory_pool().await;

        let mut with_comment = rule("a.example.com", "block");
        with_comment.comment = Some("  kids devices  ".into());
        SniService::add_rule(&pool, with_comment).await.unwrap();

        let mut blank = rule("b.example.com", "block");
        blank.comment = Some("   ".into());
        SniService::add_rule(&pool, blank).await.unwrap();

        let mut bad = rule("c.example.com", "block");
        bad.comment = Some("line\nbreak".into());
        assert!(SniService::add_rule(&pool, bad).await.is_err());

        let saved = SniService::list_rules(&pool).await.unwrap();
        assert_eq!(saved.len(), 2);
        assert_eq!(saved[0].comment.as_deref(), Some("kids devices"));
        assert_eq!(saved[1].comment, None);
    }
}
