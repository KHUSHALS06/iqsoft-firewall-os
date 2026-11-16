use crate::{
    models::{
        appcontrol::{find_app, normalize_app_action, AppEntry, CATALOG},
        sni::SniRule,
    },
    repository::appcontrol_repository::AppControlRepository,
};
use sqlx::SqlitePool;
use std::collections::HashMap;

pub struct AppControlService;

impl AppControlService {
    /// The whole catalog with the person's current choice next to each app.
    /// An app with no saved choice shows "default".
    pub async fn list_apps(pool: &SqlitePool) -> Result<Vec<AppEntry>, String> {
        let choices: HashMap<String, String> = AppControlRepository::list_choices(pool)
            .await
            .map_err(|e| e.to_string())?
            .into_iter()
            .collect();

        Ok(CATALOG
            .iter()
            .map(|app| {
                let action = choices.get(app.id).map(|a| a.as_str()).unwrap_or("default");
                AppEntry::from_definition(app, action)
            })
            .collect())
    }

    /// Sets one app to "block", "allow" or "default" and returns the app as
    /// it now looks. "default" removes the saved choice.
    pub async fn set_app_action(
        pool: &SqlitePool,
        app_id: &str,
        action: &str,
    ) -> Result<AppEntry, String> {
        let app = find_app(app_id).ok_or_else(|| format!("Unknown app '{}'", app_id.trim()))?;

        let action = normalize_app_action(action)
            .ok_or("Action must be 'block', 'allow' or 'default'")?;

        if action == "default" {
            AppControlRepository::clear_choice(pool, app.id)
                .await
                .map_err(|e| e.to_string())?;
        } else {
            AppControlRepository::set_choice(pool, app.id, action)
                .await
                .map_err(|e| e.to_string())?;
        }

        Ok(AppEntry::from_definition(app, action))
    }

    /// The saved choices turned into plain SNI rules (one per domain), ready
    /// for the policy matcher.
    pub async fn rules(pool: &SqlitePool) -> Result<Vec<SniRule>, String> {
        let choices = AppControlRepository::list_choices(pool)
            .await
            .map_err(|e| e.to_string())?;

        Ok(Self::expand_choices(&choices))
    }

    /// Pure helper, no database. An app that is no longer in the catalog, or
    /// a stored value that is not block/allow, is skipped, so an old row can
    /// never break the policy.
    pub fn expand_choices(choices: &[(String, String)]) -> Vec<SniRule> {
        let mut rules = Vec::new();

        for (app_id, action) in choices {
            let Some(app) = find_app(app_id) else {
                continue;
            };

            let action = match normalize_app_action(action) {
                Some("block") => "block",
                Some("allow") => "allow",
                _ => continue,
            };

            for domain in app.domains {
                rules.push(SniRule {
                    id: None,
                    domain: domain.to_string(),
                    action: action.to_string(),
                    comment: Some(format!("app: {}", app.name)),
                });
            }
        }

        rules
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

    fn action_of(apps: &[AppEntry], id: &str) -> String {
        apps.iter().find(|a| a.id == id).unwrap().action.clone()
    }

    #[tokio::test]
    async fn every_app_starts_on_default() {
        let pool = memory_pool().await;
        let apps = AppControlService::list_apps(&pool).await.unwrap();

        assert_eq!(apps.len(), CATALOG.len());
        assert!(apps.iter().all(|a| a.action == "default"));
        assert!(AppControlService::rules(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_app_can_be_blocked_allowed_and_put_back_on_default() {
        let pool = memory_pool().await;

        let saved = AppControlService::set_app_action(&pool, " YouTube ", " BLOCK ").await.unwrap();
        assert_eq!(saved.id, "youtube");
        assert_eq!(saved.action, "block");
        assert_eq!(action_of(&AppControlService::list_apps(&pool).await.unwrap(), "youtube"), "block");

        AppControlService::set_app_action(&pool, "youtube", "allow").await.unwrap();
        assert_eq!(action_of(&AppControlService::list_apps(&pool).await.unwrap(), "youtube"), "allow");

        let back = AppControlService::set_app_action(&pool, "youtube", "default").await.unwrap();
        assert_eq!(back.action, "default");
        assert_eq!(action_of(&AppControlService::list_apps(&pool).await.unwrap(), "youtube"), "default");

        // Putting an app on default twice is fine.
        AppControlService::set_app_action(&pool, "youtube", "default").await.unwrap();
    }

    #[tokio::test]
    async fn unknown_apps_and_bad_actions_are_refused_and_change_nothing() {
        let pool = memory_pool().await;

        assert!(AppControlService::set_app_action(&pool, "myspace", "block").await.is_err());
        assert!(AppControlService::set_app_action(&pool, "", "block").await.is_err());
        assert!(AppControlService::set_app_action(&pool, "zoom", "deny").await.is_err());
        assert!(AppControlService::set_app_action(&pool, "zoom", "").await.is_err());

        let apps = AppControlService::list_apps(&pool).await.unwrap();
        assert!(apps.iter().all(|a| a.action == "default"));
    }

    #[tokio::test]
    async fn choices_become_one_rule_per_domain() {
        let pool = memory_pool().await;

        AppControlService::set_app_action(&pool, "whatsapp", "block").await.unwrap();
        AppControlService::set_app_action(&pool, "gmail", "allow").await.unwrap();

        let rules = AppControlService::rules(&pool).await.unwrap();

        let whatsapp = find_app("whatsapp").unwrap();
        let gmail = find_app("gmail").unwrap();
        assert_eq!(rules.len(), whatsapp.domains.len() + gmail.domains.len());

        let wa = rules.iter().find(|r| r.domain == "whatsapp.com").unwrap();
        assert_eq!(wa.action, "block");
        assert_eq!(wa.comment.as_deref(), Some("app: WhatsApp"));

        let gm = rules.iter().find(|r| r.domain == "gmail.com").unwrap();
        assert_eq!(gm.action, "allow");
    }

    #[test]
    fn old_or_broken_rows_are_skipped_when_building_rules() {
        let choices = vec![
            ("myspace".to_string(), "block".to_string()),
            ("zoom".to_string(), "sideways".to_string()),
            ("zoom".to_string(), "default".to_string()),
            ("telegram".to_string(), "block".to_string()),
        ];

        let rules = AppControlService::expand_choices(&choices);

        assert_eq!(rules.len(), find_app("telegram").unwrap().domains.len());
        assert!(rules.iter().all(|r| r.action == "block"));
        assert!(rules.iter().any(|r| r.domain == "t.me"));
    }
}
