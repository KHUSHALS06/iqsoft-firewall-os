use sqlx::{Row, SqlitePool};

pub struct AppControlRepository;

impl AppControlRepository {
    /// Every app the person has made a choice for, as (app_id, action).
    /// Apps with no row are on "default" and do not appear here.
    pub async fn list_choices(pool: &SqlitePool) -> Result<Vec<(String, String)>, sqlx::Error> {
        let rows = sqlx::query("SELECT app_id, action FROM sni_apps ORDER BY app_id ASC")
            .fetch_all(pool)
            .await?;

        Ok(rows
            .iter()
            .map(|row| (row.get("app_id"), row.get("action")))
            .collect())
    }

    /// Saves "block" or "allow" for one app, replacing an earlier choice.
    pub async fn set_choice(
        pool: &SqlitePool,
        app_id: &str,
        action: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO sni_apps (app_id, action)
            VALUES (?, ?)
            ON CONFLICT(app_id) DO UPDATE SET action = excluded.action
            "#,
        )
        .bind(app_id)
        .bind(action)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Removes the choice, which puts the app back on "default".
    /// Returns how many rows were removed (0 when there was no choice).
    pub async fn clear_choice(pool: &SqlitePool, app_id: &str) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM sni_apps WHERE app_id = ?")
            .bind(app_id)
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

    #[tokio::test]
    async fn there_are_no_choices_at_first() {
        let pool = memory_pool().await;

        assert!(AppControlRepository::list_choices(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn choices_are_saved_and_listed_by_app() {
        let pool = memory_pool().await;

        AppControlRepository::set_choice(&pool, "youtube", "block").await.unwrap();
        AppControlRepository::set_choice(&pool, "gmail", "allow").await.unwrap();

        assert_eq!(
            AppControlRepository::list_choices(&pool).await.unwrap(),
            vec![
                ("gmail".to_string(), "allow".to_string()),
                ("youtube".to_string(), "block".to_string()),
            ]
        );
    }

    #[tokio::test]
    async fn saving_again_replaces_the_choice_instead_of_adding_a_row() {
        let pool = memory_pool().await;

        AppControlRepository::set_choice(&pool, "zoom", "block").await.unwrap();
        AppControlRepository::set_choice(&pool, "zoom", "allow").await.unwrap();

        assert_eq!(
            AppControlRepository::list_choices(&pool).await.unwrap(),
            vec![("zoom".to_string(), "allow".to_string())]
        );
    }

    #[tokio::test]
    async fn clearing_reports_how_many_rows_it_removed() {
        let pool = memory_pool().await;

        AppControlRepository::set_choice(&pool, "steam", "block").await.unwrap();

        assert_eq!(AppControlRepository::clear_choice(&pool, "steam").await.unwrap(), 1);
        assert_eq!(AppControlRepository::clear_choice(&pool, "steam").await.unwrap(), 0);
        assert!(AppControlRepository::list_choices(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_database_refuses_a_value_other_than_block_or_allow() {
        let pool = memory_pool().await;

        assert!(AppControlRepository::set_choice(&pool, "zoom", "default").await.is_err());
        assert!(AppControlRepository::set_choice(&pool, "Zoom", "block").await.is_err());
    }
}
