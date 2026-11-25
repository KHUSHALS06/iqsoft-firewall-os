use crate::models::role::UserAccount;
use sqlx::{sqlite::SqliteRow, Row, SqlitePool};

pub struct UserRepository;

const SELECT: &str = r#"
    SELECT u.id, u.username, u.role_id, u.enabled, u.created_at,
           COALESCE(r.name, u.role) AS role
    FROM users u
    LEFT JOIN roles r ON r.id = u.role_id
"#;

fn account(r: &SqliteRow) -> UserAccount {
    UserAccount {
        id: r.get("id"),
        username: r.get("username"),
        role_id: r.get("role_id"),
        role: r.get("role"),
        enabled: r.get::<i64, _>("enabled") != 0,
        created_at: r.get("created_at"),
    }
}

impl UserRepository {
    pub async fn list(pool: &SqlitePool) -> Result<Vec<UserAccount>, sqlx::Error> {
        let rows = sqlx::query(&format!("{} ORDER BY u.id ASC", SELECT))
            .fetch_all(pool)
            .await?;

        Ok(rows.iter().map(account).collect())
    }

    pub async fn find(pool: &SqlitePool, id: i64) -> Result<Option<UserAccount>, sqlx::Error> {
        let row = sqlx::query(&format!("{} WHERE u.id = ?", SELECT))
            .bind(id)
            .fetch_optional(pool)
            .await?;

        Ok(row.as_ref().map(account))
    }

    pub async fn username_taken(pool: &SqlitePool, username: &str) -> Result<bool, sqlx::Error> {
        let row = sqlx::query("SELECT COUNT(*) AS c FROM users WHERE username = ? COLLATE NOCASE")
            .bind(username)
            .fetch_one(pool)
            .await?;

        Ok(row.get::<i64, _>("c") > 0)
    }

    pub async fn create(
        pool: &SqlitePool,
        username: &str,
        password_hash: &str,
        role_id: i64,
        role_name: &str,
        enabled: bool,
        created_at: i64,
    ) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO users (username, password_hash, role, role_id, enabled, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(username)
        .bind(password_hash)
        .bind(role_name)
        .bind(role_id)
        .bind(if enabled { 1 } else { 0 })
        .bind(created_at)
        .execute(pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn update_access(
        pool: &SqlitePool,
        id: i64,
        role_id: i64,
        role_name: &str,
        enabled: bool,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET role_id = ?, role = ?, enabled = ? WHERE id = ?")
            .bind(role_id)
            .bind(role_name)
            .bind(if enabled { 1 } else { 0 })
            .bind(id)
            .execute(pool)
            .await?;

        Ok(())
    }

    /// Accounts that are switched on and hold the given role. Used to make sure the last
    /// Super Admin can never be removed, demoted or locked out.
    pub async fn count_enabled_with_role(pool: &SqlitePool, role_id: i64) -> Result<i64, sqlx::Error> {
        let row = sqlx::query("SELECT COUNT(*) AS c FROM users WHERE role_id = ? AND enabled = 1")
            .bind(role_id)
            .fetch_one(pool)
            .await?;

        Ok(row.get("c"))
    }

    pub async fn delete(pool: &SqlitePool, id: i64) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }
}
