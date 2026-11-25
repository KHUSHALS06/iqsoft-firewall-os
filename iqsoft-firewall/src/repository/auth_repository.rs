use crate::{models::auth::User, repository::role_repository::RoleRepository};
use sqlx::{sqlite::SqliteRow, Row, SqlitePool};

/// The role name comes from the roles table, so a renamed role shows up at once.
const SELECT_USER: &str = r#"
    SELECT u.id, u.username, u.password_hash, u.role_id,
           COALESCE(r.name, u.role) AS role
    FROM users u
    LEFT JOIN roles r ON r.id = u.role_id
"#;

pub struct AuthRepository;

impl AuthRepository {
    pub async fn count_users(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
        let row = sqlx::query("SELECT COUNT(*) AS c FROM users")
            .fetch_one(pool)
            .await?;

        Ok(row.get::<i64, _>("c"))
    }

    pub async fn create_user(
        pool: &SqlitePool,
        username: &str,
        password_hash: &str,
        role: &str,
        created_at: i64,
    ) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO users (username, password_hash, role, role_id, created_at)
            VALUES (?, ?, ?, (SELECT id FROM roles WHERE name = ? COLLATE NOCASE), ?)
            "#,
        )
        .bind(username)
        .bind(password_hash)
        .bind(role)
        .bind(role)
        .bind(created_at)
        .execute(pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    /// Only accounts that are switched on can be found, so a disabled account can neither
    /// sign in nor keep a session.
    pub async fn find_by_username(
        pool: &SqlitePool,
        username: &str,
    ) -> Result<Option<User>, sqlx::Error> {
        let row = sqlx::query(&format!("{} WHERE u.username = ? AND u.enabled = 1", SELECT_USER))
            .bind(username)
            .fetch_optional(pool)
            .await?;

        Self::with_permissions(pool, row).await
    }

    pub async fn find_by_id(pool: &SqlitePool, id: i64) -> Result<Option<User>, sqlx::Error> {
        let row = sqlx::query(&format!("{} WHERE u.id = ? AND u.enabled = 1", SELECT_USER))
            .bind(id)
            .fetch_optional(pool)
            .await?;

        Self::with_permissions(pool, row).await
    }

    async fn with_permissions(
        pool: &SqlitePool,
        row: Option<SqliteRow>,
    ) -> Result<Option<User>, sqlx::Error> {
        let Some(r) = row else {
            return Ok(None);
        };

        let role_id: Option<i64> = r.get("role_id");
        let permissions = match role_id {
            Some(id) => RoleRepository::permissions_for(pool, id).await?,
            None => Vec::new(),
        };

        Ok(Some(User {
            id: r.get("id"),
            username: r.get("username"),
            password_hash: r.get("password_hash"),
            role: r.get("role"),
            permissions,
        }))
    }

    pub async fn update_password(
        pool: &SqlitePool,
        user_id: i64,
        password_hash: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(password_hash)
            .bind(user_id)
            .execute(pool)
            .await?;

        Ok(())
    }

    pub async fn create_session(
        pool: &SqlitePool,
        token_hash: &str,
        user_id: i64,
        created_at: i64,
        expires_at: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO sessions (token_hash, user_id, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(token_hash)
        .bind(user_id)
        .bind(created_at)
        .bind(expires_at)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn find_user_by_session(
        pool: &SqlitePool,
        token_hash: &str,
        now: i64,
    ) -> Result<Option<User>, sqlx::Error> {
        let row = sqlx::query(&format!(
            "{} JOIN sessions s ON s.user_id = u.id
             WHERE s.token_hash = ? AND s.expires_at > ? AND u.enabled = 1",
            SELECT_USER
        ))
        .bind(token_hash)
        .bind(now)
        .fetch_optional(pool)
        .await?;

        Self::with_permissions(pool, row).await
    }

    pub async fn delete_session(pool: &SqlitePool, token_hash: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
            .bind(token_hash)
            .execute(pool)
            .await?;

        Ok(())
    }

    pub async fn delete_user_sessions(
        pool: &SqlitePool,
        user_id: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(user_id)
            .execute(pool)
            .await?;

        Ok(())
    }

    pub async fn delete_expired_sessions(
        pool: &SqlitePool,
        now: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
            .bind(now)
            .execute(pool)
            .await?;

        Ok(())
    }
}
