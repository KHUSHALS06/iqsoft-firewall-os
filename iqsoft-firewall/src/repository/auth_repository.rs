use crate::models::auth::User;
use sqlx::{Row, SqlitePool};

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
            INSERT INTO users (username, password_hash, role, created_at)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(username)
        .bind(password_hash)
        .bind(role)
        .bind(created_at)
        .execute(pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn find_by_username(
        pool: &SqlitePool,
        username: &str,
    ) -> Result<Option<User>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| User {
            id: r.get("id"),
            username: r.get("username"),
            password_hash: r.get("password_hash"),
            role: r.get("role"),
        }))
    }

    pub async fn find_by_id(pool: &SqlitePool, id: i64) -> Result<Option<User>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, username, password_hash, role FROM users WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| User {
            id: r.get("id"),
            username: r.get("username"),
            password_hash: r.get("password_hash"),
            role: r.get("role"),
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
        let row = sqlx::query(
            r#"
            SELECT u.id, u.username, u.password_hash, u.role
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ? AND s.expires_at > ?
            "#,
        )
        .bind(token_hash)
        .bind(now)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| User {
            id: r.get("id"),
            username: r.get("username"),
            password_hash: r.get("password_hash"),
            role: r.get("role"),
        }))
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
