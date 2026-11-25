use crate::models::role::Role;
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;

pub struct RoleRepository;

impl RoleRepository {
    pub async fn list(pool: &SqlitePool) -> Result<Vec<Role>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT r.id, r.name, r.description, r.is_system, r.created_at,
                   (SELECT COUNT(*) FROM users u WHERE u.role_id = r.id) AS user_count
            FROM roles r
            ORDER BY r.is_system DESC, r.id ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        let mut permissions: HashMap<i64, Vec<String>> = HashMap::new();
        for row in sqlx::query("SELECT role_id, permission FROM role_permissions ORDER BY permission")
            .fetch_all(pool)
            .await?
        {
            permissions
                .entry(row.get("role_id"))
                .or_default()
                .push(row.get("permission"));
        }

        Ok(rows
            .into_iter()
            .map(|r| {
                let id: i64 = r.get("id");
                Role {
                    id,
                    name: r.get("name"),
                    description: r.get("description"),
                    is_system: r.get::<i64, _>("is_system") != 0,
                    created_at: r.get("created_at"),
                    permissions: permissions.remove(&id).unwrap_or_default(),
                    user_count: r.get("user_count"),
                }
            })
            .collect())
    }

    pub async fn find(pool: &SqlitePool, id: i64) -> Result<Option<Role>, sqlx::Error> {
        Ok(Self::list(pool).await?.into_iter().find(|r| r.id == id))
    }

    pub async fn name_taken(
        pool: &SqlitePool,
        name: &str,
        except_id: Option<i64>,
    ) -> Result<bool, sqlx::Error> {
        let row = sqlx::query("SELECT COUNT(*) AS c FROM roles WHERE name = ? COLLATE NOCASE AND id != ?")
            .bind(name)
            .bind(except_id.unwrap_or(-1))
            .fetch_one(pool)
            .await?;

        Ok(row.get::<i64, _>("c") > 0)
    }

    pub async fn create(
        pool: &SqlitePool,
        name: &str,
        description: Option<&str>,
        permissions: &[String],
        created_at: i64,
    ) -> Result<i64, sqlx::Error> {
        let mut tx = pool.begin().await?;

        let id = sqlx::query(
            "INSERT INTO roles (name, description, is_system, created_at) VALUES (?, ?, 0, ?)",
        )
        .bind(name)
        .bind(description)
        .bind(created_at)
        .execute(&mut *tx)
        .await?
        .last_insert_rowid();

        for permission in permissions {
            sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES (?, ?)")
                .bind(id)
                .bind(permission)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(id)
    }

    /// Replaces the name, description and permissions in one step, and keeps the
    /// role name stored on each account in step.
    pub async fn update(
        pool: &SqlitePool,
        id: i64,
        name: &str,
        description: Option<&str>,
        permissions: &[String],
    ) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query("UPDATE roles SET name = ?, description = ? WHERE id = ?")
            .bind(name)
            .bind(description)
            .bind(id)
            .execute(&mut *tx)
            .await?;

        sqlx::query("DELETE FROM role_permissions WHERE role_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        for permission in permissions {
            sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES (?, ?)")
                .bind(id)
                .bind(permission)
                .execute(&mut *tx)
                .await?;
        }

        sqlx::query("UPDATE users SET role = ? WHERE role_id = ?")
            .bind(name)
            .bind(id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn delete(pool: &SqlitePool, id: i64) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query("DELETE FROM role_permissions WHERE role_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        sqlx::query("DELETE FROM roles WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn permissions_for(pool: &SqlitePool, role_id: i64) -> Result<Vec<String>, sqlx::Error> {
        let rows = sqlx::query("SELECT permission FROM role_permissions WHERE role_id = ? ORDER BY permission")
            .bind(role_id)
            .fetch_all(pool)
            .await?;

        Ok(rows.into_iter().map(|r| r.get("permission")).collect())
    }
}
