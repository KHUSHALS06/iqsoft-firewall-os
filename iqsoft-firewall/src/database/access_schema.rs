use crate::services::{
    auth_service::AuthService,
    permissions::{all_permissions, ROLE_ADMIN, ROLE_SUPER_ADMIN},
};
use sqlx::{Row, SqlitePool};

/// Roles, their permissions, and the extra columns on `users`.
///
/// Safe to run on every start. It also upgrades a database made before roles existed:
/// the accounts it already has are put into the built-in roles, and the first account
/// becomes the Super Admin so that somebody can manage everyone else.
pub async fn create_access_tables(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS roles (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL UNIQUE COLLATE NOCASE,
            description  TEXT,
            is_system    INTEGER NOT NULL DEFAULT 0 CHECK (is_system IN (0, 1)),
            created_at   INTEGER NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS role_permissions (
            role_id     INTEGER NOT NULL,
            permission  TEXT NOT NULL,
            PRIMARY KEY (role_id, permission),
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
        );
        "#,
    )
    .execute(pool)
    .await?;

    let columns: Vec<String> = sqlx::query("PRAGMA table_info(users);")
        .fetch_all(pool)
        .await?
        .iter()
        .map(|r| r.get::<String, _>("name"))
        .collect();

    if !columns.iter().any(|c| c == "role_id") {
        sqlx::query("ALTER TABLE users ADD COLUMN role_id INTEGER REFERENCES roles(id);")
            .execute(pool)
            .await?;
    }

    if !columns.iter().any(|c| c == "enabled") {
        sqlx::query("ALTER TABLE users ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1;")
            .execute(pool)
            .await?;
    }

    let now = AuthService::now();

    let (super_id, super_is_new) = ensure_role(
        pool,
        ROLE_SUPER_ADMIN,
        "Full access to everything, including users and roles. Cannot be changed.",
        now,
    )
    .await?;

    let (admin_id, admin_is_new) = ensure_role(
        pool,
        ROLE_ADMIN,
        "Full access by default. A Super Admin can narrow it down.",
        now,
    )
    .await?;

    // The Super Admin always holds every permission, including ones added in later versions.
    for permission in all_permissions() {
        sqlx::query("INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES (?, ?)")
            .bind(super_id)
            .bind(&permission)
            .execute(pool)
            .await?;
    }

    // The Admin role gets everything only when it is first created, so that later edits by
    // a Super Admin are not undone at the next start.
    if admin_is_new {
        for permission in all_permissions() {
            sqlx::query(
                "INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES (?, ?)",
            )
            .bind(admin_id)
            .bind(&permission)
            .execute(pool)
            .await?;
        }
    }

    // Accounts from before roles existed: keep their role if it names a known one, else Admin.
    sqlx::query(
        "UPDATE users SET role_id = (SELECT id FROM roles WHERE name = users.role COLLATE NOCASE)
         WHERE role_id IS NULL",
    )
    .execute(pool)
    .await?;

    sqlx::query("UPDATE users SET role_id = ? WHERE role_id IS NULL")
        .bind(admin_id)
        .execute(pool)
        .await?;

    // Only when the Super Admin role has just been created: make the oldest account one.
    if super_is_new {
        sqlx::query("UPDATE users SET role_id = ? WHERE id = (SELECT MIN(id) FROM users)")
            .bind(super_id)
            .execute(pool)
            .await?;
    }

    // `users.role` is the role's name, kept in step for backups and older readers.
    sqlx::query(
        "UPDATE users SET role = (SELECT name FROM roles WHERE roles.id = users.role_id)
         WHERE role_id IS NOT NULL",
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Returns the role's id and whether this call created it.
async fn ensure_role(
    pool: &SqlitePool,
    name: &str,
    description: &str,
    now: i64,
) -> Result<(i64, bool), sqlx::Error> {
    let inserted = sqlx::query(
        "INSERT OR IGNORE INTO roles (name, description, is_system, created_at)
         VALUES (?, ?, 1, ?)",
    )
    .bind(name)
    .bind(description)
    .bind(now)
    .execute(pool)
    .await?
    .rows_affected()
        == 1;

    let id: i64 = sqlx::query("SELECT id FROM roles WHERE name = ? COLLATE NOCASE")
        .bind(name)
        .fetch_one(pool)
        .await?
        .get("id");

    sqlx::query("UPDATE roles SET is_system = 1 WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok((id, inserted))
}
