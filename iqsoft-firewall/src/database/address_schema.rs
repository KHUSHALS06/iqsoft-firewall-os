use sqlx::SqlitePool;

/// Address objects, address groups and group membership.
///
/// Safe to run on every boot (CREATE TABLE IF NOT EXISTS).
///
/// Object and group names share one namespace, but SQLite cannot enforce
/// uniqueness across two tables, so the service layer checks that.
pub async fn create_address_tables(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS address_objects (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            name      TEXT NOT NULL UNIQUE COLLATE NOCASE,
            kind      TEXT NOT NULL CHECK (kind IN ('host', 'subnet', 'range')),
            value     TEXT NOT NULL,
            family    TEXT NOT NULL CHECK (family IN ('ipv4', 'ipv6')),
            comment   TEXT
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS address_groups (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            name      TEXT NOT NULL UNIQUE COLLATE NOCASE,
            comment   TEXT
        );
        "#,
    )
    .execute(pool)
    .await?;

    // Deleting a group removes its memberships.
    // Deleting an object that is still in a group is refused (RESTRICT).
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS address_group_members (
            group_id   INTEGER NOT NULL,
            object_id  INTEGER NOT NULL,
            PRIMARY KEY (group_id, object_id),
            FOREIGN KEY (group_id)  REFERENCES address_groups(id)  ON DELETE CASCADE,
            FOREIGN KEY (object_id) REFERENCES address_objects(id) ON DELETE RESTRICT
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_address_group_members_object ON address_group_members(object_id);",
    )
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn memory_pool() -> SqlitePool {
        // One connection, otherwise every connection would get its own empty in-memory database.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        create_address_tables(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn schema_can_be_created_twice() {
        let pool = memory_pool().await;
        create_address_tables(&pool).await.unwrap();
    }

    #[tokio::test]
    async fn names_are_unique_ignoring_case() {
        let pool = memory_pool().await;

        sqlx::query("INSERT INTO address_objects (name, kind, value, family) VALUES ('Office', 'host', '10.0.0.1', 'ipv4')")
            .execute(&pool)
            .await
            .unwrap();

        let dup = sqlx::query("INSERT INTO address_objects (name, kind, value, family) VALUES ('office', 'host', '10.0.0.2', 'ipv4')")
            .execute(&pool)
            .await;

        assert!(dup.is_err());
    }

    #[tokio::test]
    async fn bad_kind_or_family_is_rejected() {
        let pool = memory_pool().await;

        let bad_kind = sqlx::query("INSERT INTO address_objects (name, kind, value, family) VALUES ('a', 'fqdn', 'x', 'ipv4')")
            .execute(&pool)
            .await;
        assert!(bad_kind.is_err());

        let bad_family = sqlx::query("INSERT INTO address_objects (name, kind, value, family) VALUES ('b', 'host', '10.0.0.1', 'ipx')")
            .execute(&pool)
            .await;
        assert!(bad_family.is_err());
    }

    #[tokio::test]
    async fn object_in_a_group_cannot_be_deleted_but_group_can() {
        let pool = memory_pool().await;

        sqlx::query("INSERT INTO address_objects (id, name, kind, value, family) VALUES (1, 'web1', 'host', '10.0.0.1', 'ipv4')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO address_groups (id, name) VALUES (1, 'servers')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO address_group_members (group_id, object_id) VALUES (1, 1)")
            .execute(&pool)
            .await
            .unwrap();

        // RESTRICT: the object is still used by a group
        let blocked = sqlx::query("DELETE FROM address_objects WHERE id = 1")
            .execute(&pool)
            .await;
        assert!(blocked.is_err());

        // CASCADE: deleting the group removes the membership ...
        sqlx::query("DELETE FROM address_groups WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();

        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM address_group_members")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 0);

        // ... after which the object can be deleted
        sqlx::query("DELETE FROM address_objects WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();
    }
}
