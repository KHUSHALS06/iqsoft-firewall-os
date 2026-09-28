use crate::models::address::{AddressGroup, AddressObject};
use sqlx::{sqlite::SqliteRow, Row, Sqlite, SqlitePool, Transaction};
use std::collections::HashMap;

/// A firewall rule refers to an object or group by writing `@name` in its
/// src_ip or dst_ip field.
pub const REF_PREFIX: char = '@';

pub fn reference(name: &str) -> String {
    format!("{}{}", REF_PREFIX, name)
}

pub struct AddressRepository;

impl AddressRepository {
    // ------------------------------------------------------------------
    // Objects
    // ------------------------------------------------------------------

    fn row_to_object(row: &SqliteRow) -> AddressObject {
        AddressObject {
            id: Some(row.get("id")),
            name: row.get("name"),
            kind: row.get("kind"),
            value: row.get("value"),
            family: row.get("family"),
            comment: row.get("comment"),
        }
    }

    /// The caller must already have validated the object and filled in `family`.
    pub async fn add_object(
        pool: &SqlitePool,
        object: &AddressObject,
    ) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO address_objects (name, kind, value, family, comment)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(&object.name)
        .bind(&object.kind)
        .bind(&object.value)
        .bind(&object.family)
        .bind(&object.comment)
        .execute(pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn list_objects(pool: &SqlitePool) -> Result<Vec<AddressObject>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, kind, value, family, comment
            FROM address_objects
            ORDER BY name COLLATE NOCASE
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_object).collect())
    }

    pub async fn get_object(
        pool: &SqlitePool,
        id: i64,
    ) -> Result<Option<AddressObject>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, name, kind, value, family, comment FROM address_objects WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(row.as_ref().map(Self::row_to_object))
    }

    /// Case-insensitive.
    pub async fn find_object_by_name(
        pool: &SqlitePool,
        name: &str,
    ) -> Result<Option<AddressObject>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, name, kind, value, family, comment FROM address_objects WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(pool)
        .await?;

        Ok(row.as_ref().map(Self::row_to_object))
    }

    /// Returns false when no object with that id exists.
    pub async fn update_object(
        pool: &SqlitePool,
        id: i64,
        object: &AddressObject,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE address_objects
            SET name = ?, kind = ?, value = ?, family = ?, comment = ?
            WHERE id = ?
            "#,
        )
        .bind(&object.name)
        .bind(&object.kind)
        .bind(&object.value)
        .bind(&object.family)
        .bind(&object.comment)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Returns false when no object with that id exists.
    /// Fails if the object is still a member of a group (foreign key RESTRICT),
    /// so the service should check `groups_using_object` first for a friendly message.
    pub async fn delete_object(pool: &SqlitePool, id: i64) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM address_objects WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    // ------------------------------------------------------------------
    // Groups
    // ------------------------------------------------------------------

    /// Members are given by object name. Every name must exist, otherwise the
    /// whole operation is rolled back.
    async fn insert_members(
        tx: &mut Transaction<'_, Sqlite>,
        group_id: i64,
        members: &[String],
    ) -> Result<(), sqlx::Error> {
        for name in members {
            let result = sqlx::query(
                r#"
                INSERT INTO address_group_members (group_id, object_id)
                SELECT ?, id FROM address_objects WHERE name = ?
                "#,
            )
            .bind(group_id)
            .bind(name)
            .execute(&mut **tx)
            .await?;

            if result.rows_affected() != 1 {
                return Err(sqlx::Error::Protocol(format!(
                    "unknown address object '{}'",
                    name
                )));
            }
        }

        Ok(())
    }

    pub async fn add_group(
        pool: &SqlitePool,
        group: &AddressGroup,
    ) -> Result<i64, sqlx::Error> {
        let mut tx = pool.begin().await?;

        let result = sqlx::query("INSERT INTO address_groups (name, comment) VALUES (?, ?)")
            .bind(&group.name)
            .bind(&group.comment)
            .execute(&mut *tx)
            .await?;

        let id = result.last_insert_rowid();

        Self::insert_members(&mut tx, id, &group.members).await?;

        tx.commit().await?;

        Ok(id)
    }

    /// Replaces the name, comment and the complete member list.
    /// Returns false when no group with that id exists.
    pub async fn update_group(
        pool: &SqlitePool,
        id: i64,
        group: &AddressGroup,
    ) -> Result<bool, sqlx::Error> {
        let mut tx = pool.begin().await?;

        let result = sqlx::query("UPDATE address_groups SET name = ?, comment = ? WHERE id = ?")
            .bind(&group.name)
            .bind(&group.comment)
            .bind(id)
            .execute(&mut *tx)
            .await?;

        if result.rows_affected() == 0 {
            return Ok(false);
        }

        sqlx::query("DELETE FROM address_group_members WHERE group_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        Self::insert_members(&mut tx, id, &group.members).await?;

        tx.commit().await?;

        Ok(true)
    }

    /// Memberships are removed automatically. Returns false when no such group exists.
    pub async fn delete_group(pool: &SqlitePool, id: i64) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM address_groups WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Groups with their member names. `family` comes from the members and is
    /// an empty string for a group with no members.
    pub async fn list_groups(pool: &SqlitePool) -> Result<Vec<AddressGroup>, sqlx::Error> {
        let group_rows = sqlx::query(
            "SELECT id, name, comment FROM address_groups ORDER BY name COLLATE NOCASE",
        )
        .fetch_all(pool)
        .await?;

        let member_rows = sqlx::query(
            r#"
            SELECT m.group_id AS group_id, o.name AS name, o.family AS family
            FROM address_group_members m
            JOIN address_objects o ON o.id = m.object_id
            ORDER BY o.name COLLATE NOCASE
            "#,
        )
        .fetch_all(pool)
        .await?;

        let mut members: HashMap<i64, Vec<(String, String)>> = HashMap::new();

        for row in member_rows {
            members
                .entry(row.get("group_id"))
                .or_default()
                .push((row.get("name"), row.get("family")));
        }

        let mut groups = Vec::new();

        for row in group_rows {
            let id: i64 = row.get("id");
            let list = members.remove(&id).unwrap_or_default();

            groups.push(AddressGroup {
                id: Some(id),
                name: row.get("name"),
                family: list.first().map(|(_, f)| f.clone()).unwrap_or_default(),
                comment: row.get("comment"),
                members: list.into_iter().map(|(name, _)| name).collect(),
            });
        }

        Ok(groups)
    }

    pub async fn get_group(
        pool: &SqlitePool,
        id: i64,
    ) -> Result<Option<AddressGroup>, sqlx::Error> {
        Ok(Self::list_groups(pool)
            .await?
            .into_iter()
            .find(|g| g.id == Some(id)))
    }

    /// Case-insensitive.
    pub async fn find_group_by_name(
        pool: &SqlitePool,
        name: &str,
    ) -> Result<Option<AddressGroup>, sqlx::Error> {
        Ok(Self::list_groups(pool)
            .await?
            .into_iter()
            .find(|g| g.name.eq_ignore_ascii_case(name)))
    }

    // ------------------------------------------------------------------
    // Names and usage
    // ------------------------------------------------------------------

    /// Objects and groups share one namespace. Case-insensitive.
    pub async fn name_in_use(pool: &SqlitePool, name: &str) -> Result<bool, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT 1 FROM address_objects WHERE name = ?
            UNION ALL
            SELECT 1 FROM address_groups WHERE name = ?
            LIMIT 1
            "#,
        )
        .bind(name)
        .bind(name)
        .fetch_optional(pool)
        .await?;

        Ok(row.is_some())
    }

    /// Names of the groups that contain this object.
    pub async fn groups_using_object(
        pool: &SqlitePool,
        object_id: i64,
    ) -> Result<Vec<String>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT g.name AS name
            FROM address_group_members m
            JOIN address_groups g ON g.id = m.group_id
            WHERE m.object_id = ?
            ORDER BY g.name COLLATE NOCASE
            "#,
        )
        .bind(object_id)
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(|r| r.get("name")).collect())
    }

    /// (id, name) of every firewall rule that refers to `@name` as its
    /// source or destination, whether enabled or not.
    pub async fn rules_using(
        pool: &SqlitePool,
        name: &str,
    ) -> Result<Vec<(i64, String)>, sqlx::Error> {
        let wanted = reference(name);

        let rows = sqlx::query(
            r#"
            SELECT id, name
            FROM firewall_rules
            WHERE trim(src_ip) = ? COLLATE NOCASE
               OR trim(dst_ip) = ? COLLATE NOCASE
            ORDER BY id
            "#,
        )
        .bind(&wanted)
        .bind(&wanted)
        .fetch_all(pool)
        .await?;

        Ok(rows
            .iter()
            .map(|r| (r.get("id"), r.get("name")))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::init::initialize_database;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn memory_pool() -> SqlitePool {
        // One connection, otherwise every connection would get its own empty in-memory database.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        initialize_database(&pool).await.unwrap();
        pool
    }

    fn object(name: &str, kind: &str, value: &str, family: &str) -> AddressObject {
        AddressObject {
            id: None,
            name: name.into(),
            kind: kind.into(),
            value: value.into(),
            family: family.into(),
            comment: None,
        }
    }

    fn group(name: &str, members: &[&str]) -> AddressGroup {
        AddressGroup {
            id: None,
            name: name.into(),
            family: String::new(),
            comment: None,
            members: members.iter().map(|m| m.to_string()).collect(),
        }
    }

    async fn insert_rule(pool: &SqlitePool, name: &str, src: Option<&str>, dst: Option<&str>) {
        sqlx::query(
            r#"
            INSERT INTO firewall_rules (name, chain_name, action, protocol, src_ip, dst_ip)
            VALUES (?, 'FORWARD', 'accept', 'any', ?, ?)
            "#,
        )
        .bind(name)
        .bind(src)
        .bind(dst)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn object_crud() {
        let pool = memory_pool().await;

        let id = AddressRepository::add_object(&pool, &object("web1", "host", "10.0.0.1", "ipv4"))
            .await
            .unwrap();

        let got = AddressRepository::get_object(&pool, id).await.unwrap().unwrap();
        assert_eq!(got.name, "web1");
        assert_eq!(got.value, "10.0.0.1");
        assert_eq!(got.family, "ipv4");

        // case-insensitive lookup
        assert!(AddressRepository::find_object_by_name(&pool, "WEB1")
            .await
            .unwrap()
            .is_some());

        let changed = AddressRepository::update_object(
            &pool,
            id,
            &object("web1", "subnet", "10.0.1.0/24", "ipv4"),
        )
        .await
        .unwrap();
        assert!(changed);

        let got = AddressRepository::get_object(&pool, id).await.unwrap().unwrap();
        assert_eq!(got.kind, "subnet");
        assert_eq!(got.value, "10.0.1.0/24");

        assert!(!AddressRepository::update_object(&pool, 9999, &object("x", "host", "10.0.0.9", "ipv4"))
            .await
            .unwrap());

        assert!(AddressRepository::delete_object(&pool, id).await.unwrap());
        assert!(!AddressRepository::delete_object(&pool, id).await.unwrap());
        assert!(AddressRepository::list_objects(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn duplicate_object_name_is_rejected() {
        let pool = memory_pool().await;

        AddressRepository::add_object(&pool, &object("Web", "host", "10.0.0.1", "ipv4"))
            .await
            .unwrap();

        let dup =
            AddressRepository::add_object(&pool, &object("web", "host", "10.0.0.2", "ipv4")).await;

        assert!(dup.is_err());
    }

    #[tokio::test]
    async fn group_with_members_round_trip() {
        let pool = memory_pool().await;

        AddressRepository::add_object(&pool, &object("web1", "host", "10.0.0.1", "ipv4")).await.unwrap();
        AddressRepository::add_object(&pool, &object("web2", "host", "10.0.0.2", "ipv4")).await.unwrap();
        AddressRepository::add_object(&pool, &object("db1", "host", "10.0.0.3", "ipv4")).await.unwrap();

        let gid = AddressRepository::add_group(&pool, &group("servers", &["web2", "web1"]))
            .await
            .unwrap();

        let got = AddressRepository::get_group(&pool, gid).await.unwrap().unwrap();
        assert_eq!(got.name, "servers");
        assert_eq!(got.family, "ipv4");
        // members come back sorted by name
        assert_eq!(got.members, vec!["web1".to_string(), "web2".to_string()]);

        // update replaces the member list completely
        let mut updated = group("servers", &["db1"]);
        updated.comment = Some("now just the database".into());
        assert!(AddressRepository::update_group(&pool, gid, &updated).await.unwrap());

        let got = AddressRepository::get_group(&pool, gid).await.unwrap().unwrap();
        assert_eq!(got.members, vec!["db1".to_string()]);
        assert_eq!(got.comment.as_deref(), Some("now just the database"));

        // unknown group id
        assert!(!AddressRepository::update_group(&pool, 9999, &updated).await.unwrap());

        // deleting the group keeps the objects
        assert!(AddressRepository::delete_group(&pool, gid).await.unwrap());
        assert_eq!(AddressRepository::list_objects(&pool).await.unwrap().len(), 3);
        assert!(AddressRepository::list_groups(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn empty_group_has_no_family() {
        let pool = memory_pool().await;

        AddressRepository::add_group(&pool, &group("empty", &[])).await.unwrap();

        let groups = AddressRepository::list_groups(&pool).await.unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].family, "");
        assert!(groups[0].members.is_empty());
    }

    #[tokio::test]
    async fn unknown_member_rolls_everything_back() {
        let pool = memory_pool().await;

        AddressRepository::add_object(&pool, &object("web1", "host", "10.0.0.1", "ipv4")).await.unwrap();

        let result =
            AddressRepository::add_group(&pool, &group("servers", &["web1", "does_not_exist"])).await;

        assert!(result.is_err());

        // the group must not have been left behind half-created
        assert!(AddressRepository::list_groups(&pool).await.unwrap().is_empty());
        assert!(!AddressRepository::name_in_use(&pool, "servers").await.unwrap());
    }

    #[tokio::test]
    async fn failed_update_keeps_the_old_members() {
        let pool = memory_pool().await;

        AddressRepository::add_object(&pool, &object("web1", "host", "10.0.0.1", "ipv4")).await.unwrap();

        let gid = AddressRepository::add_group(&pool, &group("servers", &["web1"]))
            .await
            .unwrap();

        let result =
            AddressRepository::update_group(&pool, gid, &group("servers", &["nope"])).await;
        assert!(result.is_err());

        let got = AddressRepository::get_group(&pool, gid).await.unwrap().unwrap();
        assert_eq!(got.members, vec!["web1".to_string()]);
    }

    #[tokio::test]
    async fn duplicate_member_in_one_group_is_rejected() {
        let pool = memory_pool().await;

        AddressRepository::add_object(&pool, &object("web1", "host", "10.0.0.1", "ipv4")).await.unwrap();

        let result =
            AddressRepository::add_group(&pool, &group("servers", &["web1", "web1"])).await;

        assert!(result.is_err());
        assert!(AddressRepository::list_groups(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn name_in_use_covers_objects_and_groups() {
        let pool = memory_pool().await;

        assert!(!AddressRepository::name_in_use(&pool, "thing").await.unwrap());

        AddressRepository::add_object(&pool, &object("thing", "host", "10.0.0.1", "ipv4")).await.unwrap();
        assert!(AddressRepository::name_in_use(&pool, "THING").await.unwrap());

        AddressRepository::add_group(&pool, &group("team", &[])).await.unwrap();
        assert!(AddressRepository::name_in_use(&pool, "Team").await.unwrap());
    }

    #[tokio::test]
    async fn object_in_group_cannot_be_deleted() {
        let pool = memory_pool().await;

        let oid = AddressRepository::add_object(&pool, &object("web1", "host", "10.0.0.1", "ipv4"))
            .await
            .unwrap();
        AddressRepository::add_group(&pool, &group("servers", &["web1"])).await.unwrap();
        AddressRepository::add_group(&pool, &group("all_web", &["web1"])).await.unwrap();

        assert_eq!(
            AddressRepository::groups_using_object(&pool, oid).await.unwrap(),
            vec!["all_web".to_string(), "servers".to_string()]
        );

        assert!(AddressRepository::delete_object(&pool, oid).await.is_err());
    }

    #[tokio::test]
    async fn rules_using_finds_source_and_destination_references() {
        let pool = memory_pool().await;

        insert_rule(&pool, "from web", Some("@web"), None).await;
        insert_rule(&pool, "to web", None, Some(" @WEB ")).await;
        insert_rule(&pool, "unrelated", Some("@other"), Some("10.0.0.0/24")).await;
        insert_rule(&pool, "literal", Some("10.0.0.1"), None).await;

        let used = AddressRepository::rules_using(&pool, "web").await.unwrap();
        let names: Vec<&str> = used.iter().map(|(_, n)| n.as_str()).collect();

        assert_eq!(names, vec!["from web", "to web"]);

        assert!(AddressRepository::rules_using(&pool, "nothing").await.unwrap().is_empty());
    }

    #[test]
    fn reference_format() {
        assert_eq!(reference("web"), "@web");
    }
}
