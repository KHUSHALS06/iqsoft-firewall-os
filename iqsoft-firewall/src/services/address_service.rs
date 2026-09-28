use crate::{
    models::address::{parse_value, validate_name, AddressGroup, AddressObject, Family},
    repository::address_repository::{AddressRepository, REF_PREFIX},
};
use sqlx::SqlitePool;

const MAX_COMMENT_LEN: usize = 200;

pub struct AddressService;

fn db_err(e: sqlx::Error) -> String {
    e.to_string()
}

/// "'rule a' (id 3), 'rule b' (id 7) and 2 more"
fn describe_rules(rules: &[(i64, String)]) -> String {
    let shown: Vec<String> = rules
        .iter()
        .take(5)
        .map(|(id, name)| format!("'{}' (id {})", name, id))
        .collect();

    let mut text = shown.join(", ");

    if rules.len() > 5 {
        text.push_str(&format!(" and {} more", rules.len() - 5));
    }

    text
}

impl AddressService {
    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn clean_comment(comment: &Option<String>) -> Result<Option<String>, String> {
        let Some(text) = comment else {
            return Ok(None);
        };

        let text = text.trim();

        if text.is_empty() {
            return Ok(None);
        }

        if text.chars().any(|c| c.is_control()) {
            return Err("Comment cannot contain control characters or line breaks".into());
        }

        if text.chars().count() > MAX_COMMENT_LEN {
            return Err(format!(
                "Comment cannot be longer than {} characters",
                MAX_COMMENT_LEN
            ));
        }

        Ok(Some(text.to_string()))
    }

    /// Validates an object from the client and returns the normalized version
    /// (trimmed name, lower-case kind, normalized value, computed family).
    fn prepare_object(object: &AddressObject) -> Result<AddressObject, String> {
        let name = object.name.trim();
        validate_name(name)?;

        let kind = object.kind.trim().to_ascii_lowercase();
        let (family, value) = parse_value(&kind, &object.value)?;

        Ok(AddressObject {
            id: object.id,
            name: name.to_string(),
            kind,
            value,
            family: family.as_str().to_string(),
            comment: Self::clean_comment(&object.comment)?,
        })
    }

    /// Validates a group from the client. Members are looked up, given their
    /// stored spelling, de-duplicated, and must all share one IP version.
    async fn prepare_group(
        pool: &SqlitePool,
        group: &AddressGroup,
    ) -> Result<AddressGroup, String> {
        let name = group.name.trim();
        validate_name(name)?;

        let comment = Self::clean_comment(&group.comment)?;

        let mut members: Vec<String> = Vec::new();
        let mut family: Option<Family> = None;

        for raw in &group.members {
            let wanted = raw.trim();

            let object = AddressRepository::find_object_by_name(pool, wanted)
                .await
                .map_err(db_err)?
                .ok_or_else(|| format!("Unknown address object '{}'", wanted))?;

            if members.iter().any(|m| m.eq_ignore_ascii_case(&object.name)) {
                continue;
            }

            let object_family = Family::from_db(&object.family)
                .ok_or_else(|| format!("Address object '{}' has an invalid IP version", object.name))?;

            match family {
                None => family = Some(object_family),
                Some(existing) if existing != object_family => {
                    return Err(format!(
                        "All members of a group must be the same IP version: '{}' is {} but the other members are {}",
                        object.name,
                        object_family.as_str(),
                        existing.as_str()
                    ));
                }
                Some(_) => {}
            }

            members.push(object.name);
        }

        Ok(AddressGroup {
            id: group.id,
            name: name.to_string(),
            family: family.map(|f| f.as_str().to_string()).unwrap_or_default(),
            comment,
            members,
        })
    }

    async fn ensure_name_free(pool: &SqlitePool, name: &str) -> Result<(), String> {
        if AddressRepository::name_in_use(pool, name)
            .await
            .map_err(db_err)?
        {
            return Err(format!(
                "The name '{}' is already used by another address object or group",
                name
            ));
        }

        Ok(())
    }

    /// Refuses when any firewall rule still refers to `@name`.
    async fn ensure_not_used_by_rules(
        pool: &SqlitePool,
        name: &str,
        action: &str,
    ) -> Result<(), String> {
        let rules = AddressRepository::rules_using(pool, name)
            .await
            .map_err(db_err)?;

        if rules.is_empty() {
            return Ok(());
        }

        Err(format!(
            "Cannot {} '{}': it is used by firewall rule(s) {}",
            action,
            name,
            describe_rules(&rules)
        ))
    }

    // ------------------------------------------------------------------
    // Objects
    // ------------------------------------------------------------------

    pub async fn list_objects(pool: &SqlitePool) -> Result<Vec<AddressObject>, String> {
        AddressRepository::list_objects(pool).await.map_err(db_err)
    }

    pub async fn add_object(pool: &SqlitePool, object: AddressObject) -> Result<i64, String> {
        let object = Self::prepare_object(&object)?;

        Self::ensure_name_free(pool, &object.name).await?;

        AddressRepository::add_object(pool, &object)
            .await
            .map_err(db_err)
    }

    pub async fn update_object(
        pool: &SqlitePool,
        id: i64,
        object: AddressObject,
    ) -> Result<(), String> {
        let existing = AddressRepository::get_object(pool, id)
            .await
            .map_err(db_err)?
            .ok_or("Address object not found")?;

        let updated = Self::prepare_object(&object)?;

        // A change of capitalization only is not a rename: rules match names
        // case-insensitively.
        let renamed = !existing.name.eq_ignore_ascii_case(&updated.name);
        let family_changed = existing.family != updated.family;

        if renamed {
            Self::ensure_name_free(pool, &updated.name).await?;
            Self::ensure_not_used_by_rules(pool, &existing.name, "rename").await?;
        }

        if family_changed {
            Self::ensure_not_used_by_rules(pool, &existing.name, "change the IP version of").await?;

            let groups = AddressRepository::groups_using_object(pool, id)
                .await
                .map_err(db_err)?;

            if !groups.is_empty() {
                return Err(format!(
                    "Cannot change the IP version of '{}': it is a member of group(s) {}",
                    existing.name,
                    groups.join(", ")
                ));
            }
        }

        let found = AddressRepository::update_object(pool, id, &updated)
            .await
            .map_err(db_err)?;

        if !found {
            return Err("Address object not found".into());
        }

        Ok(())
    }

    pub async fn delete_object(pool: &SqlitePool, id: i64) -> Result<(), String> {
        let existing = AddressRepository::get_object(pool, id)
            .await
            .map_err(db_err)?
            .ok_or("Address object not found")?;

        let groups = AddressRepository::groups_using_object(pool, id)
            .await
            .map_err(db_err)?;

        if !groups.is_empty() {
            return Err(format!(
                "Cannot delete '{}': it is a member of group(s) {}",
                existing.name,
                groups.join(", ")
            ));
        }

        Self::ensure_not_used_by_rules(pool, &existing.name, "delete").await?;

        let found = AddressRepository::delete_object(pool, id)
            .await
            .map_err(db_err)?;

        if !found {
            return Err("Address object not found".into());
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Groups
    // ------------------------------------------------------------------

    pub async fn list_groups(pool: &SqlitePool) -> Result<Vec<AddressGroup>, String> {
        AddressRepository::list_groups(pool).await.map_err(db_err)
    }

    pub async fn add_group(pool: &SqlitePool, group: AddressGroup) -> Result<i64, String> {
        let group = Self::prepare_group(pool, &group).await?;

        Self::ensure_name_free(pool, &group.name).await?;

        AddressRepository::add_group(pool, &group)
            .await
            .map_err(db_err)
    }

    pub async fn update_group(
        pool: &SqlitePool,
        id: i64,
        group: AddressGroup,
    ) -> Result<(), String> {
        let existing = AddressRepository::get_group(pool, id)
            .await
            .map_err(db_err)?
            .ok_or("Address group not found")?;

        let updated = Self::prepare_group(pool, &group).await?;

        let renamed = !existing.name.eq_ignore_ascii_case(&updated.name);

        if renamed {
            Self::ensure_name_free(pool, &updated.name).await?;
            Self::ensure_not_used_by_rules(pool, &existing.name, "rename").await?;
        }

        // Rules using this group were checked against its old IP version.
        // If the version changes (or the group becomes empty) they would break.
        if existing.family != updated.family {
            Self::ensure_not_used_by_rules(
                pool,
                &existing.name,
                "change the IP version or empty",
            )
            .await?;
        }

        let found = AddressRepository::update_group(pool, id, &updated)
            .await
            .map_err(db_err)?;

        if !found {
            return Err("Address group not found".into());
        }

        Ok(())
    }

    pub async fn delete_group(pool: &SqlitePool, id: i64) -> Result<(), String> {
        let existing = AddressRepository::get_group(pool, id)
            .await
            .map_err(db_err)?
            .ok_or("Address group not found")?;

        Self::ensure_not_used_by_rules(pool, &existing.name, "delete").await?;

        let found = AddressRepository::delete_group(pool, id)
            .await
            .map_err(db_err)?;

        if !found {
            return Err("Address group not found".into());
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Used by the firewall rule validation
    // ------------------------------------------------------------------

    /// Checks that `value` (for example "@office_lan") names an existing
    /// object or non-empty group and returns its IP version.
    /// `label` is only used in error messages, e.g. "Source IP".
    pub async fn resolve_reference(
        pool: &SqlitePool,
        value: &str,
        label: &str,
    ) -> Result<Family, String> {
        let trimmed = value.trim();
        let name = trimmed.strip_prefix(REF_PREFIX).unwrap_or(trimmed);

        validate_name(name)
            .map_err(|e| format!("{}: invalid reference '{}': {}", label, trimmed, e))?;

        if let Some(object) = AddressRepository::find_object_by_name(pool, name)
            .await
            .map_err(db_err)?
        {
            return Family::from_db(&object.family)
                .ok_or_else(|| format!("{}: '{}' has an invalid IP version", label, object.name));
        }

        if let Some(group) = AddressRepository::find_group_by_name(pool, name)
            .await
            .map_err(db_err)?
        {
            if group.members.is_empty() {
                return Err(format!(
                    "{}: group '{}' has no members, add at least one address object first",
                    label, group.name
                ));
            }

            return Family::from_db(&group.family)
                .ok_or_else(|| format!("{}: group '{}' has an invalid IP version", label, group.name));
        }

        Err(format!(
            "{}: unknown address object or group '{}'",
            label, name
        ))
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

    fn object(name: &str, kind: &str, value: &str) -> AddressObject {
        AddressObject {
            id: None,
            name: name.into(),
            kind: kind.into(),
            value: value.into(),
            // clients may send anything here, the server must ignore it
            family: "garbage".into(),
            comment: None,
        }
    }

    fn group(name: &str, members: &[&str]) -> AddressGroup {
        AddressGroup {
            id: None,
            name: name.into(),
            family: "garbage".into(),
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

    async fn add_obj(pool: &SqlitePool, name: &str, value: &str) -> i64 {
        AddressService::add_object(pool, object(name, "host", value))
            .await
            .unwrap()
    }

    // ---------------- objects ----------------

    #[tokio::test]
    async fn add_object_normalizes_input() {
        let pool = memory_pool().await;

        let mut input = object("  lan  ", " SUBNET ", "192.168.1.77/24");
        input.comment = Some("  office network  ".into());

        let id = AddressService::add_object(&pool, input).await.unwrap();

        let stored = AddressRepository::get_object(&pool, id).await.unwrap().unwrap();
        assert_eq!(stored.name, "lan");
        assert_eq!(stored.kind, "subnet");
        assert_eq!(stored.value, "192.168.1.0/24");
        assert_eq!(stored.family, "ipv4");
        assert_eq!(stored.comment.as_deref(), Some("office network"));
    }

    #[tokio::test]
    async fn add_object_rejects_bad_input() {
        let pool = memory_pool().await;

        assert!(AddressService::add_object(&pool, object("bad name", "host", "10.0.0.1")).await.is_err());
        assert!(AddressService::add_object(&pool, object("ok", "host", "10.0.0.999")).await.is_err());
        assert!(AddressService::add_object(&pool, object("ok", "fqdn", "example.com")).await.is_err());

        let mut with_newline = object("ok", "host", "10.0.0.1");
        with_newline.comment = Some("line1\nline2".into());
        assert!(AddressService::add_object(&pool, with_newline).await.is_err());

        let mut too_long = object("ok", "host", "10.0.0.1");
        too_long.comment = Some("x".repeat(MAX_COMMENT_LEN + 1));
        assert!(AddressService::add_object(&pool, too_long).await.is_err());

        assert!(AddressService::list_objects(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn names_are_unique_across_objects_and_groups() {
        let pool = memory_pool().await;

        add_obj(&pool, "web", "10.0.0.1").await;

        let dup_object = AddressService::add_object(&pool, object("WEB", "host", "10.0.0.2")).await;
        assert!(dup_object.unwrap_err().contains("already used"));

        let dup_group = AddressService::add_group(&pool, group("web", &[])).await;
        assert!(dup_group.unwrap_err().contains("already used"));

        AddressService::add_group(&pool, group("team", &[])).await.unwrap();

        let object_named_like_group =
            AddressService::add_object(&pool, object("team", "host", "10.0.0.3")).await;
        assert!(object_named_like_group.unwrap_err().contains("already used"));
    }

    #[tokio::test]
    async fn update_object_missing_id() {
        let pool = memory_pool().await;

        let err = AddressService::update_object(&pool, 999, object("x", "host", "10.0.0.1"))
            .await
            .unwrap_err();
        assert!(err.contains("not found"));
    }

    #[tokio::test]
    async fn object_used_by_rule_cannot_be_renamed_or_deleted() {
        let pool = memory_pool().await;

        let id = add_obj(&pool, "web", "10.0.0.1").await;
        insert_rule(&pool, "allow web", Some("@web"), None).await;

        let rename = AddressService::update_object(&pool, id, object("web2", "host", "10.0.0.1"))
            .await
            .unwrap_err();
        assert!(rename.contains("allow web"), "{}", rename);

        let delete = AddressService::delete_object(&pool, id).await.unwrap_err();
        assert!(delete.contains("allow web"), "{}", delete);

        // changing the value within the same IP version is fine, even while in use
        AddressService::update_object(&pool, id, object("web", "host", "10.0.0.50"))
            .await
            .unwrap();

        // and so is changing only the capitalization
        AddressService::update_object(&pool, id, object("WEB", "host", "10.0.0.50"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn unused_object_can_be_renamed_and_deleted() {
        let pool = memory_pool().await;

        let id = add_obj(&pool, "web", "10.0.0.1").await;

        AddressService::update_object(&pool, id, object("web_new", "host", "10.0.0.1"))
            .await
            .unwrap();

        assert!(AddressRepository::find_object_by_name(&pool, "web_new").await.unwrap().is_some());

        AddressService::delete_object(&pool, id).await.unwrap();
        assert!(AddressService::list_objects(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn rename_to_a_taken_name_is_refused() {
        let pool = memory_pool().await;

        add_obj(&pool, "a", "10.0.0.1").await;
        let b = add_obj(&pool, "b", "10.0.0.2").await;

        let err = AddressService::update_object(&pool, b, object("A", "host", "10.0.0.2"))
            .await
            .unwrap_err();
        assert!(err.contains("already used"));
    }

    #[tokio::test]
    async fn object_in_group_cannot_be_deleted_or_change_version() {
        let pool = memory_pool().await;

        let id = add_obj(&pool, "web", "10.0.0.1").await;
        AddressService::add_group(&pool, group("servers", &["web"])).await.unwrap();

        let delete = AddressService::delete_object(&pool, id).await.unwrap_err();
        assert!(delete.contains("servers"), "{}", delete);

        let to_v6 = AddressService::update_object(&pool, id, object("web", "host", "2001:db8::1"))
            .await
            .unwrap_err();
        assert!(to_v6.contains("servers"), "{}", to_v6);
    }

    #[tokio::test]
    async fn rule_list_in_error_is_capped() {
        let pool = memory_pool().await;

        let id = add_obj(&pool, "web", "10.0.0.1").await;

        for i in 0..8 {
            insert_rule(&pool, &format!("rule{}", i), Some("@web"), None).await;
        }

        let err = AddressService::delete_object(&pool, id).await.unwrap_err();
        assert!(err.contains("and 3 more"), "{}", err);
    }

    // ---------------- groups ----------------

    #[tokio::test]
    async fn group_members_are_normalized() {
        let pool = memory_pool().await;

        add_obj(&pool, "Web1", "10.0.0.1").await;
        add_obj(&pool, "web2", "10.0.0.2").await;

        // wrong case and a duplicate are cleaned up
        let id = AddressService::add_group(&pool, group("servers", &["web1", " WEB2 ", "WEB1"]))
            .await
            .unwrap();

        let stored = AddressRepository::get_group(&pool, id).await.unwrap().unwrap();
        assert_eq!(stored.family, "ipv4");
        assert_eq!(stored.members, vec!["Web1".to_string(), "web2".to_string()]);
    }

    #[tokio::test]
    async fn group_rejects_mixed_versions_and_unknown_members() {
        let pool = memory_pool().await;

        add_obj(&pool, "v4host", "10.0.0.1").await;
        add_obj(&pool, "v6host", "2001:db8::1").await;

        let mixed = AddressService::add_group(&pool, group("mixed", &["v4host", "v6host"]))
            .await
            .unwrap_err();
        assert!(mixed.contains("same IP version"), "{}", mixed);

        let unknown = AddressService::add_group(&pool, group("ghosts", &["nobody"]))
            .await
            .unwrap_err();
        assert!(unknown.contains("Unknown address object"), "{}", unknown);

        assert!(AddressService::list_groups(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn group_used_by_rule_is_protected() {
        let pool = memory_pool().await;

        add_obj(&pool, "web1", "10.0.0.1").await;
        add_obj(&pool, "v6host", "2001:db8::1").await;

        let gid = AddressService::add_group(&pool, group("servers", &["web1"]))
            .await
            .unwrap();

        insert_rule(&pool, "allow servers", None, Some("@servers")).await;

        let delete = AddressService::delete_group(&pool, gid).await.unwrap_err();
        assert!(delete.contains("allow servers"), "{}", delete);

        let rename = AddressService::update_group(&pool, gid, group("machines", &["web1"]))
            .await
            .unwrap_err();
        assert!(rename.contains("allow servers"), "{}", rename);

        let to_v6 = AddressService::update_group(&pool, gid, group("servers", &["v6host"]))
            .await
            .unwrap_err();
        assert!(to_v6.contains("allow servers"), "{}", to_v6);

        let to_empty = AddressService::update_group(&pool, gid, group("servers", &[]))
            .await
            .unwrap_err();
        assert!(to_empty.contains("allow servers"), "{}", to_empty);

        // the failed updates changed nothing
        let stored = AddressRepository::get_group(&pool, gid).await.unwrap().unwrap();
        assert_eq!(stored.members, vec!["web1".to_string()]);

        // adding another member of the same version is fine while in use
        add_obj(&pool, "web2", "10.0.0.2").await;
        AddressService::update_group(&pool, gid, group("servers", &["web1", "web2"]))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn unused_group_can_change_freely_and_be_deleted() {
        let pool = memory_pool().await;

        add_obj(&pool, "web1", "10.0.0.1").await;
        add_obj(&pool, "v6host", "2001:db8::1").await;

        let gid = AddressService::add_group(&pool, group("servers", &["web1"]))
            .await
            .unwrap();

        AddressService::update_group(&pool, gid, group("machines", &["v6host"]))
            .await
            .unwrap();

        let stored = AddressRepository::get_group(&pool, gid).await.unwrap().unwrap();
        assert_eq!(stored.name, "machines");
        assert_eq!(stored.family, "ipv6");

        AddressService::delete_group(&pool, gid).await.unwrap();
        assert!(AddressService::list_groups(&pool).await.unwrap().is_empty());
    }

    // ---------------- reference resolution ----------------

    #[tokio::test]
    async fn resolve_reference_for_objects_and_groups() {
        let pool = memory_pool().await;

        add_obj(&pool, "web1", "10.0.0.1").await;
        add_obj(&pool, "v6host", "2001:db8::1").await;
        AddressService::add_group(&pool, group("servers", &["web1"])).await.unwrap();
        AddressService::add_group(&pool, group("empty", &[])).await.unwrap();

        assert_eq!(
            AddressService::resolve_reference(&pool, "@web1", "Source IP").await.unwrap(),
            Family::V4
        );
        assert_eq!(
            AddressService::resolve_reference(&pool, " @V6HOST ", "Source IP").await.unwrap(),
            Family::V6
        );
        assert_eq!(
            AddressService::resolve_reference(&pool, "@servers", "Destination IP").await.unwrap(),
            Family::V4
        );

        let unknown = AddressService::resolve_reference(&pool, "@nope", "Source IP")
            .await
            .unwrap_err();
        assert!(unknown.contains("Source IP") && unknown.contains("unknown"), "{}", unknown);

        let empty = AddressService::resolve_reference(&pool, "@empty", "Destination IP")
            .await
            .unwrap_err();
        assert!(empty.contains("no members"), "{}", empty);

        let bad_syntax = AddressService::resolve_reference(&pool, "@bad name;", "Source IP")
            .await
            .unwrap_err();
        assert!(bad_syntax.contains("invalid reference"), "{}", bad_syntax);
    }
}
