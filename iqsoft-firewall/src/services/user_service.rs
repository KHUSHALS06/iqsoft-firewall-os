use crate::{
    models::{
        auth::User,
        role::{CreateUserRequest, Role, UpdateUserRequest, UserAccount},
    },
    repository::{
        auth_repository::AuthRepository, role_repository::RoleRepository,
        user_repository::UserRepository,
    },
    services::{
        auth_service::{AuthService, MIN_PASSWORD_LEN},
        permissions::ROLE_SUPER_ADMIN,
        role_service::{holds_all, AccessError},
    },
};
use sqlx::SqlitePool;

const MIN_USERNAME: usize = 3;
const MAX_USERNAME: usize = 32;

fn clean_username(raw: &str) -> Result<String, AccessError> {
    let name = raw.trim().to_string();
    let length = name.chars().count();

    if length < MIN_USERNAME || length > MAX_USERNAME {
        return Err(AccessError::BadRequest(format!(
            "The user name must be {} to {} characters",
            MIN_USERNAME, MAX_USERNAME
        )));
    }

    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(AccessError::BadRequest(
            "The user name may only contain letters, numbers, dots, dashes and underscores".to_string(),
        ));
    }

    Ok(name)
}

fn check_password(password: &str) -> Result<(), AccessError> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(AccessError::BadRequest(format!(
            "The password must be at least {} characters",
            MIN_PASSWORD_LEN
        )));
    }

    Ok(())
}

async fn find_role(pool: &SqlitePool, id: i64) -> Result<Role, AccessError> {
    RoleRepository::find(pool, id)
        .await?
        .ok_or_else(|| AccessError::BadRequest("That role does not exist".to_string()))
}

/// May `actor` put somebody into this role, or manage somebody who is in it?
fn check_can_manage(actor: &User, role: &Role) -> Result<(), AccessError> {
    if role.name == ROLE_SUPER_ADMIN && !actor.is_super_admin() {
        return Err(AccessError::Forbidden(
            "Only a Super Admin can manage a Super Admin".to_string(),
        ));
    }

    if !holds_all(actor, &role.permissions) {
        return Err(AccessError::Forbidden(
            "That role has permissions that you do not have yourself".to_string(),
        ));
    }

    Ok(())
}

pub struct UserService;

impl UserService {
    pub async fn list(pool: &SqlitePool) -> Result<Vec<UserAccount>, AccessError> {
        Ok(UserRepository::list(pool).await?)
    }

    pub async fn create(
        pool: &SqlitePool,
        actor: &User,
        req: CreateUserRequest,
    ) -> Result<UserAccount, AccessError> {
        let username = clean_username(&req.username)?;
        check_password(&req.password)?;

        let role = find_role(pool, req.role_id).await?;
        check_can_manage(actor, &role)?;

        if UserRepository::username_taken(pool, &username).await? {
            return Err(AccessError::Conflict("That user name is already taken".to_string()));
        }

        let hash = AuthService::hash_password_async(req.password).await?;

        let id = UserRepository::create(
            pool,
            &username,
            &hash,
            role.id,
            &role.name,
            req.enabled.unwrap_or(true),
            AuthService::now(),
        )
        .await?;

        UserRepository::find(pool, id)
            .await?
            .ok_or_else(|| AccessError::Internal("the new user could not be read back".to_string()))
    }

    pub async fn update(
        pool: &SqlitePool,
        actor: &User,
        id: i64,
        req: UpdateUserRequest,
    ) -> Result<UserAccount, AccessError> {
        let target = UserRepository::find(pool, id)
            .await?
            .ok_or_else(|| AccessError::NotFound("User not found".to_string()))?;

        let current_role = match target.role_id {
            Some(role_id) => find_role(pool, role_id).await?,
            None => {
                return Err(AccessError::Internal("the user has no role".to_string()));
            }
        };

        check_can_manage(actor, &current_role)?;

        let new_role = match req.role_id {
            Some(role_id) if Some(role_id) != target.role_id => {
                let role = find_role(pool, role_id).await?;
                check_can_manage(actor, &role)?;
                role
            }
            _ => current_role.clone(),
        };

        let new_enabled = req.enabled.unwrap_or(target.enabled);
        let role_changed = new_role.id != current_role.id;
        let enabled_changed = new_enabled != target.enabled;

        if actor.id == target.id && (role_changed || !new_enabled) {
            return Err(AccessError::BadRequest(
                "You cannot change your own role or switch off your own account".to_string(),
            ));
        }

        // Keep at least one working Super Admin.
        let loses_super = current_role.name == ROLE_SUPER_ADMIN
            && target.enabled
            && (new_role.name != ROLE_SUPER_ADMIN || !new_enabled);

        if loses_super && UserRepository::count_enabled_with_role(pool, current_role.id).await? <= 1 {
            return Err(AccessError::Conflict(
                "This is the last active Super Admin. Make another one first".to_string(),
            ));
        }

        let new_hash = match req.password.as_deref() {
            Some(password) if !password.is_empty() => {
                if actor.id == target.id {
                    return Err(AccessError::BadRequest(
                        "Use Change password in System to change your own password".to_string(),
                    ));
                }

                check_password(password)?;
                Some(AuthService::hash_password_async(password.to_string()).await?)
            }
            _ => None,
        };

        if role_changed || enabled_changed {
            UserRepository::update_access(pool, id, new_role.id, &new_role.name, new_enabled).await?;
        }

        if let Some(hash) = &new_hash {
            AuthRepository::update_password(pool, id, hash).await?;
        }

        // A changed role, a switched-off account or a new password ends the open sessions.
        if role_changed || !new_enabled || new_hash.is_some() {
            AuthRepository::delete_user_sessions(pool, id).await?;
        }

        UserRepository::find(pool, id)
            .await?
            .ok_or_else(|| AccessError::Internal("the user could not be read back".to_string()))
    }

    pub async fn delete(
        pool: &SqlitePool,
        actor: &User,
        id: i64,
    ) -> Result<UserAccount, AccessError> {
        let target = UserRepository::find(pool, id)
            .await?
            .ok_or_else(|| AccessError::NotFound("User not found".to_string()))?;

        if actor.id == target.id {
            return Err(AccessError::BadRequest("You cannot delete your own account".to_string()));
        }

        if let Some(role_id) = target.role_id {
            let role = find_role(pool, role_id).await?;
            check_can_manage(actor, &role)?;

            if role.name == ROLE_SUPER_ADMIN
                && target.enabled
                && UserRepository::count_enabled_with_role(pool, role.id).await? <= 1
            {
                return Err(AccessError::Conflict(
                    "This is the last active Super Admin and cannot be deleted".to_string(),
                ));
            }
        }

        UserRepository::delete(pool, id).await?;
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::{access_schema::create_access_tables, init::initialize_database},
        models::role::RoleRequest,
        services::{permissions::ROLE_ADMIN, role_service::RoleService},
    };
    use sqlx::sqlite::SqlitePoolOptions;

    async fn pool() -> SqlitePool {
        // One connection, otherwise every connection would get its own empty in-memory database.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        initialize_database(&pool).await.unwrap();
        pool
    }

    async fn role_id(pool: &SqlitePool, name: &str) -> i64 {
        RoleService::list(pool)
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.name == name)
            .unwrap()
            .id
    }

    /// Makes an account directly and returns it as the signed-in `User` would look.
    async fn account(pool: &SqlitePool, name: &str, role: &str) -> User {
        let rid = role_id(pool, role).await;
        let id = UserRepository::create(pool, name, "x", rid, role, true, 1).await.unwrap();
        let perms = RoleRepository::permissions_for(pool, rid).await.unwrap();
        User {
            id,
            username: name.to_string(),
            password_hash: "x".into(),
            role: role.to_string(),
            permissions: perms,
        }
    }

    fn new_user(name: &str, role_id: i64) -> CreateUserRequest {
        CreateUserRequest {
            username: name.into(),
            password: "a-long-enough-password".into(),
            role_id,
            enabled: None,
        }
    }

    fn role_req(name: &str, perms: &[&str]) -> RoleRequest {
        RoleRequest {
            name: name.into(),
            description: None,
            permissions: perms.iter().map(|p| p.to_string()).collect(),
        }
    }

    #[tokio::test]
    async fn the_built_in_roles_exist_and_the_super_admin_holds_everything() {
        let pool = pool().await;
        let roles = RoleService::list(&pool).await.unwrap();

        let super_admin = roles.iter().find(|r| r.name == "super_admin").unwrap();
        assert!(super_admin.is_system);
        assert_eq!(super_admin.permissions.len(), crate::services::permissions::all_permissions().len());

        let admin = roles.iter().find(|r| r.name == "admin").unwrap();
        assert!(admin.is_system);
        assert!(admin.permissions.contains(&"users.create".to_string()));
        assert!(admin.permissions.contains(&"roles.create".to_string()));
    }

    #[tokio::test]
    async fn an_account_from_before_roles_existed_becomes_the_super_admin() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        sqlx::query(
            "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
             password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin', created_at INTEGER NOT NULL)",
        )
        .execute(&pool)
        .await
        .unwrap();
        for name in ["first", "second"] {
            sqlx::query("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, 'x', 'admin', 1)")
                .bind(name)
                .execute(&pool)
                .await
                .unwrap();
        }

        create_access_tables(&pool).await.unwrap();
        create_access_tables(&pool).await.unwrap(); // running it again changes nothing

        let users = UserService::list(&pool).await.unwrap();
        assert_eq!(users[0].role, "super_admin");
        assert_eq!(users[1].role, "admin");
        assert!(users.iter().all(|u| u.enabled));
    }

    #[tokio::test]
    async fn an_admin_cannot_create_a_super_admin_or_touch_one() {
        let pool = pool().await;
        let boss = account(&pool, "boss", "super_admin").await;
        let admin = account(&pool, "ann", "admin").await;
        let super_id = role_id(&pool, "super_admin").await;

        let err = UserService::create(&pool, &admin, new_user("sneaky", super_id)).await.unwrap_err();
        assert!(matches!(err, AccessError::Forbidden(_)));

        let err = UserService::delete(&pool, &admin, boss.id).await.unwrap_err();
        assert!(matches!(err, AccessError::Forbidden(_)));

        let err = UserService::update(
            &pool,
            &admin,
            boss.id,
            UpdateUserRequest { role_id: None, enabled: Some(false), password: Some("another-long-password".into()) },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AccessError::Forbidden(_)));
    }

    #[tokio::test]
    async fn nobody_can_hand_out_permissions_they_do_not_hold() {
        let pool = pool().await;
        let boss = account(&pool, "boss", "super_admin").await;

        // A manager who may manage roles and users but has no VPN rights.
        RoleService::create(
            &pool,
            &boss,
            role_req("Manager", &["roles.create", "roles.edit", "users.create", "users.edit", "firewall.view"]),
        )
        .await
        .unwrap();
        let manager = account(&pool, "mia", "Manager").await;

        let err = RoleService::create(&pool, &manager, role_req("Sneaky", &["vpn.edit"])).await.unwrap_err();
        assert!(matches!(err, AccessError::Forbidden(_)));

        // Inside their own rights it is fine.
        RoleService::create(&pool, &manager, role_req("Viewer", &["firewall.view"])).await.unwrap();

        // They cannot put anybody into the powerful Admin role either.
        let admin_id = role_id(&pool, ROLE_ADMIN).await;
        let err = UserService::create(&pool, &manager, new_user("pal", admin_id)).await.unwrap_err();
        assert!(matches!(err, AccessError::Forbidden(_)));

        let viewer_id = role_id(&pool, "Viewer").await;
        UserService::create(&pool, &manager, new_user("pal", viewer_id)).await.unwrap();
    }

    #[tokio::test]
    async fn the_last_super_admin_cannot_be_deleted_disabled_or_demoted() {
        let pool = pool().await;
        let boss = account(&pool, "boss", "super_admin").await;
        let other = account(&pool, "other", "super_admin").await;
        let admin_id = role_id(&pool, "admin").await;

        // With two of them, one may go.
        UserService::update(
            &pool,
            &boss,
            other.id,
            UpdateUserRequest { role_id: Some(admin_id), enabled: None, password: None },
        )
        .await
        .unwrap();

        // Now `boss` is the only one. Another account cannot be the actor here (an admin may not
        // touch a Super Admin), so a second Super Admin tries it to prove the rule itself.
        let second = account(&pool, "second", "super_admin").await;
        UserService::update(
            &pool,
            &boss,
            second.id,
            UpdateUserRequest { role_id: None, enabled: Some(false), password: None },
        )
        .await
        .unwrap();

        let err = UserService::update(
            &pool,
            &second,
            boss.id,
            UpdateUserRequest { role_id: None, enabled: Some(false), password: None },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AccessError::Conflict(_)), "{:?}", err);

        let err = UserService::delete(&pool, &second, boss.id).await.unwrap_err();
        assert!(matches!(err, AccessError::Conflict(_)), "{:?}", err);
    }

    #[tokio::test]
    async fn you_cannot_delete_or_demote_yourself() {
        let pool = pool().await;
        let _boss = account(&pool, "boss", "super_admin").await;
        let admin = account(&pool, "ann", "admin").await;
        let super_id = role_id(&pool, "super_admin").await;

        assert!(matches!(
            UserService::delete(&pool, &admin, admin.id).await.unwrap_err(),
            AccessError::BadRequest(_)
        ));
        assert!(matches!(
            UserService::update(&pool, &admin, admin.id, UpdateUserRequest { role_id: Some(super_id), enabled: None, password: None })
                .await
                .unwrap_err(),
            AccessError::Forbidden(_)
        ));
        assert!(matches!(
            UserService::update(&pool, &admin, admin.id, UpdateUserRequest { role_id: None, enabled: Some(false), password: None })
                .await
                .unwrap_err(),
            AccessError::BadRequest(_)
        ));
    }

    #[tokio::test]
    async fn a_disabled_account_cannot_sign_in_and_loses_its_sessions() {
        let pool = pool().await;
        let boss = account(&pool, "boss", "super_admin").await;
        let admin_id = role_id(&pool, "admin").await;

        let created = UserService::create(&pool, &boss, new_user("dave", admin_id)).await.unwrap();

        let login = AuthService::login(&pool, "dave", "a-long-enough-password").await.unwrap();
        assert!(AuthService::authenticate(&pool, &login.token).await.unwrap().is_some());

        UserService::update(
            &pool,
            &boss,
            created.id,
            UpdateUserRequest { role_id: None, enabled: Some(false), password: None },
        )
        .await
        .unwrap();

        assert!(AuthService::authenticate(&pool, &login.token).await.unwrap().is_none());
        assert!(AuthService::login(&pool, "dave", "a-long-enough-password").await.is_err());
    }

    #[tokio::test]
    async fn a_role_change_applies_to_people_who_are_already_signed_in() {
        let pool = pool().await;
        let boss = account(&pool, "boss", "super_admin").await;

        let role = RoleService::create(&pool, &boss, role_req("Watcher", &["logs.view"])).await.unwrap();
        UserService::create(&pool, &boss, new_user("wendy", role.id)).await.unwrap();

        let login = AuthService::login(&pool, "wendy", "a-long-enough-password").await.unwrap();
        let before = AuthService::authenticate(&pool, &login.token).await.unwrap().unwrap();
        assert!(before.can("logs.view"));
        assert!(!before.can("firewall.view"));

        RoleService::update(&pool, &boss, role.id, role_req("Watcher", &["logs.view", "firewall.edit"]))
            .await
            .unwrap();

        let after = AuthService::authenticate(&pool, &login.token).await.unwrap().unwrap();
        assert!(after.can("firewall.edit"));
        assert!(after.can("firewall.view"), "edit also grants view");
    }

    #[tokio::test]
    async fn roles_have_rules_about_names_deleting_and_the_built_in_ones() {
        let pool = pool().await;
        let boss = account(&pool, "boss", "super_admin").await;

        assert!(matches!(RoleService::create(&pool, &boss, role_req("Super Admin", &[])).await.unwrap_err(), AccessError::BadRequest(_)));
        assert!(matches!(RoleService::create(&pool, &boss, role_req("<script>", &[])).await.unwrap_err(), AccessError::BadRequest(_)));
        assert!(matches!(RoleService::create(&pool, &boss, role_req("Ops", &["nope.view"])).await.unwrap_err(), AccessError::BadRequest(_)));

        let ops = RoleService::create(&pool, &boss, role_req("Ops", &["vpn.view"])).await.unwrap();
        assert!(matches!(RoleService::create(&pool, &boss, role_req("ops", &[])).await.unwrap_err(), AccessError::Conflict(_)));

        // A role with people in it cannot be deleted.
        UserService::create(&pool, &boss, new_user("olga", ops.id)).await.unwrap();
        assert!(matches!(RoleService::delete(&pool, &boss, ops.id).await.unwrap_err(), AccessError::Conflict(_)));

        // Built-in roles: Super Admin is frozen, Admin can only be changed by a Super Admin and never deleted.
        let super_id = role_id(&pool, "super_admin").await;
        let admin_id = role_id(&pool, "admin").await;
        assert!(matches!(RoleService::update(&pool, &boss, super_id, role_req("super_admin", &[])).await.unwrap_err(), AccessError::Forbidden(_)));
        assert!(matches!(RoleService::delete(&pool, &boss, admin_id).await.unwrap_err(), AccessError::Forbidden(_)));
        assert!(matches!(RoleService::update(&pool, &boss, admin_id, role_req("renamed", &["vpn.view"])).await.unwrap_err(), AccessError::BadRequest(_)));

        let ann = account(&pool, "ann", "admin").await;
        assert!(matches!(RoleService::update(&pool, &ann, admin_id, role_req("admin", &["vpn.view"])).await.unwrap_err(), AccessError::Forbidden(_)));
        RoleService::update(&pool, &boss, admin_id, role_req("admin", &["vpn.view"])).await.unwrap();

        // A renamed custom role shows its new name on its accounts.
        RoleService::update(&pool, &boss, ops.id, role_req("Operators", &["vpn.view"])).await.unwrap();
        let users = UserService::list(&pool).await.unwrap();
        assert_eq!(users.iter().find(|u| u.username == "olga").unwrap().role, "Operators");
    }

    #[tokio::test]
    async fn usernames_and_passwords_are_checked() {
        let pool = pool().await;
        let boss = account(&pool, "boss", "super_admin").await;
        let admin_id = role_id(&pool, "admin").await;

        let mut bad = new_user("a b", admin_id);
        assert!(matches!(UserService::create(&pool, &boss, bad).await.unwrap_err(), AccessError::BadRequest(_)));

        bad = new_user("shortpw", admin_id);
        bad.password = "short".into();
        assert!(matches!(UserService::create(&pool, &boss, bad).await.unwrap_err(), AccessError::BadRequest(_)));

        UserService::create(&pool, &boss, new_user("Carol", admin_id)).await.unwrap();
        assert!(matches!(UserService::create(&pool, &boss, new_user("carol", admin_id)).await.unwrap_err(), AccessError::Conflict(_)));
        assert!(matches!(UserService::create(&pool, &boss, new_user("nobody", 9999)).await.unwrap_err(), AccessError::BadRequest(_)));
    }
}
