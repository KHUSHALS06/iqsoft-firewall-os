use crate::{
    models::{
        auth::User,
        role::{Role, RoleRequest},
    },
    repository::role_repository::RoleRepository,
    services::{
        auth_service::AuthService,
        permissions::{self, ROLE_ADMIN, ROLE_SUPER_ADMIN},
    },
};
use sqlx::SqlitePool;

/// Why an access-management request was refused. The messages are fixed text written
/// here; they never repeat what the client sent.
#[derive(Debug)]
pub enum AccessError {
    BadRequest(String),
    Forbidden(String),
    NotFound(String),
    Conflict(String),
    Internal(String),
}

impl From<sqlx::Error> for AccessError {
    fn from(e: sqlx::Error) -> Self {
        AccessError::Internal(e.to_string())
    }
}

impl From<crate::services::auth_service::AuthError> for AccessError {
    fn from(e: crate::services::auth_service::AuthError) -> Self {
        AccessError::Internal(format!("{:?}", e))
    }
}

const MAX_NAME: usize = 40;
const MIN_NAME: usize = 2;
const MAX_DESCRIPTION: usize = 200;

/// May `actor` hand out (or manage something that holds) exactly these permissions?
/// A Super Admin can; everybody else only what they hold themselves, so nobody can
/// raise their own or anybody else's rights above their own.
pub fn holds_all(actor: &User, wanted: &[String]) -> bool {
    actor.is_super_admin() || wanted.iter().all(|p| actor.can(p))
}

fn clean_name(raw: &str) -> Result<String, AccessError> {
    let name = raw.trim().to_string();
    let length = name.chars().count();

    if length < MIN_NAME || length > MAX_NAME {
        return Err(AccessError::BadRequest(format!(
            "The role name must be {} to {} characters",
            MIN_NAME, MAX_NAME
        )));
    }

    let ok = name
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.'));

    if !ok {
        return Err(AccessError::BadRequest(
            "The role name may only contain letters, numbers, spaces, dots, dashes and underscores"
                .to_string(),
        ));
    }

    Ok(name)
}

fn clean_description(raw: &Option<String>) -> Result<Option<String>, AccessError> {
    let text = raw.as_deref().unwrap_or("").trim().to_string();

    if text.chars().count() > MAX_DESCRIPTION {
        return Err(AccessError::BadRequest(format!(
            "The description must be at most {} characters",
            MAX_DESCRIPTION
        )));
    }

    if text.chars().any(|c| c.is_control()) {
        return Err(AccessError::BadRequest(
            "The description contains characters that are not allowed".to_string(),
        ));
    }

    Ok(if text.is_empty() { None } else { Some(text) })
}

/// "Super Admin" and "super_admin" are the same name as far as anyone reading is concerned.
fn is_reserved(name: &str) -> bool {
    let flat = name.to_lowercase().replace([' ', '-', '.'], "_");
    flat == ROLE_SUPER_ADMIN || flat == ROLE_ADMIN
}

pub struct RoleService;

impl RoleService {
    pub async fn list(pool: &SqlitePool) -> Result<Vec<Role>, AccessError> {
        Ok(RoleRepository::list(pool).await?)
    }

    pub async fn create(
        pool: &SqlitePool,
        actor: &User,
        req: RoleRequest,
    ) -> Result<Role, AccessError> {
        let name = clean_name(&req.name)?;
        let description = clean_description(&req.description)?;
        let perms = permissions::normalize(&req.permissions).map_err(AccessError::BadRequest)?;

        if is_reserved(&name) {
            return Err(AccessError::BadRequest(
                "That name is reserved for a built-in role".to_string(),
            ));
        }

        if !holds_all(actor, &perms) {
            return Err(AccessError::Forbidden(
                "You cannot give a role permissions that you do not have yourself".to_string(),
            ));
        }

        if RoleRepository::name_taken(pool, &name, None).await? {
            return Err(AccessError::Conflict("A role with that name already exists".to_string()));
        }

        let id = RoleRepository::create(
            pool,
            &name,
            description.as_deref(),
            &perms,
            AuthService::now(),
        )
        .await?;

        RoleRepository::find(pool, id)
            .await?
            .ok_or_else(|| AccessError::Internal("the new role could not be read back".to_string()))
    }

    pub async fn update(
        pool: &SqlitePool,
        actor: &User,
        id: i64,
        req: RoleRequest,
    ) -> Result<Role, AccessError> {
        let current = RoleRepository::find(pool, id)
            .await?
            .ok_or_else(|| AccessError::NotFound("Role not found".to_string()))?;

        if current.name == ROLE_SUPER_ADMIN {
            return Err(AccessError::Forbidden(
                "The Super Admin role always has every permission and cannot be changed".to_string(),
            ));
        }

        let perms = permissions::normalize(&req.permissions).map_err(AccessError::BadRequest)?;
        let description = clean_description(&req.description)?;

        let name = if current.is_system {
            // Built-in roles keep their name.
            if req.name.trim() != current.name {
                return Err(AccessError::BadRequest(
                    "A built-in role cannot be renamed".to_string(),
                ));
            }

            if !actor.is_super_admin() {
                return Err(AccessError::Forbidden(
                    "Only a Super Admin can change a built-in role".to_string(),
                ));
            }

            current.name.clone()
        } else {
            let name = clean_name(&req.name)?;

            if is_reserved(&name) {
                return Err(AccessError::BadRequest(
                    "That name is reserved for a built-in role".to_string(),
                ));
            }

            if RoleRepository::name_taken(pool, &name, Some(id)).await? {
                return Err(AccessError::Conflict("A role with that name already exists".to_string()));
            }

            name
        };

        // Somebody who holds less than the role cannot rewrite it, or they could take away
        // rights from people who rank above them.
        if !holds_all(actor, &current.permissions) {
            return Err(AccessError::Forbidden(
                "This role has permissions that you do not have, so you cannot change it".to_string(),
            ));
        }

        if !holds_all(actor, &perms) {
            return Err(AccessError::Forbidden(
                "You cannot give a role permissions that you do not have yourself".to_string(),
            ));
        }

        RoleRepository::update(pool, id, &name, description.as_deref(), &perms).await?;

        RoleRepository::find(pool, id)
            .await?
            .ok_or_else(|| AccessError::Internal("the role could not be read back".to_string()))
    }

    pub async fn delete(pool: &SqlitePool, actor: &User, id: i64) -> Result<Role, AccessError> {
        let current = RoleRepository::find(pool, id)
            .await?
            .ok_or_else(|| AccessError::NotFound("Role not found".to_string()))?;

        if current.is_system {
            return Err(AccessError::Forbidden("A built-in role cannot be deleted".to_string()));
        }

        if !holds_all(actor, &current.permissions) {
            return Err(AccessError::Forbidden(
                "This role has permissions that you do not have, so you cannot delete it".to_string(),
            ));
        }

        if current.user_count > 0 {
            return Err(AccessError::Conflict(format!(
                "{} user(s) still have this role. Move them to another role first",
                current.user_count
            )));
        }

        RoleRepository::delete(pool, id).await?;
        Ok(current)
    }
}
