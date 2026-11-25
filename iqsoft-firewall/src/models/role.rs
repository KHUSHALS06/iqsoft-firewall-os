use serde::{Deserialize, Serialize};

/// A role as shown to administrators.
#[derive(Debug, Clone, Serialize)]
pub struct Role {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    /// Built-in roles (Super Admin, Admin) cannot be renamed or deleted.
    pub is_system: bool,
    pub created_at: i64,
    pub permissions: Vec<String>,
    pub user_count: i64,
}

/// A user account as shown to administrators. The password hash is never part of it.
#[derive(Debug, Clone, Serialize)]
pub struct UserAccount {
    pub id: i64,
    pub username: String,
    pub role_id: Option<i64>,
    pub role: String,
    pub enabled: bool,
    pub created_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct RoleRequest {
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role_id: i64,
    pub enabled: Option<bool>,
}

/// Every field is optional; only the ones that are present change.
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub role_id: Option<i64>,
    pub enabled: Option<bool>,
    pub password: Option<String>,
}
