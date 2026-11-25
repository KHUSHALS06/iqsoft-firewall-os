use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    /// What the user's role allows, e.g. `firewall.view`. Loaded fresh on every request,
    /// so a change to a role applies to people who are already signed in.
    pub permissions: Vec<String>,
}

impl User {
    pub fn is_super_admin(&self) -> bool {
        self.role == crate::services::permissions::ROLE_SUPER_ADMIN
    }

    pub fn can(&self, permission: &str) -> bool {
        self.is_super_admin() || self.permissions.iter().any(|p| p == permission)
    }

    pub fn can_any(&self, list: &[String]) -> bool {
        self.is_super_admin() || list.iter().any(|p| self.can(p))
    }
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}
