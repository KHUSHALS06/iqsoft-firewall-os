use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub role: String,
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
