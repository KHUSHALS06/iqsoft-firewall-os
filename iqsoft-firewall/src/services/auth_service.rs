use crate::{
    models::auth::{LoginResponse, User},
    repository::auth_repository::AuthRepository,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::{distributions::Alphanumeric, Rng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::time::{SystemTime, UNIX_EPOCH};

const SESSION_TTL_SECONDS: i64 = 8 * 60 * 60;
const MIN_PASSWORD_LEN: usize = 10;

#[derive(Debug)]
pub enum AuthError {
    InvalidCredentials,
    BadRequest(String),
    Internal(String),
}

impl From<sqlx::Error> for AuthError {
    fn from(e: sqlx::Error) -> Self {
        AuthError::Internal(e.to_string())
    }
}

pub struct AuthService;

impl AuthService {
    pub fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    pub fn hash_token(token: &str) -> String {
        hex::encode(Sha256::digest(token.as_bytes()))
    }

    fn generate_token() -> String {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    fn generate_password() -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(20)
            .map(char::from)
            .collect()
    }

    fn hash_password(password: &str) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| AuthError::Internal(e.to_string()))
    }

    fn verify_password(password: &str, hash: &str) -> bool {
        match PasswordHash::new(hash) {
            Ok(parsed) => Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok(),
            Err(_) => false,
        }
    }

    async fn hash_password_async(password: String) -> Result<String, AuthError> {
        tokio::task::spawn_blocking(move || Self::hash_password(&password))
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?
    }

    async fn verify_password_async(password: String, hash: String) -> bool {
        tokio::task::spawn_blocking(move || Self::verify_password(&password, &hash))
            .await
            .unwrap_or(false)
    }

    pub async fn ensure_admin(pool: &SqlitePool) -> Result<(), AuthError> {
        if AuthRepository::count_users(pool).await? > 0 {
            return Ok(());
        }

        let password = Self::generate_password();
        let hash = Self::hash_password_async(password.clone()).await?;

        AuthRepository::create_user(pool, "admin", &hash, "admin", Self::now()).await?;

        println!("==================================================");
        println!(" First boot: admin account created");
        println!("   username: admin");
        println!("   password: {}", password);
        println!(" This password is shown only once. Change it after login.");
        println!("==================================================");

        Ok(())
    }

    pub async fn login(
        pool: &SqlitePool,
        username: &str,
        password: &str,
    ) -> Result<LoginResponse, AuthError> {
        let user = AuthRepository::find_by_username(pool, username.trim()).await?;

        let user = match user {
            Some(u) => {
                if !Self::verify_password_async(password.to_string(), u.password_hash.clone())
                    .await
                {
                    return Err(AuthError::InvalidCredentials);
                }
                u
            }
            None => {
                let _ = Self::hash_password_async(password.to_string()).await;
                return Err(AuthError::InvalidCredentials);
            }
        };

        let now = Self::now();
        let _ = AuthRepository::delete_expired_sessions(pool, now).await;

        let token = Self::generate_token();
        let expires_at = now + SESSION_TTL_SECONDS;

        AuthRepository::create_session(pool, &Self::hash_token(&token), user.id, now, expires_at)
            .await?;

        Ok(LoginResponse { token, expires_at })
    }

    pub async fn authenticate(
        pool: &SqlitePool,
        token: &str,
    ) -> Result<Option<User>, AuthError> {
        let user =
            AuthRepository::find_user_by_session(pool, &Self::hash_token(token), Self::now())
                .await?;

        Ok(user)
    }

    pub async fn logout(pool: &SqlitePool, token: &str) -> Result<(), AuthError> {
        AuthRepository::delete_session(pool, &Self::hash_token(token)).await?;
        Ok(())
    }

    pub async fn change_password(
        pool: &SqlitePool,
        user: &User,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), AuthError> {
        if new_password.len() < MIN_PASSWORD_LEN {
            return Err(AuthError::BadRequest(format!(
                "New password must be at least {} characters",
                MIN_PASSWORD_LEN
            )));
        }

        if !Self::verify_password_async(current_password.to_string(), user.password_hash.clone())
            .await
        {
            return Err(AuthError::InvalidCredentials);
        }

        let hash = Self::hash_password_async(new_password.to_string()).await?;

        AuthRepository::update_password(pool, user.id, &hash).await?;
        AuthRepository::delete_user_sessions(pool, user.id).await?;

        Ok(())
    }
}
