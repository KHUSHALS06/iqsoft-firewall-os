use crate::{
    firewall::safe_commit::SafeCommit,
    services::login_throttle::LoginThrottle,
};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub commit_lock: Arc<Mutex<()>>,
    pub login_throttle: LoginThrottle,
    pub safe_commit: SafeCommit,
}
