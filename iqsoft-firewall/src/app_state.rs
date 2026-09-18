use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
     pub commit_lock: Arc<Mutex<()>>,
}
