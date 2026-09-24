use crate::firewall::commit::FirewallCommit;
use sqlx::SqlitePool;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const MIN_CONFIRM_SECONDS: u64 = 10;
const MAX_CONFIRM_SECONDS: u64 = 600;

struct Pending {
    id: u64,
    deadline: Instant,
}

pub enum SafeCommitError {
    Pending(u64),
    Invalid(String),
    Failed(String),
}

#[derive(Clone, Default)]
pub struct SafeCommit {
    pending: Arc<Mutex<Option<Pending>>>,
    counter: Arc<AtomicU64>,
}

impl SafeCommit {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn commit(
        &self,
        pool: &SqlitePool,
        lock: &Arc<Mutex<()>>,
        confirm_within: Option<u64>,
    ) -> Result<String, SafeCommitError> {
        if let Some(seconds) = confirm_within {
            if !(MIN_CONFIRM_SECONDS..=MAX_CONFIRM_SECONDS).contains(&seconds) {
                return Err(SafeCommitError::Invalid(format!(
                    "confirm_within must be between {} and {} seconds",
                    MIN_CONFIRM_SECONDS, MAX_CONFIRM_SECONDS
                )));
            }
        }

        let mut guard = self.pending.lock().await;

        if let Some(p) = guard.as_ref() {
            return Err(SafeCommitError::Pending(
                p.deadline.saturating_duration_since(Instant::now()).as_secs(),
            ));
        }

        let mut message = FirewallCommit::commit(pool, lock)
            .await
            .map_err(SafeCommitError::Failed)?;

        if let Some(seconds) = confirm_within {
            let id = self.counter.fetch_add(1, Ordering::SeqCst) + 1;

            *guard = Some(Pending {
                id,
                deadline: Instant::now() + Duration::from_secs(seconds),
            });

            drop(guard);

            let this = self.clone();
            let pool = pool.clone();
            let lock = lock.clone();

            tokio::spawn(async move {
                this.expire(id, seconds, pool, lock).await;
            });

            message.push_str(&format!(
                "\nAutomatic rollback in {} seconds unless confirmed with POST /api/commit/confirm",
                seconds
            ));
        }

        Ok(message)
    }

    async fn expire(self, id: u64, seconds: u64, pool: SqlitePool, lock: Arc<Mutex<()>>) {
        tokio::time::sleep(Duration::from_secs(seconds)).await;

        let mut guard = self.pending.lock().await;

        let is_current = guard.as_ref().map(|p| p.id == id).unwrap_or(false);

        if !is_current {
            return;
        }

        *guard = None;

        match FirewallCommit::rollback(&pool, &lock).await {
            Ok(message) => println!(
                "Commit was not confirmed in time, rolled back automatically: {}",
                message
            ),
            Err(e) => eprintln!(
                "Commit was not confirmed in time and the automatic rollback FAILED: {}",
                e
            ),
        }
    }

    pub async fn confirm(&self) -> Result<String, String> {
        let mut guard = self.pending.lock().await;

        if guard.take().is_some() {
            Ok("Commit confirmed".into())
        } else {
            Err("No commit is waiting for confirmation".into())
        }
    }

    pub async fn rollback(
        &self,
        pool: &SqlitePool,
        lock: &Arc<Mutex<()>>,
    ) -> Result<String, String> {
        let mut guard = self.pending.lock().await;
        *guard = None;

        FirewallCommit::rollback(pool, lock).await
    }

    pub async fn seconds_left(&self) -> Option<u64> {
        self.pending
            .lock()
            .await
            .as_ref()
            .map(|p| p.deadline.saturating_duration_since(Instant::now()).as_secs())
    }
}
