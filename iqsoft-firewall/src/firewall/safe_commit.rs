use crate::firewall::commit::FirewallCommit;
use sqlx::SqlitePool;
use std::{
    fs,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

const MIN_CONFIRM_SECONDS: u64 = 10;
const MAX_CONFIRM_SECONDS: u64 = 600;
const PENDING_PATH: &str = "config-history/pending-confirm.txt";

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

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn write_pending_file(deadline_epoch: u64) -> Result<(), String> {
    let tmp_path = format!("{}.tmp", PENDING_PATH);
    fs::write(&tmp_path, deadline_epoch.to_string()).map_err(|e| e.to_string())?;
    fs::rename(&tmp_path, PENDING_PATH).map_err(|e| e.to_string())
}

fn clear_pending_file() {
    if let Err(e) = fs::remove_file(PENDING_PATH) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!("WARNING: could not remove {}: {}", PENDING_PATH, e);
        }
    }
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

            if let Err(e) = write_pending_file(now_epoch() + seconds) {
                message.push_str(&format!(
                    "\nWarning: could not record the pending confirmation on disk ({}). If the service restarts before you confirm, the automatic rollback will not happen.",
                    e
                ));
            }

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
        clear_pending_file();

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

    pub async fn recover_on_boot(
        &self,
        pool: &SqlitePool,
        lock: &Arc<Mutex<()>>,
    ) -> Result<String, String> {
        let raw = match fs::read_to_string(PENDING_PATH) {
            Ok(raw) => raw,
            Err(_) => return Ok("No unconfirmed commit found".into()),
        };

        let deadline_epoch: u64 = raw.trim().parse().unwrap_or(0);
        let remaining = deadline_epoch.saturating_sub(now_epoch());

        if remaining == 0 || remaining > MAX_CONFIRM_SECONDS {
            clear_pending_file();

            return match FirewallCommit::rollback(pool, lock).await {
                Ok(message) => Ok(format!(
                    "Found a commit that was never confirmed before the restart, rolled it back: {}",
                    message
                )),
                Err(e) => Err(format!(
                    "Found a commit that was never confirmed before the restart, but the rollback FAILED: {}",
                    e
                )),
            };
        }

        let id = self.counter.fetch_add(1, Ordering::SeqCst) + 1;

        {
            let mut guard = self.pending.lock().await;
            *guard = Some(Pending {
                id,
                deadline: Instant::now() + Duration::from_secs(remaining),
            });
        }

        let this = self.clone();
        let pool = pool.clone();
        let lock = lock.clone();

        tokio::spawn(async move {
            this.expire(id, remaining, pool, lock).await;
        });

        Ok(format!(
            "Found a commit waiting for confirmation from before the restart, automatic rollback in {} seconds unless confirmed",
            remaining
        ))
    }

    pub async fn confirm(&self) -> Result<String, String> {
        let mut guard = self.pending.lock().await;

        if guard.take().is_some() {
            clear_pending_file();
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
        clear_pending_file();

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
