use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const MAX_FAILURES: u32 = 5;
const WINDOW: Duration = Duration::from_secs(15 * 60);
const LOCKOUT: Duration = Duration::from_secs(15 * 60);
const MAX_TRACKED: usize = 10_000;

struct Entry {
    failures: u32,
    window_start: Instant,
    locked_until: Option<Instant>,
}

#[derive(Clone, Default)]
pub struct LoginThrottle {
    inner: Arc<Mutex<HashMap<IpAddr, Entry>>>,
}

impl LoginThrottle {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn check(&self, ip: IpAddr) -> Result<(), u64> {
        let mut map = self.inner.lock().await;
        let now = Instant::now();

        let locked = map.get(&ip).and_then(|e| e.locked_until);

        if let Some(until) = locked {
            if until > now {
                return Err((until - now).as_secs().max(1));
            }
            map.remove(&ip);
        }

        Ok(())
    }

    pub async fn record_failure(&self, ip: IpAddr) {
        let mut map = self.inner.lock().await;
        let now = Instant::now();

        if map.len() > MAX_TRACKED {
            map.retain(|_, e| match e.locked_until {
                Some(until) => until > now,
                None => now.duration_since(e.window_start) < WINDOW,
            });
        }

        let entry = map.entry(ip).or_insert(Entry {
            failures: 0,
            window_start: now,
            locked_until: None,
        });

        if now.duration_since(entry.window_start) >= WINDOW {
            entry.failures = 0;
            entry.window_start = now;
        }

        entry.failures += 1;

        if entry.failures >= MAX_FAILURES {
            entry.locked_until = Some(now + LOCKOUT);
        }
    }

    pub async fn record_success(&self, ip: IpAddr) {
        self.inner.lock().await.remove(&ip);
    }
}
