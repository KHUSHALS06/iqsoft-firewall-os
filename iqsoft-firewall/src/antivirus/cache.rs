//! Verdict cache (option 2): a file whose hash was scanned recently is not
//! sent to clamd again.
//!
//! * Keyed by the SHA-256 of the content, never by URL or headers. A server
//!   could otherwise serve a clean file once and malware later under the same
//!   URL and ETag.
//! * Only real verdicts are cached (clean / infected). Errors, over-size and
//!   skipped files are never cached.
//! * Call `clear()` after every signature update, because a file that was
//!   clean yesterday may be detected today.
//! * Only useful for fully buffered scans. A streaming scan learns the hash
//!   too late to avoid the scan.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CachedVerdict {
    Clean,
    Infected(String),
}

struct Entry {
    verdict: CachedVerdict,
    stored: Instant,
}

pub struct VerdictCache {
    entries: Mutex<HashMap<[u8; 32], Entry>>,
    ttl: Duration,
    max_entries: usize,
}

impl VerdictCache {
    /// One hour and 4096 entries is a sensible starting point.
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max_entries: max_entries.max(1),
        }
    }

    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);

        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    pub fn get(&self, key: &[u8; 32]) -> Option<CachedVerdict> {
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(entry) = map.get(key) {
            if entry.stored.elapsed() < self.ttl {
                return Some(entry.verdict.clone());
            }
        }

        // Expired (or absent: removing a missing key is harmless).
        map.remove(key);
        None
    }

    pub fn put(&self, key: [u8; 32], verdict: CachedVerdict) {
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());

        if map.len() >= self.max_entries && !map.contains_key(&key) {
            let ttl = self.ttl;
            map.retain(|_, entry| entry.stored.elapsed() < ttl);

            if map.len() >= self.max_entries {
                // Still full: drop the oldest entry.
                let oldest = map
                    .iter()
                    .min_by_key(|(_, entry)| entry.stored)
                    .map(|(k, _)| *k);

                if let Some(oldest) = oldest {
                    map.remove(&oldest);
                }
            }
        }

        map.insert(
            key,
            Entry {
                verdict,
                stored: Instant::now(),
            },
        );
    }

    /// Forget everything. Call after a signature update.
    pub fn clear(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_and_returns_verdicts() {
        let cache = VerdictCache::new(Duration::from_secs(60), 10);
        let key = VerdictCache::hash(b"file one");

        assert_eq!(cache.get(&key), None);

        cache.put(key, CachedVerdict::Infected("Eicar-Test-Signature".into()));
        assert_eq!(
            cache.get(&key),
            Some(CachedVerdict::Infected("Eicar-Test-Signature".into()))
        );

        // Different content, different key.
        assert_eq!(cache.get(&VerdictCache::hash(b"file two")), None);
    }

    #[test]
    fn entries_expire() {
        let cache = VerdictCache::new(Duration::from_millis(20), 10);
        let key = VerdictCache::hash(b"x");

        cache.put(key, CachedVerdict::Clean);
        assert_eq!(cache.get(&key), Some(CachedVerdict::Clean));

        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(cache.get(&key), None);
    }

    #[test]
    fn never_grows_past_the_limit() {
        let cache = VerdictCache::new(Duration::from_secs(60), 3);

        for i in 0..10u8 {
            cache.put(VerdictCache::hash(&[i]), CachedVerdict::Clean);
        }

        assert!(cache.len() <= 3);
    }

    #[test]
    fn clear_forgets_everything() {
        let cache = VerdictCache::new(Duration::from_secs(60), 10);
        cache.put(VerdictCache::hash(b"a"), CachedVerdict::Clean);
        assert!(!cache.is_empty());

        cache.clear();
        assert!(cache.is_empty());
    }
}
