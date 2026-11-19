//! Live health of the antivirus: is the proxy listening, does clamd answer,
//! and does clamd really detect something (the canary).
//!
//! The canary is the industry-standard EICAR test file. It is harmless, and it
//! is built from pieces at run time so this source file never contains the
//! whole string (otherwise scanners would flag the repository).
//!
//! "Healthy" therefore means: a real detection worked recently, not just that
//! a process exists.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

use super::clamav::{ClamAvClient, ClamAvVerdict};
use super::scanner::{ScanAction, ScannerOutcome};

static PROXY_UP: AtomicBool = AtomicBool::new(false);
static PROXY_PORT: AtomicU16 = AtomicU16::new(0);
static CLAMD_REACHABLE: AtomicBool = AtomicBool::new(false);
static CLAMD_DETECTS: AtomicBool = AtomicBool::new(false);
static LAST_CHECK: AtomicI64 = AtomicI64::new(0);
static REDIRECT_ON: AtomicBool = AtomicBool::new(false);
static SCANNED: AtomicU64 = AtomicU64::new(0);
static BLOCKED: AtomicU64 = AtomicU64::new(0);
static ERRORS: AtomicU64 = AtomicU64::new(0);

/// Seconds without a successful canary after which the status turns red.
const STALE_AFTER_SECS: i64 = 180;

pub fn set_proxy(up: bool, port: u16) {
    PROXY_UP.store(up, Ordering::Relaxed);
    PROXY_PORT.store(if up { port } else { 0 }, Ordering::Relaxed);
}

/// True once the proxy has bound its port. The firewall generator uses this to
/// decide whether the redirect starts open.
pub fn proxy_up() -> bool {
    PROXY_UP.load(Ordering::Relaxed)
}

pub fn set_redirect(on: bool) {
    REDIRECT_ON.store(on, Ordering::Relaxed);
}

/// Update the counters from one finished scan.
pub fn count_outcome(outcome: &ScannerOutcome) {
    if outcome.scanned {
        SCANNED.fetch_add(1, Ordering::Relaxed);
    }
    if outcome.action == ScanAction::Block {
        BLOCKED.fetch_add(1, Ordering::Relaxed);
    }
    if outcome.reason.contains("scanning failed") {
        ERRORS.fetch_add(1, Ordering::Relaxed);
    }
}

/// The EICAR test file (68 bytes), assembled at run time.
pub fn test_file() -> Vec<u8> {
    [
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
        "EICAR-STANDARD-",
        "ANTIVIRUS-TEST-FILE!",
        "$H+H*",
    ]
    .concat()
    .into_bytes()
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Ask clamd whether it is alive and whether it detects the test file.
pub async fn check_clamd(socket: &str) {
    let client = ClamAvClient::with_socket(socket);

    let reachable = matches!(timeout(Duration::from_secs(5), client.ping()).await, Ok(Ok(true)));

    let detects = if reachable {
        match timeout(Duration::from_secs(20), client.scan_bytes(&test_file())).await {
            Ok(Ok(ClamAvVerdict::Infected(signature))) => {
                signature.to_ascii_lowercase().contains("eicar")
            }
            _ => false,
        }
    } else {
        false
    };

    CLAMD_REACHABLE.store(reachable, Ordering::Relaxed);
    CLAMD_DETECTS.store(detects, Ordering::Relaxed);
    LAST_CHECK.store(now(), Ordering::Relaxed);
}

/// clamd's version string, which includes the signature database number.
/// A change means signatures were updated (so cached verdicts are stale).
pub async fn clamd_version(socket: &str) -> Option<String> {
    let read = async {
        let mut stream = UnixStream::connect(socket).await.ok()?;
        stream.write_all(b"zVERSION\0").await.ok()?;

        let mut out = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            if stream.read(&mut byte).await.ok()? == 0 || byte[0] == 0 {
                break;
            }
            out.push(byte[0]);
            if out.len() > 512 {
                return None;
            }
        }

        String::from_utf8(out).ok()
    };

    timeout(Duration::from_secs(5), read).await.ok().flatten()
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusSnapshot {
    pub enabled: bool,
    pub healthy: bool,
    pub proxy_listening: bool,
    pub proxy_port: u16,
    pub clamd_reachable: bool,
    pub clamd_detects_test_file: bool,
    pub last_check_unix: i64,
    pub redirect_active: bool,
    pub files_scanned: u64,
    pub files_blocked: u64,
    pub scan_errors: u64,
    pub problems: Vec<String>,
}

pub fn snapshot(enabled: bool) -> StatusSnapshot {
    let proxy_listening = PROXY_UP.load(Ordering::Relaxed);
    let clamd_reachable = CLAMD_REACHABLE.load(Ordering::Relaxed);
    let detects = CLAMD_DETECTS.load(Ordering::Relaxed);
    let last_check = LAST_CHECK.load(Ordering::Relaxed);
    let redirect_active = REDIRECT_ON.load(Ordering::Relaxed);

    let mut problems = Vec::new();

    if enabled {
        if !proxy_listening {
            problems.push("The scanning proxy is not listening.".to_string());
        }
        if !clamd_reachable {
            problems.push("ClamAV (clamd) is not answering.".to_string());
        } else if !detects {
            problems.push(
                "ClamAV answers but did not detect the test file. Its signatures may be missing."
                    .to_string(),
            );
        }
        if last_check == 0 || now() - last_check > STALE_AFTER_SECS {
            problems.push("The ClamAV self-test has not run recently.".to_string());
        }
        if !redirect_active {
            problems.push(
                "Web traffic is not being redirected to the scanner. Commit the firewall configuration."
                    .to_string(),
            );
        }
    }

    StatusSnapshot {
        enabled,
        healthy: enabled && problems.is_empty(),
        proxy_listening,
        proxy_port: PROXY_PORT.load(Ordering::Relaxed),
        clamd_reachable,
        clamd_detects_test_file: detects,
        last_check_unix: last_check,
        redirect_active,
        files_scanned: SCANNED.load(Ordering::Relaxed),
        files_blocked: BLOCKED.load(Ordering::Relaxed),
        scan_errors: ERRORS.load(Ordering::Relaxed),
        problems,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_is_the_68_byte_standard_string() {
        let file = test_file();
        assert_eq!(file.len(), 68);
        assert!(file.starts_with(b"X5O!P%@AP"));
        assert!(file.ends_with(b"TEST-FILE!$H+H*"));
    }

    #[test]
    fn disabled_av_has_no_problems_and_is_not_healthy() {
        let status = snapshot(false);
        assert!(!status.enabled);
        assert!(!status.healthy);
        assert!(status.problems.is_empty());
    }

    #[test]
    fn outcomes_are_counted() {
        let before = snapshot(false);

        count_outcome(&ScannerOutcome {
            action: ScanAction::Block,
            infected: true,
            signature: Some("Eicar-Test-Signature".into()),
            reason: "Malware detected".into(),
            scanned: true,
        });

        let after = snapshot(false);
        assert!(after.files_scanned > before.files_scanned);
        assert!(after.files_blocked > before.files_blocked);
    }
}
