use crate::models::interface_config::InterfaceConfig;
use crate::netconfig::generator::{file_name, networkd_dir, InterfaceGenerator};
use crate::repository::interface_config_repository::InterfaceConfigRepository;
use sqlx::SqlitePool;
use std::{
    collections::HashSet,
    fs,
    net::IpAddr,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex as StdMutex, OnceLock,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{process::Command, sync::Mutex};

const HISTORY_DIR: &str = "config-history";
const CURRENT_PATH: &str = "config-history/current.interfaces.json";
const PREVIOUS_PATH: &str = "config-history/previous.interfaces.json";

/// When a change touches the port you are connected through, the new settings are undone
/// after this many seconds unless you press "Keep these settings".
pub const CONFIRM_SECONDS: u64 = 60;

/// (id, deadline as unix seconds) of a change that is waiting for confirmation.
static PENDING: OnceLock<StdMutex<Option<(u64, u64)>>> = OnceLock::new();
static COUNTER: AtomicU64 = AtomicU64::new(1);

fn pending() -> &'static StdMutex<Option<(u64, u64)>> {
    PENDING.get_or_init(|| StdMutex::new(None))
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct ApplyOutcome {
    pub message: String,
    /// Set when the change must be confirmed, with the time left in seconds.
    pub confirm_seconds: Option<u64>,
}

pub struct InterfaceCommit;

impl InterfaceCommit {
    pub async fn commit(
        pool: &SqlitePool,
        lock: &Arc<Mutex<()>>,
        peer: Option<IpAddr>,
    ) -> Result<ApplyOutcome, String> {
        let _guard = lock.lock().await;

        fs::create_dir_all(HISTORY_DIR).map_err(|e| e.to_string())?;

        let desired = InterfaceConfigRepository::list(pool)
            .await
            .map_err(|e| e.to_string())?;
        let previous = Self::read_snapshot(CURRENT_PATH)?;

        for cfg in &desired {
            Self::validate_exists(&cfg.name)?;
        }

        let changed = Self::changed_names(&previous, &desired);

        // Is the person pressing Apply connected through a port that is about to change?
        let risky = if changed.is_empty() {
            false
        } else {
            match peer.map(Self::unmap) {
                None => false,
                Some(ip) => match Self::management_interface(ip).await {
                    Some(dev) => changed.contains(&dev),
                    None => !ip.is_loopback(),
                },
            }
        };

        if let Err(e) = Self::apply_all(&desired, &previous).await {
            return Err(match Self::apply_all(&previous, &desired).await {
                Ok(_) => format!("Applying port settings failed, the previous settings were restored: {}", e),
                Err(revert) => format!(
                    "Applying port settings failed ({}) and restoring the previous settings also failed ({}). Check the ports on the device console.",
                    e, revert
                ),
            });
        }

        let snapshot = serde_json::to_string(&desired).map_err(|e| e.to_string())?;
        if Path::new(CURRENT_PATH).exists() {
            fs::copy(CURRENT_PATH, PREVIOUS_PATH).map_err(|e| e.to_string())?;
        } else {
            Self::write_atomic(Path::new(PREVIOUS_PATH), "[]")?;
        }
        Self::write_atomic(Path::new(CURRENT_PATH), &snapshot)?;

        if !risky {
            return Ok(ApplyOutcome {
                message: format!("Port settings applied to {} port(s)", desired.len()),
                confirm_seconds: None,
            });
        }

        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut slot) = pending().lock() {
            *slot = Some((id, now_epoch() + CONFIRM_SECONDS));
        }

        let pool = pool.clone();
        let lock = Arc::clone(lock);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(CONFIRM_SECONDS)).await;

            let still_waiting = pending()
                .lock()
                .map(|slot| matches!(*slot, Some((pid, _)) if pid == id))
                .unwrap_or(false);
            if !still_waiting {
                return;
            }

            match Self::rollback(&pool, &lock).await {
                Ok(message) => eprintln!("network: change was not confirmed in time. {}", message),
                Err(e) => eprintln!("network: automatic rollback failed: {}", e),
            }
        });

        Ok(ApplyOutcome {
            message: format!(
                "Port settings applied. Press \"Keep these settings\" within {} seconds, otherwise they are undone automatically.",
                CONFIRM_SECONDS
            ),
            confirm_seconds: Some(CONFIRM_SECONDS),
        })
    }

    /// The person reached the device again, so the change stays.
    pub fn confirm() -> Result<String, String> {
        let mut slot = pending().lock().map_err(|_| "Internal error".to_string())?;
        if slot.take().is_some() {
            Ok("Port settings confirmed".into())
        } else {
            Err("There is no change waiting for confirmation".into())
        }
    }

    pub fn seconds_left() -> Option<u64> {
        let slot = pending().lock().ok()?;
        (*slot).map(|(_, deadline)| deadline.saturating_sub(now_epoch()))
    }

    pub async fn rollback(pool: &SqlitePool, lock: &Arc<Mutex<()>>) -> Result<String, String> {
        let _guard = lock.lock().await;

        if !Path::new(PREVIOUS_PATH).exists() {
            return Err("No previous port settings available to roll back to".into());
        }

        let previous = Self::read_snapshot(PREVIOUS_PATH)?;
        let current = Self::read_snapshot(CURRENT_PATH)?;

        Self::apply_all(&previous, &current).await?;

        let previous_json = serde_json::to_string(&previous).map_err(|e| e.to_string())?;

        InterfaceConfigRepository::replace_all(pool, &previous)
            .await
            .map_err(|e| {
                format!(
                    "Rolled back on the device, but saving the old settings to the database failed: {}",
                    e
                )
            })?;

        Self::write_atomic(Path::new(CURRENT_PATH), &previous_json)?;

        if let Ok(mut slot) = pending().lock() {
            *slot = None;
        }

        Ok("Rolled back to the previous port settings".into())
    }

    pub async fn restore_on_boot(lock: &Arc<Mutex<()>>) -> Result<String, String> {
        let _guard = lock.lock().await;

        if !Path::new(CURRENT_PATH).exists() {
            return Ok("No saved port settings found, nothing was restored".into());
        }

        let current = Self::read_snapshot(CURRENT_PATH)?;
        Self::apply_all(&current, &[]).await?;

        Ok(format!("Restored settings for {} port(s)", current.len()))
    }

    /* ---------------- applying ---------------- */

    /// Writes the files for `desired`, removes the files of ports that are no longer in it
    /// (they are in `old`) and makes the settings live.
    async fn apply_all(desired: &[InterfaceConfig], old: &[InterfaceConfig]) -> Result<(), String> {
        let dir = networkd_dir();
        fs::create_dir_all(&dir)
            .map_err(|e| format!("Could not create {}: {}", dir.display(), e))?;

        for cfg in desired {
            Self::write_atomic(&dir.join(file_name(&cfg.name)), &InterfaceGenerator::render(cfg))?;
        }

        let keep: HashSet<&str> = desired.iter().map(|c| c.name.as_str()).collect();
        for cfg in old {
            if !keep.contains(cfg.name.as_str()) {
                let _ = fs::remove_file(dir.join(file_name(&cfg.name)));
            }
        }

        if Self::networkd_active().await {
            Self::run("networkctl", &["reload"]).await?;
            for cfg in desired {
                Self::run("networkctl", &["reconfigure", &cfg.name]).await?;
                if !cfg.enabled {
                    let _ = Self::run("ip", &["link", "set", "dev", &cfg.name, "down"]).await;
                }
            }
        } else {
            for cfg in desired {
                if cfg.mode == "dhcp" {
                    return Err(format!(
                        "Port {} uses DHCP, which needs systemd-networkd to be running on this system",
                        cfg.name
                    ));
                }
                for command in InterfaceGenerator::ip_commands(cfg) {
                    let args: Vec<&str> = command.iter().map(|s| s.as_str()).collect();
                    Self::run("ip", &args).await?;
                }
            }
        }

        Ok(())
    }

    /// systemd-networkd is used when it is running. Set IQSOFT_NET_BACKEND=ip to force plain
    /// `ip` commands (handy on a development machine that uses NetworkManager or netplan).
    async fn networkd_active() -> bool {
        if std::env::var("IQSOFT_NET_BACKEND").map(|v| v == "ip").unwrap_or(false) {
            return false;
        }
        Command::new("systemctl")
            .args(["is-active", "--quiet", "systemd-networkd"])
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    async fn run(program: &str, args: &[&str]) -> Result<(), String> {
        let output = Command::new(program)
            .args(args)
            .output()
            .await
            .map_err(|e| format!("Could not run {}: {}", program, e))?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!("exited with {}", output.status)
        };

        Err(format!("{} {}: {}", program, args.join(" "), detail))
    }

    /* ---------------- helpers ---------------- */

    fn unmap(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
            other => other,
        }
    }

    /// The port this device uses to reach the person who is changing settings.
    async fn management_interface(peer: IpAddr) -> Option<String> {
        let output = Command::new("ip")
            .args(["-o", "route", "get", &peer.to_string()])
            .output()
            .await
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout).to_string();
        let mut parts = text.split_whitespace();
        while let Some(part) = parts.next() {
            if part == "dev" {
                return parts.next().map(|s| s.to_string());
            }
        }
        None
    }

    fn changed_names(previous: &[InterfaceConfig], desired: &[InterfaceConfig]) -> HashSet<String> {
        let mut changed = HashSet::new();

        for d in desired {
            match previous.iter().find(|p| p.name == d.name) {
                Some(p) if p == d => {}
                _ => {
                    changed.insert(d.name.clone());
                }
            }
        }
        for p in previous {
            if !desired.iter().any(|d| d.name == p.name) {
                changed.insert(p.name.clone());
            }
        }
        changed
    }

    fn validate_exists(name: &str) -> Result<(), String> {
        if !Path::new(&format!("/sys/class/net/{}", name)).exists() {
            return Err(format!(
                "Port '{}' does not exist on this system. Remove its saved settings or check the name.",
                name
            ));
        }
        Ok(())
    }

    fn read_snapshot(path: &str) -> Result<Vec<InterfaceConfig>, String> {
        if !Path::new(path).exists() {
            return Ok(Vec::new());
        }
        let json = fs::read_to_string(path).map_err(|e| e.to_string())?;
        serde_json::from_str(&json)
            .map_err(|e| format!("Saved port snapshot {} is corrupt: {}", path, e))
    }

    fn write_atomic(path: &Path, content: &str) -> Result<(), String> {
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, content).map_err(|e| format!("Could not write {}: {}", tmp.display(), e))?;
        fs::rename(&tmp, path).map_err(|e| format!("Could not replace {}: {}", path.display(), e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(name: &str, addr: &str) -> InterfaceConfig {
        InterfaceConfig {
            name: name.into(),
            mode: "static".into(),
            addresses: vec![addr.into()],
            gateway: None,
            dns: vec![],
            mtu: None,
            enabled: true,
            comment: None,
        }
    }

    #[test]
    fn changed_names_finds_edits_additions_and_removals() {
        let previous = vec![cfg("eth0", "10.0.0.1/24"), cfg("eth1", "10.0.1.1/24")];
        let desired = vec![cfg("eth0", "10.0.0.1/24"), cfg("eth2", "10.0.2.1/24")];
        let changed = InterfaceCommit::changed_names(&previous, &desired);
        assert!(!changed.contains("eth0"));
        assert!(changed.contains("eth1"));
        assert!(changed.contains("eth2"));
    }

    #[test]
    fn mapped_addresses_are_unwrapped() {
        let mapped: IpAddr = "::ffff:192.168.1.5".parse().unwrap();
        assert_eq!(InterfaceCommit::unmap(mapped), "192.168.1.5".parse::<IpAddr>().unwrap());
    }
}
