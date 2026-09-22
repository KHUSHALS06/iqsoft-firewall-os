use crate::dns::generator::DnsGenerator;
use crate::models::dns::DnsSnapshot;
use crate::repository::dns_repository::DnsRepository;
use sqlx::SqlitePool;
use std::{fs, path::Path, sync::Arc, time::Duration};
use tokio::{process::Command, sync::Mutex};

const HISTORY_DIR: &str = "config-history";
const STAGED_PATH: &str = "config-history/dns-staged.conf";
const CURRENT_PATH: &str = "config-history/current.dns.conf";
const PREVIOUS_PATH: &str = "config-history/previous.dns.conf";
const CURRENT_DB_PATH: &str = "config-history/current.dns.json";
const PREVIOUS_DB_PATH: &str = "config-history/previous.dns.json";
const DNSMASQ_CONF_PATH: &str = "/etc/iqsoft/dnsmasq.d/dns.conf";
const DNSMASQ_SERVICE: &str = "dnsmasq";

pub struct DnsCommit;

impl DnsCommit {
    pub async fn commit(
        pool: &SqlitePool,
        lock: &Arc<Mutex<()>>,
    ) -> Result<String, String> {
        let _guard = lock.lock().await;

        fs::create_dir_all(HISTORY_DIR).map_err(|e| e.to_string())?;

        let config = DnsRepository::get_config(pool)
            .await
            .map_err(|e| e.to_string())?;
        let records = DnsRepository::list_records(pool)
            .await
            .map_err(|e| e.to_string())?;

        if config.enabled {
            for iface in &config.listen_interfaces {
                Self::validate_interface_exists(iface)?;
            }
        }

        let rendered = DnsGenerator::render(&config, &records)?;
        let enabled = config.enabled;

        let snapshot = DnsSnapshot { config, records };
        let snapshot_json =
            serde_json::to_string(&snapshot).map_err(|e| e.to_string())?;

        fs::write(STAGED_PATH, &rendered).map_err(|e| e.to_string())?;

        if enabled {
            Self::test_config(STAGED_PATH).await.map_err(|e| {
                format!("Validation failed, nothing was applied: {}", e)
            })?;
        }

        let backup = fs::read_to_string(DNSMASQ_CONF_PATH).ok();

        Self::write_live_config(&rendered)?;

        if let Err(e) = Self::apply_service().await {
            if let Some(old) = &backup {
                let _ = fs::write(DNSMASQ_CONF_PATH, old);
                let _ = Self::apply_service().await;
            }
            return Err(format!(
                "Applying DNS configuration failed, previous configuration restored: {}",
                e
            ));
        }

        if Path::new(CURRENT_PATH).exists() {
            fs::copy(CURRENT_PATH, PREVIOUS_PATH).map_err(|e| e.to_string())?;
        }
        if Path::new(CURRENT_DB_PATH).exists() {
            fs::copy(CURRENT_DB_PATH, PREVIOUS_DB_PATH).map_err(|e| e.to_string())?;
        }
        fs::write(CURRENT_PATH, &rendered).map_err(|e| e.to_string())?;
        fs::write(CURRENT_DB_PATH, &snapshot_json).map_err(|e| e.to_string())?;

        if enabled {
            Ok("DNS server updated successfully".into())
        } else {
            Ok("DNS server is disabled".into())
        }
    }

    pub async fn rollback(
        pool: &SqlitePool,
        lock: &Arc<Mutex<()>>,
    ) -> Result<String, String> {
        let _guard = lock.lock().await;

        if !Path::new(PREVIOUS_PATH).exists() || !Path::new(PREVIOUS_DB_PATH).exists() {
            return Err(
                "No previous DNS configuration available to roll back to".into(),
            );
        }

        let snapshot_json =
            fs::read_to_string(PREVIOUS_DB_PATH).map_err(|e| e.to_string())?;
        let snapshot: DnsSnapshot =
            serde_json::from_str(&snapshot_json).map_err(|e| e.to_string())?;
        let previous_conf =
            fs::read_to_string(PREVIOUS_PATH).map_err(|e| e.to_string())?;
        let enabled = snapshot.config.enabled;

        if enabled {
            Self::test_config(PREVIOUS_PATH).await.map_err(|e| {
                format!(
                    "Stored previous config failed validation, refusing to roll back: {}",
                    e
                )
            })?;
        }

        Self::write_live_config(&previous_conf)?;

        Self::apply_service()
            .await
            .map_err(|e| format!("Rollback apply failed: {}", e))?;

        if let Err(e) =
            DnsRepository::replace_all(pool, snapshot.config, snapshot.records).await
        {
            return Err(format!(
                "Rollback applied to the live DNS server, but failed to sync the database: {}. The live server and database are now out of sync — do not run /api/dns/commit until this is resolved.",
                e
            ));
        }

        fs::copy(PREVIOUS_PATH, CURRENT_PATH).map_err(|e| e.to_string())?;
        fs::copy(PREVIOUS_DB_PATH, CURRENT_DB_PATH).map_err(|e| e.to_string())?;

        Ok("Rolled back to previous DNS configuration successfully".into())
    }

    fn validate_interface_exists(name: &str) -> Result<(), String> {
        let path = format!("/sys/class/net/{}", name);
        if !Path::new(&path).exists() {
            return Err(format!(
                "Configured DNS listen interface '{}' does not exist on this system — refusing to commit",
                name
            ));
        }
        Ok(())
    }

    fn write_live_config(content: &str) -> Result<(), String> {
        if let Some(parent) = Path::new(DNSMASQ_CONF_PATH).parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(DNSMASQ_CONF_PATH, content).map_err(|e| {
            format!("Failed to write {}: {}", DNSMASQ_CONF_PATH, e)
        })
    }

    async fn test_config(path: &str) -> Result<(), String> {
        let output = Command::new("dnsmasq")
            .arg("--test")
            .arg(format!("--conf-file={}", path))
            .output()
            .await
            .map_err(|e| format!("Could not run dnsmasq: {}", e))?;

        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
        }

        Ok(())
    }

    async fn apply_service() -> Result<(), String> {
        let output = Command::new("systemctl")
            .arg("restart")
            .arg(DNSMASQ_SERVICE)
            .output()
            .await
            .map_err(|e| format!("Could not run systemctl: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "systemctl restart {} failed: {}",
                DNSMASQ_SERVICE,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        tokio::time::sleep(Duration::from_millis(700)).await;

        let active = Command::new("systemctl")
            .arg("is-active")
            .arg("--quiet")
            .arg(DNSMASQ_SERVICE)
            .status()
            .await
            .map_err(|e| format!("Could not run systemctl: {}", e))?;

        if !active.success() {
            return Err(format!(
                "{} did not stay running after restart — check 'journalctl -u {}'",
                DNSMASQ_SERVICE, DNSMASQ_SERVICE
            ));
        }

        Ok(())
    }
}
