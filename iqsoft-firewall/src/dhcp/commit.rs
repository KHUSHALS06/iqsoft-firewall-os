use crate::dhcp::generator::DhcpGenerator;
use crate::models::dhcp::DhcpSnapshot;
use crate::repository::dhcp_repository::DhcpRepository;
use crate::repository::network_config_repository::NetworkConfigRepository;
use sqlx::SqlitePool;
use std::{fs, path::Path, sync::Arc, time::Duration};
use tokio::{process::Command, sync::Mutex};

const HISTORY_DIR: &str = "config-history";
const STAGED_PATH: &str = "config-history/dhcp-staged.conf";
const CURRENT_PATH: &str = "config-history/current.dhcp.conf";
const PREVIOUS_PATH: &str = "config-history/previous.dhcp.conf";
const CURRENT_DB_PATH: &str = "config-history/current.dhcp.json";
const PREVIOUS_DB_PATH: &str = "config-history/previous.dhcp.json";
const DNSMASQ_CONF_PATH: &str = "/etc/iqsoft/dnsmasq.d/dhcp.conf";
const DNSMASQ_SERVICE: &str = "dnsmasq";

pub struct DhcpCommit;

impl DhcpCommit {
    pub async fn commit(
        pool: &SqlitePool,
        lock: &Arc<Mutex<()>>,
    ) -> Result<String, String> {
        let _guard = lock.lock().await;

        fs::create_dir_all(HISTORY_DIR).map_err(|e| e.to_string())?;

        let config = DhcpRepository::get_config(pool)
            .await
            .map_err(|e| e.to_string())?;
        let reservations = DhcpRepository::list_reservations(pool)
            .await
            .map_err(|e| e.to_string())?;

        if config.enabled {
            let net = NetworkConfigRepository::get(pool)
                .await
                .map_err(|e| e.to_string())?;

            if config.interface_name.trim() == net.wan_interface.trim() {
                return Err(
                    "Refusing to serve DHCP on the WAN interface".into(),
                );
            }

            Self::validate_interface_exists(config.interface_name.trim())?;
        }

        let rendered = DhcpGenerator::render(&config, &reservations)?;
        let enabled = config.enabled;

        let snapshot = DhcpSnapshot {
            config,
            reservations,
        };
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

        if let Err(e) = Self::apply_service(enabled).await {
            if let Some(old) = &backup {
                let _ = fs::write(DNSMASQ_CONF_PATH, old);
                let _ = Self::apply_service(old.contains("dhcp-range=")).await;
            }
            return Err(format!(
                "Applying DHCP configuration failed, previous configuration restored: {}",
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
            Ok("DHCP server updated successfully".into())
        } else {
            Ok("DHCP server is disabled and stopped".into())
        }
    }

    pub async fn rollback(
        pool: &SqlitePool,
        lock: &Arc<Mutex<()>>,
    ) -> Result<String, String> {
        let _guard = lock.lock().await;

        if !Path::new(PREVIOUS_PATH).exists() || !Path::new(PREVIOUS_DB_PATH).exists() {
            return Err(
                "No previous DHCP configuration available to roll back to".into(),
            );
        }

        let snapshot_json =
            fs::read_to_string(PREVIOUS_DB_PATH).map_err(|e| e.to_string())?;
        let snapshot: DhcpSnapshot =
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

        Self::apply_service(enabled)
            .await
            .map_err(|e| format!("Rollback apply failed: {}", e))?;

        if let Err(e) =
            DhcpRepository::replace_all(pool, snapshot.config, snapshot.reservations).await
        {
            return Err(format!(
                "Rollback applied to the live DHCP server, but failed to sync the database: {}. The live server and database are now out of sync — do not run /api/dhcp/commit until this is resolved.",
                e
            ));
        }

        fs::copy(PREVIOUS_PATH, CURRENT_PATH).map_err(|e| e.to_string())?;
        fs::copy(PREVIOUS_DB_PATH, CURRENT_DB_PATH).map_err(|e| e.to_string())?;

        Ok("Rolled back to previous DHCP configuration successfully".into())
    }

    fn validate_interface_exists(name: &str) -> Result<(), String> {
        let path = format!("/sys/class/net/{}", name);
        if !Path::new(&path).exists() {
            return Err(format!(
                "Configured DHCP interface '{}' does not exist on this system — refusing to commit",
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

    async fn apply_service(enabled: bool) -> Result<(), String> {
        let action = if enabled { "restart" } else { "stop" };

        let output = Command::new("systemctl")
            .arg(action)
            .arg(DNSMASQ_SERVICE)
            .output()
            .await
            .map_err(|e| format!("Could not run systemctl: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "systemctl {} {} failed: {}",
                action,
                DNSMASQ_SERVICE,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        if enabled {
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
        }

        Ok(())
    }
}
