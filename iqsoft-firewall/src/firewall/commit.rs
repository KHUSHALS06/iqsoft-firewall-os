use crate::firewall::generator::FirewallGenerator;
use crate::models::firewall_rule::FirewallRule;
use crate::repository::firewall_repository::FirewallRepository;
use crate::repository::network_config_repository::NetworkConfigRepository;
use sqlx::SqlitePool;
use std::{
    fs,
    path::Path,
    process::Command,
    sync::Arc,
};
use tokio::sync::Mutex;

const HISTORY_DIR: &str = "config-history";
const CURRENT_PATH: &str = "config-history/current.nft";
const PREVIOUS_PATH: &str = "config-history/previous.nft";
const CURRENT_RULES_PATH: &str = "config-history/current.rules.json";
const PREVIOUS_RULES_PATH: &str = "config-history/previous.rules.json";
const STAGED_PATH: &str = "/tmp/iqsoft-firewall-staged.nft";

pub struct FirewallCommit;

impl FirewallCommit {
    pub async fn commit(pool: &SqlitePool, lock: &Arc<Mutex<()>>) -> Result<String, String> {
        let _guard = lock.lock().await;

        fs::create_dir_all(HISTORY_DIR).map_err(|e| e.to_string())?;

        let net_config = NetworkConfigRepository::get(pool)
            .await
            .map_err(|e| e.to_string())?;

        Self::validate_interface_exists(&net_config.wan_interface)?;
        Self::validate_interface_exists(&net_config.lan_interface)?;

        let config = FirewallGenerator::generate(pool).await?;

        let rules_snapshot = FirewallRepository::list_rules(pool)
            .await
            .map_err(|e| e.to_string())?;
        let rules_snapshot_json =
            serde_json::to_string(&rules_snapshot).map_err(|e| e.to_string())?;

        fs::write(STAGED_PATH, &config).map_err(|e| e.to_string())?;

        let check = Command::new("nft")
            .arg("--check")
            .arg("-f")
            .arg(STAGED_PATH)
            .output()
            .map_err(|e| e.to_string())?;

        if !check.status.success() {
            return Err(format!(
                "Validation failed, nothing was applied: {}",
                String::from_utf8_lossy(&check.stderr)
            ));
        }

        if Path::new(CURRENT_PATH).exists() {
            fs::copy(CURRENT_PATH, PREVIOUS_PATH).map_err(|e| e.to_string())?;
        }
        if Path::new(CURRENT_RULES_PATH).exists() {
            fs::copy(CURRENT_RULES_PATH, PREVIOUS_RULES_PATH).map_err(|e| e.to_string())?;
        }

        let apply = Command::new("nft")
            .arg("-f")
            .arg(STAGED_PATH)
            .output()
            .map_err(|e| e.to_string())?;

        if !apply.status.success() {
            return Err(format!(
                "Apply failed after passing validation — running firewall state is unchanged from before this commit: {}",
                String::from_utf8_lossy(&apply.stderr)
            ));
        }

        fs::write(CURRENT_PATH, &config).map_err(|e| e.to_string())?;
        fs::write(CURRENT_RULES_PATH, &rules_snapshot_json).map_err(|e| e.to_string())?;

        if net_config.ip_forward_enabled {
            // Runtime effect only — does not survive reboot yet. Persisting
            // this via /etc/sysctl.d/ is a follow-up (see roadmap).
            if let Err(e) = fs::write("/proc/sys/net/ipv4/ip_forward", "1") {
                return Err(format!(
                    "Firewall rules and NAT were applied, but enabling IPv4 forwarding failed: {}. \
                     Traffic will not actually route until this is fixed — run \
                     'sysctl -w net.ipv4.ip_forward=1' manually or fix permissions and re-commit.",
                    e
                ));
            }
        }

        Ok("Firewall updated successfully".into())
    }

    fn validate_interface_exists(name: &str) -> Result<(), String> {
        let path = format!("/sys/class/net/{}", name);
        if !Path::new(&path).exists() {
            return Err(format!(
                "Configured interface '{}' does not exist on this system — refusing to commit. \
                 Check /api/network and update it to match your real WAN/LAN interfaces.",
                name
            ));
        }
        Ok(())
    }

    pub async fn rollback(pool: &SqlitePool, lock: &Arc<Mutex<()>>) -> Result<String, String> {
        let _guard = lock.lock().await;

        if !Path::new(PREVIOUS_PATH).exists() {
            return Err("No previous configuration available to roll back to".into());
        }
        if !Path::new(PREVIOUS_RULES_PATH).exists() {
            return Err(
                "No previous database snapshot available to roll back to (previous.rules.json missing)".into(),
            );
        }

        let check = Command::new("nft")
            .arg("--check")
            .arg("-f")
            .arg(PREVIOUS_PATH)
            .output()
            .map_err(|e| e.to_string())?;

        if !check.status.success() {
            return Err(format!(
                "Stored previous config failed validation, refusing to roll back: {}",
                String::from_utf8_lossy(&check.stderr)
            ));
        }

        let apply = Command::new("nft")
            .arg("-f")
            .arg(PREVIOUS_PATH)
            .output()
            .map_err(|e| e.to_string())?;

        if !apply.status.success() {
            return Err(format!(
                "Rollback apply failed: {}",
                String::from_utf8_lossy(&apply.stderr)
            ));
        }

        let rules_json = fs::read_to_string(PREVIOUS_RULES_PATH).map_err(|e| e.to_string())?;
        let rules: Vec<FirewallRule> = serde_json::from_str(&rules_json).map_err(|e| e.to_string())?;

        if let Err(e) = FirewallRepository::replace_all_rules(pool, rules).await {
            return Err(format!(
                "Rollback applied to the live firewall, but failed to sync the database: {}. The live firewall and database are now out of sync — do not run /api/commit until this is resolved.",
                e
            ));
        }

        fs::copy(PREVIOUS_PATH, CURRENT_PATH).map_err(|e| e.to_string())?;
        fs::copy(PREVIOUS_RULES_PATH, CURRENT_RULES_PATH).map_err(|e| e.to_string())?;

        Ok("Rolled back to previous configuration successfully".into())
    }
}
