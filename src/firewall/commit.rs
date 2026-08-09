use crate::firewall::generator::FirewallGenerator;
use sqlx::SqlitePool;
use std::{
    fs,
    path::Path,
    process::Command,
};

const HISTORY_DIR: &str = "config-history";
const CURRENT_PATH: &str = "config-history/current.nft";
const PREVIOUS_PATH: &str = "config-history/previous.nft";
const STAGED_PATH: &str = "/tmp/iqsoft-firewall-staged.nft";

pub struct FirewallCommit;

impl FirewallCommit {
    pub async fn commit(pool: &SqlitePool) -> Result<String, String> {
        fs::create_dir_all(HISTORY_DIR).map_err(|e| e.to_string())?;

        // Generate nftables configuration (includes flush ruleset)
        let config = FirewallGenerator::generate(pool).await?;

        // Write to a staging file first — never touch the running
        // config until it's validated
        fs::write(STAGED_PATH, &config).map_err(|e| e.to_string())?;

        // Validate before applying anything
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

        // Rotate: whatever was "current" becomes the rollback target,
        // but only if a current config already exists (first-ever commit won't)
        if Path::new(CURRENT_PATH).exists() {
            fs::copy(CURRENT_PATH, PREVIOUS_PATH).map_err(|e| e.to_string())?;
        }

        // Apply the validated staged config
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

        // Only mark as "current" after a successful apply
        fs::write(CURRENT_PATH, &config).map_err(|e| e.to_string())?;

        Ok("Firewall updated successfully".into())
    }

    pub async fn rollback() -> Result<String, String> {
        if !Path::new(PREVIOUS_PATH).exists() {
            return Err("No previous configuration available to roll back to".into());
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

        // The previous config is now live — it becomes "current"
        fs::copy(PREVIOUS_PATH, CURRENT_PATH).map_err(|e| e.to_string())?;

        Ok("Rolled back to previous configuration successfully".into())
    }
}
