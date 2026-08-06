use crate::firewall::generator::FirewallGenerator;

use sqlx::SqlitePool;

use std::{
    fs,
    process::Command,
};

pub struct FirewallCommit;

impl FirewallCommit {
    pub async fn commit(pool: &SqlitePool) -> Result<String, String> {

        // Generate nftables configuration
        let config = FirewallGenerator::generate(pool).await?;

        let path = "/tmp/iqsoft-firewall.nft";

        // Write configuration to disk
        fs::write(path, &config)
            .map_err(|e| e.to_string())?;

        // Validate configuration
        let check = Command::new("nft")
            .arg("--check")
            .arg("-f")
            .arg(path)
            .output()
            .map_err(|e| e.to_string())?;

        if !check.status.success() {
            return Err(
                String::from_utf8_lossy(&check.stderr).to_string()
            );
        }

        // Apply configuration
        let apply = Command::new("nft")
            .arg("-f")
            .arg(path)
            .output()
            .map_err(|e| e.to_string())?;

        if !apply.status.success() {
            return Err(
                String::from_utf8_lossy(&apply.stderr).to_string()
            );
        }

        Ok("Firewall updated successfully".into())
    }
}
