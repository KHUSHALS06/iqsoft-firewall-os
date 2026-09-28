use crate::models::route::Route;
use crate::repository::route_repository::RouteRepository;
use crate::routing::generator::RouteGenerator;
use sqlx::SqlitePool;
use std::{fs, path::Path, sync::Arc};
use tokio::{process::Command, sync::Mutex};

const HISTORY_DIR: &str = "config-history";
const CURRENT_DB_PATH: &str = "config-history/current.routes.json";
const PREVIOUS_DB_PATH: &str = "config-history/previous.routes.json";
const STAGED_APPLY_PATH: &str = "/tmp/iqsoft-routes-apply.batch";
const STAGED_REMOVE_PATH: &str = "/tmp/iqsoft-routes-remove.batch";

pub struct RouteCommit;

impl RouteCommit {
    pub async fn commit(pool: &SqlitePool, lock: &Arc<Mutex<()>>) -> Result<String, String> {
        let _guard = lock.lock().await;

        fs::create_dir_all(HISTORY_DIR).map_err(|e| e.to_string())?;

        let routes = RouteRepository::list_routes(pool)
            .await
            .map_err(|e| e.to_string())?;
        let previous = Self::read_snapshot(CURRENT_DB_PATH)?;

        let desired = RouteGenerator::applicable(&routes);
        for route in &desired {
            if let Some(interface) = &route.interface_name {
                Self::validate_interface_exists(interface)?;
            }
        }

        let apply_script = RouteGenerator::render(&routes);
        let removal_script = RouteGenerator::render_removals(&previous, &routes);
        let snapshot_json = serde_json::to_string(&routes).map_err(|e| e.to_string())?;

        if let Err(e) = Self::run_batch(&apply_script, STAGED_APPLY_PATH, false).await {
            if e.starts_with("Could not run ip") {
                return Err(e);
            }

            return Err(match Self::revert(&routes, &previous).await {
                Ok(_) => format!("Applying routes failed, previous routes restored: {}", e),
                Err(revert_error) => format!(
                    "Applying routes failed ({}) and restoring the previous routes also failed ({}) — check the routing table manually",
                    e, revert_error
                ),
            });
        }

        let removed = Self::count_commands(&removal_script);
        let mut warning = String::new();

        if let Err(e) = Self::run_batch(&removal_script, STAGED_REMOVE_PATH, true).await {
            warning = format!(" (warning: some old routes could not be removed: {})", e);
        }

        if Path::new(CURRENT_DB_PATH).exists() {
            fs::copy(CURRENT_DB_PATH, PREVIOUS_DB_PATH).map_err(|e| e.to_string())?;
        } else {
            Self::write_atomic(PREVIOUS_DB_PATH, "[]")?;
        }
        Self::write_atomic(CURRENT_DB_PATH, &snapshot_json)?;

        Ok(format!(
            "Routing table updated: {} route(s) active, {} removed{}",
            desired.len(),
            removed,
            warning
        ))
    }

    pub async fn rollback(pool: &SqlitePool, lock: &Arc<Mutex<()>>) -> Result<String, String> {
        let _guard = lock.lock().await;

        if !Path::new(PREVIOUS_DB_PATH).exists() {
            return Err("No previous routing configuration available to roll back to".into());
        }

        let previous = Self::read_snapshot(PREVIOUS_DB_PATH)?;
        let current = Self::read_snapshot(CURRENT_DB_PATH)?;

        for route in RouteGenerator::applicable(&previous) {
            if let Some(interface) = &route.interface_name {
                Self::validate_interface_exists(interface).map_err(|e| {
                    format!("Refusing to roll back, nothing was changed: {}", e)
                })?;
            }
        }

        let apply_script = RouteGenerator::render(&previous);
        let removal_script = RouteGenerator::render_removals(&current, &previous);

        if let Err(e) = Self::run_batch(&apply_script, STAGED_APPLY_PATH, false).await {
            if e.starts_with("Could not run ip") {
                return Err(e);
            }

            return Err(match Self::revert(&previous, &current).await {
                Ok(_) => format!("Rollback failed, current routes restored: {}", e),
                Err(revert_error) => format!(
                    "Rollback failed ({}) and restoring the current routes also failed ({}) — check the routing table manually",
                    e, revert_error
                ),
            });
        }

        let mut warning = String::new();

        if let Err(e) = Self::run_batch(&removal_script, STAGED_REMOVE_PATH, true).await {
            warning = format!(" (warning: some routes could not be removed: {})", e);
        }

        let previous_json = serde_json::to_string(&previous).map_err(|e| e.to_string())?;

        if let Err(e) = RouteRepository::replace_all_routes(pool, previous).await {
            return Err(format!(
                "Rollback applied to the live routing table, but failed to sync the database: {}. The live routes and database are now out of sync — do not run /api/routes/commit until this is resolved.",
                e
            ));
        }

        Self::write_atomic(CURRENT_DB_PATH, &previous_json)?;

        Ok(format!(
            "Rolled back to previous routing configuration successfully{}",
            warning
        ))
    }

    pub async fn restore_on_boot(lock: &Arc<Mutex<()>>) -> Result<String, String> {
        let _guard = lock.lock().await;

        if !Path::new(CURRENT_DB_PATH).exists() {
            return Ok("No saved routing configuration found, nothing was restored".into());
        }

        let routes = Self::read_snapshot(CURRENT_DB_PATH)?;
        let script = RouteGenerator::render(&routes);

        Self::run_batch(&script, STAGED_APPLY_PATH, true)
            .await
            .map_err(|e| format!("Saved routes were only partly restored: {}", e))?;

        Ok(format!(
            "Restored {} saved route(s)",
            RouteGenerator::applicable(&routes).len()
        ))
    }

    async fn revert(attempted: &[Route], target: &[Route]) -> Result<(), String> {
        let restore_script = RouteGenerator::render(target);
        let cleanup_script = RouteGenerator::render_removals(attempted, target);

        Self::run_batch(&restore_script, STAGED_APPLY_PATH, true).await?;

        let _ = Self::run_batch(&cleanup_script, STAGED_REMOVE_PATH, true).await;

        Ok(())
    }

    async fn run_batch(script: &str, path: &str, force: bool) -> Result<(), String> {
        if Self::count_commands(script) == 0 {
            return Ok(());
        }

        fs::write(path, script).map_err(|e| format!("Failed to write {}: {}", path, e))?;

        let mut command = Command::new("ip");

        if force {
            command.arg("-force");
        }

        command.arg("-batch").arg(path);

        let output = command
            .output()
            .await
            .map_err(|e| format!("Could not run ip: {}", e))?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if !stderr.is_empty() {
            Err(stderr)
        } else if !stdout.is_empty() {
            Err(stdout)
        } else {
            Err(format!("ip exited with {}", output.status))
        }
    }

    fn count_commands(script: &str) -> usize {
        script
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty() && !trimmed.starts_with('#')
            })
            .count()
    }

    fn read_snapshot(path: &str) -> Result<Vec<Route>, String> {
        if !Path::new(path).exists() {
            return Ok(Vec::new());
        }

        let json = fs::read_to_string(path).map_err(|e| e.to_string())?;

        serde_json::from_str(&json)
            .map_err(|e| format!("Saved routing snapshot {} is corrupt: {}", path, e))
    }

    fn write_atomic(path: &str, content: &str) -> Result<(), String> {
        let tmp_path = format!("{}.tmp", path);
        fs::write(&tmp_path, content).map_err(|e| e.to_string())?;
        fs::rename(&tmp_path, path).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn validate_interface_exists(name: &str) -> Result<(), String> {
        let path = format!("/sys/class/net/{}", name);

        if !Path::new(&path).exists() {
            return Err(format!(
                "Route interface '{}' does not exist on this system — refusing to commit",
                name
            ));
        }

        Ok(())
    }
}
