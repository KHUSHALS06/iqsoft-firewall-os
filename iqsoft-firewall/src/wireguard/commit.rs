use crate::models::wireguard::{WireguardConfig, WireguardSnapshot};
use crate::repository::wireguard_repository::WireguardRepository;
use crate::wireguard::generator::WireguardGenerator;
use ipnet::IpNet;
use sqlx::SqlitePool;
use std::collections::BTreeSet;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::process::Stdio;
use std::{fs, path::Path, sync::Arc};
use tokio::{io::AsyncWriteExt, process::Command, sync::Mutex};

const HISTORY_DIR: &str = "config-history";
const CURRENT_DB_PATH: &str = "config-history/current.wireguard.json";
const PREVIOUS_DB_PATH: &str = "config-history/previous.wireguard.json";
const CHECK_INTERFACE: &str = "iqsoftchk0";

pub struct WireguardCommit;

impl WireguardCommit {
    pub async fn commit(pool: &SqlitePool, lock: &Arc<Mutex<()>>) -> Result<String, String> {
        let _guard = lock.lock().await;

        fs::create_dir_all(HISTORY_DIR).map_err(|e| e.to_string())?;

        let config = WireguardRepository::get_config(pool)
            .await
            .map_err(|e| e.to_string())?;
        let peers = WireguardRepository::list_peers(pool)
            .await
            .map_err(|e| e.to_string())?;

        let target = WireguardSnapshot { config, peers };
        let live = Self::read_snapshot(CURRENT_DB_PATH)?;

        // Everything below this block can fail without touching the live tunnel.
        let rendered = WireguardGenerator::render(&target.config, &target.peers)?;

        if target.config.enabled {
            Self::check_name(&target.config.interface_name)?;
            Self::check_interface_available(&target.config.interface_name)?;

            Self::trial_load(&rendered)
                .await
                .map_err(|e| format!("Validation failed, nothing was applied: {}", e))?;
        }

        let snapshot_json = serde_json::to_string(&target).map_err(|e| e.to_string())?;

        if let Err(e) = Self::apply_state(&target, live.as_ref()).await {
            let fallback = match &live {
                Some(snapshot) => snapshot.clone(),
                None => Self::empty_disabled(&target.config),
            };

            return Err(match Self::apply_state(&fallback, Some(&target)).await {
                Ok(_) => format!(
                    "Applying WireGuard failed, previous configuration restored: {}",
                    e
                ),
                Err(revert_error) => format!(
                    "Applying WireGuard failed ({}) and restoring the previous configuration also failed ({}) — check 'wg show' and 'ip addr' manually",
                    e, revert_error
                ),
            });
        }

        if Path::new(CURRENT_DB_PATH).exists() {
            fs::copy(CURRENT_DB_PATH, PREVIOUS_DB_PATH).map_err(|e| e.to_string())?;
            fs::set_permissions(PREVIOUS_DB_PATH, fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        } else {
            let empty = Self::empty_disabled(&target.config);
            let empty_json = serde_json::to_string(&empty).map_err(|e| e.to_string())?;
            Self::write_private(PREVIOUS_DB_PATH, &empty_json)?;
        }
        Self::write_private(CURRENT_DB_PATH, &snapshot_json)?;

        if target.config.enabled {
            Ok(format!(
                "WireGuard updated: interface {} is up with {} peer(s)",
                target.config.interface_name,
                rendered.matches("[Peer]").count()
            ))
        } else {
            Ok("WireGuard is disabled".into())
        }
    }

    pub async fn rollback(pool: &SqlitePool, lock: &Arc<Mutex<()>>) -> Result<String, String> {
        let _guard = lock.lock().await;

        if !Path::new(PREVIOUS_DB_PATH).exists() {
            return Err("No previous WireGuard configuration available to roll back to".into());
        }

        let previous = Self::read_snapshot(PREVIOUS_DB_PATH)?
            .ok_or_else(|| "No previous WireGuard configuration available to roll back to".to_string())?;
        let current = Self::read_snapshot(CURRENT_DB_PATH)?;

        if previous.config.enabled {
            Self::check_name(&previous.config.interface_name)?;
            Self::check_interface_available(&previous.config.interface_name)
                .map_err(|e| format!("Refusing to roll back, nothing was changed: {}", e))?;
        }

        if let Err(e) = Self::apply_state(&previous, current.as_ref()).await {
            let fallback = match &current {
                Some(snapshot) => snapshot.clone(),
                None => Self::empty_disabled(&previous.config),
            };

            return Err(match Self::apply_state(&fallback, Some(&previous)).await {
                Ok(_) => format!("Rollback failed, current configuration restored: {}", e),
                Err(revert_error) => format!(
                    "Rollback failed ({}) and restoring the current configuration also failed ({}) — check 'wg show' and 'ip addr' manually",
                    e, revert_error
                ),
            });
        }

        let previous_json = serde_json::to_string(&previous).map_err(|e| e.to_string())?;

        if let Err(e) = WireguardRepository::replace_all(
            pool,
            previous.config.clone(),
            previous.peers.clone(),
        )
        .await
        {
            return Err(format!(
                "Rollback applied to the live tunnel, but failed to sync the database: {}. The live tunnel and database are now out of sync — do not run /api/wireguard/commit until this is resolved.",
                e
            ));
        }

        Self::write_private(CURRENT_DB_PATH, &previous_json)?;

        Ok("Rolled back to previous WireGuard configuration successfully".into())
    }

    pub async fn restore_on_boot(lock: &Arc<Mutex<()>>) -> Result<String, String> {
        let _guard = lock.lock().await;

        let snapshot = match Self::read_snapshot(CURRENT_DB_PATH)? {
            Some(snapshot) => snapshot,
            None => {
                return Ok("No saved WireGuard configuration found, nothing was restored".into())
            }
        };

        if !snapshot.config.enabled {
            return Ok("WireGuard is disabled, nothing was restored".into());
        }

        Self::apply_state(&snapshot, None).await?;

        Ok(format!(
            "Restored WireGuard interface {}",
            snapshot.config.interface_name
        ))
    }

    /// Makes the running system match `target`. `live` is what this program last
    /// applied (or the attempt that is being undone), and tells us what to tear down.
    async fn apply_state(
        target: &WireguardSnapshot,
        live: Option<&WireguardSnapshot>,
    ) -> Result<(), String> {
        let live_config = live.map(|s| &s.config).filter(|c| c.enabled);

        if let Some(old) = live_config {
            Self::check_name(&old.interface_name)?;
        }

        if !target.config.enabled {
            if let Some(old) = live_config {
                Self::remove_interface(&old.interface_name).await?;
            }
            return Ok(());
        }

        let config = &target.config;
        Self::check_name(&config.interface_name)?;

        let iface = config.interface_name.as_str();
        let rendered = WireguardGenerator::render(config, &target.peers)?;
        let wg_text = Self::strip_for_wg(&rendered);

        Self::check_interface_available(iface)?;

        let can_sync = match live_config {
            Some(old) => {
                old.interface_name == config.interface_name
                    && old.address == config.address
                    && old.mtu == config.mtu
                    && Self::interface_is_wireguard(iface)
            }
            None => false,
        };

        if can_sync {
            // Same interface, address and MTU: update keys/peers in place so connected
            // clients are not dropped, then fix the routes that syncconf does not touch.
            Self::run_stdin("wg", &["syncconf", iface, "/dev/stdin"], &wg_text).await?;

            let old_routes = match live {
                Some(snapshot) => WireguardGenerator::render(&snapshot.config, &snapshot.peers)
                    .map(|text| Self::routes_from_rendered(&text))
                    .unwrap_or_default(),
                None => BTreeSet::new(),
            };
            let new_routes = Self::routes_from_rendered(&rendered);

            return Self::sync_routes(iface, &old_routes, &new_routes).await;
        }

        if let Some(old) = live_config {
            if old.interface_name != config.interface_name {
                Self::remove_interface(&old.interface_name).await?;
            }
        }

        Self::remove_interface(iface).await?;

        if let Err(e) = Self::bring_up(config, &wg_text, &rendered).await {
            // Do not leave a half-built interface behind.
            let _ = Self::remove_interface(iface).await;
            return Err(e);
        }

        Ok(())
    }

    /// Builds the interface step by step with ip and wg, so nothing depends on
    /// wg-quick (which wants sudo and shell access).
    async fn bring_up(
        config: &WireguardConfig,
        wg_text: &str,
        rendered: &str,
    ) -> Result<(), String> {
        let iface = config.interface_name.as_str();

        Self::run("ip", &["link", "add", "dev", iface, "type", "wireguard"]).await?;

        Self::run_stdin("wg", &["setconf", iface, "/dev/stdin"], wg_text).await?;

        let mut args: Vec<&str> = Vec::new();
        if config.address.contains(':') {
            args.push("-6");
        }
        args.extend(["address", "add", config.address.as_str(), "dev", iface]);
        Self::run("ip", &args).await?;

        let mtu_text;
        let mut link: Vec<&str> = vec!["link", "set"];
        if let Some(mtu) = config.mtu {
            mtu_text = mtu.to_string();
            link.extend(["mtu", mtu_text.as_str()]);
        }
        link.extend(["up", "dev", iface]);
        Self::run("ip", &link).await?;

        for net in Self::routes_from_rendered(rendered) {
            Self::route_command("replace", iface, &net).await?;
        }

        Ok(())
    }

    /// wg only understands its own keys. Everything wg-quick would normally
    /// handle (address, MTU, DNS, hooks) is removed before the text goes to wg.
    fn strip_for_wg(rendered: &str) -> String {
        const WG_QUICK_ONLY: [&str; 9] = [
            "address", "mtu", "dns", "table", "saveconfig", "preup", "postup", "predown",
            "postdown",
        ];

        let mut out = String::new();

        for line in rendered.lines() {
            let key = line
                .split('=')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();

            if WG_QUICK_ONLY.contains(&key.as_str()) {
                continue;
            }

            out.push_str(line);
            out.push('\n');
        }

        out
    }

    async fn sync_routes(
        iface: &str,
        old: &BTreeSet<IpNet>,
        new: &BTreeSet<IpNet>,
    ) -> Result<(), String> {
        for net in new {
            Self::route_command("replace", iface, net).await?;
        }

        for net in old.difference(new) {
            // The route may already be gone, that is fine.
            let _ = Self::route_command("del", iface, net).await;
        }

        Ok(())
    }

    async fn route_command(action: &str, iface: &str, net: &IpNet) -> Result<(), String> {
        let network = net.to_string();
        let mut args: Vec<&str> = Vec::new();

        if net.addr().is_ipv6() {
            args.push("-6");
        }

        args.extend([
            "route",
            action,
            network.as_str(),
            "dev",
            iface,
        ]);

        Self::run("ip", &args).await.map(|_| ())
    }

    fn routes_from_rendered(rendered: &str) -> BTreeSet<IpNet> {
        let mut routes = BTreeSet::new();

        for line in rendered.lines() {
            if let Some(list) = line.trim().strip_prefix("AllowedIPs = ") {
                for item in list.split(',') {
                    if let Ok(net) = item.trim().parse::<IpNet>() {
                        routes.insert(net);
                    }
                }
            }
        }

        routes
    }

    /// Loads the new config into a throw-away interface first. This proves the
    /// kernel supports WireGuard and that wg accepts every line, before the
    /// live tunnel is touched. The throw-away interface is always removed.
    async fn trial_load(rendered: &str) -> Result<(), String> {
        let wg_text = Self::strip_for_wg(rendered);

        if Self::interface_exists(CHECK_INTERFACE) {
            let _ = Self::run("ip", &["link", "delete", "dev", CHECK_INTERFACE]).await;
        }

        Self::run(
            "ip",
            &["link", "add", "dev", CHECK_INTERFACE, "type", "wireguard"],
        )
        .await
        .map_err(|e| {
            format!(
                "{} (does this kernel support WireGuard, and is the firewall running as root?)",
                e
            )
        })?;

        let result = Self::run_stdin(
            "wg",
            &["setconf", CHECK_INTERFACE, "/dev/stdin"],
            &wg_text,
        )
        .await;

        let _ = Self::run("ip", &["link", "delete", "dev", CHECK_INTERFACE]).await;

        result.map(|_| ())
    }

    async fn remove_interface(name: &str) -> Result<(), String> {
        if !Self::interface_exists(name) {
            return Ok(());
        }

        if !Self::interface_is_wireguard(name) {
            return Err(format!(
                "Interface '{}' exists but is not a WireGuard interface, refusing to remove it",
                name
            ));
        }

        Self::run("ip", &["link", "delete", "dev", name])
            .await
            .map(|_| ())
    }

    fn check_interface_available(name: &str) -> Result<(), String> {
        if Self::interface_exists(name) && !Self::interface_is_wireguard(name) {
            return Err(format!(
                "Interface '{}' already exists on this system and is not a WireGuard interface, choose another interface name",
                name
            ));
        }

        Ok(())
    }

    fn interface_exists(name: &str) -> bool {
        Path::new(&format!("/sys/class/net/{}", name)).exists()
    }

    fn interface_is_wireguard(name: &str) -> bool {
        fs::read_to_string(format!("/sys/class/net/{}/uevent", name))
            .map(|text| text.lines().any(|line| line.trim() == "DEVTYPE=wireguard"))
            .unwrap_or(false)
    }

    fn check_name(name: &str) -> Result<(), String> {
        let valid = !name.is_empty()
            && name.len() <= 15
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');

        if valid {
            Ok(())
        } else {
            Err(format!("Invalid WireGuard interface name '{}'", name))
        }
    }

    /// Used as the "nothing was active before" state for a first commit.
    fn empty_disabled(config: &WireguardConfig) -> WireguardSnapshot {
        let mut config = config.clone();
        config.enabled = false;

        WireguardSnapshot {
            config,
            peers: Vec::new(),
        }
    }

    async fn run(program: &str, args: &[&str]) -> Result<String, String> {
        let output = Command::new(program)
            .args(args)
            .output()
            .await
            .map_err(|e| format!("Could not run {}: {}", program, e))?;

        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
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

        Err(format!("{} {} failed: {}", program, args.join(" "), detail))
    }

    /// Like run, but feeds `input` to the program's stdin. Keys therefore never
    /// have to be written to a temporary file.
    async fn run_stdin(program: &str, args: &[&str], input: &str) -> Result<String, String> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Could not run {}: {}", program, e))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(input.as_bytes())
                .await
                .map_err(|e| format!("Could not write to {}: {}", program, e))?;
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| format!("Could not run {}: {}", program, e))?;

        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let detail = if stderr.is_empty() {
            format!("exited with {}", output.status)
        } else {
            stderr
        };

        Err(format!("{} {} failed: {}", program, args.join(" "), detail))
    }

    fn read_snapshot(path: &str) -> Result<Option<WireguardSnapshot>, String> {
        if !Path::new(path).exists() {
            return Ok(None);
        }

        let json = fs::read_to_string(path).map_err(|e| e.to_string())?;

        serde_json::from_str(&json)
            .map(Some)
            .map_err(|e| format!("Saved WireGuard snapshot {} is corrupt: {}", path, e))
    }

    /// Keys live in these files, so they are created readable by the owner only.
    fn write_private(path: &str, content: &str) -> Result<(), String> {
        let tmp_path = format!("{}.tmp", path);
        let _ = fs::remove_file(&tmp_path);

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| format!("Failed to write {}: {}", tmp_path, e))?;

        file.write_all(content.as_bytes())
            .map_err(|e| format!("Failed to write {}: {}", tmp_path, e))?;
        file.sync_all().map_err(|e| e.to_string())?;
        drop(file);

        fs::rename(&tmp_path, path).map_err(|e| format!("Failed to write {}: {}", path, e))
    }
}

#[cfg(test)]
mod tests {
    use super::WireguardCommit;

    #[test]
    fn routes_are_read_from_peer_sections() {
        let text = "[Interface]\nAddress = 10.8.0.1/24\n\n[Peer]\n# a\nPublicKey = x\nAllowedIPs = 10.8.0.2/32, 192.168.50.0/24\n\n[Peer]\nAllowedIPs = fd00:8::2/128\n";
        let routes = WireguardCommit::routes_from_rendered(text);

        assert_eq!(routes.len(), 3);
        assert!(routes.contains(&"10.8.0.2/32".parse().unwrap()));
        assert!(routes.contains(&"192.168.50.0/24".parse().unwrap()));
        assert!(routes.contains(&"fd00:8::2/128".parse().unwrap()));
    }

    #[test]
    fn wg_quick_only_lines_are_removed_before_wg_sees_the_config() {
        let text = "[Interface]\nAddress = 10.8.0.1/24\nListenPort = 51820\nPrivateKey = k\nMTU = 1380\nSaveConfig = false\n\n[Peer]\n# laptop\nPublicKey = p\nAllowedIPs = 10.8.0.2/32\n";
        let out = WireguardCommit::strip_for_wg(text);

        assert_eq!(
            out,
            "[Interface]\nListenPort = 51820\nPrivateKey = k\n\n[Peer]\n# laptop\nPublicKey = p\nAllowedIPs = 10.8.0.2/32\n"
        );
    }

    #[test]
    fn interface_names_are_checked_before_use_in_paths() {
        assert!(WireguardCommit::check_name("wg0").is_ok());
        assert!(WireguardCommit::check_name("wg-office_1").is_ok());
        assert!(WireguardCommit::check_name("").is_err());
        assert!(WireguardCommit::check_name("../etc").is_err());
        assert!(WireguardCommit::check_name("wg0.conf").is_err());
        assert!(WireguardCommit::check_name("abcdefghijklmnop").is_err());
    }
}
