use crate::models::overlay::{OverlaySettings, OverlayTunnel};
use crate::models::sdwan::SdwanLink;
use crate::overlay::generator::{is_overlay_interface, FileKind, OverlayGenerator, OverlayInput};
use crate::repository::overlay_repository::OverlayRepository;
use crate::repository::sdwan_repository::SdwanRepository;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Mutex;

const HISTORY_DIR: &str = "config-history";
const CURRENT_JSON: &str = "current.overlay.json";
const PREVIOUS_JSON: &str = "previous.overlay.json";
const STAGED_IP_PATH: &str = "/tmp/iqsoft-overlay.batch";

/// Where the generated files go.
pub const SWANCTL_CONF: &str = "/etc/swanctl/swanctl.conf";
pub const CHARON_CONF: &str = "/etc/strongswan.d/iqsoft.conf";
pub const FRR_CONF: &str = "/etc/frr/frr.conf";

/// Where the tunnel service looks for certificate files (the tunnels name them without a path).
const X509_DIR: &str = "/etc/swanctl/x509";
const X509CA_DIR: &str = "/etc/swanctl/x509ca";
const PRIVATE_DIR: &str = "/etc/swanctl/private";

/// systemd unit names. Neither is enabled at boot: the commit starts them, and the boot
/// restore starts them again after a reboot.
const IPSEC_SERVICE: &str = "strongswan";
const ROUTING_SERVICE: &str = "frr";

/// The tunnel config holds the pre-shared keys, so only root may read it.
const MODE_PRIVATE: u32 = 0o600;
/// Nothing secret in these two (the routing daemon runs as its own user and must read its file).
const MODE_PUBLIC: u32 = 0o644;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// The tunnel service needs a moment before it accepts its first command after a start.
const SWANCTL_ATTEMPTS: usize = 10;
const SWANCTL_RETRY_DELAY: Duration = Duration::from_millis(500);

/// Everything the commit needs from the outside world. The real one talks to the
/// system; the tests use a fake that only writes down what it was asked to do.
#[allow(async_fn_in_trait)]
trait Backend {
    fn history_dir(&self) -> PathBuf;
    fn interface_exists(&self, name: &str) -> bool;
    /// The overlay (xfrm) interfaces that exist right now.
    fn overlay_interfaces(&self) -> Vec<String>;
    fn read_file(&self, path: &Path) -> Option<String>;
    fn file_exists(&self, path: &Path) -> bool;
    fn write_file(&self, path: &Path, content: &str, mode: u32) -> Result<(), String>;
    /// With `force`, failing lines are expected and ignored (used for cleaning up).
    async fn ip_batch(&self, script: &str, force: bool) -> Result<(), String>;
    async fn systemctl(&self, args: &[&str]) -> Result<(), String>;
    async fn swanctl(&self, args: &[&str]) -> Result<(), String>;
}

async fn run_command(program: &str, args: &[&str]) -> Result<String, String> {
    use tokio::process::Command;

    let child = Command::new(program).args(args).kill_on_drop(true).output();

    let output = match tokio::time::timeout(COMMAND_TIMEOUT, child).await {
        Err(_) => {
            return Err(format!(
                "{} did not finish within {} seconds",
                program,
                COMMAND_TIMEOUT.as_secs()
            ));
        }
        Ok(Err(e)) => return Err(format!("could not run {}: {}", program, e)),
        Ok(Ok(output)) => output,
    };

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if output.status.success() {
        return Ok(stdout);
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if !stderr.is_empty() {
        Err(stderr)
    } else if !stdout.is_empty() {
        Err(stdout)
    } else {
        Err(format!("{} exited with {}", program, output.status))
    }
}

struct SystemBackend;

impl Backend for SystemBackend {
    fn history_dir(&self) -> PathBuf {
        PathBuf::from(HISTORY_DIR)
    }

    fn interface_exists(&self, name: &str) -> bool {
        Path::new(&format!("/sys/class/net/{}", name)).exists()
    }

    fn overlay_interfaces(&self) -> Vec<String> {
        match fs::read_dir("/sys/class/net") {
            Ok(entries) => entries
                .filter_map(|entry| entry.ok())
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|name| is_overlay_interface(name))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn read_file(&self, path: &Path) -> Option<String> {
        fs::read_to_string(path).ok()
    }

    fn file_exists(&self, path: &Path) -> bool {
        path.is_file()
    }

    fn write_file(&self, path: &Path, content: &str, mode: u32) -> Result<(), String> {
        if cfg!(test) {
            return Err("files are not touched in test builds".to_string());
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create {}: {}", parent.display(), e))?;
        }

        write_atomic(path, content, mode)
            .map_err(|e| format!("Failed to write {}: {}", path.display(), e))
    }

    async fn ip_batch(&self, script: &str, force: bool) -> Result<(), String> {
        if cfg!(test) {
            return Err("ip is not touched in test builds".to_string());
        }

        if count_commands(script) == 0 {
            return Ok(());
        }

        fs::write(STAGED_IP_PATH, script)
            .map_err(|e| format!("Failed to write {}: {}", STAGED_IP_PATH, e))?;

        let mut command = tokio::process::Command::new("ip");

        if force {
            command.arg("-force");
        }

        command.arg("-batch").arg(STAGED_IP_PATH);

        let output = command
            .output()
            .await
            .map_err(|e| format!("Could not run ip: {}", e))?;

        if output.status.success() || force {
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

    async fn systemctl(&self, args: &[&str]) -> Result<(), String> {
        if cfg!(test) {
            return Err("systemctl is not touched in test builds".to_string());
        }

        run_command("systemctl", args).await.map(|_| ())
    }

    async fn swanctl(&self, args: &[&str]) -> Result<(), String> {
        if cfg!(test) {
            return Err("swanctl is not touched in test builds".to_string());
        }

        let mut last_error = String::new();

        for attempt in 0..SWANCTL_ATTEMPTS {
            match run_command("swanctl", args).await {
                Ok(_) => return Ok(()),
                Err(e) => last_error = e,
            }

            if attempt + 1 < SWANCTL_ATTEMPTS {
                tokio::time::sleep(SWANCTL_RETRY_DELAY).await;
            }
        }

        Err(last_error)
    }
}

/// What was applied: the settings, the tunnels (with their keys) and the WAN links, as
/// the generator saw them. The saved file holds secrets, so it is written owner-only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlaySnapshot {
    pub settings: OverlaySettings,
    pub tunnels: Vec<OverlayTunnel>,
    pub links: Vec<SdwanLink>,
}

impl OverlaySnapshot {
    fn from_input(input: &OverlayInput) -> Self {
        OverlaySnapshot {
            settings: input.settings.clone(),
            tunnels: input.tunnels.clone(),
            links: input.links.clone(),
        }
    }

    fn to_input(&self) -> OverlayInput {
        OverlayInput {
            settings: self.settings.clone(),
            tunnels: self.tunnels.clone(),
            links: self.links.clone(),
        }
    }
}

/// The generated texts for one configuration.
#[derive(Debug, Clone, PartialEq)]
struct Rendered {
    swanctl: String,
    charon: String,
    frr: String,
    ip: String,
    /// How many tunnels will actually run (0 means the overlay is effectively off).
    tunnels: usize,
}

impl Rendered {
    fn of(input: &OverlayInput) -> Self {
        Rendered {
            swanctl: OverlayGenerator::render_swanctl(input),
            charon: OverlayGenerator::render_charon_conf(),
            frr: OverlayGenerator::render_frr(input),
            ip: OverlayGenerator::render_ip_apply(input),
            tunnels: OverlayGenerator::active_tunnels(input).len(),
        }
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

fn switched_off() -> OverlayInput {
    OverlayInput {
        settings: OverlaySettings::default(),
        tunnels: Vec::new(),
        links: Vec::new(),
    }
}

fn read_snapshot(path: &Path) -> Result<Option<OverlaySnapshot>, String> {
    if !path.exists() {
        return Ok(None);
    }

    let json = fs::read_to_string(path).map_err(|e| e.to_string())?;

    serde_json::from_str(&json).map(Some).map_err(|e| {
        format!(
            "Saved overlay snapshot {} is corrupt: {}",
            path.display(),
            e
        )
    })
}

/// Writes through a temporary file so a crash never leaves half a file behind. The file
/// is created with `mode` from the start, so a secret is never readable by others, not
/// even for a moment.
fn write_atomic(path: &Path, content: &str, mode: u32) -> Result<(), String> {
    use std::io::Write;

    let tmp_path = path.with_extension("tmp");

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }

    {
        let mut file = options.open(&tmp_path).map_err(|e| e.to_string())?;
        file.write_all(content.as_bytes()).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
    }

    // The mode above only counts for a file that is new.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(mode))
            .map_err(|e| e.to_string())?;
    }

    #[cfg(not(unix))]
    let _ = mode;

    fs::rename(&tmp_path, path).map_err(|e| e.to_string())?;

    Ok(())
}

fn check_interfaces<B: Backend>(backend: &B, input: &OverlayInput) -> Result<(), String> {
    for interface in OverlayGenerator::link_interfaces(input) {
        if !backend.interface_exists(&interface) {
            return Err(format!(
                "WAN interface '{}' does not exist on this system - refusing to apply the overlay",
                interface
            ));
        }
    }

    Ok(())
}

fn check_files<B: Backend>(backend: &B, input: &OverlayInput) -> Result<(), String> {
    for file in OverlayGenerator::required_files(input) {
        let (dir, label) = match file.kind {
            FileKind::Certificate => (X509_DIR, "Certificate"),
            FileKind::PrivateKey => (PRIVATE_DIR, "Private key"),
            FileKind::CaCertificate => (X509CA_DIR, "CA certificate"),
        };

        if !backend.file_exists(&Path::new(dir).join(&file.name)) {
            return Err(format!(
                "{} '{}' of tunnel '{}' is not on this system - refusing to apply the overlay",
                label, file.name, file.tunnel
            ));
        }
    }

    Ok(())
}

/// Stops the overlay and removes what it created. Best effort: switching off must work
/// on a box where the services were never installed or started.
async fn stop_overlay<B: Backend>(backend: &B, rendered: &Rendered) -> Result<(), String> {
    for service in [ROUTING_SERVICE, IPSEC_SERVICE] {
        if let Err(e) = backend.systemctl(&["stop", service]).await {
            eprintln!("WARNING: could not stop {}: {}", service, e);
        }
    }

    backend
        .ip_batch(
            &OverlayGenerator::render_ip_remove(&backend.overlay_interfaces()),
            true,
        )
        .await?;

    // Empty configs, so a reboot starts nothing even if a service is started by hand.
    let empties = [
        (SWANCTL_CONF, &rendered.swanctl, MODE_PRIVATE),
        (FRR_CONF, &rendered.frr, MODE_PUBLIC),
    ];

    for (path, content, mode) in empties {
        if let Err(e) = backend.write_file(Path::new(path), content, mode) {
            eprintln!("WARNING: {}", e);
        }
    }

    Ok(())
}

/// Makes the running system match `input`.
///
/// Order matters: the config files first, then the interfaces and routes to the peers
/// (the routing config names the interfaces), then the tunnels, then OSPF on top.
/// A service whose config did not change is only started (a no-op when it already runs),
/// so a commit that only changes OSPF does not drop the tunnels.
async fn apply_state<B: Backend>(backend: &B, input: &OverlayInput) -> Result<(), String> {
    let rendered = Rendered::of(input);

    if rendered.tunnels == 0 {
        return stop_overlay(backend, &rendered).await;
    }

    check_interfaces(backend, input)?;
    check_files(backend, input)?;

    let swanctl_path = Path::new(SWANCTL_CONF);
    let charon_path = Path::new(CHARON_CONF);
    let frr_path = Path::new(FRR_CONF);

    let tunnel_service_changed = backend.read_file(swanctl_path).as_deref()
        != Some(rendered.swanctl.as_str())
        || backend.read_file(charon_path).as_deref() != Some(rendered.charon.as_str());
    let routing_changed = backend.read_file(frr_path).as_deref() != Some(rendered.frr.as_str());

    backend.write_file(charon_path, &rendered.charon, MODE_PUBLIC)?;
    backend.write_file(swanctl_path, &rendered.swanctl, MODE_PRIVATE)?;
    backend.write_file(frr_path, &rendered.frr, MODE_PUBLIC)?;

    backend
        .ip_batch(
            &OverlayGenerator::render_ip_remove(&backend.overlay_interfaces()),
            true,
        )
        .await?;
    backend.ip_batch(&rendered.ip, false).await?;

    let action = if tunnel_service_changed { "restart" } else { "start" };
    backend
        .systemctl(&[action, IPSEC_SERVICE])
        .await
        .map_err(|e| format!("Could not start the tunnel service: {}", e))?;
    backend
        .swanctl(&["--load-all"])
        .await
        .map_err(|e| format!("Could not load the tunnel configuration: {}", e))?;

    let action = if routing_changed { "restart" } else { "start" };
    backend
        .systemctl(&[action, ROUTING_SERVICE])
        .await
        .map_err(|e| format!("Could not start the routing service: {}", e))?;

    Ok(())
}

/// Applies `target`; if that fails, puts `fallback` back (or switches the overlay off when
/// there was nothing before) and says what happened.
async fn apply_with_revert<B: Backend>(
    backend: &B,
    target: &OverlayInput,
    fallback: Option<&OverlayInput>,
    what: &str,
) -> Result<(), String> {
    let error = match apply_state(backend, target).await {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };

    let reverted = match fallback {
        Some(previous) => apply_state(backend, previous).await,
        None => apply_state(backend, &switched_off()).await,
    };

    Err(match reverted {
        Ok(()) => format!(
            "{} failed, the previous overlay setup was restored: {}",
            what, error
        ),
        Err(revert_error) => format!(
            "{} failed ({}) and restoring the previous setup also failed ({}) - check the tunnels and routing manually",
            what, error, revert_error
        ),
    })
}

fn save_current(dir: &Path, input: &OverlayInput) -> Result<(), String> {
    let json = serde_json::to_string(&OverlaySnapshot::from_input(input))
        .map_err(|e| e.to_string())?;

    write_atomic(&dir.join(CURRENT_JSON), &json, MODE_PRIVATE)
}

fn describe(input: &OverlayInput) -> String {
    format!(
        "{} tunnel(s) active",
        OverlayGenerator::active_tunnels(input).len()
    )
}

async fn commit_with<B: Backend>(
    backend: &B,
    pool: &SqlitePool,
    lock: &Arc<Mutex<()>>,
) -> Result<String, String> {
    let _guard = lock.lock().await;

    let dir = backend.history_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let live = read_snapshot(&dir.join(CURRENT_JSON))?;

    let input = OverlayGenerator::load_input(pool).await?;
    let rendered = Rendered::of(&input);

    // Nothing changed: leave the running tunnels alone.
    if let Some(snapshot) = &live {
        if Rendered::of(&snapshot.to_input()) == rendered {
            return Ok("The overlay is already up to date".into());
        }
    }

    if rendered.tunnels > 0 {
        check_interfaces(backend, &input)
            .and_then(|_| check_files(backend, &input))
            .map_err(|e| format!("Validation failed, nothing was applied: {}", e))?;
    }

    let live_input = live.as_ref().map(|s| s.to_input());

    apply_with_revert(backend, &input, live_input.as_ref(), "Applying the overlay").await?;

    if dir.join(CURRENT_JSON).exists() {
        fs::copy(dir.join(CURRENT_JSON), dir.join(PREVIOUS_JSON)).map_err(|e| e.to_string())?;
    }

    save_current(&dir, &input)?;

    if rendered.tunnels == 0 {
        Ok("The overlay is switched off, its tunnels and routing were stopped".into())
    } else {
        Ok(format!("Overlay applied: {}", describe(&input)))
    }
}

async fn rollback_with<B: Backend>(
    backend: &B,
    pool: &SqlitePool,
    lock: &Arc<Mutex<()>>,
) -> Result<String, String> {
    let _guard = lock.lock().await;

    let dir = backend.history_dir();

    let previous = read_snapshot(&dir.join(PREVIOUS_JSON))?
        .ok_or_else(|| "No previous overlay configuration available to roll back to".to_string())?;
    let current = read_snapshot(&dir.join(CURRENT_JSON))?;

    // The WAN links belong to SD-WAN and may have changed since. The tunnels come from
    // the snapshot, the links from the database as they are now.
    let links = SdwanRepository::list_links(pool)
        .await
        .map_err(|e| e.to_string())?;

    for tunnel in &previous.tunnels {
        if !links.iter().any(|l| l.id == Some(tunnel.link_id)) {
            return Err(format!(
                "Refusing to roll back, nothing was changed: tunnel '{}' uses a WAN link that no longer exists",
                tunnel.name
            ));
        }
    }

    let mut target = previous.to_input();
    target.links = links;

    let rendered = Rendered::of(&target);

    if rendered.tunnels > 0 {
        check_interfaces(backend, &target)
            .and_then(|_| check_files(backend, &target))
            .map_err(|e| format!("Refusing to roll back, nothing was changed: {}", e))?;
    }

    let live_input = current.as_ref().map(|s| s.to_input());

    apply_with_revert(
        backend,
        &target,
        live_input.as_ref(),
        "Rolling back the overlay",
    )
    .await?;

    if let Err(e) = OverlayRepository::replace_all(pool, &previous.settings, &previous.tunnels).await
    {
        return Err(format!(
            "Rollback applied to the live system, but failed to sync the database: {}. The running overlay and the database are now out of sync - do not commit the overlay until this is resolved.",
            e
        ));
    }

    save_current(&dir, &target)?;

    Ok("Rolled back to the previous overlay configuration successfully".into())
}

async fn restore_on_boot_with<B: Backend>(
    backend: &B,
    lock: &Arc<Mutex<()>>,
) -> Result<String, String> {
    let _guard = lock.lock().await;

    let dir = backend.history_dir();

    let Some(snapshot) = read_snapshot(&dir.join(CURRENT_JSON))? else {
        return Ok("No saved overlay configuration found, nothing was restored".into());
    };

    if !snapshot.settings.enabled {
        return Ok("The overlay is disabled, nothing was restored".into());
    }

    let input = snapshot.to_input();

    apply_state(backend, &input)
        .await
        .map_err(|e| format!("Saved overlay setup could not be restored: {}", e))?;

    Ok(format!("Restored the overlay: {}", describe(&input)))
}

pub struct OverlayCommit;

impl OverlayCommit {
    /// Applies what is in the database. The previous setup becomes the rollback target.
    /// Does nothing when nothing changed, so running tunnels are not interrupted.
    pub async fn commit(pool: &SqlitePool, lock: &Arc<Mutex<()>>) -> Result<String, String> {
        commit_with(&SystemBackend, pool, lock).await
    }

    pub async fn rollback(pool: &SqlitePool, lock: &Arc<Mutex<()>>) -> Result<String, String> {
        rollback_with(&SystemBackend, pool, lock).await
    }

    /// The tunnel interfaces do not survive a reboot, so the saved setup is applied again.
    pub async fn restore_on_boot(
        _pool: &SqlitePool,
        lock: &Arc<Mutex<()>>,
    ) -> Result<String, String> {
        restore_on_boot_with(&SystemBackend, lock).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::init::initialize_database;
    use crate::services::overlay_service::OverlayService;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    const PSK: &str = "a-long-enough-secret";

    /// Writes down every call instead of touching the system, keeps the "written" files in
    /// memory, and can be told to fail the Nth call of one kind.
    struct FakeBackend {
        dir: PathBuf,
        owns_dir: bool,
        interfaces: Vec<String>,
        overlay_interfaces: Vec<String>,
        present_files: Vec<String>,
        files: std::sync::Mutex<HashMap<String, (String, u32)>>,
        scripts: std::sync::Mutex<Vec<String>>,
        log: std::sync::Mutex<Vec<String>>,
        counts: std::sync::Mutex<HashMap<String, usize>>,
        failures: std::sync::Mutex<Vec<(String, usize)>>,
    }

    impl FakeBackend {
        fn new(interfaces: &[&str]) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "iqsoft-overlay-test-{}-{}",
                std::process::id(),
                DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
            ));

            FakeBackend {
                dir,
                owns_dir: true,
                interfaces: interfaces.iter().map(|s| s.to_string()).collect(),
                overlay_interfaces: Vec::new(),
                present_files: Vec::new(),
                files: Default::default(),
                scripts: Default::default(),
                log: Default::default(),
                counts: Default::default(),
                failures: Default::default(),
            }
        }

        fn with_overlay_interfaces(mut self, names: &[&str]) -> Self {
            self.overlay_interfaces = names.iter().map(|s| s.to_string()).collect();
            self
        }

        fn with_files(mut self, names: &[&str]) -> Self {
            self.present_files = names.iter().map(|s| s.to_string()).collect();
            self
        }

        /// Same saved history, but a machine that just booted: no config files, no calls.
        fn rebooted(&self) -> Self {
            FakeBackend {
                dir: self.dir.clone(),
                owns_dir: false,
                interfaces: self.interfaces.clone(),
                overlay_interfaces: Vec::new(),
                present_files: self.present_files.clone(),
                files: Default::default(),
                scripts: Default::default(),
                log: Default::default(),
                counts: Default::default(),
                failures: Default::default(),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }

        fn clear_calls(&self) {
            self.log.lock().unwrap().clear();
            self.counts.lock().unwrap().clear();
        }

        fn fail_nth(&self, op: &str, nth: usize) {
            self.failures.lock().unwrap().push((op.to_string(), nth));
        }

        fn step(&self, op: &str) -> Result<(), String> {
            self.log.lock().unwrap().push(op.to_string());

            let mut counts = self.counts.lock().unwrap();
            let count = counts.entry(op.to_string()).or_insert(0);
            *count += 1;

            if self
                .failures
                .lock()
                .unwrap()
                .iter()
                .any(|(name, nth)| name == op && nth == count)
            {
                return Err(format!("{} failed on purpose", op));
            }

            Ok(())
        }

        fn file(&self, name: &str) -> Option<String> {
            self.files.lock().unwrap().get(name).map(|(c, _)| c.clone())
        }

        fn file_mode(&self, name: &str) -> Option<u32> {
            self.files.lock().unwrap().get(name).map(|(_, m)| *m)
        }

        fn last_removal_script(&self) -> String {
            self.scripts
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|s| s.contains("removal"))
                .cloned()
                .unwrap_or_default()
        }

        fn name_of(path: &Path) -> String {
            path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default()
        }
    }

    impl Drop for FakeBackend {
        fn drop(&mut self) {
            if self.owns_dir {
                let _ = fs::remove_dir_all(&self.dir);
            }
        }
    }

    impl Backend for FakeBackend {
        fn history_dir(&self) -> PathBuf {
            self.dir.clone()
        }

        fn interface_exists(&self, name: &str) -> bool {
            self.interfaces.iter().any(|i| i == name)
        }

        fn overlay_interfaces(&self) -> Vec<String> {
            self.overlay_interfaces.clone()
        }

        fn read_file(&self, path: &Path) -> Option<String> {
            self.file(&Self::name_of(path))
        }

        fn file_exists(&self, path: &Path) -> bool {
            self.present_files.contains(&Self::name_of(path))
        }

        fn write_file(&self, path: &Path, content: &str, mode: u32) -> Result<(), String> {
            let name = Self::name_of(path);
            self.step(&format!("write:{}", name))?;
            self.files
                .lock()
                .unwrap()
                .insert(name, (content.to_string(), mode));
            Ok(())
        }

        async fn ip_batch(&self, script: &str, _force: bool) -> Result<(), String> {
            self.scripts.lock().unwrap().push(script.to_string());

            if script.contains("removal") {
                self.step("ip_remove")
            } else {
                self.step("ip_apply")
            }
        }

        async fn systemctl(&self, args: &[&str]) -> Result<(), String> {
            self.step(&format!("systemctl {}", args.join(" ")))
        }

        async fn swanctl(&self, args: &[&str]) -> Result<(), String> {
            self.step(&format!("swanctl {}", args.join(" ")))
        }
    }

    async fn memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        initialize_database(&pool).await.unwrap();

        for (name, iface) in [("wan1", "eth0"), ("wan2", "eth1")] {
            sqlx::query("INSERT INTO sdwan_links (name, interface_name, gateway) VALUES (?, ?, '192.168.1.1')")
                .bind(name)
                .bind(iface)
                .execute(&pool)
                .await
                .unwrap();
        }

        pool
    }

    fn lock() -> Arc<Mutex<()>> {
        Arc::new(Mutex::new(()))
    }

    /// Tunnel number `n` goes to 203.0.113.(10+n) and uses 10.255.<n>.0/30.
    fn new_tunnel(name: &str, link_id: i64, n: i64) -> OverlayTunnel {
        let mut t: OverlayTunnel = serde_json::from_str(
            r#"{"name":"hq","link_id":1,"remote_address":"203.0.113.10",
                "inner_local":"10.255.0.1/30","inner_remote":"10.255.0.2"}"#,
        )
        .unwrap();

        t.name = name.to_string();
        t.link_id = link_id;
        t.remote_address = format!("203.0.113.{}", 10 + n);
        t.inner_local = format!("10.255.{}.1/30", n);
        t.inner_remote = format!("10.255.{}.2", n);
        t.psk = Some(PSK.to_string());
        t
    }

    /// Two WAN links, two PSK tunnels (ids 1 and 2), overlay on.
    async fn configured_pool() -> SqlitePool {
        let pool = memory_pool().await;

        OverlayService::add_tunnel(&pool, new_tunnel("hq", 1, 1)).await.unwrap();
        OverlayService::add_tunnel(&pool, new_tunnel("dr", 2, 2)).await.unwrap();

        let mut s = OverlayService::get_settings(&pool).await.unwrap();
        s.router_id = Some("10.0.0.1".into());
        s.advertised_networks = vec!["192.168.10.0/24".into()];
        OverlayService::save_settings(&pool, s).await.unwrap();
        OverlayService::set_enabled(&pool, true).await.unwrap();

        pool
    }

    async fn set_cost(pool: &SqlitePool, id: i64, cost: i64) {
        let mut t = OverlayRepository::get_tunnel(pool, id).await.unwrap().unwrap();
        t.ospf_cost = cost;
        OverlayService::update_tunnel(pool, id, t).await.unwrap();
    }

    async fn cost_of(pool: &SqlitePool, id: i64) -> i64 {
        OverlayRepository::get_tunnel(pool, id)
            .await
            .unwrap()
            .unwrap()
            .ospf_cost
    }

    fn backend() -> FakeBackend {
        FakeBackend::new(&["eth0", "eth1"])
    }

    const FIRST_APPLY: [&str; 8] = [
        "write:iqsoft.conf",
        "write:swanctl.conf",
        "write:frr.conf",
        "ip_remove",
        "ip_apply",
        "systemctl restart strongswan",
        "swanctl --load-all",
        "systemctl restart frr",
    ];

    // ---------------------------------------------------------------- commit

    #[tokio::test]
    async fn the_first_commit_applies_everything_in_order() {
        let pool = configured_pool().await;
        let fake = backend();

        let message = commit_with(&fake, &pool, &lock()).await.unwrap();

        assert_eq!(message, "Overlay applied: 2 tunnel(s) active");
        assert_eq!(fake.calls(), FIRST_APPLY);
    }

    #[tokio::test]
    async fn the_generated_files_are_written_with_the_right_content_and_modes() {
        let pool = configured_pool().await;
        let fake = backend();

        commit_with(&fake, &pool, &lock()).await.unwrap();

        let swanctl = fake.file("swanctl.conf").unwrap();
        assert!(swanctl.contains("iqsoft-t1 {"));
        assert!(swanctl.contains("iqsoft-t2 {"));
        assert!(swanctl.contains(&format!("secret = \"{}\"", PSK)));

        let frr = fake.file("frr.conf").unwrap();
        assert!(frr.contains("interface xfrm1"));
        assert!(frr.contains("network 192.168.10.0/24 area 0.0.0.0"));

        assert!(fake.file("iqsoft.conf").unwrap().contains("install_routes = no"));

        // only the file with the keys is private
        assert_eq!(fake.file_mode("swanctl.conf"), Some(0o600));
        assert_eq!(fake.file_mode("frr.conf"), Some(0o644));
        assert_eq!(fake.file_mode("iqsoft.conf"), Some(0o644));
    }

    #[tokio::test]
    async fn leftover_overlay_interfaces_are_removed_before_the_new_ones_are_added() {
        let pool = configured_pool().await;
        let fake = backend().with_overlay_interfaces(&["xfrm9", "xfrm1"]);

        commit_with(&fake, &pool, &lock()).await.unwrap();

        let removal = fake.last_removal_script();
        assert!(removal.contains("link del xfrm9"), "{}", removal);
        assert!(removal.contains("link del xfrm1"), "{}", removal);
    }

    #[tokio::test]
    async fn committing_twice_without_changes_touches_nothing() {
        let pool = configured_pool().await;
        let fake = backend();
        commit_with(&fake, &pool, &lock()).await.unwrap();
        fake.clear_calls();

        let message = commit_with(&fake, &pool, &lock()).await.unwrap();

        assert_eq!(message, "The overlay is already up to date");
        assert!(fake.calls().is_empty(), "{:?}", fake.calls());
    }

    #[tokio::test]
    async fn changing_only_the_ospf_cost_does_not_restart_the_tunnel_service() {
        let pool = configured_pool().await;
        let fake = backend();
        commit_with(&fake, &pool, &lock()).await.unwrap();
        fake.clear_calls();

        set_cost(&pool, 1, 99).await;
        commit_with(&fake, &pool, &lock()).await.unwrap();

        let calls = fake.calls();
        assert!(calls.contains(&"systemctl start strongswan".to_string()), "{:?}", calls);
        assert!(!calls.contains(&"systemctl restart strongswan".to_string()), "{:?}", calls);
        assert!(calls.contains(&"systemctl restart frr".to_string()), "{:?}", calls);
        assert!(fake.file("frr.conf").unwrap().contains("ip ospf cost 99"));
    }

    #[tokio::test]
    async fn changing_a_key_restarts_the_tunnel_service() {
        let pool = configured_pool().await;
        let fake = backend();
        commit_with(&fake, &pool, &lock()).await.unwrap();
        fake.clear_calls();

        let mut t = OverlayRepository::get_tunnel(&pool, 1).await.unwrap().unwrap();
        t.psk = Some("another-long-secret-1".into());
        OverlayService::update_tunnel(&pool, 1, t).await.unwrap();

        commit_with(&fake, &pool, &lock()).await.unwrap();

        let calls = fake.calls();
        assert!(calls.contains(&"systemctl restart strongswan".to_string()), "{:?}", calls);
        // the routing config did not change
        assert!(calls.contains(&"systemctl start frr".to_string()), "{:?}", calls);
    }

    #[tokio::test]
    async fn the_old_setup_becomes_the_rollback_target_only_from_the_second_commit() {
        let pool = configured_pool().await;
        let fake = backend();

        commit_with(&fake, &pool, &lock()).await.unwrap();
        assert!(fake.dir.join(CURRENT_JSON).exists());
        assert!(!fake.dir.join(PREVIOUS_JSON).exists());

        set_cost(&pool, 1, 99).await;
        commit_with(&fake, &pool, &lock()).await.unwrap();
        assert!(fake.dir.join(PREVIOUS_JSON).exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_saved_snapshot_with_the_keys_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let pool = configured_pool().await;
        let fake = backend();
        commit_with(&fake, &pool, &lock()).await.unwrap();

        let mode = fs::metadata(fake.dir.join(CURRENT_JSON)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // ------------------------------------------------------------ validation

    #[tokio::test]
    async fn a_missing_wan_interface_is_refused_before_anything_is_applied() {
        let pool = configured_pool().await;
        let fake = FakeBackend::new(&["eth0"]);

        let err = commit_with(&fake, &pool, &lock()).await.unwrap_err();

        assert!(err.contains("Validation failed"), "{}", err);
        assert!(err.contains("eth1"), "{}", err);
        assert!(fake.calls().is_empty(), "{:?}", fake.calls());
        assert!(!fake.dir.join(CURRENT_JSON).exists());
    }

    #[tokio::test]
    async fn a_missing_certificate_file_is_refused_before_anything_is_applied() {
        let pool = memory_pool().await;

        let mut t = new_tunnel("hq", 1, 1);
        t.auth_method = "cert".into();
        t.psk = None;
        t.local_cert = Some("site.pem".into());
        t.local_key = Some("site.key".into());
        t.remote_ca = Some("ca.pem".into());
        OverlayService::add_tunnel(&pool, t).await.unwrap();

        let mut s = OverlayService::get_settings(&pool).await.unwrap();
        s.router_id = Some("10.0.0.1".into());
        OverlayService::save_settings(&pool, s).await.unwrap();
        OverlayService::set_enabled(&pool, true).await.unwrap();

        // the private key is missing
        let fake = backend().with_files(&["site.pem", "ca.pem"]);
        let err = commit_with(&fake, &pool, &lock()).await.unwrap_err();
        assert!(err.contains("Private key 'site.key'"), "{}", err);
        assert!(fake.calls().is_empty(), "{:?}", fake.calls());

        // all three present
        let fake = backend().with_files(&["site.pem", "site.key", "ca.pem"]);
        commit_with(&fake, &pool, &lock()).await.unwrap();
        assert!(fake.file("swanctl.conf").unwrap().contains("certs = site.pem"));
    }

    // -------------------------------------------------------------- failures

    #[tokio::test]
    async fn a_failed_apply_puts_the_previous_setup_back() {
        let pool = configured_pool().await;
        let fake = backend();
        commit_with(&fake, &pool, &lock()).await.unwrap();
        let before = fake.file("frr.conf").unwrap();
        fake.clear_calls();

        set_cost(&pool, 1, 99).await;
        fake.fail_nth("ip_apply", 1);

        let err = commit_with(&fake, &pool, &lock()).await.unwrap_err();

        assert!(err.contains("previous overlay setup was restored"), "{}", err);
        // the old routing config is back on disk and the old setup was applied again
        assert_eq!(fake.file("frr.conf").unwrap(), before);
        assert_eq!(fake.calls().iter().filter(|c| *c == "ip_apply").count(), 2);

        // the saved current setup is still the old one, so a retry is not skipped
        let saved = read_snapshot(&fake.dir.join(CURRENT_JSON)).unwrap().unwrap();
        assert!(saved.tunnels.iter().all(|t| t.ospf_cost == 10));
    }

    #[tokio::test]
    async fn a_failed_first_apply_switches_the_overlay_off_again() {
        let pool = configured_pool().await;
        let fake = backend();
        fake.fail_nth("swanctl --load-all", 1);

        let err = commit_with(&fake, &pool, &lock()).await.unwrap_err();

        assert!(err.contains("previous overlay setup was restored"), "{}", err);
        assert!(err.contains("Could not load the tunnel configuration"), "{}", err);

        let calls = fake.calls();
        assert!(calls.contains(&"systemctl stop frr".to_string()), "{:?}", calls);
        assert!(calls.contains(&"systemctl stop strongswan".to_string()), "{:?}", calls);
        assert!(!fake.dir.join(CURRENT_JSON).exists());
    }

    #[tokio::test]
    async fn a_failure_while_restoring_is_reported_too() {
        let pool = configured_pool().await;
        let fake = backend();
        commit_with(&fake, &pool, &lock()).await.unwrap();
        fake.clear_calls();

        set_cost(&pool, 1, 99).await;
        fake.fail_nth("ip_apply", 1);
        fake.fail_nth("ip_apply", 2);

        let err = commit_with(&fake, &pool, &lock()).await.unwrap_err();

        assert!(err.contains("also failed"), "{}", err);
    }

    // ------------------------------------------------------------- switching off

    #[tokio::test]
    async fn switching_the_overlay_off_stops_everything() {
        let pool = configured_pool().await;
        let fake = backend();
        commit_with(&fake, &pool, &lock()).await.unwrap();
        fake.clear_calls();

        OverlayService::set_enabled(&pool, false).await.unwrap();
        let message = commit_with(&fake, &pool, &lock()).await.unwrap();

        assert!(message.contains("switched off"), "{}", message);
        assert_eq!(
            fake.calls(),
            [
                "systemctl stop frr",
                "systemctl stop strongswan",
                "ip_remove",
                "write:swanctl.conf",
                "write:frr.conf",
            ]
        );

        // nothing is left in the written configs
        assert!(!fake.file("swanctl.conf").unwrap().contains("iqsoft-t1"));
        assert!(!fake.file("frr.conf").unwrap().contains("router ospf"));

        let saved = read_snapshot(&fake.dir.join(CURRENT_JSON)).unwrap().unwrap();
        assert!(!saved.settings.enabled);
    }

    #[tokio::test]
    async fn switching_off_works_when_the_services_cannot_be_stopped() {
        let pool = configured_pool().await;
        let fake = backend();
        commit_with(&fake, &pool, &lock()).await.unwrap();
        fake.clear_calls();

        OverlayService::set_enabled(&pool, false).await.unwrap();
        fake.fail_nth("systemctl stop frr", 1);
        fake.fail_nth("systemctl stop strongswan", 1);
        fake.fail_nth("write:swanctl.conf", 1);

        assert!(commit_with(&fake, &pool, &lock()).await.is_ok());
    }

    // -------------------------------------------------------------- rollback

    #[tokio::test]
    async fn rollback_without_a_previous_setup_says_so() {
        let pool = configured_pool().await;
        let fake = backend();

        let err = rollback_with(&fake, &pool, &lock()).await.unwrap_err();
        assert!(err.contains("No previous overlay configuration"), "{}", err);

        commit_with(&fake, &pool, &lock()).await.unwrap();
        let err = rollback_with(&fake, &pool, &lock()).await.unwrap_err();
        assert!(err.contains("No previous overlay configuration"), "{}", err);
    }

    #[tokio::test]
    async fn rollback_restores_the_live_setup_and_the_database() {
        let pool = configured_pool().await;
        let fake = backend();
        commit_with(&fake, &pool, &lock()).await.unwrap();

        set_cost(&pool, 1, 99).await;
        commit_with(&fake, &pool, &lock()).await.unwrap();
        assert!(fake.file("frr.conf").unwrap().contains("ip ospf cost 99"));

        let message = rollback_with(&fake, &pool, &lock()).await.unwrap();

        assert!(message.contains("Rolled back"), "{}", message);
        assert!(!fake.file("frr.conf").unwrap().contains("ip ospf cost 99"));
        assert_eq!(cost_of(&pool, 1).await, 10);

        // the keys survive the round trip
        let tunnels = OverlayService::list_tunnels_with_secrets(&pool).await.unwrap();
        assert!(tunnels.iter().all(|t| t.psk.as_deref() == Some(PSK)));
        assert_eq!(tunnels.len(), 2);
    }

    #[tokio::test]
    async fn rollback_can_bring_back_a_deleted_tunnel_with_its_id() {
        let pool = configured_pool().await;
        let fake = backend();
        commit_with(&fake, &pool, &lock()).await.unwrap();

        OverlayService::delete_tunnel(&pool, 2).await.unwrap();
        commit_with(&fake, &pool, &lock()).await.unwrap();
        assert!(!fake.file("swanctl.conf").unwrap().contains("iqsoft-t2"));

        rollback_with(&fake, &pool, &lock()).await.unwrap();

        assert!(fake.file("swanctl.conf").unwrap().contains("iqsoft-t2"));
        let ids: Vec<Option<i64>> = OverlayService::list_tunnels(&pool)
            .await
            .unwrap()
            .iter()
            .map(|t| t.id)
            .collect();
        assert_eq!(ids, vec![Some(1), Some(2)]);
    }

    #[tokio::test]
    async fn rollback_is_refused_when_a_wan_link_is_gone() {
        let pool = configured_pool().await;
        let fake = backend();
        commit_with(&fake, &pool, &lock()).await.unwrap();

        // the second tunnel and its link are removed, and that is committed
        OverlayService::delete_tunnel(&pool, 2).await.unwrap();
        sqlx::query("DELETE FROM sdwan_links WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();
        commit_with(&fake, &pool, &lock()).await.unwrap();
        fake.clear_calls();

        let err = rollback_with(&fake, &pool, &lock()).await.unwrap_err();

        assert!(err.contains("no longer exists"), "{}", err);
        assert!(err.contains("nothing was changed"), "{}", err);
        assert!(fake.calls().is_empty(), "{:?}", fake.calls());
        assert_eq!(OverlayService::list_tunnels(&pool).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_failed_rollback_apply_leaves_the_database_alone() {
        let pool = configured_pool().await;
        let fake = backend();
        commit_with(&fake, &pool, &lock()).await.unwrap();
        set_cost(&pool, 1, 99).await;
        commit_with(&fake, &pool, &lock()).await.unwrap();
        fake.clear_calls();

        fake.fail_nth("ip_apply", 1);
        let err = rollback_with(&fake, &pool, &lock()).await.unwrap_err();

        assert!(err.contains("previous overlay setup was restored"), "{}", err);
        assert_eq!(cost_of(&pool, 1).await, 99);
    }

    // ------------------------------------------------------------- boot restore

    #[tokio::test]
    async fn boot_restore_with_nothing_saved_does_nothing() {
        let fake = backend();

        let message = restore_on_boot_with(&fake, &lock()).await.unwrap();

        assert!(message.contains("nothing was restored"), "{}", message);
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn boot_restore_applies_the_saved_setup_again() {
        let pool = configured_pool().await;
        let fake = backend();
        commit_with(&fake, &pool, &lock()).await.unwrap();

        // after a reboot: no config files, no interfaces, the history is still there
        let after_reboot = fake.rebooted();
        let message = restore_on_boot_with(&after_reboot, &lock()).await.unwrap();

        assert_eq!(message, "Restored the overlay: 2 tunnel(s) active");
        assert_eq!(after_reboot.calls(), FIRST_APPLY);
        assert!(after_reboot
            .file("swanctl.conf")
            .unwrap()
            .contains(&format!("secret = \"{}\"", PSK)));
    }

    #[tokio::test]
    async fn boot_restore_leaves_a_switched_off_overlay_alone() {
        let pool = configured_pool().await;
        let fake = backend();
        commit_with(&fake, &pool, &lock()).await.unwrap();

        OverlayService::set_enabled(&pool, false).await.unwrap();
        commit_with(&fake, &pool, &lock()).await.unwrap();

        let after_reboot = fake.rebooted();
        let message = restore_on_boot_with(&after_reboot, &lock()).await.unwrap();

        assert!(message.contains("disabled"), "{}", message);
        assert!(after_reboot.calls().is_empty());
    }

    #[tokio::test]
    async fn boot_restore_reports_a_setup_that_cannot_be_restored() {
        let pool = configured_pool().await;
        let fake = backend();
        commit_with(&fake, &pool, &lock()).await.unwrap();

        // a WAN port is missing after the reboot
        let after_reboot = FakeBackend::new(&["eth0"]);
        let after_reboot = FakeBackend {
            dir: fake.dir.clone(),
            owns_dir: false,
            ..after_reboot
        };

        let err = restore_on_boot_with(&after_reboot, &lock()).await.unwrap_err();

        assert!(err.contains("could not be restored"), "{}", err);
        assert!(err.contains("eth1"), "{}", err);
    }

    // --------------------------------------------------------------- small pieces

    #[test]
    fn only_real_commands_are_counted() {
        assert_eq!(count_commands("# header\n\nroute flush proto 252\nlink del xfrm1\n"), 2);
        assert_eq!(count_commands("# only a header\n"), 0);
    }

    #[test]
    fn a_snapshot_keeps_the_keys_for_the_restore() {
        let mut t = new_tunnel("hq", 1, 1);
        t.id = Some(1);

        let snapshot = OverlaySnapshot {
            settings: OverlaySettings::default(),
            tunnels: vec![t],
            links: Vec::new(),
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        let back: OverlaySnapshot = serde_json::from_str(&json).unwrap();

        assert_eq!(back.tunnels[0].psk.as_deref(), Some(PSK));
    }

    #[test]
    fn a_corrupt_snapshot_is_reported_not_ignored() {
        let dir = std::env::temp_dir().join(format!("iqsoft-overlay-corrupt-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(CURRENT_JSON);
        fs::write(&path, "{ not json").unwrap();

        let err = read_snapshot(&path).unwrap_err();
        assert!(err.contains("corrupt"), "{}", err);

        let _ = fs::remove_dir_all(&dir);
    }
}
