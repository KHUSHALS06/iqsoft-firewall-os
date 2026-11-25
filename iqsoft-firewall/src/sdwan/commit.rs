use crate::models::sdwan::{SdwanLink, SdwanLinkStatus, SdwanRule};
use crate::repository::sdwan_repository::SdwanRepository;
use crate::sdwan::generator::{SdwanGenerator, SdwanInput, TABLE_NAME};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;

const HISTORY_DIR: &str = "config-history";
const CURRENT_JSON: &str = "current.sdwan.json";
const PREVIOUS_JSON: &str = "previous.sdwan.json";
const CURRENT_NFT: &str = "current.sdwan.nft";
const CURRENT_IP: &str = "current.sdwan.ip";
const STAGED_IP_PATH: &str = "/tmp/iqsoft-sdwan.batch";

/// Everything the commit needs from the outside world. The real one talks to the
/// kernel; the tests use a fake that only writes down what it was asked to do.
#[allow(async_fn_in_trait)]
trait Backend {
    fn history_dir(&self) -> PathBuf;
    fn interface_exists(&self, name: &str) -> bool;
    async fn nft_check(&self, script: &str) -> Result<(), String>;
    async fn nft_apply(&self, script: &str) -> Result<(), String>;
    /// With `force`, failing lines are expected and ignored (used for cleaning up).
    async fn ip_batch(&self, script: &str, force: bool) -> Result<(), String>;
    async fn loosen_rp_filter(&self, interface: &str) -> Result<(), String>;
}

struct SystemBackend;

impl SystemBackend {
    async fn run_nft(args: &[&str], script: &str) -> Result<(), String> {
        use std::process::Stdio;
        use tokio::{io::AsyncWriteExt, process::Command};

        let mut child = Command::new("nft")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("could not run nft: {}", e))?;

        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "could not open nft's input".to_string())?;

        stdin
            .write_all(script.as_bytes())
            .await
            .map_err(|e| format!("could not send the SD-WAN rules to nft: {}", e))?;
        drop(stdin);

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| format!("nft did not finish: {}", e))?;

        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
        }

        Ok(())
    }
}

impl Backend for SystemBackend {
    fn history_dir(&self) -> PathBuf {
        PathBuf::from(HISTORY_DIR)
    }

    fn interface_exists(&self, name: &str) -> bool {
        Path::new(&format!("/sys/class/net/{}", name)).exists()
    }

    async fn nft_check(&self, script: &str) -> Result<(), String> {
        if cfg!(test) {
            return Err("nft is not touched in test builds".to_string());
        }

        Self::run_nft(&["--check", "-f", "-"], script).await
    }

    async fn nft_apply(&self, script: &str) -> Result<(), String> {
        if cfg!(test) {
            return Err("nft is not touched in test builds".to_string());
        }

        Self::run_nft(&["-f", "-"], script).await
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

    /// Replies come back on a different link than a strict check expects, so the
    /// reverse-path check of every link is loosened (1 -> 2). Other values stay.
    async fn loosen_rp_filter(&self, interface: &str) -> Result<(), String> {
        if cfg!(test) {
            return Err("sysctl is not touched in test builds".to_string());
        }

        let path = format!("/proc/sys/net/ipv4/conf/{}/rp_filter", interface);

        let current = fs::read_to_string(&path)
            .map_err(|e| format!("could not read {}: {}", path, e))?;

        if current.trim() == "1" {
            fs::write(&path, "2").map_err(|e| format!("could not write {}: {}", path, e))?;
        }

        Ok(())
    }
}

/// What was applied: the settings, the links and the rules, as the generator saw them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdwanSnapshot {
    pub enabled: bool,
    pub links: Vec<SdwanLink>,
    pub rules: Vec<SdwanRule>,
    pub nat_enabled: bool,
    pub wan_interface: String,
}

impl SdwanSnapshot {
    fn from_input(input: &SdwanInput) -> Self {
        SdwanSnapshot {
            enabled: input.enabled,
            links: input.links.clone(),
            rules: input.rules.clone(),
            nat_enabled: input.nat_enabled,
            wan_interface: input.wan_interface.clone(),
        }
    }

    fn to_input(&self) -> SdwanInput {
        SdwanInput {
            enabled: self.enabled,
            links: self.links.clone(),
            rules: self.rules.clone(),
            nat_enabled: self.nat_enabled,
            wan_interface: self.wan_interface.clone(),
        }
    }
}

/// The two generated texts for one configuration.
#[derive(Debug, Clone, PartialEq)]
struct Rendered {
    table: String,
    ip: String,
}

impl Rendered {
    fn of(input: &SdwanInput) -> Self {
        Rendered {
            table: SdwanGenerator::render_table(input),
            ip: SdwanGenerator::render_ip_apply(input),
        }
    }

    fn nft_script(&self) -> String {
        build_apply_script(&self.table)
    }
}

/// A script that replaces only the SD-WAN table: it is created if missing, deleted and
/// written again in one nftables transaction. With empty text it just removes the table.
pub fn build_apply_script(table_text: &str) -> String {
    format!(
        "add table ip {t}\ndelete table ip {t}\n{body}",
        t = TABLE_NAME,
        body = table_text
    )
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

/// Puts the live health (up/down, latency, ...) from the database onto links from a
/// saved snapshot, so a restore never trusts a state that is hours old.
pub fn overlay_statuses(links: &mut [SdwanLink], statuses: &[SdwanLinkStatus]) {
    for link in links.iter_mut() {
        let Some(status) = link
            .id
            .and_then(|id| statuses.iter().find(|s| s.link_id == id))
        else {
            continue;
        };

        link.state = status.state.clone();
        link.latency_ms = status.latency_ms;
        link.loss_pct = status.loss_pct;
        link.last_check = status.last_check;
        link.last_change = status.last_change;
        link.last_error = status.last_error.clone();
    }
}

fn switched_off() -> SdwanInput {
    SdwanInput {
        enabled: false,
        links: Vec::new(),
        rules: Vec::new(),
        nat_enabled: false,
        wan_interface: String::new(),
    }
}

fn read_snapshot(path: &Path) -> Result<Option<SdwanSnapshot>, String> {
    if !path.exists() {
        return Ok(None);
    }

    let json = fs::read_to_string(path).map_err(|e| e.to_string())?;

    serde_json::from_str(&json).map(Some).map_err(|e| {
        format!(
            "Saved SD-WAN snapshot {} is corrupt: {}",
            path.display(),
            e
        )
    })
}

fn write_atomic(path: &Path, content: &str) -> Result<(), String> {
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, content).map_err(|e| e.to_string())?;
    fs::rename(&tmp_path, path).map_err(|e| e.to_string())?;
    Ok(())
}

fn check_interfaces<B: Backend>(backend: &B, input: &SdwanInput) -> Result<(), String> {
    for interface in SdwanGenerator::link_interfaces(input) {
        if !backend.interface_exists(&interface) {
            return Err(format!(
                "WAN interface '{}' does not exist on this system - refusing to apply SD-WAN",
                interface
            ));
        }
    }

    Ok(())
}

/// Makes the running system match `input`.
///
/// Order matters. Switching on: routing tables first, then the marking rules, so a
/// mark never points at a table that does not exist yet. Switching off: marking rules
/// first, then the tables.
async fn apply_state<B: Backend>(backend: &B, input: &SdwanInput) -> Result<(), String> {
    let rendered = Rendered::of(input);

    if rendered.table.is_empty() {
        backend.nft_apply(&rendered.nft_script()).await?;
        backend
            .ip_batch(&SdwanGenerator::render_ip_remove_all(), true)
            .await?;
        return Ok(());
    }

    check_interfaces(backend, input)?;

    for interface in SdwanGenerator::link_interfaces(input) {
        if let Err(e) = backend.loosen_rp_filter(&interface).await {
            eprintln!(
                "WARNING: could not loosen reverse-path filtering on {}: {}",
                interface, e
            );
        }
    }

    backend
        .ip_batch(&SdwanGenerator::render_ip_remove_all(), true)
        .await?;
    backend.ip_batch(&rendered.ip, false).await?;
    backend.nft_apply(&rendered.nft_script()).await?;

    Ok(())
}

/// Applies `target`; if that fails, puts `fallback` back (or switches SD-WAN off when
/// there was nothing before) and says what happened.
async fn apply_with_revert<B: Backend>(
    backend: &B,
    target: &SdwanInput,
    fallback: Option<&SdwanInput>,
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
            "{} failed, the previous SD-WAN setup was restored: {}",
            what, error
        ),
        Err(revert_error) => format!(
            "{} failed ({}) and restoring the previous setup also failed ({}) - check the routing rules and firewall rules manually",
            what, error, revert_error
        ),
    })
}

fn stored_rendered(dir: &Path) -> Option<Rendered> {
    Some(Rendered {
        table: fs::read_to_string(dir.join(CURRENT_NFT)).ok()?,
        ip: fs::read_to_string(dir.join(CURRENT_IP)).ok()?,
    })
}

fn save_current(dir: &Path, input: &SdwanInput, rendered: &Rendered) -> Result<(), String> {
    let json = serde_json::to_string(&SdwanSnapshot::from_input(input))
        .map_err(|e| e.to_string())?;

    write_atomic(&dir.join(CURRENT_JSON), &json)?;
    write_atomic(&dir.join(CURRENT_NFT), &rendered.table)?;
    write_atomic(&dir.join(CURRENT_IP), &rendered.ip)?;

    Ok(())
}

fn describe(input: &SdwanInput) -> String {
    let links = SdwanGenerator::link_interfaces(input).len();
    let rules = input.rules.iter().filter(|r| r.enabled).count();

    format!("{} link(s) and {} rule(s) active", links, rules)
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Mode {
    /// Someone pressed commit: the old setup becomes the rollback target.
    User,
    /// The probe task reacting to a link going down or coming back: only the
    /// live setup changes, the rollback target stays what the person committed.
    Automatic,
}

async fn commit_with<B: Backend>(
    backend: &B,
    pool: &SqlitePool,
    lock: &Arc<Mutex<()>>,
    mode: Mode,
) -> Result<String, String> {
    let _guard = lock.lock().await;

    let dir = backend.history_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let live = read_snapshot(&dir.join(CURRENT_JSON))?;

    if mode == Mode::Automatic && live.is_none() {
        return Ok("SD-WAN has not been committed yet, nothing to refresh".into());
    }

    let input = SdwanGenerator::load_input(pool).await?;
    let rendered = Rendered::of(&input);

    if mode == Mode::Automatic && stored_rendered(&dir).as_ref() == Some(&rendered) {
        return Ok("SD-WAN is already up to date".into());
    }

    if !rendered.table.is_empty() {
        check_interfaces(backend, &input)?;

        backend
            .nft_check(&rendered.nft_script())
            .await
            .map_err(|e| format!("Validation failed, nothing was applied: {}", e))?;
    }

    let live_input = live.as_ref().map(|s| s.to_input());

    apply_with_revert(backend, &input, live_input.as_ref(), "Applying SD-WAN").await?;

    if mode == Mode::User && dir.join(CURRENT_JSON).exists() {
        fs::copy(dir.join(CURRENT_JSON), dir.join(PREVIOUS_JSON)).map_err(|e| e.to_string())?;
    }

    save_current(&dir, &input, &rendered)?;

    if rendered.table.is_empty() {
        Ok("SD-WAN is switched off, its routing and rules were removed".into())
    } else {
        Ok(format!("SD-WAN applied: {}", describe(&input)))
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
        .ok_or_else(|| "No previous SD-WAN configuration available to roll back to".to_string())?;
    let current = read_snapshot(&dir.join(CURRENT_JSON))?;

    let statuses = SdwanRepository::list_statuses(pool)
        .await
        .map_err(|e| e.to_string())?;

    let mut target = previous.to_input();
    overlay_statuses(&mut target.links, &statuses);

    let rendered = Rendered::of(&target);

    if !rendered.table.is_empty() {
        check_interfaces(backend, &target)
            .map_err(|e| format!("Refusing to roll back, nothing was changed: {}", e))?;
    }

    let live_input = current.as_ref().map(|s| s.to_input());

    apply_with_revert(backend, &target, live_input.as_ref(), "Rolling back SD-WAN").await?;

    if let Err(e) = restore_database(pool, &previous).await {
        return Err(format!(
            "Rollback applied to the live system, but failed to sync the database: {}. The live SD-WAN setup and the database are now out of sync - do not commit SD-WAN until this is resolved.",
            e
        ));
    }

    save_current(&dir, &target, &rendered)?;

    Ok("Rolled back to the previous SD-WAN configuration successfully".into())
}

async fn restore_on_boot_with<B: Backend>(
    backend: &B,
    pool: &SqlitePool,
    lock: &Arc<Mutex<()>>,
) -> Result<String, String> {
    let _guard = lock.lock().await;

    let dir = backend.history_dir();

    let Some(snapshot) = read_snapshot(&dir.join(CURRENT_JSON))? else {
        return Ok("No saved SD-WAN configuration found, nothing was restored".into());
    };

    if !snapshot.enabled {
        return Ok("SD-WAN is disabled, nothing was restored".into());
    }

    let statuses = SdwanRepository::list_statuses(pool)
        .await
        .unwrap_or_default();

    let mut input = snapshot.to_input();
    overlay_statuses(&mut input.links, &statuses);

    apply_state(backend, &input)
        .await
        .map_err(|e| format!("Saved SD-WAN setup could not be restored: {}", e))?;

    save_current(&dir, &input, &Rendered::of(&input))?;

    Ok(format!("Restored SD-WAN: {}", describe(&input)))
}

/// Puts the settings, links and rules of a snapshot back into the database, keeping
/// every id (rules point at links by id) and the live health of links that still exist.
async fn restore_database(pool: &SqlitePool, snapshot: &SdwanSnapshot) -> Result<(), String> {
    let statuses = SdwanRepository::list_statuses(pool)
        .await
        .map_err(|e| e.to_string())?;

    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;

    sqlx::query("DELETE FROM sdwan_rules")
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    sqlx::query("DELETE FROM sdwan_links")
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

    for link in &snapshot.links {
        let id = link
            .id
            .ok_or_else(|| format!("Saved link '{}' has no id", link.name))?;

        sqlx::query(
            r#"
            INSERT INTO sdwan_links (
                id, name, interface_name, gateway, enabled, priority, weight,
                probe_target, probe_interval_secs, probe_timeout_secs,
                fail_threshold, recover_threshold, comment
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(id)
        .bind(&link.name)
        .bind(&link.interface_name)
        .bind(&link.gateway)
        .bind(link.enabled as i64)
        .bind(link.priority)
        .bind(link.weight)
        .bind(&link.probe_target)
        .bind(link.probe_interval_secs)
        .bind(link.probe_timeout_secs)
        .bind(link.fail_threshold)
        .bind(link.recover_threshold)
        .bind(&link.comment)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        match statuses.iter().find(|s| s.link_id == id) {
            Some(status) => {
                sqlx::query(
                    r#"
                    INSERT INTO sdwan_link_status (
                        link_id, state, latency_ms, loss_pct, consecutive_fail,
                        consecutive_ok, last_check, last_change, last_error
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                )
                .bind(status.link_id)
                .bind(&status.state)
                .bind(status.latency_ms)
                .bind(status.loss_pct)
                .bind(status.consecutive_fail)
                .bind(status.consecutive_ok)
                .bind(status.last_check)
                .bind(status.last_change)
                .bind(&status.last_error)
                .execute(&mut *tx)
                .await
                .map_err(|e| e.to_string())?;
            }
            None => {
                sqlx::query("INSERT INTO sdwan_link_status (link_id) VALUES (?)")
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
            }
        }
    }

    for rule in &snapshot.rules {
        let id = rule
            .id
            .ok_or_else(|| format!("Saved rule '{}' has no id", rule.name))?;

        sqlx::query(
            r#"
            INSERT INTO sdwan_rules (
                id, name, enabled, position, src_cidr, dst_cidr, protocol,
                dport_start, dport_end, strategy, link_id, on_link_down, comment
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(id)
        .bind(&rule.name)
        .bind(rule.enabled as i64)
        .bind(rule.position)
        .bind(&rule.src_cidr)
        .bind(&rule.dst_cidr)
        .bind(&rule.protocol)
        .bind(rule.dport_start)
        .bind(rule.dport_end)
        .bind(&rule.strategy)
        .bind(rule.link_id)
        .bind(&rule.on_link_down)
        .bind(&rule.comment)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    }

    sqlx::query("UPDATE sdwan_settings SET enabled = ? WHERE id = 1")
        .bind(snapshot.enabled as i64)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

    tx.commit().await.map_err(|e| e.to_string())?;

    Ok(())
}

pub struct SdwanCommit;

impl SdwanCommit {
    /// Applies what is in the database. The previous setup becomes the rollback target.
    pub async fn commit(pool: &SqlitePool, lock: &Arc<Mutex<()>>) -> Result<String, String> {
        commit_with(&SystemBackend, pool, lock, Mode::User).await
    }

    /// For the probe task: re-applies after a link changed state. It does nothing
    /// when nothing would change, and never touches the rollback target.
    pub async fn refresh(pool: &SqlitePool, lock: &Arc<Mutex<()>>) -> Result<String, String> {
        commit_with(&SystemBackend, pool, lock, Mode::Automatic).await
    }

    pub async fn rollback(pool: &SqlitePool, lock: &Arc<Mutex<()>>) -> Result<String, String> {
        rollback_with(&SystemBackend, pool, lock).await
    }

    /// The routing rules do not survive a reboot, so the saved setup is applied again.
    pub async fn restore_on_boot(
        pool: &SqlitePool,
        lock: &Arc<Mutex<()>>,
    ) -> Result<String, String> {
        restore_on_boot_with(&SystemBackend, pool, lock).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::init::initialize_database;
    use crate::services::sdwan_service::SdwanService;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// Writes down every call instead of touching the system, and can be told to
    /// fail the Nth call of one kind.
    struct FakeBackend {
        dir: PathBuf,
        owns_dir: bool,
        interfaces: Vec<String>,
        log: std::sync::Mutex<Vec<String>>,
        counts: std::sync::Mutex<HashMap<String, usize>>,
        failures: std::sync::Mutex<Vec<(String, usize)>>,
    }

    impl FakeBackend {
        fn new(interfaces: &[&str]) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "iqsoft-sdwan-test-{}-{}",
                std::process::id(),
                DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
            ));

            FakeBackend {
                dir,
                owns_dir: true,
                interfaces: interfaces.iter().map(|s| s.to_string()).collect(),
                log: Default::default(),
                counts: Default::default(),
                failures: Default::default(),
            }
        }

        /// Same saved files, but a different set of interfaces (and a fresh call log).
        fn sharing_files(&self, interfaces: &[&str]) -> Self {
            FakeBackend {
                dir: self.dir.clone(),
                owns_dir: false,
                interfaces: interfaces.iter().map(|s| s.to_string()).collect(),
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

        fn file(&self, name: &str) -> PathBuf {
            self.dir.join(name)
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

        async fn nft_check(&self, _script: &str) -> Result<(), String> {
            self.step("nft_check")
        }

        async fn nft_apply(&self, script: &str) -> Result<(), String> {
            if script.contains("chain ") {
                self.step("nft_apply")
            } else {
                self.step("nft_remove")
            }
        }

        async fn ip_batch(&self, script: &str, _force: bool) -> Result<(), String> {
            if script.contains("routing removal") {
                self.step("ip_remove")
            } else {
                self.step("ip_apply")
            }
        }

        async fn loosen_rp_filter(&self, interface: &str) -> Result<(), String> {
            self.step(&format!("rp:{}", interface))
        }
    }

    async fn memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        initialize_database(&pool).await.unwrap();
        pool
    }

    fn lock() -> Arc<Mutex<()>> {
        Arc::new(Mutex::new(()))
    }

    fn new_link(name: &str, iface: &str, priority: i64) -> SdwanLink {
        SdwanLink {
            id: None,
            name: name.to_string(),
            interface_name: iface.to_string(),
            gateway: Some("192.168.1.1".to_string()),
            enabled: true,
            priority,
            weight: 1,
            probe_target: "1.1.1.1".to_string(),
            probe_interval_secs: 5,
            probe_timeout_secs: 2,
            fail_threshold: 3,
            recover_threshold: 2,
            comment: None,
            state: "unknown".to_string(),
            latency_ms: None,
            loss_pct: None,
            last_check: None,
            last_change: None,
            last_error: None,
        }
    }

    fn new_rule(name: &str, link_id: Option<i64>) -> SdwanRule {
        SdwanRule {
            id: None,
            name: name.to_string(),
            enabled: true,
            position: 100,
            src_cidr: None,
            dst_cidr: None,
            protocol: "any".to_string(),
            dport_start: None,
            dport_end: None,
            strategy: if link_id.is_some() { "link" } else { "balance" }.to_string(),
            link_id,
            on_link_down: "fallback".to_string(),
            comment: None,
        }
    }

    /// Two links, one pinned rule, SD-WAN on.
    async fn configured_pool() -> (SqlitePool, i64, i64) {
        let pool = memory_pool().await;

        let one = SdwanService::add_link(&pool, new_link("ISP1", "eth0", 10))
            .await
            .unwrap();
        let two = SdwanService::add_link(&pool, new_link("ISP2", "eth2", 20))
            .await
            .unwrap();

        SdwanService::add_rule(&pool, new_rule("voice", Some(two)))
            .await
            .unwrap();
        SdwanService::set_enabled(&pool, true).await.unwrap();

        (pool, one, two)
    }

    fn status(link_id: i64, state: &str) -> SdwanLinkStatus {
        SdwanLinkStatus {
            link_id,
            state: state.to_string(),
            latency_ms: Some(12.5),
            loss_pct: Some(0),
            consecutive_fail: 0,
            consecutive_ok: 3,
            last_check: Some(1000),
            last_change: Some(900),
            last_error: None,
        }
    }

    // ------------------------------------------------------------ small pieces

    #[test]
    fn the_apply_script_replaces_only_the_sdwan_table() {
        let script = build_apply_script("table ip iqsoft_sdwan {\n}\n");

        assert_eq!(
            script,
            "add table ip iqsoft_sdwan\ndelete table ip iqsoft_sdwan\ntable ip iqsoft_sdwan {\n}\n"
        );
        assert_eq!(
            build_apply_script(""),
            "add table ip iqsoft_sdwan\ndelete table ip iqsoft_sdwan\n"
        );
    }

    #[test]
    fn commands_are_counted_without_comments_and_blank_lines() {
        assert_eq!(count_commands("# a\n\nrule add x\n  route add y\n# b\n"), 2);
        assert_eq!(count_commands("# only a comment\n"), 0);
    }

    #[test]
    fn live_health_is_laid_over_saved_links() {
        let mut one = new_link("ISP1", "eth0", 10);
        one.id = Some(1);
        let mut two = new_link("ISP2", "eth2", 20);
        two.id = Some(2);

        let mut links = vec![one, two];
        overlay_statuses(&mut links, &[status(2, "down")]);

        assert_eq!(links[0].state, "unknown");
        assert_eq!(links[1].state, "down");
        assert_eq!(links[1].latency_ms, Some(12.5));
        assert_eq!(links[1].last_change, Some(900));
    }

    #[test]
    fn a_real_system_backend_never_touches_the_system_in_test_builds() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            assert!(SystemBackend.nft_apply("x").await.is_err());
            assert!(SystemBackend.nft_check("x").await.is_err());
            assert!(SystemBackend.ip_batch("rule add x", false).await.is_err());
            assert!(SystemBackend.loosen_rp_filter("eth0").await.is_err());
        });
    }

    #[tokio::test]
    async fn the_commit_futures_can_be_spawned() {
        fn assert_send<T: Send>(_: &T) {}

        let pool = memory_pool().await;
        let lock = lock();

        assert_send(&SdwanCommit::commit(&pool, &lock));
        assert_send(&SdwanCommit::refresh(&pool, &lock));
        assert_send(&SdwanCommit::rollback(&pool, &lock));
        assert_send(&SdwanCommit::restore_on_boot(&pool, &lock));
    }

    // --------------------------------------------------------------- commit

    #[tokio::test]
    async fn a_commit_validates_then_applies_in_the_safe_order() {
        let (pool, _, _) = configured_pool().await;
        let backend = FakeBackend::new(&["eth0", "eth2"]);

        let message = commit_with(&backend, &pool, &lock(), Mode::User)
            .await
            .unwrap();

        assert_eq!(message, "SD-WAN applied: 2 link(s) and 1 rule(s) active");
        assert_eq!(
            backend.calls(),
            vec![
                "nft_check", "rp:eth0", "rp:eth2", "ip_remove", "ip_apply", "nft_apply"
            ]
        );

        for name in [CURRENT_JSON, CURRENT_NFT, CURRENT_IP] {
            assert!(backend.file(name).exists(), "{}", name);
        }
        assert!(!backend.file(PREVIOUS_JSON).exists());

        let table = fs::read_to_string(backend.file(CURRENT_NFT)).unwrap();
        assert!(table.starts_with("table ip iqsoft_sdwan {"));
    }

    #[tokio::test]
    async fn the_second_commit_keeps_the_first_as_the_rollback_target() {
        let (pool, _, _) = configured_pool().await;
        let backend = FakeBackend::new(&["eth0", "eth2"]);

        commit_with(&backend, &pool, &lock(), Mode::User).await.unwrap();
        SdwanService::add_rule(&pool, new_rule("extra", None)).await.unwrap();
        commit_with(&backend, &pool, &lock(), Mode::User).await.unwrap();

        let previous = read_snapshot(&backend.file(PREVIOUS_JSON)).unwrap().unwrap();
        let current = read_snapshot(&backend.file(CURRENT_JSON)).unwrap().unwrap();

        assert_eq!(previous.rules.len(), 1);
        assert_eq!(current.rules.len(), 2);
    }

    #[tokio::test]
    async fn a_missing_interface_stops_the_commit_before_anything_changes() {
        let (pool, _, _) = configured_pool().await;
        let backend = FakeBackend::new(&["eth0"]);

        let error = commit_with(&backend, &pool, &lock(), Mode::User)
            .await
            .unwrap_err();

        assert!(error.contains("'eth2' does not exist"), "{}", error);
        assert!(backend.calls().is_empty());
        assert!(!backend.file(CURRENT_JSON).exists());
    }

    #[tokio::test]
    async fn a_failed_nft_check_stops_the_commit_before_anything_changes() {
        let (pool, _, _) = configured_pool().await;
        let backend = FakeBackend::new(&["eth0", "eth2"]);
        backend.fail_nth("nft_check", 1);

        let error = commit_with(&backend, &pool, &lock(), Mode::User)
            .await
            .unwrap_err();

        assert!(error.starts_with("Validation failed, nothing was applied"), "{}", error);
        assert_eq!(backend.calls(), vec!["nft_check"]);
        assert!(!backend.file(CURRENT_JSON).exists());
    }

    #[tokio::test]
    async fn a_failed_first_commit_switches_everything_back_off() {
        let (pool, _, _) = configured_pool().await;
        let backend = FakeBackend::new(&["eth0", "eth2"]);
        backend.fail_nth("ip_apply", 1);

        let error = commit_with(&backend, &pool, &lock(), Mode::User)
            .await
            .unwrap_err();

        assert!(error.contains("the previous SD-WAN setup was restored"), "{}", error);
        assert!(error.contains("ip_apply failed on purpose"), "{}", error);

        // after the failure: switched off again (marking rules first, then the tables)
        let calls = backend.calls();
        assert_eq!(&calls[calls.len() - 2..], ["nft_remove", "ip_remove"]);
        assert!(!backend.file(CURRENT_JSON).exists());
    }

    #[tokio::test]
    async fn a_failed_commit_puts_the_last_good_setup_back() {
        let (pool, _, _) = configured_pool().await;
        let backend = FakeBackend::new(&["eth0", "eth2"]);

        commit_with(&backend, &pool, &lock(), Mode::User).await.unwrap();
        let good_json = fs::read_to_string(backend.file(CURRENT_JSON)).unwrap();

        SdwanService::add_rule(&pool, new_rule("extra", None)).await.unwrap();
        backend.clear_calls();
        backend.fail_nth("nft_apply", 1);

        let error = commit_with(&backend, &pool, &lock(), Mode::User)
            .await
            .unwrap_err();

        assert!(error.contains("the previous SD-WAN setup was restored"), "{}", error);

        // the failed attempt, then the old setup applied again in full
        assert_eq!(
            backend.calls(),
            vec![
                "nft_check", "rp:eth0", "rp:eth2", "ip_remove", "ip_apply", "nft_apply",
                "rp:eth0", "rp:eth2", "ip_remove", "ip_apply", "nft_apply"
            ]
        );

        // and the saved state is untouched
        assert_eq!(fs::read_to_string(backend.file(CURRENT_JSON)).unwrap(), good_json);
        assert!(!backend.file(PREVIOUS_JSON).exists());
    }

    #[tokio::test]
    async fn if_the_revert_fails_too_the_message_says_to_check_by_hand() {
        let (pool, _, _) = configured_pool().await;
        let backend = FakeBackend::new(&["eth0", "eth2"]);

        commit_with(&backend, &pool, &lock(), Mode::User).await.unwrap();
        SdwanService::add_rule(&pool, new_rule("extra", None)).await.unwrap();

        backend.clear_calls();
        backend.fail_nth("nft_apply", 1);
        backend.fail_nth("nft_apply", 2);

        let error = commit_with(&backend, &pool, &lock(), Mode::User)
            .await
            .unwrap_err();

        assert!(error.contains("restoring the previous setup also failed"), "{}", error);
        assert!(error.contains("check the routing rules and firewall rules manually"), "{}", error);
    }

    #[tokio::test]
    async fn switching_sdwan_off_removes_the_rules_first_and_the_tables_second() {
        let (pool, _, _) = configured_pool().await;
        let backend = FakeBackend::new(&["eth0", "eth2"]);

        commit_with(&backend, &pool, &lock(), Mode::User).await.unwrap();

        SdwanService::set_enabled(&pool, false).await.unwrap();
        backend.clear_calls();

        let message = commit_with(&backend, &pool, &lock(), Mode::User)
            .await
            .unwrap();

        assert_eq!(message, "SD-WAN is switched off, its routing and rules were removed");
        assert_eq!(backend.calls(), vec!["nft_remove", "ip_remove"]);
        assert_eq!(fs::read_to_string(backend.file(CURRENT_NFT)).unwrap(), "");
    }

    #[tokio::test]
    async fn a_disabled_link_does_not_need_to_exist() {
        let pool = memory_pool().await;
        SdwanService::add_link(&pool, new_link("ISP1", "eth0", 10)).await.unwrap();

        let mut spare = new_link("ISP2", "eth9", 20);
        spare.enabled = false;
        SdwanService::add_link(&pool, spare).await.unwrap();
        SdwanService::set_enabled(&pool, true).await.unwrap();

        let backend = FakeBackend::new(&["eth0"]);

        assert!(commit_with(&backend, &pool, &lock(), Mode::User).await.is_ok());
    }

    // -------------------------------------------------------------- refresh

    #[tokio::test]
    async fn a_refresh_before_any_commit_does_nothing() {
        let (pool, _, _) = configured_pool().await;
        let backend = FakeBackend::new(&["eth0", "eth2"]);

        let message = commit_with(&backend, &pool, &lock(), Mode::Automatic)
            .await
            .unwrap();

        assert!(message.contains("has not been committed yet"), "{}", message);
        assert!(backend.calls().is_empty());
    }

    #[tokio::test]
    async fn a_refresh_with_nothing_new_does_nothing() {
        let (pool, _, _) = configured_pool().await;
        let backend = FakeBackend::new(&["eth0", "eth2"]);

        commit_with(&backend, &pool, &lock(), Mode::User).await.unwrap();
        backend.clear_calls();

        let message = commit_with(&backend, &pool, &lock(), Mode::Automatic)
            .await
            .unwrap();

        assert_eq!(message, "SD-WAN is already up to date");
        assert!(backend.calls().is_empty());
    }

    #[tokio::test]
    async fn a_refresh_after_a_link_went_down_applies_but_keeps_the_rollback_target() {
        let (pool, one, _) = configured_pool().await;
        let backend = FakeBackend::new(&["eth0", "eth2"]);

        commit_with(&backend, &pool, &lock(), Mode::User).await.unwrap();
        SdwanService::add_rule(&pool, new_rule("extra", None)).await.unwrap();
        commit_with(&backend, &pool, &lock(), Mode::User).await.unwrap();

        let target_before = fs::read_to_string(backend.file(PREVIOUS_JSON)).unwrap();

        SdwanRepository::save_status(&pool, &status(one, "down")).await.unwrap();
        backend.clear_calls();

        let message = commit_with(&backend, &pool, &lock(), Mode::Automatic)
            .await
            .unwrap();

        assert!(message.starts_with("SD-WAN applied"), "{}", message);
        assert!(backend.calls().contains(&"nft_apply".to_string()));

        assert_eq!(
            fs::read_to_string(backend.file(PREVIOUS_JSON)).unwrap(),
            target_before
        );

        let current = read_snapshot(&backend.file(CURRENT_JSON)).unwrap().unwrap();
        assert_eq!(current.links[0].state, "down");
    }

    // ------------------------------------------------------------- rollback

    #[tokio::test]
    async fn a_rollback_needs_a_previous_setup() {
        let (pool, _, _) = configured_pool().await;
        let backend = FakeBackend::new(&["eth0", "eth2"]);

        let error = rollback_with(&backend, &pool, &lock()).await.unwrap_err();
        assert!(error.contains("No previous SD-WAN configuration"), "{}", error);

        commit_with(&backend, &pool, &lock(), Mode::User).await.unwrap();

        let error = rollback_with(&backend, &pool, &lock()).await.unwrap_err();
        assert!(error.contains("No previous SD-WAN configuration"), "{}", error);
    }

    #[tokio::test]
    async fn a_rollback_really_goes_back_to_the_older_setup() {
        let (pool, one, two) = configured_pool().await;
        let backend = FakeBackend::new(&["eth0", "eth2", "eth3"]);

        commit_with(&backend, &pool, &lock(), Mode::User).await.unwrap();

        let extra = SdwanService::add_rule(&pool, new_rule("extra", None)).await.unwrap();
        let three = SdwanService::add_link(&pool, new_link("ISP3", "eth3", 30))
            .await
            .unwrap();
        commit_with(&backend, &pool, &lock(), Mode::User).await.unwrap();

        // go back to: two links, one rule
        backend.clear_calls();
        rollback_with(&backend, &pool, &lock()).await.unwrap();

        let links = SdwanRepository::list_links(&pool).await.unwrap();
        let rules = SdwanRepository::list_rules(&pool).await.unwrap();

        assert_eq!(
            links.iter().map(|l| l.id.unwrap()).collect::<Vec<_>>(),
            vec![one, two]
        );
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "voice");
        assert_eq!(rules[0].link_id, Some(two));
        assert!(rules.iter().all(|r| r.id != Some(extra)));
        assert!(links.iter().all(|l| l.id != Some(three)));

        // the live system was given the older setup, and it is now the saved one
        let current = read_snapshot(&backend.file(CURRENT_JSON)).unwrap().unwrap();
        assert_eq!(current.links.len(), 2);
        assert_eq!(current.rules.len(), 1);
    }

    #[tokio::test]
    async fn a_rollback_keeps_the_live_health_of_links_that_still_exist() {
        let (pool, one, _) = configured_pool().await;
        let backend = FakeBackend::new(&["eth0", "eth2"]);

        commit_with(&backend, &pool, &lock(), Mode::User).await.unwrap();
        SdwanService::add_rule(&pool, new_rule("extra", None)).await.unwrap();
        commit_with(&backend, &pool, &lock(), Mode::User).await.unwrap();

        SdwanRepository::save_status(&pool, &status(one, "down")).await.unwrap();

        rollback_with(&backend, &pool, &lock()).await.unwrap();

        let link = SdwanRepository::get_link(&pool, one).await.unwrap().unwrap();
        assert_eq!(link.state, "down");
        assert_eq!(link.latency_ms, Some(12.5));
    }

    #[tokio::test]
    async fn a_rollback_to_a_missing_interface_changes_nothing() {
        let (pool, _, _) = configured_pool().await;
        let backend = FakeBackend::new(&["eth0", "eth2"]);

        commit_with(&backend, &pool, &lock(), Mode::User).await.unwrap();
        SdwanService::add_rule(&pool, new_rule("extra", None)).await.unwrap();
        commit_with(&backend, &pool, &lock(), Mode::User).await.unwrap();

        let broken = backend.sharing_files(&["eth0"]);

        let error = rollback_with(&broken, &pool, &lock()).await.unwrap_err();

        assert!(error.starts_with("Refusing to roll back, nothing was changed"), "{}", error);
        assert!(broken.calls().is_empty());
        assert_eq!(SdwanRepository::list_rules(&pool).await.unwrap().len(), 2);
    }

    // -------------------------------------------------------------- restore

    #[tokio::test]
    async fn restoring_without_a_saved_setup_does_nothing() {
        let (pool, _, _) = configured_pool().await;
        let backend = FakeBackend::new(&["eth0", "eth2"]);

        let message = restore_on_boot_with(&backend, &pool, &lock()).await.unwrap();

        assert!(message.contains("nothing was restored"), "{}", message);
        assert!(backend.calls().is_empty());
    }

    #[tokio::test]
    async fn restoring_a_disabled_setup_does_nothing() {
        let (pool, _, _) = configured_pool().await;
        let backend = FakeBackend::new(&["eth0", "eth2"]);

        SdwanService::set_enabled(&pool, false).await.unwrap();
        commit_with(&backend, &pool, &lock(), Mode::User).await.unwrap();
        backend.clear_calls();

        let message = restore_on_boot_with(&backend, &pool, &lock()).await.unwrap();

        assert_eq!(message, "SD-WAN is disabled, nothing was restored");
        assert!(backend.calls().is_empty());
    }

    #[tokio::test]
    async fn restoring_applies_the_saved_setup_with_the_current_link_health() {
        let (pool, one, _) = configured_pool().await;
        let backend = FakeBackend::new(&["eth0", "eth2"]);

        commit_with(&backend, &pool, &lock(), Mode::User).await.unwrap();

        // after the "reboot" the first link is known to be down
        SdwanRepository::save_status(&pool, &status(one, "down")).await.unwrap();
        backend.clear_calls();

        let message = restore_on_boot_with(&backend, &pool, &lock()).await.unwrap();

        assert_eq!(message, "Restored SD-WAN: 2 link(s) and 1 rule(s) active");
        assert_eq!(
            backend.calls(),
            vec!["rp:eth0", "rp:eth2", "ip_remove", "ip_apply", "nft_apply"]
        );

        // the restored table already leaves out the dead link
        let table = fs::read_to_string(backend.file(CURRENT_NFT)).unwrap();
        assert!(!table.contains("chain pick_1"));
        assert!(table.contains("chain pick_2"));
    }

    #[tokio::test]
    async fn restoring_reports_a_missing_interface() {
        let (pool, _, _) = configured_pool().await;
        let backend = FakeBackend::new(&["eth0", "eth2"]);
        commit_with(&backend, &pool, &lock(), Mode::User).await.unwrap();

        let broken = backend.sharing_files(&["eth0"]);

        let error = restore_on_boot_with(&broken, &pool, &lock()).await.unwrap_err();
        assert!(error.contains("could not be restored"), "{}", error);
        assert!(error.contains("'eth2'"), "{}", error);
    }

    #[tokio::test]
    async fn a_corrupt_snapshot_is_reported_not_ignored() {
        let (pool, _, _) = configured_pool().await;
        let backend = FakeBackend::new(&["eth0", "eth2"]);

        fs::create_dir_all(&backend.dir).unwrap();
        fs::write(backend.file(CURRENT_JSON), "{ nope").unwrap();

        let error = commit_with(&backend, &pool, &lock(), Mode::User)
            .await
            .unwrap_err();

        assert!(error.contains("is corrupt"), "{}", error);
        assert!(backend.calls().is_empty());
    }

    // ------------------------------------------------------------- database

    #[tokio::test]
    async fn restoring_the_database_keeps_ids_links_rules_and_settings() {
        let (pool, one, two) = configured_pool().await;

        let snapshot = SdwanSnapshot {
            enabled: false,
            links: {
                let mut l = new_link("ISP1", "eth0", 10);
                l.id = Some(one);
                vec![l]
            },
            rules: vec![{
                let mut r = new_rule("spread", None);
                r.id = Some(77);
                r
            }],
            nat_enabled: true,
            wan_interface: "eth0".to_string(),
        };

        SdwanRepository::save_status(&pool, &status(one, "up")).await.unwrap();

        restore_database(&pool, &snapshot).await.unwrap();

        let links = SdwanRepository::list_links(&pool).await.unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].id, Some(one));
        assert_eq!(links[0].state, "up");
        assert!(SdwanRepository::get_link(&pool, two).await.unwrap().is_none());

        let rules = SdwanRepository::list_rules(&pool).await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, Some(77));

        assert!(!SdwanRepository::get_settings(&pool).await.unwrap().enabled);
    }

    #[tokio::test]
    async fn a_failed_database_restore_changes_nothing() {
        let (pool, _, _) = configured_pool().await;

        // the rule points at a link that is not in the snapshot
        let snapshot = SdwanSnapshot {
            enabled: true,
            links: vec![{
                let mut l = new_link("ISP1", "eth0", 10);
                l.id = Some(1);
                l
            }],
            rules: vec![{
                let mut r = new_rule("bad", Some(99));
                r.id = Some(5);
                r
            }],
            nat_enabled: true,
            wan_interface: "eth0".to_string(),
        };

        assert!(restore_database(&pool, &snapshot).await.is_err());

        assert_eq!(SdwanRepository::list_links(&pool).await.unwrap().len(), 2);
        assert_eq!(SdwanRepository::list_rules(&pool).await.unwrap().len(), 1);
    }
}
