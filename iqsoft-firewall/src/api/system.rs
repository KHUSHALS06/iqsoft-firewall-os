use crate::{
    app_state::AppState,
    models::auth::User,
    services::audit_service::{AuditEvent, AuditService},
};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{sqlite::SqliteConnectOptions, ConnectOptions, Connection, Row};
use std::{
    fs,
    net::SocketAddr,
    path::Path,
    process::Command,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const MAX_RESTORE_BYTES: usize = 128 * 1024 * 1024;

pub const PENDING_PATH: &str = "database/restore.pending";
const DB_PATH: &str = "database/firewall.db";
const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";
const REQUIRED_TABLES: [&str; 3] = ["users", "firewall_rules", "audit_log"];

const ACTION_BACKUP: &str = "system.backup";
const ACTION_RESTORE: &str = "system.restore";
const ACTION_RESTORE_CANCEL: &str = "system.restore_cancel";
const ACTION_REBOOT: &str = "system.reboot";
const ACTION_SHUTDOWN: &str = "system.shutdown";

type Failure = (StatusCode, Json<Value>);

fn fail(status: StatusCode, message: &str) -> Failure {
    (status, Json(json!({ "error": message })))
}

fn require_admin(user: &User) -> Result<(), Failure> {
    if user.role != "admin" {
        return Err(fail(
            StatusCode::FORBIDDEN,
            "Only administrators can use system tools",
        ));
    }
    Ok(())
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn read_trimmed(path: &str) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn os_name() -> Option<String> {
    let text = fs::read_to_string("/etc/os-release").ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(|value| value.trim().trim_matches('"').to_string())
}

fn read_info() -> Value {
    json!({
        "product": "IQSOFT Firewall OS",
        "version": env!("CARGO_PKG_VERSION"),
        "hostname": read_trimmed("/proc/sys/kernel/hostname"),
        "kernel": read_trimmed("/proc/sys/kernel/osrelease"),
        "os": os_name(),
        "arch": std::env::consts::ARCH,
        "server_time": now_secs(),
        "database_bytes": fs::metadata(DB_PATH).map(|m| m.len()).ok(),
        "restore_pending": Path::new(PENDING_PATH).exists()
    })
}

pub async fn info(Extension(user): Extension<User>) -> Response {
    if let Err(denied) = require_admin(&user) {
        return denied.into_response();
    }

    match tokio::task::spawn_blocking(read_info).await {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(e) => {
            eprintln!("system: info task failed: {}", e);
            fail(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
        }
    }
}

pub async fn backup(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
) -> Response {
    if let Err(denied) = require_admin(&user) {
        return denied.into_response();
    }

    let stamp = now_secs();
    let temp = format!("database/backup-{}-{}.tmp", stamp, rand::random::<u32>());

    if let Err(e) = sqlx::query(&format!("VACUUM INTO '{}'", temp))
        .execute(&state.db)
        .await
    {
        eprintln!("system: backup failed: {}", e);
        let _ = fs::remove_file(&temp);
        AuditService::record(
            &state.db,
            AuditEvent::new(ACTION_BACKUP)
                .user(&user)
                .source_ip(addr.ip())
                .failed(),
        )
        .await;
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "Could not create the backup").into_response();
    }

    let bytes = tokio::fs::read(&temp).await;
    let _ = tokio::fs::remove_file(&temp).await;

    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("system: backup could not be read back: {}", e);
            return fail(StatusCode::INTERNAL_SERVER_ERROR, "Could not read the backup").into_response();
        }
    };

    AuditService::record(
        &state.db,
        AuditEvent::new(ACTION_BACKUP)
            .user(&user)
            .source_ip(addr.ip())
            .detail(&format!("{} bytes", bytes.len())),
    )
    .await;

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"iqsoft-firewall-backup-{}.db\"", stamp),
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        bytes,
    )
        .into_response()
}

async fn check_backup_file(path: &str) -> Result<(), String> {
    let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", path))
        .map_err(|_| "Could not open the uploaded file".to_string())?
        .read_only(true);

    let mut conn = options
        .connect()
        .await
        .map_err(|_| "The file is not a readable SQLite database".to_string())?;

    let integrity: String = sqlx::query("PRAGMA integrity_check")
        .fetch_one(&mut conn)
        .await
        .map_err(|_| "The file is not a readable SQLite database".to_string())?
        .try_get(0)
        .map_err(|_| "The database failed its integrity check".to_string())?;

    if integrity != "ok" {
        return Err("The database failed its integrity check".to_string());
    }

    for table in REQUIRED_TABLES {
        let found = sqlx::query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?")
            .bind(table)
            .fetch_optional(&mut conn)
            .await
            .map_err(|_| "The file is not a readable SQLite database".to_string())?;

        if found.is_none() {
            return Err(format!(
                "This is not an IQSOFT Firewall backup: table '{}' is missing",
                table
            ));
        }
    }

    let _ = conn.close().await;
    Ok(())
}

async fn reject_restore(state: &AppState, user: &User, addr: SocketAddr, message: &str) -> Response {
    AuditService::record(
        &state.db,
        AuditEvent::new(ACTION_RESTORE)
            .user(user)
            .source_ip(addr.ip())
            .detail(message)
            .failed(),
    )
    .await;

    fail(StatusCode::BAD_REQUEST, message).into_response()
}

pub async fn restore(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
    body: Bytes,
) -> Response {
    if let Err(denied) = require_admin(&user) {
        return denied.into_response();
    }

    if body.len() < 512 || !body.starts_with(SQLITE_MAGIC) {
        return reject_restore(&state, &user, addr, "That file is not an SQLite database").await;
    }

    let staging = format!("database/restore-{}-{}.check", now_secs(), rand::random::<u32>());

    if let Err(e) = tokio::fs::write(&staging, &body).await {
        eprintln!("system: could not store the uploaded backup: {}", e);
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "Could not store the uploaded file").into_response();
    }

    if let Err(message) = check_backup_file(&staging).await {
        let _ = tokio::fs::remove_file(&staging).await;
        return reject_restore(&state, &user, addr, &message).await;
    }

    if let Err(e) = tokio::fs::rename(&staging, PENDING_PATH).await {
        eprintln!("system: could not stage the restore: {}", e);
        let _ = tokio::fs::remove_file(&staging).await;
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "Could not stage the restore").into_response();
    }

    AuditService::record(
        &state.db,
        AuditEvent::new(ACTION_RESTORE)
            .user(&user)
            .source_ip(addr.ip())
            .detail(&format!("{} bytes staged", body.len())),
    )
    .await;

    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "message": "Backup checked and staged. It replaces the current configuration the next time the firewall service starts."
        })),
    )
        .into_response()
}

pub async fn cancel_restore(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
) -> Response {
    if let Err(denied) = require_admin(&user) {
        return denied.into_response();
    }

    match tokio::fs::remove_file(PENDING_PATH).await {
        Ok(_) => {
            AuditService::record(
                &state.db,
                AuditEvent::new(ACTION_RESTORE_CANCEL)
                    .user(&user)
                    .source_ip(addr.ip()),
            )
            .await;
            (StatusCode::OK, Json(json!({ "status": "ok", "message": "Pending restore cancelled." }))).into_response()
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            (StatusCode::OK, Json(json!({ "status": "ok", "message": "There was no pending restore." }))).into_response()
        }
        Err(e) => {
            eprintln!("system: could not cancel the restore: {}", e);
            fail(StatusCode::INTERNAL_SERVER_ERROR, "Could not cancel the pending restore").into_response()
        }
    }
}

fn run_systemctl(verb: &'static str) {
    for program in ["/usr/bin/systemctl", "/bin/systemctl", "systemctl"] {
        match Command::new(program).arg(verb).output() {
            Ok(output) if output.status.success() => return,
            Ok(output) => eprintln!(
                "system: {} {} failed: {}",
                program,
                verb,
                String::from_utf8_lossy(&output.stderr).trim()
            ),
            Err(e) => eprintln!("system: {}: {}", program, e),
        }
    }
}

async fn power(
    state: AppState,
    addr: SocketAddr,
    user: User,
    action: &'static str,
    verb: &'static str,
    message: &'static str,
) -> Response {
    if let Err(denied) = require_admin(&user) {
        return denied.into_response();
    }

    AuditService::record(
        &state.db,
        AuditEvent::new(action).user(&user).source_ip(addr.ip()),
    )
    .await;

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let _ = tokio::task::spawn_blocking(move || run_systemctl(verb)).await;
    });

    (StatusCode::OK, Json(json!({ "status": "ok", "message": message }))).into_response()
}

pub async fn reboot(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
) -> Response {
    power(state, addr, user, ACTION_REBOOT, "reboot", "Rebooting in a moment.").await
}

pub async fn shutdown(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
) -> Response {
    power(state, addr, user, ACTION_SHUTDOWN, "poweroff", "Shutting down in a moment.").await
}

const ACTION_SETTINGS: &str = "system.settings";

#[derive(Deserialize)]
pub struct SettingsUpdate {
    hostname: String,
    timezone: String,
    ntp_enabled: bool,
}

fn run_tool(program: &str, args: &[&str]) -> Result<String, String> {
    let candidates = [
        format!("/usr/bin/{}", program),
        format!("/bin/{}", program),
        program.to_string(),
    ];
    for path in candidates.iter() {
        match Command::new(path).args(args).output() {
            Ok(out) if out.status.success() => {
                return Ok(String::from_utf8_lossy(&out.stdout).into_owned())
            }
            Ok(out) => return Err(String::from_utf8_lossy(&out.stderr).trim().to_string()),
            Err(_) => continue,
        }
    }
    Err(format!("{} is not available on this system", program))
}

fn valid_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn list_timezones() -> Vec<String> {
    run_tool("timedatectl", &["list-timezones"])
        .map(|text| {
            text.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn read_settings() -> Result<Value, String> {
    let show = run_tool(
        "timedatectl",
        &["show", "-p", "Timezone", "-p", "NTP", "-p", "NTPSynchronized"],
    )?;

    let mut timezone = String::new();
    let mut ntp_enabled = false;
    let mut ntp_synchronized = false;

    for line in show.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key {
                "Timezone" => timezone = value.trim().to_string(),
                "NTP" => ntp_enabled = value.trim() == "yes",
                "NTPSynchronized" => ntp_synchronized = value.trim() == "yes",
                _ => {}
            }
        }
    }

    Ok(json!({
        "hostname": read_trimmed("/proc/sys/kernel/hostname"),
        "timezone": timezone,
        "ntp_enabled": ntp_enabled,
        "ntp_synchronized": ntp_synchronized,
        "timezones": list_timezones()
    }))
}

fn apply_settings(req: &SettingsUpdate) -> Result<(), String> {
    if !list_timezones().iter().any(|z| z == &req.timezone) {
        return Err("Unknown timezone".to_string());
    }

    let current_host = read_trimmed("/proc/sys/kernel/hostname").unwrap_or_default();

    run_tool("timedatectl", &["set-timezone", &req.timezone])?;
    run_tool(
        "timedatectl",
        &["set-ntp", if req.ntp_enabled { "true" } else { "false" }],
    )?;
    if req.hostname != current_host {
        run_tool("hostnamectl", &["set-hostname", &req.hostname])?;
    }
    Ok(())
}

pub async fn get_settings(Extension(user): Extension<User>) -> Response {
    if let Err(denied) = require_admin(&user) {
        return denied.into_response();
    }

    match tokio::task::spawn_blocking(read_settings).await {
        Ok(Ok(value)) => (StatusCode::OK, Json(value)).into_response(),
        Ok(Err(message)) => fail(StatusCode::INTERNAL_SERVER_ERROR, &message).into_response(),
        Err(e) => {
            eprintln!("system: settings read task failed: {}", e);
            fail(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
        }
    }
}

pub async fn update_settings(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user): Extension<User>,
    Json(req): Json<SettingsUpdate>,
) -> Response {
    if let Err(denied) = require_admin(&user) {
        return denied.into_response();
    }

    if !valid_hostname(&req.hostname) {
        return fail(
            StatusCode::BAD_REQUEST,
            "Host name must be 1-63 characters: lowercase letters, digits and hyphens, not starting or ending with a hyphen",
        )
        .into_response();
    }

    let detail = format!(
        "host={} timezone={} ntp={}",
        req.hostname, req.timezone, req.ntp_enabled
    );

    let result = tokio::task::spawn_blocking(move || apply_settings(&req)).await;

    match result {
        Ok(Ok(())) => {
            AuditService::record(
                &state.db,
                AuditEvent::new(ACTION_SETTINGS)
                    .user(&user)
                    .source_ip(addr.ip())
                    .detail(&detail),
            )
            .await;
            (
                StatusCode::OK,
                Json(json!({ "status": "ok", "message": "Settings saved." })),
            )
                .into_response()
        }
        Ok(Err(message)) => {
            AuditService::record(
                &state.db,
                AuditEvent::new(ACTION_SETTINGS)
                    .user(&user)
                    .source_ip(addr.ip())
                    .detail(&message)
                    .failed(),
            )
            .await;
            fail(StatusCode::BAD_REQUEST, &message).into_response()
        }
        Err(e) => {
            eprintln!("system: settings task failed: {}", e);
            fail(StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
        }
    }
}
