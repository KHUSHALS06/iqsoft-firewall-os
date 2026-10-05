use crate::{
    models::auth::User,
    repository::audit_repository::{AuditEntry, AuditFilter, AuditRepository, NewAuditEntry},
    services::auth_service::AuthService,
};
use sqlx::SqlitePool;
use std::net::IpAddr;

/// Names for the events we record. Using constants keeps the spelling identical
/// everywhere, so filtering the trail by action always finds what you expect.
pub mod actions {
    pub const LOGIN: &str = "auth.login";
    pub const LOGOUT: &str = "auth.logout";
    pub const PASSWORD_CHANGE: &str = "auth.password_change";

    pub const RULE_CREATE: &str = "rule.create";
    pub const RULE_UPDATE: &str = "rule.update";
    pub const RULE_DELETE: &str = "rule.delete";

    pub const COMMIT: &str = "firewall.commit";
    pub const COMMIT_CONFIRM: &str = "firewall.commit_confirm";
    pub const ROLLBACK: &str = "firewall.rollback";

    pub const ACCESS_DENIED: &str = "auth.access_denied";
}

const MAX_ACTION: usize = 64;
const MAX_USERNAME: usize = 128;
const MAX_TARGET: usize = 256;
const MAX_DETAIL: usize = 1024;
const MAX_SOURCE_IP: usize = 64;

/// One thing that happened, built up step by step and then handed to
/// [`AuditService::record`].
///
/// Never put secrets in here. Passwords, session tokens and private keys must not
/// appear in `target` or `detail`, because the trail is meant to be read by people.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    user_id: Option<i64>,
    username: Option<String>,
    action: String,
    target: Option<String>,
    detail: Option<String>,
    success: bool,
    source_ip: Option<String>,
}

impl AuditEvent {
    /// A successful event. Call [`failed`](Self::failed) to mark it as a failure.
    pub fn new(action: &str) -> Self {
        Self {
            user_id: None,
            username: None,
            action: action.to_string(),
            target: None,
            detail: None,
            success: true,
            source_ip: None,
        }
    }

    /// Who did it, when we have a logged-in user.
    pub fn user(mut self, user: &User) -> Self {
        self.user_id = Some(user.id);
        self.username = Some(user.username.clone());
        self
    }

    /// Who did it, when all we have is a name, for example a failed login.
    pub fn username(mut self, username: &str) -> Self {
        self.username = Some(username.to_string());
        self
    }

    /// What it was done to, for example `rule:42`.
    pub fn target(mut self, target: &str) -> Self {
        self.target = Some(target.to_string());
        self
    }

    /// A short human-readable note.
    pub fn detail(mut self, detail: &str) -> Self {
        self.detail = Some(detail.to_string());
        self
    }

    pub fn source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip.to_string());
        self
    }

    pub fn failed(mut self) -> Self {
        self.success = false;
        self
    }

    /// Turns the event into what is stored. Text fields are cleaned here so that
    /// nothing reaches the database that could forge or break a log line.
    fn into_new_entry(self, now: i64) -> NewAuditEntry {
        NewAuditEntry {
            created_at: now,
            user_id: self.user_id,
            username: clean(&self.username.unwrap_or_default(), MAX_USERNAME),
            action: clean(&self.action, MAX_ACTION).unwrap_or_else(|| "unknown".to_string()),
            target: clean(&self.target.unwrap_or_default(), MAX_TARGET),
            detail: clean(&self.detail.unwrap_or_default(), MAX_DETAIL),
            success: self.success,
            source_ip: clean(&self.source_ip.unwrap_or_default(), MAX_SOURCE_IP),
        }
    }
}

/// Replaces control characters (newlines, tabs, escape codes) with spaces, trims,
/// and cuts to `max` characters. Returns `None` when nothing is left.
///
/// Cutting is done by characters, not bytes, so multi-byte text never splits in the middle.
fn clean(value: &str, max: usize) -> Option<String> {
    let replaced: String = value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();

    let trimmed = replaced.trim();
    if trimmed.is_empty() {
        return None;
    }

    Some(trimmed.chars().take(max).collect())
}

pub struct AuditService;

impl AuditService {
    /// Records an event and reports any database error to the caller.
    /// Mostly useful in tests; handlers should use [`record`](Self::record).
    pub async fn try_record(pool: &SqlitePool, event: AuditEvent) -> Result<i64, sqlx::Error> {
        let entry = event.into_new_entry(AuthService::now());
        AuditRepository::insert(pool, &entry).await
    }

    /// Records an event. A problem with the audit table must never stop the
    /// administrator from doing their job, so errors are printed and then dropped.
    pub async fn record(pool: &SqlitePool, event: AuditEvent) {
        let action = event.action.clone();

        if let Err(e) = Self::try_record(pool, event).await {
            eprintln!("audit: could not record '{}': {}", action, e);
        }
    }

    pub async fn list(
        pool: &SqlitePool,
        filter: &AuditFilter,
    ) -> Result<Vec<AuditEntry>, sqlx::Error> {
        AuditRepository::list(pool, filter).await
    }

    pub async fn count(pool: &SqlitePool, filter: &AuditFilter) -> Result<i64, sqlx::Error> {
        AuditRepository::count(pool, filter).await
    }

    /// Retention. Keeps at least one day, so a typo like `0` cannot wipe the whole trail.
    pub async fn purge_older_than_days(pool: &SqlitePool, days: i64) -> Result<u64, sqlx::Error> {
        let days = days.max(1);
        let cutoff = AuthService::now().saturating_sub(days.saturating_mul(86_400));

        AuditRepository::delete_older_than(pool, cutoff).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::init::initialize_database;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn memory_pool() -> SqlitePool {
        // One connection, otherwise every connection would get its own empty in-memory database.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        initialize_database(&pool).await.unwrap();
        pool
    }

    fn user() -> User {
        User {
            id: 7,
            username: "admin".into(),
            password_hash: "not-a-real-hash".into(),
            role: "admin".into(),
        }
    }

    async fn all(pool: &SqlitePool) -> Vec<AuditEntry> {
        AuditService::list(pool, &AuditFilter::default()).await.unwrap()
    }

    #[tokio::test]
    async fn records_who_did_what_to_what() {
        let pool = memory_pool().await;

        AuditService::try_record(
            &pool,
            AuditEvent::new(actions::RULE_CREATE)
                .user(&user())
                .target("rule:42")
                .detail("allow tcp 22")
                .source_ip("10.0.0.5".parse().unwrap()),
        )
        .await
        .unwrap();

        let rows = all(&pool).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].user_id, Some(7));
        assert_eq!(rows[0].username.as_deref(), Some("admin"));
        assert_eq!(rows[0].action, "rule.create");
        assert_eq!(rows[0].target.as_deref(), Some("rule:42"));
        assert_eq!(rows[0].detail.as_deref(), Some("allow tcp 22"));
        assert_eq!(rows[0].source_ip.as_deref(), Some("10.0.0.5"));
        assert!(rows[0].success);
        assert!(rows[0].created_at > 0);
    }

    #[tokio::test]
    async fn failed_events_are_marked_and_can_have_a_name_without_a_user_id() {
        let pool = memory_pool().await;

        AuditService::try_record(
            &pool,
            AuditEvent::new(actions::LOGIN)
                .username("ghost")
                .source_ip("2001:db8::1".parse().unwrap())
                .failed(),
        )
        .await
        .unwrap();

        let rows = all(&pool).await;
        assert_eq!(rows[0].user_id, None);
        assert_eq!(rows[0].username.as_deref(), Some("ghost"));
        assert_eq!(rows[0].source_ip.as_deref(), Some("2001:db8::1"));
        assert!(!rows[0].success);
    }

    #[test]
    fn control_characters_cannot_forge_extra_log_lines() {
        let entry = AuditEvent::new("rule.delete")
            .username("evil\nadmin\r\nlogin ok")
            .detail("line one\nline two\t\x1b[31mred")
            .into_new_entry(1);

        assert_eq!(entry.username.as_deref(), Some("evil admin  login ok"));
        assert_eq!(entry.detail.as_deref(), Some("line one line two  [31mred"));
        assert!(!entry.detail.unwrap().chars().any(|c| c.is_control()));
    }

    #[test]
    fn long_text_is_cut_by_characters_not_bytes() {
        // Two bytes per character: cutting by bytes could split one in half.
        let entry = AuditEvent::new("x")
            .detail(&"é".repeat(5_000))
            .target(&"t".repeat(5_000))
            .username(&"u".repeat(5_000))
            .into_new_entry(1);

        assert_eq!(entry.detail.unwrap().chars().count(), MAX_DETAIL);
        assert_eq!(entry.target.unwrap().chars().count(), MAX_TARGET);
        assert_eq!(entry.username.unwrap().chars().count(), MAX_USERNAME);
    }

    #[test]
    fn blank_optional_fields_become_none_and_blank_action_becomes_unknown() {
        let entry = AuditEvent::new("   ")
            .target("   ")
            .detail("\n\t")
            .username("")
            .into_new_entry(1);

        assert_eq!(entry.action, "unknown");
        assert_eq!(entry.target, None);
        assert_eq!(entry.detail, None);
        assert_eq!(entry.username, None);
    }

    #[tokio::test]
    async fn a_broken_audit_table_never_stops_the_caller() {
        let pool = memory_pool().await;
        pool.close().await;

        // Must return normally. The error is printed, not propagated and not a panic.
        AuditService::record(&pool, AuditEvent::new(actions::COMMIT).user(&user())).await;

        assert!(AuditService::try_record(&pool, AuditEvent::new(actions::COMMIT))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn purge_removes_old_entries_and_keeps_recent_ones() {
        let pool = memory_pool().await;
        let now = AuthService::now();

        for at in [now - 40 * 86_400, now - 10 * 86_400, now] {
            AuditRepository::insert(
                &pool,
                &AuditEvent::new(actions::LOGIN).into_new_entry(at),
            )
            .await
            .unwrap();
        }

        let removed = AuditService::purge_older_than_days(&pool, 30).await.unwrap();
        assert_eq!(removed, 1);
        assert_eq!(all(&pool).await.len(), 2);
    }

    #[tokio::test]
    async fn purge_never_wipes_everything_even_when_asked_for_zero_or_negative_days() {
        let pool = memory_pool().await;

        AuditService::try_record(&pool, AuditEvent::new(actions::LOGIN)).await.unwrap();

        assert_eq!(AuditService::purge_older_than_days(&pool, 0).await.unwrap(), 0);
        assert_eq!(AuditService::purge_older_than_days(&pool, -50).await.unwrap(), 0);
        assert_eq!(all(&pool).await.len(), 1);
    }

    #[tokio::test]
    async fn list_and_count_pass_filters_through() {
        let pool = memory_pool().await;

        AuditService::try_record(&pool, AuditEvent::new(actions::LOGIN).username("a")).await.unwrap();
        AuditService::try_record(&pool, AuditEvent::new(actions::LOGIN).username("b").failed())
            .await
            .unwrap();
        AuditService::try_record(&pool, AuditEvent::new(actions::COMMIT).username("a")).await.unwrap();

        let filter = AuditFilter {
            username: Some("a".into()),
            ..AuditFilter::default()
        };

        assert_eq!(AuditService::list(&pool, &filter).await.unwrap().len(), 2);
        assert_eq!(AuditService::count(&pool, &filter).await.unwrap(), 2);

        let failures = AuditFilter {
            success: Some(false),
            ..AuditFilter::default()
        };
        assert_eq!(AuditService::count(&pool, &failures).await.unwrap(), 1);
    }
}
