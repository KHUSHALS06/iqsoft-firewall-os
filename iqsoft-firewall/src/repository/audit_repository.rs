use serde::Serialize;
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool};

/// Largest page the API is allowed to ask for in one go.
pub const MAX_PAGE_SIZE: i64 = 500;

/// Page size used when the caller does not say.
pub const DEFAULT_PAGE_SIZE: i64 = 100;

/// One row of the audit trail, as stored.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub id: i64,
    pub created_at: i64,
    pub user_id: Option<i64>,
    pub username: Option<String>,
    pub action: String,
    pub target: Option<String>,
    pub detail: Option<String>,
    pub success: bool,
    pub source_ip: Option<String>,
}

/// What a caller supplies to record an event. The id is assigned by the database.
#[derive(Debug, Clone)]
pub struct NewAuditEntry {
    pub created_at: i64,
    pub user_id: Option<i64>,
    pub username: Option<String>,
    pub action: String,
    pub target: Option<String>,
    pub detail: Option<String>,
    pub success: bool,
    pub source_ip: Option<String>,
}

/// Optional filters for reading the trail. Every field left as `None` is not filtered on.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub username: Option<String>,
    pub action: Option<String>,
    pub success: Option<bool>,
    /// Inclusive lower bound on `created_at` (unix seconds).
    pub since: Option<i64>,
    /// Inclusive upper bound on `created_at` (unix seconds).
    pub until: Option<i64>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub struct AuditRepository;

impl AuditRepository {
    pub async fn insert(pool: &SqlitePool, entry: &NewAuditEntry) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO audit_log
                (created_at, user_id, username, action, target, detail, success, source_ip)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(entry.created_at)
        .bind(entry.user_id)
        .bind(&entry.username)
        .bind(&entry.action)
        .bind(&entry.target)
        .bind(&entry.detail)
        .bind(if entry.success { 1_i64 } else { 0_i64 })
        .bind(&entry.source_ip)
        .execute(pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    /// Newest first. Ties on the timestamp are broken by id, so paging is stable.
    pub async fn list(
        pool: &SqlitePool,
        filter: &AuditFilter,
    ) -> Result<Vec<AuditEntry>, sqlx::Error> {
        let mut builder: QueryBuilder<Sqlite> = QueryBuilder::new(
            "SELECT id, created_at, user_id, username, action, target, detail, success, source_ip \
             FROM audit_log",
        );
        Self::push_filters(&mut builder, filter);

        builder.push(" ORDER BY created_at DESC, id DESC LIMIT ");
        builder.push_bind(Self::clamp_limit(filter.limit));
        builder.push(" OFFSET ");
        builder.push_bind(filter.offset.unwrap_or(0).max(0));

        let rows = builder.build().fetch_all(pool).await?;

        Ok(rows
            .into_iter()
            .map(|row| AuditEntry {
                id: row.get("id"),
                created_at: row.get("created_at"),
                user_id: row.get("user_id"),
                username: row.get("username"),
                action: row.get("action"),
                target: row.get("target"),
                detail: row.get("detail"),
                success: row.get::<i64, _>("success") != 0,
                source_ip: row.get("source_ip"),
            })
            .collect())
    }

    /// How many rows match the filter, ignoring `limit` and `offset`.
    pub async fn count(pool: &SqlitePool, filter: &AuditFilter) -> Result<i64, sqlx::Error> {
        let mut builder: QueryBuilder<Sqlite> =
            QueryBuilder::new("SELECT COUNT(*) AS c FROM audit_log");
        Self::push_filters(&mut builder, filter);

        let row = builder.build().fetch_one(pool).await?;
        Ok(row.get::<i64, _>("c"))
    }

    /// Retention: remove everything older than `cutoff`. Returns the number of rows removed.
    pub async fn delete_older_than(pool: &SqlitePool, cutoff: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM audit_log WHERE created_at < ?")
            .bind(cutoff)
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }

    fn clamp_limit(limit: Option<i64>) -> i64 {
        limit.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE)
    }

    /// Every value goes through a bind, never into the SQL text, so a filter coming
    /// straight from a query string cannot inject anything.
    fn push_filters(builder: &mut QueryBuilder<'_, Sqlite>, filter: &AuditFilter) {
        let mut first = true;
        let mut glue = |builder: &mut QueryBuilder<'_, Sqlite>| {
            builder.push(if first { " WHERE " } else { " AND " });
            first = false;
        };

        if let Some(username) = &filter.username {
            glue(builder);
            builder.push("username = ");
            builder.push_bind(username.clone());
        }
        if let Some(action) = &filter.action {
            glue(builder);
            builder.push("action = ");
            builder.push_bind(action.clone());
        }
        if let Some(success) = filter.success {
            glue(builder);
            builder.push("success = ");
            builder.push_bind(if success { 1_i64 } else { 0_i64 });
        }
        if let Some(since) = filter.since {
            glue(builder);
            builder.push("created_at >= ");
            builder.push_bind(since);
        }
        if let Some(until) = filter.until {
            glue(builder);
            builder.push("created_at <= ");
            builder.push_bind(until);
        }
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

    fn entry(at: i64, user: &str, action: &str, success: bool) -> NewAuditEntry {
        NewAuditEntry {
            created_at: at,
            user_id: Some(1),
            username: Some(user.into()),
            action: action.into(),
            target: None,
            detail: None,
            success,
            source_ip: None,
        }
    }

    #[tokio::test]
    async fn insert_then_list_round_trips_every_field() {
        let pool = memory_pool().await;

        let id = AuditRepository::insert(
            &pool,
            &NewAuditEntry {
                created_at: 1_700_000_000,
                user_id: Some(7),
                username: Some("admin".into()),
                action: "rule.create".into(),
                target: Some("rule:42".into()),
                detail: Some("allow tcp 22".into()),
                success: true,
                source_ip: Some("10.0.0.5".into()),
            },
        )
        .await
        .unwrap();

        let rows = AuditRepository::list(&pool, &AuditFilter::default())
            .await
            .unwrap();

        assert_eq!(
            rows,
            vec![AuditEntry {
                id,
                created_at: 1_700_000_000,
                user_id: Some(7),
                username: Some("admin".into()),
                action: "rule.create".into(),
                target: Some("rule:42".into()),
                detail: Some("allow tcp 22".into()),
                success: true,
                source_ip: Some("10.0.0.5".into()),
            }]
        );
    }

    #[tokio::test]
    async fn optional_fields_may_be_empty() {
        let pool = memory_pool().await;

        // A failed login for a name that does not exist has no user id.
        AuditRepository::insert(
            &pool,
            &NewAuditEntry {
                created_at: 10,
                user_id: None,
                username: Some("ghost".into()),
                action: "login".into(),
                target: None,
                detail: None,
                success: false,
                source_ip: None,
            },
        )
        .await
        .unwrap();

        let rows = AuditRepository::list(&pool, &AuditFilter::default())
            .await
            .unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].user_id, None);
        assert!(!rows[0].success);
    }

    #[tokio::test]
    async fn list_is_newest_first_with_id_breaking_ties() {
        let pool = memory_pool().await;

        let a = AuditRepository::insert(&pool, &entry(100, "a", "login", true)).await.unwrap();
        let b = AuditRepository::insert(&pool, &entry(300, "b", "login", true)).await.unwrap();
        let c = AuditRepository::insert(&pool, &entry(300, "c", "login", true)).await.unwrap();

        let ids: Vec<i64> = AuditRepository::list(&pool, &AuditFilter::default())
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();

        assert_eq!(ids, vec![c, b, a]);
    }

    #[tokio::test]
    async fn filters_combine_with_and() {
        let pool = memory_pool().await;

        AuditRepository::insert(&pool, &entry(100, "alice", "login", true)).await.unwrap();
        AuditRepository::insert(&pool, &entry(200, "alice", "login", false)).await.unwrap();
        AuditRepository::insert(&pool, &entry(300, "bob", "login", false)).await.unwrap();
        AuditRepository::insert(&pool, &entry(400, "alice", "commit", true)).await.unwrap();

        let failed_logins_by_alice = AuditFilter {
            username: Some("alice".into()),
            action: Some("login".into()),
            success: Some(false),
            ..AuditFilter::default()
        };
        let rows = AuditRepository::list(&pool, &failed_logins_by_alice).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].created_at, 200);

        let all_failures = AuditFilter {
            success: Some(false),
            ..AuditFilter::default()
        };
        assert_eq!(AuditRepository::list(&pool, &all_failures).await.unwrap().len(), 2);

        let only_successes = AuditFilter {
            success: Some(true),
            ..AuditFilter::default()
        };
        assert_eq!(AuditRepository::list(&pool, &only_successes).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn time_range_is_inclusive_on_both_ends() {
        let pool = memory_pool().await;

        for at in [100, 200, 300, 400] {
            AuditRepository::insert(&pool, &entry(at, "u", "login", true)).await.unwrap();
        }

        let filter = AuditFilter {
            since: Some(200),
            until: Some(300),
            ..AuditFilter::default()
        };
        let times: Vec<i64> = AuditRepository::list(&pool, &filter)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.created_at)
            .collect();

        assert_eq!(times, vec![300, 200]);
    }

    #[tokio::test]
    async fn paging_and_count_ignore_each_other() {
        let pool = memory_pool().await;

        for at in 1..=5 {
            AuditRepository::insert(&pool, &entry(at, "u", "login", true)).await.unwrap();
        }

        let page = AuditFilter {
            limit: Some(2),
            offset: Some(2),
            ..AuditFilter::default()
        };
        let times: Vec<i64> = AuditRepository::list(&pool, &page)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.created_at)
            .collect();

        assert_eq!(times, vec![3, 2]);
        // The total is for the whole match, not for the page.
        assert_eq!(AuditRepository::count(&pool, &page).await.unwrap(), 5);
    }

    #[tokio::test]
    async fn limit_is_clamped_and_negative_offset_is_ignored() {
        assert_eq!(AuditRepository::clamp_limit(None), DEFAULT_PAGE_SIZE);
        assert_eq!(AuditRepository::clamp_limit(Some(0)), 1);
        assert_eq!(AuditRepository::clamp_limit(Some(-5)), 1);
        assert_eq!(AuditRepository::clamp_limit(Some(10_000)), MAX_PAGE_SIZE);

        let pool = memory_pool().await;
        AuditRepository::insert(&pool, &entry(1, "u", "login", true)).await.unwrap();

        let filter = AuditFilter {
            offset: Some(-3),
            ..AuditFilter::default()
        };
        assert_eq!(AuditRepository::list(&pool, &filter).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn hostile_filter_text_is_treated_as_data() {
        let pool = memory_pool().await;
        AuditRepository::insert(&pool, &entry(1, "admin", "login", true)).await.unwrap();

        let filter = AuditFilter {
            username: Some("x' OR '1'='1".into()),
            ..AuditFilter::default()
        };

        assert!(AuditRepository::list(&pool, &filter).await.unwrap().is_empty());
        assert_eq!(AuditRepository::count(&pool, &filter).await.unwrap(), 0);
        // The table is still there and still holds its row.
        assert_eq!(
            AuditRepository::count(&pool, &AuditFilter::default()).await.unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn delete_older_than_keeps_the_boundary_row() {
        let pool = memory_pool().await;

        for at in [100, 200, 300] {
            AuditRepository::insert(&pool, &entry(at, "u", "login", true)).await.unwrap();
        }

        let removed = AuditRepository::delete_older_than(&pool, 200).await.unwrap();
        assert_eq!(removed, 1);

        let times: Vec<i64> = AuditRepository::list(&pool, &AuditFilter::default())
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.created_at)
            .collect();
        assert_eq!(times, vec![300, 200]);
    }
}
