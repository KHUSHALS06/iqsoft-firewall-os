use crate::models::firewall_rule::FirewallRule;
use sqlx::{Row, SqlitePool};

pub struct FirewallRepository;

impl FirewallRepository {
    pub async fn add_rule(
        pool: &SqlitePool,
        rule: FirewallRule,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO firewall_rules (
                name,
                enabled,
                priority,
                chain_name,
                action,
                protocol,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                port_any,
                interface_name,
                src_mac,
                time_start,
                time_end,
                days,
                rate_limit,
                log_enabled,
                comment
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(rule.name)
        .bind(rule.enabled)
        .bind(rule.priority)
        .bind(rule.chain_name)
        .bind(rule.action)
        .bind(rule.protocol)
        .bind(rule.src_ip)
        .bind(rule.dst_ip)
        .bind(rule.src_port)
        .bind(rule.dst_port)
        .bind(rule.port_any)
        .bind(rule.interface_name)
        .bind(rule.src_mac)
        .bind(rule.time_start)
        .bind(rule.time_end)
        .bind(rule.days)
        .bind(rule.rate_limit)
        .bind(rule.log_enabled)
        .bind(rule.comment)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn list_rules(
        pool: &SqlitePool,
    ) -> Result<Vec<FirewallRule>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                name,
                enabled,
                priority,
                chain_name,
                action,
                protocol,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                port_any,
                interface_name,
                src_mac,
                time_start,
                time_end,
                days,
                rate_limit,
                log_enabled,
                comment
            FROM firewall_rules
            ORDER BY priority ASC, id ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        let mut rules = Vec::new();

        for row in rows {
            rules.push(FirewallRule {
                id: Some(row.get("id")),

                name: row.get("name"),
                enabled: row.get::<i64, _>("enabled") != 0,
                priority: row.get("priority"),

                chain_name: row.get("chain_name"),
                action: row.get("action"),
                protocol: row.get("protocol"),

                src_ip: row.get("src_ip"),
                dst_ip: row.get("dst_ip"),

                src_port: row.get("src_port"),
                dst_port: row.get("dst_port"),
                port_any: row.get::<i64, _>("port_any") != 0,

                interface_name: row.get("interface_name"),

                src_mac: row.get("src_mac"),

                time_start: row.get("time_start"),
                time_end: row.get("time_end"),
                days: row.get("days"),

                rate_limit: row.get("rate_limit"),

                log_enabled: row.get::<i64, _>("log_enabled") != 0,

                comment: row.get("comment"),
            });
        }

        Ok(rules)
    }

    pub async fn update_rule(
        pool: &SqlitePool,
        id: i64,
        rule: FirewallRule,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE firewall_rules
            SET
                name=?,
                enabled=?,
                priority=?,
                chain_name=?,
                action=?,
                protocol=?,
                src_ip=?,
                dst_ip=?,
                src_port=?,
                dst_port=?,
                port_any=?,
                interface_name=?,
                src_mac=?,
                time_start=?,
                time_end=?,
                days=?,
                rate_limit=?,
                log_enabled=?,
                comment=?
            WHERE id=?
            "#,
        )
        .bind(rule.name)
        .bind(rule.enabled)
        .bind(rule.priority)
        .bind(rule.chain_name)
        .bind(rule.action)
        .bind(rule.protocol)
        .bind(rule.src_ip)
        .bind(rule.dst_ip)
        .bind(rule.src_port)
        .bind(rule.dst_port)
        .bind(rule.port_any)
        .bind(rule.interface_name)
        .bind(rule.src_mac)
        .bind(rule.time_start)
        .bind(rule.time_end)
        .bind(rule.days)
        .bind(rule.rate_limit)
        .bind(rule.log_enabled)
        .bind(rule.comment)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn delete_rule(
        pool: &SqlitePool,
        id: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM firewall_rules WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        Ok(())
    }

    pub async fn replace_all_rules(
        pool: &SqlitePool,
        rules: Vec<FirewallRule>,
    ) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query("DELETE FROM firewall_rules")
            .execute(&mut *tx)
            .await?;

        for rule in rules {
            sqlx::query(
                r#"
                INSERT INTO firewall_rules (
                    id,
                    name,
                    enabled,
                    priority,
                    chain_name,
                    action,
                    protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    port_any,
                    interface_name,
                    src_mac,
                    time_start,
                    time_end,
                    days,
                    rate_limit,
                    log_enabled,
                    comment
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(rule.id)
            .bind(rule.name)
            .bind(rule.enabled)
            .bind(rule.priority)
            .bind(rule.chain_name)
            .bind(rule.action)
            .bind(rule.protocol)
            .bind(rule.src_ip)
            .bind(rule.dst_ip)
            .bind(rule.src_port)
            .bind(rule.dst_port)
            .bind(rule.port_any)
            .bind(rule.interface_name)
            .bind(rule.src_mac)
            .bind(rule.time_start)
            .bind(rule.time_end)
            .bind(rule.days)
            .bind(rule.rate_limit)
            .bind(rule.log_enabled)
            .bind(rule.comment)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::FirewallRepository;
    use crate::database::init::initialize_database;
    use crate::models::firewall_rule::FirewallRule;
    use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};

    async fn memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        initialize_database(&pool).await.unwrap();
        pool
    }

    fn rule(name: &str, src_mac: Option<&str>) -> FirewallRule {
        FirewallRule {
            id: None,
            name: name.into(),
            enabled: true,
            priority: 100,
            chain_name: "INPUT".into(),
            action: "drop".into(),
            protocol: "any".into(),
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            port_any: false,
            interface_name: None,
            src_mac: src_mac.map(String::from),
            time_start: None,
            time_end: None,
            days: None,
            rate_limit: None,
            log_enabled: false,
            comment: None,
        }
    }

    #[tokio::test]
    async fn src_mac_round_trips_through_add_and_list() {
        let pool = memory_pool().await;

        FirewallRepository::add_rule(&pool, rule("with mac", Some("aa:bb:cc:dd:ee:ff"))).await.unwrap();
        FirewallRepository::add_rule(&pool, rule("without mac", None)).await.unwrap();

        let rules = FirewallRepository::list_rules(&pool).await.unwrap();

        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].src_mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(rules[1].src_mac, None);
    }

    #[tokio::test]
    async fn update_can_set_change_and_clear_src_mac() {
        let pool = memory_pool().await;

        FirewallRepository::add_rule(&pool, rule("r", None)).await.unwrap();
        let id = FirewallRepository::list_rules(&pool).await.unwrap()[0].id.unwrap();

        FirewallRepository::update_rule(&pool, id, rule("r", Some("aa:bb:cc:dd:ee:ff"))).await.unwrap();
        assert_eq!(
            FirewallRepository::list_rules(&pool).await.unwrap()[0].src_mac.as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );

        FirewallRepository::update_rule(&pool, id, rule("r", Some("00:11:22:33:44:55"))).await.unwrap();
        assert_eq!(
            FirewallRepository::list_rules(&pool).await.unwrap()[0].src_mac.as_deref(),
            Some("00:11:22:33:44:55")
        );

        FirewallRepository::update_rule(&pool, id, rule("r", None)).await.unwrap();
        assert_eq!(FirewallRepository::list_rules(&pool).await.unwrap()[0].src_mac, None);
    }

    #[tokio::test]
    async fn replace_all_rules_restores_src_mac() {
        let pool = memory_pool().await;

        FirewallRepository::add_rule(&pool, rule("keep", Some("aa:bb:cc:dd:ee:ff"))).await.unwrap();
        let snapshot = FirewallRepository::list_rules(&pool).await.unwrap();

        FirewallRepository::update_rule(&pool, snapshot[0].id.unwrap(), rule("changed", None)).await.unwrap();
        FirewallRepository::replace_all_rules(&pool, snapshot).await.unwrap();

        let rules = FirewallRepository::list_rules(&pool).await.unwrap();

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "keep");
        assert_eq!(rules[0].src_mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
    }

    #[tokio::test]
    async fn time_fields_round_trip_update_and_restore() {
        let pool = memory_pool().await;

        let mut timed = rule("office hours", None);
        timed.time_start = Some("08:00".into());
        timed.time_end = Some("18:00".into());
        timed.days = Some("mon,tue,wed,thu,fri".into());

        FirewallRepository::add_rule(&pool, timed).await.unwrap();
        FirewallRepository::add_rule(&pool, rule("always", None)).await.unwrap();

        let snapshot = FirewallRepository::list_rules(&pool).await.unwrap();
        assert_eq!(snapshot[0].time_start.as_deref(), Some("08:00"));
        assert_eq!(snapshot[0].time_end.as_deref(), Some("18:00"));
        assert_eq!(snapshot[0].days.as_deref(), Some("mon,tue,wed,thu,fri"));
        assert_eq!(snapshot[1].time_start, None);
        assert_eq!(snapshot[1].time_end, None);
        assert_eq!(snapshot[1].days, None);

        let id = snapshot[0].id.unwrap();
        let mut changed = rule("office hours", None);
        changed.time_start = Some("22:00".into());
        changed.time_end = Some("06:00".into());
        changed.days = Some("sat,sun".into());
        FirewallRepository::update_rule(&pool, id, changed).await.unwrap();

        let after_update = FirewallRepository::list_rules(&pool).await.unwrap();
        assert_eq!(after_update[0].time_start.as_deref(), Some("22:00"));
        assert_eq!(after_update[0].days.as_deref(), Some("sat,sun"));

        FirewallRepository::update_rule(&pool, id, rule("office hours", None)).await.unwrap();
        let cleared = FirewallRepository::list_rules(&pool).await.unwrap();
        assert_eq!(cleared[0].time_start, None);
        assert_eq!(cleared[0].time_end, None);
        assert_eq!(cleared[0].days, None);

        FirewallRepository::replace_all_rules(&pool, snapshot).await.unwrap();
        let restored = FirewallRepository::list_rules(&pool).await.unwrap();
        assert_eq!(restored[0].time_start.as_deref(), Some("08:00"));
        assert_eq!(restored[0].time_end.as_deref(), Some("18:00"));
        assert_eq!(restored[0].days.as_deref(), Some("mon,tue,wed,thu,fri"));
    }
}
