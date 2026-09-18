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
                log_enabled,
                comment
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    log_enabled,
                    comment
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            .bind(rule.log_enabled)
            .bind(rule.comment)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(())
    }
}
