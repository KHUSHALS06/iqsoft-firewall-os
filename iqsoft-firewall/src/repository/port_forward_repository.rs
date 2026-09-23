use crate::models::port_forward::PortForwardRule;
use sqlx::{sqlite::SqliteRow, Row, SqlitePool};

pub struct PortForwardRepository;

impl PortForwardRepository {
    fn row_to_rule(row: &SqliteRow) -> PortForwardRule {
        PortForwardRule {
            id: Some(row.get("id")),
            name: row.get("name"),
            enabled: row.get::<i64, _>("enabled") != 0,
            protocol: row.get("protocol"),
            external_port_start: row.get("external_port_start"),
            external_port_end: row.get("external_port_end"),
            internal_ip: row.get("internal_ip"),
            internal_port_start: row.get("internal_port_start"),
            comment: row.get("comment"),
        }
    }

    pub async fn list_rules(pool: &SqlitePool) -> Result<Vec<PortForwardRule>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                name,
                enabled,
                protocol,
                external_port_start,
                external_port_end,
                internal_ip,
                internal_port_start,
                comment
            FROM port_forward_rules
            ORDER BY external_port_start ASC, id ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_rule).collect())
    }

    pub async fn add_rule(pool: &SqlitePool, rule: PortForwardRule) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO port_forward_rules (
                name,
                enabled,
                protocol,
                external_port_start,
                external_port_end,
                internal_ip,
                internal_port_start,
                comment
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(rule.name)
        .bind(rule.enabled)
        .bind(rule.protocol)
        .bind(rule.external_port_start)
        .bind(rule.external_port_end)
        .bind(rule.internal_ip)
        .bind(rule.internal_port_start)
        .bind(rule.comment)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Returns the number of rows changed (0 means the id does not exist).
    pub async fn update_rule(
        pool: &SqlitePool,
        id: i64,
        rule: PortForwardRule,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE port_forward_rules
            SET
                name = ?,
                enabled = ?,
                protocol = ?,
                external_port_start = ?,
                external_port_end = ?,
                internal_ip = ?,
                internal_port_start = ?,
                comment = ?
            WHERE id = ?
            "#,
        )
        .bind(rule.name)
        .bind(rule.enabled)
        .bind(rule.protocol)
        .bind(rule.external_port_start)
        .bind(rule.external_port_end)
        .bind(rule.internal_ip)
        .bind(rule.internal_port_start)
        .bind(rule.comment)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Returns the number of rows deleted (0 means the id does not exist).
    pub async fn delete_rule(pool: &SqlitePool, id: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM port_forward_rules WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }

    pub async fn replace_all_rules(
        pool: &SqlitePool,
        rules: Vec<PortForwardRule>,
    ) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query("DELETE FROM port_forward_rules")
            .execute(&mut *tx)
            .await?;

        for rule in rules {
            sqlx::query(
                r#"
                INSERT INTO port_forward_rules (
                    id,
                    name,
                    enabled,
                    protocol,
                    external_port_start,
                    external_port_end,
                    internal_ip,
                    internal_port_start,
                    comment
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(rule.id)
            .bind(rule.name)
            .bind(rule.enabled)
            .bind(rule.protocol)
            .bind(rule.external_port_start)
            .bind(rule.external_port_end)
            .bind(rule.internal_ip)
            .bind(rule.internal_port_start)
            .bind(rule.comment)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(())
    }
}
