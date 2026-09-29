use crate::models::one_to_one_nat::OneToOneNatRule;
use sqlx::{sqlite::SqliteRow, Row, SqlitePool};

pub struct OneToOneNatRepository;

impl OneToOneNatRepository {
    fn row_to_rule(row: &SqliteRow) -> OneToOneNatRule {
        OneToOneNatRule {
            id: Some(row.get("id")),
            name: row.get("name"),
            enabled: row.get::<i64, _>("enabled") != 0,
            external_ip: row.get("external_ip"),
            internal_ip: row.get("internal_ip"),
            comment: row.get("comment"),
        }
    }

    pub async fn list_rules(pool: &SqlitePool) -> Result<Vec<OneToOneNatRule>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, enabled, external_ip, internal_ip, comment
            FROM one_to_one_nat_rules
            ORDER BY id ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_rule).collect())
    }

    pub async fn add_rule(pool: &SqlitePool, rule: OneToOneNatRule) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO one_to_one_nat_rules (name, enabled, external_ip, internal_ip, comment)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(rule.name)
        .bind(rule.enabled)
        .bind(rule.external_ip)
        .bind(rule.internal_ip)
        .bind(rule.comment)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Returns the number of rows changed (0 means the id does not exist).
    pub async fn update_rule(
        pool: &SqlitePool,
        id: i64,
        rule: OneToOneNatRule,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE one_to_one_nat_rules
            SET name = ?, enabled = ?, external_ip = ?, internal_ip = ?, comment = ?
            WHERE id = ?
            "#,
        )
        .bind(rule.name)
        .bind(rule.enabled)
        .bind(rule.external_ip)
        .bind(rule.internal_ip)
        .bind(rule.comment)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Returns the number of rows deleted (0 means the id does not exist).
    pub async fn delete_rule(pool: &SqlitePool, id: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM one_to_one_nat_rules WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }

    /// Used by rollback: replaces the whole table in one transaction.
    pub async fn replace_all_rules(
        pool: &SqlitePool,
        rules: Vec<OneToOneNatRule>,
    ) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query("DELETE FROM one_to_one_nat_rules")
            .execute(&mut *tx)
            .await?;

        for rule in rules {
            sqlx::query(
                r#"
                INSERT INTO one_to_one_nat_rules
                    (id, name, enabled, external_ip, internal_ip, comment)
                VALUES (?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(rule.id)
            .bind(rule.name)
            .bind(rule.enabled)
            .bind(rule.external_ip)
            .bind(rule.internal_ip)
            .bind(rule.comment)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(())
    }
}
