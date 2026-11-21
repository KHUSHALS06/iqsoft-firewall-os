use crate::models::interface_config::InterfaceConfig;
use sqlx::{sqlite::SqliteRow, Row, SqlitePool};

pub struct InterfaceConfigRepository;

fn split(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

impl InterfaceConfigRepository {
    fn row_to_config(row: &SqliteRow) -> InterfaceConfig {
        let addresses: String = row.get("addresses");
        let dns: String = row.get("dns");
        let mtu: Option<i64> = row.get("mtu");

        InterfaceConfig {
            name: row.get("name"),
            mode: row.get("mode"),
            addresses: split(&addresses),
            gateway: row.get("gateway"),
            dns: split(&dns),
            mtu: mtu.and_then(|m| u32::try_from(m).ok()),
            enabled: row.get::<i64, _>("enabled") != 0,
            comment: row.get("comment"),
        }
    }

    pub async fn list(pool: &SqlitePool) -> Result<Vec<InterfaceConfig>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT name, mode, addresses, gateway, dns, mtu, enabled, comment \
             FROM interface_configs ORDER BY name",
        )
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_config).collect())
    }

    pub async fn upsert(pool: &SqlitePool, cfg: &InterfaceConfig) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO interface_configs (name, mode, addresses, gateway, dns, mtu, enabled, comment)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                mode = excluded.mode,
                addresses = excluded.addresses,
                gateway = excluded.gateway,
                dns = excluded.dns,
                mtu = excluded.mtu,
                enabled = excluded.enabled,
                comment = excluded.comment
            "#,
        )
        .bind(&cfg.name)
        .bind(&cfg.mode)
        .bind(cfg.addresses.join(","))
        .bind(&cfg.gateway)
        .bind(cfg.dns.join(","))
        .bind(cfg.mtu.map(|m| m as i64))
        .bind(cfg.enabled)
        .bind(&cfg.comment)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn delete(pool: &SqlitePool, name: &str) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM interface_configs WHERE name = ?")
            .bind(name)
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }

    /// Replaces every saved port setting (used when a rollback restores an older set).
    pub async fn replace_all(
        pool: &SqlitePool,
        configs: &[InterfaceConfig],
    ) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query("DELETE FROM interface_configs")
            .execute(&mut *tx)
            .await?;

        for cfg in configs {
            sqlx::query(
                r#"
                INSERT INTO interface_configs (name, mode, addresses, gateway, dns, mtu, enabled, comment)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&cfg.name)
            .bind(&cfg.mode)
            .bind(cfg.addresses.join(","))
            .bind(&cfg.gateway)
            .bind(cfg.dns.join(","))
            .bind(cfg.mtu.map(|m| m as i64))
            .bind(cfg.enabled)
            .bind(&cfg.comment)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await
    }
}
