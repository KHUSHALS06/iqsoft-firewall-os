use crate::models::dns::{DnsConfig, DnsStaticRecord};
use sqlx::{Row, SqlitePool};

pub struct DnsRepository;

impl DnsRepository {
    pub async fn get_config(pool: &SqlitePool) -> Result<DnsConfig, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT
                enabled,
                listen_interfaces,
                upstream_servers,
                local_domain,
                use_dhcp_hostnames
            FROM dns_config
            WHERE id = 1
            "#,
        )
        .fetch_one(pool)
        .await?;

        Ok(Self::row_to_config(&row))
    }

    pub async fn set_config(pool: &SqlitePool, config: DnsConfig) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE dns_config
            SET
                enabled = ?,
                listen_interfaces = ?,
                upstream_servers = ?,
                local_domain = ?,
                use_dhcp_hostnames = ?
            WHERE id = 1
            "#,
        )
        .bind(config.enabled)
        .bind(config.listen_interfaces.join(","))
        .bind(config.upstream_servers.join(","))
        .bind(config.local_domain)
        .bind(config.use_dhcp_hostnames)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn list_records(
        pool: &SqlitePool,
    ) -> Result<Vec<DnsStaticRecord>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, hostname, ip
            FROM dns_static_records
            ORDER BY id ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| DnsStaticRecord {
                id: Some(row.get("id")),
                hostname: row.get("hostname"),
                ip: row.get("ip"),
            })
            .collect())
    }

    pub async fn add_record(
        pool: &SqlitePool,
        record: DnsStaticRecord,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO dns_static_records (hostname, ip)
            VALUES (?, ?)
            "#,
        )
        .bind(record.hostname)
        .bind(record.ip)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn update_record(
        pool: &SqlitePool,
        id: i64,
        record: DnsStaticRecord,
    ) -> Result<(), sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE dns_static_records
            SET hostname = ?, ip = ?
            WHERE id = ?
            "#,
        )
        .bind(record.hostname)
        .bind(record.ip)
        .bind(id)
        .execute(pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(sqlx::Error::RowNotFound);
        }

        Ok(())
    }

    pub async fn delete_record(pool: &SqlitePool, id: i64) -> Result<(), sqlx::Error> {
        let result = sqlx::query("DELETE FROM dns_static_records WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(sqlx::Error::RowNotFound);
        }

        Ok(())
    }

    pub async fn replace_all(
        pool: &SqlitePool,
        config: DnsConfig,
        records: Vec<DnsStaticRecord>,
    ) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query(
            r#"
            UPDATE dns_config
            SET
                enabled = ?,
                listen_interfaces = ?,
                upstream_servers = ?,
                local_domain = ?,
                use_dhcp_hostnames = ?
            WHERE id = 1
            "#,
        )
        .bind(config.enabled)
        .bind(config.listen_interfaces.join(","))
        .bind(config.upstream_servers.join(","))
        .bind(config.local_domain)
        .bind(config.use_dhcp_hostnames)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM dns_static_records")
            .execute(&mut *tx)
            .await?;

        for record in records {
            sqlx::query(
                r#"
                INSERT INTO dns_static_records (id, hostname, ip)
                VALUES (?, ?, ?)
                "#,
            )
            .bind(record.id)
            .bind(record.hostname)
            .bind(record.ip)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(())
    }

    fn row_to_config(row: &sqlx::sqlite::SqliteRow) -> DnsConfig {
        let listen_raw: String = row.get("listen_interfaces");
        let upstream_raw: String = row.get("upstream_servers");

        DnsConfig {
            enabled: row.get::<i64, _>("enabled") != 0,
            listen_interfaces: listen_raw
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            upstream_servers: upstream_raw
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            local_domain: row.get("local_domain"),
            use_dhcp_hostnames: row.get::<i64, _>("use_dhcp_hostnames") != 0,
        }
    }
}
