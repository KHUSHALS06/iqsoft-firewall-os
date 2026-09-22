use crate::models::dhcp::{DhcpConfig, DhcpReservation};
use sqlx::{Row, SqlitePool};

pub struct DhcpRepository;

impl DhcpRepository {
    pub async fn get_config(pool: &SqlitePool) -> Result<DhcpConfig, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT
                enabled,
                interface_name,
                subnet,
                range_start,
                range_end,
                gateway,
                dns_servers,
                lease_time_seconds,
                domain
            FROM dhcp_config
            WHERE id = 1
            "#,
        )
        .fetch_one(pool)
        .await?;

        let dns_raw: String = row.get("dns_servers");

        Ok(DhcpConfig {
            enabled: row.get::<i64, _>("enabled") != 0,
            interface_name: row.get("interface_name"),
            subnet: row.get("subnet"),
            range_start: row.get("range_start"),
            range_end: row.get("range_end"),
            gateway: row.get("gateway"),
            dns_servers: dns_raw
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            lease_time_seconds: row.get("lease_time_seconds"),
            domain: row.get("domain"),
        })
    }

    pub async fn set_config(
        pool: &SqlitePool,
        config: DhcpConfig,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE dhcp_config
            SET
                enabled = ?,
                interface_name = ?,
                subnet = ?,
                range_start = ?,
                range_end = ?,
                gateway = ?,
                dns_servers = ?,
                lease_time_seconds = ?,
                domain = ?
            WHERE id = 1
            "#,
        )
        .bind(config.enabled)
        .bind(config.interface_name)
        .bind(config.subnet)
        .bind(config.range_start)
        .bind(config.range_end)
        .bind(config.gateway)
        .bind(config.dns_servers.join(","))
        .bind(config.lease_time_seconds)
        .bind(config.domain)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn list_reservations(
        pool: &SqlitePool,
    ) -> Result<Vec<DhcpReservation>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, mac, ip, hostname
            FROM dhcp_reservations
            ORDER BY id ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| DhcpReservation {
                id: Some(row.get("id")),
                mac: row.get("mac"),
                ip: row.get("ip"),
                hostname: row.get("hostname"),
            })
            .collect())
    }

    pub async fn add_reservation(
        pool: &SqlitePool,
        reservation: DhcpReservation,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO dhcp_reservations (mac, ip, hostname)
            VALUES (?, ?, ?)
            "#,
        )
        .bind(reservation.mac)
        .bind(reservation.ip)
        .bind(reservation.hostname)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn update_reservation(
        pool: &SqlitePool,
        id: i64,
        reservation: DhcpReservation,
    ) -> Result<(), sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE dhcp_reservations
            SET mac = ?, ip = ?, hostname = ?
            WHERE id = ?
            "#,
        )
        .bind(reservation.mac)
        .bind(reservation.ip)
        .bind(reservation.hostname)
        .bind(id)
        .execute(pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(sqlx::Error::RowNotFound);
        }

        Ok(())
    }

    pub async fn delete_reservation(
        pool: &SqlitePool,
        id: i64,
    ) -> Result<(), sqlx::Error> {
        let result = sqlx::query("DELETE FROM dhcp_reservations WHERE id = ?")
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
        config: DhcpConfig,
        reservations: Vec<DhcpReservation>,
    ) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query(
            r#"
            UPDATE dhcp_config
            SET
                enabled = ?,
                interface_name = ?,
                subnet = ?,
                range_start = ?,
                range_end = ?,
                gateway = ?,
                dns_servers = ?,
                lease_time_seconds = ?,
                domain = ?
            WHERE id = 1
            "#,
        )
        .bind(config.enabled)
        .bind(config.interface_name)
        .bind(config.subnet)
        .bind(config.range_start)
        .bind(config.range_end)
        .bind(config.gateway)
        .bind(config.dns_servers.join(","))
        .bind(config.lease_time_seconds)
        .bind(config.domain)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM dhcp_reservations")
            .execute(&mut *tx)
            .await?;

        for reservation in reservations {
            sqlx::query(
                r#"
                INSERT INTO dhcp_reservations (id, mac, ip, hostname)
                VALUES (?, ?, ?, ?)
                "#,
            )
            .bind(reservation.id)
            .bind(reservation.mac)
            .bind(reservation.ip)
            .bind(reservation.hostname)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(())
    }
}
