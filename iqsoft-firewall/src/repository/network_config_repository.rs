use crate::models::network_config::NetworkConfig;
use sqlx::{Row, SqlitePool};

pub struct NetworkConfigRepository;

impl NetworkConfigRepository {
    pub async fn get(pool: &SqlitePool) -> Result<NetworkConfig, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT wan_interface, lan_interface, nat_enabled, ip_forward_enabled
            FROM network_config
            WHERE id = 1
            "#,
        )
        .fetch_one(pool)
        .await?;

        Ok(NetworkConfig {
            wan_interface: row.get("wan_interface"),
            lan_interface: row.get("lan_interface"),
            nat_enabled: row.get::<i64, _>("nat_enabled") != 0,
            ip_forward_enabled: row.get::<i64, _>("ip_forward_enabled") != 0,
        })
    }

    pub async fn set(pool: &SqlitePool, config: NetworkConfig) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE network_config
            SET wan_interface = ?, lan_interface = ?, nat_enabled = ?, ip_forward_enabled = ?
            WHERE id = 1
            "#,
        )
        .bind(config.wan_interface)
        .bind(config.lan_interface)
        .bind(config.nat_enabled)
        .bind(config.ip_forward_enabled)
        .execute(pool)
        .await?;

        Ok(())
    }
}
