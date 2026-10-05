use crate::models::wireguard::{WireguardConfig, WireguardPeer};
use sqlx::{Row, SqlitePool};

pub struct WireguardRepository;

fn join_list(values: &[String]) -> String {
    values.join(",")
}

fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

impl WireguardRepository {
    pub async fn get_config(pool: &SqlitePool) -> Result<WireguardConfig, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT
                enabled,
                interface_name,
                listen_port,
                address,
                mtu,
                dns,
                endpoint,
                client_allowed_ips,
                private_key,
                public_key
            FROM wireguard_config
            WHERE id = 1
            "#,
        )
        .fetch_one(pool)
        .await?;

        Ok(Self::row_to_config(&row))
    }

    pub async fn set_config(
        pool: &SqlitePool,
        config: &WireguardConfig,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE wireguard_config
            SET
                enabled = ?,
                interface_name = ?,
                listen_port = ?,
                address = ?,
                mtu = ?,
                dns = ?,
                endpoint = ?,
                client_allowed_ips = ?,
                private_key = ?,
                public_key = ?
            WHERE id = 1
            "#,
        )
        .bind(config.enabled)
        .bind(&config.interface_name)
        .bind(config.listen_port)
        .bind(&config.address)
        .bind(config.mtu)
        .bind(&config.dns)
        .bind(&config.endpoint)
        .bind(join_list(&config.client_allowed_ips))
        .bind(&config.private_key)
        .bind(&config.public_key)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn list_peers(pool: &SqlitePool) -> Result<Vec<WireguardPeer>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                name,
                enabled,
                public_key,
                preshared_key,
                allowed_ips,
                endpoint,
                persistent_keepalive,
                comment
            FROM wireguard_peers
            ORDER BY id ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_peer).collect())
    }

    pub async fn get_peer(
        pool: &SqlitePool,
        id: i64,
    ) -> Result<Option<WireguardPeer>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT
                id,
                name,
                enabled,
                public_key,
                preshared_key,
                allowed_ips,
                endpoint,
                persistent_keepalive,
                comment
            FROM wireguard_peers
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(row.as_ref().map(Self::row_to_peer))
    }

    pub async fn add_peer(
        pool: &SqlitePool,
        peer: &WireguardPeer,
    ) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO wireguard_peers (
                name,
                enabled,
                public_key,
                preshared_key,
                allowed_ips,
                endpoint,
                persistent_keepalive,
                comment
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&peer.name)
        .bind(peer.enabled)
        .bind(&peer.public_key)
        .bind(&peer.preshared_key)
        .bind(join_list(&peer.allowed_ips))
        .bind(&peer.endpoint)
        .bind(peer.persistent_keepalive)
        .bind(&peer.comment)
        .execute(pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn update_peer(
        pool: &SqlitePool,
        id: i64,
        peer: &WireguardPeer,
    ) -> Result<(), sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE wireguard_peers
            SET
                name = ?,
                enabled = ?,
                public_key = ?,
                preshared_key = ?,
                allowed_ips = ?,
                endpoint = ?,
                persistent_keepalive = ?,
                comment = ?
            WHERE id = ?
            "#,
        )
        .bind(&peer.name)
        .bind(peer.enabled)
        .bind(&peer.public_key)
        .bind(&peer.preshared_key)
        .bind(join_list(&peer.allowed_ips))
        .bind(&peer.endpoint)
        .bind(peer.persistent_keepalive)
        .bind(&peer.comment)
        .bind(id)
        .execute(pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(sqlx::Error::RowNotFound);
        }

        Ok(())
    }

    pub async fn delete_peer(pool: &SqlitePool, id: i64) -> Result<(), sqlx::Error> {
        let result = sqlx::query("DELETE FROM wireguard_peers WHERE id = ?")
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
        config: WireguardConfig,
        peers: Vec<WireguardPeer>,
    ) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query(
            r#"
            UPDATE wireguard_config
            SET
                enabled = ?,
                interface_name = ?,
                listen_port = ?,
                address = ?,
                mtu = ?,
                dns = ?,
                endpoint = ?,
                client_allowed_ips = ?,
                private_key = ?,
                public_key = ?
            WHERE id = 1
            "#,
        )
        .bind(config.enabled)
        .bind(&config.interface_name)
        .bind(config.listen_port)
        .bind(&config.address)
        .bind(config.mtu)
        .bind(&config.dns)
        .bind(&config.endpoint)
        .bind(join_list(&config.client_allowed_ips))
        .bind(&config.private_key)
        .bind(&config.public_key)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM wireguard_peers")
            .execute(&mut *tx)
            .await?;

        for peer in peers {
            sqlx::query(
                r#"
                INSERT INTO wireguard_peers (
                    id,
                    name,
                    enabled,
                    public_key,
                    preshared_key,
                    allowed_ips,
                    endpoint,
                    persistent_keepalive,
                    comment
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(peer.id)
            .bind(&peer.name)
            .bind(peer.enabled)
            .bind(&peer.public_key)
            .bind(&peer.preshared_key)
            .bind(join_list(&peer.allowed_ips))
            .bind(&peer.endpoint)
            .bind(peer.persistent_keepalive)
            .bind(&peer.comment)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(())
    }

    fn row_to_config(row: &sqlx::sqlite::SqliteRow) -> WireguardConfig {
        let allowed_raw: String = row.get("client_allowed_ips");

        WireguardConfig {
            enabled: row.get::<i64, _>("enabled") != 0,
            interface_name: row.get("interface_name"),
            listen_port: row.get("listen_port"),
            address: row.get("address"),
            mtu: row.get("mtu"),
            dns: row.get("dns"),
            endpoint: row.get("endpoint"),
            client_allowed_ips: split_list(&allowed_raw),
            private_key: row.get("private_key"),
            public_key: row.get("public_key"),
        }
    }

    fn row_to_peer(row: &sqlx::sqlite::SqliteRow) -> WireguardPeer {
        let allowed_raw: String = row.get("allowed_ips");

        WireguardPeer {
            id: Some(row.get("id")),
            name: row.get("name"),
            enabled: row.get::<i64, _>("enabled") != 0,
            public_key: row.get("public_key"),
            preshared_key: row.get("preshared_key"),
            allowed_ips: split_list(&allowed_raw),
            endpoint: row.get("endpoint"),
            persistent_keepalive: row.get("persistent_keepalive"),
            comment: row.get("comment"),
        }
    }
}
