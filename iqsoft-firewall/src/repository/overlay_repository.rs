use crate::models::overlay::{OverlaySettings, OverlayTunnel, OverlayTunnelStatus};
use sqlx::{sqlite::SqliteRow, Row, SqlitePool};

const TUNNEL_SELECT: &str = r#"
    SELECT
        t.id, t.name, t.enabled, t.link_id, t.remote_address, t.local_id, t.remote_id,
        t.auth_method, t.psk, t.local_cert, t.local_key, t.remote_ca, t.initiate,
        t.inner_local, t.inner_remote, t.mtu, t.dpd_delay_secs, t.ospf_cost, t.comment,
        COALESCE(s.state, 'unknown') AS state,
        COALESCE(s.ike_state, 'unknown') AS ike_state,
        COALESCE(s.child_state, 'unknown') AS child_state,
        COALESCE(s.routing_state, 'unknown') AS routing_state,
        s.latency_ms, s.loss_pct, s.uptime_secs, s.bytes_in, s.bytes_out,
        s.applied_cost, s.last_check, s.last_change, s.last_error
    FROM sdwan_tunnels t
    LEFT JOIN sdwan_tunnel_status s ON s.tunnel_id = t.id
"#;

const STATUS_SELECT: &str = r#"
    SELECT
        tunnel_id, state, ike_state, child_state, routing_state, latency_ms, loss_pct,
        uptime_secs, bytes_in, bytes_out, applied_cost, consecutive_fail, consecutive_ok,
        last_check, last_change, last_error
    FROM sdwan_tunnel_status
"#;

const TUNNEL_INSERT: &str = r#"
    INSERT INTO sdwan_tunnels (
        id, name, enabled, link_id, remote_address, local_id, remote_id, auth_method,
        psk, local_cert, local_key, remote_ca, initiate, inner_local, inner_remote,
        mtu, dpd_delay_secs, ospf_cost, comment
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"#;

pub struct OverlayRepository;

impl OverlayRepository {
    fn split_networks(text: &str) -> Vec<String> {
        text.split(',')
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty())
            .collect()
    }

    fn row_to_tunnel(row: &SqliteRow) -> OverlayTunnel {
        let psk: Option<String> = row.get("psk");

        OverlayTunnel {
            id: Some(row.get("id")),
            name: row.get("name"),
            enabled: row.get::<i64, _>("enabled") != 0,
            link_id: row.get("link_id"),
            remote_address: row.get("remote_address"),
            local_id: row.get("local_id"),
            remote_id: row.get("remote_id"),
            auth_method: row.get("auth_method"),
            psk_set: psk.as_deref().map(|p| !p.is_empty()).unwrap_or(false),
            psk,
            local_cert: row.get("local_cert"),
            local_key: row.get("local_key"),
            remote_ca: row.get("remote_ca"),
            initiate: row.get::<i64, _>("initiate") != 0,
            inner_local: row.get("inner_local"),
            inner_remote: row.get("inner_remote"),
            mtu: row.get("mtu"),
            dpd_delay_secs: row.get("dpd_delay_secs"),
            ospf_cost: row.get("ospf_cost"),
            comment: row.get("comment"),
            state: row.get("state"),
            ike_state: row.get("ike_state"),
            child_state: row.get("child_state"),
            routing_state: row.get("routing_state"),
            latency_ms: row.get("latency_ms"),
            loss_pct: row.get("loss_pct"),
            uptime_secs: row.get("uptime_secs"),
            bytes_in: row.get("bytes_in"),
            bytes_out: row.get("bytes_out"),
            applied_cost: row.get("applied_cost"),
            last_check: row.get("last_check"),
            last_change: row.get("last_change"),
            last_error: row.get("last_error"),
        }
    }

    fn row_to_status(row: &SqliteRow) -> OverlayTunnelStatus {
        OverlayTunnelStatus {
            tunnel_id: row.get("tunnel_id"),
            state: row.get("state"),
            ike_state: row.get("ike_state"),
            child_state: row.get("child_state"),
            routing_state: row.get("routing_state"),
            latency_ms: row.get("latency_ms"),
            loss_pct: row.get("loss_pct"),
            uptime_secs: row.get("uptime_secs"),
            bytes_in: row.get("bytes_in"),
            bytes_out: row.get("bytes_out"),
            applied_cost: row.get("applied_cost"),
            consecutive_fail: row.get("consecutive_fail"),
            consecutive_ok: row.get("consecutive_ok"),
            last_check: row.get("last_check"),
            last_change: row.get("last_change"),
            last_error: row.get("last_error"),
        }
    }

    pub async fn get_settings(pool: &SqlitePool) -> Result<OverlaySettings, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT enabled, site_name, router_id, ospf_area, advertised_networks,
                   ospf_hello_secs, ospf_dead_secs
            FROM sdwan_overlay_settings
            WHERE id = 1
            "#,
        )
        .fetch_one(pool)
        .await?;

        let networks: String = row.get("advertised_networks");

        Ok(OverlaySettings {
            enabled: row.get::<i64, _>("enabled") != 0,
            site_name: row.get("site_name"),
            router_id: row.get("router_id"),
            ospf_area: row.get("ospf_area"),
            advertised_networks: Self::split_networks(&networks),
            ospf_hello_secs: row.get("ospf_hello_secs"),
            ospf_dead_secs: row.get("ospf_dead_secs"),
        })
    }

    pub async fn save_settings(
        pool: &SqlitePool,
        settings: &OverlaySettings,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE sdwan_overlay_settings
            SET
                enabled = ?,
                site_name = ?,
                router_id = ?,
                ospf_area = ?,
                advertised_networks = ?,
                ospf_hello_secs = ?,
                ospf_dead_secs = ?
            WHERE id = 1
            "#,
        )
        .bind(settings.enabled as i64)
        .bind(&settings.site_name)
        .bind(&settings.router_id)
        .bind(&settings.ospf_area)
        .bind(settings.advertised_networks.join(","))
        .bind(settings.ospf_hello_secs)
        .bind(settings.ospf_dead_secs)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn list_tunnels(pool: &SqlitePool) -> Result<Vec<OverlayTunnel>, sqlx::Error> {
        let sql = format!("{} ORDER BY t.id ASC", TUNNEL_SELECT);

        let rows = sqlx::query(&sql).fetch_all(pool).await?;
        Ok(rows.iter().map(Self::row_to_tunnel).collect())
    }

    pub async fn get_tunnel(
        pool: &SqlitePool,
        id: i64,
    ) -> Result<Option<OverlayTunnel>, sqlx::Error> {
        let sql = format!("{} WHERE t.id = ?", TUNNEL_SELECT);

        let row = sqlx::query(&sql).bind(id).fetch_optional(pool).await?;
        Ok(row.as_ref().map(Self::row_to_tunnel))
    }

    pub async fn get_tunnel_by_name(
        pool: &SqlitePool,
        name: &str,
    ) -> Result<Option<OverlayTunnel>, sqlx::Error> {
        let sql = format!("{} WHERE t.name = ? COLLATE NOCASE", TUNNEL_SELECT);

        let row = sqlx::query(&sql).bind(name).fetch_optional(pool).await?;
        Ok(row.as_ref().map(Self::row_to_tunnel))
    }

    pub async fn get_tunnel_by_inner_local(
        pool: &SqlitePool,
        inner_local: &str,
    ) -> Result<Option<OverlayTunnel>, sqlx::Error> {
        let sql = format!("{} WHERE t.inner_local = ?", TUNNEL_SELECT);

        let row = sqlx::query(&sql)
            .bind(inner_local)
            .fetch_optional(pool)
            .await?;
        Ok(row.as_ref().map(Self::row_to_tunnel))
    }

    pub async fn get_tunnel_by_link_and_remote(
        pool: &SqlitePool,
        link_id: i64,
        remote_address: &str,
    ) -> Result<Option<OverlayTunnel>, sqlx::Error> {
        let sql = format!(
            "{} WHERE t.link_id = ? AND t.remote_address = ?",
            TUNNEL_SELECT
        );

        let row = sqlx::query(&sql)
            .bind(link_id)
            .bind(remote_address)
            .fetch_optional(pool)
            .await?;
        Ok(row.as_ref().map(Self::row_to_tunnel))
    }

    pub async fn count_tunnels(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT COUNT(*) FROM sdwan_tunnels")
            .fetch_one(pool)
            .await
    }

    pub async fn count_tunnels_using_link(
        pool: &SqlitePool,
        link_id: i64,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT COUNT(*) FROM sdwan_tunnels WHERE link_id = ?")
            .bind(link_id)
            .fetch_one(pool)
            .await
    }

    pub async fn add_tunnel(
        pool: &SqlitePool,
        tunnel: &OverlayTunnel,
    ) -> Result<i64, sqlx::Error> {
        let mut tx = pool.begin().await?;

        let result = sqlx::query(TUNNEL_INSERT)
            .bind(Option::<i64>::None)
            .bind(&tunnel.name)
            .bind(tunnel.enabled as i64)
            .bind(tunnel.link_id)
            .bind(&tunnel.remote_address)
            .bind(&tunnel.local_id)
            .bind(&tunnel.remote_id)
            .bind(&tunnel.auth_method)
            .bind(&tunnel.psk)
            .bind(&tunnel.local_cert)
            .bind(&tunnel.local_key)
            .bind(&tunnel.remote_ca)
            .bind(tunnel.initiate as i64)
            .bind(&tunnel.inner_local)
            .bind(&tunnel.inner_remote)
            .bind(tunnel.mtu)
            .bind(tunnel.dpd_delay_secs)
            .bind(tunnel.ospf_cost)
            .bind(&tunnel.comment)
            .execute(&mut *tx)
            .await?;

        let id = result.last_insert_rowid();

        sqlx::query("INSERT OR IGNORE INTO sdwan_tunnel_status (tunnel_id) VALUES (?)")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok(id)
    }

    pub async fn update_tunnel(
        pool: &SqlitePool,
        id: i64,
        tunnel: &OverlayTunnel,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE sdwan_tunnels
            SET
                name = ?,
                enabled = ?,
                link_id = ?,
                remote_address = ?,
                local_id = ?,
                remote_id = ?,
                auth_method = ?,
                psk = CASE WHEN ? = 'psk' THEN COALESCE(?, psk) ELSE NULL END,
                local_cert = ?,
                local_key = ?,
                remote_ca = ?,
                initiate = ?,
                inner_local = ?,
                inner_remote = ?,
                mtu = ?,
                dpd_delay_secs = ?,
                ospf_cost = ?,
                comment = ?
            WHERE id = ?
            "#,
        )
        .bind(&tunnel.name)
        .bind(tunnel.enabled as i64)
        .bind(tunnel.link_id)
        .bind(&tunnel.remote_address)
        .bind(&tunnel.local_id)
        .bind(&tunnel.remote_id)
        .bind(&tunnel.auth_method)
        .bind(&tunnel.auth_method)
        .bind(&tunnel.psk)
        .bind(&tunnel.local_cert)
        .bind(&tunnel.local_key)
        .bind(&tunnel.remote_ca)
        .bind(tunnel.initiate as i64)
        .bind(&tunnel.inner_local)
        .bind(&tunnel.inner_remote)
        .bind(tunnel.mtu)
        .bind(tunnel.dpd_delay_secs)
        .bind(tunnel.ospf_cost)
        .bind(&tunnel.comment)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn delete_tunnel(pool: &SqlitePool, id: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM sdwan_tunnels WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }

    pub async fn get_status(
        pool: &SqlitePool,
        tunnel_id: i64,
    ) -> Result<Option<OverlayTunnelStatus>, sqlx::Error> {
        let sql = format!("{} WHERE tunnel_id = ?", STATUS_SELECT);

        let row = sqlx::query(&sql)
            .bind(tunnel_id)
            .fetch_optional(pool)
            .await?;
        Ok(row.as_ref().map(Self::row_to_status))
    }

    pub async fn list_statuses(
        pool: &SqlitePool,
    ) -> Result<Vec<OverlayTunnelStatus>, sqlx::Error> {
        let sql = format!("{} ORDER BY tunnel_id ASC", STATUS_SELECT);

        let rows = sqlx::query(&sql).fetch_all(pool).await?;
        Ok(rows.iter().map(Self::row_to_status).collect())
    }

    pub async fn save_status(
        pool: &SqlitePool,
        status: &OverlayTunnelStatus,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO sdwan_tunnel_status (
                tunnel_id, state, ike_state, child_state, routing_state, latency_ms,
                loss_pct, uptime_secs, bytes_in, bytes_out, applied_cost,
                consecutive_fail, consecutive_ok, last_check, last_change, last_error
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tunnel_id) DO UPDATE SET
                state = excluded.state,
                ike_state = excluded.ike_state,
                child_state = excluded.child_state,
                routing_state = excluded.routing_state,
                latency_ms = excluded.latency_ms,
                loss_pct = excluded.loss_pct,
                uptime_secs = excluded.uptime_secs,
                bytes_in = excluded.bytes_in,
                bytes_out = excluded.bytes_out,
                applied_cost = excluded.applied_cost,
                consecutive_fail = excluded.consecutive_fail,
                consecutive_ok = excluded.consecutive_ok,
                last_check = excluded.last_check,
                last_change = excluded.last_change,
                last_error = excluded.last_error
            "#,
        )
        .bind(status.tunnel_id)
        .bind(&status.state)
        .bind(&status.ike_state)
        .bind(&status.child_state)
        .bind(&status.routing_state)
        .bind(status.latency_ms)
        .bind(status.loss_pct)
        .bind(status.uptime_secs)
        .bind(status.bytes_in)
        .bind(status.bytes_out)
        .bind(status.applied_cost)
        .bind(status.consecutive_fail)
        .bind(status.consecutive_ok)
        .bind(status.last_check)
        .bind(status.last_change)
        .bind(&status.last_error)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn replace_all(
        pool: &SqlitePool,
        settings: &OverlaySettings,
        tunnels: &[OverlayTunnel],
    ) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query("DELETE FROM sdwan_tunnels")
            .execute(&mut *tx)
            .await?;

        for tunnel in tunnels {
            let result = sqlx::query(TUNNEL_INSERT)
                .bind(tunnel.id)
                .bind(&tunnel.name)
                .bind(tunnel.enabled as i64)
                .bind(tunnel.link_id)
                .bind(&tunnel.remote_address)
                .bind(&tunnel.local_id)
                .bind(&tunnel.remote_id)
                .bind(&tunnel.auth_method)
                .bind(&tunnel.psk)
                .bind(&tunnel.local_cert)
                .bind(&tunnel.local_key)
                .bind(&tunnel.remote_ca)
                .bind(tunnel.initiate as i64)
                .bind(&tunnel.inner_local)
                .bind(&tunnel.inner_remote)
                .bind(tunnel.mtu)
                .bind(tunnel.dpd_delay_secs)
                .bind(tunnel.ospf_cost)
                .bind(&tunnel.comment)
                .execute(&mut *tx)
                .await?;

            sqlx::query("INSERT OR IGNORE INTO sdwan_tunnel_status (tunnel_id) VALUES (?)")
                .bind(result.last_insert_rowid())
                .execute(&mut *tx)
                .await?;
        }

        sqlx::query(
            r#"
            UPDATE sdwan_overlay_settings
            SET
                enabled = ?,
                site_name = ?,
                router_id = ?,
                ospf_area = ?,
                advertised_networks = ?,
                ospf_hello_secs = ?,
                ospf_dead_secs = ?
            WHERE id = 1
            "#,
        )
        .bind(settings.enabled as i64)
        .bind(&settings.site_name)
        .bind(&settings.router_id)
        .bind(&settings.ospf_area)
        .bind(settings.advertised_networks.join(","))
        .bind(settings.ospf_hello_secs)
        .bind(settings.ospf_dead_secs)
        .execute(&mut *tx)
        .await?;

        tx.commit().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::sdwan_schema::create_sdwan_tables;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        create_sdwan_tables(&pool).await.unwrap();
        pool
    }

    async fn add_link(pool: &SqlitePool, name: &str, iface: &str) -> i64 {
        sqlx::query("INSERT INTO sdwan_links (name, interface_name) VALUES (?, ?)")
            .bind(name)
            .bind(iface)
            .execute(pool)
            .await
            .unwrap()
            .last_insert_rowid()
    }

    fn tunnel(name: &str, link_id: i64, inner: &str) -> OverlayTunnel {
        serde_json::from_value(serde_json::json!({
            "name": name,
            "link_id": link_id,
            "remote_address": "203.0.113.10",
            "psk": "a-long-enough-secret",
            "inner_local": inner,
            "inner_remote": "10.255.0.2"
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn settings_start_switched_off_and_round_trip() {
        let pool = memory_pool().await;

        let first = OverlayRepository::get_settings(&pool).await.unwrap();
        assert_eq!(first, OverlaySettings::default());

        let wanted = OverlaySettings {
            enabled: true,
            site_name: "branch-1".to_string(),
            router_id: Some("10.0.0.1".to_string()),
            ospf_area: "0.0.0.1".to_string(),
            advertised_networks: vec!["192.168.10.0/24".to_string(), "192.168.20.0/24".to_string()],
            ospf_hello_secs: 3,
            ospf_dead_secs: 12,
        };
        OverlayRepository::save_settings(&pool, &wanted).await.unwrap();

        assert_eq!(OverlayRepository::get_settings(&pool).await.unwrap(), wanted);

        OverlayRepository::save_settings(&pool, &OverlaySettings::default())
            .await
            .unwrap();
        let cleared = OverlayRepository::get_settings(&pool).await.unwrap();
        assert!(cleared.advertised_networks.is_empty());
        assert_eq!(cleared.router_id, None);
    }

    #[tokio::test]
    async fn adding_a_tunnel_also_creates_its_status_row() {
        let pool = memory_pool().await;
        let link = add_link(&pool, "ISP1", "enp3s0").await;

        let id = OverlayRepository::add_tunnel(&pool, &tunnel("hq", link, "10.255.0.1/30"))
            .await
            .unwrap();

        let got = OverlayRepository::get_tunnel(&pool, id).await.unwrap().unwrap();
        assert_eq!(got.id, Some(id));
        assert_eq!(got.name, "hq");
        assert_eq!(got.link_id, link);
        assert_eq!(got.psk.as_deref(), Some("a-long-enough-secret"));
        assert!(got.psk_set);
        assert_eq!(got.mtu, 1400);
        assert_eq!(got.state, "unknown");
        assert_eq!(got.ike_state, "unknown");
        assert_eq!(got.latency_ms, None);

        assert_eq!(OverlayRepository::list_statuses(&pool).await.unwrap().len(), 1);
        assert_eq!(OverlayRepository::count_tunnels(&pool).await.unwrap(), 1);
        assert_eq!(OverlayRepository::count_tunnels_using_link(&pool, link).await.unwrap(), 1);
        assert_eq!(OverlayRepository::count_tunnels_using_link(&pool, 999).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_duplicate_or_orphan_tunnel_adds_nothing_at_all() {
        let pool = memory_pool().await;
        let link = add_link(&pool, "ISP1", "enp3s0").await;
        OverlayRepository::add_tunnel(&pool, &tunnel("hq", link, "10.255.0.1/30"))
            .await
            .unwrap();

        let duplicate =
            OverlayRepository::add_tunnel(&pool, &tunnel("HQ", link, "10.255.0.5/30")).await;
        assert!(duplicate.is_err());

        let orphan =
            OverlayRepository::add_tunnel(&pool, &tunnel("x", 999, "10.255.0.9/30")).await;
        assert!(orphan.is_err());

        assert_eq!(OverlayRepository::count_tunnels(&pool).await.unwrap(), 1);
        assert_eq!(OverlayRepository::list_statuses(&pool).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn tunnels_can_be_found_by_name_inner_address_and_link_with_peer() {
        let pool = memory_pool().await;
        let link = add_link(&pool, "ISP1", "enp3s0").await;
        OverlayRepository::add_tunnel(&pool, &tunnel("hq", link, "10.255.0.1/30"))
            .await
            .unwrap();

        assert!(OverlayRepository::get_tunnel_by_name(&pool, "HQ").await.unwrap().is_some());
        assert!(OverlayRepository::get_tunnel_by_name(&pool, "other").await.unwrap().is_none());
        assert!(OverlayRepository::get_tunnel_by_inner_local(&pool, "10.255.0.1/30")
            .await
            .unwrap()
            .is_some());
        assert!(OverlayRepository::get_tunnel_by_inner_local(&pool, "10.255.0.5/30")
            .await
            .unwrap()
            .is_none());
        assert!(OverlayRepository::get_tunnel_by_link_and_remote(&pool, link, "203.0.113.10")
            .await
            .unwrap()
            .is_some());
        assert!(OverlayRepository::get_tunnel_by_link_and_remote(&pool, link, "198.51.100.1")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn updating_a_tunnel_keeps_its_live_status_and_its_psk_when_none_is_sent() {
        let pool = memory_pool().await;
        let link = add_link(&pool, "ISP1", "enp3s0").await;
        let id = OverlayRepository::add_tunnel(&pool, &tunnel("hq", link, "10.255.0.1/30"))
            .await
            .unwrap();

        let mut status = OverlayRepository::get_status(&pool, id).await.unwrap().unwrap();
        status.state = "up".to_string();
        status.ike_state = "established".to_string();
        status.child_state = "installed".to_string();
        status.latency_ms = Some(21.5);
        OverlayRepository::save_status(&pool, &status).await.unwrap();

        let mut changed = tunnel("hq-renamed", link, "10.255.0.1/30");
        changed.psk = None;
        changed.mtu = 1350;
        changed.ospf_cost = 40;
        assert_eq!(OverlayRepository::update_tunnel(&pool, id, &changed).await.unwrap(), 1);

        let got = OverlayRepository::get_tunnel(&pool, id).await.unwrap().unwrap();
        assert_eq!(got.name, "hq-renamed");
        assert_eq!(got.mtu, 1350);
        assert_eq!(got.ospf_cost, 40);
        assert_eq!(got.psk.as_deref(), Some("a-long-enough-secret"));
        assert_eq!(got.state, "up");
        assert_eq!(got.ike_state, "established");
        assert_eq!(got.latency_ms, Some(21.5));

        changed.psk = Some("another-long-secret-1".to_string());
        OverlayRepository::update_tunnel(&pool, id, &changed).await.unwrap();
        let got = OverlayRepository::get_tunnel(&pool, id).await.unwrap().unwrap();
        assert_eq!(got.psk.as_deref(), Some("another-long-secret-1"));

        assert_eq!(OverlayRepository::update_tunnel(&pool, 999, &changed).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn switching_to_certificates_clears_the_psk() {
        let pool = memory_pool().await;
        let link = add_link(&pool, "ISP1", "enp3s0").await;
        let id = OverlayRepository::add_tunnel(&pool, &tunnel("hq", link, "10.255.0.1/30"))
            .await
            .unwrap();

        let mut cert = tunnel("hq", link, "10.255.0.1/30");
        cert.auth_method = "cert".to_string();
        cert.psk = None;
        cert.local_cert = Some("site.pem".to_string());
        cert.local_key = Some("site.key".to_string());
        cert.remote_ca = Some("ca.pem".to_string());
        OverlayRepository::update_tunnel(&pool, id, &cert).await.unwrap();

        let got = OverlayRepository::get_tunnel(&pool, id).await.unwrap().unwrap();
        assert_eq!(got.auth_method, "cert");
        assert_eq!(got.psk, None);
        assert!(!got.psk_set);
        assert_eq!(got.local_cert.as_deref(), Some("site.pem"));

        let mut back = tunnel("hq", link, "10.255.0.1/30");
        back.psk = None;
        assert!(OverlayRepository::update_tunnel(&pool, id, &back).await.is_err());
    }

    #[tokio::test]
    async fn saving_a_status_twice_keeps_one_row_with_the_newest_values() {
        let pool = memory_pool().await;
        let link = add_link(&pool, "ISP1", "enp3s0").await;
        let id = OverlayRepository::add_tunnel(&pool, &tunnel("hq", link, "10.255.0.1/30"))
            .await
            .unwrap();

        let mut status = OverlayRepository::get_status(&pool, id).await.unwrap().unwrap();
        status.state = "down".to_string();
        status.ike_state = "connecting".to_string();
        status.consecutive_fail = 3;
        status.last_error = Some("no reply".to_string());
        OverlayRepository::save_status(&pool, &status).await.unwrap();

        status.state = "up".to_string();
        status.ike_state = "established".to_string();
        status.child_state = "installed".to_string();
        status.routing_state = "full".to_string();
        status.uptime_secs = Some(120);
        status.bytes_in = Some(1000);
        status.bytes_out = Some(2000);
        status.applied_cost = Some(10);
        status.consecutive_fail = 0;
        status.consecutive_ok = 2;
        status.last_error = None;
        OverlayRepository::save_status(&pool, &status).await.unwrap();

        let all = OverlayRepository::list_statuses(&pool).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], status);
    }

    #[tokio::test]
    async fn deleting_a_tunnel_removes_its_status() {
        let pool = memory_pool().await;
        let link = add_link(&pool, "ISP1", "enp3s0").await;
        let id = OverlayRepository::add_tunnel(&pool, &tunnel("hq", link, "10.255.0.1/30"))
            .await
            .unwrap();

        assert_eq!(OverlayRepository::delete_tunnel(&pool, id).await.unwrap(), 1);
        assert_eq!(OverlayRepository::delete_tunnel(&pool, id).await.unwrap(), 0);
        assert!(OverlayRepository::get_status(&pool, id).await.unwrap().is_none());
        assert!(OverlayRepository::list_statuses(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn replace_all_restores_settings_and_tunnels_with_their_ids() {
        let pool = memory_pool().await;
        let isp1 = add_link(&pool, "ISP1", "enp3s0").await;
        let isp2 = add_link(&pool, "ISP2", "enp4s0").await;

        let first = OverlayRepository::add_tunnel(&pool, &tunnel("hq", isp1, "10.255.0.1/30"))
            .await
            .unwrap();
        let second = OverlayRepository::add_tunnel(&pool, &tunnel("hq-b", isp2, "10.255.0.5/30"))
            .await
            .unwrap();

        let saved_settings = OverlaySettings {
            enabled: true,
            advertised_networks: vec!["192.168.1.0/24".to_string()],
            ..OverlaySettings::default()
        };
        OverlayRepository::save_settings(&pool, &saved_settings).await.unwrap();
        let saved_tunnels = OverlayRepository::list_tunnels(&pool).await.unwrap();

        OverlayRepository::delete_tunnel(&pool, first).await.unwrap();
        OverlayRepository::save_settings(&pool, &OverlaySettings::default())
            .await
            .unwrap();

        OverlayRepository::replace_all(&pool, &saved_settings, &saved_tunnels)
            .await
            .unwrap();

        assert_eq!(OverlayRepository::get_settings(&pool).await.unwrap(), saved_settings);

        let now = OverlayRepository::list_tunnels(&pool).await.unwrap();
        assert_eq!(now.len(), 2);
        assert_eq!(now[0].id, Some(first));
        assert_eq!(now[0].psk.as_deref(), Some("a-long-enough-secret"));
        assert_eq!(now[1].id, Some(second));
        assert_eq!(OverlayRepository::list_statuses(&pool).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_failing_replace_all_changes_nothing() {
        let pool = memory_pool().await;
        let link = add_link(&pool, "ISP1", "enp3s0").await;
        OverlayRepository::add_tunnel(&pool, &tunnel("hq", link, "10.255.0.1/30"))
            .await
            .unwrap();

        let mut broken = tunnel("broken", 999, "10.255.0.9/30");
        broken.id = Some(50);

        let result = OverlayRepository::replace_all(
            &pool,
            &OverlaySettings {
                enabled: true,
                ..OverlaySettings::default()
            },
            &[broken],
        )
        .await;
        assert!(result.is_err());

        let tunnels = OverlayRepository::list_tunnels(&pool).await.unwrap();
        assert_eq!(tunnels.len(), 1);
        assert_eq!(tunnels[0].name, "hq");
        assert!(!OverlayRepository::get_settings(&pool).await.unwrap().enabled);
    }
}
