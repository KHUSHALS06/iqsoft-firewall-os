use sqlx::SqlitePool;

pub async fn create_sdwan_tables(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // One row only (id = 1): the master on/off switch for the whole SD-WAN feature.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sdwan_settings (
            id       INTEGER PRIMARY KEY CHECK (id = 1),
            enabled  INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1))
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("INSERT OR IGNORE INTO sdwan_settings (id, enabled) VALUES (1, 0);")
        .execute(pool)
        .await?;

    // A WAN link (one internet uplink).
    //
    // priority: lower number = preferred. Links with the SAME priority share the
    //           traffic by weight (load balancing). A higher priority number is
    //           only used when every link with a lower number is down (failover).
    // weight:   share of traffic inside the same priority group.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sdwan_links (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            name                TEXT NOT NULL UNIQUE COLLATE NOCASE,
            interface_name      TEXT NOT NULL UNIQUE,
            gateway             TEXT,
            enabled             INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
            priority            INTEGER NOT NULL DEFAULT 10
                                CHECK (priority BETWEEN 1 AND 100),
            weight              INTEGER NOT NULL DEFAULT 1
                                CHECK (weight BETWEEN 1 AND 100),
            probe_target        TEXT NOT NULL DEFAULT '1.1.1.1',
            probe_interval_secs INTEGER NOT NULL DEFAULT 5
                                CHECK (probe_interval_secs BETWEEN 1 AND 3600),
            probe_timeout_secs  INTEGER NOT NULL DEFAULT 2
                                CHECK (probe_timeout_secs BETWEEN 1 AND 30),
            fail_threshold      INTEGER NOT NULL DEFAULT 3
                                CHECK (fail_threshold BETWEEN 1 AND 20),
            recover_threshold   INTEGER NOT NULL DEFAULT 2
                                CHECK (recover_threshold BETWEEN 1 AND 20),
            comment             TEXT,
            CHECK (probe_timeout_secs <= probe_interval_secs)
        );
        "#,
    )
    .execute(pool)
    .await?;

    // Live health of each link, written by the background probe task.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sdwan_link_status (
            link_id           INTEGER PRIMARY KEY,
            state             TEXT NOT NULL DEFAULT 'unknown'
                              CHECK (state IN ('unknown', 'up', 'down')),
            latency_ms        REAL,
            loss_pct          INTEGER CHECK (loss_pct IS NULL OR loss_pct BETWEEN 0 AND 100),
            consecutive_fail  INTEGER NOT NULL DEFAULT 0,
            consecutive_ok    INTEGER NOT NULL DEFAULT 0,
            last_check        INTEGER,
            last_change       INTEGER,
            last_error        TEXT,
            FOREIGN KEY (link_id) REFERENCES sdwan_links(id) ON DELETE CASCADE
        );
        "#,
    )
    .execute(pool)
    .await?;

    // Per-traffic link rules, checked top to bottom (lowest position first).
    // A NULL src_cidr / dst_cidr / port means "any".
    //
    // strategy:
    //   link          send matching traffic out of one chosen link (link_id)
    //   balance       spread matching traffic over all links by weight
    //   best_quality  send matching traffic out of the healthiest/fastest link
    //
    // on_link_down (only used by strategy 'link'):
    //   fallback      use normal SD-WAN routing while the chosen link is down
    //   block         drop the traffic while the chosen link is down
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sdwan_rules (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT NOT NULL UNIQUE COLLATE NOCASE,
            enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
            position      INTEGER NOT NULL DEFAULT 100,
            src_cidr      TEXT,
            dst_cidr      TEXT,
            protocol      TEXT NOT NULL DEFAULT 'any'
                          CHECK (protocol IN ('any', 'tcp', 'udp', 'icmp')),
            dport_start   INTEGER CHECK (dport_start IS NULL OR dport_start BETWEEN 1 AND 65535),
            dport_end     INTEGER CHECK (dport_end IS NULL OR dport_end BETWEEN 1 AND 65535),
            strategy      TEXT NOT NULL DEFAULT 'link'
                          CHECK (strategy IN ('link', 'balance', 'best_quality')),
            link_id       INTEGER,
            on_link_down  TEXT NOT NULL DEFAULT 'fallback'
                          CHECK (on_link_down IN ('fallback', 'block')),
            comment       TEXT,
            FOREIGN KEY (link_id) REFERENCES sdwan_links(id) ON DELETE RESTRICT,
            CHECK (strategy <> 'link' OR link_id IS NOT NULL),
            CHECK ((dport_start IS NULL) = (dport_end IS NULL)),
            CHECK (dport_start IS NULL OR dport_start <= dport_end),
            CHECK (dport_start IS NULL OR protocol IN ('tcp', 'udp'))
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_sdwan_rules_position ON sdwan_rules(position, id);",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sdwan_overlay_settings (
            id                   INTEGER PRIMARY KEY CHECK (id = 1),
            enabled              INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
            site_name            TEXT NOT NULL DEFAULT 'site',
            router_id            TEXT,
            ospf_area            TEXT NOT NULL DEFAULT '0.0.0.0',
            advertised_networks  TEXT NOT NULL DEFAULT '',
            ospf_hello_secs      INTEGER NOT NULL DEFAULT 2
                                 CHECK (ospf_hello_secs BETWEEN 1 AND 60),
            ospf_dead_secs       INTEGER NOT NULL DEFAULT 8
                                 CHECK (ospf_dead_secs BETWEEN 2 AND 240),
            CHECK (ospf_dead_secs > ospf_hello_secs)
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("INSERT OR IGNORE INTO sdwan_overlay_settings (id, enabled) VALUES (1, 0);")
        .execute(pool)
        .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sdwan_tunnels (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            name             TEXT NOT NULL UNIQUE COLLATE NOCASE,
            enabled          INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
            link_id          INTEGER NOT NULL,
            remote_address   TEXT NOT NULL,
            local_id         TEXT,
            remote_id        TEXT,
            auth_method      TEXT NOT NULL DEFAULT 'psk'
                             CHECK (auth_method IN ('psk', 'cert')),
            psk              TEXT,
            local_cert       TEXT,
            local_key        TEXT,
            remote_ca        TEXT,
            initiate         INTEGER NOT NULL DEFAULT 1 CHECK (initiate IN (0, 1)),
            inner_local      TEXT NOT NULL UNIQUE,
            inner_remote     TEXT NOT NULL,
            mtu              INTEGER NOT NULL DEFAULT 1400 CHECK (mtu BETWEEN 1280 AND 1500),
            dpd_delay_secs   INTEGER NOT NULL DEFAULT 10
                             CHECK (dpd_delay_secs BETWEEN 2 AND 300),
            ospf_cost        INTEGER NOT NULL DEFAULT 10
                             CHECK (ospf_cost BETWEEN 1 AND 60000),
            comment          TEXT,
            FOREIGN KEY (link_id) REFERENCES sdwan_links(id) ON DELETE RESTRICT,
            UNIQUE (link_id, remote_address),
            CHECK (auth_method <> 'psk' OR (psk IS NOT NULL AND length(psk) >= 16)),
            CHECK (auth_method <> 'cert' OR (local_cert IS NOT NULL AND local_key IS NOT NULL))
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sdwan_tunnel_status (
            tunnel_id         INTEGER PRIMARY KEY,
            state             TEXT NOT NULL DEFAULT 'unknown'
                              CHECK (state IN ('unknown', 'up', 'down')),
            ike_state         TEXT NOT NULL DEFAULT 'unknown'
                              CHECK (ike_state IN ('unknown', 'down', 'connecting', 'established')),
            child_state       TEXT NOT NULL DEFAULT 'unknown'
                              CHECK (child_state IN ('unknown', 'down', 'installed')),
            routing_state     TEXT NOT NULL DEFAULT 'unknown'
                              CHECK (routing_state IN ('unknown', 'down', 'forming', 'full')),
            latency_ms        REAL,
            loss_pct          INTEGER CHECK (loss_pct IS NULL OR loss_pct BETWEEN 0 AND 100),
            uptime_secs       INTEGER,
            bytes_in          INTEGER,
            bytes_out         INTEGER,
            applied_cost      INTEGER,
            consecutive_fail  INTEGER NOT NULL DEFAULT 0,
            consecutive_ok    INTEGER NOT NULL DEFAULT 0,
            last_check        INTEGER,
            last_change       INTEGER,
            last_error        TEXT,
            FOREIGN KEY (tunnel_id) REFERENCES sdwan_tunnels(id) ON DELETE CASCADE
        );
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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

    async fn add_link(pool: &SqlitePool, name: &str, iface: &str) {
        sqlx::query("INSERT INTO sdwan_links (name, interface_name) VALUES (?, ?)")
            .bind(name)
            .bind(iface)
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn schema_can_be_created_twice() {
        let pool = memory_pool().await;
        create_sdwan_tables(&pool).await.unwrap();

        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sdwan_settings")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 1);
    }

    #[tokio::test]
    async fn sdwan_starts_switched_off() {
        let pool = memory_pool().await;

        let enabled: i64 = sqlx::query_scalar("SELECT enabled FROM sdwan_settings WHERE id = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(enabled, 0);

        let second = sqlx::query("INSERT INTO sdwan_settings (id, enabled) VALUES (2, 0)")
            .execute(&pool)
            .await;
        assert!(second.is_err());
    }

    #[tokio::test]
    async fn link_defaults_are_sensible() {
        let pool = memory_pool().await;
        add_link(&pool, "ISP1", "enp3s0").await;

        let row: (i64, i64, i64, String, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT enabled, priority, weight, probe_target, probe_interval_secs, \
             probe_timeout_secs, fail_threshold, recover_threshold FROM sdwan_links",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(row, (1, 10, 1, "1.1.1.1".to_string(), 5, 2, 3, 2));
    }

    #[tokio::test]
    async fn link_names_and_interfaces_are_unique() {
        let pool = memory_pool().await;
        add_link(&pool, "ISP1", "enp3s0").await;

        let same_name = sqlx::query("INSERT INTO sdwan_links (name, interface_name) VALUES ('isp1', 'enp5s0')")
            .execute(&pool)
            .await;
        assert!(same_name.is_err());

        let same_iface = sqlx::query("INSERT INTO sdwan_links (name, interface_name) VALUES ('ISP2', 'enp3s0')")
            .execute(&pool)
            .await;
        assert!(same_iface.is_err());
    }

    #[tokio::test]
    async fn out_of_range_link_values_are_rejected() {
        let pool = memory_pool().await;

        for sql in [
            "INSERT INTO sdwan_links (name, interface_name, priority) VALUES ('a', 'e1', 0)",
            "INSERT INTO sdwan_links (name, interface_name, priority) VALUES ('b', 'e2', 101)",
            "INSERT INTO sdwan_links (name, interface_name, weight) VALUES ('c', 'e3', 0)",
            "INSERT INTO sdwan_links (name, interface_name, weight) VALUES ('d', 'e4', 101)",
            "INSERT INTO sdwan_links (name, interface_name, probe_interval_secs) VALUES ('e', 'e5', 0)",
            "INSERT INTO sdwan_links (name, interface_name, fail_threshold) VALUES ('f', 'e6', 0)",
            "INSERT INTO sdwan_links (name, interface_name, recover_threshold) VALUES ('g', 'e7', 21)",
            "INSERT INTO sdwan_links (name, interface_name, enabled) VALUES ('h', 'e8', 2)",
            // timeout longer than the interval would make probes overlap
            "INSERT INTO sdwan_links (name, interface_name, probe_interval_secs, probe_timeout_secs) VALUES ('i', 'e9', 3, 5)",
        ] {
            assert!(sqlx::query(sql).execute(&pool).await.is_err(), "{}", sql);
        }
    }

    #[tokio::test]
    async fn status_needs_a_link_and_dies_with_it() {
        let pool = memory_pool().await;

        let orphan = sqlx::query("INSERT INTO sdwan_link_status (link_id) VALUES (99)")
            .execute(&pool)
            .await;
        assert!(orphan.is_err());

        add_link(&pool, "ISP1", "enp3s0").await;
        sqlx::query("INSERT INTO sdwan_link_status (link_id) VALUES (1)")
            .execute(&pool)
            .await
            .unwrap();

        let state: String = sqlx::query_scalar("SELECT state FROM sdwan_link_status WHERE link_id = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(state, "unknown");

        let bad_state = sqlx::query("UPDATE sdwan_link_status SET state = 'broken' WHERE link_id = 1")
            .execute(&pool)
            .await;
        assert!(bad_state.is_err());

        let bad_loss = sqlx::query("UPDATE sdwan_link_status SET loss_pct = 101 WHERE link_id = 1")
            .execute(&pool)
            .await;
        assert!(bad_loss.is_err());

        sqlx::query("DELETE FROM sdwan_links WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();

        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sdwan_link_status")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 0);
    }

    #[tokio::test]
    async fn rule_defaults_and_pinned_link_rules() {
        let pool = memory_pool().await;
        add_link(&pool, "ISP1", "enp3s0").await;

        sqlx::query("INSERT INTO sdwan_rules (name, strategy, link_id) VALUES ('voice', 'link', 1)")
            .execute(&pool)
            .await
            .unwrap();

        let row: (i64, i64, String, String, String) = sqlx::query_as(
            "SELECT enabled, position, protocol, strategy, on_link_down FROM sdwan_rules",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row, (1, 100, "any".to_string(), "link".to_string(), "fallback".to_string()));

        // a rule that pins a link must say which link
        let no_link = sqlx::query("INSERT INTO sdwan_rules (name, strategy) VALUES ('x', 'link')")
            .execute(&pool)
            .await;
        assert!(no_link.is_err());

        // balance and best_quality rules do not need a link
        sqlx::query("INSERT INTO sdwan_rules (name, strategy) VALUES ('spread', 'balance')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO sdwan_rules (name, strategy) VALUES ('fast', 'best_quality')")
            .execute(&pool)
            .await
            .unwrap();

        let bad_strategy = sqlx::query("INSERT INTO sdwan_rules (name, strategy) VALUES ('y', 'random')")
            .execute(&pool)
            .await;
        assert!(bad_strategy.is_err());

        let dup = sqlx::query("INSERT INTO sdwan_rules (name, strategy) VALUES ('VOICE', 'balance')")
            .execute(&pool)
            .await;
        assert!(dup.is_err());
    }

    #[tokio::test]
    async fn rule_ports_are_checked() {
        let pool = memory_pool().await;

        sqlx::query(
            "INSERT INTO sdwan_rules (name, strategy, protocol, dport_start, dport_end) \
             VALUES ('web', 'balance', 'tcp', 80, 443)",
        )
        .execute(&pool)
        .await
        .unwrap();

        for sql in [
            // ports need a tcp or udp protocol
            "INSERT INTO sdwan_rules (name, strategy, protocol, dport_start, dport_end) VALUES ('a', 'balance', 'any', 80, 80)",
            "INSERT INTO sdwan_rules (name, strategy, protocol, dport_start, dport_end) VALUES ('b', 'balance', 'icmp', 80, 80)",
            // start and end come as a pair
            "INSERT INTO sdwan_rules (name, strategy, protocol, dport_start) VALUES ('c', 'balance', 'tcp', 80)",
            // start must not be after end
            "INSERT INTO sdwan_rules (name, strategy, protocol, dport_start, dport_end) VALUES ('d', 'balance', 'udp', 500, 400)",
            // out of range
            "INSERT INTO sdwan_rules (name, strategy, protocol, dport_start, dport_end) VALUES ('e', 'balance', 'tcp', 0, 10)",
            "INSERT INTO sdwan_rules (name, strategy, protocol, dport_start, dport_end) VALUES ('f', 'balance', 'tcp', 10, 70000)",
        ] {
            assert!(sqlx::query(sql).execute(&pool).await.is_err(), "{}", sql);
        }
    }

    #[tokio::test]
    async fn a_link_used_by_a_rule_cannot_be_deleted() {
        let pool = memory_pool().await;
        add_link(&pool, "ISP1", "enp3s0").await;

        sqlx::query("INSERT INTO sdwan_rules (name, strategy, link_id) VALUES ('voice', 'link', 1)")
            .execute(&pool)
            .await
            .unwrap();

        let blocked = sqlx::query("DELETE FROM sdwan_links WHERE id = 1")
            .execute(&pool)
            .await;
        assert!(blocked.is_err());

        sqlx::query("DELETE FROM sdwan_rules WHERE name = 'voice'")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM sdwan_links WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();
    }

    async fn add_tunnel(pool: &SqlitePool, name: &str, link_id: i64, inner: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO sdwan_tunnels (name, link_id, remote_address, psk, inner_local, inner_remote) \
             VALUES (?, ?, '203.0.113.10', 'a-long-enough-secret', ?, '10.255.0.2')",
        )
        .bind(name)
        .bind(link_id)
        .bind(inner)
        .execute(pool)
        .await
        .map(|_| ())
    }

    #[tokio::test]
    async fn overlay_starts_switched_off_with_one_settings_row() {
        let pool = memory_pool().await;
        create_sdwan_tables(&pool).await.unwrap();

        let row: (i64, String, String, i64, i64) = sqlx::query_as(
            "SELECT enabled, site_name, ospf_area, ospf_hello_secs, ospf_dead_secs \
             FROM sdwan_overlay_settings WHERE id = 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row, (0, "site".to_string(), "0.0.0.0".to_string(), 2, 8));

        let second = sqlx::query("INSERT INTO sdwan_overlay_settings (id) VALUES (2)")
            .execute(&pool)
            .await;
        assert!(second.is_err());

        let dead_not_after_hello =
            sqlx::query("UPDATE sdwan_overlay_settings SET ospf_hello_secs = 10, ospf_dead_secs = 10")
                .execute(&pool)
                .await;
        assert!(dead_not_after_hello.is_err());
    }

    #[tokio::test]
    async fn a_tunnel_needs_a_link_and_its_defaults_are_sensible() {
        let pool = memory_pool().await;

        assert!(add_tunnel(&pool, "hq", 1, "10.255.0.1/30").await.is_err());

        add_link(&pool, "ISP1", "enp3s0").await;
        add_tunnel(&pool, "hq", 1, "10.255.0.1/30").await.unwrap();

        let row: (i64, String, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT enabled, auth_method, initiate, mtu, dpd_delay_secs, ospf_cost FROM sdwan_tunnels",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row, (1, "psk".to_string(), 1, 1400, 10, 10));
    }

    #[tokio::test]
    async fn tunnel_names_inner_addresses_and_peers_are_unique() {
        let pool = memory_pool().await;
        add_link(&pool, "ISP1", "enp3s0").await;
        add_link(&pool, "ISP2", "enp4s0").await;
        add_tunnel(&pool, "hq", 1, "10.255.0.1/30").await.unwrap();

        assert!(add_tunnel(&pool, "HQ", 2, "10.255.0.5/30").await.is_err());
        assert!(add_tunnel(&pool, "hq2", 2, "10.255.0.1/30").await.is_err());
        assert!(add_tunnel(&pool, "hq3", 1, "10.255.0.9/30").await.is_err());

        add_tunnel(&pool, "hq-backup", 2, "10.255.0.5/30").await.unwrap();
    }

    #[tokio::test]
    async fn tunnel_credentials_are_checked() {
        let pool = memory_pool().await;
        add_link(&pool, "ISP1", "enp3s0").await;

        for sql in [
            "INSERT INTO sdwan_tunnels (name, link_id, remote_address, auth_method, inner_local, inner_remote) \
             VALUES ('a', 1, '1.1.1.1', 'psk', '10.0.0.1/30', '10.0.0.2')",
            "INSERT INTO sdwan_tunnels (name, link_id, remote_address, auth_method, psk, inner_local, inner_remote) \
             VALUES ('b', 1, '1.1.1.1', 'psk', 'short', '10.0.0.5/30', '10.0.0.6')",
            "INSERT INTO sdwan_tunnels (name, link_id, remote_address, auth_method, inner_local, inner_remote) \
             VALUES ('c', 1, '1.1.1.1', 'cert', '10.0.0.9/30', '10.0.0.10')",
            "INSERT INTO sdwan_tunnels (name, link_id, remote_address, auth_method, local_cert, inner_local, inner_remote) \
             VALUES ('d', 1, '1.1.1.1', 'cert', 'site.pem', '10.0.0.13/30', '10.0.0.14')",
            "INSERT INTO sdwan_tunnels (name, link_id, remote_address, auth_method, inner_local, inner_remote) \
             VALUES ('e', 1, '1.1.1.1', 'token', '10.0.0.17/30', '10.0.0.18')",
        ] {
            assert!(sqlx::query(sql).execute(&pool).await.is_err(), "{}", sql);
        }

        sqlx::query(
            "INSERT INTO sdwan_tunnels (name, link_id, remote_address, auth_method, local_cert, local_key, remote_ca, inner_local, inner_remote) \
             VALUES ('ok', 1, '1.1.1.1', 'cert', 'site.pem', 'site.key', 'ca.pem', '10.0.0.21/30', '10.0.0.22')",
        )
        .execute(&pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn out_of_range_tunnel_values_are_rejected() {
        let pool = memory_pool().await;
        add_link(&pool, "ISP1", "enp3s0").await;

        for (column, value) in [
            ("mtu", 1279),
            ("mtu", 1501),
            ("dpd_delay_secs", 1),
            ("dpd_delay_secs", 301),
            ("ospf_cost", 0),
            ("ospf_cost", 60001),
            ("enabled", 2),
            ("initiate", 2),
        ] {
            let sql = format!(
                "INSERT INTO sdwan_tunnels (name, link_id, remote_address, psk, inner_local, inner_remote, {}) \
                 VALUES ('t', 1, '1.1.1.1', 'a-long-enough-secret', '10.1.0.1/30', '10.1.0.2', {})",
                column, value
            );
            assert!(sqlx::query(&sql).execute(&pool).await.is_err(), "{}", sql);
        }
    }

    #[tokio::test]
    async fn a_link_with_a_tunnel_cannot_be_deleted() {
        let pool = memory_pool().await;
        add_link(&pool, "ISP1", "enp3s0").await;
        add_tunnel(&pool, "hq", 1, "10.255.0.1/30").await.unwrap();

        let blocked = sqlx::query("DELETE FROM sdwan_links WHERE id = 1")
            .execute(&pool)
            .await;
        assert!(blocked.is_err());

        sqlx::query("DELETE FROM sdwan_tunnels WHERE name = 'hq'")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM sdwan_links WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn tunnel_status_is_checked_and_dies_with_its_tunnel() {
        let pool = memory_pool().await;
        add_link(&pool, "ISP1", "enp3s0").await;
        add_tunnel(&pool, "hq", 1, "10.255.0.1/30").await.unwrap();

        assert!(sqlx::query("INSERT INTO sdwan_tunnel_status (tunnel_id) VALUES (99)")
            .execute(&pool)
            .await
            .is_err());

        sqlx::query("INSERT INTO sdwan_tunnel_status (tunnel_id) VALUES (1)")
            .execute(&pool)
            .await
            .unwrap();

        let row: (String, String, String, String) = sqlx::query_as(
            "SELECT state, ike_state, child_state, routing_state FROM sdwan_tunnel_status",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            row,
            ("unknown".to_string(), "unknown".to_string(), "unknown".to_string(), "unknown".to_string())
        );

        for sql in [
            "UPDATE sdwan_tunnel_status SET state = 'broken'",
            "UPDATE sdwan_tunnel_status SET ike_state = 'half'",
            "UPDATE sdwan_tunnel_status SET child_state = 'half'",
            "UPDATE sdwan_tunnel_status SET routing_state = 'half'",
            "UPDATE sdwan_tunnel_status SET loss_pct = 101",
        ] {
            assert!(sqlx::query(sql).execute(&pool).await.is_err(), "{}", sql);
        }

        sqlx::query("DELETE FROM sdwan_tunnels WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();

        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sdwan_tunnel_status")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 0);
    }
}
