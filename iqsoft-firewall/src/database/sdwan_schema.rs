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
}
