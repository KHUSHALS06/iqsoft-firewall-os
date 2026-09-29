use sqlx::{Row, SqlitePool};

pub async fn initialize_database(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // Check if firewall_rules exists
    let table_exists = sqlx::query(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='firewall_rules';",
    )
    .fetch_optional(pool)
    .await?
    .is_some();

    if !table_exists {
        // Fresh installation
        sqlx::query(
            r#"
            CREATE TABLE firewall_rules (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT NOT NULL,
                enabled         INTEGER NOT NULL DEFAULT 1,
                priority        INTEGER NOT NULL DEFAULT 100,

                chain_name      TEXT NOT NULL,
                action          TEXT NOT NULL,
                protocol        TEXT NOT NULL,

                src_ip          TEXT,
                dst_ip          TEXT,

                src_port        INTEGER,
                dst_port        INTEGER,
                port_any        INTEGER NOT NULL DEFAULT 0,

                interface_name  TEXT,

                log_enabled     INTEGER NOT NULL DEFAULT 0,

                comment         TEXT
            );
            "#,
        )
        .execute(pool)
        .await?;

        println!("✓ Created firewall_rules table");
    } else {
        let rows = sqlx::query("PRAGMA table_info(firewall_rules);")
            .fetch_all(pool)
            .await?;

        let mut has_protocol = false;

        for row in rows {
            let name: String = row.get("name");

            if name == "protocol" {
                has_protocol = true;
            }
        }

        if !has_protocol {
            println!("Migrating firewall_rules table...");

            sqlx::query(
                r#"
                CREATE TABLE firewall_rules_new (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    name            TEXT NOT NULL,
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    priority        INTEGER NOT NULL DEFAULT 100,

                    chain_name      TEXT NOT NULL,
                    action          TEXT NOT NULL,
                    protocol        TEXT NOT NULL DEFAULT 'tcp',

                    src_ip          TEXT,
                    dst_ip          TEXT,

                    src_port        INTEGER,
                    dst_port        INTEGER,

                    interface_name  TEXT,

                    log_enabled     INTEGER NOT NULL DEFAULT 0,

                    comment         TEXT
                );
                "#,
            )
            .execute(pool)
            .await?;

            sqlx::query(
                r#"
                INSERT INTO firewall_rules_new (
                    id,
                    name,
                    enabled,
                    priority,
                    chain_name,
                    action,
                    protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    interface_name,
                    log_enabled,
                    comment
                )
                SELECT
                    id,
                    name,
                    enabled,
                    priority,
                    chain_name,
                    action,
                    'tcp',
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    interface_name,
                    log_enabled,
                    comment
                FROM firewall_rules;
                "#,
            )
            .execute(pool)
            .await?;

            sqlx::query("DROP TABLE firewall_rules;")
                .execute(pool)
                .await?;

            sqlx::query("ALTER TABLE firewall_rules_new RENAME TO firewall_rules;")
                .execute(pool)
                .await?;

            println!("✓ Database migrated successfully");
        }
    }

    let rule_columns = sqlx::query("PRAGMA table_info(firewall_rules);")
        .fetch_all(pool)
        .await?;

    let has_port_any = rule_columns
        .iter()
        .any(|row| row.get::<String, _>("name") == "port_any");

    if !has_port_any {
        sqlx::query(
            "ALTER TABLE firewall_rules ADD COLUMN port_any INTEGER NOT NULL DEFAULT 0;",
        )
        .execute(pool)
        .await?;

        println!("✓ Added port_any column to firewall_rules");
    }

    let has_rate_limit = rule_columns
        .iter()
        .any(|row| row.get::<String, _>("name") == "rate_limit");

    if !has_rate_limit {
        sqlx::query("ALTER TABLE firewall_rules ADD COLUMN rate_limit TEXT;")
            .execute(pool)
            .await?;

        println!("✓ Added rate_limit column to firewall_rules");
    }

    let has_src_mac = rule_columns
        .iter()
        .any(|row| row.get::<String, _>("name") == "src_mac");

    if !has_src_mac {
        sqlx::query("ALTER TABLE firewall_rules ADD COLUMN src_mac TEXT;")
            .execute(pool)
            .await?;

        println!("✓ Added src_mac column to firewall_rules");
    }

    for column in ["time_start", "time_end", "days"] {
        let has_column = rule_columns
            .iter()
            .any(|row| row.get::<String, _>("name") == column);

        if !has_column {
            sqlx::query(&format!("ALTER TABLE firewall_rules ADD COLUMN {} TEXT;", column))
                .execute(pool)
                .await?;

            println!("✓ Added {} column to firewall_rules", column);
        }
    }

    // Check if network_config exists
    let network_config_exists = sqlx::query(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='network_config';",
    )
    .fetch_optional(pool)
    .await?
    .is_some();

    if !network_config_exists {
        sqlx::query(
            r#"
            CREATE TABLE network_config (
                id                   INTEGER PRIMARY KEY CHECK (id = 1),
                wan_interface        TEXT NOT NULL DEFAULT 'eth0',
                lan_interface        TEXT NOT NULL DEFAULT 'eth1',
                nat_enabled          INTEGER NOT NULL DEFAULT 1,
                ip_forward_enabled   INTEGER NOT NULL DEFAULT 1
            );
            "#,
        )
        .execute(pool)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO network_config (id, wan_interface, lan_interface, nat_enabled, ip_forward_enabled)
            VALUES (1, 'eth0', 'eth1', 1, 1);
            "#,
        )
        .execute(pool)
        .await?;

        println!("✓ Created network_config table (defaults: wan=eth0, lan=eth1 — update before commit)");
    }

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS dhcp_config (
            id                  INTEGER PRIMARY KEY CHECK (id = 1),
            enabled             INTEGER NOT NULL DEFAULT 0,
            interface_name      TEXT NOT NULL DEFAULT 'eth1',
            subnet              TEXT NOT NULL DEFAULT '192.168.1.0/24',
            range_start         TEXT NOT NULL DEFAULT '192.168.1.100',
            range_end           TEXT NOT NULL DEFAULT '192.168.1.200',
            gateway             TEXT,
            dns_servers         TEXT NOT NULL DEFAULT '1.1.1.1,8.8.8.8',
            lease_time_seconds  INTEGER NOT NULL DEFAULT 43200,
            domain              TEXT
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        INSERT OR IGNORE INTO dhcp_config (id, enabled, interface_name, gateway)
        VALUES (1, 0, 'eth1', '192.168.1.1');
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS dhcp_reservations (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            mac       TEXT NOT NULL UNIQUE,
            ip        TEXT NOT NULL UNIQUE,
            hostname  TEXT
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS dns_config (
            id                  INTEGER PRIMARY KEY CHECK (id = 1),
            enabled             INTEGER NOT NULL DEFAULT 0,
            listen_interfaces   TEXT NOT NULL DEFAULT 'eth1',
            upstream_servers    TEXT NOT NULL DEFAULT '1.1.1.1,8.8.8.8',
            local_domain        TEXT,
            use_dhcp_hostnames  INTEGER NOT NULL DEFAULT 0
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        INSERT OR IGNORE INTO dns_config (id, enabled, listen_interfaces)
        VALUES (1, 0, 'eth1');
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS dns_static_records (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname  TEXT NOT NULL UNIQUE,
            ip        TEXT NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS port_forward_rules (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            name                 TEXT NOT NULL,
            enabled              INTEGER NOT NULL DEFAULT 1,
            protocol             TEXT NOT NULL,
            external_port_start  INTEGER NOT NULL,
            external_port_end    INTEGER NOT NULL,
            internal_ip          TEXT NOT NULL,
            internal_port_start  INTEGER NOT NULL,
            comment              TEXT
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS routes (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT NOT NULL,
            enabled         INTEGER NOT NULL DEFAULT 1,
            destination     TEXT NOT NULL,
            gateway         TEXT,
            interface_name  TEXT,
            metric          INTEGER NOT NULL DEFAULT 100,
            comment         TEXT
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            username       TEXT NOT NULL UNIQUE,
            password_hash  TEXT NOT NULL,
            role           TEXT NOT NULL DEFAULT 'admin',
            created_at     INTEGER NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash  TEXT PRIMARY KEY,
            user_id     INTEGER NOT NULL,
            created_at  INTEGER NOT NULL,
            expires_at  INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        "#,
    )
    .execute(pool)
    .await?;

    super::address_schema::create_address_tables(pool).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::initialize_database;
    use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};

    async fn memory_pool() -> SqlitePool {
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap()
    }

    async fn rule_columns(pool: &SqlitePool) -> Vec<String> {
        sqlx::query("PRAGMA table_info(firewall_rules);")
            .fetch_all(pool)
            .await
            .unwrap()
            .iter()
            .map(|row| row.get::<String, _>("name"))
            .collect()
    }

    #[tokio::test]
    async fn fresh_database_has_src_mac_column() {
        let pool = memory_pool().await;
        initialize_database(&pool).await.unwrap();

        assert!(rule_columns(&pool).await.contains(&"src_mac".to_string()));
    }

    #[tokio::test]
    async fn initializing_twice_keeps_a_single_src_mac_column() {
        let pool = memory_pool().await;
        initialize_database(&pool).await.unwrap();
        initialize_database(&pool).await.unwrap();

        let count = rule_columns(&pool)
            .await
            .iter()
            .filter(|name| name.as_str() == "src_mac")
            .count();

        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn existing_database_gets_src_mac_and_keeps_its_rules() {
        let pool = memory_pool().await;
        initialize_database(&pool).await.unwrap();

        sqlx::query(
            "INSERT INTO firewall_rules (name, chain_name, action, protocol, dst_port)
             VALUES ('old rule', 'INPUT', 'accept', 'tcp', 22)",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query("ALTER TABLE firewall_rules DROP COLUMN src_mac;")
            .execute(&pool)
            .await
            .unwrap();
        assert!(!rule_columns(&pool).await.contains(&"src_mac".to_string()));

        initialize_database(&pool).await.unwrap();

        assert!(rule_columns(&pool).await.contains(&"src_mac".to_string()));

        let row = sqlx::query("SELECT name, src_mac FROM firewall_rules")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row.get::<String, _>("name"), "old rule");
        assert_eq!(row.get::<Option<String>, _>("src_mac"), None);
    }

    #[tokio::test]
    async fn fresh_database_has_the_time_rule_columns() {
        let pool = memory_pool().await;
        initialize_database(&pool).await.unwrap();

        let columns = rule_columns(&pool).await;

        for column in ["time_start", "time_end", "days"] {
            assert!(columns.contains(&column.to_string()), "{}", column);
        }
    }

    #[tokio::test]
    async fn initializing_twice_keeps_a_single_copy_of_each_time_column() {
        let pool = memory_pool().await;
        initialize_database(&pool).await.unwrap();
        initialize_database(&pool).await.unwrap();

        let columns = rule_columns(&pool).await;

        for column in ["time_start", "time_end", "days"] {
            assert_eq!(columns.iter().filter(|name| name.as_str() == column).count(), 1, "{}", column);
        }
    }

    #[tokio::test]
    async fn existing_database_gets_the_time_columns_and_keeps_its_rules() {
        let pool = memory_pool().await;
        initialize_database(&pool).await.unwrap();

        sqlx::query(
            "INSERT INTO firewall_rules (name, chain_name, action, protocol, dst_port)
             VALUES ('old rule', 'INPUT', 'accept', 'tcp', 22)",
        )
        .execute(&pool)
        .await
        .unwrap();

        for column in ["time_start", "time_end", "days"] {
            sqlx::query(&format!("ALTER TABLE firewall_rules DROP COLUMN {};", column))
                .execute(&pool)
                .await
                .unwrap();
        }

        let columns = rule_columns(&pool).await;
        for column in ["time_start", "time_end", "days"] {
            assert!(!columns.contains(&column.to_string()), "{}", column);
        }

        initialize_database(&pool).await.unwrap();

        let columns = rule_columns(&pool).await;
        for column in ["time_start", "time_end", "days"] {
            assert!(columns.contains(&column.to_string()), "{}", column);
        }

        let row = sqlx::query("SELECT name, time_start, time_end, days FROM firewall_rules")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row.get::<String, _>("name"), "old rule");
        assert_eq!(row.get::<Option<String>, _>("time_start"), None);
        assert_eq!(row.get::<Option<String>, _>("time_end"), None);
        assert_eq!(row.get::<Option<String>, _>("days"), None);
    }
}
