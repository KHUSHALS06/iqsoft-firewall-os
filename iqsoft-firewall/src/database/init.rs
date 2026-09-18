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
        // Detect whether this is the old schema
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

        // Single row, seeded with placeholder interface names — the operator
        // must set the real ones via PUT /api/network before committing,
        // otherwise commit will fail validation against live interfaces.
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

    Ok(())
}
