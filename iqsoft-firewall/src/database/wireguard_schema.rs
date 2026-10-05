use sqlx::SqlitePool;

pub async fn create_wireguard_tables(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS wireguard_config (
            id                  INTEGER PRIMARY KEY CHECK (id = 1),
            enabled             INTEGER NOT NULL DEFAULT 0,
            interface_name      TEXT NOT NULL DEFAULT 'wg0',
            listen_port         INTEGER NOT NULL DEFAULT 51820
                                CHECK (listen_port BETWEEN 1 AND 65535),
            address             TEXT NOT NULL DEFAULT '10.8.0.1/24',
            mtu                 INTEGER,
            dns                 TEXT,
            endpoint            TEXT,
            client_allowed_ips  TEXT NOT NULL DEFAULT '0.0.0.0/0,::/0',
            private_key         TEXT NOT NULL DEFAULT '',
            public_key          TEXT NOT NULL DEFAULT ''
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        INSERT OR IGNORE INTO wireguard_config (id, enabled)
        VALUES (1, 0);
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS wireguard_peers (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            name                  TEXT NOT NULL UNIQUE COLLATE NOCASE,
            enabled               INTEGER NOT NULL DEFAULT 1,
            public_key            TEXT NOT NULL UNIQUE,
            preshared_key         TEXT,
            allowed_ips           TEXT NOT NULL,
            endpoint              TEXT,
            persistent_keepalive  INTEGER NOT NULL DEFAULT 0
                                  CHECK (persistent_keepalive BETWEEN 0 AND 65535),
            comment               TEXT
        );
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}
