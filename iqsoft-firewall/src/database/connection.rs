use sqlx::{sqlite::{SqlitePoolOptions, SqliteConnectOptions}, SqlitePool};
use std::path::Path;
use std::str::FromStr;

const LIVE_DB: &str = "database/firewall.db";
const PENDING_RESTORE: &str = "database/restore.pending";
const REPLACED_DB: &str = "database/firewall.db.before-restore";
const SIDE_FILES: [&str; 3] = ["", "-wal", "-shm"];

fn apply_pending_restore() {
    if !Path::new(PENDING_RESTORE).exists() {
        return;
    }

    for suffix in SIDE_FILES {
        let _ = std::fs::remove_file(format!("{}{}", REPLACED_DB, suffix));
    }

    for suffix in SIDE_FILES {
        let live = format!("{}{}", LIVE_DB, suffix);
        if Path::new(&live).exists() {
            if let Err(e) = std::fs::rename(&live, format!("{}{}", REPLACED_DB, suffix)) {
                eprintln!("ERROR: restore cancelled, could not move {} aside: {}", live, e);
                return;
            }
        }
    }

    match std::fs::rename(PENDING_RESTORE, LIVE_DB) {
        Ok(_) => println!("Restored the configuration from the uploaded backup. The previous database was kept as {}", REPLACED_DB),
        Err(e) => {
            eprintln!("ERROR: could not put the uploaded backup in place: {}", e);
            for suffix in SIDE_FILES {
                let _ = std::fs::rename(format!("{}{}", REPLACED_DB, suffix), format!("{}{}", LIVE_DB, suffix));
            }
        }
    }
}

pub async fn create_pool() -> Result<SqlitePool, sqlx::Error> {
    std::fs::create_dir_all("database").ok();

    apply_pending_restore();

    let options = SqliteConnectOptions::from_str("sqlite://database/firewall.db")?
        .create_if_missing(true);

    SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
}
