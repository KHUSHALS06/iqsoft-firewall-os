use sqlx::{sqlite::{SqlitePoolOptions, SqliteConnectOptions}, SqlitePool};
use std::str::FromStr;

pub async fn create_pool() -> Result<SqlitePool, sqlx::Error> {
    std::fs::create_dir_all("database").ok();

    let options = SqliteConnectOptions::from_str("sqlite://database/firewall.db")?
        .create_if_missing(true);

    SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
}
