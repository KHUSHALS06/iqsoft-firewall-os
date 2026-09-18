use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};

pub async fn create_pool() -> Result<SqlitePool, sqlx::Error> {
    SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite://database/firewall.db")
        .await
}
