use crate::models::route::Route;
use sqlx::{sqlite::SqliteRow, Row, SqlitePool};

pub struct RouteRepository;

impl RouteRepository {
    fn row_to_route(row: &SqliteRow) -> Route {
        Route {
            id: Some(row.get("id")),
            name: row.get("name"),
            enabled: row.get::<i64, _>("enabled") != 0,
            destination: row.get("destination"),
            gateway: row.get("gateway"),
            interface_name: row.get("interface_name"),
            metric: row.get("metric"),
            comment: row.get("comment"),
        }
    }

    pub async fn list_routes(pool: &SqlitePool) -> Result<Vec<Route>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                name,
                enabled,
                destination,
                gateway,
                interface_name,
                metric,
                comment
            FROM routes
            ORDER BY metric ASC, id ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_route).collect())
    }

    pub async fn add_route(pool: &SqlitePool, route: Route) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO routes (
                name,
                enabled,
                destination,
                gateway,
                interface_name,
                metric,
                comment
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(route.name)
        .bind(route.enabled)
        .bind(route.destination)
        .bind(route.gateway)
        .bind(route.interface_name)
        .bind(route.metric)
        .bind(route.comment)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn update_route(
        pool: &SqlitePool,
        id: i64,
        route: Route,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE routes
            SET
                name = ?,
                enabled = ?,
                destination = ?,
                gateway = ?,
                interface_name = ?,
                metric = ?,
                comment = ?
            WHERE id = ?
            "#,
        )
        .bind(route.name)
        .bind(route.enabled)
        .bind(route.destination)
        .bind(route.gateway)
        .bind(route.interface_name)
        .bind(route.metric)
        .bind(route.comment)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn delete_route(pool: &SqlitePool, id: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM routes WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }

    pub async fn replace_all_routes(
        pool: &SqlitePool,
        routes: Vec<Route>,
    ) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query("DELETE FROM routes")
            .execute(&mut *tx)
            .await?;

        for route in routes {
            sqlx::query(
                r#"
                INSERT INTO routes (
                    id,
                    name,
                    enabled,
                    destination,
                    gateway,
                    interface_name,
                    metric,
                    comment
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(route.id)
            .bind(route.name)
            .bind(route.enabled)
            .bind(route.destination)
            .bind(route.gateway)
            .bind(route.interface_name)
            .bind(route.metric)
            .bind(route.comment)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(())
    }
}
