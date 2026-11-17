use crate::{
    repository::threatfeed_repository::{now_seconds, ThreatFeedRepository},
    threatintel::{generator, refresh},
};
use sqlx::SqlitePool;
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;

const TICK: Duration = Duration::from_secs(60);

/// Downloads every feed whose refresh time has come, then puts all the results into the kernel with a
/// single table swap. Returns how many feeds were updated successfully.
pub async fn run_due(pool: &SqlitePool, lock: &Arc<Mutex<()>>) -> usize {
    let due = match ThreatFeedRepository::list_due_feeds(pool, now_seconds()).await {
        Ok(due) => due,
        Err(e) => {
            eprintln!("threat feeds: could not look for feeds to refresh: {}", e);
            return 0;
        }
    };

    let mut updated = 0usize;

    for feed in due {
        match refresh::refresh_data(pool, &feed).await {
            Ok(result) => {
                updated += 1;
                println!(
                    "threat feeds: '{}' updated ({} IPv4, {} IPv6 networks)",
                    feed.name, result.ipv4_imported, result.ipv6_imported
                );
            }
            Err(e) => eprintln!("threat feeds: '{}' not updated: {}", feed.name, e),
        }
    }

    if updated > 0 {
        if let Err(e) = generator::apply_live(pool, lock).await {
            eprintln!("threat feeds: could not apply the new lists: {}", e);
        }
    }

    updated
}

/// Starts the background updater. The first thing it does is put the stored blocklists into the
/// kernel, because the ruleset restored at boot may hold an older copy of them.
pub fn spawn(pool: SqlitePool, lock: Arc<Mutex<()>>) {
    tokio::spawn(async move {
        match generator::apply_live(&pool, &lock).await {
            Ok(()) => println!("threat feeds: blocklists loaded"),
            Err(e) => eprintln!("threat feeds: could not load the blocklists: {}", e),
        }

        loop {
            run_due(&pool, &lock).await;
            tokio::time::sleep(TICK).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::init::initialize_database;
    use sqlx::sqlite::SqlitePoolOptions;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    async fn memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        initialize_database(&pool).await.unwrap();
        pool
    }

    async fn serve(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };

                tokio::spawn(async move {
                    let mut buffer = [0u8; 2048];
                    let _ = socket.read(&mut buffer).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });

        format!("http://127.0.0.1:{}/list.txt", port)
    }

    async fn add_url_feed(pool: &SqlitePool, name: &str, url: &str) -> i64 {
        sqlx::query("INSERT INTO threat_feeds (name, kind, url) VALUES (?, 'url', ?)")
            .bind(name)
            .bind(url)
            .execute(pool)
            .await
            .unwrap()
            .last_insert_rowid()
    }

    #[tokio::test]
    async fn only_due_feeds_are_downloaded_and_a_second_pass_finds_nothing_to_do() {
        let pool = memory_pool().await;
        let lock = Arc::new(Mutex::new(()));

        let url = serve("1.2.3.4\n5.6.7.8\n").await;
        let due = add_url_feed(&pool, "due", &url).await;

        let url2 = serve("9.9.9.9\n").await;
        let recent = add_url_feed(&pool, "recent", &url2).await;
        sqlx::query("UPDATE threat_feeds SET last_attempt = ?, last_updated = ? WHERE id = ?")
            .bind(now_seconds())
            .bind(now_seconds())
            .bind(recent)
            .execute(&pool)
            .await
            .unwrap();

        assert_eq!(run_due(&pool, &lock).await, 1);

        assert_eq!(ThreatFeedRepository::count_entries(&pool, due).await.unwrap(), 2);
        assert_eq!(ThreatFeedRepository::count_entries(&pool, recent).await.unwrap(), 0);

        assert_eq!(run_due(&pool, &lock).await, 0);
    }

    #[tokio::test]
    async fn a_failing_feed_does_not_stop_the_others() {
        let pool = memory_pool().await;
        let lock = Arc::new(Mutex::new(()));

        let dead = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            format!("http://127.0.0.1:{}/x", port)
        };
        let bad = add_url_feed(&pool, "a-dead", &dead).await;

        let url = serve("1.2.3.4\n").await;
        let good = add_url_feed(&pool, "b-good", &url).await;

        assert_eq!(run_due(&pool, &lock).await, 1);

        let bad_feed = ThreatFeedRepository::get_feed(&pool, bad).await.unwrap().unwrap();
        assert!(bad_feed.last_error.is_some());
        assert_eq!(ThreatFeedRepository::count_entries(&pool, good).await.unwrap(), 1);
    }
}
