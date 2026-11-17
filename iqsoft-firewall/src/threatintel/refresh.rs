use crate::{
    models::threatfeed::{
        clip_error, parse_feed_text, ThreatFeed, ThreatRefreshResult, MAX_DOWNLOAD_BYTES,
    },
    repository::threatfeed_repository::{now_seconds, ThreatFeedRepository},
    threatintel::generator,
};
use sqlx::SqlitePool;
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;

const USER_AGENT: &str = "IQSOFT-Firewall threat-feed-updater";

/// What a refresh did, including whether the new list is already blocking in the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshOutcome {
    pub result: ThreatRefreshResult,
    pub applied: bool,
    pub apply_error: Option<String>,
}

/// Downloads a list. The size is capped while reading, so a hostile server cannot fill the memory.
pub async fn download(url: &str) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .map_err(|e| format!("could not start the download: {}", e.without_url()))?;

    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("download failed: {}", e.without_url()))?;

    if !response.status().is_success() {
        return Err(format!("download failed: HTTP {}", response.status().as_u16()));
    }

    if let Some(length) = response.content_length() {
        if length as usize > MAX_DOWNLOAD_BYTES {
            return Err(format!(
                "download refused: the list is larger than {} MB",
                MAX_DOWNLOAD_BYTES / (1024 * 1024)
            ));
        }
    }

    let mut body: Vec<u8> = Vec::new();

    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|e| format!("download failed: {}", e.without_url()))?;

        let Some(chunk) = chunk else { break };

        if body.len() + chunk.len() > MAX_DOWNLOAD_BYTES {
            return Err(format!(
                "download refused: the list is larger than {} MB",
                MAX_DOWNLOAD_BYTES / (1024 * 1024)
            ));
        }

        body.extend_from_slice(&chunk);
    }

    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Downloads one feed and stores the result. Does not touch the kernel.
///
/// A failed download or an unusable list leaves the stored networks exactly as they were and only
/// records what went wrong, so a broken feed server can never empty the blocklist.
pub async fn refresh_data(
    pool: &SqlitePool,
    feed: &ThreatFeed,
) -> Result<ThreatRefreshResult, String> {
    let id = feed.id.ok_or("The feed has no id")?;

    if feed.kind != "url" {
        return Err("Only download feeds can be refreshed, a manual feed takes imports".into());
    }

    let url = feed
        .url
        .as_deref()
        .ok_or("The download feed has no URL")?;

    let now = now_seconds();

    let outcome = match download(url).await {
        Ok(text) => parse_feed_text(&text),
        Err(e) => Err(e),
    };

    match outcome {
        Ok(parsed) => {
            ThreatFeedRepository::replace_entries(pool, id, &parsed, now)
                .await
                .map_err(|e| e.to_string())?;

            Ok(ThreatRefreshResult {
                feed_id: id,
                ipv4_imported: parsed.ipv4.len(),
                ipv6_imported: parsed.ipv6.len(),
                skipped: parsed.skipped,
            })
        }
        Err(e) => {
            let message = clip_error(&e);

            if let Err(db_error) =
                ThreatFeedRepository::record_failure(pool, id, now, &message).await
            {
                eprintln!(
                    "threat feeds: could not record the failure of feed {}: {}",
                    id, db_error
                );
            }

            Err(message)
        }
    }
}

/// Refreshes one feed and, when the feed is switched on, puts the result into the kernel straight away.
pub async fn refresh_feed(
    pool: &SqlitePool,
    lock: &Arc<Mutex<()>>,
    id: i64,
) -> Result<RefreshOutcome, String> {
    let feed = ThreatFeedRepository::get_feed(pool, id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("Threat feed {} does not exist", id))?;

    let result = refresh_data(pool, &feed).await?;

    if !feed.enabled {
        return Ok(RefreshOutcome {
            result,
            applied: false,
            apply_error: None,
        });
    }

    match generator::apply_live(pool, lock).await {
        Ok(()) => Ok(RefreshOutcome {
            result,
            applied: true,
            apply_error: None,
        }),
        Err(e) => Ok(RefreshOutcome {
            result,
            applied: false,
            apply_error: Some(clip_error(&e)),
        }),
    }
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

    /// A tiny web server on 127.0.0.1 that answers every request with the given status and body.
    async fn serve(status: &'static str, body: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                let body = body.clone();

                tokio::spawn(async move {
                    let mut buffer = [0u8; 2048];
                    let _ = socket.read(&mut buffer).await;

                    let response = format!(
                        "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status,
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

    /// The URL validator refuses 127.0.0.1, so tests write the feed straight into the table.
    async fn add_url_feed(pool: &SqlitePool, name: &str, url: &str, enabled: bool) -> i64 {
        sqlx::query("INSERT INTO threat_feeds (name, kind, url, enabled) VALUES (?, 'url', ?, ?)")
            .bind(name)
            .bind(url)
            .bind(enabled as i64)
            .execute(pool)
            .await
            .unwrap()
            .last_insert_rowid()
    }

    #[tokio::test]
    async fn a_good_download_replaces_the_stored_list() {
        let pool = memory_pool().await;
        let url = serve("200 OK", "# list\n1.2.3.4\n5.6.7.0/24 ; SBL1\n10.0.0.1\nrubbish\n".into()).await;
        let id = add_url_feed(&pool, "f", &url, true).await;

        sqlx::query("INSERT INTO threat_feed_entries (feed_id, family, cidr) VALUES (?, 'ipv4', '9.9.9.9/32')")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();

        let lock = Arc::new(Mutex::new(()));
        let outcome = refresh_feed(&pool, &lock, id).await.unwrap();

        assert_eq!(outcome.result.ipv4_imported, 2);
        assert_eq!(outcome.result.ipv6_imported, 0);
        assert_eq!(outcome.result.skipped, 2);
        assert!(!outcome.applied);
        assert!(outcome.apply_error.is_some());

        assert_eq!(
            ThreatFeedRepository::list_networks(&pool, id, "ipv4").await.unwrap(),
            vec!["1.2.3.4/32", "5.6.7.0/24"]
        );

        let stored = ThreatFeedRepository::get_feed(&pool, id).await.unwrap().unwrap();
        assert!(stored.last_updated.is_some());
        assert_eq!(stored.last_error, None);
    }

    #[tokio::test]
    async fn an_http_error_keeps_the_old_list_and_records_the_failure() {
        let pool = memory_pool().await;
        let url = serve("503 Service Unavailable", "down".into()).await;
        let id = add_url_feed(&pool, "f", &url, true).await;

        sqlx::query("INSERT INTO threat_feed_entries (feed_id, family, cidr) VALUES (?, 'ipv4', '9.9.9.9/32')")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();

        let lock = Arc::new(Mutex::new(()));
        let error = refresh_feed(&pool, &lock, id).await.unwrap_err();
        assert!(error.contains("503"), "{}", error);

        assert_eq!(
            ThreatFeedRepository::list_networks(&pool, id, "ipv4").await.unwrap(),
            vec!["9.9.9.9/32"]
        );

        let stored = ThreatFeedRepository::get_feed(&pool, id).await.unwrap().unwrap();
        assert!(stored.last_error.unwrap().contains("503"));
        assert!(stored.last_attempt.is_some());
        assert_eq!(stored.last_updated, None);
    }

    #[tokio::test]
    async fn a_page_with_no_networks_in_it_does_not_wipe_the_list() {
        let pool = memory_pool().await;
        let url = serve("200 OK", "<html><body>Rate limited</body></html>".into()).await;
        let id = add_url_feed(&pool, "f", &url, true).await;

        sqlx::query("INSERT INTO threat_feed_entries (feed_id, family, cidr) VALUES (?, 'ipv4', '9.9.9.9/32')")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();

        let lock = Arc::new(Mutex::new(()));
        assert!(refresh_feed(&pool, &lock, id).await.is_err());

        assert_eq!(ThreatFeedRepository::count_entries(&pool, id).await.unwrap(), 1);

        let stored = ThreatFeedRepository::get_feed(&pool, id).await.unwrap().unwrap();
        assert!(stored.last_error.is_some());
    }

    #[tokio::test]
    async fn a_server_that_is_not_there_is_a_recorded_failure_not_a_crash() {
        let pool = memory_pool().await;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let id = add_url_feed(&pool, "f", &format!("http://127.0.0.1:{}/x", port), true).await;

        let lock = Arc::new(Mutex::new(()));
        let error = refresh_feed(&pool, &lock, id).await.unwrap_err();
        assert!(error.contains("download failed"), "{}", error);

        let stored = ThreatFeedRepository::get_feed(&pool, id).await.unwrap().unwrap();
        assert!(stored.last_error.is_some());
    }

    #[tokio::test]
    async fn a_disabled_feed_is_refreshed_but_not_applied() {
        let pool = memory_pool().await;
        let url = serve("200 OK", "1.2.3.4\n".into()).await;
        let id = add_url_feed(&pool, "f", &url, false).await;

        let lock = Arc::new(Mutex::new(()));
        let outcome = refresh_feed(&pool, &lock, id).await.unwrap();

        assert_eq!(outcome.result.ipv4_imported, 1);
        assert!(!outcome.applied);
        assert_eq!(outcome.apply_error, None);
    }

    #[tokio::test]
    async fn manual_and_missing_feeds_cannot_be_refreshed() {
        let pool = memory_pool().await;
        let lock = Arc::new(Mutex::new(()));

        let manual = sqlx::query("INSERT INTO threat_feeds (name, kind) VALUES ('m', 'manual')")
            .execute(&pool)
            .await
            .unwrap()
            .last_insert_rowid();

        assert!(refresh_feed(&pool, &lock, manual).await.is_err());
        assert!(refresh_feed(&pool, &lock, 999).await.is_err());
    }

    #[tokio::test]
    async fn an_oversized_download_is_refused() {
        let pool = memory_pool().await;
        let big = "1.2.3.4\n".repeat(MAX_DOWNLOAD_BYTES / 8 + 10);
        let url = serve("200 OK", big).await;
        let id = add_url_feed(&pool, "f", &url, true).await;

        let lock = Arc::new(Mutex::new(()));
        let error = refresh_feed(&pool, &lock, id).await.unwrap_err();
        assert!(error.contains("larger than"), "{}", error);
        assert_eq!(ThreatFeedRepository::count_entries(&pool, id).await.unwrap(), 0);
    }
}
