//! The SD-WAN health monitor.
//!
//! Every second it looks at the WAN links and pings the ones whose probe interval has passed.
//! The result goes through `health::next_status`, so one lost ping never flips a link: a link
//! goes down after `fail_threshold` failed probes in a row and comes back after
//! `recover_threshold` good ones. The new status is saved in the database.
//!
//! When a link changes state, the SD-WAN setup is refreshed straight away, so traffic moves to
//! another link within seconds. Latency and loss changes (used by "best quality" rules) are
//! picked up at most once a minute, to keep the routing from flapping between two similar links.
//!
//! The refresh only does something when SD-WAN has been committed before, and only when the
//! generated rules really differ from the ones in use (that is what `SdwanCommit::refresh` does).
//! While SD-WAN is switched off the monitor sends no pings at all.

use crate::{
    models::sdwan::{link_mark, SdwanLink, SdwanLinkStatus},
    repository::sdwan_repository::SdwanRepository,
    sdwan::{
        commit::SdwanCommit,
        generator::SdwanGenerator,
        health::{self, ProbeOutcome},
    },
};
use sqlx::SqlitePool;
use std::{
    future::Future,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::Mutex, task::JoinSet};

const TICK: Duration = Duration::from_secs(1);

/// Between two refreshes that are only caused by new latency or loss numbers.
const LATENCY_REFRESH_SECS: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoundResult {
    /// How many links were pinged.
    pub probed: usize,
    /// How many of them changed state (unknown / up / down).
    pub changed: usize,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A link is pinged when it is enabled and its probe interval has passed.
/// A link that was never pinged is due at once, and so is any link when the clock jumped back.
pub fn is_due(now: i64, link: &SdwanLink) -> bool {
    if !link.enabled {
        return false;
    }

    match link.last_check {
        None => true,
        Some(last) => now < last || now - last >= link.probe_interval_secs,
    }
}

/// Whether the SD-WAN setup should be refreshed after this round.
pub fn should_refresh(
    state_changed: bool,
    probed_since_refresh: bool,
    now: i64,
    last_refresh: i64,
) -> bool {
    state_changed || (probed_since_refresh && now - last_refresh >= LATENCY_REFRESH_SECS)
}

/// Results of a refresh that are normal and not worth a line in the log.
pub fn is_quiet(message: &str) -> bool {
    message.contains("already up to date") || message.contains("nothing to refresh")
}

fn blank_status(link_id: i64) -> SdwanLinkStatus {
    SdwanLinkStatus {
        link_id,
        state: "unknown".to_string(),
        latency_ms: None,
        loss_pct: None,
        consecutive_fail: 0,
        consecutive_ok: 0,
        last_check: None,
        last_change: None,
        last_error: None,
    }
}

/// The real probe: pings through the link's interface, marked so the ping follows the
/// link's own routing table.
async fn real_probe(link: SdwanLink, slot: u32) -> ProbeOutcome {
    health::probe(
        &link.interface_name,
        &link.probe_target,
        link.probe_timeout_secs,
        Some(link_mark(slot)),
    )
    .await
}

/// One round: ping every link that is due (all of them at the same time), then save the results.
/// With `force` every enabled link is pinged, due or not.
async fn probe_round_with<F, Fut>(
    pool: &SqlitePool,
    now: i64,
    force: bool,
    prober: F,
) -> Result<RoundResult, String>
where
    F: Fn(SdwanLink, u32) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = ProbeOutcome> + Send + 'static,
{
    let input = SdwanGenerator::load_input(pool).await?;

    if !input.enabled {
        return Ok(RoundResult {
            probed: 0,
            changed: 0,
        });
    }

    let slots = SdwanGenerator::slots(&input);

    let mut set = JoinSet::new();

    for link in &input.links {
        let Some(id) = link.id else {
            continue;
        };

        // Links the generator skipped as invalid have no slot, so they get no probe either.
        let Some(&(_, slot)) = slots.iter().find(|(link_id, _)| *link_id == id) else {
            continue;
        };

        if !link.enabled || (!force && !is_due(now, link)) {
            continue;
        }

        let link = link.clone();
        let prober = prober.clone();

        set.spawn(async move {
            let outcome = prober(link.clone(), slot).await;
            (link, outcome)
        });
    }

    let mut probed = 0usize;
    let mut changed = 0usize;

    while let Some(joined) = set.join_next().await {
        let Ok((link, outcome)) = joined else {
            continue;
        };

        let Some(id) = link.id else {
            continue;
        };

        probed += 1;

        let previous = match SdwanRepository::get_status(pool, id).await {
            Ok(Some(status)) => status,
            Ok(None) => blank_status(id),
            Err(e) => {
                eprintln!("sdwan: could not read the status of '{}': {}", link.name, e);
                continue;
            }
        };

        let next = health::next_status(
            link.fail_threshold,
            link.recover_threshold,
            &previous,
            &outcome,
            now,
        );

        // The link may have been deleted while it was being pinged; that is not an error.
        if let Err(e) = SdwanRepository::save_status(pool, &next).await {
            eprintln!("sdwan: could not save the status of '{}': {}", link.name, e);
            continue;
        }

        if next.state != previous.state {
            changed += 1;

            println!(
                "sdwan: link '{}' ({}) is now {}{}",
                link.name,
                link.interface_name,
                next.state,
                match (&next.last_error, next.state.as_str()) {
                    (Some(error), "down") => format!(" - {}", error),
                    _ => String::new(),
                }
            );
        }
    }

    Ok(RoundResult { probed, changed })
}

/// Pings every enabled link right now (for the "test links" button). Does nothing while
/// SD-WAN is switched off.
pub async fn probe_now(pool: &SqlitePool) -> Result<RoundResult, String> {
    probe_round_with(pool, now(), true, real_probe).await
}

/// Starts the background monitor. Never blocks the caller.
pub fn spawn(pool: SqlitePool, lock: Arc<Mutex<()>>) {
    tokio::spawn(async move {
        let mut last_refresh = 0i64;
        let mut probed_since_refresh = false;
        let mut last_error = String::new();

        loop {
            tokio::time::sleep(TICK).await;

            let moment = now();

            let result = match probe_round_with(&pool, moment, false, real_probe).await {
                Ok(result) => {
                    last_error.clear();
                    result
                }
                Err(e) => {
                    // Print a problem once, not every second.
                    if e != last_error {
                        eprintln!("sdwan: could not check the links: {}", e);
                        last_error = e;
                    }
                    continue;
                }
            };

            if result.probed > 0 {
                probed_since_refresh = true;
            }

            if !should_refresh(
                result.changed > 0,
                probed_since_refresh,
                moment,
                last_refresh,
            ) {
                continue;
            }

            last_refresh = moment;
            probed_since_refresh = false;

            match SdwanCommit::refresh(&pool, &lock).await {
                Ok(message) if is_quiet(&message) => {}
                Ok(message) => println!("sdwan: {}", message),
                Err(e) => eprintln!("sdwan: could not refresh the routing: {}", e),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::init::initialize_database, services::sdwan_service::SdwanService,
    };
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Mutex as StdMutex,
    };

    type Calls = Arc<StdMutex<Vec<(String, u32)>>>;

    fn good() -> ProbeOutcome {
        ProbeOutcome {
            success: true,
            latency_ms: Some(12.5),
            loss_pct: 0,
            error: None,
        }
    }

    /// A prober that never touches the network: it answers well or badly as told, and
    /// writes down which interface and slot it was asked about.
    fn scripted(
        ok: Arc<AtomicBool>,
        calls: Calls,
    ) -> impl Fn(SdwanLink, u32) -> std::future::Ready<ProbeOutcome> + Clone + Send + 'static {
        move |link: SdwanLink, slot: u32| {
            calls.lock().unwrap().push((link.interface_name.clone(), slot));

            std::future::ready(if ok.load(Ordering::Relaxed) {
                good()
            } else {
                ProbeOutcome::failure("No reply from the probe target")
            })
        }
    }

    fn new_link(name: &str, interface: &str, priority: i64) -> SdwanLink {
        SdwanLink {
            id: None,
            name: name.to_string(),
            interface_name: interface.to_string(),
            gateway: Some("10.1.0.1".to_string()),
            enabled: true,
            priority,
            weight: 1,
            probe_target: "1.1.1.1".to_string(),
            probe_interval_secs: 10,
            probe_timeout_secs: 2,
            fail_threshold: 2,
            recover_threshold: 2,
            comment: None,
            state: "unknown".to_string(),
            latency_ms: None,
            loss_pct: None,
            last_check: None,
            last_change: None,
            last_error: None,
        }
    }

    async fn memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        initialize_database(&pool).await.unwrap();
        pool
    }

    fn harness() -> (Arc<AtomicBool>, Calls) {
        (
            Arc::new(AtomicBool::new(true)),
            Arc::new(StdMutex::new(Vec::new())),
        )
    }

    async fn one_link_pool() -> (SqlitePool, i64) {
        let pool = memory_pool().await;

        let id = SdwanService::add_link(&pool, new_link("ISP1", "eth0", 10))
            .await
            .unwrap();
        SdwanService::set_enabled(&pool, true).await.unwrap();

        (pool, id)
    }

    #[test]
    fn a_link_is_due_when_never_checked_or_the_interval_has_passed() {
        let mut link = new_link("ISP1", "eth0", 10);

        assert!(is_due(1_000, &link));

        link.last_check = Some(1_000);
        assert!(!is_due(1_005, &link));
        assert!(!is_due(1_009, &link));
        assert!(is_due(1_010, &link));
        assert!(is_due(1_500, &link));

        // The clock jumped backwards: do not wait for it to catch up.
        assert!(is_due(900, &link));

        link.enabled = false;
        assert!(!is_due(1_500, &link));
    }

    #[test]
    fn a_state_change_refreshes_at_once_but_numbers_alone_wait_a_minute() {
        assert!(should_refresh(true, false, 1_001, 1_000));
        assert!(!should_refresh(false, false, 5_000, 1_000));
        assert!(!should_refresh(false, true, 1_030, 1_000));
        assert!(should_refresh(false, true, 1_060, 1_000));
    }

    #[test]
    fn routine_refresh_results_are_not_logged() {
        assert!(is_quiet("SD-WAN is already up to date"));
        assert!(is_quiet("SD-WAN has not been committed yet, nothing to refresh"));
        assert!(!is_quiet("SD-WAN applied: 2 link(s) and 1 rule(s) active"));
    }

    #[tokio::test]
    async fn nothing_is_pinged_while_sdwan_is_switched_off() {
        let pool = memory_pool().await;
        SdwanService::add_link(&pool, new_link("ISP1", "eth0", 10))
            .await
            .unwrap();

        let (ok, calls) = harness();

        let result = probe_round_with(&pool, 1_000, false, scripted(ok.clone(), calls.clone()))
            .await
            .unwrap();
        assert_eq!(result, RoundResult { probed: 0, changed: 0 });

        let forced = probe_round_with(&pool, 1_000, true, scripted(ok, calls.clone()))
            .await
            .unwrap();
        assert_eq!(forced.probed, 0);

        assert!(calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_first_good_ping_brings_a_link_up_and_is_saved() {
        let (pool, id) = one_link_pool().await;
        let (ok, calls) = harness();

        let result = probe_round_with(&pool, 1_000, false, scripted(ok, calls))
            .await
            .unwrap();
        assert_eq!(result, RoundResult { probed: 1, changed: 1 });

        let status = SdwanRepository::get_status(&pool, id).await.unwrap().unwrap();
        assert_eq!(status.state, "up");
        assert_eq!(status.latency_ms, Some(12.5));
        assert_eq!(status.loss_pct, Some(0));
        assert_eq!(status.last_check, Some(1_000));
        assert_eq!(status.last_change, Some(1_000));
        assert_eq!(status.consecutive_ok, 1);
        assert_eq!(status.last_error, None);

        // The link list the generator reads shows the live state too.
        let links = SdwanRepository::list_links(&pool).await.unwrap();
        assert_eq!(links[0].state, "up");
        assert_eq!(links[0].last_check, Some(1_000));
    }

    #[tokio::test]
    async fn links_are_only_pinged_when_their_interval_has_passed() {
        let (pool, _id) = one_link_pool().await;
        let (ok, calls) = harness();

        let first = probe_round_with(&pool, 1_000, false, scripted(ok.clone(), calls.clone()))
            .await
            .unwrap();
        assert_eq!(first.probed, 1);

        let too_soon = probe_round_with(&pool, 1_005, false, scripted(ok.clone(), calls.clone()))
            .await
            .unwrap();
        assert_eq!(too_soon, RoundResult { probed: 0, changed: 0 });

        let again = probe_round_with(&pool, 1_010, false, scripted(ok.clone(), calls.clone()))
            .await
            .unwrap();
        assert_eq!(again, RoundResult { probed: 1, changed: 0 });

        // "Test now" pings regardless of the interval.
        let forced = probe_round_with(&pool, 1_011, true, scripted(ok, calls.clone()))
            .await
            .unwrap();
        assert_eq!(forced.probed, 1);

        assert_eq!(calls.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn a_link_goes_down_after_repeated_failures_and_comes_back_after_repeated_successes() {
        let (pool, id) = one_link_pool().await;
        let (ok, calls) = harness();

        // Establish "up" first.
        probe_round_with(&pool, 1_000, false, scripted(ok.clone(), calls.clone()))
            .await
            .unwrap();

        ok.store(false, Ordering::Relaxed);

        // One lost probe is not enough (fail_threshold is 2).
        let first_fail = probe_round_with(&pool, 1_010, false, scripted(ok.clone(), calls.clone()))
            .await
            .unwrap();
        assert_eq!(first_fail.changed, 0);

        let status = SdwanRepository::get_status(&pool, id).await.unwrap().unwrap();
        assert_eq!(status.state, "up");
        assert_eq!(status.consecutive_fail, 1);

        let second_fail = probe_round_with(&pool, 1_020, false, scripted(ok.clone(), calls.clone()))
            .await
            .unwrap();
        assert_eq!(second_fail.changed, 1);

        let status = SdwanRepository::get_status(&pool, id).await.unwrap().unwrap();
        assert_eq!(status.state, "down");
        assert_eq!(status.last_change, Some(1_020));
        assert_eq!(status.latency_ms, None);
        assert_eq!(status.loss_pct, Some(100));
        assert!(status.last_error.unwrap().contains("No reply"));

        // Recovery needs recover_threshold (2) good probes in a row.
        ok.store(true, Ordering::Relaxed);

        let first_ok = probe_round_with(&pool, 1_030, false, scripted(ok.clone(), calls.clone()))
            .await
            .unwrap();
        assert_eq!(first_ok.changed, 0);

        let second_ok = probe_round_with(&pool, 1_040, false, scripted(ok, calls))
            .await
            .unwrap();
        assert_eq!(second_ok.changed, 1);

        let status = SdwanRepository::get_status(&pool, id).await.unwrap().unwrap();
        assert_eq!(status.state, "up");
        assert_eq!(status.last_change, Some(1_040));
        assert_eq!(status.last_error, None);
    }

    #[tokio::test]
    async fn every_link_is_pinged_through_its_own_slot_and_disabled_links_are_left_alone() {
        let pool = memory_pool().await;

        SdwanService::add_link(&pool, new_link("ISP1", "eth0", 10))
            .await
            .unwrap();
        SdwanService::add_link(&pool, new_link("ISP2", "eth2", 20))
            .await
            .unwrap();

        let mut spare = new_link("Spare", "eth3", 30);
        spare.enabled = false;
        SdwanService::add_link(&pool, spare).await.unwrap();

        SdwanService::set_enabled(&pool, true).await.unwrap();

        let (ok, calls) = harness();

        let result = probe_round_with(&pool, 1_000, false, scripted(ok, calls.clone()))
            .await
            .unwrap();
        assert_eq!(result, RoundResult { probed: 2, changed: 2 });

        let mut seen = calls.lock().unwrap().clone();
        seen.sort();

        assert_eq!(
            seen,
            vec![("eth0".to_string(), 1), ("eth2".to_string(), 2)]
        );

        let links = SdwanRepository::list_links(&pool).await.unwrap();
        let spare = links.iter().find(|l| l.name == "Spare").unwrap();
        assert_eq!(spare.state, "unknown");
        assert_eq!(spare.last_check, None);
    }
}
