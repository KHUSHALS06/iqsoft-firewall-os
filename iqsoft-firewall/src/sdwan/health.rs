use crate::models::sdwan::{SdwanLinkStatus, MAX_ERROR_LEN};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;
use tokio::process::Command;

/// How many pings one probe sends.
pub const PROBE_COUNT: u32 = 3;

/// What one probe found out about a link.
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeOutcome {
    pub success: bool,
    pub latency_ms: Option<f64>,
    pub loss_pct: i64,
    pub error: Option<String>,
}

impl ProbeOutcome {
    pub fn failure(error: impl Into<String>) -> Self {
        ProbeOutcome {
            success: false,
            latency_ms: None,
            loss_pct: 100,
            error: Some(error.into()),
        }
    }
}

/// The arguments for one `ping` run.
///
/// -I sends the pings out of the link's interface, -m tags them with the link's
/// packet mark so they follow the link's own routing table (the main routing
/// table only has one default route, so without the mark a probe could never
/// leave through a backup link).
pub fn ping_args(interface: &str, mark: Option<u32>, target: &str, timeout_secs: i64) -> Vec<String> {
    let mut args = vec![
        "-n".to_string(),
        "-q".to_string(),
        "-c".to_string(),
        PROBE_COUNT.to_string(),
        "-i".to_string(),
        "0.3".to_string(),
        "-W".to_string(),
        timeout_secs.max(1).to_string(),
        "-I".to_string(),
        interface.to_string(),
    ];

    if let Some(mark) = mark {
        args.push("-m".to_string());
        args.push(mark.to_string());
    }

    args.push(target.to_string());
    args
}

fn leading_number(text: &str) -> Option<f64> {
    let text = text.trim().trim_start_matches('+');
    let end = text
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(text.len());

    text[..end].parse().ok()
}

/// Reads the summary that `ping -q` prints at the end, for example:
///
///   3 packets transmitted, 3 received, 0% packet loss, time 602ms
///   rtt min/avg/max/mdev = 10.1/11.2/12.3/0.9 ms
pub fn parse_ping_output(output: &str) -> ProbeOutcome {
    let Some(summary) = output.lines().find(|l| l.contains("packets transmitted")) else {
        return ProbeOutcome::failure("Could not read the ping result");
    };

    let mut received: Option<f64> = None;
    let mut loss: Option<f64> = None;

    for part in summary.split(',') {
        let part = part.trim();

        if part.contains("packet loss") {
            loss = leading_number(part);
        } else if part.contains("received") {
            received = leading_number(part);
        }
    }

    let Some(received) = received else {
        return ProbeOutcome::failure("Could not read the ping result");
    };

    if received < 1.0 {
        let mut outcome = ProbeOutcome::failure("No reply from the probe target");
        if let Some(loss) = loss {
            outcome.loss_pct = (loss.round() as i64).clamp(0, 100);
        }
        return outcome;
    }

    let loss_pct = (loss.unwrap_or(0.0).round() as i64).clamp(0, 100);

    let latency_ms = output
        .lines()
        .find(|l| l.contains("min/avg/max"))
        .and_then(|l| l.split('=').nth(1))
        .and_then(|v| v.trim().split(' ').next())
        .and_then(|v| v.split('/').nth(1))
        .and_then(|v| v.parse::<f64>().ok());

    ProbeOutcome {
        success: true,
        latency_ms,
        loss_pct,
        error: None,
    }
}

/// Pings the target through one link and reports what happened.
/// This never panics and never hangs: a stuck ping is killed after a grace period.
pub async fn probe(
    interface: &str,
    target: &str,
    timeout_secs: i64,
    mark: Option<u32>,
) -> ProbeOutcome {
    if Ipv4Addr::from_str(target).is_err() {
        return ProbeOutcome::failure(format!("Probe target '{}' is not an IPv4 address", target));
    }

    if interface.is_empty() || interface.starts_with('-') {
        return ProbeOutcome::failure(format!("Interface '{}' is not valid", interface));
    }

    let mut command = Command::new("ping");
    command
        .args(ping_args(interface, mark, target, timeout_secs))
        .kill_on_drop(true);

    let limit = Duration::from_secs(timeout_secs.max(1) as u64 + 5);

    match tokio::time::timeout(limit, command.output()).await {
        Err(_) => ProbeOutcome::failure("The ping did not finish in time"),
        Ok(Err(e)) => ProbeOutcome::failure(format!("Could not run ping: {}", e)),
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut outcome = parse_ping_output(&stdout);

            // When ping printed no summary at all, its own error message is more useful.
            if !outcome.success && !stdout.contains("packets transmitted") {
                let stderr = String::from_utf8_lossy(&output.stderr);

                if let Some(line) = stderr.lines().map(|l| l.trim()).find(|l| !l.is_empty()) {
                    outcome.error = Some(line.to_string());
                }
            }

            outcome
        }
    }
}

fn limit_error(text: &str) -> String {
    text.chars().take(MAX_ERROR_LEN).collect()
}

/// Works out the new status of a link from its old status and the latest probe.
///
/// A link does not flip on a single lost ping:
///   - an "up" link goes down after `fail_threshold` failed probes in a row
///   - a "down" link comes back after `recover_threshold` good probes in a row
///   - a link that was never probed ("unknown") is trusted on its first good
///     probe, and goes down after `fail_threshold` failed probes in a row
pub fn next_status(
    fail_threshold: i64,
    recover_threshold: i64,
    previous: &SdwanLinkStatus,
    outcome: &ProbeOutcome,
    now: i64,
) -> SdwanLinkStatus {
    let mut next = previous.clone();

    next.last_check = Some(now);
    next.loss_pct = Some(outcome.loss_pct);

    if outcome.success {
        next.consecutive_ok = previous.consecutive_ok.saturating_add(1);
        next.consecutive_fail = 0;
        next.latency_ms = outcome.latency_ms;
        next.last_error = None;
    } else {
        next.consecutive_fail = previous.consecutive_fail.saturating_add(1);
        next.consecutive_ok = 0;
        next.latency_ms = None;
        next.last_error = outcome.error.as_deref().map(limit_error);
    }

    let new_state = match previous.state.as_str() {
        "up" => {
            if !outcome.success && next.consecutive_fail >= fail_threshold {
                "down"
            } else {
                "up"
            }
        }
        "down" => {
            if outcome.success && next.consecutive_ok >= recover_threshold {
                "up"
            } else {
                "down"
            }
        }
        _ => {
            if outcome.success {
                "up"
            } else if next.consecutive_fail >= fail_threshold {
                "down"
            } else {
                "unknown"
            }
        }
    };

    if new_state != previous.state {
        next.last_change = Some(now);
    }

    next.state = new_state.to_string();
    next
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "PING 1.1.1.1 (1.1.1.1) from 192.168.0.167 enp3s0: 56(84) bytes of data.\n\
\n\
--- 1.1.1.1 ping statistics ---\n\
3 packets transmitted, 3 received, 0% packet loss, time 602ms\n\
rtt min/avg/max/mdev = 10.100/11.200/12.300/0.900 ms\n";

    fn status(state: &str) -> SdwanLinkStatus {
        SdwanLinkStatus {
            link_id: 1,
            state: state.to_string(),
            latency_ms: None,
            loss_pct: None,
            consecutive_fail: 0,
            consecutive_ok: 0,
            last_check: None,
            last_change: None,
            last_error: None,
        }
    }

    fn good() -> ProbeOutcome {
        ProbeOutcome {
            success: true,
            latency_ms: Some(12.5),
            loss_pct: 0,
            error: None,
        }
    }

    fn bad() -> ProbeOutcome {
        ProbeOutcome::failure("No reply from the probe target")
    }

    /// Runs the outcomes one after another with thresholds fail=3, recover=2.
    fn run(start: &str, outcomes: &[ProbeOutcome]) -> SdwanLinkStatus {
        let mut current = status(start);

        for (i, outcome) in outcomes.iter().enumerate() {
            current = next_status(3, 2, &current, outcome, 1000 + i as i64);
        }

        current
    }

    // ------------------------------------------------------------- the ping text

    #[test]
    fn a_clean_ping_is_a_success_with_its_average_time() {
        let outcome = parse_ping_output(GOOD);

        assert!(outcome.success);
        assert_eq!(outcome.loss_pct, 0);
        assert_eq!(outcome.latency_ms, Some(11.2));
        assert_eq!(outcome.error, None);
    }

    #[test]
    fn some_lost_pings_still_count_as_a_success() {
        let text = "3 packets transmitted, 2 received, 33.3333% packet loss, time 1003ms\n\
rtt min/avg/max/mdev = 20.0/25.0/30.0/5.0 ms\n";

        let outcome = parse_ping_output(text);

        assert!(outcome.success);
        assert_eq!(outcome.loss_pct, 33);
        assert_eq!(outcome.latency_ms, Some(25.0));
    }

    #[test]
    fn no_replies_is_a_failure_with_full_loss() {
        let text = "3 packets transmitted, 0 received, 100% packet loss, time 2050ms\n";
        let outcome = parse_ping_output(text);

        assert!(!outcome.success);
        assert_eq!(outcome.loss_pct, 100);
        assert_eq!(outcome.latency_ms, None);
        assert!(outcome.error.is_some());
    }

    #[test]
    fn a_ping_that_reports_errors_is_a_failure() {
        let text = "3 packets transmitted, 0 received, +3 errors, 100% packet loss, time 2050ms\n";
        let outcome = parse_ping_output(text);

        assert!(!outcome.success);
        assert_eq!(outcome.loss_pct, 100);
    }

    #[test]
    fn unreadable_output_is_a_failure() {
        for text in ["", "ping: connect: Network is unreachable\n", "hello"] {
            let outcome = parse_ping_output(text);

            assert!(!outcome.success, "{:?}", text);
            assert!(outcome.error.as_deref().unwrap().contains("read"), "{:?}", text);
        }
    }

    #[test]
    fn a_missing_time_line_still_counts_as_up() {
        let outcome = parse_ping_output("3 packets transmitted, 3 received, 0% packet loss\n");

        assert!(outcome.success);
        assert_eq!(outcome.latency_ms, None);
    }

    #[test]
    fn the_ping_command_is_built_with_and_without_a_mark() {
        assert_eq!(
            ping_args("enp3s0", Some(65536), "1.1.1.1", 2),
            vec![
                "-n", "-q", "-c", "3", "-i", "0.3", "-W", "2", "-I", "enp3s0", "-m", "65536",
                "1.1.1.1"
            ]
        );

        assert_eq!(
            ping_args("enp3s0", None, "8.8.8.8", 0),
            vec![
                "-n", "-q", "-c", "3", "-i", "0.3", "-W", "1", "-I", "enp3s0", "8.8.8.8"
            ]
        );
    }

    #[tokio::test]
    async fn a_bad_target_or_interface_is_refused_without_running_ping() {
        let outcome = probe("enp3s0", "1.1.1.1; reboot", 2, None).await;
        assert!(!outcome.success);
        assert!(outcome.error.as_deref().unwrap().contains("not an IPv4"));

        let outcome = probe("-rf", "1.1.1.1", 2, None).await;
        assert!(!outcome.success);
        assert!(outcome.error.as_deref().unwrap().contains("not valid"));

        let outcome = probe("", "1.1.1.1", 2, None).await;
        assert!(!outcome.success);
    }

    // ------------------------------------------------------------ the state rules

    #[test]
    fn a_new_link_is_trusted_after_one_good_probe() {
        let after = run("unknown", &[good()]);

        assert_eq!(after.state, "up");
        assert_eq!(after.last_change, Some(1000));
        assert_eq!(after.latency_ms, Some(12.5));
        assert_eq!(after.loss_pct, Some(0));
        assert_eq!(after.consecutive_ok, 1);
        assert_eq!(after.last_error, None);
    }

    #[test]
    fn a_new_link_goes_down_after_three_failed_probes() {
        let after_two = run("unknown", &[bad(), bad()]);
        assert_eq!(after_two.state, "unknown");
        assert_eq!(after_two.last_change, None);

        let after_three = run("unknown", &[bad(), bad(), bad()]);
        assert_eq!(after_three.state, "down");
        assert_eq!(after_three.last_change, Some(1002));
        assert_eq!(after_three.consecutive_fail, 3);
        assert!(after_three.last_error.is_some());
    }

    #[test]
    fn an_up_link_survives_two_failures_and_a_good_probe_resets_the_count() {
        let after = run("up", &[bad(), bad()]);
        assert_eq!(after.state, "up");
        assert_eq!(after.consecutive_fail, 2);

        let reset = run("up", &[bad(), bad(), good(), bad(), bad()]);
        assert_eq!(reset.state, "up");
        assert_eq!(reset.consecutive_fail, 2);
    }

    #[test]
    fn an_up_link_goes_down_after_three_failures_in_a_row() {
        let after = run("up", &[bad(), bad(), bad()]);

        assert_eq!(after.state, "down");
        assert_eq!(after.last_change, Some(1002));
        assert_eq!(after.latency_ms, None);
        assert_eq!(after.loss_pct, Some(100));
    }

    #[test]
    fn a_down_link_needs_two_good_probes_in_a_row_to_come_back() {
        let after_one = run("down", &[good()]);
        assert_eq!(after_one.state, "down");
        assert_eq!(after_one.last_change, None);

        let after_two = run("down", &[good(), good()]);
        assert_eq!(after_two.state, "up");
        assert_eq!(after_two.last_change, Some(1001));

        let broken_streak = run("down", &[good(), bad(), good()]);
        assert_eq!(broken_streak.state, "down");
        assert_eq!(broken_streak.consecutive_ok, 1);
    }

    #[test]
    fn last_change_only_moves_when_the_state_changes() {
        let mut current = status("up");
        current.last_change = Some(500);

        let after = next_status(3, 2, &current, &good(), 2000);

        assert_eq!(after.state, "up");
        assert_eq!(after.last_change, Some(500));
        assert_eq!(after.last_check, Some(2000));
    }

    #[test]
    fn a_long_error_is_cut_to_the_limit() {
        let outcome = ProbeOutcome::failure("x".repeat(1000));
        let after = next_status(3, 2, &status("up"), &outcome, 1);

        assert_eq!(after.last_error.unwrap().chars().count(), MAX_ERROR_LEN);
    }

    #[test]
    fn thresholds_of_one_react_immediately() {
        let down = next_status(1, 1, &status("up"), &bad(), 1);
        assert_eq!(down.state, "down");

        let up = next_status(1, 1, &down, &good(), 2);
        assert_eq!(up.state, "up");
    }
}
