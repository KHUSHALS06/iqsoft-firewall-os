use serde::Serialize;
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

/// CPU counters from the previous reading: (idle ticks, total ticks).
/// The CPU load is the change between two readings, so the last one is kept here.
static LAST_CPU: Mutex<Option<(u64, u64)>> = Mutex::new(None);

/// CPU, memory and disk use of the firewall box.
/// A value is `null` when it could not be read, the dashboard then shows "–".
#[derive(Debug, Serialize, Clone, PartialEq, Default)]
pub struct SystemStats {
    /// Share of CPU time in use since the previous reading, 0 to 100.
    pub cpu_percent: Option<f64>,
    /// Memory in use (without cache that can be freed), 0 to 100.
    pub memory_percent: Option<f64>,
    pub memory_used_bytes: Option<u64>,
    pub memory_total_bytes: Option<u64>,
    /// Space used on the disk that holds "/", 0 to 100.
    pub disk_percent: Option<f64>,
    pub disk_used_bytes: Option<u64>,
    pub disk_total_bytes: Option<u64>,
    pub uptime_seconds: Option<u64>,
}

/// Read CPU, memory, disk and uptime.
/// This can wait a moment on the very first call, so run it off the async threads.
pub fn read_system() -> SystemStats {
    let mut stats = SystemStats::default();

    stats.cpu_percent = cpu_percent();

    if let Some((used, total)) = read_memory() {
        stats.memory_used_bytes = Some(used);
        stats.memory_total_bytes = Some(total);
        stats.memory_percent = percent(used, total);
    }

    if let Some((used, total)) = read_disk() {
        stats.disk_used_bytes = Some(used);
        stats.disk_total_bytes = Some(total);
        stats.disk_percent = percent(used, total);
    }

    stats.uptime_seconds = read_uptime();

    stats
}

fn percent(used: u64, total: u64) -> Option<f64> {
    if total == 0 {
        return None;
    }
    Some(round1(used as f64 / total as f64 * 100.0))
}

fn round1(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

/* ---------------- CPU ---------------- */

fn cpu_percent() -> Option<f64> {
    let previous = LAST_CPU.lock().ok().and_then(|guard| *guard);

    let before = match previous {
        Some(value) => value,
        None => {
            // First reading since the program started: measure over a short pause.
            let first = read_cpu_times()?;
            std::thread::sleep(Duration::from_millis(250));
            first
        }
    };

    let now = read_cpu_times()?;

    if let Ok(mut guard) = LAST_CPU.lock() {
        *guard = Some(now);
    }

    cpu_between(before, now)
}

fn cpu_between(before: (u64, u64), now: (u64, u64)) -> Option<f64> {
    let total = now.1.checked_sub(before.1)?;
    let idle = now.0.checked_sub(before.0)?;

    if total == 0 {
        return None;
    }

    let busy = total - idle.min(total);
    Some(round1(busy as f64 / total as f64 * 100.0))
}

fn read_cpu_times() -> Option<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/stat").ok()?;
    parse_cpu_times(&text)
}

/// Parses the first line of /proc/stat:
///   cpu  user nice system idle iowait irq softirq steal guest guest_nice
/// Returns (idle ticks, total ticks).
fn parse_cpu_times(text: &str) -> Option<(u64, u64)> {
    let line = text.lines().find(|line| line.starts_with("cpu "))?;

    let fields: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|value| value.parse().ok())
        .collect();

    if fields.len() < 4 {
        return None;
    }

    let idle = fields[3] + fields.get(4).copied().unwrap_or(0);
    let total: u64 = fields.iter().take(8).sum();

    Some((idle, total))
}

/* ---------------- memory ---------------- */

fn read_memory() -> Option<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    parse_meminfo(&text)
}

/// Parses /proc/meminfo, returns (used bytes, total bytes).
fn parse_meminfo(text: &str) -> Option<(u64, u64)> {
    let mut total_kb: Option<u64> = None;
    let mut available_kb: Option<u64> = None;

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total_kb = first_number(rest);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            available_kb = first_number(rest);
        }
    }

    let total = total_kb? * 1024;
    let available = available_kb? * 1024;

    Some((total.saturating_sub(available), total))
}

fn first_number(text: &str) -> Option<u64> {
    text.split_whitespace().next()?.parse().ok()
}

/* ---------------- disk ---------------- */

fn read_disk() -> Option<(u64, u64)> {
    for program in ["/usr/bin/df", "/bin/df", "df"] {
        if let Ok(output) = Command::new(program).args(["-Pk", "/"]).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout).into_owned();
                return parse_df(&text);
            }
        }
    }
    None
}

/// Parses `df -Pk /`, returns (used bytes, total bytes).
/// Example line: /dev/sda2  100000000  32000000  63000000  34% /
fn parse_df(text: &str) -> Option<(u64, u64)> {
    let line = text.lines().nth(1)?;
    let parts: Vec<&str> = line.split_whitespace().collect();

    if parts.len() < 4 {
        return None;
    }

    let used: u64 = parts[2].parse().ok()?;
    let available: u64 = parts[3].parse().ok()?;

    // Same maths as df: used / (used + available), so the number matches `df`.
    Some((used * 1024, (used + available) * 1024))
}

/* ---------------- uptime ---------------- */

fn read_uptime() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/uptime").ok()?;
    let seconds: f64 = text.split_whitespace().next()?.parse().ok()?;
    Some(seconds as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cpu_times() {
        let text = "cpu  100 5 50 800 20 3 2 1 0 0\ncpu0 50 2 25 400 10 1 1 0 0 0\n";
        let (idle, total) = parse_cpu_times(text).expect("should parse");

        assert_eq!(idle, 820);
        assert_eq!(total, 981);
    }

    #[test]
    fn cpu_load_is_the_change_between_two_readings() {
        // 100 ticks passed, 75 of them idle: 25 percent busy.
        let load = cpu_between((800, 1000), (875, 1100)).expect("should work");
        assert_eq!(load, 25.0);

        // No time passed: no answer.
        assert_eq!(cpu_between((800, 1000), (800, 1000)), None);
    }

    #[test]
    fn parses_meminfo() {
        let text = "MemTotal:        8000000 kB\nMemFree:          500000 kB\nMemAvailable:    6000000 kB\n";
        let (used, total) = parse_meminfo(text).expect("should parse");

        assert_eq!(total, 8_000_000 * 1024);
        assert_eq!(used, 2_000_000 * 1024);
        assert_eq!(percent(used, total), Some(25.0));
    }

    #[test]
    fn parses_df_output() {
        let text = "Filesystem     1024-blocks     Used Available Capacity Mounted on\n/dev/sda2        100000000 32000000  63000000      34% /\n";
        let (used, total) = parse_df(text).expect("should parse");

        assert_eq!(used, 32_000_000 * 1024);
        assert_eq!(total, 95_000_000 * 1024);
        assert_eq!(percent(used, total), Some(33.7));
    }

    #[test]
    fn bad_input_gives_none() {
        assert_eq!(parse_cpu_times("nothing here"), None);
        assert_eq!(parse_meminfo("MemTotal: 100 kB"), None);
        assert_eq!(parse_df("Filesystem only"), None);
        assert_eq!(percent(5, 0), None);
    }
}
