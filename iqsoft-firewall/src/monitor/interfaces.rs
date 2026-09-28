use serde::Serialize;
use std::fs;

/// Traffic counters and link state for one network interface.
/// Counters are totals since boot; the UI can work out speed
/// by comparing two readings taken a few seconds apart.
#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct InterfaceStats {
    pub name: String,
    /// "up", "down" or "unknown" (tailscale0 and lo normally say "unknown")
    pub state: String,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errors: u64,
    pub rx_dropped: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errors: u64,
    pub tx_dropped: u64,
}

/// Read statistics for every interface on the box.
pub fn read_interfaces() -> Result<Vec<InterfaceStats>, String> {
    let content = fs::read_to_string("/proc/net/dev")
        .map_err(|e| format!("Could not read /proc/net/dev: {}", e))?;

    let mut interfaces = parse_proc_net_dev(&content);

    for iface in interfaces.iter_mut() {
        iface.state = read_link_state(&iface.name);
    }

    Ok(interfaces)
}

/// Reads "up" / "down" from sysfs. Falls back to "unknown".
fn read_link_state(name: &str) -> String {
    // Interface names come from /proc, but never build a path from
    // something containing a slash.
    if name.contains('/') || name.contains("..") {
        return "unknown".to_string();
    }

    fs::read_to_string(format!("/sys/class/net/{}/operstate", name))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Parses the text of /proc/net/dev.
///
/// Each interface line looks like:
///   enp3s0: 1234 10 0 0 0 0 0 0 5678 12 0 0 0 0 0 0
/// The first 8 numbers are receive counters, the next 8 are transmit.
fn parse_proc_net_dev(content: &str) -> Vec<InterfaceStats> {
    let mut result = Vec::new();

    // The first two lines are column headers.
    for line in content.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };

        let numbers: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|v| v.parse().ok())
            .collect();

        if numbers.len() < 16 {
            continue;
        }

        result.push(InterfaceStats {
            name: name.trim().to_string(),
            state: "unknown".to_string(),
            rx_bytes: numbers[0],
            rx_packets: numbers[1],
            rx_errors: numbers[2],
            rx_dropped: numbers[3],
            tx_bytes: numbers[8],
            tx_packets: numbers[9],
            tx_errors: numbers[10],
            tx_dropped: numbers[11],
        });
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_net_dev() {
        let sample = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:     100       5    0    0    0     0          0         0     100       5    0    0    0     0       0          0
enp3s0: 123456     900    1    2    0     0          0         0  654321     800    3    4    0     0       0          0
";

        let parsed = parse_proc_net_dev(sample);

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].name, "enp3s0");
        assert_eq!(parsed[1].rx_bytes, 123456);
        assert_eq!(parsed[1].rx_errors, 1);
        assert_eq!(parsed[1].rx_dropped, 2);
        assert_eq!(parsed[1].tx_bytes, 654321);
        assert_eq!(parsed[1].tx_packets, 800);
        assert_eq!(parsed[1].tx_errors, 3);
        assert_eq!(parsed[1].tx_dropped, 4);
    }
}
