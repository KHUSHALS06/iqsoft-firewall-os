use serde::Serialize;
use std::fs;

const CONNTRACK_FILE: &str = "/proc/net/nf_conntrack";
const CONNTRACK_COUNT_FILE: &str = "/proc/sys/net/netfilter/nf_conntrack_count";
const CONNTRACK_MAX_FILE: &str = "/proc/sys/net/netfilter/nf_conntrack_max";

/// One tracked connection.
///
/// The "reply" addresses show what the connection looks like on the way
/// back. When they differ from the original addresses, NAT is rewriting
/// this connection (masquerade or port forward).
#[derive(Debug, Serialize, Clone, Default, PartialEq)]
pub struct Connection {
    pub protocol: String,
    /// TCP state such as ESTABLISHED or TIME_WAIT. None for UDP/ICMP.
    pub state: Option<String>,
    /// Seconds until the kernel forgets this connection if it stays idle.
    pub timeout_seconds: u64,

    pub src: String,
    pub dst: String,
    pub sport: Option<u16>,
    pub dport: Option<u16>,

    pub reply_src: String,
    pub reply_dst: String,
    pub reply_sport: Option<u16>,
    pub reply_dport: Option<u16>,

    /// True while no reply packet has been seen yet.
    pub unreplied: bool,
    /// True once traffic has flowed both ways.
    pub assured: bool,

    /// Byte counters. Only present when the kernel has accounting on:
    ///   sysctl -w net.netfilter.nf_conntrack_acct=1
    pub bytes_out: Option<u64>,
    pub bytes_in: Option<u64>,
}

/// A page of connections plus the total number found.
#[derive(Debug, Serialize)]
pub struct ConnectionList {
    pub total: usize,
    pub shown: usize,
    pub connections: Vec<Connection>,
}

/// How full the kernel's connection table is.
#[derive(Debug, Serialize)]
pub struct ConntrackUsage {
    pub count: Option<u64>,
    pub max: Option<u64>,
}

/// Read up to `limit` tracked connections.
pub fn read_connections(limit: usize) -> Result<ConnectionList, String> {
    let content = load_conntrack_text()?;

    let all: Vec<Connection> = content.lines().filter_map(parse_line).collect();
    let total = all.len();
    let connections: Vec<Connection> = all.into_iter().take(limit).collect();

    Ok(ConnectionList {
        total,
        shown: connections.len(),
        connections,
    })
}

/// Gets the raw connection table as text.
///
/// Older kernels expose it as /proc/net/nf_conntrack. Some kernels do not,
/// so fall back to the `conntrack` command (package: conntrack).
fn load_conntrack_text() -> Result<String, String> {
    if let Ok(text) = fs::read_to_string(CONNTRACK_FILE) {
        return Ok(text);
    }

    let mut last_error = String::from("conntrack tool not found");

    for program in ["/usr/sbin/conntrack", "/sbin/conntrack", "conntrack"] {
        match std::process::Command::new(program)
            .args(["-L", "-o", "extended"])
            .output()
        {
            Ok(output) if output.status.success() => {
                return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
            }
            Ok(output) => {
                last_error = format!(
                    "{} failed: {}",
                    program,
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            Err(e) => {
                last_error = format!("{}: {}", program, e);
            }
        }
    }

    Err(format!(
        "Connection tracking is not available: {} does not exist and the conntrack tool could not be used ({}). Install it with 'apt install conntrack' and make sure the API runs as root.",
        CONNTRACK_FILE, last_error
    ))
}

/// Read the current and maximum size of the connection table.
pub fn read_usage() -> ConntrackUsage {
    ConntrackUsage {
        count: read_number(CONNTRACK_COUNT_FILE),
        max: read_number(CONNTRACK_MAX_FILE),
    }
}

fn read_number(path: &str) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Parses one line of connection tracking output.
///
/// Example TCP line:
///   ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.10.50 dst=1.1.1.1
///   sport=51234 dport=443 src=1.1.1.1 dst=192.168.0.50 sport=443
///   dport=51234 [ASSURED] mark=0 use=2
///
/// The first src/dst/sport/dport group is the original direction,
/// the second group is the reply direction.
fn parse_line(line: &str) -> Option<Connection> {
    let mut tokens = line.split_whitespace();

    let _family = tokens.next()?; // ipv4 / ipv6
    let _family_number = tokens.next()?;
    let protocol = tokens.next()?.to_string();
    let _protocol_number = tokens.next()?;
    let timeout_seconds: u64 = tokens.next()?.parse().ok()?;

    let mut conn = Connection {
        protocol,
        timeout_seconds,
        ..Default::default()
    };

    for token in tokens {
        if let Some((key, value)) = token.split_once('=') {
            match key {
                "src" => {
                    if conn.src.is_empty() {
                        conn.src = value.to_string();
                    } else {
                        conn.reply_src = value.to_string();
                    }
                }
                "dst" => {
                    if conn.dst.is_empty() {
                        conn.dst = value.to_string();
                    } else {
                        conn.reply_dst = value.to_string();
                    }
                }
                "sport" => {
                    if conn.sport.is_none() {
                        conn.sport = value.parse().ok();
                    } else {
                        conn.reply_sport = value.parse().ok();
                    }
                }
                "dport" => {
                    if conn.dport.is_none() {
                        conn.dport = value.parse().ok();
                    } else {
                        conn.reply_dport = value.parse().ok();
                    }
                }
                "bytes" => {
                    if conn.bytes_out.is_none() {
                        conn.bytes_out = value.parse().ok();
                    } else {
                        conn.bytes_in = value.parse().ok();
                    }
                }
                _ => {} // packets, mark, zone, use, id, type, code ...
            }
        } else if token == "[UNREPLIED]" {
            conn.unreplied = true;
        } else if token == "[ASSURED]" {
            conn.assured = true;
        } else if conn.state.is_none()
            && token.chars().all(|c| c.is_ascii_uppercase() || c == '_')
        {
            // TCP state words: ESTABLISHED, SYN_SENT, TIME_WAIT ...
            conn.state = Some(token.to_string());
        }
    }

    // A line without addresses is not a usable connection.
    if conn.src.is_empty() || conn.dst.is_empty() {
        return None;
    }

    Some(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nat_tcp_connection() {
        let line = "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.10.50 dst=1.1.1.1 sport=51234 dport=443 packets=10 bytes=1234 src=1.1.1.1 dst=192.168.0.99 sport=443 dport=51234 packets=12 bytes=5678 [ASSURED] mark=0 zone=0 use=2";

        let c = parse_line(line).expect("should parse");

        assert_eq!(c.protocol, "tcp");
        assert_eq!(c.state.as_deref(), Some("ESTABLISHED"));
        assert_eq!(c.timeout_seconds, 431999);
        assert_eq!(c.src, "192.168.10.50");
        assert_eq!(c.dst, "1.1.1.1");
        assert_eq!(c.sport, Some(51234));
        assert_eq!(c.dport, Some(443));
        // NAT: reply goes back to the WAN address, not the LAN client.
        assert_eq!(c.reply_dst, "192.168.0.99");
        assert_eq!(c.bytes_out, Some(1234));
        assert_eq!(c.bytes_in, Some(5678));
        assert!(c.assured);
        assert!(!c.unreplied);
    }

    #[test]
    fn parses_unreplied_udp_connection() {
        let line = "ipv4     2 udp      17 25 src=192.168.10.50 dst=8.8.8.8 sport=40000 dport=53 [UNREPLIED] src=8.8.8.8 dst=192.168.10.50 sport=53 dport=40000 mark=0 use=1";

        let c = parse_line(line).expect("should parse");

        assert_eq!(c.protocol, "udp");
        assert_eq!(c.state, None);
        assert!(c.unreplied);
        assert_eq!(c.bytes_out, None);
    }

    #[test]
    fn ignores_garbage_lines() {
        assert!(parse_line("").is_none());
        assert!(parse_line("hello world").is_none());
    }
}
