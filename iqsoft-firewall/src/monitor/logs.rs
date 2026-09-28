use serde::Serialize;
use serde_json::Value;
use std::process::Command;

/// Log lines written by the firewall start with "iqsoft-rule-<id>:".
const RULE_TAG: &str = "iqsoft-rule-";

/// How many matching kernel log lines to read before filtering further.
const MAX_LINES: &str = "5000";

/// One packet that a logging rule matched.
#[derive(Debug, Serialize, Clone, PartialEq, Default)]
pub struct LogEntry {
    /// Unix time in seconds (for example `date -d @1790612926`).
    pub time: i64,
    pub rule_id: i64,
    pub in_interface: String,
    pub out_interface: String,
    pub src: String,
    pub dst: String,
    /// TCP, UDP, ICMP ...
    pub protocol: String,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    pub length: Option<u32>,
    /// SYN means a new connection attempt.
    pub tcp_flags: Vec<String>,
}

/// Read the newest firewall log entries, newest first.
///
/// `rule_id` limits the result to one rule, `limit` caps the count.
pub fn read_logs(limit: usize, rule_id: Option<i64>) -> Result<Vec<LogEntry>, String> {
    // Some journalctl builds do not support --grep, so retry without it.
    let text = match run_journalctl(true) {
        Ok(text) => text,
        Err(_) => run_journalctl(false)?,
    };

    let entries = text
        .lines()
        .filter_map(parse_journal_line)
        .filter(|entry| rule_id.map_or(true, |id| entry.rule_id == id))
        .take(limit)
        .collect();

    Ok(entries)
}

fn run_journalctl(use_grep: bool) -> Result<String, String> {
    let mut args = vec!["-k", "-o", "json", "--no-pager", "-r", "-n", MAX_LINES];

    if use_grep {
        args.push("-g");
        args.push(RULE_TAG);
    }

    let mut last_error = String::from("journalctl not found");

    for program in ["/usr/bin/journalctl", "/bin/journalctl", "journalctl"] {
        match Command::new(program).args(&args).output() {
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
        "Could not read the kernel log ({}). Make sure the API runs as root.",
        last_error
    ))
}

/// Parses one JSON line from `journalctl -o json`.
fn parse_journal_line(line: &str) -> Option<LogEntry> {
    let value: Value = serde_json::from_str(line).ok()?;

    let message = value.get("MESSAGE")?.as_str()?;

    // journald stores the timestamp in microseconds, as a string.
    let micros: i64 = match value.get("__REALTIME_TIMESTAMP")? {
        Value::String(s) => s.parse().ok()?,
        Value::Number(n) => n.as_i64()?,
        _ => return None,
    };

    parse_message(message, micros / 1_000_000)
}

/// Parses the text of one kernel log message.
///
/// Example:
///   iqsoft-rule-15: IN=tailscale0 OUT= MAC= SRC=100.69.243.3
///   DST=100.80.192.57 LEN=60 ... PROTO=TCP SPT=62340 DPT=9999 ... SYN URGP=0
fn parse_message(message: &str, time: i64) -> Option<LogEntry> {
    let start = message.find(RULE_TAG)?;
    let rest = &message[start + RULE_TAG.len()..];

    let (id_text, fields) = rest.split_once(':')?;
    let rule_id: i64 = id_text.trim().parse().ok()?;

    let mut entry = LogEntry {
        time,
        rule_id,
        ..Default::default()
    };

    for token in fields.split_whitespace() {
        if let Some((key, value)) = token.split_once('=') {
            match key {
                "IN" => entry.in_interface = value.to_string(),
                "OUT" => entry.out_interface = value.to_string(),
                "SRC" => entry.src = value.to_string(),
                "DST" => entry.dst = value.to_string(),
                "PROTO" => entry.protocol = value.to_string(),
                "SPT" => entry.sport = value.parse().ok(),
                "DPT" => entry.dport = value.parse().ok(),
                "LEN" => entry.length = value.parse().ok(),
                _ => {} // MAC, TTL, ID, WINDOW, RES, URGP ...
            }
        } else if matches!(token, "SYN" | "ACK" | "FIN" | "RST" | "PSH" | "URG") {
            entry.tcp_flags.push(token.to_string());
        }
    }

    // A line with no addresses is not a usable entry.
    if entry.src.is_empty() && entry.dst.is_empty() {
        return None;
    }

    Some(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "iqsoft-rule-15: IN=tailscale0 OUT= MAC= SRC=100.69.243.3 DST=100.80.192.57 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=55295 DF PROTO=TCP SPT=62340 DPT=9999 WINDOW=64480 RES=0x00 SYN URGP=0";

    #[test]
    fn parses_a_real_log_message() {
        let e = parse_message(SAMPLE, 1790612926).expect("should parse");

        assert_eq!(e.time, 1790612926);
        assert_eq!(e.rule_id, 15);
        assert_eq!(e.in_interface, "tailscale0");
        assert_eq!(e.out_interface, "");
        assert_eq!(e.src, "100.69.243.3");
        assert_eq!(e.dst, "100.80.192.57");
        assert_eq!(e.protocol, "TCP");
        assert_eq!(e.sport, Some(62340));
        assert_eq!(e.dport, Some(9999));
        assert_eq!(e.length, Some(60));
        assert_eq!(e.tcp_flags, vec!["SYN".to_string()]);
    }

    #[test]
    fn parses_a_journal_json_line() {
        let line = format!(
            r#"{{"__REALTIME_TIMESTAMP":"1790612926000000","MESSAGE":"{}"}}"#,
            SAMPLE
        );

        let e = parse_journal_line(&line).expect("should parse");

        assert_eq!(e.time, 1790612926);
        assert_eq!(e.rule_id, 15);
        assert_eq!(e.dport, Some(9999));
    }

    #[test]
    fn ignores_other_kernel_messages() {
        assert!(parse_message("usb 1-1: new device found", 0).is_none());
        assert!(parse_message("iqsoft-rule-abc: SRC=1.1.1.1 DST=2.2.2.2", 0).is_none());
        assert!(parse_journal_line("not json").is_none());
    }
}
