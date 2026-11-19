//! Reads Suricata's `eve.json` log and turns alert lines into `IdsEvent`s.
//!
//! Suricata appends one JSON object per line. We only care about the lines
//! with `"event_type": "alert"`. The reader remembers how far it has read and
//! copes with the file being rotated, truncated or not existing yet.

use crate::models::ids::IdsEvent;
use serde_json::Value;
use std::{
    io::SeekFrom,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt},
};

/// A single line longer than this is skipped (a healthy alert line is well under 2 KB).
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// The most bytes read from the file in one call, so a huge backlog is worked off in pieces.
pub const MAX_READ_BYTES: u64 = 8 * 1024 * 1024;

// ---------- timestamps ----------

/// Days between 1970-01-01 and the given date (proleptic Gregorian calendar).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;

    era * 146_097 + doe - 719_468
}

fn digits(bytes: &[u8], from: usize, count: usize) -> Option<i64> {
    let part = bytes.get(from..from + count)?;

    if !part.iter().all(u8::is_ascii_digit) {
        return None;
    }

    let mut value = 0i64;
    for b in part {
        value = value * 10 + i64::from(b - b'0');
    }

    Some(value)
}

/// Parses Suricata's timestamp, for example `2026-11-19T10:15:30.123456+0530`,
/// into Unix seconds. A trailing `Z`, `+hhmm` and `+hh:mm` are all accepted.
pub fn parse_timestamp(text: &str) -> Option<i64> {
    let b = text.trim().as_bytes();

    let year = digits(b, 0, 4)?;

    if *b.get(4)? != b'-' {
        return None;
    }
    let month = digits(b, 5, 2)?;

    if *b.get(7)? != b'-' {
        return None;
    }
    let day = digits(b, 8, 2)?;

    if !matches!(b.get(10)?, b'T' | b' ') {
        return None;
    }
    let hour = digits(b, 11, 2)?;

    if *b.get(13)? != b':' {
        return None;
    }
    let minute = digits(b, 14, 2)?;

    if *b.get(16)? != b':' {
        return None;
    }
    let second = digits(b, 17, 2)?;

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }

    let mut pos = 19;

    if b.get(pos) == Some(&b'.') {
        pos += 1;
        while b.get(pos).is_some_and(u8::is_ascii_digit) {
            pos += 1;
        }
    }

    let offset_seconds = match b.get(pos) {
        None | Some(b'Z') => 0,
        Some(sign @ (b'+' | b'-')) => {
            let hours = digits(b, pos + 1, 2)?;

            let minutes_at = if b.get(pos + 3) == Some(&b':') {
                pos + 4
            } else {
                pos + 3
            };
            let minutes = digits(b, minutes_at, 2)?;

            if hours > 23 || minutes > 59 {
                return None;
            }

            let total = hours * 3600 + minutes * 60;

            if *sign == b'-' {
                -total
            } else {
                total
            }
        }
        Some(_) => return None,
    };

    let days = days_from_civil(year, month, day);

    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset_seconds)
}

// ---------- one line ----------

fn text(value: &Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(str::to_string)
}

fn port(value: &Value, key: &str) -> Option<i64> {
    value.get(key)?.as_i64()
}

/// Turns one `eve.json` line into an event. Returns `None` for anything that is
/// not a complete alert (other event types, broken JSON, missing fields).
pub fn parse_line(line: &str) -> Option<IdsEvent> {
    let line = line.trim();

    if line.is_empty() {
        return None;
    }

    let root: Value = serde_json::from_str(line).ok()?;

    if root.get("event_type")?.as_str()? != "alert" {
        return None;
    }

    let alert = root.get("alert")?;

    let sid = alert.get("signature_id")?.as_i64()?;
    let signature = text(alert, "signature")?;

    let action = match alert.get("action").and_then(Value::as_str) {
        Some("blocked") => "blocked",
        _ => "allowed",
    };

    Some(IdsEvent {
        id: None,
        ts: root
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(parse_timestamp)
            .unwrap_or(0),
        src_ip: text(&root, "src_ip")?,
        src_port: port(&root, "src_port"),
        dest_ip: text(&root, "dest_ip")?,
        dest_port: port(&root, "dest_port"),
        proto: text(&root, "proto").unwrap_or_default(),
        app_proto: text(&root, "app_proto"),
        sid,
        signature,
        category: text(alert, "category"),
        severity: alert.get("severity").and_then(Value::as_i64).unwrap_or(3),
        action: action.to_string(),
    })
}

// ---------- following the file ----------

pub struct EveTailer {
    path: PathBuf,
    offset: u64,
    inode: Option<u64>,
    known: bool,
    from_start: bool,
    pending: Vec<u8>,
}

impl EveTailer {
    /// Starts at the end of the file, so alerts that are already in the log
    /// are not counted a second time after a restart of the firewall.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            offset: 0,
            inode: None,
            known: false,
            from_start: false,
            pending: Vec::new(),
        }
    }

    /// Starts at the beginning of the file, so everything already in it is read.
    #[allow(dead_code)]
    pub fn from_start(path: impl Into<PathBuf>) -> Self {
        let mut tailer = Self::new(path);
        tailer.from_start = true;
        tailer
    }

    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn forget_file(&mut self) {
        self.offset = 0;
        self.inode = None;
        self.known = false;
        self.pending.clear();
        // A file that shows up later is a new log, so it is read from its first line.
        self.from_start = true;
    }

    /// Returns the alerts written since the last call.
    pub async fn read_new(&mut self) -> Result<Vec<IdsEvent>, String> {
        let meta = match tokio::fs::metadata(&self.path).await {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.forget_file();
                return Ok(Vec::new());
            }
            Err(e) => {
                return Err(format!("could not look at {}: {}", self.path.display(), e));
            }
        };

        let inode = meta.ino();
        let size = meta.len();

        if !self.known {
            self.known = true;
            self.inode = Some(inode);
            self.offset = if self.from_start { 0 } else { size };
            self.pending.clear();
        } else if self.inode != Some(inode) || size < self.offset {
            // Rotated (new file) or truncated: start again from the top.
            self.inode = Some(inode);
            self.offset = 0;
            self.pending.clear();
        }

        if size <= self.offset {
            return Ok(Vec::new());
        }

        let want = (size - self.offset).min(MAX_READ_BYTES);

        let mut file = File::open(&self.path)
            .await
            .map_err(|e| format!("could not open {}: {}", self.path.display(), e))?;

        file.seek(SeekFrom::Start(self.offset))
            .await
            .map_err(|e| format!("could not read {}: {}", self.path.display(), e))?;

        let mut buffer = Vec::with_capacity(want as usize);

        file.take(want)
            .read_to_end(&mut buffer)
            .await
            .map_err(|e| format!("could not read {}: {}", self.path.display(), e))?;

        self.offset += buffer.len() as u64;
        self.pending.extend_from_slice(&buffer);

        let mut events = Vec::new();
        let mut start = 0usize;

        while let Some(found) = self.pending[start..].iter().position(|b| *b == b'\n') {
            let end = start + found;
            let line = &self.pending[start..end];

            if line.len() <= MAX_LINE_BYTES {
                if let Some(event) = parse_line(&String::from_utf8_lossy(line)) {
                    events.push(event);
                }
            }

            start = end + 1;
        }

        self.pending.drain(..start);

        // A line that is still unfinished is kept for the next call, unless it is absurdly long.
        if self.pending.len() > MAX_LINE_BYTES {
            self.pending.clear();
        }

        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        sync::atomic::{AtomicU64, Ordering},
    };

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_path() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);

        std::env::temp_dir().join(format!("iqsoft-eve-test-{}-{}.json", std::process::id(), n))
    }

    fn alert_line(sid: i64, action: &str) -> String {
        format!(
            "{{\"timestamp\":\"2026-11-19T10:15:30.123456+0000\",\"event_type\":\"alert\",\
             \"src_ip\":\"10.0.0.5\",\"src_port\":51000,\"dest_ip\":\"203.0.113.9\",\
             \"dest_port\":80,\"proto\":\"TCP\",\"app_proto\":\"http\",\
             \"alert\":{{\"action\":\"{}\",\"gid\":1,\"signature_id\":{},\"rev\":1,\
             \"signature\":\"Test signature {}\",\"category\":\"Potentially Bad Traffic\",\
             \"severity\":2}}}}\n",
            action, sid, sid
        )
    }

    fn append(path: &Path, text: &str) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();

        file.write_all(text.as_bytes()).unwrap();
    }

    #[test]
    fn timestamps_are_converted_to_unix_seconds() {
        assert_eq!(parse_timestamp("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_timestamp("2000-01-01T00:00:00.000000+0000"), Some(946_684_800));
        assert_eq!(parse_timestamp("2024-03-01T00:00:00+0000"), Some(1_709_251_200));
    }

    #[test]
    fn timestamp_offsets_are_applied() {
        assert_eq!(parse_timestamp("2024-02-29T12:00:00+0530"), Some(1_709_188_200));
        assert_eq!(parse_timestamp("2024-02-29T12:00:00+05:30"), Some(1_709_188_200));
        assert_eq!(parse_timestamp("2024-02-29T12:00:00-0100"), Some(1_709_211_600));
    }

    #[test]
    fn bad_timestamps_are_refused() {
        assert_eq!(parse_timestamp(""), None);
        assert_eq!(parse_timestamp("yesterday"), None);
        assert_eq!(parse_timestamp("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_timestamp("2026-11-19T25:00:00Z"), None);
        assert_eq!(parse_timestamp("2026-11-19T10:15:30*0000"), None);
    }

    #[test]
    fn an_alert_line_becomes_an_event() {
        let event = parse_line(&alert_line(2_100_498, "allowed")).unwrap();

        assert_eq!(event.ts, parse_timestamp("2026-11-19T10:15:30+0000").unwrap());
        assert_eq!(event.src_ip, "10.0.0.5");
        assert_eq!(event.src_port, Some(51_000));
        assert_eq!(event.dest_ip, "203.0.113.9");
        assert_eq!(event.dest_port, Some(80));
        assert_eq!(event.proto, "TCP");
        assert_eq!(event.app_proto.as_deref(), Some("http"));
        assert_eq!(event.sid, 2_100_498);
        assert_eq!(event.signature, "Test signature 2100498");
        assert_eq!(event.category.as_deref(), Some("Potentially Bad Traffic"));
        assert_eq!(event.severity, 2);
        assert_eq!(event.action, "allowed");
        assert_eq!(event.id, None);
    }

    #[test]
    fn dropped_packets_are_marked_blocked() {
        assert_eq!(parse_line(&alert_line(1, "blocked")).unwrap().action, "blocked");
        assert_eq!(parse_line(&alert_line(1, "allowed")).unwrap().action, "allowed");
    }

    #[test]
    fn an_alert_without_ports_or_app_protocol_still_parses() {
        let line = "{\"timestamp\":\"2026-11-19T10:15:30+0000\",\"event_type\":\"alert\",\
                    \"src_ip\":\"10.0.0.5\",\"dest_ip\":\"8.8.8.8\",\"proto\":\"ICMP\",\
                    \"alert\":{\"signature_id\":7,\"signature\":\"ICMP test\",\"severity\":3}}";

        let event = parse_line(line).unwrap();

        assert_eq!(event.src_port, None);
        assert_eq!(event.dest_port, None);
        assert_eq!(event.app_proto, None);
        assert_eq!(event.category, None);
        assert_eq!(event.action, "allowed");
    }

    #[test]
    fn other_lines_are_ignored() {
        assert!(parse_line("").is_none());
        assert!(parse_line("not json at all").is_none());
        assert!(parse_line("{\"event_type\":\"dns\",\"src_ip\":\"1.1.1.1\"}").is_none());
        assert!(parse_line("{\"event_type\":\"alert\",\"src_ip\":\"1.1.1.1\",\"dest_ip\":\"2.2.2.2\"}").is_none());
        assert!(parse_line(
            "{\"event_type\":\"alert\",\"src_ip\":\"1.1.1.1\",\"dest_ip\":\"2.2.2.2\",\
             \"alert\":{\"signature\":\"no sid\"}}"
        )
        .is_none());
    }

    #[tokio::test]
    async fn a_new_tailer_skips_what_is_already_in_the_file() {
        let path = temp_path();
        append(&path, &alert_line(1, "allowed"));

        let mut tailer = EveTailer::new(&path);
        assert!(tailer.read_new().await.unwrap().is_empty());

        append(&path, &alert_line(2, "blocked"));

        let events = tailer.read_new().await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sid, 2);

        assert!(tailer.read_new().await.unwrap().is_empty());

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn from_start_reads_the_existing_lines() {
        let path = temp_path();
        append(&path, &alert_line(1, "allowed"));
        append(&path, &alert_line(2, "allowed"));

        let mut tailer = EveTailer::from_start(&path);
        let events = tailer.read_new().await.unwrap();

        assert_eq!(events.iter().map(|e| e.sid).collect::<Vec<_>>(), vec![1, 2]);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn an_unfinished_line_waits_for_its_end() {
        let path = temp_path();
        append(&path, "");

        let mut tailer = EveTailer::new(&path);
        assert!(tailer.read_new().await.unwrap().is_empty());

        let line = alert_line(5, "allowed");
        let (first, second) = line.split_at(40);

        append(&path, first);
        assert!(tailer.read_new().await.unwrap().is_empty());

        append(&path, second);
        let events = tailer.read_new().await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sid, 5);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn a_truncated_file_is_read_again_from_the_top() {
        let path = temp_path();
        append(&path, &alert_line(1, "allowed"));
        append(&path, &alert_line(2, "allowed"));

        let mut tailer = EveTailer::new(&path);
        assert!(tailer.read_new().await.unwrap().is_empty());

        std::fs::write(&path, alert_line(3, "blocked")).unwrap();

        let events = tailer.read_new().await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sid, 3);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn a_file_that_appears_later_is_read_from_its_first_line() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);

        let mut tailer = EveTailer::new(&path);
        assert!(tailer.read_new().await.unwrap().is_empty());

        append(&path, &alert_line(9, "allowed"));

        let events = tailer.read_new().await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sid, 9);

        let _ = std::fs::remove_file(&path);
    }
}
