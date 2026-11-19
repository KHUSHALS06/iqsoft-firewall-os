use serde::{Deserialize, Serialize};

pub const MAX_NAME_LEN: usize = 40;
pub const MAX_COMMENT_LEN: usize = 200;
pub const MAX_ERROR_LEN: usize = 300;

/// Most WAN links and most rules the feature accepts.
pub const MAX_LINKS: usize = 16;
pub const MAX_RULES: usize = 200;

pub const MIN_PRIORITY: i64 = 1;
pub const MAX_PRIORITY: i64 = 100;
pub const MIN_WEIGHT: i64 = 1;
pub const MAX_WEIGHT: i64 = 100;

pub const MIN_PROBE_INTERVAL_SECS: i64 = 1;
pub const MAX_PROBE_INTERVAL_SECS: i64 = 3600;
pub const MIN_PROBE_TIMEOUT_SECS: i64 = 1;
pub const MAX_PROBE_TIMEOUT_SECS: i64 = 30;
pub const MIN_THRESHOLD: i64 = 1;
pub const MAX_THRESHOLD: i64 = 20;

pub const PROTOCOLS: [&str; 4] = ["any", "tcp", "udp", "icmp"];
pub const STRATEGIES: [&str; 3] = ["link", "balance", "best_quality"];
pub const ON_LINK_DOWN: [&str; 2] = ["fallback", "block"];
pub const LINK_STATES: [&str; 3] = ["unknown", "up", "down"];

/// Packet marks used to steer traffic to a link.
///
/// SD-WAN owns bits 16-23 of the packet mark (0x00FF0000). The SNI filter uses
/// bit 26 (0x04000000), so the two never touch each other's bits.
///
/// Every link gets a "slot" number (1, 2, 3 ...) each time the configuration is
/// built. The slot decides its packet mark and its routing table number.
pub const MARK_MASK: u32 = 0x00FF_0000;
pub const MARK_SHIFT: u32 = 16;

/// Routing table number of slot N is TABLE_BASE + N (101, 102, ...).
/// Tables 253, 254 and 255 are used by Linux itself, so the slots stay far below them.
pub const TABLE_BASE: u32 = 100;

pub fn link_mark(slot: u32) -> u32 {
    slot << MARK_SHIFT
}

pub fn link_table(slot: u32) -> u32 {
    TABLE_BASE + slot
}

fn default_true() -> bool {
    true
}

fn default_priority() -> i64 {
    10
}

fn default_weight() -> i64 {
    1
}

fn default_probe_target() -> String {
    "1.1.1.1".to_string()
}

fn default_probe_interval() -> i64 {
    5
}

fn default_probe_timeout() -> i64 {
    2
}

fn default_fail_threshold() -> i64 {
    3
}

fn default_recover_threshold() -> i64 {
    2
}

fn default_state() -> String {
    "unknown".to_string()
}

fn default_position() -> i64 {
    100
}

fn default_protocol() -> String {
    "any".to_string()
}

fn default_strategy() -> String {
    "link".to_string()
}

fn default_on_link_down() -> String {
    "fallback".to_string()
}

/// The master switch. While it is off, SD-WAN changes nothing on the box.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SdwanSettings {
    pub enabled: bool,
}

/// One WAN uplink. The fields from `state` down are filled in by the server
/// (the probe task); whatever a client sends for them is ignored.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SdwanLink {
    pub id: Option<i64>,
    pub name: String,
    pub interface_name: String,
    pub gateway: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_priority")]
    pub priority: i64,
    #[serde(default = "default_weight")]
    pub weight: i64,
    #[serde(default = "default_probe_target")]
    pub probe_target: String,
    #[serde(default = "default_probe_interval")]
    pub probe_interval_secs: i64,
    #[serde(default = "default_probe_timeout")]
    pub probe_timeout_secs: i64,
    #[serde(default = "default_fail_threshold")]
    pub fail_threshold: i64,
    #[serde(default = "default_recover_threshold")]
    pub recover_threshold: i64,
    pub comment: Option<String>,

    #[serde(default = "default_state")]
    pub state: String,
    #[serde(default)]
    pub latency_ms: Option<f64>,
    #[serde(default)]
    pub loss_pct: Option<i64>,
    #[serde(default)]
    pub last_check: Option<i64>,
    #[serde(default)]
    pub last_change: Option<i64>,
    #[serde(default)]
    pub last_error: Option<String>,
}

impl SdwanLink {
    /// A link takes traffic unless the probe has marked it down.
    /// "unknown" (not probed yet) counts as usable so a fresh commit is not blocked.
    pub fn is_usable(&self) -> bool {
        self.enabled && self.state != "down"
    }
}

/// Live health of one link, as the probe task records it.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SdwanLinkStatus {
    pub link_id: i64,
    pub state: String,
    pub latency_ms: Option<f64>,
    pub loss_pct: Option<i64>,
    pub consecutive_fail: i64,
    pub consecutive_ok: i64,
    pub last_check: Option<i64>,
    pub last_change: Option<i64>,
    pub last_error: Option<String>,
}

/// A per-traffic rule. A missing source, destination or port means "any".
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SdwanRule {
    pub id: Option<i64>,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_position")]
    pub position: i64,
    pub src_cidr: Option<String>,
    pub dst_cidr: Option<String>,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    pub dport_start: Option<i64>,
    pub dport_end: Option<i64>,
    #[serde(default = "default_strategy")]
    pub strategy: String,
    pub link_id: Option<i64>,
    #[serde(default = "default_on_link_down")]
    pub on_link_down: String,
    pub comment: Option<String>,
}

impl SdwanRule {
    pub fn has_ports(&self) -> bool {
        self.dport_start.is_some() && self.dport_end.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_with_only_a_name_and_interface_gets_the_defaults() {
        let link: SdwanLink =
            serde_json::from_str(r#"{"name":"ISP1","interface_name":"enp3s0"}"#).unwrap();

        assert_eq!(link.id, None);
        assert_eq!(link.gateway, None);
        assert!(link.enabled);
        assert_eq!(link.priority, 10);
        assert_eq!(link.weight, 1);
        assert_eq!(link.probe_target, "1.1.1.1");
        assert_eq!(link.probe_interval_secs, 5);
        assert_eq!(link.probe_timeout_secs, 2);
        assert_eq!(link.fail_threshold, 3);
        assert_eq!(link.recover_threshold, 2);
        assert_eq!(link.state, "unknown");
        assert_eq!(link.latency_ms, None);
    }

    #[test]
    fn a_link_is_usable_unless_disabled_or_down() {
        let mut link: SdwanLink =
            serde_json::from_str(r#"{"name":"ISP1","interface_name":"enp3s0"}"#).unwrap();

        assert!(link.is_usable());

        link.state = "up".into();
        assert!(link.is_usable());

        link.state = "down".into();
        assert!(!link.is_usable());

        link.state = "up".into();
        link.enabled = false;
        assert!(!link.is_usable());
    }

    #[test]
    fn a_rule_with_only_a_name_gets_the_defaults() {
        let rule: SdwanRule = serde_json::from_str(r#"{"name":"voice"}"#).unwrap();

        assert!(rule.enabled);
        assert_eq!(rule.position, 100);
        assert_eq!(rule.protocol, "any");
        assert_eq!(rule.strategy, "link");
        assert_eq!(rule.on_link_down, "fallback");
        assert_eq!(rule.src_cidr, None);
        assert_eq!(rule.link_id, None);
        assert!(!rule.has_ports());
    }

    #[test]
    fn a_rule_has_ports_only_when_both_ends_are_set() {
        let mut rule: SdwanRule = serde_json::from_str(r#"{"name":"web"}"#).unwrap();

        rule.dport_start = Some(80);
        assert!(!rule.has_ports());

        rule.dport_end = Some(443);
        assert!(rule.has_ports());
    }

    #[test]
    fn marks_and_tables_follow_the_slot_number() {
        assert_eq!(link_mark(1), 0x0001_0000);
        assert_eq!(link_mark(2), 0x0002_0000);
        assert_eq!(link_mark(16), 0x0010_0000);
        assert_eq!(link_table(1), 101);
        assert_eq!(link_table(16), 116);
    }

    #[test]
    fn marks_stay_inside_the_mask_and_away_from_the_sni_bit() {
        const SNI_BIT: u32 = 0x0400_0000;

        for slot in 1..=MAX_LINKS as u32 {
            assert_eq!(link_mark(slot) & !MARK_MASK, 0, "slot {}", slot);
            assert_eq!(link_mark(slot) & SNI_BIT, 0, "slot {}", slot);
            assert!(link_table(slot) < 253, "slot {}", slot);
        }

        assert_eq!(MARK_MASK & SNI_BIT, 0);
    }

    #[test]
    fn the_allowed_words_match_the_database_checks() {
        assert_eq!(PROTOCOLS, ["any", "tcp", "udp", "icmp"]);
        assert_eq!(STRATEGIES, ["link", "balance", "best_quality"]);
        assert_eq!(ON_LINK_DOWN, ["fallback", "block"]);
        assert_eq!(LINK_STATES, ["unknown", "up", "down"]);
    }
}
