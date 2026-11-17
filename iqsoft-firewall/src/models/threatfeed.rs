use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::IpAddr;

pub const MAX_NAME_LEN: usize = 60;
pub const MAX_URL_LEN: usize = 500;
pub const MAX_COMMENT_LEN: usize = 200;
pub const MAX_ERROR_LEN: usize = 300;

/// Most networks one feed may hold. A bigger list is refused, never silently cut.
pub const MAX_FEED_ENTRIES: usize = 300_000;
pub const MAX_FEED_LINES: usize = 1_000_000;
pub const MAX_DOWNLOAD_BYTES: usize = 24 * 1024 * 1024;

pub const MIN_REFRESH_HOURS: i64 = 1;
pub const MAX_REFRESH_HOURS: i64 = 720;
pub const DEFAULT_REFRESH_HOURS: i64 = 6;

/// Narrower than these is fine, wider is skipped. A feed that lists a /4 is broken or hostile.
const MIN_V4_PREFIX: u8 = 8;
const MIN_V6_PREFIX: u8 = 16;

const PROTECTED_RANGES: [&str; 14] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/8",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
    "2001:db8::/32",
];

fn default_true() -> bool {
    true
}

fn default_kind() -> String {
    "url".to_string()
}

fn default_direction() -> String {
    "both".to_string()
}

fn default_refresh_hours() -> i64 {
    DEFAULT_REFRESH_HOURS
}

/// One blocklist. `kind` is "url" (downloaded on a schedule) or "manual" (filled by IOC import).
/// The status fields at the bottom are filled in by the server; whatever a client sends for them is ignored.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ThreatFeed {
    pub id: Option<i64>,
    pub name: String,
    #[serde(default = "default_kind")]
    pub kind: String,
    pub url: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_direction")]
    pub direction: String,
    #[serde(default = "default_refresh_hours")]
    pub refresh_hours: i64,
    #[serde(default)]
    pub log_enabled: bool,
    pub comment: Option<String>,

    #[serde(default)]
    pub last_updated: Option<i64>,
    #[serde(default)]
    pub last_attempt: Option<i64>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub ipv4_count: i64,
    #[serde(default)]
    pub ipv6_count: i64,
}

impl ThreatFeed {
    pub fn blocks_inbound(&self) -> bool {
        self.direction == "inbound" || self.direction == "both"
    }

    pub fn blocks_outbound(&self) -> bool {
        self.direction == "outbound" || self.direction == "both"
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ThreatImportRequest {
    pub data: String,
    /// "append" (default) adds to the feed, "replace" throws the old list away first.
    pub mode: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ThreatImportResult {
    pub feed_id: i64,
    pub ipv4_imported: usize,
    pub ipv6_imported: usize,
    pub skipped: usize,
    pub ipv4_total: i64,
    pub ipv6_total: i64,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct ThreatRefreshResult {
    pub feed_id: i64,
    pub ipv4_imported: usize,
    pub ipv6_imported: usize,
    pub skipped: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedFeed {
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub skipped: usize,
}

#[derive(Debug, Serialize, Clone, Copy)]
pub struct FeedPreset {
    pub id: &'static str,
    pub name: &'static str,
    pub url: &'static str,
    pub description: &'static str,
    pub refresh_hours: i64,
}

pub const PRESETS: [FeedPreset; 6] = [
    FeedPreset {
        id: "spamhaus-drop-v4",
        name: "Spamhaus DROP (IPv4)",
        url: "https://www.spamhaus.org/drop/drop_v4.json",
        description: "Hijacked and criminal-controlled IPv4 networks. Spamhaus asks for at most one download per hour.",
        refresh_hours: 24,
    },
    FeedPreset {
        id: "spamhaus-drop-v6",
        name: "Spamhaus DROP (IPv6)",
        url: "https://www.spamhaus.org/drop/drop_v6.json",
        description: "The IPv6 part of the Spamhaus DROP list.",
        refresh_hours: 24,
    },
    FeedPreset {
        id: "feodo-tracker",
        name: "abuse.ch Feodo Tracker",
        url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        description: "Botnet command-and-control servers (Emotet, Dridex, TrickBot and similar).",
        refresh_hours: 6,
    },
    FeedPreset {
        id: "emerging-threats-block",
        name: "Emerging Threats block IPs",
        url: "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        description: "Proofpoint's list of known hostile addresses, including the Spamhaus DROP networks.",
        refresh_hours: 12,
    },
    FeedPreset {
        id: "firehol-level1",
        name: "FireHOL level 1",
        url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        description: "Conservative aggregate of several attack and malware lists, built to cause very few false positives.",
        refresh_hours: 12,
    },
    FeedPreset {
        id: "blocklist-de",
        name: "blocklist.de (all attackers)",
        url: "https://lists.blocklist.de/lists/all.txt",
        description: "Addresses reported for SSH, mail, web and other attacks in the last 48 hours. Large and fast-changing.",
        refresh_hours: 6,
    },
];

pub fn normalize_kind(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "url" => Some("url"),
        "manual" => Some("manual"),
        _ => None,
    }
}

pub fn normalize_direction(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "inbound" => Some("inbound"),
        "outbound" => Some("outbound"),
        "both" => Some("both"),
        _ => None,
    }
}

pub fn normalize_import_mode(value: &Option<String>) -> Option<&'static str> {
    match value.as_deref().map(|v| v.trim().to_ascii_lowercase()) {
        None => Some("append"),
        Some(v) if v.is_empty() || v == "append" => Some("append"),
        Some(v) if v == "replace" => Some("replace"),
        _ => None,
    }
}

pub fn validate_name(value: &str) -> Result<String, String> {
    let name = value.trim();

    if name.is_empty() || name.chars().count() > MAX_NAME_LEN {
        return Err(format!(
            "Feed name must be 1-{} characters",
            MAX_NAME_LEN
        ));
    }

    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | '(' | ')'))
    {
        return Err(
            "Feed name can only contain letters, numbers, spaces and - _ . ( )".to_string(),
        );
    }

    Ok(name.to_string())
}

pub fn validate_refresh_hours(value: i64) -> Result<i64, String> {
    if !(MIN_REFRESH_HOURS..=MAX_REFRESH_HOURS).contains(&value) {
        return Err(format!(
            "Refresh interval must be between {} and {} hours",
            MIN_REFRESH_HOURS, MAX_REFRESH_HOURS
        ));
    }

    Ok(value)
}

pub fn validate_comment(value: &Option<String>) -> Result<Option<String>, String> {
    let Some(text) = value else {
        return Ok(None);
    };

    let text = text.trim();

    if text.is_empty() {
        return Ok(None);
    }

    if text.chars().count() > MAX_COMMENT_LEN {
        return Err(format!(
            "Comment cannot be longer than {} characters",
            MAX_COMMENT_LEN
        ));
    }

    if text.chars().any(|c| c.is_control()) {
        return Err("Comment cannot contain control characters".into());
    }

    Ok(Some(text.to_string()))
}

/// Only plain http(s) addresses of public hosts, without a user name or password in them.
/// The appliance downloads these itself, so a feed must not be able to aim it at the appliance's own
/// management port or at the LAN.
pub fn validate_url(value: &str) -> Result<String, String> {
    let text = value.trim();

    if text.is_empty() || text.chars().count() > MAX_URL_LEN {
        return Err(format!("URL must be 1-{} characters", MAX_URL_LEN));
    }

    if text.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("URL cannot contain spaces or control characters".into());
    }

    let parsed = reqwest::Url::parse(text).map_err(|_| "URL is not valid".to_string())?;

    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err("URL must start with http:// or https://".into());
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("URL cannot contain a user name or password".into());
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "URL has no host name".to_string())?
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();

    if host == "localhost" || host.ends_with(".localhost") || host.ends_with(".local") {
        return Err("URL must point to a public host".into());
    }

    if let Ok(addr) = host.parse::<IpAddr>() {
        let protected = protected_networks();
        if touches_protected_space(&IpNet::from(addr), &protected) {
            return Err("URL must point to a public host".into());
        }
    }

    Ok(parsed.to_string())
}

fn protected_networks() -> Vec<IpNet> {
    PROTECTED_RANGES
        .iter()
        .filter_map(|range| range.parse::<IpNet>().ok())
        .collect()
}

fn touches_protected_space(net: &IpNet, protected: &[IpNet]) -> bool {
    protected
        .iter()
        .any(|range| range.contains(net) || net.contains(range))
}

fn parse_network(token: &str) -> Option<IpNet> {
    if let Ok(net) = token.parse::<IpNet>() {
        return Some(net.trunc());
    }

    token.parse::<IpAddr>().ok().map(IpNet::from)
}

/// What to read from one line. `None` means "nothing here" (blank, comment, JSON without an address),
/// `Some(Err(()))` means "there was something, but it is not usable".
fn line_token(raw: &str) -> Option<Result<String, ()>> {
    let line = raw.trim();

    if line.is_empty()
        || line.starts_with('#')
        || line.starts_with(';')
        || line.starts_with("//")
    {
        return None;
    }

    if line.starts_with('{') {
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => return Some(Err(())),
        };

        let field = value
            .get("cidr")
            .or_else(|| value.get("ip"))
            .and_then(|v| v.as_str());

        return match field {
            Some(text) => Some(Ok(text.trim().to_string())),
            None => None,
        };
    }

    let token = line
        .split(|c: char| c.is_whitespace() || matches!(c, ';' | ',' | '#'))
        .next()
        .unwrap_or("")
        .trim_matches('"');

    if token.is_empty() {
        return Some(Err(()));
    }

    Some(Ok(token.to_string()))
}

/// Reads a blocklist in any of the usual shapes: one address or network per line, with `#` or `;`
/// comments after it, Spamhaus-style JSON lines, or the first column of a CSV.
///
/// Anything that is not a clean public IP network is skipped and counted, so a poisoned list can never
/// write something odd into the ruleset or block the appliance's own networks.
pub fn parse_feed_text(text: &str) -> Result<ParsedFeed, String> {
    if text.lines().count() > MAX_FEED_LINES {
        return Err(format!(
            "A feed cannot have more than {} lines",
            MAX_FEED_LINES
        ));
    }

    let protected = protected_networks();
    let mut v4: BTreeSet<IpNet> = BTreeSet::new();
    let mut v6: BTreeSet<IpNet> = BTreeSet::new();
    let mut skipped = 0usize;

    for raw in text.lines() {
        let token = match line_token(raw) {
            None => continue,
            Some(Err(())) => {
                skipped += 1;
                continue;
            }
            Some(Ok(token)) => token,
        };

        let net = match parse_network(&token) {
            Some(net) => net,
            None => {
                skipped += 1;
                continue;
            }
        };

        let too_wide = match net {
            IpNet::V4(_) => net.prefix_len() < MIN_V4_PREFIX,
            IpNet::V6(_) => net.prefix_len() < MIN_V6_PREFIX,
        };

        if too_wide || touches_protected_space(&net, &protected) {
            skipped += 1;
            continue;
        }

        match net {
            IpNet::V4(_) => {
                v4.insert(net);
            }
            IpNet::V6(_) => {
                v6.insert(net);
            }
        }
    }

    if v4.is_empty() && v6.is_empty() {
        return Err("No valid public IP addresses or networks found in the list".into());
    }

    if v4.len() + v6.len() > MAX_FEED_ENTRIES {
        return Err(format!(
            "The list has more than {} networks, which is more than one feed may hold",
            MAX_FEED_ENTRIES
        ));
    }

    Ok(ParsedFeed {
        ipv4: v4.iter().map(|net| net.to_string()).collect(),
        ipv6: v6.iter().map(|net| net.to_string()).collect(),
        skipped,
    })
}

pub fn clip_error(value: &str) -> String {
    let flat: String = value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();

    flat.trim().chars().take(MAX_ERROR_LEN).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_and_directions_are_normalized_or_refused() {
        assert_eq!(normalize_kind(" URL "), Some("url"));
        assert_eq!(normalize_kind("Manual"), Some("manual"));
        assert_eq!(normalize_kind("ftp"), None);

        assert_eq!(normalize_direction("Inbound"), Some("inbound"));
        assert_eq!(normalize_direction(" both "), Some("both"));
        assert_eq!(normalize_direction("sideways"), None);
    }

    #[test]
    fn import_mode_defaults_to_append() {
        assert_eq!(normalize_import_mode(&None), Some("append"));
        assert_eq!(normalize_import_mode(&Some("".into())), Some("append"));
        assert_eq!(normalize_import_mode(&Some("APPEND".into())), Some("append"));
        assert_eq!(normalize_import_mode(&Some(" replace ".into())), Some("replace"));
        assert_eq!(normalize_import_mode(&Some("merge".into())), None);
    }

    #[test]
    fn names_are_checked() {
        assert_eq!(validate_name("  Spamhaus DROP (v4) ").unwrap(), "Spamhaus DROP (v4)");
        assert!(validate_name("").is_err());
        assert!(validate_name("   ").is_err());
        assert!(validate_name(&"x".repeat(MAX_NAME_LEN + 1)).is_err());
        assert!(validate_name("bad;name").is_err());
        assert!(validate_name("bad\nname").is_err());
        assert!(validate_name("quote\"d").is_err());
    }

    #[test]
    fn refresh_interval_is_bounded() {
        assert!(validate_refresh_hours(0).is_err());
        assert!(validate_refresh_hours(1).is_ok());
        assert!(validate_refresh_hours(720).is_ok());
        assert!(validate_refresh_hours(721).is_err());
        assert!(validate_refresh_hours(-5).is_err());
    }

    #[test]
    fn comments_are_trimmed_and_checked() {
        assert_eq!(validate_comment(&None).unwrap(), None);
        assert_eq!(validate_comment(&Some("  ".into())).unwrap(), None);
        assert_eq!(
            validate_comment(&Some(" from the SOC ".into())).unwrap(),
            Some("from the SOC".to_string())
        );
        assert!(validate_comment(&Some("x".repeat(MAX_COMMENT_LEN + 1))).is_err());
        assert!(validate_comment(&Some("a\nb".into())).is_err());
    }

    #[test]
    fn urls_must_be_plain_public_http() {
        assert!(validate_url("https://feodotracker.abuse.ch/downloads/ipblocklist.txt").is_ok());
        assert!(validate_url("http://lists.blocklist.de/lists/all.txt").is_ok());
        assert!(validate_url("https://8.8.8.8/list.txt").is_ok());

        for bad in [
            "",
            "   ",
            "ftp://example.com/list.txt",
            "file:///etc/passwd",
            "example.com/list.txt",
            "https://user:pass@example.com/list.txt",
            "https://user@example.com/list.txt",
            "https://localhost/list.txt",
            "https://printer.local/list.txt",
            "http://127.0.0.1:3000/api/rules",
            "http://10.0.0.5/list.txt",
            "http://192.168.1.1/list.txt",
            "http://169.254.169.254/latest/meta-data",
            "http://[::1]/list.txt",
            "https://example.com/a b",
        ] {
            assert!(validate_url(bad).is_err(), "accepted {:?}", bad);
        }

        assert!(validate_url(&format!("https://example.com/{}", "a".repeat(MAX_URL_LEN))).is_err());
    }

    #[test]
    fn a_plain_list_is_split_by_family_sorted_and_deduplicated() {
        let parsed = parse_feed_text("8.8.8.8\n1.2.3.4\n1.2.3.4\n2001:4860::1\n").unwrap();
        assert_eq!(parsed.ipv4, vec!["1.2.3.4/32", "8.8.8.8/32"]);
        assert_eq!(parsed.ipv6, vec!["2001:4860::1/128"]);
        assert_eq!(parsed.skipped, 0);
    }

    #[test]
    fn comments_blank_lines_and_trailing_notes_are_fine() {
        let parsed = parse_feed_text(
            "# Feodo\r\n; spamhaus style\r\n// other\r\n\r\n1.10.16.0/20 ; SBL256894\r\n5.6.7.8 # c2\r\n9.9.9.9,443,online\r\n\"4.4.4.4\"\r\n",
        )
        .unwrap();
        assert_eq!(
            parsed.ipv4,
            vec!["1.10.16.0/20", "4.4.4.4/32", "5.6.7.8/32", "9.9.9.9/32"]
        );
        assert_eq!(parsed.skipped, 0);
    }

    #[test]
    fn spamhaus_json_lines_are_understood() {
        let parsed = parse_feed_text(
            "{\"cidr\":\"1.10.16.0/20\",\"sblid\":\"SBL256894\",\"rir\":\"apnic\"}\n\
             {\"cidr\":\"2a00:1450::/32\",\"sblid\":\"SBL1\",\"rir\":\"ripencc\"}\n\
             {\"ip\":\"6.6.6.6\"}\n\
             {\"type\":\"metadata\",\"timestamp\":1700000000,\"size\":3}\n",
        )
        .unwrap();
        assert_eq!(parsed.ipv4, vec!["1.10.16.0/20", "6.6.6.6/32"]);
        assert_eq!(parsed.ipv6, vec!["2a00:1450::/32"]);
        assert_eq!(parsed.skipped, 0);
    }

    #[test]
    fn broken_json_lines_are_skipped_and_counted() {
        let parsed = parse_feed_text("{\"cidr\":\"1.2.3.0/24\"}\n{\"cidr\": oops\n").unwrap();
        assert_eq!(parsed.ipv4, vec!["1.2.3.0/24"]);
        assert_eq!(parsed.skipped, 1);
    }

    #[test]
    fn host_bits_are_cleared() {
        let parsed = parse_feed_text("1.2.3.77/24\n").unwrap();
        assert_eq!(parsed.ipv4, vec!["1.2.3.0/24"]);
    }

    #[test]
    fn garbage_and_injection_attempts_are_skipped_and_counted() {
        let parsed = parse_feed_text(
            "1.2.3.4\nnot an ip\n1.2.3.4/33\n999.1.1.1\n}\nip saddr 1.1.1.1\n<html>\n\"; flush ruleset\n",
        )
        .unwrap();
        assert_eq!(parsed.ipv4, vec!["1.2.3.4/32"]);
        assert_eq!(parsed.skipped, 7);
    }

    #[test]
    fn private_loopback_link_local_and_multicast_space_is_never_imported() {
        let parsed = parse_feed_text(
            "10.1.2.3\n192.168.1.1\n172.16.5.5\n127.0.0.1\n169.254.1.1\n100.64.1.1\n224.0.0.1\n240.0.0.1\n0.1.2.3\n\
             fd00::1\nfe80::1\n::1\nff02::1\n2001:db8::1\n1.2.3.4\n",
        )
        .unwrap();
        assert_eq!(parsed.ipv4, vec!["1.2.3.4/32"]);
        assert!(parsed.ipv6.is_empty());
        assert_eq!(parsed.skipped, 14);
    }

    #[test]
    fn default_routes_and_huge_networks_are_skipped() {
        let parsed = parse_feed_text(
            "0.0.0.0/0\n::/0\n1.0.0.0/4\n64.0.0.0/2\n2000::/8\n2a00::/12\n8.0.0.0/8\n1.2.3.4\n",
        )
        .unwrap();
        assert_eq!(parsed.ipv4, vec!["1.2.3.4/32", "8.0.0.0/8"]);
        assert!(parsed.ipv6.is_empty());
        assert_eq!(parsed.skipped, 6);
    }

    #[test]
    fn a_network_that_swallows_private_space_is_skipped() {
        let parsed = parse_feed_text("8.0.0.0/5\n1.2.3.4\n").unwrap();
        assert_eq!(parsed.ipv4, vec!["1.2.3.4/32"]);
        assert_eq!(parsed.skipped, 1);
    }

    #[test]
    fn a_list_with_nothing_usable_is_an_error() {
        assert!(parse_feed_text("").is_err());
        assert!(parse_feed_text("# only a comment\n\n").is_err());
        assert!(parse_feed_text("10.0.0.1\n0.0.0.0/0\nrubbish\n").is_err());
        assert!(parse_feed_text("<html><body>Too many requests</body></html>").is_err());
    }

    #[test]
    fn too_many_lines_or_entries_is_an_error() {
        let text = "# c\n".repeat(MAX_FEED_LINES + 1);
        assert!(parse_feed_text(&text).is_err());

        let mut big = String::new();
        for i in 0..(MAX_FEED_ENTRIES as u32 + 1) {
            big.push_str(&std::net::Ipv4Addr::from(0x0B00_0000u32 + i).to_string());
            big.push('\n');
        }
        assert!(parse_feed_text(&big).is_err());
    }

    #[test]
    fn output_is_deterministic_regardless_of_input_order() {
        let a = parse_feed_text("1.2.3.4\n5.6.7.8\n2001:4860::1\n2001:4861::1\n").unwrap();
        let b = parse_feed_text("2001:4861::1\n5.6.7.8\n2001:4860::1\n1.2.3.4\n").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn only_clean_network_strings_come_out() {
        let parsed = parse_feed_text("1.2.3.4\n ABCD::1 \n5.6.7.0/24\n").unwrap();
        for entry in parsed.ipv4.iter().chain(parsed.ipv6.iter()) {
            assert!(entry
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':' || c == '/'));
            assert!(entry.parse::<IpNet>().is_ok());
        }
        assert_eq!(parsed.ipv6, vec!["abcd::1/128"]);
    }

    #[test]
    fn every_preset_has_a_valid_public_url_and_a_sane_interval() {
        let mut ids = BTreeSet::new();
        for preset in PRESETS.iter() {
            assert!(ids.insert(preset.id), "duplicate preset id {}", preset.id);
            assert!(validate_url(preset.url).is_ok(), "{}", preset.id);
            assert!(validate_name(preset.name).is_ok(), "{}", preset.id);
            assert!(validate_refresh_hours(preset.refresh_hours).is_ok(), "{}", preset.id);
            assert!(preset.url.starts_with("https://"), "{}", preset.id);
        }
    }

    #[test]
    fn json_defaults_make_an_enabled_two_way_url_feed() {
        let feed: ThreatFeed =
            serde_json::from_str(r#"{"name":"x","url":"https://example.com/l.txt"}"#).unwrap();
        assert_eq!(feed.kind, "url");
        assert!(feed.enabled);
        assert_eq!(feed.direction, "both");
        assert_eq!(feed.refresh_hours, DEFAULT_REFRESH_HOURS);
        assert!(!feed.log_enabled);
        assert!(feed.blocks_inbound() && feed.blocks_outbound());
        assert!(feed.id.is_none());
    }

    #[test]
    fn errors_are_flattened_and_clipped() {
        assert_eq!(clip_error("a\nb\tc"), "a b c");
        assert_eq!(clip_error(&"x".repeat(1000)).chars().count(), MAX_ERROR_LEN);
    }
}
