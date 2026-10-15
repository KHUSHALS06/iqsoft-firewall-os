use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::IpAddr;

pub const MAX_ZONE_LINES: usize = 200_000;
pub const MAX_COMMENT_LEN: usize = 200;
pub const MAX_SOURCE_LEN: usize = 200;

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

fn default_direction() -> String {
    "inbound".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GeoipPolicy {
    pub id: Option<i64>,

    pub country_code: String,

    #[serde(default = "default_direction")]
    pub direction: String,

    #[serde(default = "default_true")]
    pub enabled: bool,

    pub comment: Option<String>,
}

impl GeoipPolicy {
    pub fn blocks_inbound(&self) -> bool {
        self.direction == "inbound" || self.direction == "both"
    }

    pub fn blocks_outbound(&self) -> bool {
        self.direction == "outbound" || self.direction == "both"
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GeoipDataset {
    pub country_code: String,
    pub updated_at: String,
    pub source: Option<String>,
    pub ipv4_count: i64,
    pub ipv6_count: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GeoipImportRequest {
    pub data: String,
    pub source: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct GeoipImportResult {
    pub country_code: String,
    pub ipv4_imported: usize,
    pub ipv6_imported: usize,
    pub skipped: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedZone {
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub skipped: usize,
}

pub fn normalize_country_code(value: &str) -> Option<String> {
    let trimmed = value.trim();

    if trimmed.len() != 2 || !trimmed.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }

    Some(trimmed.to_ascii_uppercase())
}

pub fn normalize_direction(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "inbound" => Some("inbound"),
        "outbound" => Some("outbound"),
        "both" => Some("both"),
        _ => None,
    }
}

pub fn validate_comment(value: &Option<String>) -> Result<(), String> {
    if let Some(text) = value {
        if text.chars().count() > MAX_COMMENT_LEN {
            return Err(format!("Comment cannot be longer than {} characters", MAX_COMMENT_LEN));
        }

        if text.chars().any(|c| c.is_control()) {
            return Err("Comment cannot contain control characters".into());
        }
    }

    Ok(())
}

pub fn validate_source(value: &Option<String>) -> Result<(), String> {
    if let Some(text) = value {
        if text.chars().count() > MAX_SOURCE_LEN {
            return Err(format!("Source cannot be longer than {} characters", MAX_SOURCE_LEN));
        }

        if text.chars().any(|c| c.is_control()) {
            return Err("Source cannot contain control characters".into());
        }
    }

    Ok(())
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

fn parse_network(line: &str) -> Option<IpNet> {
    if let Ok(net) = line.parse::<IpNet>() {
        return Some(net.trunc());
    }

    match line.parse::<IpAddr>() {
        Ok(addr) => Some(IpNet::from(addr)),
        Err(_) => None,
    }
}

pub fn parse_zone_list(text: &str) -> Result<ParsedZone, String> {
    if text.lines().count() > MAX_ZONE_LINES {
        return Err(format!("A country list cannot have more than {} lines", MAX_ZONE_LINES));
    }

    let protected = protected_networks();

    let mut v4: BTreeSet<IpNet> = BTreeSet::new();
    let mut v6: BTreeSet<IpNet> = BTreeSet::new();
    let mut skipped = 0usize;

    for raw in text.lines() {
        let line = raw.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let net = match parse_network(line) {
            Some(net) => net,
            None => {
                skipped += 1;
                continue;
            }
        };

        if net.prefix_len() == 0 || touches_protected_space(&net, &protected) {
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
        return Err("No valid networks found in the list".into());
    }

    Ok(ParsedZone {
        ipv4: v4.iter().map(|net| net.to_string()).collect(),
        ipv6: v6.iter().map(|net| net.to_string()).collect(),
        skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn country_codes_are_trimmed_and_uppercased() {
        assert_eq!(normalize_country_code("cn"), Some("CN".to_string()));
        assert_eq!(normalize_country_code("  Ru "), Some("RU".to_string()));
        assert_eq!(normalize_country_code("US"), Some("US".to_string()));
    }

    #[test]
    fn bad_country_codes_are_refused() {
        for bad in ["", "C", "CHN", "1A", "C1", "C N", "é1", "中国", "C;"] {
            assert_eq!(normalize_country_code(bad), None, "{:?}", bad);
        }
    }

    #[test]
    fn directions_are_normalized_or_refused() {
        assert_eq!(normalize_direction("Inbound"), Some("inbound"));
        assert_eq!(normalize_direction(" OUTBOUND "), Some("outbound"));
        assert_eq!(normalize_direction("both"), Some("both"));
        assert_eq!(normalize_direction("sideways"), None);
        assert_eq!(normalize_direction(""), None);
    }

    #[test]
    fn policy_direction_helpers() {
        let mut policy = GeoipPolicy {
            id: None,
            country_code: "CN".into(),
            direction: "inbound".into(),
            enabled: true,
            comment: None,
        };

        assert!(policy.blocks_inbound());
        assert!(!policy.blocks_outbound());

        policy.direction = "outbound".into();
        assert!(!policy.blocks_inbound());
        assert!(policy.blocks_outbound());

        policy.direction = "both".into();
        assert!(policy.blocks_inbound());
        assert!(policy.blocks_outbound());
    }

    #[test]
    fn policy_json_defaults_to_inbound_and_enabled() {
        let policy: GeoipPolicy = serde_json::from_str(r#"{"country_code":"CN"}"#).unwrap();
        assert_eq!(policy.direction, "inbound");
        assert!(policy.enabled);
        assert!(policy.id.is_none());
    }

    #[test]
    fn comments_and_sources_are_checked() {
        assert!(validate_comment(&None).is_ok());
        assert!(validate_comment(&Some("blocked after scan".into())).is_ok());
        assert!(validate_comment(&Some("x".repeat(MAX_COMMENT_LEN + 1))).is_err());
        assert!(validate_comment(&Some("line\nbreak".into())).is_err());
        assert!(validate_source(&Some("ipdeny.com cn.zone".into())).is_ok());
        assert!(validate_source(&Some("bad\u{0007}".into())).is_err());
        assert!(validate_source(&Some("y".repeat(MAX_SOURCE_LEN + 1))).is_err());
    }

    #[test]
    fn a_normal_zone_file_is_split_by_family_and_sorted() {
        let parsed = parse_zone_list("1.0.2.0/23\n1.0.1.0/24\n2001:250::/32\n").unwrap();

        assert_eq!(parsed.ipv4, vec!["1.0.1.0/24", "1.0.2.0/23"]);
        assert_eq!(parsed.ipv6, vec!["2001:250::/32"]);
        assert_eq!(parsed.skipped, 0);
    }

    #[test]
    fn blank_lines_comments_and_windows_line_endings_are_fine() {
        let parsed = parse_zone_list("# china\r\n\r\n1.0.1.0/24\r\n   \r\n  1.0.2.0/24  \r\n").unwrap();

        assert_eq!(parsed.ipv4, vec!["1.0.1.0/24", "1.0.2.0/24"]);
        assert_eq!(parsed.skipped, 0);
    }

    #[test]
    fn duplicates_are_collapsed() {
        let parsed = parse_zone_list("1.0.1.0/24\n1.0.1.0/24\n1.0.1.0/24\n").unwrap();
        assert_eq!(parsed.ipv4, vec!["1.0.1.0/24"]);
    }

    #[test]
    fn host_bits_are_cleared_and_bare_addresses_become_host_networks() {
        let parsed = parse_zone_list("1.0.1.77/24\n8.8.4.4\n2001:4860::1\n").unwrap();

        assert_eq!(parsed.ipv4, vec!["1.0.1.0/24", "8.8.4.4/32"]);
        assert_eq!(parsed.ipv6, vec!["2001:4860::1/128"]);
    }

    #[test]
    fn garbage_lines_are_skipped_and_counted() {
        let parsed = parse_zone_list(
            "1.0.1.0/24\nnot a network\n1.0.1.0/33\n999.1.1.1/24\n1.0.1.0/24; drop\n}\nip saddr 1.1.1.1\n",
        )
        .unwrap();

        assert_eq!(parsed.ipv4, vec!["1.0.1.0/24"]);
        assert_eq!(parsed.skipped, 6);
    }

    #[test]
    fn default_routes_and_huge_supernets_are_skipped() {
        let parsed = parse_zone_list("0.0.0.0/0\n::/0\n0.0.0.0/1\n128.0.0.0/1\n1.0.1.0/24\n").unwrap();

        assert_eq!(parsed.ipv4, vec!["1.0.1.0/24"]);
        assert!(parsed.ipv6.is_empty());
        assert_eq!(parsed.skipped, 4);
    }

    #[test]
    fn private_loopback_and_link_local_space_is_skipped() {
        let parsed = parse_zone_list(
            "10.1.0.0/16\n192.168.1.0/24\n172.16.0.0/12\n172.20.1.0/24\n127.0.0.1\n169.254.1.0/24\n100.64.0.0/10\n224.0.0.0/4\n\
             fc00::/7\nfd12:3456::/32\nfe80::/10\n::1\nff02::/16\n1.0.1.0/24\n",
        )
        .unwrap();

        assert_eq!(parsed.ipv4, vec!["1.0.1.0/24"]);
        assert!(parsed.ipv6.is_empty());
        assert_eq!(parsed.skipped, 13);
    }

    #[test]
    fn a_range_that_swallows_private_space_is_skipped() {
        let parsed = parse_zone_list("8.0.0.0/5\n1.0.1.0/24\n").unwrap();

        assert_eq!(parsed.ipv4, vec!["1.0.1.0/24"]);
        assert_eq!(parsed.skipped, 1);
    }

    #[test]
    fn a_list_with_nothing_usable_is_an_error() {
        assert!(parse_zone_list("").is_err());
        assert!(parse_zone_list("# only a comment\n\n").is_err());
        assert!(parse_zone_list("10.0.0.0/8\n0.0.0.0/0\nrubbish\n").is_err());
    }

    #[test]
    fn too_many_lines_is_an_error() {
        let text = "1.0.1.0/24\n".repeat(MAX_ZONE_LINES + 1);
        assert!(parse_zone_list(&text).is_err());

        let text = "1.0.1.0/24\n".repeat(MAX_ZONE_LINES);
        assert!(parse_zone_list(&text).is_ok());
    }

    #[test]
    fn output_is_deterministic_regardless_of_input_order() {
        let a = parse_zone_list("1.0.2.0/24\n1.0.1.0/24\n2001:250::/32\n2001:240::/32\n").unwrap();
        let b = parse_zone_list("2001:240::/32\n1.0.1.0/24\n2001:250::/32\n1.0.2.0/24\n").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn only_clean_network_strings_come_out() {
        let parsed = parse_zone_list("1.0.1.0/24\n 1.0.2.0/24 \nABCD::/16\n").unwrap();

        for entry in parsed.ipv4.iter().chain(parsed.ipv6.iter()) {
            assert!(entry
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':' || c == '/'));
            assert!(entry.parse::<IpNet>().is_ok());
        }
        assert_eq!(parsed.ipv6, vec!["abcd::/16"]);
    }
}
