use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::IpAddr;

pub const MAX_LIST_LINES: usize = 500_000;
pub const MAX_COMMENT_LEN: usize = 200;
pub const MAX_SOURCE_LEN: usize = 200;
pub const MAX_DOMAIN_LEN: usize = 253;
pub const MAX_CATEGORY_LEN: usize = 40;

fn default_true() -> bool {
    true
}

fn default_block_response() -> String {
    "nxdomain".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DnsFilterSettings {
    #[serde(default)]
    pub enabled: bool,

    /// "nxdomain" answers "no such domain"; "sinkhole" answers 0.0.0.0 / ::
    #[serde(default = "default_block_response")]
    pub block_response: String,

    #[serde(default)]
    pub safe_search: bool,

    #[serde(default)]
    pub enforce_dns: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsFilterCategory {
    pub name: String,

    #[serde(default = "default_true")]
    pub enabled: bool,

    pub comment: Option<String>,

    /// Filled in by the server when a list is imported; ignored on input.
    #[serde(default)]
    pub source: Option<String>,

    #[serde(default)]
    pub updated_at: Option<String>,

    #[serde(default)]
    pub domain_count: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsFilterRule {
    pub id: Option<i64>,

    pub domain: String,

    /// "block" or "allow"
    pub action: String,

    pub comment: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsFilterImportRequest {
    pub data: String,
    pub source: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DnsFilterImportResult {
    pub category: String,
    pub imported: usize,
    pub skipped: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDomains {
    pub domains: Vec<String>,
    pub skipped: usize,
}

pub fn normalize_category_name(value: &str) -> Option<String> {
    let name = value.trim().to_ascii_lowercase();

    if name.is_empty() || name.len() > MAX_CATEGORY_LEN {
        return None;
    }

    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return None;
    }

    Some(name)
}

pub fn normalize_block_response(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "nxdomain" => Some("nxdomain"),
        "sinkhole" => Some("sinkhole"),
        _ => None,
    }
}

pub fn normalize_action(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "block" => Some("block"),
        "allow" => Some("allow"),
        _ => None,
    }
}

/// Turns what a person (or a list file) wrote into one clean lowercase domain,
/// or None when it is not a usable domain name. Accepted extras: a leading
/// `*.` or `.` and a trailing `.`, because blocking a domain also covers its
/// subdomains. Single names ("localhost", "com") and IP addresses are refused,
/// so a bad list can never block a whole top-level domain.
pub fn normalize_domain(value: &str) -> Option<String> {
    let mut domain = value.trim().to_ascii_lowercase();

    if let Some(rest) = domain.strip_prefix("*.") {
        domain = rest.to_string();
    }
    if let Some(rest) = domain.strip_prefix('.') {
        domain = rest.to_string();
    }
    if let Some(rest) = domain.strip_suffix('.') {
        domain = rest.to_string();
    }

    if domain.len() < 3 || domain.len() > MAX_DOMAIN_LEN {
        return None;
    }

    let labels: Vec<&str> = domain.split('.').collect();

    if labels.len() < 2 {
        return None;
    }

    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return None;
        }

        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }

        if !label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return None;
        }
    }

    // 1.2.3.4 is an address, not a domain name.
    if labels
        .last()
        .map(|last| last.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or(true)
    {
        return None;
    }

    Some(domain)
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

/// Reads a block list in any of the common shapes:
///   - one domain per line               `ads.example.com`
///   - hosts-file lines                  `0.0.0.0 ads.example.com`
///   - simple adblock domain rules       `||ads.example.com^`
/// Comments (`#`, `!`, `[header]`) and blank lines are ignored. Anything else
/// is skipped and counted. Output is sorted, without duplicates.
pub fn parse_domain_list(text: &str) -> Result<ParsedDomains, String> {
    if text.lines().count() > MAX_LIST_LINES {
        return Err(format!("A list cannot have more than {} lines", MAX_LIST_LINES));
    }

    let mut domains: BTreeSet<String> = BTreeSet::new();
    let mut skipped = 0usize;

    for raw in text.lines() {
        let mut line = raw.trim();

        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with('!')
            || line.starts_with('[')
        {
            continue;
        }

        if let Some(at) = line.find('#') {
            line = line[..at].trim();

            if line.is_empty() {
                continue;
            }
        }

        // ||ads.example.com^
        if let Some(rule) = line.strip_prefix("||") {
            match rule.strip_suffix('^').and_then(normalize_domain) {
                Some(domain) => {
                    domains.insert(domain);
                }
                None => skipped += 1,
            }
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();

        // 0.0.0.0 ads.example.com [more.names ...]
        if tokens.len() > 1 && tokens[0].parse::<IpAddr>().is_ok() {
            for token in &tokens[1..] {
                match normalize_domain(token) {
                    Some(domain) => {
                        domains.insert(domain);
                    }
                    None => skipped += 1,
                }
            }
            continue;
        }

        if tokens.len() == 1 {
            match normalize_domain(tokens[0]) {
                Some(domain) => {
                    domains.insert(domain);
                }
                None => skipped += 1,
            }
            continue;
        }

        skipped += 1;
    }

    if domains.is_empty() {
        return Err("No valid domains found in the list".into());
    }

    Ok(ParsedDomains {
        domains: domains.into_iter().collect(),
        skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_names_are_trimmed_lowercased_and_checked() {
        assert_eq!(normalize_category_name(" Adult "), Some("adult".to_string()));
        assert_eq!(normalize_category_name("social-media"), Some("social-media".to_string()));
        assert_eq!(normalize_category_name("ads_2"), Some("ads_2".to_string()));

        let too_long = "x".repeat(MAX_CATEGORY_LEN + 1);

        for bad in ["", "   ", "a b", "a;b", "a/b", "é", "中", too_long.as_str()] {
            assert_eq!(normalize_category_name(bad), None, "{:?}", bad);
        }
    }

    #[test]
    fn block_response_and_action_are_normalized_or_refused() {
        assert_eq!(normalize_block_response(" NXDOMAIN "), Some("nxdomain"));
        assert_eq!(normalize_block_response("sinkhole"), Some("sinkhole"));
        assert_eq!(normalize_block_response("refuse"), None);

        assert_eq!(normalize_action("Block"), Some("block"));
        assert_eq!(normalize_action(" allow "), Some("allow"));
        assert_eq!(normalize_action("maybe"), None);
        assert_eq!(normalize_action(""), None);
    }

    #[test]
    fn good_domains_are_cleaned() {
        assert_eq!(normalize_domain("Ads.Example.COM"), Some("ads.example.com".to_string()));
        assert_eq!(normalize_domain("  example.org. "), Some("example.org".to_string()));
        assert_eq!(normalize_domain("*.tracker.net"), Some("tracker.net".to_string()));
        assert_eq!(normalize_domain(".tracker.net"), Some("tracker.net".to_string()));
        assert_eq!(normalize_domain("xn--80ak6aa92e.com"), Some("xn--80ak6aa92e.com".to_string()));
        assert_eq!(normalize_domain("a-b.c-d.example.co.uk"), Some("a-b.c-d.example.co.uk".to_string()));
    }

    #[test]
    fn bad_domains_are_refused() {
        let long_label = format!("{}.com", "a".repeat(64));
        let long_name = format!("{}.com", "a.".repeat(130));

        for bad in [
            "",
            "com",
            "localhost",
            ".",
            "a.",
            "ex ample.com",
            "a/b.com",
            "a;b.com",
            "a=b.com",
            "a,b.com",
            "a..b.com",
            "-a.com",
            "a-.com",
            "a.-b.com",
            "under_score.com",
            "*.*.example.com",
            "1.2.3.4",
            "10.0.0.0",
            "http://example.com",
            "example.com/path",
            "bücher.de",
            "例え.jp",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert_eq!(normalize_domain(bad), None, "{:?}", bad);
        }
    }

    #[test]
    fn comments_and_sources_are_checked() {
        assert!(validate_comment(&None).is_ok());
        assert!(validate_comment(&Some("kids network".into())).is_ok());
        assert!(validate_comment(&Some("x".repeat(MAX_COMMENT_LEN + 1))).is_err());
        assert!(validate_comment(&Some("line\nbreak".into())).is_err());
        assert!(validate_source(&Some("stevenblack hosts".into())).is_ok());
        assert!(validate_source(&Some("bad\u{0007}".into())).is_err());
    }

    #[test]
    fn plain_lists_are_cleaned_sorted_and_deduplicated() {
        let parsed = parse_domain_list("b.example.com\nA.Example.com\nb.example.com\n*.c.example.com\n").unwrap();

        assert_eq!(parsed.domains, vec!["a.example.com", "b.example.com", "c.example.com"]);
        assert_eq!(parsed.skipped, 0);
    }

    #[test]
    fn hosts_file_lines_are_understood() {
        let parsed = parse_domain_list(
            "# hosts\n127.0.0.1 localhost\n::1 localhost\n0.0.0.0 ads.example.com\n0.0.0.0 a.example.net b.example.net\n",
        )
        .unwrap();

        assert_eq!(parsed.domains, vec!["a.example.net", "ads.example.com", "b.example.net"]);
        assert_eq!(parsed.skipped, 2);
    }

    #[test]
    fn simple_adblock_rules_are_understood_and_others_skipped() {
        let parsed = parse_domain_list(
            "[Adblock Plus 2.0]\n! comment\n||ads.example.com^\n||x.example.com/path^\n||y.example.com^$third-party\n||z.example.com\n",
        )
        .unwrap();

        assert_eq!(parsed.domains, vec!["ads.example.com"]);
        assert_eq!(parsed.skipped, 3);
    }

    #[test]
    fn comments_blank_lines_and_windows_line_endings_are_fine() {
        let parsed = parse_domain_list(
            "# list\r\n\r\nads.example.com # annoying\r\n   \r\n  tracker.example.org  \r\n# end\r\n",
        )
        .unwrap();

        assert_eq!(parsed.domains, vec!["ads.example.com", "tracker.example.org"]);
        assert_eq!(parsed.skipped, 0);
    }

    #[test]
    fn config_injection_and_garbage_are_skipped_and_counted() {
        let parsed = parse_domain_list(
            "ads.example.com\naddress=/x.com/1.1.1.1\nserver=/x.com/8.8.8.8\nevil.com; drop\nex ample.com\n}\n1.2.3.4\ncom\n",
        )
        .unwrap();

        assert_eq!(parsed.domains, vec!["ads.example.com"]);
        assert_eq!(parsed.skipped, 7);
    }

    #[test]
    fn a_list_with_nothing_usable_is_an_error() {
        assert!(parse_domain_list("").is_err());
        assert!(parse_domain_list("# only a comment\n\n").is_err());
        assert!(parse_domain_list("com\n1.2.3.4\nrubbish rubbish\n").is_err());
    }

    #[test]
    fn too_many_lines_is_an_error() {
        let text = "a.example.com\n".repeat(MAX_LIST_LINES + 1);
        assert!(parse_domain_list(&text).is_err());

        let text = "a.example.com\n".repeat(MAX_LIST_LINES);
        assert!(parse_domain_list(&text).is_ok());
    }

    #[test]
    fn output_is_deterministic_regardless_of_input_order() {
        let a = parse_domain_list("b.example.com\na.example.com\nc.example.org\n").unwrap();
        let b = parse_domain_list("c.example.org\na.example.com\nb.example.com\n").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn only_clean_domain_strings_come_out() {
        let parsed = parse_domain_list("Ads.Example.com\n 0.0.0.0 TRACK.example.NET \n||Pop.Example.org^\n").unwrap();

        for domain in &parsed.domains {
            assert!(domain
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-'));
            assert_eq!(normalize_domain(domain).as_deref(), Some(domain.as_str()));
        }
    }

    #[test]
    fn json_defaults_are_safe() {
        let settings: DnsFilterSettings = serde_json::from_str("{}").unwrap();
        assert!(!settings.enabled);
        assert_eq!(settings.block_response, "nxdomain");
        assert!(!settings.safe_search);
        assert!(!settings.enforce_dns);

        let category: DnsFilterCategory = serde_json::from_str(r#"{"name":"adult"}"#).unwrap();
        assert!(category.enabled);
        assert_eq!(category.domain_count, 0);
        assert!(category.comment.is_none());
    }
}
