use crate::models::dnsfilter::{normalize_domain, validate_comment};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

pub const MIN_SCAN_MB: i64 = 1;
pub const MAX_SCAN_MB: i64 = 512;
pub const MIN_PROXY_PORT: i64 = 1024;
pub const MAX_PROXY_PORT: i64 = 65_535;
pub const MAX_SOCKET_LEN: usize = 200;

fn default_true() -> bool {
    true
}

fn default_mode() -> String {
    "block".to_string()
}

fn default_max_scan_mb() -> i64 {
    25
}

fn default_over_size_action() -> String {
    "allow".to_string()
}

fn default_fail_mode() -> String {
    "open".to_string()
}

fn default_clamd_socket() -> String {
    "/run/clamav/clamd.ctl".to_string()
}

fn default_proxy_port() -> i64 {
    3128
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AvSettings {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_mode")]
    pub mode: String,

    #[serde(default = "default_max_scan_mb")]
    pub max_scan_mb: i64,

    #[serde(default = "default_over_size_action")]
    pub over_size_action: String,

    #[serde(default = "default_fail_mode")]
    pub fail_mode: String,

    #[serde(default = "default_true")]
    pub scan_archives: bool,

    #[serde(default)]
    pub block_encrypted_archives: bool,

    #[serde(default = "default_clamd_socket", rename = "scanner_socket", alias = "clamd_socket")]
    pub clamd_socket: String,

    #[serde(default = "default_proxy_port")]
    pub proxy_port: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AvException {
    pub id: Option<i64>,

    pub kind: String,

    pub value: String,

    pub comment: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AvEvent {
    pub id: Option<i64>,

    pub ts: i64,

    pub client_ip: String,

    pub host: String,

    pub url: String,

    pub file_name: Option<String>,

    pub size_bytes: i64,

    pub engine: String,

    pub signature: Option<String>,

    pub action: String,
}

pub fn normalize_mode(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "block" => Some("block"),
        "monitor" => Some("monitor"),
        _ => None,
    }
}

pub fn normalize_over_size_action(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "allow" => Some("allow"),
        "block" => Some("block"),
        _ => None,
    }
}

pub fn normalize_fail_mode(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "open" => Some("open"),
        "closed" => Some("closed"),
        _ => None,
    }
}

pub fn normalize_exception_kind(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "domain" => Some("domain"),
        "cidr" => Some("cidr"),
        _ => None,
    }
}

pub fn normalize_socket_path(value: &str) -> Result<String, String> {
    let path = value.trim();

    if path.is_empty() || path.len() > MAX_SOCKET_LEN {
        return Err(format!(
            "Virus scanner socket path must be between 1 and {} characters",
            MAX_SOCKET_LEN
        ));
    }

    if !path.starts_with('/') {
        return Err("Virus scanner socket path must be an absolute path".into());
    }

    if path.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("Virus scanner socket path cannot contain spaces or control characters".into());
    }

    if path.split('/').any(|part| part == "..") {
        return Err("Virus scanner socket path cannot contain '..'".into());
    }

    Ok(path.to_string())
}

pub fn normalize_cidr(value: &str) -> Option<String> {
    let text = value.trim();

    if text.is_empty() {
        return None;
    }

    if text.contains('/') {
        let net: IpNet = text.parse().ok()?;
        return Some(net.trunc().to_string());
    }

    let addr: std::net::IpAddr = text.parse().ok()?;
    Some(IpNet::from(addr).to_string())
}

pub fn clean_settings(mut settings: AvSettings) -> Result<AvSettings, String> {
    settings.mode = normalize_mode(&settings.mode)
        .ok_or("Mode must be 'block' or 'monitor'")?
        .to_string();

    settings.over_size_action = normalize_over_size_action(&settings.over_size_action)
        .ok_or("Over-size action must be 'allow' or 'block'")?
        .to_string();

    settings.fail_mode = normalize_fail_mode(&settings.fail_mode)
        .ok_or("Fail mode must be 'open' or 'closed'")?
        .to_string();

    if settings.max_scan_mb < MIN_SCAN_MB || settings.max_scan_mb > MAX_SCAN_MB {
        return Err(format!(
            "Maximum scan size must be between {} and {} MB",
            MIN_SCAN_MB, MAX_SCAN_MB
        ));
    }

    if settings.proxy_port < MIN_PROXY_PORT || settings.proxy_port > MAX_PROXY_PORT {
        return Err(format!(
            "Proxy port must be between {} and {}",
            MIN_PROXY_PORT, MAX_PROXY_PORT
        ));
    }

    settings.clamd_socket = normalize_socket_path(&settings.clamd_socket)?;

    Ok(settings)
}

pub fn clean_exception(mut exception: AvException) -> Result<AvException, String> {
    validate_comment(&exception.comment)?;

    let kind = normalize_exception_kind(&exception.kind)
        .ok_or("Exception type must be 'domain' or 'cidr'")?;

    exception.value = match kind {
        "domain" => normalize_domain(&exception.value)
            .ok_or("Domain must be a full name such as example.com")?,
        _ => normalize_cidr(&exception.value)
            .ok_or("Network must be an IP address or CIDR such as 10.0.0.0/24")?,
    };

    exception.kind = kind.to_string();

    if exception.comment.as_deref().map(str::trim) == Some("") {
        exception.comment = None;
    }

    Ok(exception)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> AvSettings {
        serde_json::from_str("{}").unwrap()
    }

    #[test]
    fn json_defaults_are_safe() {
        let settings = defaults();

        assert!(!settings.enabled);
        assert_eq!(settings.mode, "block");
        assert_eq!(settings.max_scan_mb, 25);
        assert_eq!(settings.over_size_action, "allow");
        assert_eq!(settings.fail_mode, "open");
        assert!(settings.scan_archives);
        assert!(!settings.block_encrypted_archives);
        assert_eq!(settings.clamd_socket, "/run/clamav/clamd.ctl");
        assert_eq!(settings.proxy_port, 3128);
    }

    #[test]
    fn default_settings_pass_cleaning_unchanged() {
        let cleaned = clean_settings(defaults()).unwrap();
        assert_eq!(cleaned, defaults());
    }

    #[test]
    fn enums_are_normalized_or_refused() {
        assert_eq!(normalize_mode(" MONITOR "), Some("monitor"));
        assert_eq!(normalize_mode("off"), None);
        assert_eq!(normalize_over_size_action("Block"), Some("block"));
        assert_eq!(normalize_over_size_action(""), None);
        assert_eq!(normalize_fail_mode("CLOSED"), Some("closed"));
        assert_eq!(normalize_fail_mode("maybe"), None);
        assert_eq!(normalize_exception_kind("Domain"), Some("domain"));
        assert_eq!(normalize_exception_kind("mac"), None);
    }

    #[test]
    fn settings_reject_out_of_range_values() {
        let mut s = defaults();
        s.max_scan_mb = 0;
        assert!(clean_settings(s).is_err());

        let mut s = defaults();
        s.max_scan_mb = 513;
        assert!(clean_settings(s).is_err());

        let mut s = defaults();
        s.proxy_port = 80;
        assert!(clean_settings(s).is_err());

        let mut s = defaults();
        s.proxy_port = 65_536;
        assert!(clean_settings(s).is_err());

        let mut s = defaults();
        s.mode = "off".into();
        assert!(clean_settings(s).is_err());

        let mut s = defaults();
        s.fail_mode = "maybe".into();
        assert!(clean_settings(s).is_err());
    }

    #[test]
    fn settings_values_are_normalized() {
        let mut s = defaults();
        s.mode = " Monitor ".into();
        s.fail_mode = "CLOSED".into();
        s.over_size_action = "Block".into();
        s.clamd_socket = " /var/run/clamd.sock ".into();

        let cleaned = clean_settings(s).unwrap();

        assert_eq!(cleaned.mode, "monitor");
        assert_eq!(cleaned.fail_mode, "closed");
        assert_eq!(cleaned.over_size_action, "block");
        assert_eq!(cleaned.clamd_socket, "/var/run/clamd.sock");
    }

    #[test]
    fn socket_path_must_be_a_safe_absolute_path() {
        assert!(normalize_socket_path("/run/clamav/clamd.ctl").is_ok());
        assert!(normalize_socket_path("run/clamd").is_err());
        assert!(normalize_socket_path("").is_err());
        assert!(normalize_socket_path("/run/../etc/passwd").is_err());
        assert!(normalize_socket_path("/run/clam d").is_err());
        assert!(normalize_socket_path("/run/cl\u{0}amd").is_err());
        assert!(normalize_socket_path(&format!("/{}", "a".repeat(200))).is_err());
    }

    #[test]
    fn cidr_is_canonical_and_validated() {
        assert_eq!(normalize_cidr("10.0.0.0/24"), Some("10.0.0.0/24".to_string()));
        assert_eq!(normalize_cidr("10.0.0.77/24"), Some("10.0.0.0/24".to_string()));
        assert_eq!(normalize_cidr(" 192.168.1.5 "), Some("192.168.1.5/32".to_string()));
        assert_eq!(normalize_cidr("fd00::1"), Some("fd00::1/128".to_string()));
        assert_eq!(normalize_cidr("10.0.0.0/33"), None);
        assert_eq!(normalize_cidr("not-an-ip"), None);
        assert_eq!(normalize_cidr(""), None);
        assert_eq!(normalize_cidr("10.0.0.0/24; drop"), None);
    }

    #[test]
    fn exceptions_are_cleaned_by_kind() {
        let domain = clean_exception(AvException {
            id: None,
            kind: " Domain ".into(),
            value: "*.Updates.Example.COM.".into(),
            comment: Some("  ".into()),
        })
        .unwrap();
        assert_eq!(domain.kind, "domain");
        assert_eq!(domain.value, "updates.example.com");
        assert_eq!(domain.comment, None);

        let net = clean_exception(AvException {
            id: None,
            kind: "cidr".into(),
            value: "10.1.2.3/16".into(),
            comment: Some("servers".into()),
        })
        .unwrap();
        assert_eq!(net.value, "10.1.0.0/16");
        assert_eq!(net.comment.as_deref(), Some("servers"));
    }

    #[test]
    fn exceptions_reject_bad_input() {
        let bad = |kind: &str, value: &str, comment: Option<&str>| {
            clean_exception(AvException {
                id: None,
                kind: kind.into(),
                value: value.into(),
                comment: comment.map(str::to_string),
            })
            .is_err()
        };

        assert!(bad("domain", "localhost", None));
        assert!(bad("domain", "10.0.0.1", None));
        assert!(bad("domain", "exa mple.com", None));
        assert!(bad("cidr", "example.com", None));
        assert!(bad("cidr", "10.0.0.0/40", None));
        assert!(bad("mac", "aa:bb:cc:dd:ee:ff", None));
        assert!(bad("domain", "example.com", Some("bad\ncomment")));
        assert!(bad("domain", "example.com", Some(&"x".repeat(201))));
    }

    #[test]
    fn events_serialize_with_optional_fields() {
        let event = AvEvent {
            id: Some(1),
            ts: 1_795_000_000,
            client_ip: "10.0.0.5".into(),
            host: "example.com".into(),
            url: "http://example.com/a.exe".into(),
            file_name: None,
            size_bytes: 68,
            engine: "clamav".into(),
            signature: Some("Eicar-Signature".into()),
            action: "blocked".into(),
        };

        let text = serde_json::to_string(&event).unwrap();
        let back: AvEvent = serde_json::from_str(&text).unwrap();

        assert_eq!(back, event);
    }
}
