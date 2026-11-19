use crate::models::av::normalize_cidr;
use crate::models::dnsfilter::validate_comment;
use crate::sni::queue::SNI_QUEUE_NUM;
use serde::{Deserialize, Serialize};

pub const MIN_QUEUE_NUM: i64 = 1;
pub const MAX_QUEUE_NUM: i64 = 65_535;
pub const MAX_RULE_UPDATE_HOURS: i64 = 720;
pub const MIN_RETENTION_DAYS: i64 = 1;
pub const MAX_RETENTION_DAYS: i64 = 365;
pub const MAX_INTERFACES: usize = 16;
pub const MAX_INTERFACE_NAME_LEN: usize = 15;
pub const MAX_HOME_NET_ENTRIES: usize = 16;
pub const MAX_HOME_NET_LEN: usize = 300;
pub const MAX_INTERFACES_LEN: usize = 200;

fn default_mode() -> String {
    "ids".to_string()
}

fn default_fail_mode() -> String {
    "open".to_string()
}

fn default_queue_num() -> i64 {
    200
}

fn default_home_net() -> String {
    "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]".to_string()
}

fn default_rule_update_hours() -> i64 {
    24
}

fn default_event_retention_days() -> i64 {
    30
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct IdsSettings {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_mode")]
    pub mode: String,

    #[serde(default)]
    pub interfaces: String,

    #[serde(default = "default_queue_num")]
    pub queue_num: i64,

    #[serde(default = "default_fail_mode")]
    pub fail_mode: String,

    #[serde(default = "default_home_net")]
    pub home_net: String,

    #[serde(default = "default_rule_update_hours")]
    pub rule_update_hours: i64,

    #[serde(default = "default_event_retention_days")]
    pub event_retention_days: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct IdsRuleOverride {
    pub id: Option<i64>,

    pub sid: i64,

    pub action: String,

    pub comment: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct IdsEvent {
    pub id: Option<i64>,

    pub ts: i64,

    pub src_ip: String,

    pub src_port: Option<i64>,

    pub dest_ip: String,

    pub dest_port: Option<i64>,

    pub proto: String,

    pub app_proto: Option<String>,

    pub sid: i64,

    pub signature: String,

    pub category: Option<String>,

    pub severity: i64,

    pub action: String,
}

pub fn normalize_mode(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "ids" => Some("ids"),
        "ips" => Some("ips"),
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

pub fn normalize_override_action(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "disable" => Some("disable"),
        "alert" => Some("alert"),
        "drop" => Some("drop"),
        _ => None,
    }
}

pub fn normalize_event_action(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "allowed" => Some("allowed"),
        "blocked" => Some("blocked"),
        _ => None,
    }
}

fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_INTERFACE_NAME_LEN
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

pub fn normalize_interfaces(value: &str) -> Result<String, String> {
    let mut names: Vec<String> = Vec::new();

    for part in value.split(',') {
        let name = part.trim();

        if name.is_empty() {
            continue;
        }

        if !valid_interface_name(name) {
            return Err(format!(
                "'{}' is not a valid interface name (letters, digits, '_', '.', '-', up to {} characters)",
                name, MAX_INTERFACE_NAME_LEN
            ));
        }

        if !names.iter().any(|existing| existing == name) {
            names.push(name.to_string());
        }
    }

    if names.len() > MAX_INTERFACES {
        return Err(format!("At most {} interfaces can be listed", MAX_INTERFACES));
    }

    let joined = names.join(",");

    if joined.len() > MAX_INTERFACES_LEN {
        return Err(format!(
            "The interface list cannot be longer than {} characters",
            MAX_INTERFACES_LEN
        ));
    }

    Ok(joined)
}

pub fn normalize_home_net(value: &str) -> Result<String, String> {
    let text = value.trim();
    let inner = text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(text);

    let mut nets: Vec<String> = Vec::new();

    for part in inner.split(',') {
        let entry = part.trim();

        if entry.is_empty() {
            continue;
        }

        let net = normalize_cidr(entry).ok_or_else(|| {
            format!(
                "'{}' is not an IP address or network such as 10.0.0.0/8",
                entry
            )
        })?;

        if !nets.contains(&net) {
            nets.push(net);
        }
    }

    if nets.is_empty() {
        return Err("Home networks cannot be empty".into());
    }

    if nets.len() > MAX_HOME_NET_ENTRIES {
        return Err(format!(
            "At most {} home networks can be listed",
            MAX_HOME_NET_ENTRIES
        ));
    }

    let rendered = format!("[{}]", nets.join(","));

    if rendered.len() > MAX_HOME_NET_LEN {
        return Err(format!(
            "The home network list cannot be longer than {} characters",
            MAX_HOME_NET_LEN
        ));
    }

    Ok(rendered)
}

pub fn clean_settings(mut settings: IdsSettings) -> Result<IdsSettings, String> {
    settings.mode = normalize_mode(&settings.mode)
        .ok_or("Mode must be 'ids' or 'ips'")?
        .to_string();

    settings.fail_mode = normalize_fail_mode(&settings.fail_mode)
        .ok_or("Fail mode must be 'open' or 'closed'")?
        .to_string();

    if settings.queue_num < MIN_QUEUE_NUM || settings.queue_num > MAX_QUEUE_NUM {
        return Err(format!(
            "Queue number must be between {} and {}",
            MIN_QUEUE_NUM, MAX_QUEUE_NUM
        ));
    }

    if settings.queue_num == i64::from(SNI_QUEUE_NUM) {
        return Err(format!(
            "Queue number {} is used by the HTTPS filter, choose another one",
            SNI_QUEUE_NUM
        ));
    }

    if settings.rule_update_hours < 0 || settings.rule_update_hours > MAX_RULE_UPDATE_HOURS {
        return Err(format!(
            "Rule update interval must be between 0 (never) and {} hours",
            MAX_RULE_UPDATE_HOURS
        ));
    }

    if settings.event_retention_days < MIN_RETENTION_DAYS
        || settings.event_retention_days > MAX_RETENTION_DAYS
    {
        return Err(format!(
            "Event retention must be between {} and {} days",
            MIN_RETENTION_DAYS, MAX_RETENTION_DAYS
        ));
    }

    settings.interfaces = normalize_interfaces(&settings.interfaces)?;
    settings.home_net = normalize_home_net(&settings.home_net)?;

    Ok(settings)
}

pub fn clean_override(mut rule: IdsRuleOverride) -> Result<IdsRuleOverride, String> {
    validate_comment(&rule.comment)?;

    if rule.sid <= 0 || rule.sid > i64::from(u32::MAX) {
        return Err("Signature ID must be a positive number".into());
    }

    rule.action = normalize_override_action(&rule.action)
        .ok_or("Action must be 'disable', 'alert' or 'drop'")?
        .to_string();

    if rule.comment.as_deref().map(str::trim) == Some("") {
        rule.comment = None;
    }

    Ok(rule)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> IdsSettings {
        serde_json::from_str("{}").unwrap()
    }

    #[test]
    fn json_defaults_are_safe() {
        let settings = defaults();

        assert!(!settings.enabled);
        assert_eq!(settings.mode, "ids");
        assert_eq!(settings.interfaces, "");
        assert_eq!(settings.queue_num, 200);
        assert_eq!(settings.fail_mode, "open");
        assert_eq!(settings.home_net, "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]");
        assert_eq!(settings.rule_update_hours, 24);
        assert_eq!(settings.event_retention_days, 30);
    }

    #[test]
    fn default_settings_pass_cleaning_unchanged() {
        let cleaned = clean_settings(defaults()).unwrap();
        assert_eq!(cleaned, defaults());
    }

    #[test]
    fn enums_are_normalized_or_refused() {
        assert_eq!(normalize_mode(" IPS "), Some("ips"));
        assert_eq!(normalize_mode("block"), None);
        assert_eq!(normalize_fail_mode("CLOSED"), Some("closed"));
        assert_eq!(normalize_fail_mode("maybe"), None);
        assert_eq!(normalize_override_action("Drop"), Some("drop"));
        assert_eq!(normalize_override_action("pass"), None);
        assert_eq!(normalize_event_action("Blocked"), Some("blocked"));
        assert_eq!(normalize_event_action("dropped"), None);
    }

    #[test]
    fn settings_reject_out_of_range_values() {
        let mut s = defaults();
        s.queue_num = 0;
        assert!(clean_settings(s).is_err());

        let mut s = defaults();
        s.queue_num = 65_536;
        assert!(clean_settings(s).is_err());

        let mut s = defaults();
        s.rule_update_hours = -1;
        assert!(clean_settings(s).is_err());

        let mut s = defaults();
        s.rule_update_hours = 721;
        assert!(clean_settings(s).is_err());

        let mut s = defaults();
        s.event_retention_days = 0;
        assert!(clean_settings(s).is_err());

        let mut s = defaults();
        s.event_retention_days = 366;
        assert!(clean_settings(s).is_err());

        let mut s = defaults();
        s.mode = "block".into();
        assert!(clean_settings(s).is_err());

        let mut s = defaults();
        s.fail_mode = "maybe".into();
        assert!(clean_settings(s).is_err());
    }

    #[test]
    fn the_https_filter_queue_is_refused() {
        let mut s = defaults();
        s.queue_num = i64::from(SNI_QUEUE_NUM);
        assert!(clean_settings(s).is_err());
    }

    #[test]
    fn settings_values_are_normalized() {
        let mut s = defaults();
        s.mode = " IPS ".into();
        s.fail_mode = "CLOSED".into();
        s.interfaces = " eth0 , eth1,eth0,, ".into();
        s.home_net = " 10.1.2.3/8 , 192.168.1.5 ".into();

        let cleaned = clean_settings(s).unwrap();

        assert_eq!(cleaned.mode, "ips");
        assert_eq!(cleaned.fail_mode, "closed");
        assert_eq!(cleaned.interfaces, "eth0,eth1");
        assert_eq!(cleaned.home_net, "[10.0.0.0/8,192.168.1.5/32]");
    }

    #[test]
    fn interfaces_must_be_safe_names() {
        assert_eq!(normalize_interfaces("").unwrap(), "");
        assert_eq!(normalize_interfaces("enp2s0").unwrap(), "enp2s0");
        assert!(normalize_interfaces("eth0;reboot").is_err());
        assert!(normalize_interfaces("eth 0").is_err());
        assert!(normalize_interfaces("eth0/../x").is_err());
        assert!(normalize_interfaces("averyveryverylongname").is_err());

        let many = (0..17).map(|i| format!("e{}", i)).collect::<Vec<_>>().join(",");
        assert!(normalize_interfaces(&many).is_err());
    }

    #[test]
    fn home_net_accepts_brackets_or_bare_lists() {
        assert_eq!(normalize_home_net("[10.0.0.0/8]").unwrap(), "[10.0.0.0/8]");
        assert_eq!(normalize_home_net("10.0.0.0/8").unwrap(), "[10.0.0.0/8]");
        assert_eq!(
            normalize_home_net("[fd00::1, 10.0.0.0/8, 10.0.0.0/8]").unwrap(),
            "[fd00::1/128,10.0.0.0/8]"
        );
    }

    #[test]
    fn home_net_rejects_bad_input() {
        assert!(normalize_home_net("").is_err());
        assert!(normalize_home_net("[]").is_err());
        assert!(normalize_home_net("any").is_err());
        assert!(normalize_home_net("!10.0.0.0/8").is_err());
        assert!(normalize_home_net("[10.0.0.0/8,$EXTERNAL_NET]").is_err());
        assert!(normalize_home_net("10.0.0.0/40").is_err());
        assert!(normalize_home_net("10.0.0.0/8; reboot").is_err());

        let many = (0..17)
            .map(|i| format!("10.{}.0.0/16", i))
            .collect::<Vec<_>>()
            .join(",");
        assert!(normalize_home_net(&many).is_err());
    }

    #[test]
    fn overrides_are_cleaned() {
        let cleaned = clean_override(IdsRuleOverride {
            id: None,
            sid: 2_100_498,
            action: " Disable ".into(),
            comment: Some("  ".into()),
        })
        .unwrap();

        assert_eq!(cleaned.action, "disable");
        assert_eq!(cleaned.comment, None);
    }

    #[test]
    fn overrides_reject_bad_input() {
        let bad = |sid: i64, action: &str, comment: Option<&str>| {
            clean_override(IdsRuleOverride {
                id: None,
                sid,
                action: action.into(),
                comment: comment.map(str::to_string),
            })
            .is_err()
        };

        assert!(bad(0, "drop", None));
        assert!(bad(-5, "drop", None));
        assert!(bad(i64::from(u32::MAX) + 1, "drop", None));
        assert!(bad(2_100_498, "pass", None));
        assert!(bad(2_100_498, "drop", Some("bad\ncomment")));
        assert!(bad(2_100_498, "drop", Some(&"x".repeat(201))));
    }

    #[test]
    fn events_round_trip_through_json() {
        let event = IdsEvent {
            id: Some(1),
            ts: 1_795_000_000,
            src_ip: "10.0.0.5".into(),
            src_port: Some(51_000),
            dest_ip: "203.0.113.9".into(),
            dest_port: Some(80),
            proto: "TCP".into(),
            app_proto: Some("http".into()),
            sid: 2_100_498,
            signature: "GPL ATTACK_RESPONSE id check returned root".into(),
            category: Some("Potentially Bad Traffic".into()),
            severity: 2,
            action: "blocked".into(),
        };

        let text = serde_json::to_string(&event).unwrap();
        let back: IdsEvent = serde_json::from_str(&text).unwrap();

        assert_eq!(event, back);
    }
}
