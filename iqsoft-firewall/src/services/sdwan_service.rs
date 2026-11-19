use crate::models::sdwan::{
    SdwanLink, SdwanRule, SdwanSettings, MAX_COMMENT_LEN, MAX_LINKS, MAX_NAME_LEN,
    MAX_PRIORITY, MAX_PROBE_INTERVAL_SECS, MAX_PROBE_TIMEOUT_SECS, MAX_RULES, MAX_THRESHOLD,
    MAX_WEIGHT, MIN_PRIORITY, MIN_PROBE_INTERVAL_SECS, MIN_PROBE_TIMEOUT_SECS, MIN_THRESHOLD,
    MIN_WEIGHT, ON_LINK_DOWN, PROTOCOLS, STRATEGIES,
};
use crate::repository::network_config_repository::NetworkConfigRepository;
use crate::repository::sdwan_repository::SdwanRepository;
use ipnet::Ipv4Net;
use sqlx::SqlitePool;
use std::net::Ipv4Addr;
use std::str::FromStr;

pub struct SdwanService;

impl SdwanService {
    // ---------------------------------------------------------------- settings

    pub async fn get_settings(pool: &SqlitePool) -> Result<SdwanSettings, String> {
        SdwanRepository::get_settings(pool)
            .await
            .map_err(|e| e.to_string())
    }

    /// Switching SD-WAN on needs at least one enabled link, switching it off is always allowed.
    pub async fn set_enabled(pool: &SqlitePool, enabled: bool) -> Result<(), String> {
        if enabled {
            let links = Self::list_links(pool).await?;

            if !links.iter().any(|l| l.enabled) {
                return Err("Add at least one enabled WAN link before switching SD-WAN on".into());
            }
        }

        SdwanRepository::set_enabled(pool, enabled)
            .await
            .map_err(|e| e.to_string())
    }

    // ------------------------------------------------------------------- links

    pub async fn list_links(pool: &SqlitePool) -> Result<Vec<SdwanLink>, String> {
        SdwanRepository::list_links(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn add_link(pool: &SqlitePool, mut link: SdwanLink) -> Result<i64, String> {
        Self::normalize_link(&mut link);
        Self::validate_link(&link)?;

        let count = SdwanRepository::count_links(pool)
            .await
            .map_err(|e| e.to_string())?;
        if count as usize >= MAX_LINKS {
            return Err(format!("At most {} WAN links are supported", MAX_LINKS));
        }

        Self::check_link_duplicates(pool, &link, None).await?;
        Self::check_not_lan_interface(pool, &link.interface_name).await?;

        SdwanRepository::add_link(pool, &link)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn update_link(
        pool: &SqlitePool,
        id: i64,
        mut link: SdwanLink,
    ) -> Result<(), String> {
        Self::normalize_link(&mut link);
        Self::validate_link(&link)?;

        let existing = SdwanRepository::get_link(pool, id)
            .await
            .map_err(|e| e.to_string())?;
        if existing.is_none() {
            return Err(format!("SD-WAN link {} does not exist", id));
        }

        Self::check_link_duplicates(pool, &link, Some(id)).await?;
        Self::check_not_lan_interface(pool, &link.interface_name).await?;

        let changed = SdwanRepository::update_link(pool, id, &link)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("SD-WAN link {} does not exist", id));
        }

        Ok(())
    }

    pub async fn delete_link(pool: &SqlitePool, id: i64) -> Result<(), String> {
        let link = SdwanRepository::get_link(pool, id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("SD-WAN link {} does not exist", id))?;

        let used_by = SdwanRepository::count_rules_using_link(pool, id)
            .await
            .map_err(|e| e.to_string())?;

        if used_by > 0 {
            return Err(format!(
                "Link '{}' is used by {} rule(s) - change or delete those rules first",
                link.name, used_by
            ));
        }

        let changed = SdwanRepository::delete_link(pool, id)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("SD-WAN link {} does not exist", id));
        }

        Ok(())
    }

    async fn check_link_duplicates(
        pool: &SqlitePool,
        link: &SdwanLink,
        self_id: Option<i64>,
    ) -> Result<(), String> {
        let same_name = SdwanRepository::get_link_by_name(pool, &link.name)
            .await
            .map_err(|e| e.to_string())?;

        if let Some(other) = same_name {
            if other.id != self_id {
                return Err(format!("A link named '{}' already exists", link.name));
            }
        }

        let same_interface = SdwanRepository::get_link_by_interface(pool, &link.interface_name)
            .await
            .map_err(|e| e.to_string())?;

        if let Some(other) = same_interface {
            if other.id != self_id {
                return Err(format!(
                    "Interface '{}' is already used by link '{}'",
                    link.interface_name, other.name
                ));
            }
        }

        Ok(())
    }

    /// The LAN side can never be an uplink. (The WAN interface can, it is usually link one.)
    async fn check_not_lan_interface(pool: &SqlitePool, interface: &str) -> Result<(), String> {
        if let Ok(config) = NetworkConfigRepository::get(pool).await {
            if config.lan_interface.trim() == interface {
                return Err(format!(
                    "Interface '{}' is the LAN interface and cannot be used as a WAN link",
                    interface
                ));
            }
        }

        Ok(())
    }

    // ------------------------------------------------------------------- rules

    pub async fn list_rules(pool: &SqlitePool) -> Result<Vec<SdwanRule>, String> {
        SdwanRepository::list_rules(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn add_rule(pool: &SqlitePool, mut rule: SdwanRule) -> Result<i64, String> {
        Self::normalize_rule(&mut rule);
        Self::validate_rule(&rule)?;

        let count = SdwanRepository::count_rules(pool)
            .await
            .map_err(|e| e.to_string())?;
        if count as usize >= MAX_RULES {
            return Err(format!("At most {} SD-WAN rules are supported", MAX_RULES));
        }

        Self::check_rule_name_free(pool, &rule, None).await?;
        Self::check_rule_link_exists(pool, &rule).await?;

        SdwanRepository::add_rule(pool, &rule)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn update_rule(
        pool: &SqlitePool,
        id: i64,
        mut rule: SdwanRule,
    ) -> Result<(), String> {
        Self::normalize_rule(&mut rule);
        Self::validate_rule(&rule)?;

        let existing = SdwanRepository::get_rule(pool, id)
            .await
            .map_err(|e| e.to_string())?;
        if existing.is_none() {
            return Err(format!("SD-WAN rule {} does not exist", id));
        }

        Self::check_rule_name_free(pool, &rule, Some(id)).await?;
        Self::check_rule_link_exists(pool, &rule).await?;

        let changed = SdwanRepository::update_rule(pool, id, &rule)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("SD-WAN rule {} does not exist", id));
        }

        Ok(())
    }

    pub async fn delete_rule(pool: &SqlitePool, id: i64) -> Result<(), String> {
        let changed = SdwanRepository::delete_rule(pool, id)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("SD-WAN rule {} does not exist", id));
        }

        Ok(())
    }

    async fn check_rule_name_free(
        pool: &SqlitePool,
        rule: &SdwanRule,
        self_id: Option<i64>,
    ) -> Result<(), String> {
        let same_name = SdwanRepository::get_rule_by_name(pool, &rule.name)
            .await
            .map_err(|e| e.to_string())?;

        if let Some(other) = same_name {
            if other.id != self_id {
                return Err(format!("A rule named '{}' already exists", rule.name));
            }
        }

        Ok(())
    }

    async fn check_rule_link_exists(pool: &SqlitePool, rule: &SdwanRule) -> Result<(), String> {
        if let Some(link_id) = rule.link_id {
            let link = SdwanRepository::get_link(pool, link_id)
                .await
                .map_err(|e| e.to_string())?;

            if link.is_none() {
                return Err(format!("Link {} does not exist", link_id));
            }
        }

        Ok(())
    }

    // ----------------------------------------------------- cleaning and checks

    fn clean_optional(value: Option<String>) -> Option<String> {
        value
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    pub fn normalize_link(link: &mut SdwanLink) {
        link.name = link.name.trim().to_string();
        link.interface_name = link.interface_name.trim().to_string();

        link.gateway = Self::clean_optional(link.gateway.take()).map(|value| {
            match Ipv4Addr::from_str(&value) {
                Ok(ip) => ip.to_string(),
                Err(_) => value,
            }
        });

        let target = link.probe_target.trim().to_string();
        link.probe_target = match Ipv4Addr::from_str(&target) {
            Ok(ip) => ip.to_string(),
            Err(_) => target,
        };

        link.comment = Self::clean_optional(link.comment.take());
    }

    pub fn validate_link(link: &SdwanLink) -> Result<(), String> {
        Self::check_name(&link.name, "Link name")?;
        Self::check_comment(&link.comment)?;
        Self::validate_interface_name(&link.interface_name)?;

        if let Some(raw) = &link.gateway {
            let gateway = Ipv4Addr::from_str(raw)
                .map_err(|_| format!("Gateway '{}' is not a valid IPv4 address", raw))?;

            Self::check_host_address(gateway, "Gateway", raw)?;
        }

        let target = Ipv4Addr::from_str(&link.probe_target).map_err(|_| {
            format!(
                "Probe target '{}' is not a valid IPv4 address",
                link.probe_target
            )
        })?;
        Self::check_host_address(target, "Probe target", &link.probe_target)?;

        Self::check_range(link.priority, MIN_PRIORITY, MAX_PRIORITY, "Priority")?;
        Self::check_range(link.weight, MIN_WEIGHT, MAX_WEIGHT, "Weight")?;
        Self::check_range(
            link.probe_interval_secs,
            MIN_PROBE_INTERVAL_SECS,
            MAX_PROBE_INTERVAL_SECS,
            "Probe interval",
        )?;
        Self::check_range(
            link.probe_timeout_secs,
            MIN_PROBE_TIMEOUT_SECS,
            MAX_PROBE_TIMEOUT_SECS,
            "Probe timeout",
        )?;
        Self::check_range(
            link.fail_threshold,
            MIN_THRESHOLD,
            MAX_THRESHOLD,
            "Fail threshold",
        )?;
        Self::check_range(
            link.recover_threshold,
            MIN_THRESHOLD,
            MAX_THRESHOLD,
            "Recover threshold",
        )?;

        if link.probe_timeout_secs > link.probe_interval_secs {
            return Err("Probe timeout cannot be longer than the probe interval".into());
        }

        Ok(())
    }

    pub fn normalize_rule(rule: &mut SdwanRule) {
        rule.name = rule.name.trim().to_string();
        rule.src_cidr = Self::normalize_network(rule.src_cidr.take());
        rule.dst_cidr = Self::normalize_network(rule.dst_cidr.take());
        rule.protocol = rule.protocol.trim().to_lowercase();
        rule.strategy = rule.strategy.trim().to_lowercase();
        rule.on_link_down = rule.on_link_down.trim().to_lowercase();
        rule.comment = Self::clean_optional(rule.comment.take());

        // One port is a range of one.
        if rule.dport_start.is_some() && rule.dport_end.is_none() {
            rule.dport_end = rule.dport_start;
        }

        // Only a "link" rule names a link.
        if rule.strategy != "link" {
            rule.link_id = None;
        }
    }

    fn normalize_network(value: Option<String>) -> Option<String> {
        Self::clean_optional(value).map(|v| match Ipv4Addr::from_str(&v) {
            Ok(ip) => format!("{}/32", ip),
            Err(_) => v,
        })
    }

    pub fn validate_rule(rule: &SdwanRule) -> Result<(), String> {
        Self::check_name(&rule.name, "Rule name")?;
        Self::check_comment(&rule.comment)?;

        if !(1..=9999).contains(&rule.position) {
            return Err("Position must be between 1 and 9999".into());
        }

        if let Some(src) = &rule.src_cidr {
            Self::validate_network(src, "Source")?;
        }

        if let Some(dst) = &rule.dst_cidr {
            Self::validate_network(dst, "Destination")?;
        }

        if !PROTOCOLS.contains(&rule.protocol.as_str()) {
            return Err(format!(
                "Protocol '{}' is not valid (use any, tcp, udp or icmp)",
                rule.protocol
            ));
        }

        match (rule.dport_start, rule.dport_end) {
            (None, None) => {}
            (Some(start), Some(end)) => {
                if rule.protocol != "tcp" && rule.protocol != "udp" {
                    return Err("Ports can only be used with the tcp or udp protocol".into());
                }

                if !(1..=65535).contains(&start) || !(1..=65535).contains(&end) {
                    return Err("Ports must be between 1 and 65535".into());
                }

                if start > end {
                    return Err("The first port cannot be higher than the last port".into());
                }
            }
            _ => return Err("A destination port range needs both a first and a last port".into()),
        }

        if !STRATEGIES.contains(&rule.strategy.as_str()) {
            return Err(format!(
                "Strategy '{}' is not valid (use link, balance or best_quality)",
                rule.strategy
            ));
        }

        if rule.strategy == "link" && rule.link_id.is_none() {
            return Err("A 'link' rule must say which link to use".into());
        }

        if rule.strategy != "link" && rule.link_id.is_some() {
            return Err("Only a 'link' rule can name a link".into());
        }

        if !ON_LINK_DOWN.contains(&rule.on_link_down.as_str()) {
            return Err(format!(
                "On-link-down '{}' is not valid (use fallback or block)",
                rule.on_link_down
            ));
        }

        Ok(())
    }

    fn validate_network(value: &str, label: &str) -> Result<(), String> {
        let net = Ipv4Net::from_str(value).map_err(|_| {
            format!(
                "{} '{}' is not a valid IPv4 network (example: 192.168.10.0/24)",
                label, value
            )
        })?;

        if net != net.trunc() {
            return Err(format!(
                "{} '{}' has host bits set - did you mean '{}'?",
                label,
                value,
                net.trunc()
            ));
        }

        Ok(())
    }

    fn check_name(name: &str, label: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err(format!("{} cannot be empty", label));
        }

        if name.chars().count() > MAX_NAME_LEN {
            return Err(format!(
                "{} cannot be longer than {} characters",
                label, MAX_NAME_LEN
            ));
        }

        if name
            .chars()
            .any(|c| c.is_control() || c == '"' || c == '\\')
        {
            return Err(format!("{} contains invalid characters", label));
        }

        Ok(())
    }

    fn check_comment(comment: &Option<String>) -> Result<(), String> {
        if let Some(comment) = comment {
            if comment.chars().count() > MAX_COMMENT_LEN {
                return Err(format!(
                    "Comment cannot be longer than {} characters",
                    MAX_COMMENT_LEN
                ));
            }

            if comment.chars().any(|c| c.is_control()) {
                return Err("Comment contains invalid characters".into());
            }
        }

        Ok(())
    }

    fn check_host_address(ip: Ipv4Addr, label: &str, raw: &str) -> Result<(), String> {
        if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast() {
            return Err(format!("{} '{}' is not a usable host address", label, raw));
        }

        Ok(())
    }

    fn check_range(value: i64, min: i64, max: i64, label: &str) -> Result<(), String> {
        if value < min || value > max {
            return Err(format!("{} must be between {} and {}", label, min, max));
        }

        Ok(())
    }

    fn validate_interface_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("Link interface cannot be empty".into());
        }

        if name.len() > 15 {
            return Err(format!(
                "Link interface '{}' is too long for a Linux interface name",
                name
            ));
        }

        let valid = name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');

        if !valid || name.starts_with('-') || name == "." || name == ".." {
            return Err(format!(
                "Link interface '{}' contains invalid characters",
                name
            ));
        }

        if name == "lo" {
            return Err("The loopback interface cannot be a WAN link".into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::init::initialize_database;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        initialize_database(&pool).await.unwrap();
        pool
    }

    fn link(name: &str, iface: &str) -> SdwanLink {
        SdwanLink {
            id: None,
            name: name.to_string(),
            interface_name: iface.to_string(),
            gateway: Some("192.168.1.1".to_string()),
            enabled: true,
            priority: 10,
            weight: 1,
            probe_target: "1.1.1.1".to_string(),
            probe_interval_secs: 5,
            probe_timeout_secs: 2,
            fail_threshold: 3,
            recover_threshold: 2,
            comment: None,
            state: "unknown".to_string(),
            latency_ms: None,
            loss_pct: None,
            last_check: None,
            last_change: None,
            last_error: None,
        }
    }

    fn rule(name: &str) -> SdwanRule {
        SdwanRule {
            id: None,
            name: name.to_string(),
            enabled: true,
            position: 100,
            src_cidr: None,
            dst_cidr: None,
            protocol: "any".to_string(),
            dport_start: None,
            dport_end: None,
            strategy: "balance".to_string(),
            link_id: None,
            on_link_down: "fallback".to_string(),
            comment: None,
        }
    }

    fn link_check(mut l: SdwanLink) -> Result<(), String> {
        SdwanService::normalize_link(&mut l);
        SdwanService::validate_link(&l)
    }

    fn rule_check(mut r: SdwanRule) -> Result<(), String> {
        SdwanService::normalize_rule(&mut r);
        SdwanService::validate_rule(&r)
    }

    // ---------------------------------------------------------- link checks

    #[test]
    fn a_normal_link_is_valid() {
        assert!(link_check(link("ISP1", "enp3s0")).is_ok());
    }

    #[test]
    fn a_link_without_a_gateway_is_valid() {
        let mut l = link("ISP1", "ppp0");
        l.gateway = None;
        assert!(link_check(l).is_ok());
    }

    #[test]
    fn normalizing_a_link_trims_and_cleans() {
        let mut l = link("  ISP1  ", " enp3s0 ");
        l.gateway = Some(" 10.0.0.1 ".to_string());
        l.probe_target = " 8.8.8.8 ".to_string();
        l.comment = Some("   ".to_string());

        SdwanService::normalize_link(&mut l);

        assert_eq!(l.name, "ISP1");
        assert_eq!(l.interface_name, "enp3s0");
        assert_eq!(l.gateway.as_deref(), Some("10.0.0.1"));
        assert_eq!(l.probe_target, "8.8.8.8");
        assert_eq!(l.comment, None);

        let mut blank = link("ISP1", "enp3s0");
        blank.gateway = Some("   ".to_string());
        SdwanService::normalize_link(&mut blank);
        assert_eq!(blank.gateway, None);
    }

    #[test]
    fn bad_names_are_refused() {
        assert!(link_check(link("", "enp3s0")).is_err());
        assert!(link_check(link("   ", "enp3s0")).is_err());
        assert!(link_check(link(&"x".repeat(41), "enp3s0")).is_err());
        assert!(link_check(link("bad\"name", "enp3s0")).is_err());
        assert!(link_check(link("bad\\name", "enp3s0")).is_err());
        assert!(link_check(link("bad\nname", "enp3s0")).is_err());
        assert!(link_check(link(&"x".repeat(40), "enp3s0")).is_ok());
    }

    #[test]
    fn bad_interface_names_are_refused() {
        for name in [
            "",
            "enp3s0 up",
            "-rf",
            "eth0;reboot",
            "a-very-long-interface-name",
            ".",
            "..",
            "lo",
        ] {
            assert!(link_check(link("ISP1", name)).is_err(), "{:?}", name);
        }

        for name in ["enp3s0", "eth0.10", "wan_1", "ppp0", "wg-uplink"] {
            assert!(link_check(link("ISP1", name)).is_ok(), "{:?}", name);
        }
    }

    #[test]
    fn bad_gateways_are_refused() {
        for gw in [
            "10.0.0.256",
            "0.0.0.0",
            "127.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "10.0.0.1; reboot",
            "gateway",
        ] {
            let mut l = link("ISP1", "enp3s0");
            l.gateway = Some(gw.to_string());
            assert!(link_check(l).is_err(), "{}", gw);
        }
    }

    #[test]
    fn bad_probe_targets_are_refused() {
        for target in ["", "example.com", "0.0.0.0", "127.0.0.1", "224.0.0.1", "1.1.1.1; ls", "::1"] {
            let mut l = link("ISP1", "enp3s0");
            l.probe_target = target.to_string();
            assert!(link_check(l).is_err(), "{:?}", target);
        }
    }

    #[test]
    fn numbers_must_be_in_range() {
        for case in 0..11 {
            let mut l = link("ISP1", "enp3s0");

            match case {
                0 => l.priority = 0,
                1 => l.priority = 101,
                2 => l.weight = 0,
                3 => l.weight = 101,
                4 => l.probe_interval_secs = 0,
                5 => l.probe_interval_secs = 3601,
                6 => l.probe_timeout_secs = 0,
                7 => l.fail_threshold = 0,
                8 => l.fail_threshold = 21,
                9 => l.recover_threshold = 0,
                _ => l.recover_threshold = 21,
            }

            assert!(link_check(l).is_err(), "case {}", case);
        }
    }

    #[test]
    fn the_timeout_cannot_be_longer_than_the_interval() {
        let mut l = link("ISP1", "enp3s0");
        l.probe_interval_secs = 3;
        l.probe_timeout_secs = 5;
        assert!(link_check(l).is_err());

        let mut ok = link("ISP1", "enp3s0");
        ok.probe_interval_secs = 5;
        ok.probe_timeout_secs = 5;
        assert!(link_check(ok).is_ok());
    }

    #[test]
    fn a_long_or_odd_comment_is_refused() {
        let mut l = link("ISP1", "enp3s0");
        l.comment = Some("x".repeat(201));
        assert!(link_check(l).is_err());

        let mut l = link("ISP1", "enp3s0");
        l.comment = Some("two\nlines".to_string());
        assert!(link_check(l).is_err());

        let mut l = link("ISP1", "enp3s0");
        l.comment = Some("x".repeat(200));
        assert!(link_check(l).is_ok());
    }

    // ---------------------------------------------------------- rule checks

    #[test]
    fn a_catch_all_balance_rule_is_valid() {
        assert!(rule_check(rule("spread")).is_ok());
    }

    #[test]
    fn a_full_voice_rule_is_valid() {
        let mut r = rule("voice");
        r.src_cidr = Some("192.168.10.0/24".to_string());
        r.dst_cidr = Some("203.0.113.0/24".to_string());
        r.protocol = "udp".to_string();
        r.dport_start = Some(10000);
        r.dport_end = Some(20000);
        r.strategy = "link".to_string();
        r.link_id = Some(1);
        r.on_link_down = "block".to_string();

        assert!(rule_check(r).is_ok());
    }

    #[test]
    fn normalizing_a_rule_cleans_networks_words_and_ports() {
        let mut r = rule("  web  ");
        r.src_cidr = Some(" 192.168.10.7 ".to_string());
        r.dst_cidr = Some("   ".to_string());
        r.protocol = " TCP ".to_string();
        r.strategy = " Balance ".to_string();
        r.on_link_down = " BLOCK ".to_string();
        r.dport_start = Some(443);
        r.dport_end = None;
        r.link_id = Some(9);

        SdwanService::normalize_rule(&mut r);

        assert_eq!(r.name, "web");
        assert_eq!(r.src_cidr.as_deref(), Some("192.168.10.7/32"));
        assert_eq!(r.dst_cidr, None);
        assert_eq!(r.protocol, "tcp");
        assert_eq!(r.strategy, "balance");
        assert_eq!(r.on_link_down, "block");
        assert_eq!(r.dport_start, Some(443));
        assert_eq!(r.dport_end, Some(443));
        assert_eq!(r.link_id, None);
    }

    #[test]
    fn bad_networks_are_refused() {
        for net in ["10.0.0.0/33", "abc", "10.0.0.5/24", "::1", "10.0.0.0/24; ls", "10.0.0"] {
            let mut r = rule("r");
            r.src_cidr = Some(net.to_string());
            assert!(rule_check(r.clone()).is_err(), "src {}", net);

            let mut r = rule("r");
            r.dst_cidr = Some(net.to_string());
            assert!(rule_check(r).is_err(), "dst {}", net);
        }
    }

    #[test]
    fn ports_need_tcp_or_udp_and_must_make_sense() {
        let with_ports = |proto: &str, start: Option<i64>, end: Option<i64>| {
            let mut r = rule("r");
            r.protocol = proto.to_string();
            r.dport_start = start;
            r.dport_end = end;
            r
        };

        assert!(rule_check(with_ports("tcp", Some(80), Some(443))).is_ok());
        assert!(rule_check(with_ports("udp", Some(53), None)).is_ok());
        assert!(rule_check(with_ports("any", Some(80), Some(80))).is_err());
        assert!(rule_check(with_ports("icmp", Some(80), Some(80))).is_err());
        assert!(rule_check(with_ports("tcp", None, Some(80))).is_err());
        assert!(rule_check(with_ports("tcp", Some(0), Some(10))).is_err());
        assert!(rule_check(with_ports("tcp", Some(10), Some(70000))).is_err());
        assert!(rule_check(with_ports("udp", Some(500), Some(400))).is_err());
    }

    #[test]
    fn strategy_and_link_must_agree() {
        let mut pinned = rule("r");
        pinned.strategy = "link".to_string();
        assert!(rule_check(pinned.clone()).is_err());

        pinned.link_id = Some(1);
        assert!(rule_check(pinned).is_ok());

        // normalizing drops a stray link from a balance rule...
        let mut balance = rule("r");
        balance.link_id = Some(1);
        assert!(rule_check(balance.clone()).is_ok());

        // ...but checking an un-normalized one still catches it
        assert!(SdwanService::validate_rule(&balance).is_err());

        let mut quality = rule("r");
        quality.strategy = "best_quality".to_string();
        assert!(rule_check(quality).is_ok());
    }

    #[test]
    fn unknown_words_and_positions_are_refused() {
        let mut r = rule("r");
        r.protocol = "gre".to_string();
        assert!(rule_check(r).is_err());

        let mut r = rule("r");
        r.strategy = "random".to_string();
        assert!(rule_check(r).is_err());

        let mut r = rule("r");
        r.on_link_down = "panic".to_string();
        assert!(rule_check(r).is_err());

        let mut r = rule("r");
        r.position = 0;
        assert!(rule_check(r).is_err());

        let mut r = rule("r");
        r.position = 10000;
        assert!(rule_check(r).is_err());

        assert!(rule_check(rule("")).is_err());
        assert!(rule_check(rule("bad\"name")).is_err());
    }

    // ------------------------------------------------------ database checks

    #[tokio::test]
    async fn links_can_be_added_listed_updated_and_deleted() {
        let pool = memory_pool().await;

        let id = SdwanService::add_link(&pool, link("ISP1", "enp3s0")).await.unwrap();

        let links = SdwanService::list_links(&pool).await.unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].id, Some(id));

        // renaming to its own name is fine
        let mut changed = link("ISP1", "enp3s0");
        changed.weight = 5;
        SdwanService::update_link(&pool, id, changed).await.unwrap();
        assert_eq!(SdwanService::list_links(&pool).await.unwrap()[0].weight, 5);

        assert!(SdwanService::update_link(&pool, 999, link("x", "enp9s0")).await.is_err());

        SdwanService::delete_link(&pool, id).await.unwrap();
        assert!(SdwanService::list_links(&pool).await.unwrap().is_empty());
        assert!(SdwanService::delete_link(&pool, id).await.is_err());
    }

    #[tokio::test]
    async fn duplicate_link_names_and_interfaces_are_refused() {
        let pool = memory_pool().await;
        SdwanService::add_link(&pool, link("ISP1", "enp3s0")).await.unwrap();
        let second = SdwanService::add_link(&pool, link("ISP2", "enp5s0")).await.unwrap();

        let name_error = SdwanService::add_link(&pool, link("isp1", "enp6s0")).await.unwrap_err();
        assert!(name_error.contains("already exists"), "{}", name_error);

        let iface_error = SdwanService::add_link(&pool, link("ISP3", "enp3s0")).await.unwrap_err();
        assert!(iface_error.contains("already used"), "{}", iface_error);

        // moving link two onto link one's name or interface is refused as well
        assert!(SdwanService::update_link(&pool, second, link("ISP1", "enp5s0")).await.is_err());
        assert!(SdwanService::update_link(&pool, second, link("ISP2", "enp3s0")).await.is_err());
    }

    #[tokio::test]
    async fn the_lan_interface_cannot_be_a_wan_link_but_the_wan_interface_can() {
        let pool = memory_pool().await;

        // the fresh database has wan = eth0 and lan = eth1
        let error = SdwanService::add_link(&pool, link("bad", "eth1")).await.unwrap_err();
        assert!(error.contains("LAN"), "{}", error);

        assert!(SdwanService::add_link(&pool, link("ISP1", "eth0")).await.is_ok());
    }

    #[tokio::test]
    async fn only_sixteen_links_are_allowed() {
        let pool = memory_pool().await;

        for i in 0..MAX_LINKS {
            SdwanService::add_link(&pool, link(&format!("l{}", i), &format!("wan{}", i)))
                .await
                .unwrap();
        }

        let error = SdwanService::add_link(&pool, link("one-too-many", "wan99")).await.unwrap_err();
        assert!(error.contains("At most"), "{}", error);
    }

    #[tokio::test]
    async fn a_link_used_by_a_rule_cannot_be_deleted() {
        let pool = memory_pool().await;
        let link_id = SdwanService::add_link(&pool, link("ISP1", "enp3s0")).await.unwrap();

        let mut pinned = rule("voice");
        pinned.strategy = "link".to_string();
        pinned.link_id = Some(link_id);
        let rule_id = SdwanService::add_rule(&pool, pinned).await.unwrap();

        let error = SdwanService::delete_link(&pool, link_id).await.unwrap_err();
        assert!(error.contains("1 rule"), "{}", error);

        SdwanService::delete_rule(&pool, rule_id).await.unwrap();
        SdwanService::delete_link(&pool, link_id).await.unwrap();
    }

    #[tokio::test]
    async fn a_rule_must_point_at_a_link_that_exists() {
        let pool = memory_pool().await;

        let mut pinned = rule("voice");
        pinned.strategy = "link".to_string();
        pinned.link_id = Some(42);

        let error = SdwanService::add_rule(&pool, pinned).await.unwrap_err();
        assert!(error.contains("does not exist"), "{}", error);
    }

    #[tokio::test]
    async fn rules_can_be_added_updated_and_deleted() {
        let pool = memory_pool().await;

        let id = SdwanService::add_rule(&pool, rule("web")).await.unwrap();
        assert_eq!(SdwanService::list_rules(&pool).await.unwrap().len(), 1);

        let mut changed = rule("web");
        changed.protocol = "tcp".to_string();
        changed.dport_start = Some(443);
        SdwanService::update_rule(&pool, id, changed).await.unwrap();

        let got = SdwanService::list_rules(&pool).await.unwrap();
        assert_eq!(got[0].dport_start, Some(443));
        assert_eq!(got[0].dport_end, Some(443));

        assert!(SdwanService::update_rule(&pool, 999, rule("x")).await.is_err());

        SdwanService::delete_rule(&pool, id).await.unwrap();
        assert!(SdwanService::delete_rule(&pool, id).await.is_err());
    }

    #[tokio::test]
    async fn duplicate_rule_names_are_refused() {
        let pool = memory_pool().await;
        SdwanService::add_rule(&pool, rule("web")).await.unwrap();
        let other = SdwanService::add_rule(&pool, rule("dns")).await.unwrap();

        let error = SdwanService::add_rule(&pool, rule("WEB")).await.unwrap_err();
        assert!(error.contains("already exists"), "{}", error);

        assert!(SdwanService::update_rule(&pool, other, rule("web")).await.is_err());
        assert!(SdwanService::update_rule(&pool, other, rule("dns")).await.is_ok());
    }

    #[tokio::test]
    async fn only_two_hundred_rules_are_allowed() {
        let pool = memory_pool().await;

        for i in 0..MAX_RULES {
            SdwanService::add_rule(&pool, rule(&format!("r{}", i))).await.unwrap();
        }

        let error = SdwanService::add_rule(&pool, rule("one-too-many")).await.unwrap_err();
        assert!(error.contains("At most"), "{}", error);
    }

    #[tokio::test]
    async fn sdwan_needs_an_enabled_link_before_it_can_be_switched_on() {
        let pool = memory_pool().await;

        assert!(!SdwanService::get_settings(&pool).await.unwrap().enabled);
        assert!(SdwanService::set_enabled(&pool, true).await.is_err());

        let mut off = link("ISP1", "enp3s0");
        off.enabled = false;
        SdwanService::add_link(&pool, off).await.unwrap();
        assert!(SdwanService::set_enabled(&pool, true).await.is_err());

        SdwanService::add_link(&pool, link("ISP2", "enp5s0")).await.unwrap();
        SdwanService::set_enabled(&pool, true).await.unwrap();
        assert!(SdwanService::get_settings(&pool).await.unwrap().enabled);

        // switching off is always allowed
        SdwanService::set_enabled(&pool, false).await.unwrap();
        assert!(!SdwanService::get_settings(&pool).await.unwrap().enabled);
    }
}
