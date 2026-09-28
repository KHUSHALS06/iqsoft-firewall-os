use crate::models::firewall_rule::{normalize_rate_limit, FirewallRule};
use crate::models::address::Family;
use crate::repository::address_repository::REF_PREFIX;
use crate::repository::firewall_repository::FirewallRepository;
use crate::services::address_service::AddressService;
use ipnet::IpNet;
use sqlx::SqlitePool;
pub struct FirewallService;
impl FirewallService {
    pub async fn add_rule(
        pool: &SqlitePool,
        rule: FirewallRule,
    ) -> Result<(), String> {
        Self::validate_rule(pool, &rule).await?;
        FirewallRepository::add_rule(pool, rule)
            .await
            .map_err(|e| e.to_string())
    }
    pub async fn list_rules(
        pool: &SqlitePool,
    ) -> Result<Vec<FirewallRule>, String> {
        FirewallRepository::list_rules(pool)
            .await
            .map_err(|e| e.to_string())
    }
    pub async fn update_rule(
        pool: &SqlitePool,
        id: i64,
        rule: FirewallRule,
    ) -> Result<(), String> {
        Self::validate_rule(pool, &rule).await?;
        FirewallRepository::update_rule(pool, id, rule)
            .await
            .map_err(|e| e.to_string())
    }
    pub async fn delete_rule(
        pool: &SqlitePool,
        id: i64,
    ) -> Result<(), String> {
        FirewallRepository::delete_rule(pool, id)
            .await
            .map_err(|e| e.to_string())
    }
    async fn validate_rule(pool: &SqlitePool, rule: &FirewallRule) -> Result<(), String> {
        if rule.name.trim().is_empty() {
            return Err("Rule name cannot be empty".into());
        }

        if rule.name.chars().any(|c| c.is_control()) {
            return Err("Rule name cannot contain control characters or line breaks".into());
        }
        match rule.action.as_str() {
            "accept" | "drop" | "reject" => {}
            _ => return Err("Invalid action".into()),
        }
        match rule.chain_name.as_str() {
            "INPUT" | "FORWARD" | "OUTPUT" => {}
            _ => return Err("Invalid chain".into()),
        }
        match rule.protocol.as_str() {
            "any" | "tcp" | "udp" | "icmp" => {}
            _ => return Err("Invalid protocol".into()),
        }
        if rule.priority < 0 {
            return Err("Priority must be >= 0".into());
        }

        if let Some(iface) = &rule.interface_name {
            Self::validate_interface_name(iface)?;
        }

        if let Some(rate) = &rule.rate_limit {
            let trimmed = rate.trim();

            if !trimmed.is_empty() && normalize_rate_limit(trimmed).is_none() {
                return Err(format!(
                    "Invalid rate limit '{}': use a format like 10/second, 60/minute, 100/hour or 1000/day",
                    trimmed
                ));
            }
        }
        let src_is_v6 = match &rule.src_ip {
            Some(value) => Self::address_is_v6(pool, value, "Source IP").await?,
            None => None,
        };
        let dst_is_v6 = match &rule.dst_ip {
            Some(value) => Self::address_is_v6(pool, value, "Destination IP").await?,
            None => None,
        };
        if let (Some(src_is_v6), Some(dst_is_v6)) = (src_is_v6, dst_is_v6) {
            if src_is_v6 != dst_is_v6 {
                return Err(
                    "Source IP and destination IP must be the same IP version (both IPv4 or both IPv6)".into(),
                );
            }
        }
        if let Some(port) = rule.src_port {
            if port <= 0 || port > 65535 {
                return Err("Invalid source port".into());
            }
        }
        if let Some(port) = rule.dst_port {
            if port <= 0 || port > 65535 {
                return Err("Invalid destination port".into());
            }
        }
        match rule.protocol.as_str() {
            "icmp" | "any" => {
                if rule.src_port.is_some() || rule.dst_port.is_some() {
                    return Err(
                        "Ports are only valid for TCP/UDP rules".into(),
                    );
                }
                if rule.port_any {
                    return Err(
                        "port_any is only valid for TCP/UDP rules".into(),
                    );
                }
            }
            "tcp" | "udp" => {
                if rule.dst_port.is_none() && !rule.port_any {
                    return Err(
                        "TCP/UDP rules must set dst_port, or explicitly set port_any = true to allow all ports".into(),
                    );
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Validates a src_ip / dst_ip value and returns its IP version
    /// (Some(true) = IPv6), or None when the field is empty.
    ///
    /// The value is either a literal IP / CIDR, or `@name` referring to an
    /// address object or group, which must exist and must not be empty.
    async fn address_is_v6(
        pool: &SqlitePool,
        value: &str,
        field_label: &str,
    ) -> Result<Option<bool>, String> {
        let trimmed = value.trim();

        if trimmed.is_empty() {
            return Ok(None);
        }

        if trimmed.starts_with(REF_PREFIX) {
            let family = AddressService::resolve_reference(pool, trimmed, field_label).await?;
            return Ok(Some(family == Family::V6));
        }

        Self::validate_ip_or_cidr(trimmed, field_label)?;
        Ok(Self::ip_is_v6(trimmed))
    }

    fn validate_interface_name(value: &str) -> Result<(), String> {
        let trimmed = value.trim();

        if trimmed.is_empty() {
            return Ok(());
        }

        if trimmed.len() > 15 {
            return Err(format!(
                "Interface '{}' is too long for a Linux interface name",
                trimmed
            ));
        }

        if !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        {
            return Err(format!(
                "Interface '{}' contains invalid characters (allowed: letters, digits, _ - .)",
                trimmed
            ));
        }

        Ok(())
    }

    fn validate_ip_or_cidr(value: &str, field_label: &str) -> Result<(), String> {
        let trimmed = value.trim();
        if trimmed.is_empty() {

            return Ok(());
        }

        if trimmed.parse::<IpNet>().is_ok() {
            return Ok(());
        }
        if trimmed.parse::<std::net::IpAddr>().is_ok() {
            return Ok(());
        }
        Err(format!(
            "{} is not a valid IP address or CIDR range: '{}'",
            field_label, trimmed
        ))
    }

    /// Returns Some(true) for IPv6, Some(false) for IPv4, None if unparseable.
    fn ip_is_v6(value: &str) -> Option<bool> {
        let trimmed = value.trim();
        if let Ok(net) = trimmed.parse::<IpNet>() {
            return Some(matches!(net, IpNet::V6(_)));
        }
        if let Ok(addr) = trimmed.parse::<std::net::IpAddr>() {
            return Some(matches!(addr, std::net::IpAddr::V6(_)));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::init::initialize_database;
    use crate::firewall::generator::FirewallGenerator;
    use crate::models::address::{AddressGroup, AddressObject};
    use sqlx::sqlite::SqlitePoolOptions;

    async fn memory_pool() -> SqlitePool {
        // One connection, otherwise every connection would get its own empty in-memory database.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        initialize_database(&pool).await.unwrap();
        pool
    }

    fn rule(src: Option<&str>, dst: Option<&str>) -> FirewallRule {
        FirewallRule {
            id: None,
            name: "test rule".into(),
            enabled: true,
            priority: 100,
            chain_name: "FORWARD".into(),
            action: "accept".into(),
            protocol: "tcp".into(),
            src_ip: src.map(String::from),
            dst_ip: dst.map(String::from),
            src_port: None,
            dst_port: Some(443),
            port_any: false,
            interface_name: None,
            rate_limit: None,
            log_enabled: false,
            comment: None,
        }
    }

    async fn add_object(pool: &SqlitePool, name: &str, value: &str) {
        let kind = if value.contains('/') { "subnet" } else { "host" };

        AddressService::add_object(
            pool,
            AddressObject {
                id: None,
                name: name.into(),
                kind: kind.into(),
                value: value.into(),
                family: String::new(),
                comment: None,
            },
        )
        .await
        .unwrap();
    }

    async fn add_group(pool: &SqlitePool, name: &str, members: &[&str]) {
        AddressService::add_group(
            pool,
            AddressGroup {
                id: None,
                name: name.into(),
                family: String::new(),
                comment: None,
                members: members.iter().map(|m| m.to_string()).collect(),
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn literal_addresses_still_work() {
        let pool = memory_pool().await;

        assert!(FirewallService::add_rule(&pool, rule(Some("10.0.0.0/24"), Some("10.1.0.1"))).await.is_ok());
        assert!(FirewallService::add_rule(&pool, rule(Some("2001:db8::/32"), None)).await.is_ok());
        assert!(FirewallService::add_rule(&pool, rule(Some(""), Some("  "))).await.is_ok());
    }

    #[tokio::test]
    async fn literal_errors_are_unchanged() {
        let pool = memory_pool().await;

        let err = FirewallService::add_rule(&pool, rule(Some("10.0.0.256"), None)).await.unwrap_err();
        assert_eq!(err, "Source IP is not a valid IP address or CIDR range: '10.0.0.256'");

        let err = FirewallService::add_rule(&pool, rule(None, Some("nonsense"))).await.unwrap_err();
        assert_eq!(err, "Destination IP is not a valid IP address or CIDR range: 'nonsense'");

        let err = FirewallService::add_rule(&pool, rule(Some("10.0.0.1"), Some("2001:db8::1"))).await.unwrap_err();
        assert!(err.contains("same IP version"));
    }

    #[tokio::test]
    async fn object_and_group_references_are_accepted() {
        let pool = memory_pool().await;
        add_object(&pool, "web1", "10.0.0.1").await;
        add_group(&pool, "servers", &["web1"]).await;

        assert!(FirewallService::add_rule(&pool, rule(Some("@web1"), None)).await.is_ok());
        assert!(FirewallService::add_rule(&pool, rule(None, Some("@servers"))).await.is_ok());
        assert!(FirewallService::add_rule(&pool, rule(Some(" @WEB1 "), Some("@servers"))).await.is_ok());
        assert!(FirewallService::add_rule(&pool, rule(Some("@web1"), Some("10.9.0.0/16"))).await.is_ok());

        assert_eq!(FirewallService::list_rules(&pool).await.unwrap().len(), 4);
    }

    #[tokio::test]
    async fn bad_references_are_refused_with_a_clear_message() {
        let pool = memory_pool().await;
        add_object(&pool, "web1", "10.0.0.1").await;
        add_group(&pool, "empty_grp", &[]).await;

        let err = FirewallService::add_rule(&pool, rule(Some("@nope"), None)).await.unwrap_err();
        assert!(err.contains("Source IP") && err.contains("unknown address object or group 'nope'"));

        let err = FirewallService::add_rule(&pool, rule(None, Some("@empty_grp"))).await.unwrap_err();
        assert!(err.contains("Destination IP") && err.contains("has no members"));

        let err = FirewallService::add_rule(&pool, rule(Some("@"), None)).await.unwrap_err();
        assert!(err.contains("invalid reference"));

        let err = FirewallService::add_rule(&pool, rule(Some("@web1; flush ruleset"), None)).await.unwrap_err();
        assert!(err.contains("invalid reference"));

        assert!(FirewallService::list_rules(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn ip_versions_are_checked_across_references_and_literals() {
        let pool = memory_pool().await;
        add_object(&pool, "v4host", "10.0.0.1").await;
        add_object(&pool, "v6host", "2001:db8::1").await;

        for (src, dst) in [
            ("@v4host", "@v6host"),
            ("@v4host", "2001:db8::9"),
            ("10.0.0.9", "@v6host"),
        ] {
            let err = FirewallService::add_rule(&pool, rule(Some(src), Some(dst))).await.unwrap_err();
            assert!(err.contains("same IP version"), "{} -> {}: {}", src, dst, err);
        }

        assert!(FirewallService::add_rule(&pool, rule(Some("@v6host"), Some("2001:db8::9"))).await.is_ok());
    }

    #[tokio::test]
    async fn update_rule_validates_references_too() {
        let pool = memory_pool().await;
        add_object(&pool, "web1", "10.0.0.1").await;
        FirewallService::add_rule(&pool, rule(Some("10.0.0.5"), None)).await.unwrap();
        let id = FirewallService::list_rules(&pool).await.unwrap()[0].id.unwrap();

        assert!(FirewallService::update_rule(&pool, id, rule(Some("@nope"), None)).await.is_err());
        assert!(FirewallService::update_rule(&pool, id, rule(Some("@web1"), None)).await.is_ok());

        let stored = FirewallService::list_rules(&pool).await.unwrap();
        assert_eq!(stored[0].src_ip.as_deref(), Some("@web1"));
    }

    #[tokio::test]
    async fn rule_using_an_object_blocks_its_deletion_end_to_end() {
        let pool = memory_pool().await;
        add_object(&pool, "web1", "10.0.0.1").await;
        FirewallService::add_rule(&pool, rule(None, Some("@web1"))).await.unwrap();

        let id = AddressService::list_objects(&pool).await.unwrap()[0].id.unwrap();
        let err = AddressService::delete_object(&pool, id).await.unwrap_err();

        assert!(err.contains("web1") && err.contains("test rule"), "{}", err);
    }

    #[tokio::test]
    async fn accepted_reference_reaches_the_generated_ruleset() {
        let pool = memory_pool().await;
        add_object(&pool, "web1", "10.0.0.1").await;
        add_object(&pool, "lan", "10.5.0.0/16").await;
        add_group(&pool, "clients", &["lan"]).await;
        FirewallService::add_rule(&pool, rule(Some("@clients"), Some("@web1"))).await.unwrap();

        let text = FirewallGenerator::generate(&pool).await.unwrap();

        assert!(text.contains("set addr_web1 {"));
        assert!(text.contains("set addr_clients {"));
        assert!(text.contains("ip saddr @addr_clients ip daddr @addr_web1 tcp dport 443"));
    }
}
