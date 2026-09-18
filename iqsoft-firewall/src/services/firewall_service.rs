use crate::models::firewall_rule::FirewallRule;
use crate::repository::firewall_repository::FirewallRepository;
use ipnet::IpNet;
use sqlx::SqlitePool;
pub struct FirewallService;
impl FirewallService {
    pub async fn add_rule(
        pool: &SqlitePool,
        rule: FirewallRule,
    ) -> Result<(), String> {
        Self::validate_rule(&rule)?;
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
        Self::validate_rule(&rule)?;
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
    fn validate_rule(rule: &FirewallRule) -> Result<(), String> {
        if rule.name.trim().is_empty() {
            return Err("Rule name cannot be empty".into());
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
        if let Some(src_ip) = &rule.src_ip {
            Self::validate_ip_or_cidr(src_ip, "Source IP")?;
        }
        if let Some(dst_ip) = &rule.dst_ip {
            Self::validate_ip_or_cidr(dst_ip, "Destination IP")?;
        }
        if let (Some(src_ip), Some(dst_ip)) = (&rule.src_ip, &rule.dst_ip) {
            let src_trimmed = src_ip.trim();
            let dst_trimmed = dst_ip.trim();
            if !src_trimmed.is_empty() && !dst_trimmed.is_empty() {
                if let (Some(src_is_v6), Some(dst_is_v6)) =
                    (Self::ip_is_v6(src_trimmed), Self::ip_is_v6(dst_trimmed))
                {
                    if src_is_v6 != dst_is_v6 {
                        return Err(
                            "Source IP and destination IP must be the same IP version (both IPv4 or both IPv6)".into(),
                        );
                    }
                }
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
