use crate::models::port_forward::PortForwardRule;
use crate::repository::port_forward_repository::PortForwardRepository;
use sqlx::SqlitePool;
use std::net::Ipv4Addr;

pub struct PortForwardService;

impl PortForwardService {
    pub async fn list_rules(pool: &SqlitePool) -> Result<Vec<PortForwardRule>, String> {
        PortForwardRepository::list_rules(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn add_rule(pool: &SqlitePool, mut rule: PortForwardRule) -> Result<(), String> {
        Self::normalize(&mut rule);
        Self::validate_rule(&rule)?;

        let existing = Self::list_rules(pool).await?;
        Self::check_overlap(&rule, None, &existing)?;

        PortForwardRepository::add_rule(pool, rule)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn update_rule(
        pool: &SqlitePool,
        id: i64,
        mut rule: PortForwardRule,
    ) -> Result<(), String> {
        Self::normalize(&mut rule);
        Self::validate_rule(&rule)?;

        let existing = Self::list_rules(pool).await?;
        Self::check_overlap(&rule, Some(id), &existing)?;

        let changed = PortForwardRepository::update_rule(pool, id, rule)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("Port forward rule {} does not exist", id));
        }

        Ok(())
    }

    pub async fn delete_rule(pool: &SqlitePool, id: i64) -> Result<(), String> {
        let changed = PortForwardRepository::delete_rule(pool, id)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("Port forward rule {} does not exist", id));
        }

        Ok(())
    }

    fn normalize(rule: &mut PortForwardRule) {
        rule.name = rule.name.trim().to_string();
        rule.protocol = rule.protocol.trim().to_lowercase();
        rule.internal_ip = rule.internal_ip.trim().to_string();
    }

    fn validate_rule(rule: &PortForwardRule) -> Result<(), String> {
        if rule.name.is_empty() {
            return Err("Rule name cannot be empty".into());
        }

        match rule.protocol.as_str() {
            "tcp" | "udp" | "both" => {}
            _ => return Err("Protocol must be 'tcp', 'udp' or 'both'".into()),
        }

        Self::validate_port(rule.external_port_start, "External start port")?;
        Self::validate_port(rule.external_port_end, "External end port")?;
        Self::validate_port(rule.internal_port_start, "Internal port")?;

        if rule.external_port_start > rule.external_port_end {
            return Err("External start port cannot be greater than the end port".into());
        }

        if rule.internal_port_end() > 65535 {
            return Err(
                "Internal port range goes past 65535 - lower the internal start port".into(),
            );
        }

        // A range is forwarded to the SAME port numbers on the internal host
        // (external 8000-8010 -> internal 8000-8010). Changing the port number
        // is only supported for a single port.
        if rule.external_port_start != rule.external_port_end
            && rule.internal_port_start != rule.external_port_start
        {
            return Err(
                "For a port range the internal start port must equal the external start port \
                 (ranges are forwarded to the same port numbers). Use a single port if you \
                 need the internal port to be different."
                    .into(),
            );
        }

        let ip: Ipv4Addr = rule
            .internal_ip
            .parse()
            .map_err(|_| format!("Internal IP is not a valid IPv4 address: '{}'", rule.internal_ip))?;

        if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast() {
            return Err(format!("Internal IP '{}' is not a usable host address", ip));
        }

        Ok(())
    }

    fn validate_port(port: i32, label: &str) -> Result<(), String> {
        if !(1..=65535).contains(&port) {
            return Err(format!("{} must be between 1 and 65535", label));
        }
        Ok(())
    }

    fn protocols_overlap(a: &str, b: &str) -> bool {
        a == "both" || b == "both" || a == b
    }

    /// Rejects a rule whose external port range collides with another rule
    /// (same protocol, or either side is 'both'). Disabled rules count too,
    /// so re-enabling one later can never create a hidden collision.
    fn check_overlap(
        rule: &PortForwardRule,
        self_id: Option<i64>,
        existing: &[PortForwardRule],
    ) -> Result<(), String> {
        for other in existing {
            if self_id.is_some() && other.id == self_id {
                continue;
            }

            if !Self::protocols_overlap(&rule.protocol, &other.protocol) {
                continue;
            }

            let ranges_overlap = rule.external_port_start <= other.external_port_end
                && other.external_port_start <= rule.external_port_end;

            if ranges_overlap {
                return Err(format!(
                    "External ports {}-{} ({}) overlap with existing rule '{}' (id {}) which uses {}-{} ({})",
                    rule.external_port_start,
                    rule.external_port_end,
                    rule.protocol,
                    other.name,
                    other.id.unwrap_or(0),
                    other.external_port_start,
                    other.external_port_end,
                    other.protocol,
                ));
            }
        }

        Ok(())
    }
}
