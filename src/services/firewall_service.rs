use crate::models::firewall_rule::FirewallRule;
use crate::repository::firewall_repository::FirewallRepository;
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
            }
            _ => {}
        }

        Ok(())
    }
}
