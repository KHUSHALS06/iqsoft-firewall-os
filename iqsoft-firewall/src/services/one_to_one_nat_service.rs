use crate::models::one_to_one_nat::OneToOneNatRule;
use crate::repository::one_to_one_nat_repository::OneToOneNatRepository;
use sqlx::SqlitePool;
use std::net::Ipv4Addr;

pub struct OneToOneNatService;

impl OneToOneNatService {
    pub async fn list_rules(pool: &SqlitePool) -> Result<Vec<OneToOneNatRule>, String> {
        OneToOneNatRepository::list_rules(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn add_rule(pool: &SqlitePool, mut rule: OneToOneNatRule) -> Result<(), String> {
        Self::prepare(&mut rule)?;

        let existing = Self::list_rules(pool).await?;
        Self::check_conflicts(&rule, None, &existing)?;

        OneToOneNatRepository::add_rule(pool, rule)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn update_rule(
        pool: &SqlitePool,
        id: i64,
        mut rule: OneToOneNatRule,
    ) -> Result<(), String> {
        Self::prepare(&mut rule)?;

        let existing = Self::list_rules(pool).await?;
        Self::check_conflicts(&rule, Some(id), &existing)?;

        let changed = OneToOneNatRepository::update_rule(pool, id, rule)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("1:1 NAT rule {} does not exist", id));
        }

        Ok(())
    }

    pub async fn delete_rule(pool: &SqlitePool, id: i64) -> Result<(), String> {
        let changed = OneToOneNatRepository::delete_rule(pool, id)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("1:1 NAT rule {} does not exist", id));
        }

        Ok(())
    }

    fn parse_host(value: &str, label: &str) -> Result<Ipv4Addr, String> {
        let ip: Ipv4Addr = value
            .parse()
            .map_err(|_| format!("{} is not a valid IPv4 address: '{}'", label, value))?;

        if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast() {
            return Err(format!("{} '{}' is not a usable host address", label, ip));
        }

        Ok(ip)
    }

    /// Trims, validates and rewrites both addresses in their canonical form.
    fn prepare(rule: &mut OneToOneNatRule) -> Result<(), String> {
        rule.name = rule.name.trim().to_string();

        if rule.name.is_empty() {
            return Err("Rule name cannot be empty".into());
        }

        let external = Self::parse_host(rule.external_ip.trim(), "External IP")?;
        let internal = Self::parse_host(rule.internal_ip.trim(), "Internal IP")?;

        if external == internal {
            return Err("External IP and internal IP must be different".into());
        }

        rule.external_ip = external.to_string();
        rule.internal_ip = internal.to_string();

        Ok(())
    }

    /// Disabled rules count too, so re-enabling one later can never create a
    /// hidden collision.
    fn check_conflicts(
        rule: &OneToOneNatRule,
        self_id: Option<i64>,
        existing: &[OneToOneNatRule],
    ) -> Result<(), String> {
        for other in existing {
            if self_id.is_some() && other.id == self_id {
                continue;
            }

            let other_id = other.id.unwrap_or(0);

            if rule.external_ip == other.external_ip {
                return Err(format!(
                    "External IP {} is already mapped by rule '{}' (id {})",
                    rule.external_ip, other.name, other_id
                ));
            }

            if rule.internal_ip == other.internal_ip {
                return Err(format!(
                    "Internal host {} already has a 1:1 NAT rule: '{}' (id {})",
                    rule.internal_ip, other.name, other_id
                ));
            }

            if rule.external_ip == other.internal_ip || rule.internal_ip == other.external_ip {
                return Err(format!(
                    "An address in this rule is already used on the other side by rule '{}' (id {})",
                    other.name, other_id
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: Option<i64>, ext: &str, int: &str) -> OneToOneNatRule {
        OneToOneNatRule {
            id,
            name: "test".into(),
            enabled: true,
            external_ip: ext.into(),
            internal_ip: int.into(),
            comment: None,
        }
    }

    #[test]
    fn accepts_a_normal_rule() {
        let mut r = rule(None, " 192.168.0.200 ", "192.168.10.50");
        assert!(OneToOneNatService::prepare(&mut r).is_ok());
        assert_eq!(r.external_ip, "192.168.0.200");
    }

    #[test]
    fn rejects_bad_addresses() {
        assert!(OneToOneNatService::prepare(&mut rule(None, "nope", "192.168.10.50")).is_err());
        assert!(OneToOneNatService::prepare(&mut rule(None, "0.0.0.0", "192.168.10.50")).is_err());
        assert!(OneToOneNatService::prepare(&mut rule(None, "10.0.0.1", "10.0.0.1")).is_err());
    }

    #[test]
    fn rejects_duplicates_but_ignores_itself() {
        let existing = vec![rule(Some(1), "192.168.0.200", "192.168.10.50")];

        let same_external = rule(None, "192.168.0.200", "192.168.10.51");
        assert!(OneToOneNatService::check_conflicts(&same_external, None, &existing).is_err());

        let same_internal = rule(None, "192.168.0.201", "192.168.10.50");
        assert!(OneToOneNatService::check_conflicts(&same_internal, None, &existing).is_err());

        let cross = rule(None, "192.168.10.50", "192.168.10.60");
        assert!(OneToOneNatService::check_conflicts(&cross, None, &existing).is_err());

        let edit_self = rule(Some(1), "192.168.0.200", "192.168.10.50");
        assert!(OneToOneNatService::check_conflicts(&edit_self, Some(1), &existing).is_ok());
    }
}
