use crate::models::dnsfilter::{normalize_domain, DnsFilterRule, DnsFilterSettings};
use crate::repository::dnsfilter_repository::DnsFilterRepository;
use sqlx::SqlitePool;
use std::collections::BTreeSet;

const DOH_CANARY_DOMAINS: [&str; 3] = [
    "use-application-dns.net",
    "mask.icloud.com",
    "mask-h2.icloud.com",
];

#[derive(Debug, Clone)]
pub struct DnsFilterData {
    pub settings: DnsFilterSettings,
    pub domains: Vec<String>,
    pub rules: Vec<DnsFilterRule>,
}

impl DnsFilterData {
    pub fn disabled() -> Self {
        Self {
            settings: DnsFilterSettings {
                enabled: false,
                block_response: "nxdomain".to_string(),
                safe_search: false,
                enforce_dns: false,
            },
            domains: Vec::new(),
            rules: Vec::new(),
        }
    }

    pub async fn load(pool: &SqlitePool) -> Result<Self, String> {
        let settings = DnsFilterRepository::get_settings(pool)
            .await
            .map_err(|e| e.to_string())?;

        if !settings.enabled {
            return Ok(Self {
                settings,
                domains: Vec::new(),
                rules: Vec::new(),
            });
        }

        let domains = DnsFilterRepository::list_enabled_domains(pool)
            .await
            .map_err(|e| e.to_string())?;
        let rules = DnsFilterRepository::list_rules(pool)
            .await
            .map_err(|e| e.to_string())?;

        Ok(Self {
            settings,
            domains,
            rules,
        })
    }

    pub fn render(&self) -> String {
        let mut out = String::new();

        if !self.settings.enabled {
            return out;
        }

        let sinkhole = self.settings.block_response == "sinkhole";

        let mut allowed: BTreeSet<String> = BTreeSet::new();
        let mut blocked: BTreeSet<String> = BTreeSet::new();

        for rule in &self.rules {
            let Some(domain) = normalize_domain(&rule.domain) else {
                continue;
            };
            match rule.action.as_str() {
                "allow" => {
                    allowed.insert(domain);
                }
                "block" => {
                    blocked.insert(domain);
                }
                _ => {}
            }
        }

        for domain in &self.domains {
            if let Some(domain) = normalize_domain(domain) {
                blocked.insert(domain);
            }
        }

        for domain in &blocked {
            if allowed.contains(domain) {
                continue;
            }
            if sinkhole {
                out.push_str(&format!("address=/{}/0.0.0.0\n", domain));
                out.push_str(&format!("address=/{}/::\n", domain));
            } else {
                out.push_str(&format!("address=/{}/\n", domain));
            }
        }

        if self.settings.enforce_dns {
            for domain in DOH_CANARY_DOMAINS {
                if allowed.contains(domain) || blocked.contains(domain) {
                    continue;
                }
                out.push_str(&format!("address=/{}/\n", domain));
            }
        }

        for domain in &allowed {
            out.push_str(&format!("server=/{}/#\n", domain));
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(response: &str, domains: &[&str], rules: &[(&str, &str)]) -> DnsFilterData {
        DnsFilterData {
            settings: DnsFilterSettings {
                enabled: true,
                block_response: response.to_string(),
                safe_search: false,
                enforce_dns: false,
            },
            domains: domains.iter().map(|d| d.to_string()).collect(),
            rules: rules
                .iter()
                .map(|(d, a)| DnsFilterRule {
                    id: None,
                    domain: d.to_string(),
                    action: a.to_string(),
                    comment: None,
                })
                .collect(),
        }
    }

    #[test]
    fn disabled_filter_renders_nothing() {
        let mut d = data("nxdomain", &["ads.example.com"], &[]);
        d.settings.enabled = false;
        assert_eq!(d.render(), "");
    }

    #[test]
    fn nxdomain_blocks_use_an_empty_address() {
        let d = data("nxdomain", &["ads.example.com"], &[("*.tiktok.com", "block")]);
        let out = d.render();
        assert!(out.contains("address=/ads.example.com/\n"));
        assert!(out.contains("address=/tiktok.com/\n"));
    }

    #[test]
    fn sinkhole_blocks_answer_zero_addresses() {
        let d = data("sinkhole", &["ads.example.com"], &[]);
        let out = d.render();
        assert!(out.contains("address=/ads.example.com/0.0.0.0\n"));
        assert!(out.contains("address=/ads.example.com/::\n"));
    }

    #[test]
    fn allow_removes_the_same_domain_and_overrides_a_parent_block() {
        let d = data(
            "nxdomain",
            &["example.com", "keep.example.org"],
            &[("keep.example.org", "allow"), ("sub.example.com", "allow")],
        );
        let out = d.render();
        assert!(out.contains("address=/example.com/\n"));
        assert!(!out.contains("address=/keep.example.org/"));
        assert!(out.contains("server=/keep.example.org/#\n"));
        assert!(out.contains("server=/sub.example.com/#\n"));
    }

    #[test]
    fn enforce_dns_answers_nxdomain_for_the_doh_canary_domains() {
        let mut d = data("sinkhole", &[], &[]);
        d.settings.enforce_dns = true;
        let out = d.render();
        assert!(out.contains("address=/use-application-dns.net/\n"));
        assert!(out.contains("address=/mask.icloud.com/\n"));
        assert!(out.contains("address=/mask-h2.icloud.com/\n"));
    }

    #[test]
    fn canary_domains_are_left_alone_without_enforce_dns_or_when_allowed() {
        let d = data("nxdomain", &[], &[]);
        assert!(!d.render().contains("use-application-dns.net"));

        let mut d = data("nxdomain", &[], &[("mask.icloud.com", "allow")]);
        d.settings.enforce_dns = true;
        let out = d.render();
        assert!(!out.contains("address=/mask.icloud.com/"));
        assert!(out.contains("server=/mask.icloud.com/#\n"));
    }

    #[test]
    fn duplicate_and_invalid_domains_are_dropped() {
        let d = data("nxdomain", &["a.example.com", "a.example.com", "bad domain"], &[]);
        let out = d.render();
        assert_eq!(out.matches("address=/a.example.com/").count(), 1);
        assert!(!out.contains("bad domain"));
    }
}
