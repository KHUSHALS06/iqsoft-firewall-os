// Decides what to do with a connection once its site name is known.
//
// `SniPolicy::build` / `load` gather the rules. `decide` takes the result of
// the parser and answers accept or drop. No network code lives here, so it
// is fully testable.

use crate::{
    models::{
        dnsfilter::{normalize_domain, DnsFilterRule},
        sni::{SniRule, SniSettings},
    },
    repository::{dnsfilter_repository::DnsFilterRepository, sni_repository::SniRepository},
    sni::parser::SniResult,
};
use sqlx::SqlitePool;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
}

/// Why a verdict was chosen. Carries the matching rule's domain so a log line
/// can say which rule fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    Disabled,
    NotTls,
    NoName,
    Malformed,
    NoRule,
    Blocked(String),
    Allowed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub verdict: Verdict,
    pub reason: Reason,
}

impl Decision {
    fn accept(reason: Reason) -> Self {
        Self { verdict: Verdict::Accept, reason }
    }

    fn drop(reason: Reason) -> Self {
        Self { verdict: Verdict::Drop, reason }
    }
}

#[derive(Debug, Clone)]
pub struct SniPolicy {
    enabled: bool,
    block_no_name: bool,
    block_malformed: bool,
    blocked: HashSet<String>,
    allowed: HashSet<String>,
}

impl SniPolicy {
    /// Collects the rules from plain data. Domains are cleaned again here and
    /// anything unusable is skipped, so a bad row can never block everything.
    ///
    /// The DNS filter lists are only used when `use_dns_filter_lists` is on.
    /// They are used even if the DNS filter itself is switched off, because
    /// turning on "use DNS filter lists" is a direct request to use them.
    pub fn build(
        settings: &SniSettings,
        sni_rules: &[SniRule],
        dns_domains: &[String],
        dns_rules: &[DnsFilterRule],
    ) -> Self {
        let mut blocked: HashSet<String> = HashSet::new();
        let mut allowed: HashSet<String> = HashSet::new();

        let mut add = |domain: &str, action: &str| {
            let Some(domain) = normalize_domain(domain) else {
                return;
            };

            match action {
                "block" => {
                    blocked.insert(domain);
                }
                "allow" => {
                    allowed.insert(domain);
                }
                _ => {}
            }
        };

        for rule in sni_rules {
            add(&rule.domain, &rule.action);
        }

        if settings.use_dns_filter_lists {
            for domain in dns_domains {
                add(domain, "block");
            }

            for rule in dns_rules {
                add(&rule.domain, &rule.action);
            }
        }

        Self {
            enabled: settings.enabled,
            block_no_name: settings.no_name_action == "block",
            block_malformed: settings.block_malformed,
            blocked,
            allowed,
        }
    }

    /// Reads the settings and rules from the database.
    pub async fn load(pool: &SqlitePool) -> Result<Self, String> {
        let settings = SniRepository::get_settings(pool)
            .await
            .map_err(|e| e.to_string())?;

        if !settings.enabled {
            return Ok(Self::build(&settings, &[], &[], &[]));
        }

        let sni_rules = SniRepository::list_rules(pool)
            .await
            .map_err(|e| e.to_string())?;

        let (dns_domains, dns_rules) = if settings.use_dns_filter_lists {
            let domains = DnsFilterRepository::list_enabled_domains(pool)
                .await
                .map_err(|e| e.to_string())?;
            let rules = DnsFilterRepository::list_rules(pool)
                .await
                .map_err(|e| e.to_string())?;
            (domains, rules)
        } else {
            (Vec::new(), Vec::new())
        };

        Ok(Self::build(&settings, &sni_rules, &dns_domains, &dns_rules))
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn rule_count(&self) -> usize {
        self.blocked.len() + self.allowed.len()
    }

    /// None means "not enough bytes yet, ask again after the next packet".
    pub fn decide(&self, result: &SniResult) -> Option<Decision> {
        if !self.enabled {
            return Some(Decision::accept(Reason::Disabled));
        }

        match result {
            SniResult::NeedMore => None,
            SniResult::NotTls => Some(Decision::accept(Reason::NotTls)),
            SniResult::NoName => Some(if self.block_no_name {
                Decision::drop(Reason::NoName)
            } else {
                Decision::accept(Reason::NoName)
            }),
            SniResult::Malformed => Some(if self.block_malformed {
                Decision::drop(Reason::Malformed)
            } else {
                Decision::accept(Reason::Malformed)
            }),
            SniResult::Name(host) => Some(self.decide_name(host)),
        }
    }

    pub fn decide_name(&self, host: &str) -> Decision {
        if !self.enabled {
            return Decision::accept(Reason::Disabled);
        }

        match self.lookup(host) {
            Some((Verdict::Drop, rule)) => Decision::drop(Reason::Blocked(rule.to_string())),
            Some((Verdict::Accept, rule)) => Decision::accept(Reason::Allowed(rule.to_string())),
            None => Decision::accept(Reason::NoRule),
        }
    }

    /// Looks for the host itself, then its parent domain, then that one's
    /// parent, and so on. The first hit is the most specific rule. A bare
    /// ending such as "com" is never looked up.
    fn lookup<'a>(&self, host: &'a str) -> Option<(Verdict, &'a str)> {
        let mut candidate = host;

        loop {
            if self.allowed.contains(candidate) {
                return Some((Verdict::Accept, candidate));
            }

            if self.blocked.contains(candidate) {
                return Some((Verdict::Drop, candidate));
            }

            match candidate.split_once('.') {
                Some((_, rest)) if rest.contains('.') => candidate = rest,
                _ => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{dnsfilter_schema::create_dnsfilter_tables, sni_schema::create_sni_tables};
    use sqlx::sqlite::SqlitePoolOptions;

    fn settings(enabled: bool, dns_lists: bool, block_no_name: bool, block_malformed: bool) -> SniSettings {
        SniSettings {
            enabled,
            use_dns_filter_lists: dns_lists,
            no_name_action: if block_no_name { "block" } else { "allow" }.into(),
            block_malformed,
            block_quic: false,
        }
    }

    fn sni_rule(domain: &str, action: &str) -> SniRule {
        SniRule {
            id: None,
            domain: domain.into(),
            action: action.into(),
            comment: None,
        }
    }

    fn dns_rule(domain: &str, action: &str) -> DnsFilterRule {
        DnsFilterRule {
            id: None,
            domain: domain.into(),
            action: action.into(),
            comment: None,
        }
    }

    fn policy(rules: &[(&str, &str)]) -> SniPolicy {
        let rules: Vec<SniRule> = rules.iter().map(|(d, a)| sni_rule(d, a)).collect();
        SniPolicy::build(&settings(true, false, false, true), &rules, &[], &[])
    }

    fn verdict(policy: &SniPolicy, host: &str) -> Verdict {
        policy.decide_name(host).verdict
    }

    #[test]
    fn subdomains_are_covered_but_lookalikes_are_not() {
        let p = policy(&[("tiktok.com", "block")]);

        assert_eq!(verdict(&p, "tiktok.com"), Verdict::Drop);
        assert_eq!(verdict(&p, "www.tiktok.com"), Verdict::Drop);
        assert_eq!(verdict(&p, "a.b.tiktok.com"), Verdict::Drop);

        assert_eq!(verdict(&p, "nottiktok.com"), Verdict::Accept);
        assert_eq!(verdict(&p, "tiktok.com.evil.net"), Verdict::Accept);
        assert_eq!(verdict(&p, "tiktok.org"), Verdict::Accept);
        assert_eq!(verdict(&p, "com"), Verdict::Accept);

        assert_eq!(
            p.decide_name("www.tiktok.com").reason,
            Reason::Blocked("tiktok.com".into())
        );
        assert_eq!(p.decide_name("fine.org").reason, Reason::NoRule);
    }

    #[test]
    fn the_most_specific_rule_wins() {
        let p = policy(&[("example.com", "block"), ("cdn.example.com", "allow")]);
        assert_eq!(verdict(&p, "www.example.com"), Verdict::Drop);
        assert_eq!(verdict(&p, "cdn.example.com"), Verdict::Accept);
        assert_eq!(verdict(&p, "a.cdn.example.com"), Verdict::Accept);
        assert_eq!(
            p.decide_name("a.cdn.example.com").reason,
            Reason::Allowed("cdn.example.com".into())
        );

        let p = policy(&[("example.com", "allow"), ("ads.example.com", "block")]);
        assert_eq!(verdict(&p, "www.example.com"), Verdict::Accept);
        assert_eq!(verdict(&p, "ads.example.com"), Verdict::Drop);
        assert_eq!(verdict(&p, "x.ads.example.com"), Verdict::Drop);
    }

    #[test]
    fn allow_beats_block_for_the_same_domain() {
        let sni = vec![sni_rule("x.example.com", "block")];
        let dns = vec![dns_rule("x.example.com", "allow")];
        let p = SniPolicy::build(&settings(true, true, false, true), &sni, &[], &dns);

        assert_eq!(verdict(&p, "x.example.com"), Verdict::Accept);
        assert_eq!(verdict(&p, "www.x.example.com"), Verdict::Accept);
    }

    #[test]
    fn dns_filter_lists_are_used_only_when_asked() {
        let dns_domains = vec!["bad.example.com".to_string()];
        let dns_rules = vec![
            dns_rule("blocked.example.net", "block"),
            dns_rule("ok.example.com", "allow"),
        ];
        let sni = vec![sni_rule("example.com", "block")];

        let without = SniPolicy::build(&settings(true, false, false, true), &[], &dns_domains, &dns_rules);
        assert_eq!(verdict(&without, "bad.example.com"), Verdict::Accept);
        assert_eq!(verdict(&without, "blocked.example.net"), Verdict::Accept);
        assert_eq!(without.rule_count(), 0);

        let with = SniPolicy::build(&settings(true, true, false, true), &sni, &dns_domains, &dns_rules);
        assert_eq!(verdict(&with, "bad.example.com"), Verdict::Drop);
        assert_eq!(verdict(&with, "blocked.example.net"), Verdict::Drop);
        assert_eq!(verdict(&with, "ok.example.com"), Verdict::Accept);
        assert_eq!(verdict(&with, "www.example.com"), Verdict::Drop);
    }

    #[test]
    fn names_missing_or_broken_follow_the_settings() {
        let strict = SniPolicy::build(&settings(true, false, true, true), &[], &[], &[]);
        assert_eq!(strict.decide(&SniResult::NoName).unwrap().verdict, Verdict::Drop);
        assert_eq!(strict.decide(&SniResult::Malformed).unwrap().verdict, Verdict::Drop);

        let relaxed = SniPolicy::build(&settings(true, false, false, false), &[], &[], &[]);
        assert_eq!(relaxed.decide(&SniResult::NoName).unwrap().verdict, Verdict::Accept);
        assert_eq!(relaxed.decide(&SniResult::Malformed).unwrap().verdict, Verdict::Accept);

        // Other traffic on port 443 is not our business, and "need more" is not an answer yet.
        assert_eq!(strict.decide(&SniResult::NotTls).unwrap().verdict, Verdict::Accept);
        assert_eq!(strict.decide(&SniResult::NeedMore), None);

        let p = policy(&[("tiktok.com", "block")]);
        let blocked = p.decide(&SniResult::Name("www.tiktok.com".into())).unwrap();
        assert_eq!(blocked.verdict, Verdict::Drop);
    }

    #[test]
    fn a_disabled_policy_accepts_everything() {
        let sni = vec![sni_rule("tiktok.com", "block")];
        let p = SniPolicy::build(&settings(false, true, true, true), &sni, &[], &[]);

        assert!(!p.is_enabled());
        assert_eq!(verdict(&p, "www.tiktok.com"), Verdict::Accept);
        assert_eq!(p.decide(&SniResult::NoName).unwrap().reason, Reason::Disabled);
        assert_eq!(p.decide(&SniResult::Malformed).unwrap().verdict, Verdict::Accept);
    }

    #[test]
    fn unusable_domains_are_ignored() {
        let sni = vec![
            sni_rule("com", "block"),
            sni_rule("1.2.3.4", "block"),
            sni_rule("bad domain", "block"),
            sni_rule("good.example.org", "block"),
        ];
        let p = SniPolicy::build(&settings(true, false, false, true), &sni, &[], &[]);

        assert_eq!(p.rule_count(), 1);
        assert_eq!(verdict(&p, "anything.com"), Verdict::Accept);
        assert_eq!(verdict(&p, "good.example.org"), Verdict::Drop);
    }

    #[tokio::test]
    async fn load_reads_the_database_and_honours_enabled_categories() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        create_sni_tables(&pool).await.unwrap();
        create_dnsfilter_tables(&pool).await.unwrap();

        sqlx::query("INSERT INTO sni_rules (domain, action) VALUES ('tiktok.com', 'block')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO dnsfilter_categories (name, enabled) VALUES ('adult', 1), ('off', 0)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO dnsfilter_domains (category, domain) VALUES ('adult', 'bad.example.com'), ('off', 'off.example.com')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO dnsfilter_rules (domain, action) VALUES ('ads.example.net', 'block')")
            .execute(&pool)
            .await
            .unwrap();

        // The filter starts switched off, so nothing is blocked yet.
        let policy = SniPolicy::load(&pool).await.unwrap();
        assert_eq!(verdict(&policy, "tiktok.com"), Verdict::Accept);

        SniRepository::set_settings(&pool, &settings(true, true, false, true)).await.unwrap();
        let policy = SniPolicy::load(&pool).await.unwrap();
        assert_eq!(verdict(&policy, "tiktok.com"), Verdict::Drop);
        assert_eq!(verdict(&policy, "www.bad.example.com"), Verdict::Drop);
        assert_eq!(verdict(&policy, "ads.example.net"), Verdict::Drop);
        assert_eq!(verdict(&policy, "off.example.com"), Verdict::Accept);
        assert_eq!(verdict(&policy, "fine.org"), Verdict::Accept);

        SniRepository::set_settings(&pool, &settings(true, false, false, true)).await.unwrap();
        let policy = SniPolicy::load(&pool).await.unwrap();
        assert_eq!(verdict(&policy, "tiktok.com"), Verdict::Drop);
        assert_eq!(verdict(&policy, "bad.example.com"), Verdict::Accept);
    }
}
