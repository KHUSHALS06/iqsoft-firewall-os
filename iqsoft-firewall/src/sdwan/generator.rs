use crate::models::sdwan::{
    link_mark, link_table, SdwanLink, SdwanRule, MARK_MASK, MAX_LINKS,
};
use crate::repository::network_config_repository::NetworkConfigRepository;
use crate::repository::sdwan_repository::SdwanRepository;
use crate::services::sdwan_service::SdwanService;
use ipnet::Ipv4Net;
use sqlx::SqlitePool;
use std::str::FromStr;

/// SD-WAN lives in its own nftables table, so it can be replaced without touching the
/// main ruleset. The same text is also appended to every full firewall commit, because
/// `flush ruleset` there removes it (the threat-intel table works the same way).
pub const TABLE_NAME: &str = "iqsoft_sdwan";

/// Routes SD-WAN adds are tagged with this protocol number (static routes use 250),
/// so they can be told apart and removed without touching anyone else's routes.
pub const ROUTE_PROTOCOL: u8 = 251;

/// `ip rule` priorities: the "main table first" rule gets RULE_PREF_BASE, the rule of
/// slot N gets RULE_PREF_BASE + N. Lower numbers are checked first.
pub const RULE_PREF_BASE: u32 = 10000;

/// Metric of the default route SD-WAN keeps in the main table for the router's own
/// traffic (DNS, NTP, updates). It follows the best working link.
pub const MAIN_DEFAULT_METRIC: u32 = 50;

/// Runs after connection tracking (-200) and before the NAT and filter hooks.
const HOOK_PRIORITY: i32 = -150;

/// Everything outside the SD-WAN bits of a packet mark.
const KEEP_OTHER_BITS: u32 = !MARK_MASK;

/// When a link has no latency reading yet, it is ranked as if it answered in this time.
const UNKNOWN_LATENCY_MS: f64 = 1000.0;

/// Every percent of packet loss counts like this many milliseconds of latency.
const LOSS_PENALTY_MS: f64 = 20.0;

/// All the data the generator needs, read from the database in one go.
#[derive(Debug, Clone)]
pub struct SdwanInput {
    pub enabled: bool,
    pub links: Vec<SdwanLink>,
    pub rules: Vec<SdwanRule>,
    pub nat_enabled: bool,
    pub wan_interface: String,
}

/// A link together with the slot it was given in this configuration.
#[derive(Debug, Clone)]
struct SlotLink {
    slot: u32,
    link: SdwanLink,
}

/// Where new connections of a rule are sent.
#[derive(Debug, Clone, PartialEq)]
enum Target {
    Single(u32),
    /// (slot, weight) pairs, spread by weight.
    Weighted(Vec<(u32, i64)>),
}

/// The configuration after cleaning: valid links with slots, valid enabled rules in order.
struct Plan {
    slots: Vec<SlotLink>,
    rules: Vec<SdwanRule>,
    nat_enabled: bool,
    wan_interface: String,
}

impl Plan {
    fn build(input: &SdwanInput) -> Self {
        // A link's slot comes from its id, so enabling, disabling or a failing probe
        // never moves another link to a different slot (and mark) while connections
        // are running. Only deleting a link shifts the ones after it.
        let mut links: Vec<SdwanLink> = input.links.clone();
        links.sort_by_key(|l| (l.id.is_none(), l.id.unwrap_or(0)));
        links.truncate(MAX_LINKS);

        let mut slots = Vec::new();

        for (index, mut link) in links.into_iter().enumerate() {
            let slot = index as u32 + 1;

            SdwanService::normalize_link(&mut link);

            if let Err(e) = SdwanService::validate_link(&link) {
                eprintln!(
                    "WARNING: skipping SD-WAN link '{}' (id={:?}) - {}",
                    link.name, link.id, e
                );
                continue;
            }

            slots.push(SlotLink { slot, link });
        }

        let mut candidates: Vec<SdwanRule> =
            input.rules.iter().filter(|r| r.enabled).cloned().collect();
        candidates.sort_by(|a, b| a.position.cmp(&b.position).then(a.id.cmp(&b.id)));

        let mut rules = Vec::new();

        for mut rule in candidates {
            SdwanService::normalize_rule(&mut rule);

            if let Err(e) = SdwanService::validate_rule(&rule) {
                eprintln!(
                    "WARNING: skipping SD-WAN rule '{}' (id={:?}) - {}",
                    rule.name, rule.id, e
                );
                continue;
            }

            rules.push(rule);
        }

        Plan {
            slots,
            rules,
            nat_enabled: input.nat_enabled,
            wan_interface: input.wan_interface.trim().to_string(),
        }
    }

    /// Links that get a routing table and an `ip rule`. Down links stay in, otherwise
    /// the probe could never see them come back.
    fn enabled_slots(&self) -> Vec<&SlotLink> {
        self.slots.iter().filter(|s| s.link.enabled).collect()
    }

    /// Links that may carry traffic right now (enabled and not down).
    fn usable(&self) -> Vec<&SlotLink> {
        self.slots.iter().filter(|s| s.link.is_usable()).collect()
    }

    fn find_by_link_id(&self, link_id: i64) -> Option<&SlotLink> {
        self.slots.iter().find(|s| s.link.id == Some(link_id))
    }

    /// The normal choice when no rule says otherwise: the working links with the best
    /// (lowest) priority number share the traffic by weight. Higher numbers only get
    /// traffic when every better link is down.
    fn default_target(&self) -> Option<Target> {
        let usable = self.usable();
        let best = usable.iter().map(|s| s.link.priority).min()?;

        let group: Vec<&&SlotLink> = usable.iter().filter(|s| s.link.priority == best).collect();

        if group.len() == 1 {
            Some(Target::Single(group[0].slot))
        } else {
            Some(Target::Weighted(
                group.iter().map(|s| (s.slot, s.link.weight)).collect(),
            ))
        }
    }

    /// The working link with the lowest latency, loss counting against it.
    /// A tie goes to the better priority, then to the lower slot.
    fn best_quality(&self) -> Option<u32> {
        fn score(link: &SdwanLink) -> f64 {
            link.latency_ms.unwrap_or(UNKNOWN_LATENCY_MS)
                + link.loss_pct.unwrap_or(0) as f64 * LOSS_PENALTY_MS
        }

        self.usable()
            .into_iter()
            .min_by(|a, b| {
                score(&a.link)
                    .total_cmp(&score(&b.link))
                    .then(a.link.priority.cmp(&b.link.priority))
                    .then(a.slot.cmp(&b.slot))
            })
            .map(|s| s.slot)
    }

    /// The link the router's own traffic should use.
    fn primary_slot(&self) -> Option<u32> {
        match self.default_target()? {
            Target::Single(slot) => Some(slot),
            Target::Weighted(list) => list
                .into_iter()
                .min_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)))
                .map(|(slot, _)| slot),
        }
    }

    fn slot_link(&self, slot: u32) -> Option<&SlotLink> {
        self.slots.iter().find(|s| s.slot == slot)
    }

    fn has_work(&self) -> bool {
        !self.enabled_slots().is_empty()
    }

    // ------------------------------------------------------------ nftables text

    fn render_table(&self) -> String {
        let usable = self.usable();
        let enabled = self.enabled_slots();
        let default_target = self.default_target();

        let all_interfaces = quoted_list(self.slots.iter().map(|s| s.link.interface_name.as_str()));

        let mut out = String::new();

        out.push_str(&format!("table ip {} {{\n", TABLE_NAME));
        out.push_str("    # SD-WAN link steering - generated, do not edit\n");
        out.push_str("    # The link of a connection is kept in its conntrack mark (bits 16-23).\n\n");

        // One tiny chain per working link: it stamps the connection with the link's mark.
        for s in &usable {
            out.push_str(&format!("    chain pick_{} {{\n", s.slot));
            out.push_str(&format!(
                "        ct mark set ct mark & 0x{:08x} | 0x{:08x} # {}\n",
                KEEP_OTHER_BITS,
                link_mark(s.slot),
                s.link.name
            ));
            out.push_str("    }\n\n");
        }

        // The rules. First match wins (goto never comes back to this chain).
        out.push_str("    chain decide {\n");

        for rule in &self.rules {
            if let Some(line) = self.rule_line(rule, &default_target) {
                out.push_str("        ");
                out.push_str(&line);
                out.push('\n');
            }
        }

        if let Some(target) = &default_target {
            out.push_str(&format!("        {}\n", action(target)));
        }

        out.push_str("    }\n\n");

        // Traffic coming in from the LAN side.
        out.push_str("    chain prerouting {\n");
        out.push_str(&format!(
            "        type filter hook prerouting priority {};\n",
            HOOK_PRIORITY
        ));
        out.push_str("        policy accept;\n\n");

        // Connections stuck on a link that is down (or gone) lose their mark,
        // so the next packet is decided again and lands on a working link.
        let stale: Vec<u32> = (1..=MAX_LINKS as u32)
            .filter(|n| !usable.iter().any(|s| s.slot == *n))
            .map(link_mark)
            .collect();

        if !stale.is_empty() {
            let marks: Vec<String> = stale.iter().map(|m| format!("0x{:08x}", m)).collect();
            out.push_str(&format!(
                "        ct mark & 0x{:08x} == {{ {} }} ct mark set ct mark & 0x{:08x} # leave dead links\n",
                MARK_MASK,
                marks.join(", "),
                KEEP_OTHER_BITS
            ));
        }

        // A connection that starts from the internet side is pinned to the link it
        // arrived on, so its replies leave the same way.
        for s in &usable {
            out.push_str(&format!(
                "        iifname \"{}\" ct state new ct mark set ct mark & 0x{:08x} | 0x{:08x}\n",
                s.link.interface_name,
                KEEP_OTHER_BITS,
                link_mark(s.slot)
            ));
        }

        // New connections from everywhere else get a link from the rules.
        if !all_interfaces.is_empty() {
            out.push_str(&format!(
                "        iifname != {{ {} }} ct state new ct mark & 0x{:08x} == 0 jump decide\n",
                all_interfaces, MARK_MASK
            ));
        }

        // Every packet gets the packet mark of its connection (the routing rules read it).
        for s in &usable {
            if all_interfaces.is_empty() {
                break;
            }

            out.push_str(&format!(
                "        iifname != {{ {} }} ct mark & 0x{:08x} == 0x{:08x} meta mark set meta mark & 0x{:08x} | 0x{:08x}\n",
                all_interfaces,
                MARK_MASK,
                link_mark(s.slot),
                KEEP_OTHER_BITS,
                link_mark(s.slot)
            ));
        }

        out.push_str("    }\n\n");

        // The router's own replies (to the management page, VPN, ...) follow the
        // same mark. "route" makes the kernel look up the path again after marking.
        out.push_str("    chain output {\n");
        out.push_str(&format!(
            "        type route hook output priority {};\n",
            HOOK_PRIORITY
        ));
        out.push_str("        policy accept;\n\n");

        for s in &usable {
            out.push_str(&format!(
                "        ct mark & 0x{:08x} == 0x{:08x} meta mark set meta mark & 0x{:08x} | 0x{:08x}\n",
                MARK_MASK,
                link_mark(s.slot),
                KEEP_OTHER_BITS,
                link_mark(s.slot)
            ));
        }

        out.push_str("    }\n");

        // The firewall's own masquerade only covers the main WAN interface.
        let masquerade: Vec<&str> = enabled
            .iter()
            .map(|s| s.link.interface_name.as_str())
            .filter(|name| *name != self.wan_interface)
            .collect();

        if self.nat_enabled && !masquerade.is_empty() {
            out.push_str("\n    chain postrouting {\n");
            out.push_str("        type nat hook postrouting priority 100;\n");
            out.push_str("        policy accept;\n\n");
            out.push_str(&format!(
                "        oifname {{ {} }} masquerade\n",
                quoted_list(masquerade.into_iter())
            ));
            out.push_str("    }\n");
        }

        out.push_str("}\n");
        out
    }

    /// One line of the `decide` chain, or None when the rule has nothing to do right now.
    fn rule_line(&self, rule: &SdwanRule, default_target: &Option<Target>) -> Option<String> {
        let target: Option<Target> = match rule.strategy.as_str() {
            "link" => {
                let pinned = rule
                    .link_id
                    .and_then(|id| self.find_by_link_id(id))
                    .filter(|s| s.link.is_usable());

                match pinned {
                    Some(s) => Some(Target::Single(s.slot)),
                    None if rule.on_link_down == "block" => {
                        return Some(with_comment(
                            join_match(&rule_match(rule), "drop"),
                            &rule.name,
                        ));
                    }
                    None => default_target.clone(),
                }
            }
            "best_quality" => self.best_quality().map(Target::Single),
            _ => default_target.clone(),
        };

        let target = target?;

        Some(with_comment(
            join_match(&rule_match(rule), &action(&target)),
            &rule.name,
        ))
    }

    // ----------------------------------------------------------- ip commands

    fn render_ip_apply(&self) -> String {
        let mut out = String::new();
        out.push_str("# iqsoft sd-wan routing - generated, do not edit\n");

        if !self.has_work() {
            return out;
        }

        // Look in the main table first, but ignore its default route: specific routes
        // (LAN, VPN, static routes) always win, only "everything else" is steered.
        out.push_str(&format!(
            "rule add lookup main suppress_prefixlength 0 pref {}\n",
            RULE_PREF_BASE
        ));

        for s in self.enabled_slots() {
            out.push_str(&format!(
                "# {} (slot {})\n",
                s.link.name, s.slot
            ));
            out.push_str(&format!(
                "route replace default{} table {} proto {}\n",
                route_target(&s.link),
                link_table(s.slot),
                ROUTE_PROTOCOL
            ));
            out.push_str(&format!(
                "rule add fwmark 0x{:x}/0x{:x} lookup {} pref {}\n",
                link_mark(s.slot),
                MARK_MASK,
                link_table(s.slot),
                RULE_PREF_BASE + s.slot
            ));
        }

        if let Some(slot) = self.primary_slot() {
            if let Some(s) = self.slot_link(slot) {
                out.push_str("# the router's own traffic follows the best link\n");
                out.push_str(&format!(
                    "route replace default{} metric {} proto {}\n",
                    route_target(&s.link),
                    MAIN_DEFAULT_METRIC,
                    ROUTE_PROTOCOL
                ));
            }
        }

        out
    }
}

// ----------------------------------------------------------------- helpers

fn quoted_list<'a>(names: impl Iterator<Item = &'a str>) -> String {
    names
        .map(|n| format!("\"{}\"", n))
        .collect::<Vec<_>>()
        .join(", ")
}

/// " via 192.168.1.1 dev enp3s0" (or just " dev ppp0" when the link has no gateway).
fn route_target(link: &SdwanLink) -> String {
    match &link.gateway {
        Some(gateway) => format!(" via {} dev {}", gateway, link.interface_name),
        None => format!(" dev {}", link.interface_name),
    }
}

fn canonical_network(value: &str) -> String {
    Ipv4Net::from_str(value)
        .map(|net| net.to_string())
        .unwrap_or_else(|_| value.to_string())
}

fn rule_match(rule: &SdwanRule) -> String {
    let mut parts: Vec<String> = Vec::new();

    if let Some(src) = &rule.src_cidr {
        parts.push(format!("ip saddr {}", canonical_network(src)));
    }

    if let Some(dst) = &rule.dst_cidr {
        parts.push(format!("ip daddr {}", canonical_network(dst)));
    }

    match rule.protocol.as_str() {
        proto @ ("tcp" | "udp") => match (rule.dport_start, rule.dport_end) {
            (Some(start), Some(end)) if start == end => {
                parts.push(format!("{} dport {}", proto, start));
            }
            (Some(start), Some(end)) => {
                parts.push(format!("{} dport {}-{}", proto, start, end));
            }
            _ => parts.push(format!("meta l4proto {}", proto)),
        },
        "icmp" => parts.push("meta l4proto icmp".to_string()),
        _ => {}
    }

    parts.join(" ")
}

fn join_match(matching: &str, action: &str) -> String {
    if matching.is_empty() {
        action.to_string()
    } else {
        format!("{} {}", matching, action)
    }
}

/// Rule names were checked to hold no control characters, so a trailing comment can
/// never run onto a second line. Anything odd is still dropped here to be safe.
fn with_comment(line: String, name: &str) -> String {
    let clean: String = name.chars().filter(|c| !c.is_control()).collect();
    format!("{} # {}", line, clean)
}

fn action(target: &Target) -> String {
    match target {
        Target::Single(slot) => format!("goto pick_{}", slot),
        Target::Weighted(list) => {
            let total: i64 = list.iter().map(|(_, w)| *w).sum();
            let mut start: i64 = 0;
            let mut entries: Vec<String> = Vec::new();

            for (slot, weight) in list {
                let end = start + weight - 1;

                if start == end {
                    entries.push(format!("{} : goto pick_{}", start, slot));
                } else {
                    entries.push(format!("{}-{} : goto pick_{}", start, end, slot));
                }

                start = end + 1;
            }

            format!("numgen random mod {} vmap {{ {} }}", total, entries.join(", "))
        }
    }
}

// --------------------------------------------------------------- public API

pub struct SdwanGenerator;

impl SdwanGenerator {
    /// The nftables table. Empty text when SD-WAN is off or has no enabled link,
    /// so it is safe to append to the main ruleset in every case.
    pub fn render_table(input: &SdwanInput) -> String {
        if !input.enabled {
            return String::new();
        }

        let plan = Plan::build(input);

        if !plan.has_work() {
            return String::new();
        }

        plan.render_table()
    }

    /// The `ip -batch` script that creates the routing tables, the `ip rule` entries
    /// and the main-table default route. Header only when SD-WAN is off.
    pub fn render_ip_apply(input: &SdwanInput) -> String {
        if !input.enabled {
            return "# iqsoft sd-wan routing - generated, do not edit\n".to_string();
        }

        Plan::build(input).render_ip_apply()
    }

    /// The `ip -force -batch` script that removes everything SD-WAN may have created,
    /// for every possible slot (so leftovers of an older configuration go too).
    pub fn render_ip_remove_all() -> String {
        let mut out = String::new();
        out.push_str("# iqsoft sd-wan routing removal - generated, do not edit\n");
        out.push_str(&format!("rule del pref {}\n", RULE_PREF_BASE));

        for slot in 1..=MAX_LINKS as u32 {
            out.push_str(&format!("rule del pref {}\n", RULE_PREF_BASE + slot));
            out.push_str(&format!("route flush table {}\n", link_table(slot)));
        }

        out.push_str(&format!(
            "route del default metric {} proto {}\n",
            MAIN_DEFAULT_METRIC, ROUTE_PROTOCOL
        ));

        out
    }

    /// The interfaces of every valid, enabled link (the commit checks they exist
    /// and loosens reverse-path filtering on them).
    pub fn link_interfaces(input: &SdwanInput) -> Vec<String> {
        Plan::build(input)
            .enabled_slots()
            .iter()
            .map(|s| s.link.interface_name.clone())
            .collect()
    }

    /// (link id, slot) for every valid link. The probe task needs the slot to mark
    /// its pings so they leave through their own link.
    pub fn slots(input: &SdwanInput) -> Vec<(i64, u32)> {
        Plan::build(input)
            .slots
            .iter()
            .filter_map(|s| s.link.id.map(|id| (id, s.slot)))
            .collect()
    }

    pub async fn load_input(pool: &SqlitePool) -> Result<SdwanInput, String> {
        let settings = SdwanRepository::get_settings(pool)
            .await
            .map_err(|e| e.to_string())?;
        let links = SdwanRepository::list_links(pool)
            .await
            .map_err(|e| e.to_string())?;
        let rules = SdwanRepository::list_rules(pool)
            .await
            .map_err(|e| e.to_string())?;
        let network = NetworkConfigRepository::get(pool)
            .await
            .map_err(|e| e.to_string())?;

        Ok(SdwanInput {
            enabled: settings.enabled,
            links,
            rules,
            nat_enabled: network.nat_enabled,
            wan_interface: network.wan_interface,
        })
    }
}

/// The SD-WAN table as text, ready to be appended to the full firewall ruleset.
pub async fn generate_table(pool: &SqlitePool) -> Result<String, String> {
    let input = SdwanGenerator::load_input(pool).await?;
    Ok(SdwanGenerator::render_table(&input))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::init::initialize_database;
    use sqlx::sqlite::SqlitePoolOptions;

    fn link(id: i64, name: &str, iface: &str, priority: i64, weight: i64, state: &str) -> SdwanLink {
        SdwanLink {
            id: Some(id),
            name: name.to_string(),
            interface_name: iface.to_string(),
            gateway: Some(format!("10.{}.0.1", id)),
            enabled: true,
            priority,
            weight,
            probe_target: "1.1.1.1".to_string(),
            probe_interval_secs: 5,
            probe_timeout_secs: 2,
            fail_threshold: 3,
            recover_threshold: 2,
            comment: None,
            state: state.to_string(),
            latency_ms: None,
            loss_pct: None,
            last_check: None,
            last_change: None,
            last_error: None,
        }
    }

    fn rule(id: i64, name: &str, strategy: &str) -> SdwanRule {
        SdwanRule {
            id: Some(id),
            name: name.to_string(),
            enabled: true,
            position: 100,
            src_cidr: None,
            dst_cidr: None,
            protocol: "any".to_string(),
            dport_start: None,
            dport_end: None,
            strategy: strategy.to_string(),
            link_id: None,
            on_link_down: "fallback".to_string(),
            comment: None,
        }
    }

    fn input(links: Vec<SdwanLink>, rules: Vec<SdwanRule>) -> SdwanInput {
        SdwanInput {
            enabled: true,
            links,
            rules,
            nat_enabled: true,
            wan_interface: "eth0".to_string(),
        }
    }

    fn decide_lines(text: &str) -> Vec<String> {
        let start = text.find("chain decide {").unwrap();
        let body = &text[start..];
        let end = body.find("\n    }").unwrap();

        body[..end]
            .lines()
            .skip(1)
            .map(|l| l.trim().to_string())
            .collect()
    }

    fn two_links() -> Vec<SdwanLink> {
        vec![
            link(1, "ISP1", "eth0", 10, 1, "up"),
            link(2, "ISP2", "eth2", 20, 1, "up"),
        ]
    }

    // ------------------------------------------------------------------ slots

    #[test]
    fn a_links_slot_follows_its_id_not_its_priority_or_state() {
        let links = vec![
            link(7, "c", "eth7", 1, 1, "up"),
            link(3, "a", "eth3", 50, 1, "down"),
            link(5, "b", "eth5", 10, 1, "up"),
        ];

        let slots = SdwanGenerator::slots(&input(links, vec![]));

        assert_eq!(slots, vec![(3, 1), (5, 2), (7, 3)]);
    }

    #[test]
    fn disabling_a_link_does_not_move_the_others() {
        let mut links = two_links();
        links.push(link(3, "ISP3", "eth3", 30, 1, "up"));
        links[0].enabled = false;

        let slots = SdwanGenerator::slots(&input(links, vec![]));

        assert_eq!(slots, vec![(1, 1), (2, 2), (3, 3)]);
    }

    #[test]
    fn an_invalid_link_is_skipped_and_keeps_the_other_slots() {
        let mut links = two_links();
        links[0].interface_name = "eth0; reboot".to_string();

        let inp = input(links, vec![]);

        assert_eq!(SdwanGenerator::slots(&inp), vec![(2, 2)]);
        assert_eq!(SdwanGenerator::link_interfaces(&inp), vec!["eth2"]);
    }

    #[test]
    fn at_most_sixteen_links_get_a_slot() {
        let links: Vec<SdwanLink> = (1..=20)
            .map(|i| link(i, &format!("l{}", i), &format!("wan{}", i), 10, 1, "up"))
            .collect();

        let slots = SdwanGenerator::slots(&input(links, vec![]));

        assert_eq!(slots.len(), MAX_LINKS);
        assert_eq!(slots.last(), Some(&(16, 16)));
    }

    // ------------------------------------------------------------ switched off

    #[test]
    fn nothing_is_generated_while_sdwan_is_off() {
        let mut inp = input(two_links(), vec![]);
        inp.enabled = false;

        assert_eq!(SdwanGenerator::render_table(&inp), "");
        assert_eq!(
            SdwanGenerator::render_ip_apply(&inp),
            "# iqsoft sd-wan routing - generated, do not edit\n"
        );
    }

    #[test]
    fn nothing_is_generated_without_an_enabled_link() {
        let mut links = two_links();
        links[0].enabled = false;
        links[1].enabled = false;

        let inp = input(links, vec![]);

        assert_eq!(SdwanGenerator::render_table(&inp), "");
        assert_eq!(
            SdwanGenerator::render_ip_apply(&inp),
            "# iqsoft sd-wan routing - generated, do not edit\n"
        );
    }

    // ------------------------------------------------------------ default path

    #[test]
    fn a_single_link_gets_all_traffic() {
        let text = SdwanGenerator::render_table(&input(
            vec![link(1, "ISP1", "eth0", 10, 1, "up")],
            vec![],
        ));

        assert!(text.starts_with("table ip iqsoft_sdwan {\n"));
        assert!(text.ends_with("}\n"));
        assert!(text.contains("chain pick_1 {"));
        assert!(text.contains("ct mark set ct mark & 0xff00ffff | 0x00010000 # ISP1"));
        assert_eq!(decide_lines(&text), vec!["goto pick_1"]);
    }

    #[test]
    fn links_with_the_same_priority_share_traffic_by_weight() {
        let links = vec![
            link(1, "ISP1", "eth0", 10, 1, "up"),
            link(2, "ISP2", "eth2", 10, 3, "up"),
        ];

        let text = SdwanGenerator::render_table(&input(links, vec![]));

        assert_eq!(
            decide_lines(&text),
            vec!["numgen random mod 4 vmap { 0 : goto pick_1, 1-3 : goto pick_2 }"]
        );
    }

    #[test]
    fn a_worse_priority_link_is_only_used_when_the_better_ones_are_down() {
        let healthy = SdwanGenerator::render_table(&input(two_links(), vec![]));
        assert_eq!(decide_lines(&healthy), vec!["goto pick_1"]);
        // the backup is working, so connections already on it are left alone
        assert!(healthy.contains("chain pick_2"));

        let mut links = two_links();
        links[0].state = "down".to_string();

        let failover = SdwanGenerator::render_table(&input(links, vec![]));
        assert_eq!(decide_lines(&failover), vec!["goto pick_2"]);
        assert!(failover.contains("chain pick_2"));
        assert!(!failover.contains("chain pick_1"));
    }

    #[test]
    fn a_link_that_was_never_probed_still_takes_traffic() {
        let text = SdwanGenerator::render_table(&input(
            vec![link(1, "ISP1", "eth0", 10, 1, "unknown")],
            vec![],
        ));

        assert_eq!(decide_lines(&text), vec!["goto pick_1"]);
    }

    #[test]
    fn with_every_link_down_nothing_is_steered() {
        let mut links = two_links();
        links[0].state = "down".to_string();
        links[1].state = "down".to_string();

        let text = SdwanGenerator::render_table(&input(links, vec![rule(1, "spread", "balance")]));

        assert!(decide_lines(&text).iter().all(|l| l.is_empty()));
        assert!(!text.contains("chain pick_"));
        assert!(!text.contains("goto"));
    }

    // ---------------------------------------------------------------- rules

    #[test]
    fn rules_match_addresses_protocols_and_ports() {
        let mut voice = rule(1, "voice", "link");
        voice.link_id = Some(2);
        voice.src_cidr = Some("192.168.10.0/24".to_string());
        voice.dst_cidr = Some("203.0.113.5".to_string());
        voice.protocol = "udp".to_string();
        voice.dport_start = Some(10000);
        voice.dport_end = Some(20000);

        let mut web = rule(2, "web", "balance");
        web.protocol = "tcp".to_string();
        web.dport_start = Some(443);

        let mut tcp_all = rule(3, "tcp-all", "balance");
        tcp_all.protocol = "tcp".to_string();

        let mut ping = rule(4, "ping", "balance");
        ping.protocol = "icmp".to_string();

        let text = SdwanGenerator::render_table(&input(
            two_links(),
            vec![voice, web, tcp_all, ping],
        ));

        assert_eq!(
            decide_lines(&text),
            vec![
                "ip saddr 192.168.10.0/24 ip daddr 203.0.113.5/32 udp dport 10000-20000 goto pick_2 # voice",
                "tcp dport 443 goto pick_1 # web",
                "meta l4proto tcp goto pick_1 # tcp-all",
                "meta l4proto icmp goto pick_1 # ping",
                "goto pick_1",
            ]
        );
    }

    #[test]
    fn rules_are_checked_by_position_then_id_and_disabled_ones_are_left_out() {
        let mut late = rule(1, "late", "balance");
        late.position = 300;
        late.dst_cidr = Some("10.9.0.0/16".to_string());

        let mut early_b = rule(3, "early-b", "balance");
        early_b.position = 10;
        early_b.dst_cidr = Some("10.8.0.0/16".to_string());

        let mut early_a = rule(2, "early-a", "balance");
        early_a.position = 10;
        early_a.dst_cidr = Some("10.7.0.0/16".to_string());

        let mut off = rule(4, "off", "balance");
        off.enabled = false;
        off.position = 1;
        off.dst_cidr = Some("10.6.0.0/16".to_string());

        let text = SdwanGenerator::render_table(&input(
            two_links(),
            vec![late, early_b, early_a, off],
        ));
        let lines = decide_lines(&text);

        assert_eq!(lines.len(), 4);
        assert!(lines[0].contains("10.7.0.0/16"));
        assert!(lines[1].contains("10.8.0.0/16"));
        assert!(lines[2].contains("10.9.0.0/16"));
        assert!(!text.contains("10.6.0.0/16"));
    }

    #[test]
    fn a_pinned_rule_follows_its_link_and_falls_back_when_it_is_down() {
        let mut pinned = rule(1, "voice", "link");
        pinned.link_id = Some(2);
        pinned.src_cidr = Some("192.168.10.0/24".to_string());

        let healthy = SdwanGenerator::render_table(&input(two_links(), vec![pinned.clone()]));
        assert_eq!(
            decide_lines(&healthy),
            vec![
                "ip saddr 192.168.10.0/24 goto pick_2 # voice",
                "goto pick_1"
            ]
        );

        let mut links = two_links();
        links[1].state = "down".to_string();

        let down = SdwanGenerator::render_table(&input(links, vec![pinned]));
        assert_eq!(
            decide_lines(&down),
            vec![
                "ip saddr 192.168.10.0/24 goto pick_1 # voice",
                "goto pick_1"
            ]
        );
    }

    #[test]
    fn a_pinned_rule_set_to_block_drops_traffic_when_its_link_is_down() {
        let mut pinned = rule(1, "voice", "link");
        pinned.link_id = Some(2);
        pinned.on_link_down = "block".to_string();
        pinned.src_cidr = Some("192.168.10.0/24".to_string());

        let mut links = two_links();
        links[1].state = "down".to_string();

        let text = SdwanGenerator::render_table(&input(links.clone(), vec![pinned.clone()]));
        assert_eq!(
            decide_lines(&text),
            vec!["ip saddr 192.168.10.0/24 drop # voice", "goto pick_1"]
        );

        // a disabled link counts as down too
        links[1].state = "up".to_string();
        links[1].enabled = false;
        let text = SdwanGenerator::render_table(&input(links, vec![pinned]));
        assert!(decide_lines(&text)[0].ends_with("drop # voice"));
    }

    #[test]
    fn a_block_rule_still_drops_when_every_link_is_down() {
        let mut pinned = rule(1, "voice", "link");
        pinned.link_id = Some(1);
        pinned.on_link_down = "block".to_string();

        let mut links = two_links();
        links[0].state = "down".to_string();
        links[1].state = "down".to_string();

        let text = SdwanGenerator::render_table(&input(links, vec![pinned]));

        assert_eq!(decide_lines(&text), vec!["drop # voice"]);
    }

    #[test]
    fn best_quality_picks_the_fastest_link_and_counts_loss() {
        let mut links = two_links();
        links[0].latency_ms = Some(40.0);
        links[1].latency_ms = Some(15.0);

        let fast = rule(1, "fast", "best_quality");

        let text = SdwanGenerator::render_table(&input(links.clone(), vec![fast.clone()]));
        assert_eq!(decide_lines(&text)[0], "goto pick_2 # fast");

        // 10% loss costs 200 ms, so the slower but clean link wins
        links[1].loss_pct = Some(10);
        let text = SdwanGenerator::render_table(&input(links.clone(), vec![fast.clone()]));
        assert_eq!(decide_lines(&text)[0], "goto pick_1 # fast");

        // a down link is never picked, however fast it was
        links[0].state = "down".to_string();
        let text = SdwanGenerator::render_table(&input(links, vec![fast]));
        assert_eq!(decide_lines(&text)[0], "goto pick_2 # fast");
    }

    #[test]
    fn best_quality_ties_go_to_the_better_priority() {
        let mut links = two_links();
        links[0].latency_ms = Some(20.0);
        links[1].latency_ms = Some(20.0);

        let text = SdwanGenerator::render_table(&input(links, vec![rule(1, "fast", "best_quality")]));

        assert_eq!(decide_lines(&text)[0], "goto pick_1 # fast");
    }

    #[test]
    fn invalid_rules_are_skipped() {
        let mut bad_net = rule(1, "bad-net", "balance");
        bad_net.src_cidr = Some("10.0.0.5/24".to_string());

        let mut bad_proto = rule(2, "bad-proto", "balance");
        bad_proto.protocol = "gre".to_string();

        let bad_name = rule(3, "x\"; flush ruleset", "balance");

        let good = rule(4, "good", "balance");

        let text = SdwanGenerator::render_table(&input(
            two_links(),
            vec![bad_net, bad_proto, bad_name, good],
        ));

        assert_eq!(
            decide_lines(&text),
            vec!["goto pick_1 # good", "goto pick_1"]
        );
        assert!(!text.contains("flush ruleset"));
    }

    // -------------------------------------------------------- the main chains

    #[test]
    fn connections_on_dead_links_lose_their_mark() {
        let mut links = two_links();
        links[0].state = "down".to_string();

        let text = SdwanGenerator::render_table(&input(links, vec![]));

        // slot 1 is down, slot 2 works, slots 3-16 do not exist
        assert!(text.contains(
            "ct mark & 0x00ff0000 == { 0x00010000, 0x00030000, 0x00040000, 0x00050000, \
0x00060000, 0x00070000, 0x00080000, 0x00090000, 0x000a0000, 0x000b0000, 0x000c0000, \
0x000d0000, 0x000e0000, 0x000f0000, 0x00100000 } ct mark set ct mark & 0xff00ffff"
        ));
        assert!(!text.contains("0x00020000,"));
    }

    #[test]
    fn replies_stay_on_the_link_the_connection_arrived_on() {
        let text = SdwanGenerator::render_table(&input(two_links(), vec![]));

        assert!(text.contains(
            "iifname \"eth0\" ct state new ct mark set ct mark & 0xff00ffff | 0x00010000"
        ));
        assert!(text.contains(
            "iifname \"eth2\" ct state new ct mark set ct mark & 0xff00ffff | 0x00020000"
        ));
    }

    #[test]
    fn only_traffic_from_inside_is_decided_and_every_packet_gets_its_mark() {
        let text = SdwanGenerator::render_table(&input(two_links(), vec![]));

        assert!(text.contains(
            "iifname != { \"eth0\", \"eth2\" } ct state new ct mark & 0x00ff0000 == 0 jump decide"
        ));
        assert!(text.contains(
            "iifname != { \"eth0\", \"eth2\" } ct mark & 0x00ff0000 == 0x00010000 meta mark set meta mark & 0xff00ffff | 0x00010000"
        ));
        assert!(text.contains(
            "iifname != { \"eth0\", \"eth2\" } ct mark & 0x00ff0000 == 0x00020000 meta mark set meta mark & 0xff00ffff | 0x00020000"
        ));
    }

    #[test]
    fn the_router_own_replies_follow_the_connection_mark() {
        let text = SdwanGenerator::render_table(&input(two_links(), vec![]));
        let output = &text[text.find("chain output {").unwrap()..];

        assert!(output.contains("type route hook output priority -150;"));
        assert!(output.contains(
            "ct mark & 0x00ff0000 == 0x00020000 meta mark set meta mark & 0xff00ffff | 0x00020000"
        ));
    }

    #[test]
    fn the_prerouting_steps_come_in_the_right_order() {
        let text = SdwanGenerator::render_table(&input(two_links(), vec![]));

        let clear = text.find("# leave dead links").unwrap();
        let ingress = text.find("iifname \"eth0\" ct state new").unwrap();
        let decide = text.find("jump decide").unwrap();
        let restore = text.find("meta mark set meta mark").unwrap();

        assert!(clear < ingress);
        assert!(ingress < decide);
        assert!(decide < restore);
    }

    #[test]
    fn sdwan_never_touches_bits_outside_its_mask() {
        let text = SdwanGenerator::render_table(&input(two_links(), vec![rule(1, "r", "balance")]));

        // every mark write keeps the other bits (the SNI bit is 0x04000000)
        for line in text.lines().filter(|l| l.contains("mark set")) {
            assert!(line.contains("& 0xff00ffff"), "{}", line);
        }

        assert!(!text.contains("0x04000000"));
    }

    #[test]
    fn masquerade_covers_the_extra_links_but_not_the_main_wan() {
        let text = SdwanGenerator::render_table(&input(two_links(), vec![]));
        let nat = &text[text.find("chain postrouting {").unwrap()..];

        assert!(nat.contains("type nat hook postrouting priority 100;"));
        assert!(nat.contains("oifname { \"eth2\" } masquerade"));
        assert!(!nat.contains("eth0"));
    }

    #[test]
    fn no_masquerade_when_nat_is_off_or_only_the_main_wan_is_a_link() {
        let mut off = input(two_links(), vec![]);
        off.nat_enabled = false;
        assert!(!SdwanGenerator::render_table(&off).contains("masquerade"));

        let only_wan = input(vec![link(1, "ISP1", "eth0", 10, 1, "up")], vec![]);
        assert!(!SdwanGenerator::render_table(&only_wan).contains("masquerade"));
    }

    #[test]
    fn a_disabled_link_gets_no_masquerade_pick_chain_or_routes() {
        let mut links = two_links();
        links[1].enabled = false;

        let inp = input(links, vec![]);
        let text = SdwanGenerator::render_table(&inp);

        assert!(!text.contains("masquerade"));
        assert!(!text.contains("chain pick_2"));
        // but its interface is still known, so its traffic is never re-decided
        assert!(text.contains("iifname != { \"eth0\", \"eth2\" }"));
        assert!(!SdwanGenerator::render_ip_apply(&inp).contains("table 102"));
    }

    #[test]
    fn the_same_input_always_gives_the_same_text() {
        let mut voice = rule(1, "voice", "link");
        voice.link_id = Some(2);

        let inp = input(two_links(), vec![voice, rule(2, "web", "balance")]);

        assert_eq!(SdwanGenerator::render_table(&inp), SdwanGenerator::render_table(&inp));
        assert_eq!(
            SdwanGenerator::render_ip_apply(&inp),
            SdwanGenerator::render_ip_apply(&inp)
        );
    }

    // ----------------------------------------------------------- ip commands

    #[test]
    fn the_ip_script_builds_tables_rules_and_the_main_default_route() {
        let text = SdwanGenerator::render_ip_apply(&input(two_links(), vec![]));
        let lines: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();

        assert_eq!(
            lines,
            vec![
                "rule add lookup main suppress_prefixlength 0 pref 10000",
                "route replace default via 10.1.0.1 dev eth0 table 101 proto 251",
                "rule add fwmark 0x10000/0xff0000 lookup 101 pref 10001",
                "route replace default via 10.2.0.1 dev eth2 table 102 proto 251",
                "rule add fwmark 0x20000/0xff0000 lookup 102 pref 10002",
                "route replace default via 10.1.0.1 dev eth0 metric 50 proto 251",
            ]
        );
    }

    #[test]
    fn a_link_without_a_gateway_routes_by_interface_only() {
        let mut ppp = link(1, "dsl", "ppp0", 10, 1, "up");
        ppp.gateway = None;

        let text = SdwanGenerator::render_ip_apply(&input(vec![ppp], vec![]));

        assert!(text.contains("route replace default dev ppp0 table 101 proto 251\n"));
        assert!(text.contains("route replace default dev ppp0 metric 50 proto 251\n"));
    }

    #[test]
    fn a_down_link_keeps_its_table_so_probes_can_see_it_recover() {
        let mut links = two_links();
        links[0].state = "down".to_string();

        let text = SdwanGenerator::render_ip_apply(&input(links, vec![]));

        assert!(text.contains("table 101"));
        assert!(text.contains("lookup 101 pref 10001"));
        // but the router's own traffic moves to the working link
        assert!(text.contains("route replace default via 10.2.0.1 dev eth2 metric 50 proto 251"));
    }

    #[test]
    fn the_main_default_route_follows_the_heaviest_link_of_the_best_group() {
        let links = vec![
            link(1, "ISP1", "eth0", 10, 1, "up"),
            link(2, "ISP2", "eth2", 10, 5, "up"),
            link(3, "ISP3", "eth3", 20, 9, "up"),
        ];

        let text = SdwanGenerator::render_ip_apply(&input(links, vec![]));

        assert!(text.contains("route replace default via 10.2.0.1 dev eth2 metric 50 proto 251"));
    }

    #[test]
    fn with_every_link_down_the_main_default_route_is_left_alone() {
        let mut links = two_links();
        links[0].state = "down".to_string();
        links[1].state = "down".to_string();

        let text = SdwanGenerator::render_ip_apply(&input(links, vec![]));

        assert!(!text.contains("metric 50"));
        assert!(text.contains("table 101"));
    }

    #[test]
    fn the_removal_script_covers_every_possible_slot() {
        let text = SdwanGenerator::render_ip_remove_all();
        let lines: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();

        assert_eq!(lines.len(), 1 + MAX_LINKS * 2 + 1);
        assert_eq!(lines[0], "rule del pref 10000");
        assert_eq!(lines[1], "rule del pref 10001");
        assert_eq!(lines[2], "route flush table 101");
        assert_eq!(lines[MAX_LINKS * 2 - 1], "rule del pref 10016");
        assert_eq!(lines[MAX_LINKS * 2], "route flush table 116");
        assert_eq!(
            lines.last(),
            Some(&"route del default metric 50 proto 251")
        );
    }

    #[test]
    fn nothing_in_the_generated_text_can_run_a_second_command() {
        let mut evil = link(1, "ISP1", "eth0", 10, 1, "up");
        evil.gateway = Some("10.0.0.1\nroute del default".to_string());

        let mut r = rule(1, "name\nflush ruleset", "balance");
        r.comment = Some("x\nflush ruleset".to_string());

        let inp = input(vec![evil, link(2, "ISP2", "eth2", 20, 1, "up")], vec![r]);

        for text in [
            SdwanGenerator::render_table(&inp),
            SdwanGenerator::render_ip_apply(&inp),
        ] {
            assert!(!text.contains("flush ruleset"));
            assert!(!text.contains("route del default\n"));
        }
    }

    // --------------------------------------------------------------- database

    #[tokio::test]
    async fn the_table_is_built_from_the_database() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        initialize_database(&pool).await.unwrap();

        // switched off: empty
        assert_eq!(generate_table(&pool).await.unwrap(), "");

        let id = SdwanService::add_link(&pool, link(0, "ISP1", "eth0", 10, 1, "unknown"))
            .await
            .unwrap();
        SdwanService::set_enabled(&pool, true).await.unwrap();

        let mut voice = rule(0, "voice", "link");
        voice.link_id = Some(id);
        voice.dst_cidr = Some("203.0.113.0/24".to_string());
        SdwanService::add_rule(&pool, voice).await.unwrap();

        let text = generate_table(&pool).await.unwrap();

        assert!(text.contains("table ip iqsoft_sdwan {"));
        assert!(text.contains("ip daddr 203.0.113.0/24 goto pick_1 # voice"));

        let loaded = SdwanGenerator::load_input(&pool).await.unwrap();
        assert!(loaded.enabled);
        assert_eq!(loaded.links.len(), 1);
        assert_eq!(loaded.rules.len(), 1);
        assert_eq!(loaded.wan_interface, "eth0");
    }
}
