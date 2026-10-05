use crate::{
    models::{
        dhcp::DhcpConfig,
        dns::DnsConfig,
        firewall_rule::{
            normalize_days, normalize_mac, normalize_rate_limit, normalize_time_of_day, FirewallRule,
        },
        network_config::NetworkConfig,
        one_to_one_nat::OneToOneNatRule,
        port_forward::PortForwardRule,
        wireguard::WireguardConfig,
    },
    repository::{
        address_repository::{AddressRepository, REF_PREFIX},
        dhcp_repository::DhcpRepository,
        dns_repository::DnsRepository,
        firewall_repository::FirewallRepository,
        network_config_repository::NetworkConfigRepository,
        one_to_one_nat_repository::OneToOneNatRepository,
        port_forward_repository::PortForwardRepository,
        wireguard_repository::WireguardRepository,
    },
};

use ipnet::IpNet;
use sqlx::SqlitePool;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr};

pub struct FirewallGenerator;

struct DdosLimits {
    tag: &'static str,
    syn_rate: u32,
    syn_burst: u32,
    max_connections: u32,
}

const DDOS_INPUT: DdosLimits = DdosLimits {
    tag: "in",
    syn_rate: 25,
    syn_burst: 50,
    max_connections: 100,
};

const DDOS_FORWARD: DdosLimits = DdosLimits {
    tag: "fwd",
    syn_rate: 200,
    syn_burst: 400,
    max_connections: 1000,
};

/// An address object or group that at least one enabled rule refers to,
/// ready to be written as an nftables named set.
struct AddrSet {
    /// Name of the set inside nftables, always `addr_<lowercase name>`.
    set_name: String,
    is_v6: bool,
    /// Already validated and normalized, safe to place in the ruleset.
    elements: Vec<String>,
}

/// Sets keyed by the lowercase object/group name (names are case-insensitive).
type AddrSets = BTreeMap<String, AddrSet>;

impl FirewallGenerator {
    pub async fn generate(pool: &SqlitePool) -> Result<String, String> {
        let rules = FirewallRepository::list_rules(pool)
            .await
            .map_err(|e| e.to_string())?;

        let net_config = NetworkConfigRepository::get(pool)
            .await
            .map_err(|e| e.to_string())?;

        let dhcp_config = DhcpRepository::get_config(pool)
            .await
            .map_err(|e| e.to_string())?;

        let dns_config = DnsRepository::get_config(pool)
            .await
            .map_err(|e| e.to_string())?;

        let wireguard_config = WireguardRepository::get_config(pool)
            .await
            .map_err(|e| e.to_string())?;

        let port_forwards: Vec<PortForwardRule> = PortForwardRepository::list_rules(pool)
            .await
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter(|r| r.enabled)
            .collect();

        let one_to_one: Vec<OneToOneNatRule> = OneToOneNatRepository::list_rules(pool)
            .await
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter(|r| r.enabled)
            .collect();

        let addr_sets = Self::load_address_sets(pool, &rules).await?;

        let mut output = String::new();

        // flush ruleset first: nftables config is declarative in the kernel and repeated commits duplicate rules.
        output.push_str("flush ruleset;\n\n");

        output.push_str("table inet filter {\n\n");

        Self::generate_address_sets(&mut output, &addr_sets);

        Self::generate_ddos_sets(&mut output, &DDOS_INPUT);
        Self::generate_ddos_sets(&mut output, &DDOS_FORWARD);

        // INPUT
        output.push_str("    chain input {\n");
        output.push_str("        type filter hook input priority 0;\n");
        output.push_str("        policy drop;\n\n");

        output.push_str("        iif lo accept\n");
        output.push_str("        ct state invalid drop\n");
        output.push_str("        ct state established,related accept\n\n");

        Self::generate_ddos_rules(&mut output, &DDOS_INPUT);

        Self::generate_self_protection(&mut output, &net_config, &dhcp_config, &dns_config);

        output.push_str(&Self::wireguard_input_block(&wireguard_config));

        Self::generate_chain(&mut output, &rules, "INPUT", &addr_sets);

        output.push_str("    }\n\n");

        // FORWARD
        output.push_str("    chain forward {\n");
        output.push_str("        type filter hook forward priority 0;\n");
        output.push_str("        policy drop;\n\n");

        // Replies to allowed connections (including replies from a port-forwarded
        // server back to the internet) must be let through.
        output.push_str("        ct state invalid drop\n");
        output.push_str("        ct state established,related accept\n\n");

        Self::generate_ddos_rules(&mut output, &DDOS_FORWARD);

        Self::generate_port_forward_accepts(&mut output, &net_config, &port_forwards);

        Self::generate_chain(&mut output, &rules, "FORWARD", &addr_sets);

        output.push_str("    }\n\n");

        // OUTPUT
        output.push_str("    chain output {\n");
        output.push_str("        type filter hook output priority 0;\n");
        output.push_str("        policy accept;\n\n");

        Self::generate_chain(&mut output, &rules, "OUTPUT", &addr_sets);

        output.push_str("    }\n");

        output.push_str("}\n\n");

        Self::generate_nat_table(&mut output, &net_config, &port_forwards, &one_to_one);

        Ok(output)
    }

    /// `@office_lan` -> Some("office_lan"). Anything else is a literal address.
    fn reference_name(value: &str) -> Option<&str> {
        value.trim().strip_prefix(REF_PREFIX)
    }

    fn set_key(name: &str) -> String {
        name.to_ascii_lowercase()
    }

    /// Looks up every object or group that an enabled rule refers to and turns
    /// each one into an `AddrSet`. Unused objects and groups are never loaded
    /// into the ruleset. A reference that cannot be resolved is left out here,
    /// and the rule using it is skipped later with a warning.
    async fn load_address_sets(
        pool: &SqlitePool,
        rules: &[FirewallRule],
    ) -> Result<AddrSets, String> {
        let mut wanted: BTreeSet<String> = BTreeSet::new();

        for rule in rules.iter().filter(|r| r.enabled) {
            for value in [&rule.src_ip, &rule.dst_ip].into_iter().flatten() {
                if let Some(name) = Self::reference_name(value) {
                    wanted.insert(Self::set_key(name));
                }
            }
        }

        let mut sets = AddrSets::new();

        if wanted.is_empty() {
            return Ok(sets);
        }

        let objects = AddressRepository::list_objects(pool)
            .await
            .map_err(|e| e.to_string())?;

        let groups = AddressRepository::list_groups(pool)
            .await
            .map_err(|e| e.to_string())?;

        let objects_by_key: BTreeMap<String, _> = objects
            .iter()
            .map(|o| (Self::set_key(&o.name), o))
            .collect();

        for key in wanted {
            let (family, mut elements): (&str, Vec<String>) =
                if let Some(object) = objects_by_key.get(&key) {
                    (object.family.as_str(), vec![object.value.clone()])
                } else if let Some(group) = groups.iter().find(|g| Self::set_key(&g.name) == key) {
                    let members: Vec<String> = group
                        .members
                        .iter()
                        .filter_map(|m| objects_by_key.get(&Self::set_key(m)))
                        .map(|o| o.value.clone())
                        .collect();

                    (group.family.as_str(), members)
                } else {
                    continue;
                };

            let is_v6 = match family {
                "ipv4" => false,
                "ipv6" => true,
                _ => continue,
            };

            if elements.is_empty() {
                continue;
            }

            elements.sort();
            elements.dedup();

            sets.insert(
                key.clone(),
                AddrSet {
                    set_name: format!("addr_{}", key),
                    is_v6,
                    elements,
                },
            );
        }

        Ok(sets)
    }

    /// One named set per referenced object or group. `interval` lets a set hold
    /// subnets and ranges, and `auto-merge` stops nftables from rejecting the
    /// whole ruleset when two members overlap (for example a host that is also
    /// inside a subnet in the same group).
    fn generate_address_sets(output: &mut String, sets: &AddrSets) {
        for set in sets.values() {
            output.push_str(&format!("    set {} {{\n", set.set_name));
            output.push_str(&format!(
                "        type {};\n",
                if set.is_v6 { "ipv6_addr" } else { "ipv4_addr" }
            ));
            output.push_str("        flags interval;\n");
            output.push_str("        auto-merge;\n");
            output.push_str(&format!(
                "        elements = {{ {} }}\n",
                set.elements.join(", ")
            ));
            output.push_str("    }\n\n");
        }
    }

    fn generate_ddos_sets(output: &mut String, limits: &DdosLimits) {
        for family in ["v4", "v6"] {
            let addr_type = if family == "v4" { "ipv4_addr" } else { "ipv6_addr" };

            output.push_str(&format!("    set ddos_syn_{}_{} {{\n", limits.tag, family));
            output.push_str(&format!("        type {};\n", addr_type));
            output.push_str("        size 65535;\n");
            output.push_str("        flags dynamic,timeout;\n");
            output.push_str("        timeout 1m;\n");
            output.push_str("    }\n\n");

            output.push_str(&format!("    set ddos_conn_{}_{} {{\n", limits.tag, family));
            output.push_str(&format!("        type {};\n", addr_type));
            output.push_str("        size 65535;\n");
            output.push_str("        flags dynamic;\n");
            output.push_str("    }\n\n");
        }
    }

    fn generate_ddos_rules(output: &mut String, limits: &DdosLimits) {
        output.push_str("        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 drop\n");
        output.push_str("        tcp flags & (fin|syn) == (fin|syn) drop\n");
        output.push_str("        tcp flags & (syn|rst) == (syn|rst) drop\n");
        output.push_str("        tcp flags & (fin|rst) == (fin|rst) drop\n");
        output.push_str("        tcp flags & (fin|ack) == fin drop\n");
        output.push_str("        tcp flags & (urg|ack) == urg drop\n");
        output.push_str("        tcp flags & (psh|ack) == psh drop\n");

        for (family, saddr) in [("v4", "ip saddr"), ("v6", "ip6 saddr")] {
            output.push_str(&format!(
                "        tcp flags & (fin|syn|rst|ack) == syn ct state new add @ddos_syn_{}_{} {{ {} limit rate over {}/second burst {} packets }} counter drop\n",
                limits.tag, family, saddr, limits.syn_rate, limits.syn_burst
            ));
        }

        for (family, saddr) in [("v4", "ip saddr"), ("v6", "ip6 saddr")] {
            output.push_str(&format!(
                "        tcp flags & (fin|syn|rst|ack) == syn ct state new add @ddos_conn_{}_{} {{ {} ct count over {} }} counter drop\n",
                limits.tag, family, saddr, limits.max_connections
            ));
        }

        output.push('\n');
    }

    /// Works out how one src_ip or dst_ip value is written in a rule.
    /// Returns (is_ipv6, text to put after `saddr` / `daddr`), or None when the
    /// value is neither a valid literal nor a reference to a usable set.
    fn address_match(value: &str, sets: &AddrSets) -> Option<(bool, String)> {
        let trimmed = value.trim();

        if let Some(name) = Self::reference_name(trimmed) {
            let set = sets.get(&Self::set_key(name))?;
            return Some((set.is_v6, format!("@{}", set.set_name)));
        }

        Self::ip_family(trimmed).map(|is_v6| (is_v6, trimmed.to_string()))
    }

    fn sanitize_comment(value: &str) -> String {
        value
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect()
    }

    fn is_safe_iface(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 15
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    }

    /// The one INPUT rule that lets WireGuard clients reach the firewall.
    pub fn wireguard_listen_rule(port: i32) -> String {
        format!("        udp dport {} accept # WireGuard VPN\n", port)
    }

    /// INPUT rules for the WireGuard tunnel: the UDP listen port, and ping to
    /// the firewall from inside the tunnel. Empty while WireGuard is disabled.
    ///
    /// Traffic that is *forwarded* from the tunnel to other networks is not
    /// opened here: the FORWARD policy stays drop, and the admin allows what
    /// VPN users may reach with normal rules on the WireGuard interface.
    pub fn wireguard_input_block(config: &WireguardConfig) -> String {
        if !config.enabled {
            return String::new();
        }

        let iface = config.interface_name.trim();

        if !Self::is_safe_iface(iface) || !(1..=65535).contains(&config.listen_port) {
            eprintln!(
                "WARNING: WireGuard is enabled but its interface name or port is not valid - skipping WireGuard allow rules"
            );
            return String::new();
        }

        let mut out = Self::wireguard_listen_rule(config.listen_port);

        out.push_str(&format!(
            "        iifname \"{}\" ip protocol icmp icmp type echo-request limit rate 10/second accept\n",
            iface
        ));
        out.push_str(&format!(
            "        iifname \"{}\" meta l4proto icmpv6 icmpv6 type echo-request limit rate 10/second accept\n",
            iface
        ));
        out.push('\n');

        out
    }

    fn management_port() -> Option<u16> {
        let bind = std::env::var("IQSOFT_BIND").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
        let addr: SocketAddr = bind.parse().ok()?;

        if addr.ip().is_loopback() {
            None
        } else {
            Some(addr.port())
        }
    }

    fn generate_self_protection(
        output: &mut String,
        net_config: &NetworkConfig,
        dhcp_config: &DhcpConfig,
        dns_config: &DnsConfig,
    ) {
        output.push_str("        meta l4proto icmpv6 icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept\n");
        output.push_str("        meta l4proto icmpv6 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } ip6 hoplimit 255 accept\n");

        let lan = net_config.lan_interface.trim();

        if Self::is_safe_iface(lan) {
            output.push_str(&format!(
                "        iifname \"{}\" ip protocol icmp icmp type echo-request limit rate 10/second accept\n",
                lan
            ));
            output.push_str(&format!(
                "        iifname \"{}\" meta l4proto icmpv6 icmpv6 type echo-request limit rate 10/second accept\n",
                lan
            ));

            if let Some(port) = Self::management_port() {
                output.push_str(&format!(
                    "        iifname \"{}\" tcp dport {} accept # management API\n",
                    lan, port
                ));
            }
        } else {
            eprintln!(
                "WARNING: LAN interface name '{}' is not valid - management API and ping access from LAN will not be allowed",
                lan
            );
        }

        if dhcp_config.enabled {
            let iface = dhcp_config.interface_name.trim();

            if Self::is_safe_iface(iface) {
                output.push_str(&format!(
                    "        iifname \"{}\" udp dport 67 accept # DHCP server\n",
                    iface
                ));
            } else {
                eprintln!(
                    "WARNING: DHCP is enabled but interface name '{}' is not valid - skipping DHCP allow rule",
                    iface
                );
            }
        }

        if dns_config.enabled {
            for iface in &dns_config.listen_interfaces {
                let iface = iface.trim();

                if Self::is_safe_iface(iface) {
                    output.push_str(&format!(
                        "        iifname \"{}\" udp dport 53 accept # DNS server\n",
                        iface
                    ));
                    output.push_str(&format!(
                        "        iifname \"{}\" tcp dport 53 accept # DNS server\n",
                        iface
                    ));
                } else {
                    eprintln!(
                        "WARNING: DNS is enabled but interface name '{}' is not valid - skipping DNS allow rules",
                        iface
                    );
                }
            }
        }

        output.push('\n');
    }

    /// "both" expands to tcp + udp.
    fn pf_protocols(rule: &PortForwardRule) -> Vec<&'static str> {
        match rule.protocol.as_str() {
            "tcp" => vec!["tcp"],
            "udp" => vec!["udp"],
            "both" => vec!["tcp", "udp"],
            _ => vec![],
        }
    }

    fn pf_port_expr(start: i32, end: i32) -> String {
        if start == end {
            start.to_string()
        } else {
            format!("{}-{}", start, end)
        }
    }

    fn pf_is_usable(rule: &PortForwardRule) -> bool {
        if rule.internal_ip.trim().parse::<Ipv4Addr>().is_err() {
            eprintln!(
                "WARNING: skipping port forward '{}' (id={:?}) - invalid internal_ip in database: '{}'",
                rule.name, rule.id, rule.internal_ip
            );
            return false;
        }
        if Self::pf_protocols(rule).is_empty() {
            eprintln!(
                "WARNING: skipping port forward '{}' (id={:?}) - invalid protocol in database: '{}'",
                rule.name, rule.id, rule.protocol
            );
            return false;
        }
        true
    }

    /// After DNAT the FORWARD chain sees the *internal* address and port, so the
    /// accept rules match on those and only for connections that were DNAT'ed.
    fn generate_port_forward_accepts(
        output: &mut String,
        net_config: &NetworkConfig,
        port_forwards: &[PortForwardRule],
    ) {
        let wan = net_config.wan_interface.trim();
        if wan.is_empty() {
            return;
        }

        for rule in port_forwards {
            if !Self::pf_is_usable(rule) {
                continue;
            }

            let internal_ports =
                Self::pf_port_expr(rule.internal_port_start, rule.internal_port_end());

            for proto in Self::pf_protocols(rule) {
                output.push_str(&format!(
                    "        iifname \"{}\" ip daddr {} {} dport {} ct status dnat accept # port forward: {}\n",
                    wan,
                    rule.internal_ip.trim(),
                    proto,
                    internal_ports,
                    Self::sanitize_comment(&rule.name),
                ));
            }
        }

        output.push('\n');
    }

    fn o2o_is_usable(rule: &OneToOneNatRule) -> bool {
        if rule.external_ip.trim().parse::<Ipv4Addr>().is_err()
            || rule.internal_ip.trim().parse::<Ipv4Addr>().is_err()
        {
            eprintln!(
                "WARNING: skipping 1:1 NAT rule '{}' (id={:?}) - invalid address in database: '{}' <-> '{}'",
                rule.name, rule.id, rule.external_ip, rule.internal_ip
            );
            return false;
        }
        true
    }

    fn generate_nat_table(
        output: &mut String,
        net_config: &NetworkConfig,
        port_forwards: &[PortForwardRule],
        one_to_one: &[OneToOneNatRule],
    ) {
        let has_forwards = !port_forwards.is_empty();
        let usable_o2o: Vec<&OneToOneNatRule> = one_to_one
            .iter()
            .filter(|r| Self::o2o_is_usable(r))
            .collect();

        if !net_config.nat_enabled && !has_forwards && usable_o2o.is_empty() {
            return;
        }

        let wan = net_config.wan_interface.trim();
        if wan.is_empty() {
            eprintln!("WARNING: NAT is enabled but no WAN interface is configured - skipping NAT table");
            return;
        }

        output.push_str("table ip nat {\n\n");

        output.push_str("    chain prerouting {\n");
        output.push_str("        type nat hook prerouting priority -100;\n");
        output.push_str("        policy accept;\n\n");

        // 1:1 NAT goes first: a whole-host mapping must win over any port forward.
        for rule in &usable_o2o {
            output.push_str(&format!(
                "        iifname \"{}\" ip daddr {} dnat to {} # 1:1 NAT: {}\n",
                wan,
                rule.external_ip.trim(),
                rule.internal_ip.trim(),
                Self::sanitize_comment(&rule.name),
            ));
        }

        // Port forwarding (DNAT)
        for rule in port_forwards {
            if !Self::pf_is_usable(rule) {
                continue;
            }

            let external_ports =
                Self::pf_port_expr(rule.external_port_start, rule.external_port_end);

            // Single port: rewrite to the chosen internal port.
            // Range: keep the same port numbers (dnat to the address only).
            let target = if rule.external_port_start == rule.external_port_end {
                format!("{}:{}", rule.internal_ip.trim(), rule.internal_port_start)
            } else {
                rule.internal_ip.trim().to_string()
            };

            for proto in Self::pf_protocols(rule) {
                output.push_str(&format!(
                    "        iifname \"{}\" {} dport {} dnat to {} # {}\n",
                    wan,
                    proto,
                    external_ports,
                    target,
                    Self::sanitize_comment(&rule.name),
                ));
            }
        }

        output.push_str("    }\n\n");

        // Outbound NAT
        output.push_str("    chain postrouting {\n");
        output.push_str("        type nat hook postrouting priority 100;\n");
        output.push_str("        policy accept;\n\n");

        // 1:1 SNAT must come before masquerade so the mapped host leaves the
        // WAN with its own external address instead of the shared WAN address.
        for rule in &usable_o2o {
            output.push_str(&format!(
                "        oifname \"{}\" ip saddr {} snat to {} # 1:1 NAT: {}\n",
                wan,
                rule.internal_ip.trim(),
                rule.external_ip.trim(),
                Self::sanitize_comment(&rule.name),
            ));
        }

        if net_config.nat_enabled {
            output.push_str(&format!(
                "        oifname \"{}\" masquerade\n",
                wan
            ));
        }

        output.push_str("    }\n");

        output.push_str("}\n");
    }

    fn generate_chain(
        output: &mut String,
        rules: &[FirewallRule],
        chain: &str,
        sets: &AddrSets,
    ) {
        for rule in rules {
            if !rule.enabled {
                continue;
            }

            if !rule.chain_name.eq_ignore_ascii_case(chain) {
                continue;
            }

            let mut line = String::from("        ");
            let mut port_any_marker = false;

            if let Some(iface) = &rule.interface_name {
                let trimmed = iface.trim();

                if !trimmed.is_empty() {
                    if !Self::is_safe_iface(trimmed) {
                        eprintln!(
                            "WARNING: skipping rule '{}' (id={:?}) — invalid interface_name in database: '{}'",
                            rule.name, rule.id, iface
                        );
                        continue;
                    }

                    let keyword = if chain.eq_ignore_ascii_case("OUTPUT") {
                        "oifname"
                    } else {
                        "iifname"
                    };

                    line.push_str(&format!("{} \"{}\" ", keyword, trimmed));
                }
            }

            if let Some(mac) = &rule.src_mac {
                let trimmed = mac.trim();

                if !trimmed.is_empty() {
                    if chain.eq_ignore_ascii_case("OUTPUT") {
                        eprintln!(
                            "WARNING: skipping rule '{}' (id={:?}) — src_mac is not valid on an OUTPUT rule",
                            rule.name, rule.id
                        );
                        continue;
                    }

                    match normalize_mac(trimmed) {
                        Some(normalized) => {
                            line.push_str(&format!("ether saddr {} ", normalized));
                        }
                        None => {
                            eprintln!(
                                "WARNING: skipping rule '{}' (id={:?}) — invalid src_mac in database: '{}'",
                                rule.name, rule.id, mac
                            );
                            continue;
                        }
                    }
                }
            }

            match Self::time_match(rule) {
                Ok(Some(text)) => line.push_str(&text),
                Ok(None) => {}
                Err(reason) => {
                    eprintln!(
                        "WARNING: skipping rule '{}' (id={:?}) — {}",
                        rule.name, rule.id, reason
                    );
                    continue;
                }
            }

            let mut src_match: Option<(bool, String)> = None;
            if let Some(src) = &rule.src_ip {
                if !src.trim().is_empty() {
                    match Self::address_match(src, sets) {
                        Some(found) => src_match = Some(found),
                        None => {
                            eprintln!(
                                "WARNING: skipping rule '{}' (id={:?}) — invalid src_ip in database: '{}'",
                                rule.name, rule.id, src
                            );
                            continue;
                        }
                    }
                }
            }

            let mut dst_match: Option<(bool, String)> = None;
            if let Some(dst) = &rule.dst_ip {
                if !dst.trim().is_empty() {
                    match Self::address_match(dst, sets) {
                        Some(found) => dst_match = Some(found),
                        None => {
                            eprintln!(
                                "WARNING: skipping rule '{}' (id={:?}) — invalid dst_ip in database: '{}'",
                                rule.name, rule.id, dst
                            );
                            continue;
                        }
                    }
                }
            }

            let src_is_v6 = src_match.as_ref().map(|(v6, _)| *v6);
            let dst_is_v6 = dst_match.as_ref().map(|(v6, _)| *v6);

            if let (Some(s), Some(d)) = (src_is_v6, dst_is_v6) {
                if s != d {
                    eprintln!(
                        "WARNING: skipping rule '{}' (id={:?}) — src_ip and dst_ip are different IP versions",
                        rule.name, rule.id
                    );
                    continue;
                }
            }

            let rule_is_v6 = src_is_v6.or(dst_is_v6);

            if let Some((is_v6, text)) = &src_match {
                let keyword = if *is_v6 { "ip6" } else { "ip" };
                line.push_str(&format!("{} saddr {} ", keyword, text));
            }

            if let Some((is_v6, text)) = &dst_match {
                let keyword = if *is_v6 { "ip6" } else { "ip" };
                line.push_str(&format!("{} daddr {} ", keyword, text));
            }

            match rule.protocol.to_lowercase().as_str() {
                "tcp" => {
                    if rule.src_port.is_some() || rule.dst_port.is_some() {
                        line.push_str("tcp ");
                    } else {
                        line.push_str("meta l4proto tcp ");
                    }

                    if let Some(port) = rule.src_port {
                        line.push_str(&format!("sport {} ", port));
                    }

                    if let Some(port) = rule.dst_port {
                        line.push_str(&format!("dport {} ", port));
                    } else if rule.port_any {
                        port_any_marker = true;
                    }
                }

                "udp" => {
                    if rule.src_port.is_some() || rule.dst_port.is_some() {
                        line.push_str("udp ");
                    } else {
                        line.push_str("meta l4proto udp ");
                    }

                    if let Some(port) = rule.src_port {
                        line.push_str(&format!("sport {} ", port));
                    }

                    if let Some(port) = rule.dst_port {
                        line.push_str(&format!("dport {} ", port));
                    } else if rule.port_any {
                        port_any_marker = true;
                    }
                }

                "icmp" => {
                    if rule_is_v6 == Some(true) {
                        line.push_str("meta l4proto icmpv6 ");
                    } else {
                        line.push_str("ip protocol icmp ");
                    }
                }

                "any" => {}

                _ => continue,
            }

            if let Some(raw) = &rule.rate_limit {
                let trimmed = raw.trim();

                if !trimmed.is_empty() {
                    match normalize_rate_limit(trimmed) {
                        Some(rate) => {
                            if rule.action.eq_ignore_ascii_case("accept") {
                                line.push_str(&format!("limit rate {} ", rate));
                            } else {
                                line.push_str(&format!("limit rate over {} ", rate));
                            }
                        }
                        None => {
                            eprintln!(
                                "WARNING: skipping rule '{}' (id={:?}) — invalid rate_limit in database: '{}'",
                                rule.name, rule.id, raw
                            );
                            continue;
                        }
                    }
                }
            }

            // Count the packets and bytes that reach this rule's verdict.
            line.push_str("counter ");

            // Logging: tag every log line with the rule that produced it,
            // so the log reader can tell which rule fired.
            if rule.log_enabled {
                match rule.id {
                    Some(id) => line.push_str(&format!("log prefix \"iqsoft-rule-{}: \" ", id)),
                    None => line.push_str("log "),
                }
            }

            match rule.action.to_lowercase().as_str() {
                "accept" => line.push_str("accept"),
                "drop" => line.push_str("drop"),
                "reject" => line.push_str("reject"),
                _ => continue,
            }

            // Tag the rule so the counters can be matched back to it.
            if let Some(id) = rule.id {
                line.push_str(&format!(" comment \"iqsoft-rule-{}\"", id));
            }

            if port_any_marker {
                line.push_str(&format!(
                    " # {}: all ports intentionally allowed",
                    Self::sanitize_comment(&rule.name)
                ));
            }

            output.push_str(&line);
            output.push('\n');
        }

        output.push('\n');
    }

    fn day_full_name(abbreviation: &str) -> Option<&'static str> {
        match abbreviation {
            "mon" => Some("Monday"),
            "tue" => Some("Tuesday"),
            "wed" => Some("Wednesday"),
            "thu" => Some("Thursday"),
            "fri" => Some("Friday"),
            "sat" => Some("Saturday"),
            "sun" => Some("Sunday"),
            _ => None,
        }
    }

    fn time_match(rule: &FirewallRule) -> Result<Option<String>, String> {
        fn non_blank(value: &Option<String>) -> Option<&str> {
            value.as_deref().map(str::trim).filter(|v| !v.is_empty())
        }

        let mut text = String::new();

        match (non_blank(&rule.time_start), non_blank(&rule.time_end)) {
            (None, None) => {}
            (Some(start), Some(end)) => {
                let start_norm = normalize_time_of_day(start)
                    .ok_or_else(|| format!("invalid time_start in database: '{}'", start))?;
                let end_norm = normalize_time_of_day(end)
                    .ok_or_else(|| format!("invalid time_end in database: '{}'", end))?;

                if start_norm == end_norm {
                    return Err("time_start and time_end are the same".into());
                }

                text.push_str(&format!("meta hour \"{}\"-\"{}\" ", start_norm, end_norm));
            }
            _ => return Err("only one of time_start and time_end is set".into()),
        }

        if let Some(days) = non_blank(&rule.days) {
            let normalized = normalize_days(days)
                .ok_or_else(|| format!("invalid days in database: '{}'", days))?;

            let names: Vec<String> = normalized
                .split(',')
                .filter_map(Self::day_full_name)
                .map(|name| format!("\"{}\"", name))
                .collect();

            if names.len() < 7 {
                text.push_str(&format!("meta day {{ {} }} ", names.join(", ")));
            }
        }

        if text.is_empty() {
            Ok(None)
        } else {
            Ok(Some(text))
        }
    }

    fn ip_family(value: &str) -> Option<bool> {
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

    #[allow(clippy::too_many_arguments)]
    async fn add_rule(
        pool: &SqlitePool,
        name: &str,
        chain: &str,
        action: &str,
        protocol: &str,
        src: Option<&str>,
        dst: Option<&str>,
        dst_port: Option<i32>,
        extra: (bool, Option<&str>, Option<&str>, bool),
    ) {
        let (port_any, iface, rate, log) = extra;

        sqlx::query(
            r#"
            INSERT INTO firewall_rules
                (name, chain_name, action, protocol, src_ip, dst_ip, dst_port,
                 port_any, interface_name, rate_limit, log_enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(name)
        .bind(chain)
        .bind(action)
        .bind(protocol)
        .bind(src)
        .bind(dst)
        .bind(dst_port)
        .bind(port_any)
        .bind(iface)
        .bind(rate)
        .bind(log)
        .execute(pool)
        .await
        .unwrap();
    }

    /// The management-API line depends on the IQSOFT_BIND environment variable
    /// of whoever runs the tests, so it is left out of the comparison.
    fn without_environment_lines(text: &str) -> String {
        text.lines()
            .filter(|l| !l.contains("# management API"))
            .map(|l| format!("{}\n", l))
            .collect()
    }

    /// A mixed ruleset that touches every branch of the rule generator.
    async fn baseline_pool() -> SqlitePool {
        let pool = memory_pool().await;
        let none = (false, None, None, false);

        add_rule(&pool, "ssh from office", "INPUT", "accept", "tcp",
            Some("192.168.1.0/24"), None, Some(22), (false, Some("eth1"), None, true)).await;
        add_rule(&pool, "web to server", "FORWARD", "accept", "tcp",
            None, Some("10.0.0.10"), Some(443), none).await;
        add_rule(&pool, "dns v6", "FORWARD", "accept", "udp",
            Some("2001:db8::/32"), Some("2001:db8:1::53"), Some(53), none).await;
        add_rule(&pool, "block host", "FORWARD", "drop", "any",
            Some("10.9.9.9"), None, None, none).await;
        add_rule(&pool, "ping limit", "INPUT", "accept", "icmp",
            None, None, None, (false, None, Some("5/second"), false)).await;
        add_rule(&pool, "all udp out", "OUTPUT", "accept", "udp",
            None, None, None, (true, Some("eth0"), None, false)).await;
        add_rule(&pool, "reject telnet", "FORWARD", "reject", "tcp",
            Some("10.1.0.0/16"), Some("10.2.0.0/16"), Some(23), (false, None, Some("1/minute"), true)).await;

        // Rules the generator must skip, and one that is switched off.
        add_rule(&pool, "mixed versions", "FORWARD", "accept", "any",
            Some("10.0.0.1"), Some("2001:db8::1"), None, none).await;
        add_rule(&pool, "bad source", "FORWARD", "accept", "any",
            Some("not-an-ip"), None, None, none).await;
        sqlx::query("UPDATE firewall_rules SET enabled = 0 WHERE name = 'block host'")
            .execute(&pool)
            .await
            .unwrap();

        pool
    }

    const BASELINE: &str = r#"flush ruleset;

table inet filter {

    set ddos_syn_in_v4 {
        type ipv4_addr;
        size 65535;
        flags dynamic,timeout;
        timeout 1m;
    }

    set ddos_conn_in_v4 {
        type ipv4_addr;
        size 65535;
        flags dynamic;
    }

    set ddos_syn_in_v6 {
        type ipv6_addr;
        size 65535;
        flags dynamic,timeout;
        timeout 1m;
    }

    set ddos_conn_in_v6 {
        type ipv6_addr;
        size 65535;
        flags dynamic;
    }

    set ddos_syn_fwd_v4 {
        type ipv4_addr;
        size 65535;
        flags dynamic,timeout;
        timeout 1m;
    }

    set ddos_conn_fwd_v4 {
        type ipv4_addr;
        size 65535;
        flags dynamic;
    }

    set ddos_syn_fwd_v6 {
        type ipv6_addr;
        size 65535;
        flags dynamic,timeout;
        timeout 1m;
    }

    set ddos_conn_fwd_v6 {
        type ipv6_addr;
        size 65535;
        flags dynamic;
    }

    chain input {
        type filter hook input priority 0;
        policy drop;

        iif lo accept
        ct state invalid drop
        ct state established,related accept

        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 drop
        tcp flags & (fin|syn) == (fin|syn) drop
        tcp flags & (syn|rst) == (syn|rst) drop
        tcp flags & (fin|rst) == (fin|rst) drop
        tcp flags & (fin|ack) == fin drop
        tcp flags & (urg|ack) == urg drop
        tcp flags & (psh|ack) == psh drop
        tcp flags & (fin|syn|rst|ack) == syn ct state new add @ddos_syn_in_v4 { ip saddr limit rate over 25/second burst 50 packets } counter drop
        tcp flags & (fin|syn|rst|ack) == syn ct state new add @ddos_syn_in_v6 { ip6 saddr limit rate over 25/second burst 50 packets } counter drop
        tcp flags & (fin|syn|rst|ack) == syn ct state new add @ddos_conn_in_v4 { ip saddr ct count over 100 } counter drop
        tcp flags & (fin|syn|rst|ack) == syn ct state new add @ddos_conn_in_v6 { ip6 saddr ct count over 100 } counter drop

        meta l4proto icmpv6 icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept
        meta l4proto icmpv6 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } ip6 hoplimit 255 accept
        iifname "eth1" ip protocol icmp icmp type echo-request limit rate 10/second accept
        iifname "eth1" meta l4proto icmpv6 icmpv6 type echo-request limit rate 10/second accept

        iifname "eth1" ip saddr 192.168.1.0/24 tcp dport 22 counter log prefix "iqsoft-rule-1: " accept comment "iqsoft-rule-1"
        ip protocol icmp limit rate 5/second counter accept comment "iqsoft-rule-5"

    }

    chain forward {
        type filter hook forward priority 0;
        policy drop;

        ct state invalid drop
        ct state established,related accept

        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 drop
        tcp flags & (fin|syn) == (fin|syn) drop
        tcp flags & (syn|rst) == (syn|rst) drop
        tcp flags & (fin|rst) == (fin|rst) drop
        tcp flags & (fin|ack) == fin drop
        tcp flags & (urg|ack) == urg drop
        tcp flags & (psh|ack) == psh drop
        tcp flags & (fin|syn|rst|ack) == syn ct state new add @ddos_syn_fwd_v4 { ip saddr limit rate over 200/second burst 400 packets } counter drop
        tcp flags & (fin|syn|rst|ack) == syn ct state new add @ddos_syn_fwd_v6 { ip6 saddr limit rate over 200/second burst 400 packets } counter drop
        tcp flags & (fin|syn|rst|ack) == syn ct state new add @ddos_conn_fwd_v4 { ip saddr ct count over 1000 } counter drop
        tcp flags & (fin|syn|rst|ack) == syn ct state new add @ddos_conn_fwd_v6 { ip6 saddr ct count over 1000 } counter drop


        ip daddr 10.0.0.10 tcp dport 443 counter accept comment "iqsoft-rule-2"
        ip6 saddr 2001:db8::/32 ip6 daddr 2001:db8:1::53 udp dport 53 counter accept comment "iqsoft-rule-3"
        ip saddr 10.1.0.0/16 ip daddr 10.2.0.0/16 tcp dport 23 limit rate over 1/minute counter log prefix "iqsoft-rule-7: " reject comment "iqsoft-rule-7"

    }

    chain output {
        type filter hook output priority 0;
        policy accept;

        oifname "eth0" meta l4proto udp counter accept comment "iqsoft-rule-6" # all udp out: all ports intentionally allowed

    }
}

table ip nat {

    chain prerouting {
        type nat hook prerouting priority -100;
        policy accept;

    }

    chain postrouting {
        type nat hook postrouting priority 100;
        policy accept;

        oifname "eth0" masquerade
    }
}
"#;

    /// Locks down the exact nftables text produced for existing (non-object)
    /// rules. If this fails after a generator change, the change altered the
    /// behavior of rules that were already working.
    #[tokio::test]
    async fn baseline_output_is_unchanged() {
        let pool = baseline_pool().await;
        let text = FirewallGenerator::generate(&pool).await.unwrap();

        assert_eq!(without_environment_lines(&text), BASELINE);
    }

    #[tokio::test]
    async fn ddos_protection_covers_input_and_forward_only() {
        let pool = memory_pool().await;
        let text = generate_text(&pool).await;

        let input = &text[text.find("chain input").unwrap()..text.find("chain forward").unwrap()];
        let forward = &text[text.find("chain forward").unwrap()..text.find("chain output").unwrap()];
        let output = &text[text.find("chain output").unwrap()..text.find("table ip nat").unwrap()];

        assert!(input.contains("add @ddos_syn_in_v4 { ip saddr limit rate over 25/second burst 50 packets }"));
        assert!(input.contains("add @ddos_conn_in_v6 { ip6 saddr ct count over 100 }"));
        assert!(forward.contains("add @ddos_syn_fwd_v4 { ip saddr limit rate over 200/second burst 400 packets }"));
        assert!(forward.contains("add @ddos_conn_fwd_v4 { ip saddr ct count over 1000 }"));
        assert!(!output.contains("ddos"));
        assert!(!output.contains("tcp flags"));

        assert_eq!(text.matches("set ddos_").count(), 8);
    }

    #[tokio::test]
    async fn ddos_rules_come_after_established_and_before_user_rules() {
        let pool = baseline_pool().await;
        let text = generate_text(&pool).await;

        let input = &text[text.find("chain input").unwrap()..text.find("chain forward").unwrap()];
        let established = input.find("ct state established,related accept").unwrap();
        let ddos = input.find("tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 drop").unwrap();
        let user_rule = input.find("iqsoft-rule-1").unwrap();

        assert!(established < ddos);
        assert!(ddos < user_rule);
    }

    #[tokio::test]
    async fn ddos_protection_passes_nft_check() {
        let pool = memory_pool().await;
        add_rule(&pool, "web", "FORWARD", "accept", "tcp",
            None, Some("10.0.0.10"), Some(443), (false, None, None, false)).await;
        nft_check(&FirewallGenerator::generate(&pool).await.unwrap());
    }

    #[tokio::test]
    async fn rules_without_ports_use_l4proto_and_pass_nft_check() {
        let pool = memory_pool().await;
        let none = (false, None, None, false);
        let any_ports = (true, None, None, false);

        add_rule(&pool, "all tcp", "FORWARD", "accept", "tcp",
            Some("10.0.0.0/24"), None, None, any_ports).await;
        add_rule(&pool, "all udp", "INPUT", "accept", "udp",
            None, None, None, any_ports).await;
        add_rule(&pool, "web", "FORWARD", "accept", "tcp",
            None, Some("10.0.0.10"), Some(443), none).await;

        let text = generate_text(&pool).await;

        assert!(text.contains("ip saddr 10.0.0.0/24 meta l4proto tcp counter accept comment"));
        assert!(text.contains("meta l4proto udp counter accept comment"));
        assert!(text.contains("ip daddr 10.0.0.10 tcp dport 443 counter accept comment"));
        assert!(!text.contains("accept tcp counter"));
        assert!(!text.replace("meta l4proto tcp counter", "").contains("tcp counter"));
        assert!(!text.replace("meta l4proto udp counter", "").contains("udp counter"));

        nft_check(&FirewallGenerator::generate(&pool).await.unwrap());
    }

    #[tokio::test]
    async fn baseline_passes_nft_check() {
        let pool = baseline_pool().await;
        nft_check(&FirewallGenerator::generate(&pool).await.unwrap());
    }

    async fn set_src_mac(pool: &SqlitePool, rule_name: &str, mac: &str) {
        sqlx::query("UPDATE firewall_rules SET src_mac = ? WHERE name = ?")
            .bind(mac)
            .bind(rule_name)
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn src_mac_renders_as_ether_saddr_after_the_interface() {
        let pool = memory_pool().await;
        let none = (false, None, None, false);

        add_rule(&pool, "block laptop", "FORWARD", "drop", "any",
            None, None, None, (false, Some("eth1"), None, false)).await;
        set_src_mac(&pool, "block laptop", "aa:bb:cc:dd:ee:ff").await;

        add_rule(&pool, "allow ssh from box", "INPUT", "accept", "tcp",
            Some("192.168.1.0/24"), None, Some(22), none).await;
        set_src_mac(&pool, "allow ssh from box", "00:1a:2b:03:04:05").await;

        let text = generate_text(&pool).await;

        assert!(text.contains("iifname \"eth1\" ether saddr aa:bb:cc:dd:ee:ff counter drop comment"));
        assert!(text.contains("ether saddr 00:1a:2b:03:04:05 ip saddr 192.168.1.0/24 tcp dport 22 counter accept comment"));
    }

    #[tokio::test]
    async fn src_mac_is_normalized_again_at_generation_time() {
        let pool = memory_pool().await;

        add_rule(&pool, "upper", "FORWARD", "drop", "any",
            None, None, None, (false, None, None, false)).await;
        set_src_mac(&pool, "upper", "AA-BB-CC-DD-EE-FF").await;

        let text = generate_text(&pool).await;

        assert!(text.contains("ether saddr aa:bb:cc:dd:ee:ff counter drop"));
        assert!(!text.contains("AA-BB"));
    }

    #[tokio::test]
    async fn bad_or_misplaced_src_mac_rows_are_skipped_not_emitted() {
        let pool = memory_pool().await;
        let none = (false, None, None, false);

        let bad_values = [
            "not-a-mac",
            "ff:ff:ff:ff:ff:ff",
            "aa:bb:cc:dd:ee:ff; accept",
            "aa:bb:cc:dd:ee:ff\" accept comment \"x",
        ];

        for (i, value) in bad_values.iter().enumerate() {
            let name = format!("bad mac {}", i);
            add_rule(&pool, &name, "FORWARD", "drop", "any", None, None, None, none).await;
            set_src_mac(&pool, &name, value).await;
        }

        add_rule(&pool, "mac on output", "OUTPUT", "drop", "any",
            None, None, None, none).await;
        set_src_mac(&pool, "mac on output", "aa:bb:cc:dd:ee:ff").await;

        add_rule(&pool, "good neighbour", "FORWARD", "accept", "tcp",
            None, Some("10.0.0.10"), Some(443), none).await;

        let text = generate_text(&pool).await;

        assert!(!text.contains("ether saddr"));
        assert!(!text.contains("not-a-mac"));
        assert!(!text.contains("ff:ff:ff:ff:ff:ff"));
        assert!(text.contains("ip daddr 10.0.0.10 tcp dport 443 counter accept comment"));
    }

    #[tokio::test]
    async fn blank_src_mac_row_behaves_like_no_mac() {
        let pool = memory_pool().await;

        add_rule(&pool, "blank", "FORWARD", "accept", "tcp",
            None, Some("10.0.0.10"), Some(443), (false, None, None, false)).await;
        set_src_mac(&pool, "blank", "   ").await;

        let text = generate_text(&pool).await;

        assert!(text.contains("ip daddr 10.0.0.10 tcp dport 443 counter accept comment"));
        assert!(!text.contains("ether saddr"));
    }

    #[tokio::test]
    async fn src_mac_rules_pass_nft_check() {
        let pool = baseline_pool().await;
        let none = (false, None, None, false);

        add_rule(&pool, "mac drop any", "FORWARD", "drop", "any",
            None, None, None, (false, Some("eth1"), None, true)).await;
        set_src_mac(&pool, "mac drop any", "aa:bb:cc:dd:ee:ff").await;

        add_rule(&pool, "mac v6", "FORWARD", "accept", "udp",
            Some("2001:db8::/32"), Some("2001:db8:1::53"), Some(53), none).await;
        set_src_mac(&pool, "mac v6", "00:1a:2b:03:04:05").await;

        add_rule(&pool, "mac icmp", "INPUT", "accept", "icmp",
            None, None, None, (false, None, Some("5/second"), false)).await;
        set_src_mac(&pool, "mac icmp", "00:1a:2b:03:04:06").await;

        add_rule(&pool, "mac all tcp", "INPUT", "accept", "tcp",
            None, None, None, (true, None, None, false)).await;
        set_src_mac(&pool, "mac all tcp", "00:1a:2b:03:04:07").await;

        let text = FirewallGenerator::generate(&pool).await.unwrap();

        assert_eq!(text.matches("ether saddr").count(), 4);
        nft_check(&text);
    }

    async fn set_time(pool: &SqlitePool, rule_name: &str, start: Option<&str>, end: Option<&str>, days: Option<&str>) {
        sqlx::query("UPDATE firewall_rules SET time_start = ?, time_end = ?, days = ? WHERE name = ?")
            .bind(start)
            .bind(end)
            .bind(days)
            .bind(rule_name)
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn time_window_and_days_render_as_meta_hour_and_meta_day() {
        let pool = memory_pool().await;

        add_rule(&pool, "office hours", "FORWARD", "accept", "tcp",
            None, Some("10.0.0.10"), Some(443), (false, None, None, false)).await;
        set_time(&pool, "office hours", Some("08:00"), Some("18:00"), Some("mon,tue,wed,thu,fri")).await;

        let text = generate_text(&pool).await;

        assert!(text.contains(
            "meta hour \"08:00\"-\"18:00\" meta day { \"Monday\", \"Tuesday\", \"Wednesday\", \"Thursday\", \"Friday\" } ip daddr 10.0.0.10 tcp dport 443 counter accept comment"
        ));
    }

    #[tokio::test]
    async fn overnight_window_is_passed_through_unchanged() {
        let pool = memory_pool().await;

        add_rule(&pool, "night block", "FORWARD", "drop", "any",
            Some("10.5.0.0/24"), None, None, (false, None, None, false)).await;
        set_time(&pool, "night block", Some("22:00"), Some("06:00"), None).await;

        let text = generate_text(&pool).await;

        assert!(text.contains("meta hour \"22:00\"-\"06:00\" ip saddr 10.5.0.0/24 counter drop comment"));
        assert!(!text.contains("meta day"));
    }

    #[tokio::test]
    async fn days_without_a_window_and_all_seven_days() {
        let pool = memory_pool().await;
        let none = (false, None, None, false);

        add_rule(&pool, "weekend only", "FORWARD", "drop", "any", Some("10.6.0.0/24"), None, None, none).await;
        set_time(&pool, "weekend only", None, None, Some("sat,sun")).await;

        add_rule(&pool, "every day", "FORWARD", "drop", "any", Some("10.7.0.0/24"), None, None, none).await;
        set_time(&pool, "every day", None, None, Some("mon,tue,wed,thu,fri,sat,sun")).await;

        let text = generate_text(&pool).await;

        assert!(text.contains("meta day { \"Saturday\", \"Sunday\" } ip saddr 10.6.0.0/24 counter drop comment"));
        assert!(text.contains("ip saddr 10.7.0.0/24 counter drop comment"));
        assert!(!text.contains("meta day { \"Monday\", \"Tuesday\", \"Wednesday\", \"Thursday\", \"Friday\", \"Saturday\", \"Sunday\" }"));
    }

    #[tokio::test]
    async fn time_values_are_normalized_again_at_generation_time() {
        let pool = memory_pool().await;

        add_rule(&pool, "loose values", "INPUT", "accept", "tcp",
            None, None, Some(22), (false, None, None, false)).await;
        set_time(&pool, "loose values", Some("8:05"), Some("18:00"), Some("Mon-Wed")).await;

        let text = generate_text(&pool).await;

        assert!(text.contains("meta hour \"08:05\"-\"18:00\" meta day { \"Monday\", \"Tuesday\", \"Wednesday\" } tcp dport 22 counter accept comment"));
    }

    #[tokio::test]
    async fn bad_time_rows_are_skipped_not_emitted() {
        let pool = memory_pool().await;
        let none = (false, None, None, false);

        let bad: [(Option<&str>, Option<&str>, Option<&str>); 7] = [
            (Some("08:00"), None, None),
            (None, Some("18:00"), None),
            (Some("08:00"), Some("8:00"), None),
            (Some("25:00"), Some("18:00"), None),
            (Some("08:00"), Some("18:00\" accept"), None),
            (None, None, Some("funday")),
            (None, None, Some("mon\" accept comment \"x")),
        ];

        for (i, (start, end, days)) in bad.iter().enumerate() {
            let name = format!("bad time {}", i);
            add_rule(&pool, &name, "FORWARD", "drop", "any", None, None, None, none).await;
            set_time(&pool, &name, *start, *end, *days).await;
        }

        add_rule(&pool, "good neighbour", "FORWARD", "accept", "tcp",
            None, Some("10.0.0.10"), Some(443), none).await;

        let text = generate_text(&pool).await;

        assert!(!text.contains("meta hour"));
        assert!(!text.contains("meta day"));
        assert!(!text.contains("funday"));
        assert!(text.contains("ip daddr 10.0.0.10 tcp dport 443 counter accept comment"));
    }

    #[tokio::test]
    async fn blank_time_row_behaves_like_no_time() {
        let pool = memory_pool().await;

        add_rule(&pool, "blank", "FORWARD", "accept", "tcp",
            None, Some("10.0.0.10"), Some(443), (false, None, None, false)).await;
        set_time(&pool, "blank", Some(" "), Some(""), Some("  ")).await;

        let text = generate_text(&pool).await;

        assert!(text.contains("ip daddr 10.0.0.10 tcp dport 443 counter accept comment"));
        assert!(!text.contains("meta hour"));
        assert!(!text.contains("meta day"));
    }

    #[tokio::test]
    async fn time_rules_pass_nft_check_together_with_other_matches() {
        let pool = baseline_pool().await;

        add_rule(&pool, "combined", "FORWARD", "drop", "tcp",
            Some("192.168.1.0/24"), Some("10.0.0.10"), Some(443), (false, Some("eth1"), Some("5/second"), true)).await;
        set_src_mac(&pool, "combined", "aa:bb:cc:dd:ee:ff").await;
        set_time(&pool, "combined", Some("22:00"), Some("06:00"), Some("fri,sat")).await;

        add_rule(&pool, "input hours", "INPUT", "accept", "tcp",
            None, None, Some(22), (false, None, None, false)).await;
        set_time(&pool, "input hours", Some("08:00"), Some("18:00"), None).await;

        add_rule(&pool, "output days", "OUTPUT", "accept", "udp",
            None, None, Some(53), (false, Some("eth0"), None, false)).await;
        set_time(&pool, "output days", None, None, Some("mon-fri")).await;

        add_rule(&pool, "v6 hours", "FORWARD", "accept", "icmp",
            Some("2001:db8::/32"), None, None, (false, None, None, false)).await;
        set_time(&pool, "v6 hours", Some("09:00"), Some("17:00"), Some("mon,wed")).await;

        let text = FirewallGenerator::generate(&pool).await.unwrap();

        assert_eq!(text.matches("meta hour").count(), 3);
        assert_eq!(text.matches("meta day").count(), 3);
        nft_check(&text);
    }

    #[tokio::test]
    async fn generation_is_deterministic() {
        let pool = baseline_pool().await;

        let first = FirewallGenerator::generate(&pool).await.unwrap();
        let second = FirewallGenerator::generate(&pool).await.unwrap();

        assert_eq!(first, second);
    }

    // ------------------------------------------------------------------
    // Address objects and groups
    // ------------------------------------------------------------------

    use crate::models::address::{AddressGroup, AddressObject};
    use crate::services::address_service::AddressService;

    async fn add_object(pool: &SqlitePool, name: &str, kind: &str, value: &str) {
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

    async fn rule_with(pool: &SqlitePool, name: &str, src: Option<&str>, dst: Option<&str>) {
        add_rule(pool, name, "FORWARD", "accept", "tcp", src, dst, Some(443), (false, None, None, false)).await;
    }

    async fn generate_text(pool: &SqlitePool) -> String {
        without_environment_lines(&FirewallGenerator::generate(pool).await.unwrap())
    }

    /// Runs the ruleset through the real `nft --check` when it can.
    /// Skipped when nft is missing or when we are not allowed to talk to the kernel.
    fn nft_check(ruleset: &str) {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let Ok(mut child) = Command::new("nft")
            .args(["--check", "--file", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        else {
            return;
        };

        child.stdin.take().unwrap().write_all(ruleset.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);

        if err.contains("Operation not permitted") {
            return;
        }

        assert!(out.status.success(), "nft --check failed:\n{}\n{}", err, ruleset);
    }

    #[tokio::test]
    async fn unused_objects_and_groups_do_not_change_the_output() {
        let plain = baseline_pool().await;
        let with_objects = baseline_pool().await;

        add_object(&with_objects, "web1", "host", "10.0.0.1").await;
        add_object(&with_objects, "lan", "subnet", "192.168.1.0/24").await;
        add_object(&with_objects, "v6net", "subnet", "2001:db8::/32").await;
        add_group(&with_objects, "servers", &["web1"]).await;

        assert_eq!(generate_text(&plain).await, generate_text(&with_objects).await);
    }

    #[tokio::test]
    async fn object_reference_becomes_a_set_and_a_match() {
        let pool = memory_pool().await;
        add_object(&pool, "web1", "host", "10.0.0.1").await;
        rule_with(&pool, "to web", None, Some("@web1")).await;

        let text = generate_text(&pool).await;

        assert!(text.contains(
            "    set addr_web1 {\n        type ipv4_addr;\n        flags interval;\n        auto-merge;\n        elements = { 10.0.0.1 }\n    }\n"
        ));
        assert!(text.contains("ip daddr @addr_web1 tcp dport 443 counter accept comment \"iqsoft-rule-1\""));
        nft_check(&text);
    }

    #[tokio::test]
    async fn group_reference_holds_every_member_of_every_kind() {
        let pool = memory_pool().await;
        add_object(&pool, "a", "host", "10.0.0.5").await;
        add_object(&pool, "b", "subnet", "10.1.0.0/16").await;
        add_object(&pool, "c", "range", "10.2.0.10-10.2.0.20").await;
        add_group(&pool, "office", &["a", "b", "c"]).await;
        rule_with(&pool, "from office", Some("@office"), None).await;

        let text = generate_text(&pool).await;

        assert!(text.contains("elements = { 10.0.0.5, 10.1.0.0/16, 10.2.0.10-10.2.0.20 }"));
        assert!(text.contains("ip saddr @addr_office tcp dport 443"));
        nft_check(&text);
    }

    #[tokio::test]
    async fn ipv6_group_uses_ip6_and_an_ipv6_set() {
        let pool = memory_pool().await;
        add_object(&pool, "n1", "subnet", "2001:db8::/32").await;
        add_object(&pool, "n2", "host", "fd00::1").await;
        add_group(&pool, "v6grp", &["n1", "n2"]).await;
        rule_with(&pool, "v6 rule", Some("@v6grp"), Some("2001:db8:1::53")).await;

        let text = generate_text(&pool).await;

        assert!(text.contains("type ipv6_addr;"));
        assert!(text.contains("ip6 saddr @addr_v6grp ip6 daddr 2001:db8:1::53 tcp dport 443"));
        nft_check(&text);
    }

    #[tokio::test]
    async fn overlapping_members_still_pass_nft_check() {
        let pool = memory_pool().await;
        add_object(&pool, "host_in_net", "host", "10.0.0.5").await;
        add_object(&pool, "whole_net", "subnet", "10.0.0.0/24").await;
        add_object(&pool, "part_range", "range", "10.0.0.10-10.0.0.20").await;
        add_group(&pool, "overlap", &["host_in_net", "whole_net", "part_range"]).await;
        rule_with(&pool, "overlap rule", Some("@overlap"), None).await;

        nft_check(&generate_text(&pool).await);
    }

    #[tokio::test]
    async fn only_sets_used_by_enabled_rules_are_emitted() {
        let pool = memory_pool().await;
        add_object(&pool, "used", "host", "10.0.0.1").await;
        add_object(&pool, "idle", "host", "10.0.0.2").await;
        add_object(&pool, "off", "host", "10.0.0.3").await;
        rule_with(&pool, "uses", Some("@used"), None).await;
        rule_with(&pool, "disabled one", Some("@off"), None).await;
        sqlx::query("UPDATE firewall_rules SET enabled = 0 WHERE name = 'disabled one'")
            .execute(&pool)
            .await
            .unwrap();

        let text = generate_text(&pool).await;

        assert!(text.contains("set addr_used {"));
        assert!(!text.contains("addr_idle"));
        assert!(!text.contains("addr_off"));
    }

    #[tokio::test]
    async fn references_are_case_insensitive_and_share_one_set() {
        let pool = memory_pool().await;
        add_object(&pool, "Web1", "host", "10.0.0.1").await;
        rule_with(&pool, "one", Some("@WEB1"), None).await;
        rule_with(&pool, "two", None, Some("@web1")).await;

        let text = generate_text(&pool).await;

        assert_eq!(text.matches("set addr_web1 {").count(), 1);
        assert!(text.contains("ip saddr @addr_web1 "));
        assert!(text.contains("ip daddr @addr_web1 "));
        nft_check(&text);
    }

    #[tokio::test]
    async fn rules_with_bad_references_are_skipped_not_fatal() {
        let pool = memory_pool().await;
        add_object(&pool, "web1", "host", "10.0.0.1").await;
        add_object(&pool, "v6host", "host", "2001:db8::1").await;
        add_group(&pool, "empty_grp", &[]).await;

        rule_with(&pool, "unknown", Some("@nope"), None).await;
        rule_with(&pool, "empty group", Some("@empty_grp"), None).await;
        rule_with(&pool, "mixed versions", Some("@web1"), Some("@v6host")).await;
        rule_with(&pool, "mixed with literal", Some("@web1"), Some("2001:db8::9")).await;
        rule_with(&pool, "injection", Some("@web1; flush ruleset"), None).await;
        rule_with(&pool, "bare at", Some("@"), None).await;
        rule_with(&pool, "good", Some("@web1"), None).await;

        let text = generate_text(&pool).await;

        assert_eq!(text.matches("saddr @addr_web1 ").count(), 1);
        assert!(text.contains("comment \"iqsoft-rule-7\""));
        for skipped in 1..=6 {
            assert!(!text.contains(&format!("comment \"iqsoft-rule-{}\"", skipped)));
        }
        assert!(!text.contains("addr_empty_grp"));
        assert!(!text.contains("addr_nope"));
        assert_eq!(text.matches("flush ruleset").count(), 1);
        nft_check(&text);
    }

    #[tokio::test]
    async fn output_with_objects_is_deterministic() {
        let pool = memory_pool().await;
        add_object(&pool, "z1", "host", "10.0.0.9").await;
        add_object(&pool, "a1", "host", "10.0.0.1").await;
        add_group(&pool, "grp", &["z1", "a1"]).await;
        rule_with(&pool, "r1", Some("@grp"), Some("@z1")).await;
        rule_with(&pool, "r2", Some("@a1"), None).await;

        let first = generate_text(&pool).await;
        let second = generate_text(&pool).await;

        assert_eq!(first, second);
        // sets come out in name order, elements in sorted order
        assert!(first.find("set addr_a1 ").unwrap() < first.find("set addr_grp ").unwrap());
        assert!(first.contains("elements = { 10.0.0.1, 10.0.0.9 }"));
    }

    #[tokio::test]
    async fn wireguard_disabled_adds_nothing_to_the_ruleset() {
        let pool = memory_pool().await;

        let out = FirewallGenerator::generate(&pool).await.unwrap();

        assert!(!out.contains("WireGuard"));
    }

    #[tokio::test]
    async fn wireguard_enabled_opens_the_listen_port_and_tunnel_ping() {
        let pool = memory_pool().await;

        sqlx::query(
            "UPDATE wireguard_config SET enabled = 1, listen_port = 51821, interface_name = 'wg7' WHERE id = 1",
        )
        .execute(&pool)
        .await
        .unwrap();

        let out = FirewallGenerator::generate(&pool).await.unwrap();

        assert!(out.contains("        udp dport 51821 accept # WireGuard VPN\n"));
        assert!(out.contains(
            "        iifname \"wg7\" ip protocol icmp icmp type echo-request limit rate 10/second accept\n"
        ));
        assert!(out.contains(
            "        iifname \"wg7\" meta l4proto icmpv6 icmpv6 type echo-request limit rate 10/second accept\n"
        ));

        // Only the INPUT chain is touched: forwarding stays closed by default.
        let forward_start = out.find("chain forward").unwrap();
        let output_start = out.find("chain output").unwrap();
        assert!(!out[forward_start..output_start].contains("wg7"));
    }

    #[tokio::test]
    async fn wireguard_rules_are_in_the_input_chain() {
        let pool = memory_pool().await;

        sqlx::query("UPDATE wireguard_config SET enabled = 1 WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();

        let out = FirewallGenerator::generate(&pool).await.unwrap();
        let input_start = out.find("chain input").unwrap();
        let forward_start = out.find("chain forward").unwrap();
        let wg = out.find("# WireGuard VPN").unwrap();

        assert!(wg > input_start && wg < forward_start);
    }

    #[test]
    fn wireguard_block_is_empty_for_unsafe_interface_names() {
        let config = WireguardConfig {
            enabled: true,
            interface_name: "wg0\" drop #".into(),
            listen_port: 51820,
            address: "10.8.0.1/24".into(),
            mtu: None,
            dns: None,
            endpoint: None,
            client_allowed_ips: vec!["0.0.0.0/0".into()],
            private_key: String::new(),
            public_key: String::new(),
        };

        assert_eq!(FirewallGenerator::wireguard_input_block(&config), "");
    }

}

