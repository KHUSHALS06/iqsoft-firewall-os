use crate::{
    models::{
        dhcp::DhcpConfig,
        dns::DnsConfig,
        firewall_rule::{normalize_rate_limit, FirewallRule},
        network_config::NetworkConfig,
        port_forward::PortForwardRule,
    },
    repository::{
        dhcp_repository::DhcpRepository,
        dns_repository::DnsRepository,
        firewall_repository::FirewallRepository,
        network_config_repository::NetworkConfigRepository,
        port_forward_repository::PortForwardRepository,
    },
};

use ipnet::IpNet;
use sqlx::SqlitePool;
use std::net::{Ipv4Addr, SocketAddr};

pub struct FirewallGenerator;

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

        let port_forwards: Vec<PortForwardRule> = PortForwardRepository::list_rules(pool)
            .await
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter(|r| r.enabled)
            .collect();

        let mut output = String::new();

        // flush ruleset first: nftables config is declarative in the kernel and repeated commits duplicate rules.
        output.push_str("flush ruleset;\n\n");

        output.push_str("table inet filter {\n\n");

        // INPUT
        output.push_str("    chain input {\n");
        output.push_str("        type filter hook input priority 0;\n");
        output.push_str("        policy drop;\n\n");

        output.push_str("        iif lo accept\n");
        output.push_str("        ct state invalid drop\n");
        output.push_str("        ct state established,related accept\n\n");

        Self::generate_self_protection(&mut output, &net_config, &dhcp_config, &dns_config);

        Self::generate_chain(&mut output, &rules, "INPUT");

        output.push_str("    }\n\n");

        // FORWARD
        output.push_str("    chain forward {\n");
        output.push_str("        type filter hook forward priority 0;\n");
        output.push_str("        policy drop;\n\n");

        // Replies to allowed connections (including replies from a port-forwarded
        // server back to the internet) must be let through.
        output.push_str("        ct state invalid drop\n");
        output.push_str("        ct state established,related accept\n\n");

        Self::generate_port_forward_accepts(&mut output, &net_config, &port_forwards);

        Self::generate_chain(&mut output, &rules, "FORWARD");

        output.push_str("    }\n\n");

        // OUTPUT
        output.push_str("    chain output {\n");
        output.push_str("        type filter hook output priority 0;\n");
        output.push_str("        policy accept;\n\n");

        Self::generate_chain(&mut output, &rules, "OUTPUT");

        output.push_str("    }\n");

        output.push_str("}\n\n");

        Self::generate_nat_table(&mut output, &net_config, &port_forwards);

        Ok(output)
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

    fn generate_nat_table(
        output: &mut String,
        net_config: &NetworkConfig,
        port_forwards: &[PortForwardRule],
    ) {
        let has_forwards = !port_forwards.is_empty();

        if !net_config.nat_enabled && !has_forwards {
            return;
        }

        let wan = net_config.wan_interface.trim();
        if wan.is_empty() {
            eprintln!("WARNING: NAT/port forwarding is enabled but no WAN interface is configured - skipping NAT table");
            return;
        }

        output.push_str("table ip nat {\n\n");

        // Port forwarding (DNAT)
        output.push_str("    chain prerouting {\n");
        output.push_str("        type nat hook prerouting priority -100;\n");
        output.push_str("        policy accept;\n\n");

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

        // Outbound NAT (masquerade)
        output.push_str("    chain postrouting {\n");
        output.push_str("        type nat hook postrouting priority 100;\n");
        output.push_str("        policy accept;\n\n");

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

            let mut src_is_v6: Option<bool> = None;
            if let Some(src) = &rule.src_ip {
                let trimmed = src.trim();
                if !trimmed.is_empty() {
                    match Self::ip_family(trimmed) {
                        Some(is_v6) => src_is_v6 = Some(is_v6),
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

            let mut dst_is_v6: Option<bool> = None;
            if let Some(dst) = &rule.dst_ip {
                let trimmed = dst.trim();
                if !trimmed.is_empty() {
                    match Self::ip_family(trimmed) {
                        Some(is_v6) => dst_is_v6 = Some(is_v6),
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

            if let Some(src) = &rule.src_ip {
                let trimmed = src.trim();
                if !trimmed.is_empty() {
                    let keyword = if src_is_v6 == Some(true) { "ip6" } else { "ip" };
                    line.push_str(&format!("{} saddr {} ", keyword, trimmed));
                }
            }

            if let Some(dst) = &rule.dst_ip {
                let trimmed = dst.trim();
                if !trimmed.is_empty() {
                    let keyword = if dst_is_v6 == Some(true) { "ip6" } else { "ip" };
                    line.push_str(&format!("{} daddr {} ", keyword, trimmed));
                }
            }

            match rule.protocol.to_lowercase().as_str() {
                "tcp" => {
                    line.push_str("tcp ");

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
                    line.push_str("udp ");

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
