use crate::{
    models::{
        firewall_rule::FirewallRule, network_config::NetworkConfig,
        port_forward::PortForwardRule,
    },
    repository::{
        firewall_repository::FirewallRepository,
        network_config_repository::NetworkConfigRepository,
        port_forward_repository::PortForwardRepository,
    },
};

use ipnet::IpNet;
use sqlx::SqlitePool;
use std::net::Ipv4Addr;

pub struct FirewallGenerator;

impl FirewallGenerator {
    pub async fn generate(pool: &SqlitePool) -> Result<String, String> {
        let rules = FirewallRepository::list_rules(pool)
            .await
            .map_err(|e| e.to_string())?;

        let net_config = NetworkConfigRepository::get(pool)
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
        output.push_str("        ct state established,related accept\n\n");

        Self::generate_chain(&mut output, &rules, "INPUT");

        output.push_str("    }\n\n");

        // FORWARD
        output.push_str("    chain forward {\n");
        output.push_str("        type filter hook forward priority 0;\n");
        output.push_str("        policy drop;\n\n");

        // Replies to allowed connections (including replies from a port-forwarded
        // server back to the internet) must be let through.
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
                    rule.name.replace('\n', " ").replace('\r', " "),
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
                    rule.name.replace('\n', " ").replace('\r', " "),
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
                if !iface.trim().is_empty() {
                    line.push_str(&format!("iif \"{}\" ", iface));
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

            if rule.log_enabled {
                line.push_str("log ");
            }

            match rule.action.to_lowercase().as_str() {
                "accept" => line.push_str("accept"),
                "drop" => line.push_str("drop"),
                "reject" => line.push_str("reject"),
                _ => continue,
            }

            if port_any_marker {
                line.push_str(&format!(" # {}: all ports intentionally allowed", rule.name));
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
