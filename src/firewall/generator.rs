use crate::{
    models::firewall_rule::FirewallRule,
    repository::firewall_repository::FirewallRepository,
};

use sqlx::SqlitePool;

pub struct FirewallGenerator;

impl FirewallGenerator {
    pub async fn generate(pool: &SqlitePool) -> Result<String, String> {
        let rules = FirewallRepository::list_rules(pool)
            .await
            .map_err(|e| e.to_string())?;

        let mut output = String::new();

        // Full replace, not accumulation — without this, deleted rules
        // stay live in the kernel and repeated commits duplicate rules.
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

        Self::generate_chain(&mut output, &rules, "FORWARD");

        output.push_str("    }\n\n");

        // OUTPUT
        output.push_str("    chain output {\n");
        output.push_str("        type filter hook output priority 0;\n");
        output.push_str("        policy accept;\n\n");

        Self::generate_chain(&mut output, &rules, "OUTPUT");

        output.push_str("    }\n");

        output.push_str("}\n");

        Ok(output)
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

            if let Some(src) = &rule.src_ip {
                if !src.trim().is_empty() {
                    line.push_str(&format!("ip saddr {} ", src));
                }
            }

            if let Some(dst) = &rule.dst_ip {
                if !dst.trim().is_empty() {
                    line.push_str(&format!("ip daddr {} ", dst));
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
                    line.push_str("ip protocol icmp ");
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
}
