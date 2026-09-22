use crate::models::dhcp::DhcpSnapshot;
use crate::models::dns::{DnsConfig, DnsStaticRecord};
use crate::services::dns_service::DnsService;
use std::fs;
use std::net::Ipv4Addr;

pub const DHCP_SNAPSHOT_PATH: &str = "config-history/current.dhcp.json";

pub struct DnsGenerator;

impl DnsGenerator {
    pub fn render(
        config: &DnsConfig,
        records: &[DnsStaticRecord],
    ) -> Result<String, String> {
        let mut out = String::new();

        if !config.enabled {
            return Ok(out);
        }

        DnsService::validate_config(config, records)?;

        out.push_str("no-resolv\n");
        out.push_str("no-hosts\n");

        for iface in &config.listen_interfaces {
            out.push_str(&format!("interface={}\n", iface));
        }

        for server in &config.upstream_servers {
            out.push_str(&format!("server={}\n", server));
        }

        if let Some(domain) = &config.local_domain {
            out.push_str(&format!("domain={}\n", domain));
            out.push_str("expand-hosts\n");
            out.push_str(&format!("local=/{}/\n", domain));
        }

        for record in records {
            if let Err(e) = DnsService::validate_record(record) {
                eprintln!(
                    "WARNING: skipping DNS record '{}' ({}) — {}",
                    record.hostname, record.ip, e
                );
                continue;
            }
            out.push_str(&format!("address=/{}/{}\n", record.hostname, record.ip));
        }

        if config.use_dhcp_hostnames {
            out.push_str(&Self::render_dhcp_hostnames(records)?);
        }

        Ok(out)
    }

    fn render_dhcp_hostnames(existing: &[DnsStaticRecord]) -> Result<String, String> {
        let mut out = String::new();

        let content = match fs::read_to_string(DHCP_SNAPSHOT_PATH) {
            Ok(c) => c,
            Err(_) => return Ok(out),
        };

        let snapshot: DhcpSnapshot = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse DHCP snapshot: {}", e))?;

        for reservation in &snapshot.reservations {
            let hostname = match &reservation.hostname {
                Some(h) if !h.trim().is_empty() => h.trim(),
                _ => continue,
            };

            if existing
                .iter()
                .any(|r| r.hostname.eq_ignore_ascii_case(hostname))
            {
                continue;
            }

            if !Self::is_safe_hostname(hostname) {
                eprintln!(
                    "WARNING: skipping DHCP hostname '{}' — contains invalid characters",
                    hostname
                );
                continue;
            }
            if reservation.ip.trim().parse::<Ipv4Addr>().is_err() {
                eprintln!(
                    "WARNING: skipping DHCP hostname '{}' — invalid IP '{}'",
                    hostname, reservation.ip
                );
                continue;
            }

            out.push_str(&format!(
                "address=/{}/{}\n",
                hostname.to_ascii_lowercase(),
                reservation.ip.trim()
            ));
        }

        Ok(out)
    }

    fn is_safe_hostname(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 63
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
    }
}
