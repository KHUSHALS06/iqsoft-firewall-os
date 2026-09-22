use crate::models::dhcp::{DhcpConfig, DhcpReservation};
use crate::services::dhcp_service::DhcpService;
use ipnet::Ipv4Net;

pub const LEASE_FILE_PATH: &str = "/var/lib/misc/dnsmasq.leases";

pub struct DhcpGenerator;

impl DhcpGenerator {
    pub fn render(
        config: &DhcpConfig,
        reservations: &[DhcpReservation],
    ) -> Result<String, String> {
        let mut out = String::new();

        out.push_str("port=0\n");
        out.push_str("bind-interfaces\n");

        if !config.enabled {
            return Ok(out);
        }

        DhcpService::validate_config(config)?;

        let subnet: Ipv4Net = config
            .subnet
            .trim()
            .parse()
            .map_err(|_| format!("Invalid subnet: '{}'", config.subnet))?;

        out.push_str(&format!("interface={}\n", config.interface_name.trim()));
        out.push_str("dhcp-authoritative\n");
        out.push_str(&format!("dhcp-leasefile={}\n", LEASE_FILE_PATH));
        out.push_str(&format!(
            "dhcp-range={},{},{},{}\n",
            config.range_start.trim(),
            config.range_end.trim(),
            subnet.netmask(),
            config.lease_time_seconds
        ));

        if let Some(gateway) = &config.gateway {
            out.push_str(&format!(
                "dhcp-option=option:router,{}\n",
                gateway.trim()
            ));
        }

        let dns: Vec<&str> = config.dns_servers.iter().map(|d| d.trim()).collect();
        out.push_str(&format!(
            "dhcp-option=option:dns-server,{}\n",
            dns.join(",")
        ));

        if let Some(domain) = &config.domain {
            out.push_str(&format!(
                "dhcp-option=option:domain-name,{}\n",
                domain
            ));
        }

        for reservation in reservations {
            if let Err(e) = DhcpService::validate_reservation(reservation, config) {
                eprintln!(
                    "WARNING: skipping DHCP reservation {} ({}) — {}",
                    reservation.mac, reservation.ip, e
                );
                continue;
            }

            let mac = match DhcpService::normalize_mac(&reservation.mac) {
                Ok(mac) => mac,
                Err(_) => continue,
            };

            match &reservation.hostname {
                Some(hostname) if !hostname.trim().is_empty() => {
                    out.push_str(&format!(
                        "dhcp-host={},{},{}\n",
                        mac,
                        reservation.ip.trim(),
                        hostname.trim()
                    ));
                }
                _ => {
                    out.push_str(&format!(
                        "dhcp-host={},{}\n",
                        mac,
                        reservation.ip.trim()
                    ));
                }
            }
        }

        Ok(out)
    }
}
