use crate::models::interface_config::{InterfaceConfig, MODE_DHCP, MODE_STATIC};
use crate::repository::interface_config_repository::InterfaceConfigRepository;
use ipnet::IpNet;
use sqlx::SqlitePool;
use std::net::IpAddr;
use std::str::FromStr;

const MAX_ADDRESSES: usize = 8;
const MAX_DNS: usize = 3;
const MIN_MTU: u32 = 576;
const MAX_MTU: u32 = 9216;
const MAX_COMMENT_LEN: usize = 200;

pub struct InterfaceConfigService;

impl InterfaceConfigService {
    pub async fn list(pool: &SqlitePool) -> Result<Vec<InterfaceConfig>, String> {
        InterfaceConfigRepository::list(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn save(
        pool: &SqlitePool,
        name: &str,
        mut cfg: InterfaceConfig,
    ) -> Result<InterfaceConfig, String> {
        cfg.name = name.to_string();
        Self::normalize(&mut cfg)?;

        let others: Vec<InterfaceConfig> = Self::list(pool)
            .await?
            .into_iter()
            .filter(|o| o.name != cfg.name)
            .collect();
        Self::check_overlap(&cfg, &others)?;

        InterfaceConfigRepository::upsert(pool, &cfg)
            .await
            .map_err(|e| e.to_string())?;

        Ok(cfg)
    }

    pub async fn delete(pool: &SqlitePool, name: &str) -> Result<(), String> {
        let removed = InterfaceConfigRepository::delete(pool, name)
            .await
            .map_err(|e| e.to_string())?;

        if removed == 0 {
            return Err(format!("No saved settings for port '{}'", name));
        }
        Ok(())
    }

    pub fn validate_name(name: &str) -> Result<(), String> {
        let name = name.trim();

        if name.is_empty() {
            return Err("Port name cannot be empty".into());
        }
        if name.len() > 15 {
            return Err(format!("Port name '{}' is too long for Linux (15 characters at most)", name));
        }
        if name == "lo" {
            return Err("The loopback port 'lo' cannot be changed".into());
        }
        if name.starts_with('.') || name.starts_with('-') {
            return Err(format!("Port name '{}' is not valid", name));
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(format!("Port name '{}' contains invalid characters", name));
        }
        Ok(())
    }

    /// Cleans the values and rejects anything that is not valid. Addresses end up as "ip/prefix".
    pub fn normalize(cfg: &mut InterfaceConfig) -> Result<(), String> {
        cfg.name = cfg.name.trim().to_string();
        Self::validate_name(&cfg.name)?;

        cfg.mode = cfg.mode.trim().to_ascii_lowercase();
        if cfg.mode != MODE_STATIC && cfg.mode != MODE_DHCP {
            return Err("Mode must be 'static' or 'dhcp'".into());
        }

        let mut nets: Vec<IpNet> = Vec::new();

        if cfg.mode == MODE_STATIC {
            if cfg.addresses.len() > MAX_ADDRESSES {
                return Err(format!("A port can have at most {} addresses", MAX_ADDRESSES));
            }
            for raw in &cfg.addresses {
                let raw = raw.trim();
                if !raw.contains('/') {
                    return Err(format!(
                        "'{}' needs a prefix length, for example {}/24",
                        raw, raw
                    ));
                }
                let net = IpNet::from_str(raw).map_err(|_| {
                    format!("'{}' is not a valid address, use a form like 192.168.1.1/24", raw)
                })?;
                let ip = net.addr();
                if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
                    return Err(format!("'{}' cannot be used as a port address", raw));
                }
                if net.prefix_len() == 0 {
                    return Err(format!("'{}' has an empty network (/0)", raw));
                }
                if nets.iter().any(|n| n.addr() == ip) {
                    return Err(format!("Address {} is listed twice", ip));
                }
                nets.push(net);
            }
            cfg.addresses = nets
                .iter()
                .map(|n| format!("{}/{}", n.addr(), n.prefix_len()))
                .collect();
        } else {
            cfg.addresses.clear();
            cfg.gateway = None;
        }

        let gateway = cfg
            .gateway
            .take()
            .map(|g| g.trim().to_string())
            .filter(|g| !g.is_empty());

        if let Some(raw) = gateway {
            let gw: IpAddr = raw
                .parse()
                .map_err(|_| format!("Gateway '{}' is not a valid IP address", raw))?;
            if gw.is_unspecified() || gw.is_multicast() {
                return Err(format!("Gateway '{}' cannot be used", raw));
            }
            if nets.iter().any(|n| n.addr() == gw) {
                return Err("The gateway cannot be this port's own address".into());
            }
            let link_local_v6 = matches!(gw, IpAddr::V6(v) if (v.segments()[0] & 0xffc0) == 0xfe80);
            let on_link = nets
                .iter()
                .any(|n| n.addr().is_ipv4() == gw.is_ipv4() && n.contains(&gw));
            if !on_link && !link_local_v6 {
                return Err(format!(
                    "Gateway {} is not inside any of this port's networks",
                    gw
                ));
            }
            cfg.gateway = Some(gw.to_string());
        }

        let mut dns: Vec<String> = Vec::new();
        for raw in &cfg.dns {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            let ip: IpAddr = raw
                .parse()
                .map_err(|_| format!("DNS server '{}' is not a valid IP address", raw))?;
            let text = ip.to_string();
            if !dns.contains(&text) {
                dns.push(text);
            }
        }
        if dns.len() > MAX_DNS {
            return Err(format!("Use at most {} DNS servers", MAX_DNS));
        }
        cfg.dns = dns;

        if let Some(mtu) = cfg.mtu {
            if !(MIN_MTU..=MAX_MTU).contains(&mtu) {
                return Err(format!("MTU must be between {} and {}", MIN_MTU, MAX_MTU));
            }
        }

        cfg.comment = cfg
            .comment
            .take()
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty());
        if let Some(c) = &cfg.comment {
            if c.len() > MAX_COMMENT_LEN {
                return Err(format!("Comment is longer than {} characters", MAX_COMMENT_LEN));
            }
        }

        Ok(())
    }

    /// Two ports cannot sit in the same network, the firewall would not know where to send traffic.
    pub fn check_overlap(cfg: &InterfaceConfig, others: &[InterfaceConfig]) -> Result<(), String> {
        for mine in cfg.addresses.iter().filter_map(|a| IpNet::from_str(a).ok()) {
            for other in others {
                for theirs in other.addresses.iter().filter_map(|a| IpNet::from_str(a).ok()) {
                    if mine.addr().is_ipv4() != theirs.addr().is_ipv4() {
                        continue;
                    }
                    if mine.trunc().contains(&theirs.trunc().addr())
                        || theirs.trunc().contains(&mine.trunc().addr())
                    {
                        return Err(format!(
                            "{} overlaps with {} on port {}. Two ports cannot be in the same network.",
                            mine, theirs, other.name
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(name: &str, addresses: &[&str], gateway: Option<&str>) -> InterfaceConfig {
        InterfaceConfig {
            name: name.into(),
            mode: "static".into(),
            addresses: addresses.iter().map(|s| s.to_string()).collect(),
            gateway: gateway.map(|g| g.to_string()),
            dns: vec![],
            mtu: None,
            enabled: true,
            comment: None,
        }
    }

    #[test]
    fn accepts_a_normal_static_port() {
        let mut c = cfg("enp3s0", &["192.168.1.1/24"], Some("192.168.1.254"));
        c.dns = vec!["1.1.1.1".into(), "8.8.8.8".into()];
        c.mtu = Some(1500);
        assert!(InterfaceConfigService::normalize(&mut c).is_ok());
        assert_eq!(c.addresses, vec!["192.168.1.1/24".to_string()]);
    }

    #[test]
    fn rejects_missing_prefix_and_bad_values() {
        assert!(InterfaceConfigService::normalize(&mut cfg("eth0", &["192.168.1.1"], None)).is_err());
        assert!(InterfaceConfigService::normalize(&mut cfg("eth0", &["999.1.1.1/24"], None)).is_err());
        assert!(InterfaceConfigService::normalize(&mut cfg("lo", &["10.0.0.1/24"], None)).is_err());
        assert!(InterfaceConfigService::normalize(&mut cfg("eth0", &["127.0.0.1/8"], None)).is_err());
    }

    #[test]
    fn gateway_must_be_on_the_port_network() {
        let mut c = cfg("eth0", &["192.168.1.1/24"], Some("10.9.9.9"));
        assert!(InterfaceConfigService::normalize(&mut c).is_err());
        let mut own = cfg("eth0", &["192.168.1.1/24"], Some("192.168.1.1"));
        assert!(InterfaceConfigService::normalize(&mut own).is_err());
    }

    #[test]
    fn dhcp_clears_static_values() {
        let mut c = cfg("eth0", &["192.168.1.1/24"], Some("192.168.1.254"));
        c.mode = "dhcp".into();
        assert!(InterfaceConfigService::normalize(&mut c).is_ok());
        assert!(c.addresses.is_empty());
        assert!(c.gateway.is_none());
    }

    #[test]
    fn overlapping_networks_on_two_ports_are_refused() {
        let a = cfg("eth0", &["192.168.1.1/24"], None);
        let b = cfg("eth1", &["192.168.1.50/25"], None);
        assert!(InterfaceConfigService::check_overlap(&b, &[a.clone()]).is_err());
        let c = cfg("eth1", &["192.168.2.1/24"], None);
        assert!(InterfaceConfigService::check_overlap(&c, &[a]).is_ok());
    }
}
