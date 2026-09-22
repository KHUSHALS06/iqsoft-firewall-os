use crate::models::dhcp::{DhcpConfig, DhcpReservation};
use crate::repository::dhcp_repository::DhcpRepository;
use crate::repository::network_config_repository::NetworkConfigRepository;
use ipnet::Ipv4Net;
use sqlx::SqlitePool;
use std::net::Ipv4Addr;

pub struct DhcpService;

impl DhcpService {
    pub async fn get_config(pool: &SqlitePool) -> Result<DhcpConfig, String> {
        DhcpRepository::get_config(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn set_config(
        pool: &SqlitePool,
        config: DhcpConfig,
    ) -> Result<(), String> {
        let config = Self::normalize_config(config);
        Self::validate_config(&config)?;

        let net = NetworkConfigRepository::get(pool)
            .await
            .map_err(|e| e.to_string())?;

        if config.interface_name == net.wan_interface.trim() {
            return Err(
                "DHCP cannot be served on the WAN interface".into(),
            );
        }

        let reservations = DhcpRepository::list_reservations(pool)
            .await
            .map_err(|e| e.to_string())?;

        for reservation in &reservations {
            Self::validate_reservation(reservation, &config).map_err(|e| {
                format!(
                    "Existing reservation {} ({}) conflicts with the new settings: {}",
                    reservation.mac, reservation.ip, e
                )
            })?;
        }

        DhcpRepository::set_config(pool, config)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn list_reservations(
        pool: &SqlitePool,
    ) -> Result<Vec<DhcpReservation>, String> {
        DhcpRepository::list_reservations(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn add_reservation(
        pool: &SqlitePool,
        reservation: DhcpReservation,
    ) -> Result<(), String> {
        let reservation = Self::normalize_reservation(reservation)?;
        let config = Self::get_config(pool).await?;
        Self::validate_reservation(&reservation, &config)?;
        Self::check_unique(pool, &reservation, None).await?;

        DhcpRepository::add_reservation(pool, reservation)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn update_reservation(
        pool: &SqlitePool,
        id: i64,
        reservation: DhcpReservation,
    ) -> Result<(), String> {
        let reservation = Self::normalize_reservation(reservation)?;
        let config = Self::get_config(pool).await?;
        Self::validate_reservation(&reservation, &config)?;
        Self::check_unique(pool, &reservation, Some(id)).await?;

        DhcpRepository::update_reservation(pool, id, reservation)
            .await
            .map_err(Self::map_write_error)
    }

    pub async fn delete_reservation(
        pool: &SqlitePool,
        id: i64,
    ) -> Result<(), String> {
        DhcpRepository::delete_reservation(pool, id)
            .await
            .map_err(Self::map_write_error)
    }

    async fn check_unique(
        pool: &SqlitePool,
        reservation: &DhcpReservation,
        exclude_id: Option<i64>,
    ) -> Result<(), String> {
        let existing = DhcpRepository::list_reservations(pool)
            .await
            .map_err(|e| e.to_string())?;

        for other in existing {
            if other.id.is_some() && other.id == exclude_id {
                continue;
            }
            if other.mac == reservation.mac {
                return Err(format!(
                    "A reservation for MAC {} already exists",
                    reservation.mac
                ));
            }
            if other.ip == reservation.ip {
                return Err(format!(
                    "IP {} is already reserved for another device",
                    reservation.ip
                ));
            }
            if let (Some(a), Some(b)) = (&other.hostname, &reservation.hostname) {
                if a.eq_ignore_ascii_case(b) {
                    return Err(format!(
                        "Hostname '{}' is already used by another reservation",
                        b
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn normalize_config(mut config: DhcpConfig) -> DhcpConfig {
        config.interface_name = config.interface_name.trim().to_string();
        config.subnet = config.subnet.trim().to_string();
        config.range_start = config.range_start.trim().to_string();
        config.range_end = config.range_end.trim().to_string();
        config.gateway = config
            .gateway
            .map(|g| g.trim().to_string())
            .filter(|g| !g.is_empty());
        config.dns_servers = config
            .dns_servers
            .into_iter()
            .map(|d| d.trim().to_string())
            .filter(|d| !d.is_empty())
            .collect();
        config.domain = config
            .domain
            .map(|d| d.trim().trim_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty());
        config
    }

    pub fn normalize_reservation(
        mut reservation: DhcpReservation,
    ) -> Result<DhcpReservation, String> {
        reservation.mac = Self::normalize_mac(&reservation.mac)?;
        reservation.ip = reservation.ip.trim().to_string();
        reservation.hostname = reservation
            .hostname
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty());
        Ok(reservation)
    }

    pub fn normalize_mac(value: &str) -> Result<String, String> {
        let trimmed = value.trim();
        let parts: Vec<&str> = trimmed.split(|c| c == ':' || c == '-').collect();

        if parts.len() != 6 {
            return Err(format!("Invalid MAC address: '{}'", trimmed));
        }

        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            if part.len() != 2 || !part.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!("Invalid MAC address: '{}'", trimmed));
            }
            bytes[i] = u8::from_str_radix(part, 16)
                .map_err(|_| format!("Invalid MAC address: '{}'", trimmed))?;
        }

        if bytes.iter().all(|b| *b == 0) {
            return Err("MAC address cannot be all zeros".into());
        }
        if bytes[0] & 1 == 1 {
            return Err("MAC address cannot be a multicast address".into());
        }

        Ok(format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        ))
    }

    pub fn validate_config(config: &DhcpConfig) -> Result<(), String> {
        Self::validate_interface_name(&config.interface_name)?;

        let subnet: Ipv4Net = config
            .subnet
            .parse()
            .map_err(|_| format!("Invalid subnet (expected IPv4 CIDR like 192.168.1.0/24): '{}'", config.subnet))?;

        if subnet.prefix_len() < 8 || subnet.prefix_len() > 30 {
            return Err("Subnet prefix length must be between 8 and 30".into());
        }

        let start = Self::parse_host(&config.range_start, &subnet, "Range start")?;
        let end = Self::parse_host(&config.range_end, &subnet, "Range end")?;

        if u32::from(start) > u32::from(end) {
            return Err("Range start must not be greater than range end".into());
        }

        if let Some(gateway) = &config.gateway {
            let gw = Self::parse_host(gateway, &subnet, "Gateway")?;
            if u32::from(gw) >= u32::from(start) && u32::from(gw) <= u32::from(end) {
                return Err("Gateway must not be inside the DHCP range".into());
            }
        }

        if config.dns_servers.is_empty() {
            return Err("At least one DNS server is required".into());
        }
        if config.dns_servers.len() > 4 {
            return Err("At most 4 DNS servers are allowed".into());
        }
        for dns in &config.dns_servers {
            let addr: Ipv4Addr = dns
                .trim()
                .parse()
                .map_err(|_| format!("Invalid DNS server address: '{}'", dns))?;
            if addr.is_unspecified() || addr.is_multicast() || addr.is_broadcast() {
                return Err(format!("Invalid DNS server address: '{}'", dns));
            }
        }

        if config.lease_time_seconds < 120 || config.lease_time_seconds > 31_536_000 {
            return Err("Lease time must be between 120 seconds and 1 year".into());
        }

        if let Some(domain) = &config.domain {
            Self::validate_domain(domain)?;
        }

        Ok(())
    }

    pub fn validate_reservation(
        reservation: &DhcpReservation,
        config: &DhcpConfig,
    ) -> Result<(), String> {
        Self::normalize_mac(&reservation.mac)?;

        let subnet: Ipv4Net = config
            .subnet
            .parse()
            .map_err(|_| format!("Invalid subnet: '{}'", config.subnet))?;

        let ip = Self::parse_host(&reservation.ip, &subnet, "Reserved IP")?;

        if let Some(gateway) = &config.gateway {
            if let Ok(gw) = gateway.trim().parse::<Ipv4Addr>() {
                if gw == ip {
                    return Err("Reserved IP cannot be the gateway address".into());
                }
            }
        }

        if let Some(hostname) = &reservation.hostname {
            Self::validate_label(hostname, "Hostname")?;
        }

        Ok(())
    }

    fn parse_host(
        value: &str,
        subnet: &Ipv4Net,
        label: &str,
    ) -> Result<Ipv4Addr, String> {
        let addr: Ipv4Addr = value
            .trim()
            .parse()
            .map_err(|_| format!("{} is not a valid IPv4 address: '{}'", label, value))?;

        if !subnet.contains(&addr) {
            return Err(format!("{} {} is outside subnet {}", label, addr, subnet));
        }
        if addr == subnet.network() || addr == subnet.broadcast() {
            return Err(format!(
                "{} {} cannot be the network or broadcast address",
                label, addr
            ));
        }

        Ok(addr)
    }

    fn validate_interface_name(name: &str) -> Result<(), String> {
        let trimmed = name.trim();

        if trimmed.is_empty() {
            return Err("DHCP interface cannot be empty".into());
        }
        if trimmed.len() > 15 {
            return Err(format!(
                "DHCP interface '{}' is too long for a Linux interface name",
                trimmed
            ));
        }
        let valid = trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
        if !valid {
            return Err(format!(
                "DHCP interface '{}' contains invalid characters",
                trimmed
            ));
        }

        Ok(())
    }

    fn validate_label(value: &str, label: &str) -> Result<(), String> {
        if value.is_empty() || value.len() > 63 {
            return Err(format!("{} must be 1-63 characters", label));
        }
        if value.starts_with('-') || value.ends_with('-') {
            return Err(format!("{} cannot start or end with a hyphen", label));
        }
        if !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!(
                "{} may only contain letters, digits and hyphens",
                label
            ));
        }
        Ok(())
    }

    fn validate_domain(domain: &str) -> Result<(), String> {
        if domain.len() > 253 {
            return Err("Domain is too long".into());
        }
        for label in domain.split('.') {
            Self::validate_label(label, "Domain label")?;
        }
        Ok(())
    }

    fn map_write_error(e: sqlx::Error) -> String {
        match e {
            sqlx::Error::RowNotFound => "Reservation not found".into(),
            other => other.to_string(),
        }
    }
}
