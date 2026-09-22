use crate::models::dns::{DnsConfig, DnsStaticRecord};
use crate::repository::dns_repository::DnsRepository;
use crate::repository::network_config_repository::NetworkConfigRepository;
use sqlx::SqlitePool;
use std::net::Ipv4Addr;

pub struct DnsService;

impl DnsService {
    pub async fn get_config(pool: &SqlitePool) -> Result<DnsConfig, String> {
        DnsRepository::get_config(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn set_config(pool: &SqlitePool, config: DnsConfig) -> Result<(), String> {
        let config = Self::normalize_config(config);
        let records = DnsRepository::list_records(pool)
            .await
            .map_err(|e| e.to_string())?;
        Self::validate_config(&config, &records)?;

        let net = NetworkConfigRepository::get(pool)
            .await
            .map_err(|e| e.to_string())?;

        if config
            .listen_interfaces
            .iter()
            .any(|iface| iface == net.wan_interface.trim())
        {
            return Err(format!(
                "DNS cannot listen on the WAN interface ('{}')",
                net.wan_interface.trim()
            ));
        }

        DnsRepository::set_config(pool, config)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn list_records(pool: &SqlitePool) -> Result<Vec<DnsStaticRecord>, String> {
        DnsRepository::list_records(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn add_record(
        pool: &SqlitePool,
        record: DnsStaticRecord,
    ) -> Result<(), String> {
        let record = Self::normalize_record(record)?;
        Self::validate_record(&record)?;
        Self::check_unique(pool, &record, None).await?;

        DnsRepository::add_record(pool, record)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn update_record(
        pool: &SqlitePool,
        id: i64,
        record: DnsStaticRecord,
    ) -> Result<(), String> {
        let record = Self::normalize_record(record)?;
        Self::validate_record(&record)?;
        Self::check_unique(pool, &record, Some(id)).await?;

        DnsRepository::update_record(pool, id, record)
            .await
            .map_err(Self::map_write_error)
    }

    pub async fn delete_record(pool: &SqlitePool, id: i64) -> Result<(), String> {
        DnsRepository::delete_record(pool, id)
            .await
            .map_err(Self::map_write_error)
    }

    async fn check_unique(
        pool: &SqlitePool,
        record: &DnsStaticRecord,
        exclude_id: Option<i64>,
    ) -> Result<(), String> {
        let existing = DnsRepository::list_records(pool)
            .await
            .map_err(|e| e.to_string())?;

        for other in existing {
            if other.id.is_some() && other.id == exclude_id {
                continue;
            }
            if other.hostname.eq_ignore_ascii_case(&record.hostname) {
                return Err(format!(
                    "A DNS record for hostname '{}' already exists",
                    record.hostname
                ));
            }
        }

        Ok(())
    }

    pub fn normalize_config(mut config: DnsConfig) -> DnsConfig {
        config.listen_interfaces = config
            .listen_interfaces
            .into_iter()
            .map(|i| i.trim().to_string())
            .filter(|i| !i.is_empty())
            .collect();
        config.upstream_servers = config
            .upstream_servers
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        config.local_domain = config
            .local_domain
            .map(|d| d.trim().trim_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty());
        config
    }

    pub fn normalize_record(
        mut record: DnsStaticRecord,
    ) -> Result<DnsStaticRecord, String> {
        record.hostname = record.hostname.trim().to_ascii_lowercase();
        record.ip = record.ip.trim().to_string();
        Ok(record)
    }

    pub fn validate_config(
        config: &DnsConfig,
        records: &[DnsStaticRecord],
    ) -> Result<(), String> {
        if !config.enabled {
            return Ok(());
        }

        if config.listen_interfaces.is_empty() {
            return Err("At least one listen interface is required".into());
        }
        for iface in &config.listen_interfaces {
            Self::validate_interface_name(iface)?;
        }

        if config.upstream_servers.is_empty() {
            return Err("At least one upstream DNS server is required".into());
        }
        if config.upstream_servers.len() > 4 {
            return Err("At most 4 upstream DNS servers are allowed".into());
        }
        for server in &config.upstream_servers {
            let addr: Ipv4Addr = server
                .parse()
                .map_err(|_| format!("Invalid upstream DNS server: '{}'", server))?;
            if addr.is_unspecified() || addr.is_multicast() || addr.is_broadcast() {
                return Err(format!("Invalid upstream DNS server: '{}'", server));
            }
        }

        let needs_domain = config.use_dhcp_hostnames || !records.is_empty();
        if needs_domain {
            match &config.local_domain {
                Some(domain) => Self::validate_domain(domain)?,
                None => {
                    return Err(
                        "local_domain is required when use_dhcp_hostnames is on or static records exist".into(),
                    )
                }
            }
        } else if let Some(domain) = &config.local_domain {
            Self::validate_domain(domain)?;
        }

        Ok(())
    }

    pub fn validate_record(record: &DnsStaticRecord) -> Result<(), String> {
        Self::validate_label(&record.hostname, "Hostname")?;

        record
            .ip
            .parse::<Ipv4Addr>()
            .map_err(|_| format!("Invalid IPv4 address: '{}'", record.ip))?;

        Ok(())
    }

    fn validate_interface_name(name: &str) -> Result<(), String> {
        let trimmed = name.trim();

        if trimmed.is_empty() {
            return Err("Listen interface cannot be empty".into());
        }
        if trimmed.len() > 15 {
            return Err(format!(
                "Listen interface '{}' is too long for a Linux interface name",
                trimmed
            ));
        }
        let valid = trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
        if !valid {
            return Err(format!(
                "Listen interface '{}' contains invalid characters",
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
            sqlx::Error::RowNotFound => "DNS record not found".into(),
            other => other.to_string(),
        }
    }
}
