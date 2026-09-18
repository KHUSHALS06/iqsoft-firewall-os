use crate::models::network_config::NetworkConfig;
use crate::repository::network_config_repository::NetworkConfigRepository;
use sqlx::SqlitePool;

pub struct NetworkConfigService;

impl NetworkConfigService {
    pub async fn get(pool: &SqlitePool) -> Result<NetworkConfig, String> {
        NetworkConfigRepository::get(pool).await.map_err(|e| e.to_string())
    }

    pub async fn set(pool: &SqlitePool, config: NetworkConfig) -> Result<(), String> {
        Self::validate(&config)?;
        NetworkConfigRepository::set(pool, config).await.map_err(|e| e.to_string())
    }

    fn validate(config: &NetworkConfig) -> Result<(), String> {
        Self::validate_interface_name(&config.wan_interface, "WAN interface")?;
        Self::validate_interface_name(&config.lan_interface, "LAN interface")?;

        if config.wan_interface == config.lan_interface {
            return Err("WAN interface and LAN interface must be different".into());
        }

        Ok(())
    }

    fn validate_interface_name(name: &str, field_label: &str) -> Result<(), String> {
        let trimmed = name.trim();

        if trimmed.is_empty() {
            return Err(format!("{} cannot be empty", field_label));
        }
        if trimmed.len() > 15 {
            return Err(format!("{} '{}' is too long for a Linux interface name", field_label, trimmed));
        }
        let valid_chars = trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
        if !valid_chars {
            return Err(format!("{} '{}' contains invalid characters", field_label, trimmed));
        }

        Ok(())
    }
}
