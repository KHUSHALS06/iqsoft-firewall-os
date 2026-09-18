use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkConfig {
    pub wan_interface: String,
    pub lan_interface: String,
    pub nat_enabled: bool,
    pub ip_forward_enabled: bool,
}
