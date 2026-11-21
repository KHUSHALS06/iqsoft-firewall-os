use serde::{Deserialize, Serialize};

pub const MODE_STATIC: &str = "static";
pub const MODE_DHCP: &str = "dhcp";

fn default_mode() -> String {
    MODE_STATIC.to_string()
}

fn default_true() -> bool {
    true
}

/// Settings for one physical or virtual port (enp3s0, eth1, ...).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct InterfaceConfig {
    #[serde(default)]
    pub name: String,

    /// "static" (addresses below) or "dhcp" (get the address from the network).
    #[serde(default = "default_mode")]
    pub mode: String,

    /// Addresses with prefix length, for example "192.168.1.1/24".
    #[serde(default)]
    pub addresses: Vec<String>,

    pub gateway: Option<String>,

    #[serde(default)]
    pub dns: Vec<String>,

    pub mtu: Option<u32>,

    /// false keeps the port administratively down.
    #[serde(default = "default_true")]
    pub enabled: bool,

    pub comment: Option<String>,
}
