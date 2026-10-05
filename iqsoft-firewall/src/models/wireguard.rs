use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

fn default_interface() -> String {
    "wg0".to_string()
}

fn default_listen_port() -> i32 {
    51820
}

fn default_client_allowed_ips() -> Vec<String> {
    vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WireguardConfig {
    pub enabled: bool,
    pub interface_name: String,
    pub listen_port: i32,
    pub address: String,
    pub mtu: Option<i32>,
    pub dns: Option<String>,
    pub endpoint: Option<String>,
    pub client_allowed_ips: Vec<String>,
    pub private_key: String,
    pub public_key: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct WireguardConfigView {
    pub enabled: bool,
    pub interface_name: String,
    pub listen_port: i32,
    pub address: String,
    pub mtu: Option<i32>,
    pub dns: Option<String>,
    pub endpoint: Option<String>,
    pub client_allowed_ips: Vec<String>,
    pub public_key: String,
}

impl From<WireguardConfig> for WireguardConfigView {
    fn from(config: WireguardConfig) -> Self {
        Self {
            enabled: config.enabled,
            interface_name: config.interface_name,
            listen_port: config.listen_port,
            address: config.address,
            mtu: config.mtu,
            dns: config.dns,
            endpoint: config.endpoint,
            client_allowed_ips: config.client_allowed_ips,
            public_key: config.public_key,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct WireguardConfigUpdate {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_interface")]
    pub interface_name: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: i32,
    pub address: String,
    pub mtu: Option<i32>,
    pub dns: Option<String>,
    pub endpoint: Option<String>,
    #[serde(default = "default_client_allowed_ips")]
    pub client_allowed_ips: Vec<String>,
    #[serde(default)]
    pub regenerate_keys: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WireguardPeer {
    pub id: Option<i64>,
    pub name: String,
    pub enabled: bool,
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub persistent_keepalive: i32,
    pub comment: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct WireguardPeerView {
    pub id: Option<i64>,
    pub name: String,
    pub enabled: bool,
    pub public_key: String,
    pub has_preshared_key: bool,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub persistent_keepalive: i32,
    pub comment: Option<String>,
}

impl From<WireguardPeer> for WireguardPeerView {
    fn from(peer: WireguardPeer) -> Self {
        Self {
            id: peer.id,
            name: peer.name,
            enabled: peer.enabled,
            public_key: peer.public_key,
            has_preshared_key: peer.preshared_key.is_some(),
            allowed_ips: peer.allowed_ips,
            endpoint: peer.endpoint,
            persistent_keepalive: peer.persistent_keepalive,
            comment: peer.comment,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct WireguardPeerInput {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub public_key: Option<String>,
    #[serde(default)]
    pub generate_keys: bool,
    #[serde(default)]
    pub use_preshared_key: bool,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    #[serde(default)]
    pub persistent_keepalive: i32,
    pub comment: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct WireguardPeerCreated {
    pub peer: WireguardPeerView,
    pub client_config: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WireguardSnapshot {
    pub config: WireguardConfig,
    pub peers: Vec<WireguardPeer>,
}

#[derive(Debug, Serialize, Clone)]
pub struct WireguardPeerStatus {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub latest_handshake: Option<i64>,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
}
