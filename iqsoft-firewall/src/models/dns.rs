use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsConfig {
    pub enabled: bool,
    pub listen_interfaces: Vec<String>,
    pub upstream_servers: Vec<String>,
    pub local_domain: Option<String>,
    pub use_dhcp_hostnames: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsStaticRecord {
    pub id: Option<i64>,
    pub hostname: String,
    pub ip: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsSnapshot {
    pub config: DnsConfig,
    pub records: Vec<DnsStaticRecord>,
}
