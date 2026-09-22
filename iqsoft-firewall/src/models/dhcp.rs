use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DhcpConfig {
    pub enabled: bool,
    pub interface_name: String,
    pub subnet: String,
    pub range_start: String,
    pub range_end: String,
    pub gateway: Option<String>,
    pub dns_servers: Vec<String>,
    pub lease_time_seconds: i64,
    pub domain: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DhcpReservation {
    pub id: Option<i64>,
    pub mac: String,
    pub ip: String,
    pub hostname: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DhcpSnapshot {
    pub config: DhcpConfig,
    pub reservations: Vec<DhcpReservation>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DhcpLease {
    pub expires: i64,
    pub mac: String,
    pub ip: String,
    pub hostname: Option<String>,
}
