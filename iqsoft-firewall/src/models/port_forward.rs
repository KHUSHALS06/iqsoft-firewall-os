use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PortForwardRule {
    pub id: Option<i64>,

    pub name: String,

    #[serde(default = "default_true")]
    pub enabled: bool,

    /// tcp / udp / both
    pub protocol: String,

    /// External (WAN-side) port range. For a single port, start == end.
    pub external_port_start: i32,
    pub external_port_end: i32,

    /// LAN host that receives the traffic.
    pub internal_ip: String,

    /// First internal port. The internal range has the same length as the
    /// external range, so the end port is calculated and not stored.
    pub internal_port_start: i32,

    pub comment: Option<String>,
}

impl PortForwardRule {
    pub fn internal_port_end(&self) -> i32 {
        self.internal_port_start + (self.external_port_end - self.external_port_start)
    }
}
