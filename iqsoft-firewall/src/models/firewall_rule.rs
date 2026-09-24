use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FirewallRule {
    pub id: Option<i64>,
    // General
    pub name: String,
    pub enabled: bool,
    pub priority: i32,
    // Packet matching
    pub chain_name: String,          // INPUT / FORWARD / OUTPUT
    pub action: String,              // accept / drop / reject
    pub protocol: String,            // any / tcp / udp / icmp
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<i32>,
    pub dst_port: Option<i32>,
    pub port_any: bool,              // explicit "allow all ports" for tcp/udp
    pub interface_name: Option<String>,
    // Optional features
    pub rate_limit: Option<String>,
    pub log_enabled: bool,
    pub comment: Option<String>,
}

pub fn normalize_rate_limit(value: &str) -> Option<String> {
    let (count, unit) = value.trim().split_once('/')?;

    let count: u32 = count.trim().parse().ok()?;
    if count == 0 || count > 1_000_000 {
        return None;
    }

    let unit = unit.trim().to_ascii_lowercase();
    match unit.as_str() {
        "second" | "minute" | "hour" | "day" => Some(format!("{}/{}", count, unit)),
        _ => None,
    }
}
