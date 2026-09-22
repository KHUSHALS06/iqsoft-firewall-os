use crate::dhcp::generator::LEASE_FILE_PATH;
use crate::models::dhcp::DhcpLease;
use std::fs;
use std::io::ErrorKind;

pub struct DhcpLeases;

impl DhcpLeases {
    pub fn read() -> Result<Vec<DhcpLease>, String> {
        match fs::read_to_string(LEASE_FILE_PATH) {
            Ok(content) => Ok(Self::parse(&content)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(format!("Failed to read {}: {}", LEASE_FILE_PATH, e)),
        }
    }

    pub fn parse(content: &str) -> Vec<DhcpLease> {
        let mut leases = Vec::new();

        for line in content.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                continue;
            }

            let expires = match fields[0].parse::<i64>() {
                Ok(v) => v,
                Err(_) => continue,
            };

            let hostname = if fields[3] == "*" {
                None
            } else {
                Some(fields[3].to_string())
            };

            leases.push(DhcpLease {
                expires,
                mac: fields[1].to_string(),
                ip: fields[2].to_string(),
                hostname,
            });
        }

        leases
    }
}
