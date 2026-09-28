use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const MAX_NAME_LEN: usize = 32;

/// An address object is a single host, subnet or range.
/// `family` is always computed by the server from `value`; whatever the client
/// sends for it is ignored.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AddressObject {
    pub id: Option<i64>,
    pub name: String,
    pub kind: String, // host / subnet / range
    pub value: String,
    #[serde(default)]
    pub family: String, // ipv4 / ipv6 (computed)
    pub comment: Option<String>,
}

/// A group is a flat list of address objects of the same family.
/// Members are referenced by object name.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AddressGroup {
    pub id: Option<i64>,
    pub name: String,
    #[serde(default)]
    pub family: String, // ipv4 / ipv6 (computed from the members)
    pub comment: Option<String>,
    #[serde(default)]
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn as_str(&self) -> &'static str {
        match self {
            Family::V4 => "ipv4",
            Family::V6 => "ipv6",
        }
    }

    pub fn from_db(value: &str) -> Option<Family> {
        match value {
            "ipv4" => Some(Family::V4),
            "ipv6" => Some(Family::V6),
            _ => None,
        }
    }
}

fn family_of(addr: &IpAddr) -> Family {
    match addr {
        IpAddr::V4(_) => Family::V4,
        IpAddr::V6(_) => Family::V6,
    }
}

/// Names end up inside the generated nftables text, so keep them boring:
/// a letter, then letters, digits or underscores.
pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Name cannot be empty".into());
    }

    if name.len() > MAX_NAME_LEN {
        return Err(format!("Name cannot be longer than {} characters", MAX_NAME_LEN));
    }

    let mut chars = name.chars();

    if !chars.next().is_some_and(|c| c.is_ascii_alphabetic()) {
        return Err("Name must start with a letter".into());
    }

    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err("Name may only contain letters, digits and underscores".into());
    }

    Ok(())
}

/// Validates `value` for the given `kind` and returns its family plus the
/// normalized text that is safe to place in an nftables set.
///
///   host    10.0.0.5            -> 10.0.0.5
///   subnet  10.0.0.5/24         -> 10.0.0.0/24   (host bits cleared)
///   range   10.0.0.10-10.0.0.20 -> 10.0.0.10-10.0.0.20
pub fn parse_value(kind: &str, value: &str) -> Result<(Family, String), String> {
    let value = value.trim();

    match kind {
        "host" => {
            let addr: IpAddr = value
                .parse()
                .map_err(|_| format!("'{}' is not a valid IP address", value))?;

            Ok((family_of(&addr), addr.to_string()))
        }

        "subnet" => {
            let net: IpNet = value
                .parse()
                .map_err(|_| format!("'{}' is not a valid subnet (example: 192.168.1.0/24)", value))?;

            let net = net.trunc();

            let family = match net {
                IpNet::V4(_) => Family::V4,
                IpNet::V6(_) => Family::V6,
            };

            Ok((family, net.to_string()))
        }

        "range" => {
            let (first, last) = value
                .split_once('-')
                .ok_or("A range must look like 10.0.0.10-10.0.0.20")?;

            let start: IpAddr = first
                .trim()
                .parse()
                .map_err(|_| format!("'{}' is not a valid IP address", first.trim()))?;

            let end: IpAddr = last
                .trim()
                .parse()
                .map_err(|_| format!("'{}' is not a valid IP address", last.trim()))?;

            if family_of(&start) != family_of(&end) {
                return Err("Both ends of a range must be the same IP version".into());
            }

            if start > end {
                return Err("The start of a range must not be after its end".into());
            }

            Ok((family_of(&start), format!("{}-{}", start, end)))
        }

        _ => Err("Kind must be host, subnet or range".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_v4_and_v6() {
        assert_eq!(
            parse_value("host", " 10.0.0.5 ").unwrap(),
            (Family::V4, "10.0.0.5".to_string())
        );
        assert_eq!(
            parse_value("host", "2001:DB8::1").unwrap(),
            (Family::V6, "2001:db8::1".to_string())
        );
    }

    #[test]
    fn host_rejects_garbage() {
        assert!(parse_value("host", "10.0.0.256").is_err());
        assert!(parse_value("host", "10.0.0.0/24").is_err());
        assert!(parse_value("host", "1.1.1.1; flush ruleset").is_err());
        assert!(parse_value("host", "").is_err());
    }

    #[test]
    fn subnet_clears_host_bits() {
        assert_eq!(
            parse_value("subnet", "10.0.0.5/24").unwrap(),
            (Family::V4, "10.0.0.0/24".to_string())
        );
        assert_eq!(
            parse_value("subnet", "2001:db8::abcd/32").unwrap(),
            (Family::V6, "2001:db8::/32".to_string())
        );
    }

    #[test]
    fn subnet_rejects_plain_ip_and_garbage() {
        assert!(parse_value("subnet", "10.0.0.5").is_err());
        assert!(parse_value("subnet", "10.0.0.0/33").is_err());
        assert!(parse_value("subnet", "nonsense").is_err());
    }

    #[test]
    fn range_ok() {
        assert_eq!(
            parse_value("range", "10.0.0.10 - 10.0.0.20").unwrap(),
            (Family::V4, "10.0.0.10-10.0.0.20".to_string())
        );
        assert_eq!(
            parse_value("range", "2001:db8::1-2001:db8::ff").unwrap(),
            (Family::V6, "2001:db8::1-2001:db8::ff".to_string())
        );
        // a one-address range is allowed
        assert!(parse_value("range", "10.0.0.5-10.0.0.5").is_ok());
    }

    #[test]
    fn range_rejects_bad_input() {
        assert!(parse_value("range", "10.0.0.20-10.0.0.10").is_err());
        assert!(parse_value("range", "10.0.0.1-2001:db8::1").is_err());
        assert!(parse_value("range", "10.0.0.1").is_err());
        assert!(parse_value("range", "10.0.0.1-").is_err());
    }

    #[test]
    fn unknown_kind_rejected() {
        assert!(parse_value("fqdn", "example.com").is_err());
    }

    #[test]
    fn names() {
        assert!(validate_name("office_lan").is_ok());
        assert!(validate_name("Servers2").is_ok());
        assert!(validate_name(&"a".repeat(MAX_NAME_LEN)).is_ok());

        assert!(validate_name("").is_err());
        assert!(validate_name("1abc").is_err());
        assert!(validate_name("_abc").is_err());
        assert!(validate_name("has space").is_err());
        assert!(validate_name("semi;colon").is_err());
        assert!(validate_name("quote\"d").is_err());
        assert!(validate_name("new\nline").is_err());
        assert!(validate_name("dash-ed").is_err());
        assert!(validate_name(&"a".repeat(MAX_NAME_LEN + 1)).is_err());
    }

    #[test]
    fn family_round_trip() {
        assert_eq!(Family::from_db(Family::V4.as_str()), Some(Family::V4));
        assert_eq!(Family::from_db(Family::V6.as_str()), Some(Family::V6));
        assert_eq!(Family::from_db("bogus"), None);
    }
}
