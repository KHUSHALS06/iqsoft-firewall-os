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
    pub src_mac: Option<String>,
    pub time_start: Option<String>,
    pub time_end: Option<String>,
    pub days: Option<String>,
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

pub fn normalize_mac(value: &str) -> Option<String> {
    let trimmed = value.trim();

    let digits: String = if trimmed.contains(':') || trimmed.contains('-') {
        let separator = if trimmed.contains(':') { ':' } else { '-' };

        if trimmed.contains(if separator == ':' { '-' } else { ':' }) || trimmed.contains('.') {
            return None;
        }

        let parts: Vec<&str> = trimmed.split(separator).collect();
        if parts.len() != 6 || parts.iter().any(|p| p.len() != 2) {
            return None;
        }
        parts.concat()
    } else if trimmed.contains('.') {
        let parts: Vec<&str> = trimmed.split('.').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.len() != 4) {
            return None;
        }
        parts.concat()
    } else {
        trimmed.to_string()
    };

    if digits.len() != 12 || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    let digits = digits.to_ascii_lowercase();
    let octets: Vec<&str> = (0..6).map(|i| &digits[i * 2..i * 2 + 2]).collect();

    let first = u8::from_str_radix(octets[0], 16).ok()?;
    if first & 1 == 1 || digits == "000000000000" {
        return None;
    }

    Some(octets.join(":"))
}

const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

fn day_index(token: &str) -> Option<usize> {
    match token {
        "mon" | "monday" => Some(0),
        "tue" | "tues" | "tuesday" => Some(1),
        "wed" | "wednesday" => Some(2),
        "thu" | "thur" | "thurs" | "thursday" => Some(3),
        "fri" | "friday" => Some(4),
        "sat" | "saturday" => Some(5),
        "sun" | "sunday" => Some(6),
        _ => None,
    }
}

pub fn normalize_time_of_day(value: &str) -> Option<String> {
    let (hours, minutes) = value.trim().split_once(':')?;

    if hours.is_empty() || hours.len() > 2 || minutes.len() != 2 {
        return None;
    }

    if !hours.chars().all(|c| c.is_ascii_digit()) || !minutes.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    let hours: u32 = hours.parse().ok()?;
    let minutes: u32 = minutes.parse().ok()?;

    if hours > 23 || minutes > 59 {
        return None;
    }

    Some(format!("{:02}:{:02}", hours, minutes))
}

pub fn normalize_days(value: &str) -> Option<String> {
    let cleaned = value.trim().to_ascii_lowercase().replace(',', " ");
    let tokens: Vec<&str> = cleaned.split_whitespace().collect();

    if tokens.is_empty() {
        return None;
    }

    let mut selected = [false; 7];

    for token in tokens {
        match token.split_once('-') {
            Some((from, to)) => {
                let from = day_index(from)?;
                let to = day_index(to)?;

                let mut day = from;
                loop {
                    selected[day] = true;
                    if day == to {
                        break;
                    }
                    day = (day + 1) % 7;
                }
            }
            None => selected[day_index(token)?] = true,
        }
    }

    let names: Vec<&str> = DAYS
        .iter()
        .enumerate()
        .filter(|(i, _)| selected[*i])
        .map(|(_, name)| *name)
        .collect();

    Some(names.join(","))
}

#[cfg(test)]
mod tests {
    use super::{normalize_days, normalize_mac, normalize_time_of_day};

    #[test]
    fn accepts_the_common_notations_and_normalizes_them() {
        for input in [
            "aa:bb:cc:dd:ee:ff",
            "AA:BB:CC:DD:EE:FF",
            "aa-bb-cc-dd-ee-ff",
            "aabb.ccdd.eeff",
            "AABBCCDDEEFF",
            "  aa:bb:cc:dd:ee:ff  ",
        ] {
            assert_eq!(normalize_mac(input).as_deref(), Some("aa:bb:cc:dd:ee:ff"), "{}", input);
        }
    }

    #[test]
    fn rule_json_without_src_mac_still_parses() {
        let json = r#"{"id":1,"name":"old","enabled":true,"priority":100,"chain_name":"INPUT","action":"accept","protocol":"tcp","src_ip":null,"dst_ip":null,"src_port":null,"dst_port":22,"port_any":false,"interface_name":null,"rate_limit":null,"log_enabled":false,"comment":null}"#;
        let rule: super::FirewallRule = serde_json::from_str(json).unwrap();

        assert_eq!(rule.src_mac, None);
    }

    #[test]
    fn rule_json_without_time_fields_still_parses() {
        let json = r#"{"id":1,"name":"old","enabled":true,"priority":100,"chain_name":"INPUT","action":"accept","protocol":"tcp","src_ip":null,"dst_ip":null,"src_port":null,"dst_port":22,"port_any":false,"interface_name":null,"src_mac":null,"rate_limit":null,"log_enabled":false,"comment":null}"#;
        let rule: super::FirewallRule = serde_json::from_str(json).unwrap();

        assert_eq!(rule.time_start, None);
        assert_eq!(rule.time_end, None);
        assert_eq!(rule.days, None);
    }

    #[test]
    fn keeps_leading_zeros() {
        assert_eq!(normalize_mac("00:1a:2b:03:04:05").as_deref(), Some("00:1a:2b:03:04:05"));
        assert_eq!(normalize_mac("001a.2b03.0405").as_deref(), Some("00:1a:2b:03:04:05"));
    }

    #[test]
    fn rejects_wrong_lengths_and_mixed_separators() {
        for input in [
            "",
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:ff:00",
            "a:b:c:d:e:f",
            "aa:bb-cc:dd-ee:ff",
            "aabb.ccdd",
            "aabb.ccdd.eeff.0011",
            "aabbccddeef",
            "aabbccddeeff00",
            "aa:bb:cc:dd:ee:fff",
        ] {
            assert_eq!(normalize_mac(input), None, "{}", input);
        }
    }

    #[test]
    fn rejects_non_hex_and_injection_payloads() {
        for input in [
            "gg:bb:cc:dd:ee:ff",
            "aa:bb:cc:dd:ee:f;",
            "aa:bb:cc:dd:ee:ff; drop",
            "aa:bb:cc:dd:ee:ff\" accept",
            "aa:bb:cc:dd:ee:ff\naccept",
            "aa:bb:cc:dd:ee:ff,11:22:33:44:55:66",
            "zzzzzzzzzzzz",
        ] {
            assert_eq!(normalize_mac(input), None, "{:?}", input);
        }
    }

    #[test]
    fn rejects_addresses_that_cannot_be_a_source() {
        assert_eq!(normalize_mac("ff:ff:ff:ff:ff:ff"), None);
        assert_eq!(normalize_mac("01:00:5e:00:00:01"), None);
        assert_eq!(normalize_mac("33:33:00:00:00:01"), None);
        assert_eq!(normalize_mac("00:00:00:00:00:00"), None);
    }

    #[test]
    fn time_of_day_is_zero_padded_and_bounded() {
        assert_eq!(normalize_time_of_day("08:00").as_deref(), Some("08:00"));
        assert_eq!(normalize_time_of_day("8:05").as_deref(), Some("08:05"));
        assert_eq!(normalize_time_of_day("  23:59 ").as_deref(), Some("23:59"));
        assert_eq!(normalize_time_of_day("00:00").as_deref(), Some("00:00"));
    }

    #[test]
    fn time_of_day_rejects_bad_input() {
        for input in [
            "", ":", "24:00", "12:60", "8:0", "08:00:00", "0800", "ab:cd", "-1:00",
            "+8:00", "08:0a", "8 :00", "08:00\" accept", "08:00; drop", "１2:00",
        ] {
            assert_eq!(normalize_time_of_day(input), None, "{:?}", input);
        }
    }

    #[test]
    fn days_accept_names_abbreviations_and_any_case() {
        assert_eq!(normalize_days("Mon").as_deref(), Some("mon"));
        assert_eq!(normalize_days("MONDAY, tuesday").as_deref(), Some("mon,tue"));
        assert_eq!(normalize_days("thurs sat").as_deref(), Some("thu,sat"));
        assert_eq!(normalize_days("  sun  ").as_deref(), Some("sun"));
    }

    #[test]
    fn days_are_sorted_and_deduplicated() {
        assert_eq!(normalize_days("sun,fri,mon,fri").as_deref(), Some("mon,fri,sun"));
        assert_eq!(
            normalize_days("sun mon tue wed thu fri sat").as_deref(),
            Some("mon,tue,wed,thu,fri,sat,sun")
        );
    }

    #[test]
    fn days_support_ranges_including_ones_that_wrap_the_week() {
        assert_eq!(normalize_days("mon-fri").as_deref(), Some("mon,tue,wed,thu,fri"));
        assert_eq!(normalize_days("fri-mon").as_deref(), Some("mon,fri,sat,sun"));
        assert_eq!(normalize_days("sat-sun, wed").as_deref(), Some("wed,sat,sun"));
        assert_eq!(normalize_days("tue-tue").as_deref(), Some("tue"));
    }

    #[test]
    fn days_reject_bad_input() {
        for input in [
            "", "   ", ",", "funday", "mon-", "-fri", "mon - fri", "mon--fri",
            "mon-fri-sun", "1", "mon;drop", "mon\" accept", "monday1",
        ] {
            assert_eq!(normalize_days(input), None, "{:?}", input);
        }
    }
}
