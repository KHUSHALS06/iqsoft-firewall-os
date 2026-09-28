use crate::models::route::Route;
use crate::repository::route_repository::RouteRepository;
use ipnet::IpNet;
use sqlx::SqlitePool;
use std::net::IpAddr;
use std::str::FromStr;

pub struct RouteService;

impl RouteService {
    pub async fn list_routes(pool: &SqlitePool) -> Result<Vec<Route>, String> {
        RouteRepository::list_routes(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn add_route(pool: &SqlitePool, mut route: Route) -> Result<(), String> {
        Self::normalize(&mut route);
        Self::validate_route(&route)?;

        let existing = Self::list_routes(pool).await?;
        Self::check_duplicate(&route, None, &existing)?;

        RouteRepository::add_route(pool, route)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn update_route(
        pool: &SqlitePool,
        id: i64,
        mut route: Route,
    ) -> Result<(), String> {
        Self::normalize(&mut route);
        Self::validate_route(&route)?;

        let existing = Self::list_routes(pool).await?;
        Self::check_duplicate(&route, Some(id), &existing)?;

        let changed = RouteRepository::update_route(pool, id, route)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("Route {} does not exist", id));
        }

        Ok(())
    }

    pub async fn delete_route(pool: &SqlitePool, id: i64) -> Result<(), String> {
        let changed = RouteRepository::delete_route(pool, id)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("Route {} does not exist", id));
        }

        Ok(())
    }

    pub fn normalize(route: &mut Route) {
        route.name = route.name.trim().to_string();

        let destination = route.destination.trim().to_lowercase();
        route.destination = match IpAddr::from_str(&destination) {
            Ok(IpAddr::V4(ip)) => format!("{}/32", ip),
            Ok(IpAddr::V6(ip)) => format!("{}/128", ip),
            Err(_) => destination,
        };

        route.gateway = Self::clean_optional(route.gateway.take()).map(|value| {
            match IpAddr::from_str(&value.to_lowercase()) {
                Ok(ip) => ip.to_string(),
                Err(_) => value,
            }
        });

        route.interface_name = Self::clean_optional(route.interface_name.take());
        route.comment = Self::clean_optional(route.comment.take());
    }

    fn clean_optional(value: Option<String>) -> Option<String> {
        value
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    pub fn validate_route(route: &Route) -> Result<(), String> {
        if route.name.is_empty() {
            return Err("Route name cannot be empty".into());
        }

        if route.name.chars().count() > 64 {
            return Err("Route name cannot be longer than 64 characters".into());
        }

        if route.name.chars().any(|c| c.is_control()) {
            return Err("Route name contains invalid characters".into());
        }

        if let Some(comment) = &route.comment {
            if comment.chars().count() > 200 {
                return Err("Route comment cannot be longer than 200 characters".into());
            }

            if comment.chars().any(|c| c.is_control()) {
                return Err("Route comment contains invalid characters".into());
            }
        }

        let net = IpNet::from_str(&route.destination).map_err(|_| {
            format!(
                "Destination '{}' is not a valid CIDR network (example: 10.0.0.0/24)",
                route.destination
            )
        })?;

        if net != net.trunc() {
            return Err(format!(
                "Destination '{}' has host bits set - did you mean '{}'?",
                route.destination,
                net.trunc()
            ));
        }

        let network = net.network();

        if network.is_loopback() {
            return Err("Destination cannot be a loopback network".into());
        }

        if network.is_multicast() {
            return Err("Destination cannot be a multicast network".into());
        }

        if network.is_unspecified() && net.prefix_len() != 0 {
            return Err(
                "Destination 0.0.0.0 or :: is only valid as the default route (prefix /0)".into(),
            );
        }

        let mut gateway_is_link_local = false;

        if let Some(raw) = &route.gateway {
            let gateway = IpAddr::from_str(raw)
                .map_err(|_| format!("Gateway '{}' is not a valid IP address", raw))?;

            let family_matches = matches!(
                (&net, &gateway),
                (IpNet::V4(_), IpAddr::V4(_)) | (IpNet::V6(_), IpAddr::V6(_))
            );

            if !family_matches {
                return Err(format!(
                    "Gateway '{}' is a different IP version than destination '{}'",
                    raw, route.destination
                ));
            }

            if gateway.is_unspecified() || gateway.is_loopback() || gateway.is_multicast() {
                return Err(format!("Gateway '{}' is not a usable host address", raw));
            }

            match gateway {
                IpAddr::V4(ip) => {
                    if ip.is_broadcast() {
                        return Err(format!("Gateway '{}' is not a usable host address", raw));
                    }
                }
                IpAddr::V6(ip) => {
                    gateway_is_link_local = (ip.segments()[0] & 0xffc0) == 0xfe80;
                }
            }
        }

        if route.gateway.is_none() && route.interface_name.is_none() {
            return Err("A route needs a gateway, an interface, or both".into());
        }

        if gateway_is_link_local && route.interface_name.is_none() {
            return Err("A link-local IPv6 gateway (fe80::) requires an interface".into());
        }

        if let Some(name) = &route.interface_name {
            Self::validate_interface_name(name)?;
        }

        if !(1..=9999).contains(&route.metric) {
            return Err("Metric must be between 1 and 9999".into());
        }

        Ok(())
    }

    fn validate_interface_name(name: &str) -> Result<(), String> {
        let trimmed = name.trim();

        if trimmed.is_empty() {
            return Err("Route interface cannot be empty".into());
        }

        if trimmed.len() > 15 {
            return Err(format!(
                "Route interface '{}' is too long for a Linux interface name",
                trimmed
            ));
        }

        let valid = trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');

        if !valid {
            return Err(format!(
                "Route interface '{}' contains invalid characters",
                trimmed
            ));
        }

        Ok(())
    }

    fn check_duplicate(
        route: &Route,
        self_id: Option<i64>,
        existing: &[Route],
    ) -> Result<(), String> {
        for other in existing {
            if self_id.is_some() && other.id == self_id {
                continue;
            }

            if other.destination == route.destination && other.metric == route.metric {
                return Err(format!(
                    "Route '{}' (id {}) already uses destination {} with metric {} - use a different metric",
                    other.name,
                    other.id.unwrap_or(0),
                    other.destination,
                    other.metric
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(dest: &str, gw: Option<&str>, iface: Option<&str>, metric: i32) -> Route {
        let mut r = Route {
            id: None,
            name: "test".into(),
            enabled: true,
            destination: dest.into(),
            gateway: gw.map(|s| s.into()),
            interface_name: iface.map(|s| s.into()),
            metric,
            comment: None,
        };
        RouteService::normalize(&mut r);
        r
    }

    fn ok(r: &Route) {
        assert!(RouteService::validate_route(r).is_ok(), "{:?}", r);
    }

    fn bad(r: &Route) {
        assert!(RouteService::validate_route(r).is_err(), "{:?}", r);
    }

    #[test]
    fn accepts_normal_routes() {
        ok(&route("10.0.0.0/24", Some("192.168.1.254"), None, 100));
        ok(&route("0.0.0.0/0", Some("203.0.113.1"), Some("eth0"), 10));
        ok(&route("::/0", Some("2001:db8::1"), None, 10));
        ok(&route("10.9.0.0/16", None, Some("wg0"), 50));
        ok(&route("2001:db8:1::/48", Some("fe80::1"), Some("eth1"), 100));
    }

    #[test]
    fn bare_ip_becomes_host_route() {
        let r = route("10.1.2.3", Some("192.168.1.1"), None, 100);
        assert_eq!(r.destination, "10.1.2.3/32");
        ok(&r);
        let r6 = route("2001:db8::5", Some("2001:db8::1"), None, 100);
        assert_eq!(r6.destination, "2001:db8::5/128");
        ok(&r6);
    }

    #[test]
    fn rejects_bad_destinations() {
        bad(&route("10.0.0.5/24", Some("192.168.1.1"), None, 100));
        bad(&route("garbage", Some("192.168.1.1"), None, 100));
        bad(&route("10.0.0.0/33", Some("192.168.1.1"), None, 100));
        bad(&route("127.0.0.0/8", Some("192.168.1.1"), None, 100));
        bad(&route("224.0.0.0/4", Some("192.168.1.1"), None, 100));
        bad(&route("0.0.0.0/8", Some("192.168.1.1"), None, 100));
        bad(&route("10.0.0.0/24; reboot", Some("192.168.1.1"), None, 100));
    }

    #[test]
    fn rejects_bad_gateways() {
        bad(&route("10.0.0.0/24", Some("not-an-ip"), None, 100));
        bad(&route("10.0.0.0/24", Some("2001:db8::1"), None, 100));
        bad(&route("2001:db8::/32", Some("192.168.1.1"), None, 100));
        bad(&route("10.0.0.0/24", Some("0.0.0.0"), None, 100));
        bad(&route("10.0.0.0/24", Some("127.0.0.1"), None, 100));
        bad(&route("10.0.0.0/24", Some("255.255.255.255"), None, 100));
        bad(&route("10.0.0.0/24", Some("224.0.0.1"), None, 100));
    }

    #[test]
    fn needs_gateway_or_interface() {
        bad(&route("10.0.0.0/24", None, None, 100));
        bad(&route("10.0.0.0/24", Some("  "), Some(" "), 100));
    }

    #[test]
    fn link_local_gateway_needs_interface() {
        bad(&route("::/0", Some("fe80::1"), None, 100));
        ok(&route("::/0", Some("fe80::1"), Some("eth0"), 100));
    }

    #[test]
    fn rejects_bad_interfaces_and_metrics() {
        bad(&route("10.0.0.0/24", None, Some("eth0; rm -rf /"), 100));
        bad(&route("10.0.0.0/24", None, Some("averyveryverylongname"), 100));
        bad(&route("10.0.0.0/24", Some("192.168.1.1"), None, 0));
        bad(&route("10.0.0.0/24", Some("192.168.1.1"), None, 10000));
    }

    #[test]
    fn rejects_bad_names_and_comments() {
        let mut r = route("10.0.0.0/24", Some("192.168.1.1"), None, 100);
        r.name = "".into();
        bad(&r);
        r.name = "line\nbreak".into();
        bad(&r);
        r.name = "fine".into();
        r.comment = Some("x\ny".into());
        bad(&r);
        r.comment = Some("a".repeat(201));
        bad(&r);
    }

    #[test]
    fn duplicate_destination_and_metric_is_rejected() {
        let mut a = route("10.0.0.0/24", Some("192.168.1.1"), None, 100);
        a.id = Some(1);
        let b = route("10.0.0.0/24", Some("192.168.1.2"), None, 100);
        assert!(RouteService::check_duplicate(&b, None, &[a.clone()]).is_err());
        assert!(RouteService::check_duplicate(&b, Some(1), &[a.clone()]).is_ok());
        let c = route("10.0.0.0/24", Some("192.168.1.2"), None, 200);
        assert!(RouteService::check_duplicate(&c, None, &[a]).is_ok());
    }
}
