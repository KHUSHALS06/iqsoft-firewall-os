use crate::models::route::Route;
use crate::services::route_service::RouteService;
use ipnet::IpNet;
use std::collections::HashSet;
use std::str::FromStr;

pub const ROUTE_PROTOCOL: u8 = 250;

pub struct RouteGenerator;

impl RouteGenerator {
    pub fn applicable(routes: &[Route]) -> Vec<Route> {
        let mut candidates: Vec<Route> = routes.iter().filter(|r| r.enabled).cloned().collect();
        candidates.sort_by(|a, b| a.metric.cmp(&b.metric).then(a.id.cmp(&b.id)));

        let mut seen: HashSet<(String, i32)> = HashSet::new();
        let mut result = Vec::new();

        for mut route in candidates {
            RouteService::normalize(&mut route);

            if let Err(e) = RouteService::validate_route(&route) {
                eprintln!(
                    "WARNING: skipping route '{}' (id={:?}) — {}",
                    route.name, route.id, e
                );
                continue;
            }

            let net = match IpNet::from_str(&route.destination) {
                Ok(net) => net,
                Err(_) => continue,
            };
            route.destination = net.to_string();

            if !seen.insert((route.destination.clone(), route.metric)) {
                eprintln!(
                    "WARNING: skipping route '{}' (id={:?}) — duplicate destination {} with metric {}",
                    route.name, route.id, route.destination, route.metric
                );
                continue;
            }

            result.push(route);
        }

        result
    }

    pub fn render(routes: &[Route]) -> String {
        let mut out = String::new();
        out.push_str("# iqsoft static routes - generated, do not edit\n");

        for route in Self::applicable(routes) {
            out.push_str(&format!(
                "# {} (id {})\n",
                route.name,
                route.id.unwrap_or(0)
            ));
            out.push_str(&Self::add_line(&route));
            out.push('\n');
        }

        out
    }

    pub fn render_removals(previous: &[Route], desired: &[Route]) -> String {
        let desired_keys: HashSet<(String, i32)> = Self::applicable(desired)
            .into_iter()
            .map(|r| (r.destination, r.metric))
            .collect();

        let mut out = String::new();

        for route in Self::applicable(previous) {
            if desired_keys.contains(&(route.destination.clone(), route.metric)) {
                continue;
            }

            out.push_str(&format!(
                "route del {} metric {} proto {}\n",
                route.destination, route.metric, ROUTE_PROTOCOL
            ));
        }

        out
    }

    fn add_line(route: &Route) -> String {
        let mut line = format!("route replace {}", route.destination);

        if let Some(gateway) = &route.gateway {
            line.push_str(&format!(" via {}", gateway));
        }

        if let Some(interface) = &route.interface_name {
            line.push_str(&format!(" dev {}", interface));
        }

        line.push_str(&format!(" metric {} proto {}", route.metric, ROUTE_PROTOCOL));

        line
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(
        id: i64,
        dest: &str,
        gw: Option<&str>,
        iface: Option<&str>,
        metric: i32,
        enabled: bool,
    ) -> Route {
        Route {
            id: Some(id),
            name: format!("r{}", id),
            enabled,
            destination: dest.into(),
            gateway: gw.map(|s| s.into()),
            interface_name: iface.map(|s| s.into()),
            metric,
            comment: None,
        }
    }

    #[test]
    fn empty_input_renders_header_only() {
        let text = RouteGenerator::render(&[]);
        assert_eq!(text, "# iqsoft static routes - generated, do not edit\n");
    }

    #[test]
    fn renders_gateway_interface_and_ipv6_routes() {
        let routes = vec![
            route(1, "10.0.0.0/24", Some("192.168.1.254"), None, 100, true),
            route(2, "0.0.0.0/0", Some("203.0.113.1"), Some("eth0"), 10, true),
            route(3, "10.9.0.0/16", None, Some("wg0"), 50, true),
            route(4, "::/0", Some("fe80::1"), Some("eth0"), 20, true),
            route(5, "2001:0db8:0:0::/32", Some("2001:db8::1"), None, 30, true),
        ];

        let text = RouteGenerator::render(&routes);
        let lines: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();

        assert_eq!(
            lines,
            vec![
                "route replace 0.0.0.0/0 via 203.0.113.1 dev eth0 metric 10 proto 250",
                "route replace ::/0 via fe80::1 dev eth0 metric 20 proto 250",
                "route replace 2001:db8::/32 via 2001:db8::1 metric 30 proto 250",
                "route replace 10.9.0.0/16 dev wg0 metric 50 proto 250",
                "route replace 10.0.0.0/24 via 192.168.1.254 metric 100 proto 250",
            ]
        );
    }

    #[test]
    fn disabled_and_invalid_routes_are_skipped() {
        let routes = vec![
            route(1, "10.0.0.0/24", Some("192.168.1.254"), None, 100, false),
            route(2, "10.1.0.0/24", Some("192.168.1.254"), None, 100, true),
            route(3, "10.2.0.5/24", Some("192.168.1.254"), None, 100, true),
            route(4, "10.3.0.0/24; reboot", Some("192.168.1.254"), None, 100, true),
            route(5, "10.4.0.0/24", Some("192.168.1.254; reboot"), None, 100, true),
            route(6, "10.5.0.0/24", None, Some("eth0 up"), 100, true),
        ];

        let text = RouteGenerator::render(&routes);
        let lines: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();

        assert_eq!(
            lines,
            vec!["route replace 10.1.0.0/24 via 192.168.1.254 metric 100 proto 250"]
        );
    }

    #[test]
    fn duplicate_destination_and_metric_keeps_first() {
        let routes = vec![
            route(2, "10.0.0.0/24", Some("192.168.1.2"), None, 100, true),
            route(1, "10.0.0.0/24", Some("192.168.1.1"), None, 100, true),
        ];

        let applicable = RouteGenerator::applicable(&routes);
        assert_eq!(applicable.len(), 1);
        assert_eq!(applicable[0].id, Some(1));
    }

    #[test]
    fn same_destination_different_metric_both_kept() {
        let routes = vec![
            route(1, "0.0.0.0/0", Some("203.0.113.1"), None, 10, true),
            route(2, "0.0.0.0/0", Some("198.51.100.1"), None, 20, true),
        ];

        assert_eq!(RouteGenerator::applicable(&routes).len(), 2);
    }

    #[test]
    fn removals_only_cover_routes_that_disappear() {
        let previous = vec![
            route(1, "10.0.0.0/24", Some("192.168.1.1"), None, 100, true),
            route(2, "10.1.0.0/24", Some("192.168.1.1"), None, 100, true),
            route(3, "10.2.0.0/24", Some("192.168.1.1"), None, 100, true),
            route(4, "10.3.0.0/24", Some("192.168.1.1"), None, 100, false),
        ];
        let desired = vec![
            route(1, "10.0.0.0/24", Some("192.168.1.9"), None, 100, true),
            route(2, "10.1.0.0/24", Some("192.168.1.1"), None, 200, true),
            route(3, "10.2.0.0/24", Some("192.168.1.1"), None, 100, false),
        ];

        let text = RouteGenerator::render_removals(&previous, &desired);
        let lines: Vec<&str> = text.lines().collect();

        assert_eq!(
            lines,
            vec![
                "route del 10.1.0.0/24 metric 100 proto 250",
                "route del 10.2.0.0/24 metric 100 proto 250",
            ]
        );
    }

    #[test]
    fn removals_empty_when_nothing_changes() {
        let routes = vec![route(1, "10.0.0.0/24", Some("192.168.1.1"), None, 100, true)];
        assert!(RouteGenerator::render_removals(&routes, &routes).is_empty());
    }

    #[test]
    fn injection_in_name_stays_inside_a_comment_line() {
        let mut r = route(1, "10.0.0.0/24", Some("192.168.1.1"), None, 100, true);
        r.name = "x; route del default".into();
        let text = RouteGenerator::render(&[r]);
        for line in text.lines() {
            assert!(line.starts_with('#') || line.starts_with("route replace 10.0.0.0/24"));
        }
    }
}
