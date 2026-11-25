//! The list of features that can be switched on or off per role, and the rules
//! that decide which permission an API request needs.
//!
//! A permission is written `feature.action`, for example `firewall.edit`.
//! The four actions are the usual CRUD ones: `view` (read), `create`, `edit`
//! (update) and `delete`. Not every feature offers all four; a read-only page
//! such as Logs only has `view`.

use axum::http::Method;

pub const ROLE_SUPER_ADMIN: &str = "super_admin";
pub const ROLE_ADMIN: &str = "admin";

const VIEW: &str = "view";
const CREATE: &str = "create";
const EDIT: &str = "edit";
const DELETE: &str = "delete";

const READ_ONLY: &[&str] = &[VIEW];
const VIEW_EDIT: &[&str] = &[VIEW, EDIT];
const CRUD: &[&str] = &[VIEW, CREATE, EDIT, DELETE];

/// (feature id, label shown in the UI, actions the feature offers).
/// The order here is the order of the rows in the role editor.
pub const FEATURES: &[(&str, &str, &[&str])] = &[
    ("dashboard", "Dashboard", READ_ONLY),
    ("network", "Network", CRUD),
    ("sdwan", "SD-WAN", CRUD),
    ("firewall", "Firewall Rules", CRUD),
    ("nat", "NAT / Port Forwarding", CRUD),
    ("threat", "Threat Intelligence", CRUD),
    ("ids", "Intrusion Detection", CRUD),
    ("geoip", "GeoIP Blocking", CRUD),
    ("antivirus", "Antivirus", CRUD),
    ("dnsfilter", "DNS Filter", CRUD),
    ("appcontrol", "App Control", CRUD),
    ("vpn", "VPN", CRUD),
    ("monitoring", "Monitoring", READ_ONLY),
    ("logs", "Logs", READ_ONLY),
    ("reports", "Reports", READ_ONLY),
    ("system", "System", VIEW_EDIT),
    ("users", "Users", CRUD),
    ("roles", "Roles", CRUD),
];

pub fn permission(feature: &str, action: &str) -> String {
    format!("{}.{}", feature, action)
}

/// Every permission that exists. The Super Admin role always holds all of them.
pub fn all_permissions() -> Vec<String> {
    FEATURES
        .iter()
        .flat_map(|(feature, _, actions)| actions.iter().map(move |a| permission(feature, a)))
        .collect()
}

pub fn is_valid_permission(value: &str) -> bool {
    FEATURES.iter().any(|(feature, _, actions)| {
        actions
            .iter()
            .any(|action| permission(feature, action) == value)
    })
}

/// Checks a list coming from a client and puts it in a canonical form:
/// unknown permissions are an error, duplicates are removed, and anything that
/// grants create, edit or delete also grants view (you cannot change what you
/// cannot see). The result is in catalog order.
pub fn normalize(requested: &[String]) -> Result<Vec<String>, String> {
    for p in requested {
        if !is_valid_permission(p) {
            return Err("Unknown permission in the request".to_string());
        }
    }

    let mut out = Vec::new();

    for (feature, _, actions) in FEATURES {
        let has = |action: &str| requested.iter().any(|p| *p == permission(feature, action));
        let any = actions.iter().any(|a| has(a));

        if !any {
            continue;
        }

        for action in actions.iter() {
            if *action == VIEW || has(action) {
                out.push(permission(feature, action));
            }
        }
    }

    Ok(out)
}

/// What a request has to hold before it may run.
#[derive(Debug, PartialEq, Eq)]
pub enum Requirement {
    /// Any signed-in user (own account: who am I, sign out, change password).
    Open,
    /// The handler checks permissions itself (users, roles).
    HandlerChecked,
    /// The user needs at least one of these permissions.
    AnyOf(Vec<String>),
    /// Nothing in the table covers this path, so only a Super Admin may use it.
    /// New API routes are therefore closed until they are added below.
    SuperAdminOnly,
}

struct Zone {
    prefix: &'static str,
    /// Features whose permission of the needed action opens this zone.
    features: &'static [&'static str],
    /// Additional features that may only *read* it (the dashboard shows data from many places).
    view_also: &'static [&'static str],
}

const SHARED_COMMIT: &[&str] = &[
    "firewall",
    "nat",
    "threat",
    "geoip",
    "antivirus",
    "dnsfilter",
    "appcontrol",
];

const ZONES: &[Zone] = &[
    Zone { prefix: "/api/rules", features: &["firewall"], view_also: &["dashboard", "monitoring", "logs", "reports"] },
    Zone { prefix: "/api/generate", features: &["firewall"], view_also: &[] },
    // The ruleset commit is shared by every page that ends in "apply the firewall rules".
    Zone { prefix: "/api/commit", features: SHARED_COMMIT, view_also: &[] },
    Zone { prefix: "/api/rollback", features: SHARED_COMMIT, view_also: &[] },
    Zone { prefix: "/api/address-objects", features: &["firewall", "network"], view_also: &[] },
    Zone { prefix: "/api/address-groups", features: &["firewall", "network"], view_also: &[] },
    Zone { prefix: "/api/port-forwards", features: &["nat"], view_also: &[] },
    Zone { prefix: "/api/one-to-one-nat", features: &["nat"], view_also: &[] },
    Zone { prefix: "/api/network", features: &["network"], view_also: &["dashboard"] },
    Zone { prefix: "/api/interfaces", features: &["network"], view_also: &[] },
    Zone { prefix: "/api/dhcp", features: &["network"], view_also: &[] },
    Zone { prefix: "/api/dns", features: &["network"], view_also: &[] },
    Zone { prefix: "/api/routes", features: &["network"], view_also: &[] },
    Zone { prefix: "/api/sdwan", features: &["sdwan"], view_also: &[] },
    Zone { prefix: "/api/threatfeeds", features: &["threat"], view_also: &["dashboard"] },
    Zone { prefix: "/api/ids", features: &["ids"], view_also: &["dashboard"] },
    Zone { prefix: "/api/geoip", features: &["geoip"], view_also: &["dashboard"] },
    Zone { prefix: "/api/av", features: &["antivirus"], view_also: &["dashboard"] },
    Zone { prefix: "/api/dnsfilter", features: &["dnsfilter"], view_also: &[] },
    Zone { prefix: "/api/sni", features: &["appcontrol"], view_also: &[] },
    Zone { prefix: "/api/wireguard", features: &["vpn"], view_also: &[] },
    Zone { prefix: "/api/monitor", features: &["monitoring"], view_also: &["dashboard", "reports", "network", "system"] },
    Zone { prefix: "/api/audit", features: &["logs"], view_also: &["reports"] },
    Zone { prefix: "/api/system", features: &["system"], view_also: &[] },
];

/// POST (or GET) paths that do something to the firewall rather than create a record.
/// They need `edit`. Listed in full on purpose: a rule or category called "commit"
/// must not be able to turn a delete into an edit.
const EDIT_PATHS: &[&str] = &[
    "/api/commit",
    "/api/commit/confirm",
    "/api/rollback",
    "/api/interfaces/commit",
    "/api/interfaces/confirm",
    "/api/interfaces/rollback",
    "/api/dhcp/commit",
    "/api/dhcp/rollback",
    "/api/dns/commit",
    "/api/dns/rollback",
    "/api/routes/commit",
    "/api/routes/rollback",
    "/api/wireguard/commit",
    "/api/wireguard/rollback",
    "/api/sdwan/commit",
    "/api/sdwan/rollback",
    "/api/sdwan/probe",
    "/api/ids/apply",
    "/api/ids/rules/update",
    "/api/threatfeeds/apply",
    "/api/system/backup",
    "/api/system/restore",
    "/api/system/reboot",
    "/api/system/shutdown",
];

fn in_zone(path: &str, prefix: &str) -> bool {
    path == prefix
        || (path.starts_with(prefix) && path.as_bytes().get(prefix.len()) == Some(&b'/'))
}

/// `/api/threatfeeds/{id}/refresh`
fn is_feed_refresh(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    parts.len() == 5 && parts[2] == "threatfeeds" && parts[4] == "refresh" && !parts[3].is_empty()
}

/// Which of view/create/edit/delete a request is.
pub fn action_for(method: &Method, path: &str) -> &'static str {
    if EDIT_PATHS.contains(&path) || is_feed_refresh(path) {
        return EDIT;
    }

    if path == "/api/geoip/locate" {
        return VIEW; // a lookup, it changes nothing
    }

    match *method {
        Method::DELETE => DELETE,
        Method::PUT | Method::PATCH => EDIT,
        Method::POST => CREATE,
        _ => VIEW,
    }
}

pub fn required_for(method: &Method, path: &str) -> Requirement {
    if in_zone(path, "/api/auth") {
        return Requirement::Open;
    }

    if in_zone(path, "/api/users")
        || in_zone(path, "/api/roles")
        || in_zone(path, "/api/permissions")
    {
        return Requirement::HandlerChecked;
    }

    let action = action_for(method, path);

    for zone in ZONES {
        if !in_zone(path, zone.prefix) {
            continue;
        }

        let mut allowed: Vec<String> = zone
            .features
            .iter()
            .map(|feature| permission(feature, action))
            .collect();

        if action == VIEW {
            allowed.extend(zone.view_also.iter().map(|f| permission(f, VIEW)));
        }

        return Requirement::AnyOf(allowed);
    }

    Requirement::SuperAdminOnly
}

#[cfg(test)]
mod tests {
    use super::*;

    fn any_of(method: Method, path: &str) -> Vec<String> {
        match required_for(&method, path) {
            Requirement::AnyOf(list) => list,
            other => panic!("expected AnyOf, got {:?}", other),
        }
    }

    #[test]
    fn the_catalog_has_no_duplicates() {
        let all = all_permissions();
        let mut sorted = all.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(all.len(), sorted.len());
        assert!(all.contains(&"firewall.delete".to_string()));
        assert!(!all.contains(&"logs.delete".to_string()));
    }

    #[test]
    fn normalize_adds_view_and_rejects_unknown_permissions() {
        let out = normalize(&["firewall.delete".to_string()]).unwrap();
        assert_eq!(out, vec!["firewall.view", "firewall.delete"]);

        assert!(normalize(&["firewall.explode".to_string()]).is_err());
        assert!(normalize(&["logs.delete".to_string()]).is_err());
        assert!(normalize(&[]).unwrap().is_empty());
    }

    #[test]
    fn normalize_removes_duplicates_and_keeps_catalog_order() {
        let out = normalize(&[
            "vpn.view".to_string(),
            "dashboard.view".to_string(),
            "vpn.view".to_string(),
        ])
        .unwrap();
        assert_eq!(out, vec!["dashboard.view", "vpn.view"]);
    }

    #[test]
    fn methods_map_to_crud_actions() {
        assert_eq!(any_of(Method::GET, "/api/rules"), vec!["firewall.view", "dashboard.view", "monitoring.view", "logs.view", "reports.view"]);
        assert_eq!(any_of(Method::POST, "/api/rules"), vec!["firewall.create"]);
        assert_eq!(any_of(Method::PUT, "/api/rules/5"), vec!["firewall.edit"]);
        assert_eq!(any_of(Method::DELETE, "/api/rules/5"), vec!["firewall.delete"]);
    }

    #[test]
    fn commit_and_system_actions_need_edit() {
        assert!(any_of(Method::POST, "/api/commit").contains(&"firewall.edit".to_string()));
        assert!(any_of(Method::POST, "/api/rollback").contains(&"nat.edit".to_string()));
        assert_eq!(any_of(Method::POST, "/api/system/reboot"), vec!["system.edit"]);
        // The backup holds password hashes and VPN keys, so reading it is an edit-level right.
        assert_eq!(any_of(Method::GET, "/api/system/backup"), vec!["system.edit"]);
        assert_eq!(any_of(Method::POST, "/api/threatfeeds/7/refresh"), vec!["threat.edit"]);
        assert_eq!(any_of(Method::POST, "/api/ids/apply"), vec!["ids.edit"]);
    }

    #[test]
    fn a_record_named_like_an_action_is_still_a_delete() {
        assert_eq!(
            any_of(Method::DELETE, "/api/dnsfilter/categories/commit"),
            vec!["dnsfilter.delete"]
        );
    }

    #[test]
    fn a_geoip_lookup_is_a_view() {
        let list = any_of(Method::POST, "/api/geoip/locate");
        assert!(list.contains(&"geoip.view".to_string()));
        assert!(list.contains(&"dashboard.view".to_string()));
    }

    #[test]
    fn prefixes_do_not_bleed_into_longer_names() {
        // /api/dnsfilter must not be treated as /api/dns (Network).
        assert_eq!(any_of(Method::GET, "/api/dnsfilter/rules"), vec!["dnsfilter.view"]);
        assert_eq!(any_of(Method::GET, "/api/dns/records"), vec!["network.view"]);
        // /api/routes is Network, /api/rules is Firewall.
        assert_eq!(any_of(Method::GET, "/api/routes"), vec!["network.view"]);
    }

    #[test]
    fn own_account_and_management_routes_are_classified() {
        assert_eq!(required_for(&Method::GET, "/api/auth/me"), Requirement::Open);
        assert_eq!(required_for(&Method::POST, "/api/auth/change-password"), Requirement::Open);
        assert_eq!(required_for(&Method::GET, "/api/users"), Requirement::HandlerChecked);
        assert_eq!(required_for(&Method::PUT, "/api/roles/3"), Requirement::HandlerChecked);
    }

    #[test]
    fn unknown_paths_are_closed_to_everyone_but_the_super_admin() {
        assert_eq!(required_for(&Method::GET, "/api/brand-new-thing"), Requirement::SuperAdminOnly);
    }
}
