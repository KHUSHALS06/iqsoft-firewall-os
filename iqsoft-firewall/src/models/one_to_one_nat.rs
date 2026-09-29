use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

/// Static one-to-one NAT: every packet sent to `external_ip` on the WAN side
/// is translated to `internal_ip`, and everything `internal_ip` sends out
/// through the WAN is translated to come from `external_ip`.
///
/// This rule only translates addresses. It does NOT open the firewall: to let
/// traffic through, add a FORWARD rule whose destination is `internal_ip`.
///
/// `external_ip` must already be an address on the WAN interface (for example
/// added with `ip addr add`), otherwise the box never receives the traffic.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OneToOneNatRule {
    pub id: Option<i64>,

    pub name: String,

    #[serde(default = "default_true")]
    pub enabled: bool,

    /// WAN-side address that maps to the internal host.
    pub external_ip: String,

    /// LAN host behind the firewall.
    pub internal_ip: String,

    pub comment: Option<String>,
}
