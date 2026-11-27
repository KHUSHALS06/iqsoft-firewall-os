use serde::{Deserialize, Serialize};

pub const MAX_NAME_LEN: usize = 40;
pub const MAX_COMMENT_LEN: usize = 200;
pub const MAX_ERROR_LEN: usize = 300;
pub const MAX_ID_LEN: usize = 128;
pub const MAX_FILE_NAME_LEN: usize = 100;
pub const MAX_SITE_NAME_LEN: usize = 40;

pub const MAX_TUNNELS: usize = 32;
pub const MAX_ADVERTISED_NETWORKS: usize = 64;

pub const MIN_PSK_LEN: usize = 16;
pub const MAX_PSK_LEN: usize = 128;

pub const MIN_MTU: i64 = 1280;
pub const MAX_MTU: i64 = 1500;
pub const MIN_DPD_DELAY_SECS: i64 = 2;
pub const MAX_DPD_DELAY_SECS: i64 = 300;
pub const MIN_OSPF_COST: i64 = 1;
pub const MAX_OSPF_COST: i64 = 60000;
pub const MIN_OSPF_HELLO_SECS: i64 = 1;
pub const MAX_OSPF_HELLO_SECS: i64 = 60;
pub const MIN_OSPF_DEAD_SECS: i64 = 2;
pub const MAX_OSPF_DEAD_SECS: i64 = 240;

pub const AUTH_METHODS: [&str; 2] = ["psk", "cert"];
pub const TUNNEL_STATES: [&str; 3] = ["unknown", "up", "down"];
pub const IKE_STATES: [&str; 4] = ["unknown", "down", "connecting", "established"];
pub const CHILD_STATES: [&str; 3] = ["unknown", "down", "installed"];
pub const ROUTING_STATES: [&str; 4] = ["unknown", "down", "forming", "full"];

pub const IKE_PROPOSAL: &str = "aes256gcm16-prfsha384-ecp384";
pub const ESP_PROPOSAL: &str = "aes256gcm16-ecp384";

pub const IF_ID_BASE: u32 = 1000;
pub const INTERFACE_PREFIX: &str = "xfrm";

pub fn tunnel_interface(id: i64) -> String {
    format!("{}{}", INTERFACE_PREFIX, id)
}

pub fn tunnel_if_id(id: i64) -> u32 {
    IF_ID_BASE + id as u32
}

pub fn tunnel_connection_name(id: i64) -> String {
    format!("iqsoft-t{}", id)
}

fn default_true() -> bool {
    true
}

fn default_site_name() -> String {
    "site".to_string()
}

fn default_ospf_area() -> String {
    "0.0.0.0".to_string()
}

fn default_hello() -> i64 {
    2
}

fn default_dead() -> i64 {
    8
}

fn default_auth_method() -> String {
    "psk".to_string()
}

fn default_mtu() -> i64 {
    1400
}

fn default_dpd_delay() -> i64 {
    10
}

fn default_ospf_cost() -> i64 {
    10
}

fn default_state() -> String {
    "unknown".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct OverlaySettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_site_name")]
    pub site_name: String,
    #[serde(default)]
    pub router_id: Option<String>,
    #[serde(default = "default_ospf_area")]
    pub ospf_area: String,
    #[serde(default)]
    pub advertised_networks: Vec<String>,
    #[serde(default = "default_hello")]
    pub ospf_hello_secs: i64,
    #[serde(default = "default_dead")]
    pub ospf_dead_secs: i64,
}

impl Default for OverlaySettings {
    fn default() -> Self {
        OverlaySettings {
            enabled: false,
            site_name: default_site_name(),
            router_id: None,
            ospf_area: default_ospf_area(),
            advertised_networks: Vec::new(),
            ospf_hello_secs: default_hello(),
            ospf_dead_secs: default_dead(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OverlayTunnel {
    pub id: Option<i64>,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub link_id: i64,
    pub remote_address: String,
    #[serde(default)]
    pub local_id: Option<String>,
    #[serde(default)]
    pub remote_id: Option<String>,
    #[serde(default = "default_auth_method")]
    pub auth_method: String,
    #[serde(default)]
    pub psk: Option<String>,
    #[serde(default)]
    pub psk_set: bool,
    #[serde(default)]
    pub local_cert: Option<String>,
    #[serde(default)]
    pub local_key: Option<String>,
    #[serde(default)]
    pub remote_ca: Option<String>,
    #[serde(default = "default_true")]
    pub initiate: bool,
    pub inner_local: String,
    pub inner_remote: String,
    #[serde(default = "default_mtu")]
    pub mtu: i64,
    #[serde(default = "default_dpd_delay")]
    pub dpd_delay_secs: i64,
    #[serde(default = "default_ospf_cost")]
    pub ospf_cost: i64,
    #[serde(default)]
    pub comment: Option<String>,

    #[serde(default = "default_state")]
    pub state: String,
    #[serde(default = "default_state")]
    pub ike_state: String,
    #[serde(default = "default_state")]
    pub child_state: String,
    #[serde(default = "default_state")]
    pub routing_state: String,
    #[serde(default)]
    pub latency_ms: Option<f64>,
    #[serde(default)]
    pub loss_pct: Option<i64>,
    #[serde(default)]
    pub uptime_secs: Option<i64>,
    #[serde(default)]
    pub bytes_in: Option<i64>,
    #[serde(default)]
    pub bytes_out: Option<i64>,
    #[serde(default)]
    pub applied_cost: Option<i64>,
    #[serde(default)]
    pub last_check: Option<i64>,
    #[serde(default)]
    pub last_change: Option<i64>,
    #[serde(default)]
    pub last_error: Option<String>,
}

impl OverlayTunnel {
    pub fn is_usable(&self) -> bool {
        self.enabled && self.state != "down"
    }

    pub fn interface_name(&self) -> Option<String> {
        self.id.map(tunnel_interface)
    }

    pub fn if_id(&self) -> Option<u32> {
        self.id.map(tunnel_if_id)
    }

    pub fn connection_name(&self) -> Option<String> {
        self.id.map(tunnel_connection_name)
    }

    pub fn redacted(mut self) -> Self {
        self.psk_set = self.psk.as_deref().map(|p| !p.is_empty()).unwrap_or(false);
        self.psk = None;
        self
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct OverlayTunnelStatus {
    pub tunnel_id: i64,
    pub state: String,
    pub ike_state: String,
    pub child_state: String,
    pub routing_state: String,
    pub latency_ms: Option<f64>,
    pub loss_pct: Option<i64>,
    pub uptime_secs: Option<i64>,
    pub bytes_in: Option<i64>,
    pub bytes_out: Option<i64>,
    pub applied_cost: Option<i64>,
    pub consecutive_fail: i64,
    pub consecutive_ok: i64,
    pub last_check: Option<i64>,
    pub last_change: Option<i64>,
    pub last_error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> OverlayTunnel {
        serde_json::from_str(
            r#"{"name":"hq","link_id":1,"remote_address":"203.0.113.10",
                "inner_local":"10.255.0.1/30","inner_remote":"10.255.0.2"}"#,
        )
        .unwrap()
    }

    #[test]
    fn a_tunnel_with_the_required_fields_gets_the_defaults() {
        let t = minimal();

        assert_eq!(t.id, None);
        assert!(t.enabled);
        assert_eq!(t.auth_method, "psk");
        assert_eq!(t.psk, None);
        assert!(!t.psk_set);
        assert!(t.initiate);
        assert_eq!(t.mtu, 1400);
        assert_eq!(t.dpd_delay_secs, 10);
        assert_eq!(t.ospf_cost, 10);
        assert_eq!(t.state, "unknown");
        assert_eq!(t.ike_state, "unknown");
        assert_eq!(t.child_state, "unknown");
        assert_eq!(t.routing_state, "unknown");
        assert_eq!(t.latency_ms, None);
    }

    #[test]
    fn settings_default_to_switched_off() {
        let s: OverlaySettings = serde_json::from_str("{}").unwrap();

        assert_eq!(s, OverlaySettings::default());
        assert!(!s.enabled);
        assert_eq!(s.site_name, "site");
        assert_eq!(s.ospf_area, "0.0.0.0");
        assert_eq!(s.ospf_hello_secs, 2);
        assert_eq!(s.ospf_dead_secs, 8);
        assert!(s.advertised_networks.is_empty());
        assert_eq!(s.router_id, None);
    }

    #[test]
    fn a_tunnel_is_usable_unless_disabled_or_down() {
        let mut t = minimal();
        assert!(t.is_usable());

        t.state = "up".into();
        assert!(t.is_usable());

        t.state = "down".into();
        assert!(!t.is_usable());

        t.state = "up".into();
        t.enabled = false;
        assert!(!t.is_usable());
    }

    #[test]
    fn names_and_ids_follow_the_tunnel_id() {
        assert_eq!(tunnel_interface(7), "xfrm7");
        assert_eq!(tunnel_if_id(7), 1007);
        assert_eq!(tunnel_connection_name(7), "iqsoft-t7");

        let mut t = minimal();
        assert_eq!(t.interface_name(), None);
        assert_eq!(t.if_id(), None);
        assert_eq!(t.connection_name(), None);

        t.id = Some(12);
        assert_eq!(t.interface_name().as_deref(), Some("xfrm12"));
        assert_eq!(t.if_id(), Some(1012));
        assert_eq!(t.connection_name().as_deref(), Some("iqsoft-t12"));
    }

    #[test]
    fn interface_names_fit_the_linux_limit() {
        assert!(tunnel_interface(999_999_999).len() <= 15);
    }

    #[test]
    fn redacting_hides_the_psk_but_remembers_it_was_set() {
        let mut t = minimal();
        t.psk = Some("a-long-enough-secret".into());

        let hidden = t.clone().redacted();
        assert_eq!(hidden.psk, None);
        assert!(hidden.psk_set);

        let json = serde_json::to_string(&hidden).unwrap();
        assert!(!json.contains("a-long-enough-secret"));

        let mut empty = minimal();
        empty.psk = Some(String::new());
        assert!(!empty.redacted().psk_set);

        assert!(!minimal().redacted().psk_set);
    }

    #[test]
    fn a_stored_snapshot_keeps_the_psk() {
        let mut t = minimal();
        t.psk = Some("a-long-enough-secret".into());

        let json = serde_json::to_string(&t).unwrap();
        let back: OverlayTunnel = serde_json::from_str(&json).unwrap();
        assert_eq!(back.psk.as_deref(), Some("a-long-enough-secret"));
    }

    #[test]
    fn the_allowed_words_match_the_database_checks() {
        assert_eq!(AUTH_METHODS, ["psk", "cert"]);
        assert_eq!(TUNNEL_STATES, ["unknown", "up", "down"]);
        assert_eq!(IKE_STATES, ["unknown", "down", "connecting", "established"]);
        assert_eq!(CHILD_STATES, ["unknown", "down", "installed"]);
        assert_eq!(ROUTING_STATES, ["unknown", "down", "forming", "full"]);
    }

    #[test]
    fn the_proposals_are_aes_256_gcm_only() {
        assert!(IKE_PROPOSAL.starts_with("aes256gcm16-"));
        assert!(ESP_PROPOSAL.starts_with("aes256gcm16-"));
        assert!(!IKE_PROPOSAL.contains(','));
        assert!(!ESP_PROPOSAL.contains(','));
    }

    #[test]
    fn the_limits_match_the_database_checks() {
        assert_eq!((MIN_MTU, MAX_MTU), (1280, 1500));
        assert_eq!((MIN_DPD_DELAY_SECS, MAX_DPD_DELAY_SECS), (2, 300));
        assert_eq!((MIN_OSPF_COST, MAX_OSPF_COST), (1, 60000));
        assert_eq!((MIN_OSPF_HELLO_SECS, MAX_OSPF_HELLO_SECS), (1, 60));
        assert_eq!((MIN_OSPF_DEAD_SECS, MAX_OSPF_DEAD_SECS), (2, 240));
        assert_eq!(MIN_PSK_LEN, 16);
    }
}
