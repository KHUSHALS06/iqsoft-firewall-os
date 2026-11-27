use crate::models::overlay::{
    OverlaySettings, OverlayTunnel, AUTH_METHODS, MAX_ADVERTISED_NETWORKS, MAX_COMMENT_LEN,
    MAX_DPD_DELAY_SECS, MAX_FILE_NAME_LEN, MAX_ID_LEN, MAX_MTU, MAX_NAME_LEN, MAX_OSPF_COST,
    MAX_OSPF_DEAD_SECS, MAX_OSPF_HELLO_SECS, MAX_PSK_LEN, MAX_SITE_NAME_LEN, MAX_TUNNELS,
    MIN_DPD_DELAY_SECS, MIN_MTU, MIN_OSPF_COST, MIN_OSPF_DEAD_SECS, MIN_OSPF_HELLO_SECS,
    MIN_PSK_LEN,
};
use crate::repository::overlay_repository::OverlayRepository;
use crate::repository::sdwan_repository::SdwanRepository;
use ipnet::Ipv4Net;
use sqlx::SqlitePool;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// The tunnel's own address is a small point-to-point style network.
const MIN_INNER_PREFIX: u8 = 16;
const MAX_INNER_PREFIX: u8 = 31;

pub struct OverlayService;

impl OverlayService {
    // ---------------------------------------------------------------- settings

    pub async fn get_settings(pool: &SqlitePool) -> Result<OverlaySettings, String> {
        OverlayRepository::get_settings(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn save_settings(
        pool: &SqlitePool,
        mut settings: OverlaySettings,
    ) -> Result<(), String> {
        Self::normalize_settings(&mut settings);
        Self::validate_settings(&settings)?;

        if settings.enabled {
            Self::check_can_enable(pool, &settings).await?;
        }

        OverlayRepository::save_settings(pool, &settings)
            .await
            .map_err(|e| e.to_string())
    }

    /// Switching the overlay on needs a router ID and at least one enabled tunnel.
    /// Switching it off is always allowed.
    pub async fn set_enabled(pool: &SqlitePool, enabled: bool) -> Result<(), String> {
        let mut settings = Self::get_settings(pool).await?;
        settings.enabled = enabled;

        Self::save_settings(pool, settings).await
    }

    async fn check_can_enable(pool: &SqlitePool, settings: &OverlaySettings) -> Result<(), String> {
        if settings.router_id.is_none() {
            return Err("Set a router ID before switching the overlay on".into());
        }

        let tunnels = OverlayRepository::list_tunnels(pool)
            .await
            .map_err(|e| e.to_string())?;

        if !tunnels.iter().any(|t| t.enabled) {
            return Err("Add at least one enabled tunnel before switching the overlay on".into());
        }

        Ok(())
    }

    // ----------------------------------------------------------------- tunnels

    /// For the web page: the pre-shared key is never returned.
    pub async fn list_tunnels(pool: &SqlitePool) -> Result<Vec<OverlayTunnel>, String> {
        let tunnels = Self::list_tunnels_with_secrets(pool).await?;
        Ok(tunnels.into_iter().map(|t| t.redacted()).collect())
    }

    /// For the config generator and the commit: includes the pre-shared key.
    /// Never send this to the web page.
    pub async fn list_tunnels_with_secrets(
        pool: &SqlitePool,
    ) -> Result<Vec<OverlayTunnel>, String> {
        OverlayRepository::list_tunnels(pool)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn get_tunnel(pool: &SqlitePool, id: i64) -> Result<OverlayTunnel, String> {
        OverlayRepository::get_tunnel(pool, id)
            .await
            .map_err(|e| e.to_string())?
            .map(|t| t.redacted())
            .ok_or_else(|| format!("Tunnel {} does not exist", id))
    }

    pub async fn add_tunnel(pool: &SqlitePool, mut tunnel: OverlayTunnel) -> Result<i64, String> {
        Self::normalize_tunnel(&mut tunnel);
        Self::validate_tunnel(&tunnel)?;

        if tunnel.auth_method == "psk" && tunnel.psk.is_none() {
            return Err("A pre-shared key is required for a PSK tunnel".into());
        }

        let count = OverlayRepository::count_tunnels(pool)
            .await
            .map_err(|e| e.to_string())?;
        if count as usize >= MAX_TUNNELS {
            return Err(format!("At most {} tunnels are supported", MAX_TUNNELS));
        }

        Self::check_link_exists(pool, tunnel.link_id).await?;
        Self::check_tunnel_duplicates(pool, &tunnel, None).await?;

        OverlayRepository::add_tunnel(pool, &tunnel)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn update_tunnel(
        pool: &SqlitePool,
        id: i64,
        mut tunnel: OverlayTunnel,
    ) -> Result<(), String> {
        Self::normalize_tunnel(&mut tunnel);
        Self::validate_tunnel(&tunnel)?;

        let existing = OverlayRepository::get_tunnel(pool, id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("Tunnel {} does not exist", id))?;

        // No key sent means "keep the stored one". That only works if there is one,
        // and a tunnel that was on certificates has none.
        if tunnel.auth_method == "psk" && tunnel.psk.is_none() {
            let had_key = existing.auth_method == "psk"
                && existing.psk.as_deref().map(|p| !p.is_empty()).unwrap_or(false);

            if !had_key {
                return Err("A pre-shared key is required for a PSK tunnel".into());
            }
        }

        Self::check_link_exists(pool, tunnel.link_id).await?;
        Self::check_tunnel_duplicates(pool, &tunnel, Some(id)).await?;

        let changed = OverlayRepository::update_tunnel(pool, id, &tunnel)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("Tunnel {} does not exist", id));
        }

        Ok(())
    }

    pub async fn delete_tunnel(pool: &SqlitePool, id: i64) -> Result<(), String> {
        let changed = OverlayRepository::delete_tunnel(pool, id)
            .await
            .map_err(|e| e.to_string())?;

        if changed == 0 {
            return Err(format!("Tunnel {} does not exist", id));
        }

        Ok(())
    }

    async fn check_link_exists(pool: &SqlitePool, link_id: i64) -> Result<(), String> {
        let link = SdwanRepository::get_link(pool, link_id)
            .await
            .map_err(|e| e.to_string())?;

        if link.is_none() {
            return Err(format!("WAN link {} does not exist", link_id));
        }

        Ok(())
    }

    async fn check_tunnel_duplicates(
        pool: &SqlitePool,
        tunnel: &OverlayTunnel,
        self_id: Option<i64>,
    ) -> Result<(), String> {
        let same_name = OverlayRepository::get_tunnel_by_name(pool, &tunnel.name)
            .await
            .map_err(|e| e.to_string())?;

        if let Some(other) = same_name {
            if other.id != self_id {
                return Err(format!("A tunnel named '{}' already exists", tunnel.name));
            }
        }

        let same_inner = OverlayRepository::get_tunnel_by_inner_local(pool, &tunnel.inner_local)
            .await
            .map_err(|e| e.to_string())?;

        if let Some(other) = same_inner {
            if other.id != self_id {
                return Err(format!(
                    "Tunnel address '{}' is already used by tunnel '{}'",
                    tunnel.inner_local, other.name
                ));
            }
        }

        let (mine, _) = Self::parse_inner(tunnel)?;
        let all = OverlayRepository::list_tunnels(pool)
            .await
            .map_err(|e| e.to_string())?;

        // The route to a peer is per peer address, not per WAN link, so two tunnels
        // cannot go to the same peer address (not even over different links).
        if let Some(other) = all
            .iter()
            .find(|o| o.id != self_id && o.remote_address == tunnel.remote_address)
        {
            return Err(format!(
                "Tunnel '{}' already connects to {}",
                other.name, tunnel.remote_address
            ));
        }

        // Two tunnels cannot share a tunnel network, even with different host addresses.
        for other in all.iter().filter(|o| o.id != self_id) {
            if let Ok(theirs) = Ipv4Net::from_str(&other.inner_local) {
                if Self::networks_overlap(&mine, &theirs) {
                    return Err(format!(
                        "Tunnel address '{}' overlaps the tunnel network of '{}' ({})",
                        tunnel.inner_local, other.name, other.inner_local
                    ));
                }
            }
        }

        Ok(())
    }

    // ----------------------------------------------------- cleaning and checks

    fn clean_optional(value: Option<String>) -> Option<String> {
        value
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    fn canonical_addr(value: &str) -> String {
        match Ipv4Addr::from_str(value) {
            Ok(ip) => ip.to_string(),
            Err(_) => value.to_string(),
        }
    }

    pub fn normalize_settings(settings: &mut OverlaySettings) {
        settings.site_name = settings.site_name.trim().to_string();
        settings.router_id = Self::clean_optional(settings.router_id.take())
            .map(|v| Self::canonical_addr(&v));
        settings.ospf_area = Self::canonical_addr(settings.ospf_area.trim());

        let mut networks: Vec<String> = Vec::new();
        for raw in settings.advertised_networks.drain(..) {
            let value = raw.trim().to_string();
            if value.is_empty() {
                continue;
            }

            let value = match Ipv4Net::from_str(&value) {
                Ok(net) => net.to_string(),
                Err(_) => value,
            };

            if !networks.contains(&value) {
                networks.push(value);
            }
        }
        settings.advertised_networks = networks;
    }

    pub fn validate_settings(settings: &OverlaySettings) -> Result<(), String> {
        Self::check_site_name(&settings.site_name)?;

        if let Some(raw) = &settings.router_id {
            let ip = Ipv4Addr::from_str(raw)
                .map_err(|_| format!("Router ID '{}' is not a valid IPv4 address", raw))?;
            Self::check_host_address(ip, "Router ID", raw)?;
        }

        Ipv4Addr::from_str(&settings.ospf_area).map_err(|_| {
            format!(
                "OSPF area '{}' is not valid (use the dotted form, for example 0.0.0.0)",
                settings.ospf_area
            )
        })?;

        if settings.advertised_networks.len() > MAX_ADVERTISED_NETWORKS {
            return Err(format!(
                "At most {} advertised networks are supported",
                MAX_ADVERTISED_NETWORKS
            ));
        }

        for network in &settings.advertised_networks {
            Self::validate_network(network, "Advertised network")?;
        }

        Self::check_range(
            settings.ospf_hello_secs,
            MIN_OSPF_HELLO_SECS,
            MAX_OSPF_HELLO_SECS,
            "OSPF hello interval",
        )?;
        Self::check_range(
            settings.ospf_dead_secs,
            MIN_OSPF_DEAD_SECS,
            MAX_OSPF_DEAD_SECS,
            "OSPF dead interval",
        )?;

        if settings.ospf_dead_secs <= settings.ospf_hello_secs {
            return Err("The OSPF dead interval must be longer than the hello interval".into());
        }

        Ok(())
    }

    pub fn normalize_tunnel(tunnel: &mut OverlayTunnel) {
        tunnel.name = tunnel.name.trim().to_string();
        tunnel.remote_address = Self::canonical_addr(tunnel.remote_address.trim());
        tunnel.auth_method = tunnel.auth_method.trim().to_lowercase();
        tunnel.local_id = Self::clean_optional(tunnel.local_id.take());
        tunnel.remote_id = Self::clean_optional(tunnel.remote_id.take());
        tunnel.comment = Self::clean_optional(tunnel.comment.take());

        tunnel.inner_local = match Ipv4Net::from_str(tunnel.inner_local.trim()) {
            Ok(net) => net.to_string(),
            Err(_) => tunnel.inner_local.trim().to_string(),
        };
        tunnel.inner_remote = Self::canonical_addr(tunnel.inner_remote.trim());

        // The key is not trimmed: that would silently change what the person typed.
        // An empty key means "none sent".
        tunnel.psk = tunnel.psk.take().filter(|p| !p.is_empty());

        // Only the fields of the chosen method are kept.
        match tunnel.auth_method.as_str() {
            "psk" => {
                tunnel.local_cert = None;
                tunnel.local_key = None;
                tunnel.remote_ca = None;
            }
            "cert" => {
                tunnel.psk = None;
                tunnel.local_cert = Self::clean_optional(tunnel.local_cert.take());
                tunnel.local_key = Self::clean_optional(tunnel.local_key.take());
                tunnel.remote_ca = Self::clean_optional(tunnel.remote_ca.take());
            }
            _ => {}
        }
    }

    /// Checks everything except whether a pre-shared key was sent: an update may
    /// leave it out to keep the stored one, so the add and update paths check that.
    pub fn validate_tunnel(tunnel: &OverlayTunnel) -> Result<(), String> {
        Self::check_name(&tunnel.name, "Tunnel name")?;
        Self::check_comment(&tunnel.comment)?;

        let remote = Ipv4Addr::from_str(&tunnel.remote_address).map_err(|_| {
            format!(
                "Remote address '{}' is not a valid IPv4 address",
                tunnel.remote_address
            )
        })?;
        Self::check_host_address(remote, "Remote address", &tunnel.remote_address)?;

        if let Some(id) = &tunnel.local_id {
            Self::check_peer_id(id, "Local ID")?;
        }
        if let Some(id) = &tunnel.remote_id {
            Self::check_peer_id(id, "Remote ID")?;
        }

        if !AUTH_METHODS.contains(&tunnel.auth_method.as_str()) {
            return Err(format!(
                "Authentication method '{}' is not valid (use psk or cert)",
                tunnel.auth_method
            ));
        }

        if tunnel.auth_method == "psk" {
            if let Some(psk) = &tunnel.psk {
                Self::check_psk(psk)?;
            }
        } else {
            Self::check_file_field(&tunnel.local_cert, "Local certificate")?;
            Self::check_file_field(&tunnel.local_key, "Local private key")?;
            Self::check_file_field(&tunnel.remote_ca, "Remote CA certificate")?;
        }

        Self::check_range(tunnel.mtu, MIN_MTU, MAX_MTU, "MTU")?;
        Self::check_range(
            tunnel.dpd_delay_secs,
            MIN_DPD_DELAY_SECS,
            MAX_DPD_DELAY_SECS,
            "Dead peer detection delay",
        )?;
        Self::check_range(tunnel.ospf_cost, MIN_OSPF_COST, MAX_OSPF_COST, "OSPF cost")?;

        let (net, _) = Self::parse_inner(tunnel)?;

        // A peer that is only reachable through its own tunnel can never bring it up.
        if net.contains(&remote) {
            return Err(format!(
                "Remote address {} is inside the tunnel network {} - it must be the peer's WAN address",
                remote,
                net.trunc()
            ));
        }

        Ok(())
    }

    /// Returns the tunnel's own network (with this side's host address kept) and the
    /// other end's address.
    fn parse_inner(tunnel: &OverlayTunnel) -> Result<(Ipv4Net, Ipv4Addr), String> {
        let net = Ipv4Net::from_str(&tunnel.inner_local).map_err(|_| {
            format!(
                "Tunnel address '{}' is not valid (example: 10.255.0.1/30)",
                tunnel.inner_local
            )
        })?;

        if net.prefix_len() < MIN_INNER_PREFIX || net.prefix_len() > MAX_INNER_PREFIX {
            return Err(format!(
                "Tunnel address '{}' must have a prefix between /{} and /{}",
                tunnel.inner_local, MIN_INNER_PREFIX, MAX_INNER_PREFIX
            ));
        }

        let local = net.addr();
        Self::check_host_address(local, "Tunnel address", &tunnel.inner_local)?;
        Self::check_inside_network(&net, local, "Tunnel address", &tunnel.inner_local)?;

        let remote = Ipv4Addr::from_str(&tunnel.inner_remote).map_err(|_| {
            format!(
                "Tunnel peer address '{}' is not a valid IPv4 address",
                tunnel.inner_remote
            )
        })?;
        Self::check_host_address(remote, "Tunnel peer address", &tunnel.inner_remote)?;

        if !net.contains(&remote) {
            return Err(format!(
                "Tunnel peer address {} is not inside the tunnel network {}",
                remote,
                net.trunc()
            ));
        }

        if remote == local {
            return Err("The tunnel peer address cannot be the same as this side's address".into());
        }

        Self::check_inside_network(&net, remote, "Tunnel peer address", &tunnel.inner_remote)?;

        Ok((net, remote))
    }

    /// On a network bigger than a /31 the first and last addresses are not hosts.
    fn check_inside_network(
        net: &Ipv4Net,
        ip: Ipv4Addr,
        label: &str,
        raw: &str,
    ) -> Result<(), String> {
        if net.prefix_len() < 31 && (ip == net.network() || ip == net.broadcast()) {
            return Err(format!(
                "{} '{}' is the network or broadcast address of {}",
                label,
                raw,
                net.trunc()
            ));
        }

        Ok(())
    }

    fn networks_overlap(a: &Ipv4Net, b: &Ipv4Net) -> bool {
        a.contains(&b.network()) || b.contains(&a.network())
    }

    fn validate_network(value: &str, label: &str) -> Result<(), String> {
        let net = Ipv4Net::from_str(value).map_err(|_| {
            format!(
                "{} '{}' is not a valid IPv4 network (example: 192.168.10.0/24)",
                label, value
            )
        })?;

        if net != net.trunc() {
            return Err(format!(
                "{} '{}' has host bits set - did you mean '{}'?",
                label,
                value,
                net.trunc()
            ));
        }

        if net.prefix_len() == 0 {
            return Err(format!("{} '{}' is too broad", label, value));
        }

        Ok(())
    }

    fn check_name(name: &str, label: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err(format!("{} cannot be empty", label));
        }

        if name.chars().count() > MAX_NAME_LEN {
            return Err(format!(
                "{} cannot be longer than {} characters",
                label, MAX_NAME_LEN
            ));
        }

        if name
            .chars()
            .any(|c| c.is_control() || c == '"' || c == '\\')
        {
            return Err(format!("{} contains invalid characters", label));
        }

        Ok(())
    }

    /// The site name ends up in the routing config, so it is kept to a safe set.
    fn check_site_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("Site name cannot be empty".into());
        }

        if name.chars().count() > MAX_SITE_NAME_LEN {
            return Err(format!(
                "Site name cannot be longer than {} characters",
                MAX_SITE_NAME_LEN
            ));
        }

        let valid = name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');

        if !valid || name.starts_with('-') {
            return Err(
                "Site name can only use letters, numbers, '-' and '_', and cannot start with '-'"
                    .into(),
            );
        }

        Ok(())
    }

    fn check_comment(comment: &Option<String>) -> Result<(), String> {
        if let Some(comment) = comment {
            if comment.chars().count() > MAX_COMMENT_LEN {
                return Err(format!(
                    "Comment cannot be longer than {} characters",
                    MAX_COMMENT_LEN
                ));
            }

            if comment.chars().any(|c| c.is_control()) {
                return Err("Comment contains invalid characters".into());
            }
        }

        Ok(())
    }

    fn check_host_address(ip: Ipv4Addr, label: &str, raw: &str) -> Result<(), String> {
        if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast() {
            return Err(format!("{} '{}' is not a usable host address", label, raw));
        }

        Ok(())
    }

    fn check_range(value: i64, min: i64, max: i64, label: &str) -> Result<(), String> {
        if value < min || value > max {
            return Err(format!("{} must be between {} and {}", label, min, max));
        }

        Ok(())
    }

    /// IKE identities: an address, a name like hq.example.com or an @name.
    /// Characters that mean something in the config file are not allowed.
    fn check_peer_id(value: &str, label: &str) -> Result<(), String> {
        if value.chars().count() > MAX_ID_LEN {
            return Err(format!(
                "{} cannot be longer than {} characters",
                label, MAX_ID_LEN
            ));
        }

        let valid = value
            .chars()
            .all(|c| c.is_ascii_graphic() && !"\"'\\#{}=;".contains(c));

        if !valid {
            return Err(format!("{} contains invalid characters", label));
        }

        Ok(())
    }

    /// The key is written into a config file, so it is plain printable text without
    /// quotes or backslashes, and without spaces at either end (usually a paste slip).
    fn check_psk(psk: &str) -> Result<(), String> {
        let len = psk.chars().count();

        if len < MIN_PSK_LEN {
            return Err(format!(
                "The pre-shared key must be at least {} characters",
                MIN_PSK_LEN
            ));
        }

        if len > MAX_PSK_LEN {
            return Err(format!(
                "The pre-shared key cannot be longer than {} characters",
                MAX_PSK_LEN
            ));
        }

        if psk.trim() != psk {
            return Err("The pre-shared key cannot start or end with a space".into());
        }

        let valid = psk
            .chars()
            .all(|c| (c == ' ' || c.is_ascii_graphic()) && c != '"' && c != '\\');

        if !valid {
            return Err(
                "The pre-shared key can only use printable ASCII characters, without quotes or backslashes"
                    .into(),
            );
        }

        Ok(())
    }

    /// Certificate and key are file names inside the certificate folder, never paths.
    fn check_file_field(value: &Option<String>, label: &str) -> Result<(), String> {
        let name = value
            .as_deref()
            .ok_or_else(|| format!("{} is required for certificate authentication", label))?;

        if name.chars().count() > MAX_FILE_NAME_LEN {
            return Err(format!(
                "{} file name cannot be longer than {} characters",
                label, MAX_FILE_NAME_LEN
            ));
        }

        let valid = name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-');

        if !valid || name.starts_with('.') || name.contains("..") {
            return Err(format!(
                "{} must be a plain file name (letters, numbers, '.', '_' and '-')",
                label
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::init::initialize_database;
    use sqlx::sqlite::SqlitePoolOptions;

    const GOOD_PSK: &str = "a-long-enough-secret";

    async fn memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        initialize_database(&pool).await.unwrap();

        sqlx::query("INSERT INTO sdwan_links (name, interface_name) VALUES ('wan1', 'eth0')")
            .execute(&pool)
            .await
            .unwrap();

        pool
    }

    fn tunnel(name: &str) -> OverlayTunnel {
        let mut t: OverlayTunnel = serde_json::from_str(
            r#"{"name":"hq","link_id":1,"remote_address":"203.0.113.10",
                "inner_local":"10.255.0.1/30","inner_remote":"10.255.0.2"}"#,
        )
        .unwrap();

        t.name = name.to_string();
        t.psk = Some(GOOD_PSK.to_string());
        t
    }

    fn cert_tunnel(name: &str) -> OverlayTunnel {
        let mut t = tunnel(name);
        t.auth_method = "cert".into();
        t.psk = None;
        t.local_cert = Some("site.pem".into());
        t.local_key = Some("site.key".into());
        t.remote_ca = Some("ca.pem".into());
        t
    }

    async fn stored_psk(pool: &SqlitePool, id: i64) -> Option<String> {
        OverlayRepository::get_tunnel(pool, id)
            .await
            .unwrap()
            .unwrap()
            .psk
    }

    // ----------------------------------------------------------------- adding

    #[tokio::test]
    async fn a_valid_tunnel_is_stored_and_the_web_view_hides_the_key() {
        let pool = memory_pool().await;

        let id = OverlayService::add_tunnel(&pool, tunnel("hq")).await.unwrap();

        let shown = OverlayService::get_tunnel(&pool, id).await.unwrap();
        assert_eq!(shown.psk, None);
        assert!(shown.psk_set);

        let listed = OverlayService::list_tunnels(&pool).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].psk, None);

        let for_generator = OverlayService::list_tunnels_with_secrets(&pool).await.unwrap();
        assert_eq!(for_generator[0].psk.as_deref(), Some(GOOD_PSK));
    }

    #[tokio::test]
    async fn input_is_cleaned_before_it_is_stored() {
        let pool = memory_pool().await;

        let mut t = tunnel("  hq  ");
        t.remote_address = " 203.0.113.10 ".into();
        t.local_id = Some("   ".into());
        t.comment = Some("  main office ".into());

        let id = OverlayService::add_tunnel(&pool, t).await.unwrap();
        let stored = OverlayService::get_tunnel(&pool, id).await.unwrap();

        assert_eq!(stored.name, "hq");
        assert_eq!(stored.remote_address, "203.0.113.10");
        assert_eq!(stored.local_id, None);
        assert_eq!(stored.comment.as_deref(), Some("main office"));
    }

    #[tokio::test]
    async fn a_psk_tunnel_needs_a_key() {
        let pool = memory_pool().await;

        let mut t = tunnel("hq");
        t.psk = None;
        let err = OverlayService::add_tunnel(&pool, t).await.unwrap_err();
        assert!(err.contains("pre-shared key is required"), "{}", err);

        let mut t = tunnel("hq");
        t.psk = Some(String::new());
        let err = OverlayService::add_tunnel(&pool, t).await.unwrap_err();
        assert!(err.contains("pre-shared key is required"), "{}", err);
    }

    #[tokio::test]
    async fn bad_keys_are_rejected() {
        let pool = memory_pool().await;

        for (psk, expect) in [
            ("short", "at least"),
            ("has-a-\"quote-in-the-key", "quotes"),
            ("has-a-back\\slash-in-key", "quotes"),
            (" leading-space-in-the-key", "start or end"),
            ("trailing-space-in-the-key ", "start or end"),
            ("tab\tinside-the-key-here", "printable"),
        ] {
            let mut t = tunnel("hq");
            t.psk = Some(psk.to_string());
            let err = OverlayService::add_tunnel(&pool, t).await.unwrap_err();
            assert!(err.contains(expect), "{:?} gave {}", psk, err);
        }

        let mut t = tunnel("hq");
        t.psk = Some("x".repeat(MAX_PSK_LEN + 1));
        assert!(OverlayService::add_tunnel(&pool, t).await.is_err());
    }

    #[tokio::test]
    async fn a_certificate_tunnel_needs_all_three_files_and_drops_any_key() {
        let pool = memory_pool().await;

        for missing in ["cert", "key", "ca"] {
            let mut t = cert_tunnel("site-a");
            match missing {
                "cert" => t.local_cert = None,
                "key" => t.local_key = None,
                _ => t.remote_ca = None,
            }
            assert!(OverlayService::add_tunnel(&pool, t).await.is_err(), "{}", missing);
        }

        let mut t = cert_tunnel("site-a");
        t.psk = Some(GOOD_PSK.to_string());
        let id = OverlayService::add_tunnel(&pool, t).await.unwrap();
        assert_eq!(stored_psk(&pool, id).await, None);
    }

    #[tokio::test]
    async fn a_psk_tunnel_drops_certificate_fields() {
        let pool = memory_pool().await;

        let mut t = tunnel("hq");
        t.local_cert = Some("site.pem".into());

        let id = OverlayService::add_tunnel(&pool, t).await.unwrap();
        let stored = OverlayRepository::get_tunnel(&pool, id).await.unwrap().unwrap();
        assert_eq!(stored.local_cert, None);
    }

    #[tokio::test]
    async fn certificate_names_must_be_plain_file_names() {
        let pool = memory_pool().await;

        for bad in ["../etc/passwd", "a/b.pem", "/abs.pem", ".hidden", "a..b.pem", "sp ace.pem"] {
            let mut t = cert_tunnel("site-a");
            t.local_cert = Some(bad.to_string());
            assert!(OverlayService::add_tunnel(&pool, t).await.is_err(), "{}", bad);
        }
    }

    #[tokio::test]
    async fn an_unknown_auth_method_is_rejected() {
        let pool = memory_pool().await;

        let mut t = tunnel("hq");
        t.auth_method = "token".into();
        let err = OverlayService::add_tunnel(&pool, t).await.unwrap_err();
        assert!(err.contains("psk or cert"), "{}", err);
    }

    #[tokio::test]
    async fn an_unknown_wan_link_is_rejected() {
        let pool = memory_pool().await;

        let mut t = tunnel("hq");
        t.link_id = 99;
        let err = OverlayService::add_tunnel(&pool, t).await.unwrap_err();
        assert!(err.contains("WAN link 99 does not exist"), "{}", err);
    }

    #[tokio::test]
    async fn names_and_ids_are_checked() {
        let pool = memory_pool().await;

        assert!(OverlayService::add_tunnel(&pool, tunnel("")).await.is_err());
        assert!(OverlayService::add_tunnel(&pool, tunnel("bad\"name")).await.is_err());
        assert!(OverlayService::add_tunnel(&pool, tunnel(&"n".repeat(MAX_NAME_LEN + 1)))
            .await
            .is_err());

        let mut t = tunnel("hq");
        t.local_id = Some("@site a".into());
        assert!(OverlayService::add_tunnel(&pool, t).await.is_err());

        let mut t = tunnel("hq");
        t.remote_id = Some("x{y}".into());
        assert!(OverlayService::add_tunnel(&pool, t).await.is_err());

        let mut t = tunnel("hq");
        t.local_id = Some("@site-a.example.com".into());
        t.remote_id = Some("hq.example.com".into());
        assert!(OverlayService::add_tunnel(&pool, t).await.is_ok());
    }

    #[tokio::test]
    async fn numeric_limits_are_checked() {
        let pool = memory_pool().await;

        let mut t = tunnel("hq");
        t.mtu = 1279;
        assert!(OverlayService::add_tunnel(&pool, t).await.is_err());

        let mut t = tunnel("hq");
        t.mtu = 1501;
        assert!(OverlayService::add_tunnel(&pool, t).await.is_err());

        let mut t = tunnel("hq");
        t.dpd_delay_secs = 1;
        assert!(OverlayService::add_tunnel(&pool, t).await.is_err());

        let mut t = tunnel("hq");
        t.ospf_cost = 0;
        assert!(OverlayService::add_tunnel(&pool, t).await.is_err());

        let mut t = tunnel("hq");
        t.ospf_cost = 60001;
        assert!(OverlayService::add_tunnel(&pool, t).await.is_err());
    }

    #[tokio::test]
    async fn the_remote_address_must_be_a_usable_ipv4_host() {
        let pool = memory_pool().await;

        for bad in ["", "vpn.example.com", "0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255"] {
            let mut t = tunnel("hq");
            t.remote_address = bad.to_string();
            assert!(OverlayService::add_tunnel(&pool, t).await.is_err(), "{:?}", bad);
        }
    }

    // ---------------------------------------------------------- tunnel address

    #[tokio::test]
    async fn the_tunnel_addresses_must_fit_together() {
        let pool = memory_pool().await;

        let cases = [
            ("10.255.0.1", "10.255.0.2", "valid IPv4 address|not valid"),
            ("10.255.0.1/30", "10.255.0.1", "same as this side"),
            ("10.255.0.1/30", "10.255.0.9", "not inside"),
            ("10.255.0.1/30", "10.255.0.0", "network or broadcast"),
            ("10.255.0.1/30", "10.255.0.3", "network or broadcast"),
            ("10.255.0.0/30", "10.255.0.1", "network or broadcast"),
            ("10.255.0.1/8", "10.255.0.2", "prefix between"),
            ("10.255.0.1/32", "10.255.0.1", "prefix between"),
            ("10.255.0.1/30", "not-an-ip", "not a valid IPv4"),
        ];

        for (local, remote, expect) in cases {
            let mut t = tunnel("hq");
            t.inner_local = local.to_string();
            t.inner_remote = remote.to_string();

            let err = OverlayService::add_tunnel(&pool, t).await.unwrap_err();
            assert!(
                expect.split('|').any(|e| err.contains(e)),
                "{} / {} gave {}",
                local,
                remote,
                err
            );
        }
    }

    #[tokio::test]
    async fn a_slash_31_tunnel_is_allowed() {
        let pool = memory_pool().await;

        let mut t = tunnel("hq");
        t.inner_local = "10.255.0.0/31".into();
        t.inner_remote = "10.255.0.1".into();

        assert!(OverlayService::add_tunnel(&pool, t).await.is_ok());
    }

    #[tokio::test]
    async fn the_peer_wan_address_cannot_be_inside_the_tunnel_network() {
        let pool = memory_pool().await;

        let mut t = tunnel("hq");
        t.remote_address = "10.255.0.2".into();

        let err = OverlayService::add_tunnel(&pool, t).await.unwrap_err();
        assert!(err.contains("peer's WAN address"), "{}", err);
    }

    // -------------------------------------------------------------- duplicates

    #[tokio::test]
    async fn duplicate_names_are_refused_ignoring_case() {
        let pool = memory_pool().await;
        OverlayService::add_tunnel(&pool, tunnel("hq")).await.unwrap();

        let mut other = tunnel("HQ");
        other.inner_local = "10.255.1.1/30".into();
        other.inner_remote = "10.255.1.2".into();
        other.remote_address = "203.0.113.20".into();

        let err = OverlayService::add_tunnel(&pool, other).await.unwrap_err();
        assert!(err.contains("already exists"), "{}", err);
    }

    #[tokio::test]
    async fn the_same_peer_over_the_same_link_is_refused() {
        let pool = memory_pool().await;
        OverlayService::add_tunnel(&pool, tunnel("hq")).await.unwrap();

        let mut other = tunnel("hq-again");
        other.inner_local = "10.255.1.1/30".into();
        other.inner_remote = "10.255.1.2".into();

        let err = OverlayService::add_tunnel(&pool, other).await.unwrap_err();
        assert!(err.contains("already connects"), "{}", err);
    }

    #[tokio::test]
    async fn the_same_peer_over_another_link_is_refused() {
        let pool = memory_pool().await;
        sqlx::query("INSERT INTO sdwan_links (name, interface_name) VALUES ('wan2', 'eth1')")
            .execute(&pool)
            .await
            .unwrap();

        OverlayService::add_tunnel(&pool, tunnel("hq-wan1")).await.unwrap();

        let mut second = tunnel("hq-wan2");
        second.link_id = 2;
        second.inner_local = "10.255.1.1/30".into();
        second.inner_remote = "10.255.1.2".into();

        let err = OverlayService::add_tunnel(&pool, second).await.unwrap_err();
        assert!(err.contains("already connects"), "{}", err);
    }

    #[tokio::test]
    async fn tunnel_networks_cannot_overlap() {
        let pool = memory_pool().await;
        OverlayService::add_tunnel(&pool, tunnel("hq")).await.unwrap();

        // same address
        let mut same = tunnel("b");
        same.remote_address = "203.0.113.20".into();
        let err = OverlayService::add_tunnel(&pool, same).await.unwrap_err();
        assert!(err.contains("already used"), "{}", err);

        // same /30, other host address
        let mut shared = tunnel("c");
        shared.remote_address = "203.0.113.21".into();
        shared.inner_local = "10.255.0.2/30".into();
        shared.inner_remote = "10.255.0.1".into();
        let err = OverlayService::add_tunnel(&pool, shared).await.unwrap_err();
        assert!(err.contains("overlaps"), "{}", err);

        // a bigger network that contains it
        let mut wide = tunnel("d");
        wide.remote_address = "203.0.113.22".into();
        wide.inner_local = "10.255.0.5/24".into();
        wide.inner_remote = "10.255.0.6".into();
        let err = OverlayService::add_tunnel(&pool, wide).await.unwrap_err();
        assert!(err.contains("overlaps"), "{}", err);
    }

    #[tokio::test]
    async fn at_most_max_tunnels_can_be_added() {
        let pool = memory_pool().await;

        for i in 0..MAX_TUNNELS {
            let mut t = tunnel(&format!("t{}", i));
            t.remote_address = format!("203.0.113.{}", i + 1);
            t.inner_local = format!("10.200.{}.1/30", i);
            t.inner_remote = format!("10.200.{}.2", i);
            OverlayService::add_tunnel(&pool, t).await.unwrap();
        }

        let mut extra = tunnel("extra");
        extra.remote_address = "203.0.113.200".into();
        extra.inner_local = "10.201.0.1/30".into();
        extra.inner_remote = "10.201.0.2".into();

        let err = OverlayService::add_tunnel(&pool, extra).await.unwrap_err();
        assert!(err.contains("At most"), "{}", err);
    }

    // ----------------------------------------------------------------- updating

    #[tokio::test]
    async fn an_update_without_a_key_keeps_the_stored_key() {
        let pool = memory_pool().await;
        let id = OverlayService::add_tunnel(&pool, tunnel("hq")).await.unwrap();

        let mut edited = tunnel("hq-renamed");
        edited.psk = None;
        edited.ospf_cost = 50;
        OverlayService::update_tunnel(&pool, id, edited).await.unwrap();

        assert_eq!(stored_psk(&pool, id).await.as_deref(), Some(GOOD_PSK));

        let shown = OverlayService::get_tunnel(&pool, id).await.unwrap();
        assert_eq!(shown.name, "hq-renamed");
        assert_eq!(shown.ospf_cost, 50);
    }

    #[tokio::test]
    async fn an_update_with_a_new_key_replaces_it() {
        let pool = memory_pool().await;
        let id = OverlayService::add_tunnel(&pool, tunnel("hq")).await.unwrap();

        let mut edited = tunnel("hq");
        edited.psk = Some("another-long-secret-1".into());
        OverlayService::update_tunnel(&pool, id, edited).await.unwrap();

        assert_eq!(stored_psk(&pool, id).await.as_deref(), Some("another-long-secret-1"));
    }

    #[tokio::test]
    async fn a_tunnel_can_be_edited_without_clashing_with_itself() {
        let pool = memory_pool().await;
        let id = OverlayService::add_tunnel(&pool, tunnel("hq")).await.unwrap();

        // same name, address and peer as before
        let mut same = tunnel("hq");
        same.psk = None;
        assert!(OverlayService::update_tunnel(&pool, id, same).await.is_ok());
    }

    #[tokio::test]
    async fn switching_to_certificates_clears_the_key() {
        let pool = memory_pool().await;
        let id = OverlayService::add_tunnel(&pool, tunnel("hq")).await.unwrap();

        OverlayService::update_tunnel(&pool, id, cert_tunnel("hq")).await.unwrap();

        assert_eq!(stored_psk(&pool, id).await, None);
    }

    #[tokio::test]
    async fn switching_back_to_psk_needs_a_new_key() {
        let pool = memory_pool().await;
        let id = OverlayService::add_tunnel(&pool, tunnel("hq")).await.unwrap();
        OverlayService::update_tunnel(&pool, id, cert_tunnel("hq")).await.unwrap();

        let mut back = tunnel("hq");
        back.psk = None;
        let err = OverlayService::update_tunnel(&pool, id, back).await.unwrap_err();
        assert!(err.contains("pre-shared key is required"), "{}", err);

        let mut back = tunnel("hq");
        back.psk = Some("brand-new-long-secret".into());
        OverlayService::update_tunnel(&pool, id, back).await.unwrap();
        assert_eq!(stored_psk(&pool, id).await.as_deref(), Some("brand-new-long-secret"));
    }

    #[tokio::test]
    async fn updating_into_another_tunnels_name_or_network_is_refused() {
        let pool = memory_pool().await;
        OverlayService::add_tunnel(&pool, tunnel("hq")).await.unwrap();

        let mut second = tunnel("branch");
        second.remote_address = "203.0.113.20".into();
        second.inner_local = "10.255.1.1/30".into();
        second.inner_remote = "10.255.1.2".into();
        let id = OverlayService::add_tunnel(&pool, second).await.unwrap();

        let mut rename = tunnel("hq");
        rename.remote_address = "203.0.113.20".into();
        rename.inner_local = "10.255.1.1/30".into();
        rename.inner_remote = "10.255.1.2".into();
        rename.psk = None;
        assert!(OverlayService::update_tunnel(&pool, id, rename).await.is_err());

        let mut renumber = tunnel("branch");
        renumber.remote_address = "203.0.113.20".into();
        renumber.psk = None;
        let err = OverlayService::update_tunnel(&pool, id, renumber).await.unwrap_err();
        assert!(err.contains("already used"), "{}", err);
    }

    #[tokio::test]
    async fn updating_or_deleting_a_missing_tunnel_says_so() {
        let pool = memory_pool().await;

        let err = OverlayService::update_tunnel(&pool, 42, tunnel("hq")).await.unwrap_err();
        assert!(err.contains("does not exist"), "{}", err);

        let err = OverlayService::delete_tunnel(&pool, 42).await.unwrap_err();
        assert!(err.contains("does not exist"), "{}", err);

        let err = OverlayService::get_tunnel(&pool, 42).await.unwrap_err();
        assert!(err.contains("does not exist"), "{}", err);
    }

    #[tokio::test]
    async fn a_deleted_tunnel_is_gone() {
        let pool = memory_pool().await;
        let id = OverlayService::add_tunnel(&pool, tunnel("hq")).await.unwrap();

        OverlayService::delete_tunnel(&pool, id).await.unwrap();

        assert!(OverlayService::list_tunnels(&pool).await.unwrap().is_empty());
    }

    // ----------------------------------------------------------------- settings

    #[test]
    fn settings_are_cleaned() {
        let mut s = OverlaySettings::default();
        s.site_name = "  branch-1 ".into();
        s.router_id = Some(" 10.0.0.1 ".into());
        s.advertised_networks = vec![
            " 192.168.10.0/24 ".into(),
            "".into(),
            "192.168.10.0/24".into(),
            "192.168.20.0/24".into(),
        ];

        OverlayService::normalize_settings(&mut s);

        assert_eq!(s.site_name, "branch-1");
        assert_eq!(s.router_id.as_deref(), Some("10.0.0.1"));
        assert_eq!(s.advertised_networks, vec!["192.168.10.0/24", "192.168.20.0/24"]);
        assert!(OverlayService::validate_settings(&s).is_ok());
    }

    #[test]
    fn bad_settings_are_rejected() {
        let ok = OverlaySettings::default();
        assert!(OverlayService::validate_settings(&ok).is_ok());

        let mut s = ok.clone();
        s.site_name = String::new();
        assert!(OverlayService::validate_settings(&s).is_err());

        let mut s = ok.clone();
        s.site_name = "bad name".into();
        assert!(OverlayService::validate_settings(&s).is_err());

        let mut s = ok.clone();
        s.site_name = "-start".into();
        assert!(OverlayService::validate_settings(&s).is_err());

        let mut s = ok.clone();
        s.router_id = Some("not-an-ip".into());
        assert!(OverlayService::validate_settings(&s).is_err());

        let mut s = ok.clone();
        s.router_id = Some("0.0.0.0".into());
        assert!(OverlayService::validate_settings(&s).is_err());

        let mut s = ok.clone();
        s.ospf_area = "backbone".into();
        assert!(OverlayService::validate_settings(&s).is_err());

        let mut s = ok.clone();
        s.advertised_networks = vec!["192.168.10.5/24".into()];
        let err = OverlayService::validate_settings(&s).unwrap_err();
        assert!(err.contains("192.168.10.0/24"), "{}", err);

        let mut s = ok.clone();
        s.advertised_networks = vec!["0.0.0.0/0".into()];
        assert!(OverlayService::validate_settings(&s).is_err());

        let mut s = ok.clone();
        s.advertised_networks = (0..=MAX_ADVERTISED_NETWORKS)
            .map(|i| format!("10.{}.0.0/24", i))
            .collect();
        assert!(OverlayService::validate_settings(&s).is_err());

        let mut s = ok.clone();
        s.ospf_hello_secs = 10;
        s.ospf_dead_secs = 10;
        let err = OverlayService::validate_settings(&s).unwrap_err();
        assert!(err.contains("longer than the hello"), "{}", err);

        let mut s = ok.clone();
        s.ospf_hello_secs = 0;
        assert!(OverlayService::validate_settings(&s).is_err());

        let mut s = ok;
        s.ospf_dead_secs = 241;
        assert!(OverlayService::validate_settings(&s).is_err());
    }

    #[tokio::test]
    async fn settings_round_trip() {
        let pool = memory_pool().await;

        let mut s = OverlaySettings::default();
        s.site_name = "branch-1".into();
        s.router_id = Some("10.0.0.1".into());
        s.advertised_networks = vec!["192.168.10.0/24".into()];
        OverlayService::save_settings(&pool, s.clone()).await.unwrap();

        assert_eq!(OverlayService::get_settings(&pool).await.unwrap(), s);
    }

    #[tokio::test]
    async fn the_overlay_cannot_be_switched_on_without_a_router_id_and_a_tunnel() {
        let pool = memory_pool().await;

        let err = OverlayService::set_enabled(&pool, true).await.unwrap_err();
        assert!(err.contains("router ID"), "{}", err);

        let mut s = OverlayService::get_settings(&pool).await.unwrap();
        s.router_id = Some("10.0.0.1".into());
        OverlayService::save_settings(&pool, s).await.unwrap();

        let err = OverlayService::set_enabled(&pool, true).await.unwrap_err();
        assert!(err.contains("enabled tunnel"), "{}", err);

        // a disabled tunnel does not count
        let mut off = tunnel("hq");
        off.enabled = false;
        OverlayService::add_tunnel(&pool, off).await.unwrap();
        assert!(OverlayService::set_enabled(&pool, true).await.is_err());

        let mut on = tunnel("branch");
        on.remote_address = "203.0.113.20".into();
        on.inner_local = "10.255.1.1/30".into();
        on.inner_remote = "10.255.1.2".into();
        OverlayService::add_tunnel(&pool, on).await.unwrap();

        OverlayService::set_enabled(&pool, true).await.unwrap();
        assert!(OverlayService::get_settings(&pool).await.unwrap().enabled);

        OverlayService::set_enabled(&pool, false).await.unwrap();
        assert!(!OverlayService::get_settings(&pool).await.unwrap().enabled);
    }

    #[tokio::test]
    async fn switching_off_is_always_allowed() {
        let pool = memory_pool().await;

        assert!(OverlayService::set_enabled(&pool, false).await.is_ok());
    }
}
