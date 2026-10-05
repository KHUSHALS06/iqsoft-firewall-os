use crate::models::wireguard::{
    WireguardConfig, WireguardConfigUpdate, WireguardConfigView, WireguardPeer,
    WireguardPeerCreated, WireguardPeerInput, WireguardPeerView,
};
use crate::repository::network_config_repository::NetworkConfigRepository;
use crate::repository::wireguard_repository::WireguardRepository;
use ipnet::IpNet;
use sqlx::SqlitePool;
use std::net::IpAddr;
use std::process::Stdio;
use tokio::{io::AsyncWriteExt, process::Command};

const KEY_TAIL_CHARS: &str = "AEIMQUYcgkosw048";
const MAX_AUTO_ASSIGN_SCAN: usize = 100_000;
const CLIENT_KEEPALIVE_SECONDS: i32 = 25;

pub struct WireguardService;

impl WireguardService {
    pub async fn get_config(pool: &SqlitePool) -> Result<WireguardConfigView, String> {
        Self::load_config(pool).await.map(WireguardConfigView::from)
    }

    pub async fn set_config(
        pool: &SqlitePool,
        update: WireguardConfigUpdate,
    ) -> Result<WireguardConfigView, String> {
        let current = Self::load_config(pool).await?;
        let peers = Self::load_peers(pool).await?;
        let network = NetworkConfigRepository::get(pool)
            .await
            .map_err(|e| e.to_string())?;

        let regenerate = update.regenerate_keys;

        let dns = match Self::normalize_optional(update.dns) {
            Some(value) => Some(Self::normalize_dns(&value)?),
            None => None,
        };

        let mut config = WireguardConfig {
            enabled: update.enabled,
            interface_name: update.interface_name.trim().to_string(),
            listen_port: update.listen_port,
            address: Self::normalize_address(&update.address)?,
            mtu: update.mtu,
            dns,
            endpoint: Self::normalize_optional(update.endpoint),
            client_allowed_ips: Self::normalize_net_list(&update.client_allowed_ips)?,
            private_key: current.private_key.clone(),
            public_key: current.public_key.clone(),
        };

        if config.interface_name == network.wan_interface.trim()
            || config.interface_name == network.lan_interface.trim()
        {
            return Err(format!(
                "'{}' is already used as the WAN or LAN interface, choose another WireGuard interface name",
                config.interface_name
            ));
        }

        if regenerate || config.private_key.is_empty() || config.public_key.is_empty() {
            let (private_key, public_key) = Self::generate_keypair().await?;
            config.private_key = private_key;
            config.public_key = public_key;
        }

        Self::validate_config(&config)?;

        let server_addr = Self::parse_server_address(&config.address)?.addr();
        for peer in &peers {
            for item in &peer.allowed_ips {
                if let Ok(net) = Self::parse_net(item) {
                    if net.contains(&server_addr) {
                        return Err(format!(
                            "Peer '{}' has allowed IP {} which would contain the new tunnel address {}",
                            peer.name, item, server_addr
                        ));
                    }
                }
            }
        }

        WireguardRepository::set_config(pool, &config)
            .await
            .map_err(|e| e.to_string())?;

        Ok(WireguardConfigView::from(config))
    }

    pub async fn list_peers(pool: &SqlitePool) -> Result<Vec<WireguardPeerView>, String> {
        Ok(Self::load_peers(pool)
            .await?
            .into_iter()
            .map(WireguardPeerView::from)
            .collect())
    }

    pub async fn add_peer(
        pool: &SqlitePool,
        input: WireguardPeerInput,
    ) -> Result<WireguardPeerCreated, String> {
        let config = Self::load_config(pool).await?;
        let existing = Self::load_peers(pool).await?;

        let (mut peer, client_config) =
            Self::prepare_peer(&config, &existing, input, None).await?;

        let id = WireguardRepository::add_peer(pool, &peer)
            .await
            .map_err(Self::map_write_error)?;
        peer.id = Some(id);

        Ok(WireguardPeerCreated {
            peer: WireguardPeerView::from(peer),
            client_config,
        })
    }

    pub async fn update_peer(
        pool: &SqlitePool,
        id: i64,
        input: WireguardPeerInput,
    ) -> Result<WireguardPeerCreated, String> {
        let config = Self::load_config(pool).await?;
        let existing = Self::load_peers(pool).await?;

        let current = existing
            .iter()
            .find(|p| p.id == Some(id))
            .cloned()
            .ok_or_else(|| "WireGuard peer not found".to_string())?;

        let (peer, client_config) =
            Self::prepare_peer(&config, &existing, input, Some(&current)).await?;

        WireguardRepository::update_peer(pool, id, &peer)
            .await
            .map_err(Self::map_write_error)?;

        Ok(WireguardPeerCreated {
            peer: WireguardPeerView::from(peer),
            client_config,
        })
    }

    pub async fn delete_peer(pool: &SqlitePool, id: i64) -> Result<(), String> {
        WireguardRepository::delete_peer(pool, id)
            .await
            .map_err(Self::map_write_error)
    }

    pub fn validate_config(config: &WireguardConfig) -> Result<(), String> {
        Self::validate_interface_name(&config.interface_name)?;

        if !(1..=65535).contains(&config.listen_port) {
            return Err("WireGuard listen port must be between 1 and 65535".into());
        }

        Self::parse_server_address(&config.address)?;

        if let Some(mtu) = config.mtu {
            if !(1280..=1500).contains(&mtu) {
                return Err("WireGuard MTU must be between 1280 and 1500".into());
            }
        }

        if let Some(dns) = &config.dns {
            Self::normalize_dns(dns)?;
        }

        if let Some(endpoint) = &config.endpoint {
            Self::validate_host(endpoint).map_err(|_| {
                format!(
                    "Invalid endpoint '{}': use a host name or IP address without a port",
                    endpoint
                )
            })?;
        }

        if config.client_allowed_ips.is_empty() {
            return Err("At least one client allowed IP network is required".into());
        }
        for item in &config.client_allowed_ips {
            Self::parse_net(item)?;
        }

        if !Self::is_valid_key(&config.private_key) {
            return Err("WireGuard server private key is missing or invalid".into());
        }
        if !Self::is_valid_key(&config.public_key) {
            return Err("WireGuard server public key is missing or invalid".into());
        }

        Ok(())
    }

    pub fn validate_peer(peer: &WireguardPeer, config: &WireguardConfig) -> Result<(), String> {
        Self::validate_peer_name(&peer.name)?;

        if !Self::is_valid_key(&peer.public_key) {
            return Err(format!(
                "Peer '{}' has an invalid public key",
                peer.name
            ));
        }

        if peer.public_key == config.public_key {
            return Err("A peer cannot use the public key of this firewall".into());
        }

        if let Some(psk) = &peer.preshared_key {
            if !Self::is_valid_key(psk) {
                return Err(format!(
                    "Peer '{}' has an invalid preshared key",
                    peer.name
                ));
            }
        }

        if peer.allowed_ips.is_empty() {
            return Err(format!(
                "Peer '{}' needs at least one allowed IP",
                peer.name
            ));
        }

        let server_addr = Self::parse_server_address(&config.address)?.addr();
        let mut seen: Vec<IpNet> = Vec::new();

        for item in &peer.allowed_ips {
            let net = Self::parse_net(item)?;

            if net.prefix_len() == 0 {
                return Err(
                    "A peer cannot be allowed 0.0.0.0/0 or ::/0, use specific networks".into(),
                );
            }

            if net.contains(&server_addr) {
                return Err(format!(
                    "Allowed IP {} contains the tunnel address of this firewall",
                    item
                ));
            }

            if seen.iter().any(|other| Self::overlaps(other, &net)) {
                return Err(format!(
                    "Allowed IP {} overlaps another allowed IP of the same peer",
                    item
                ));
            }

            seen.push(net);
        }

        if let Some(endpoint) = &peer.endpoint {
            Self::validate_peer_endpoint(endpoint)?;
        }

        if !(0..=65535).contains(&peer.persistent_keepalive) {
            return Err("Persistent keepalive must be between 0 and 65535 seconds".into());
        }

        if let Some(comment) = &peer.comment {
            if comment.len() > 200 || comment.chars().any(|c| c.is_control()) {
                return Err(
                    "Peer comment must be at most 200 characters with no control characters"
                        .into(),
                );
            }
        }

        Ok(())
    }

    pub fn is_valid_key(key: &str) -> bool {
        let bytes = key.as_bytes();

        if bytes.len() != 44 || bytes[43] != b'=' {
            return false;
        }

        if !KEY_TAIL_CHARS.contains(bytes[42] as char) {
            return false;
        }

        bytes[..43]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
    }

    pub async fn generate_keypair() -> Result<(String, String), String> {
        let private_key = Self::run_wg(&["genkey"], None).await?;
        let public_key = Self::run_wg(&["pubkey"], Some(&private_key)).await?;
        Ok((private_key, public_key))
    }

    pub async fn generate_preshared_key() -> Result<String, String> {
        Self::run_wg(&["genpsk"], None).await
    }

    async fn run_wg(args: &[&str], input: Option<&str>) -> Result<String, String> {
        let mut child = Command::new("wg")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Could not run wg (is wireguard-tools installed?): {}", e))?;

        if let Some(mut stdin) = child.stdin.take() {
            if let Some(data) = input {
                stdin
                    .write_all(data.as_bytes())
                    .await
                    .map_err(|e| format!("Could not write to wg: {}", e))?;
                stdin
                    .write_all(b"\n")
                    .await
                    .map_err(|e| format!("Could not write to wg: {}", e))?;
            }
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| format!("Could not run wg: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "wg {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        let text = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if !Self::is_valid_key(&text) {
            return Err("wg returned an invalid key".into());
        }

        Ok(text)
    }

    async fn prepare_peer(
        config: &WireguardConfig,
        others: &[WireguardPeer],
        input: WireguardPeerInput,
        current: Option<&WireguardPeer>,
    ) -> Result<(WireguardPeer, Option<String>), String> {
        let mut allowed_ips = Self::normalize_net_list(&input.allowed_ips)?;

        if allowed_ips.is_empty() {
            match current {
                Some(existing) => allowed_ips = existing.allowed_ips.clone(),
                None => {
                    if input.generate_keys {
                        allowed_ips = vec![Self::next_free_address(config, others)?];
                    }
                }
            }
        }

        let supplied_key = input
            .public_key
            .as_deref()
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .map(str::to_string);

        let (public_key, private_key, preshared_key) = if input.generate_keys {
            if supplied_key.is_some() {
                return Err("Use either generate_keys or public_key, not both".into());
            }

            if config.endpoint.is_none() {
                return Err(
                    "Set the server endpoint before generating client keys, the client config needs it"
                        .into(),
                );
            }

            let (private_key, public_key) = Self::generate_keypair().await?;

            let preshared = if input.use_preshared_key {
                Some(Self::generate_preshared_key().await?)
            } else {
                None
            };

            (public_key, Some(private_key), preshared)
        } else {
            if input.use_preshared_key {
                return Err(
                    "use_preshared_key requires generate_keys, because the server hands the key to the client inside the generated config"
                        .into(),
                );
            }

            let public_key = match supplied_key {
                Some(key) => key,
                None => match current {
                    Some(existing) => existing.public_key.clone(),
                    None => {
                        return Err("public_key is required unless generate_keys is true".into())
                    }
                },
            };

            (
                public_key,
                None,
                current.and_then(|existing| existing.preshared_key.clone()),
            )
        };

        let peer = WireguardPeer {
            id: current.and_then(|existing| existing.id),
            name: input.name.trim().to_string(),
            enabled: input.enabled,
            public_key,
            preshared_key,
            allowed_ips,
            endpoint: Self::normalize_optional(input.endpoint),
            persistent_keepalive: input.persistent_keepalive,
            comment: Self::normalize_optional(input.comment),
        };

        Self::validate_peer(&peer, config)?;
        Self::check_unique(&peer, others)?;
        Self::check_overlap_with_others(&peer, others)?;

        let client_config = match private_key {
            Some(key) => Some(Self::build_client_config(config, &key, &peer)?),
            None => None,
        };

        Ok((peer, client_config))
    }

    fn check_unique(peer: &WireguardPeer, others: &[WireguardPeer]) -> Result<(), String> {
        for other in others {
            if peer.id.is_some() && other.id == peer.id {
                continue;
            }

            if other.name.eq_ignore_ascii_case(&peer.name) {
                return Err(format!("A peer named '{}' already exists", peer.name));
            }

            if other.public_key == peer.public_key {
                return Err("A peer with this public key already exists".into());
            }
        }

        Ok(())
    }

    fn check_overlap_with_others(
        peer: &WireguardPeer,
        others: &[WireguardPeer],
    ) -> Result<(), String> {
        for other in others {
            if peer.id.is_some() && other.id == peer.id {
                continue;
            }

            for mine in &peer.allowed_ips {
                let mine_net = Self::parse_net(mine)?;

                for theirs in &other.allowed_ips {
                    if let Ok(theirs_net) = Self::parse_net(theirs) {
                        if Self::overlaps(&mine_net, &theirs_net) {
                            return Err(format!(
                                "Allowed IP {} overlaps {} of peer '{}'",
                                mine, theirs, other.name
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn next_free_address(
        config: &WireguardConfig,
        others: &[WireguardPeer],
    ) -> Result<String, String> {
        let net = Self::parse_server_address(&config.address)?;

        if !net.addr().is_ipv4() {
            return Err(
                "Automatic address assignment supports IPv4 tunnels only, set allowed_ips explicitly"
                    .into(),
            );
        }

        let server = net.addr();
        let taken: Vec<IpNet> = others
            .iter()
            .flat_map(|peer| peer.allowed_ips.iter())
            .filter_map(|value| Self::parse_net(value).ok())
            .collect();

        for candidate in net.trunc().hosts().take(MAX_AUTO_ASSIGN_SCAN) {
            if candidate == server {
                continue;
            }

            if taken.iter().any(|existing| existing.contains(&candidate)) {
                continue;
            }

            return Ok(format!("{}/32", candidate));
        }

        Err("No free address is left in the tunnel subnet".into())
    }

    fn build_client_config(
        config: &WireguardConfig,
        private_key: &str,
        peer: &WireguardPeer,
    ) -> Result<String, String> {
        let first = peer
            .allowed_ips
            .first()
            .ok_or_else(|| "Peer has no allowed IP to use as the client address".to_string())?;
        let net = Self::parse_net(first)?;

        let host_prefix = if net.addr().is_ipv4() { 32 } else { 128 };
        if net.prefix_len() != host_prefix {
            return Err(
                "The first allowed IP of a generated client must be a single address (/32 or /128), it becomes the client's tunnel address"
                    .into(),
            );
        }

        let host = config
            .endpoint
            .as_deref()
            .ok_or_else(|| "Server endpoint is not set".to_string())?;

        let endpoint = match host.parse::<IpAddr>() {
            Ok(IpAddr::V6(_)) => format!("[{}]:{}", host, config.listen_port),
            _ => format!("{}:{}", host, config.listen_port),
        };

        let mut out = String::new();
        out.push_str("[Interface]\n");
        out.push_str(&format!("PrivateKey = {}\n", private_key));
        out.push_str(&format!("Address = {}\n", net));

        if let Some(dns) = &config.dns {
            out.push_str(&format!("DNS = {}\n", dns.replace(',', ", ")));
        }

        if let Some(mtu) = config.mtu {
            out.push_str(&format!("MTU = {}\n", mtu));
        }

        out.push('\n');
        out.push_str("[Peer]\n");
        out.push_str(&format!("PublicKey = {}\n", config.public_key));

        if let Some(psk) = &peer.preshared_key {
            out.push_str(&format!("PresharedKey = {}\n", psk));
        }

        out.push_str(&format!(
            "AllowedIPs = {}\n",
            config.client_allowed_ips.join(", ")
        ));
        out.push_str(&format!("Endpoint = {}\n", endpoint));
        out.push_str(&format!(
            "PersistentKeepalive = {}\n",
            CLIENT_KEEPALIVE_SECONDS
        ));

        Ok(out)
    }

    fn validate_interface_name(name: &str) -> Result<(), String> {
        let valid = !name.is_empty()
            && name.len() <= 15
            && name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');

        if !valid {
            return Err(format!(
                "Invalid interface name '{}': use 1-15 letters, digits, '_' or '-', starting with a letter",
                name
            ));
        }

        Ok(())
    }

    fn validate_peer_name(name: &str) -> Result<(), String> {
        let name = name.trim();

        if name.is_empty() || name.len() > 64 {
            return Err("Peer name must be 1-64 characters".into());
        }

        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.'))
        {
            return Err(
                "Peer name may only contain letters, digits, spaces, '_', '-' and '.'".into(),
            );
        }

        Ok(())
    }

    fn parse_server_address(value: &str) -> Result<IpNet, String> {
        let invalid = || {
            format!(
                "Invalid tunnel address '{}': use CIDR notation such as 10.8.0.1/24",
                value.trim()
            )
        };

        let net: IpNet = value.trim().parse().map_err(|_| invalid())?;
        let addr = net.addr();

        if addr.is_unspecified() || addr.is_loopback() || addr.is_multicast() {
            return Err(invalid());
        }

        let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
        if net.prefix_len() > max_prefix - 2 {
            return Err(format!(
                "Tunnel subnet in '{}' is too small, use a prefix that leaves room for peers",
                value.trim()
            ));
        }

        if addr == net.network() || addr == net.broadcast() {
            return Err(format!(
                "Tunnel address '{}' is the network or broadcast address, use a host address",
                value.trim()
            ));
        }

        Ok(net)
    }

    fn normalize_address(value: &str) -> Result<String, String> {
        Ok(Self::parse_server_address(value)?.to_string())
    }

    fn parse_net(value: &str) -> Result<IpNet, String> {
        let value = value.trim();

        if let Ok(addr) = value.parse::<IpAddr>() {
            return Ok(IpNet::from(addr));
        }

        value
            .parse::<IpNet>()
            .map(|net| net.trunc())
            .map_err(|_| {
                format!(
                    "Invalid network '{}': use CIDR notation such as 10.8.0.2/32",
                    value
                )
            })
    }

    fn normalize_net_list(values: &[String]) -> Result<Vec<String>, String> {
        let mut nets: Vec<IpNet> = Vec::new();

        for value in values {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                continue;
            }

            let net = Self::parse_net(trimmed)?;

            if nets.contains(&net) {
                return Err(format!("Duplicate network '{}'", net));
            }

            nets.push(net);
        }

        Ok(nets.into_iter().map(|net| net.to_string()).collect())
    }

    fn normalize_dns(value: &str) -> Result<String, String> {
        let mut servers: Vec<String> = Vec::new();

        for part in value.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let addr: IpAddr = part
                .parse()
                .map_err(|_| format!("Invalid DNS server '{}': use an IP address", part))?;
            servers.push(addr.to_string());
        }

        if servers.is_empty() {
            return Err("DNS must contain at least one IP address".into());
        }

        Ok(servers.join(","))
    }

    fn validate_host(value: &str) -> Result<(), String> {
        let value = value.trim();
        let invalid = || format!("Invalid host '{}'", value);

        if value.is_empty() || value.len() > 253 {
            return Err(invalid());
        }

        if value.parse::<IpAddr>().is_ok() {
            return Ok(());
        }

        let labels_ok = value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });

        if labels_ok {
            Ok(())
        } else {
            Err(invalid())
        }
    }

    fn validate_peer_endpoint(value: &str) -> Result<(), String> {
        let invalid = || {
            format!(
                "Invalid peer endpoint '{}': use host:port, with [brackets] around IPv6 addresses",
                value.trim()
            )
        };

        let (raw_host, raw_port) = value.trim().rsplit_once(':').ok_or_else(invalid)?;

        let host = if raw_host.contains(':') {
            raw_host
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .ok_or_else(invalid)?
        } else {
            raw_host
        };

        let port: u16 = raw_port.parse().map_err(|_| invalid())?;
        if port == 0 {
            return Err(invalid());
        }

        Self::validate_host(host).map_err(|_| invalid())
    }

    fn overlaps(a: &IpNet, b: &IpNet) -> bool {
        a.contains(b) || b.contains(a)
    }

    fn normalize_optional(value: Option<String>) -> Option<String> {
        value
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    async fn load_config(pool: &SqlitePool) -> Result<WireguardConfig, String> {
        WireguardRepository::get_config(pool)
            .await
            .map_err(|e| e.to_string())
    }

    async fn load_peers(pool: &SqlitePool) -> Result<Vec<WireguardPeer>, String> {
        WireguardRepository::list_peers(pool)
            .await
            .map_err(|e| e.to_string())
    }

    fn map_write_error(error: sqlx::Error) -> String {
        if matches!(error, sqlx::Error::RowNotFound) {
            return "WireGuard peer not found".into();
        }

        let message = error.to_string();

        if message.contains("wireguard_peers.public_key") {
            return "A peer with this public key already exists".into();
        }

        if message.contains("wireguard_peers.name") {
            return "A peer with this name already exists".into();
        }

        message
    }
}

#[cfg(test)]
mod tests {
    use super::WireguardService;
    use crate::models::wireguard::{WireguardConfig, WireguardPeer};

    const SERVER_PUB: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const PEER_PUB: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    const PEER_PUB_2: &str = "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=";
    const PSK: &str = "jrcCyG6FRMkS4vJhpyVWjYoV6lqVEkyr1jPlyJ0uAmw=";

    fn config() -> WireguardConfig {
        WireguardConfig {
            enabled: true,
            interface_name: "wg0".into(),
            listen_port: 51820,
            address: "10.8.0.1/24".into(),
            mtu: None,
            dns: Some("1.1.1.1,8.8.8.8".into()),
            endpoint: Some("vpn.example.com".into()),
            client_allowed_ips: vec!["0.0.0.0/0".into(), "::/0".into()],
            private_key: PEER_PUB_2.into(),
            public_key: SERVER_PUB.into(),
        }
    }

    fn peer(id: i64, name: &str, key: &str, ips: &[&str]) -> WireguardPeer {
        WireguardPeer {
            id: Some(id),
            name: name.into(),
            enabled: true,
            public_key: key.into(),
            preshared_key: None,
            allowed_ips: ips.iter().map(|s| s.to_string()).collect(),
            endpoint: None,
            persistent_keepalive: 0,
            comment: None,
        }
    }

    #[test]
    fn key_format_accepts_real_keys_and_rejects_bad_ones() {
        assert!(WireguardService::is_valid_key(SERVER_PUB));
        assert!(WireguardService::is_valid_key(PEER_PUB));
        assert!(WireguardService::is_valid_key(PSK));
        assert!(!WireguardService::is_valid_key(""));
        assert!(!WireguardService::is_valid_key("short"));
        assert!(!WireguardService::is_valid_key(
            "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmj="
        ));
        assert!(!WireguardService::is_valid_key(
            "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk "
        ));
        assert!(!WireguardService::is_valid_key(
            "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fB\nk="
        ));
        assert!(!WireguardService::is_valid_key(
            "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmkk"
        ));
    }

    #[test]
    fn server_address_rules() {
        assert!(WireguardService::normalize_address("10.8.0.1/24").is_ok());
        assert!(WireguardService::normalize_address("fd00:8::1/64").is_ok());
        assert!(WireguardService::normalize_address("10.8.0.0/24").is_err());
        assert!(WireguardService::normalize_address("10.8.0.255/24").is_err());
        assert!(WireguardService::normalize_address("10.8.0.1/32").is_err());
        assert!(WireguardService::normalize_address("10.8.0.1/31").is_err());
        assert!(WireguardService::normalize_address("127.0.0.1/8").is_err());
        assert!(WireguardService::normalize_address("0.0.0.0/0").is_err());
        assert!(WireguardService::normalize_address("10.8.0.1").is_err());
        assert!(WireguardService::normalize_address("abc").is_err());
    }

    #[test]
    fn net_list_normalizes_and_rejects_duplicates() {
        let out = WireguardService::normalize_net_list(&[
            "10.8.0.5/24".to_string(),
            " 192.168.5.7 ".to_string(),
            "".to_string(),
        ])
        .unwrap();
        assert_eq!(out, vec!["10.8.0.0/24", "192.168.5.7/32"]);

        assert!(WireguardService::normalize_net_list(&[
            "10.8.0.2/32".to_string(),
            "10.8.0.2".to_string()
        ])
        .is_err());
        assert!(WireguardService::normalize_net_list(&["nope".to_string()]).is_err());
        assert!(WireguardService::normalize_net_list(&["10.0.0.0/33".to_string()]).is_err());
        assert!(WireguardService::normalize_net_list(&[]).unwrap().is_empty());
    }

    #[test]
    fn dns_normalizes() {
        assert_eq!(
            WireguardService::normalize_dns(" 1.1.1.1 , 8.8.8.8,").unwrap(),
            "1.1.1.1,8.8.8.8"
        );
        assert!(WireguardService::normalize_dns("dns.example.com").is_err());
        assert!(WireguardService::normalize_dns(" , ").is_err());
    }

    #[test]
    fn host_and_peer_endpoint_rules() {
        assert!(WireguardService::validate_host("vpn.example.com").is_ok());
        assert!(WireguardService::validate_host("203.0.113.5").is_ok());
        assert!(WireguardService::validate_host("2001:db8::1").is_ok());
        assert!(WireguardService::validate_host("vpn.example.com:51820").is_err());
        assert!(WireguardService::validate_host("bad host").is_err());
        assert!(WireguardService::validate_host("-bad.example.com").is_err());
        assert!(WireguardService::validate_host("a\nb").is_err());
        assert!(WireguardService::validate_host("").is_err());

        assert!(WireguardService::validate_peer_endpoint("vpn.example.com:51820").is_ok());
        assert!(WireguardService::validate_peer_endpoint("203.0.113.5:51820").is_ok());
        assert!(WireguardService::validate_peer_endpoint("[2001:db8::1]:51820").is_ok());
        assert!(WireguardService::validate_peer_endpoint("2001:db8::1:51820").is_err());
        assert!(WireguardService::validate_peer_endpoint("vpn.example.com").is_err());
        assert!(WireguardService::validate_peer_endpoint("vpn.example.com:0").is_err());
        assert!(WireguardService::validate_peer_endpoint("vpn.example.com:70000").is_err());
        assert!(WireguardService::validate_peer_endpoint("a b:51820").is_err());
    }

    #[test]
    fn interface_name_rules() {
        assert!(WireguardService::validate_interface_name("wg0").is_ok());
        assert!(WireguardService::validate_interface_name("wg-office_1").is_ok());
        assert!(WireguardService::validate_interface_name("").is_err());
        assert!(WireguardService::validate_interface_name("0wg").is_err());
        assert!(WireguardService::validate_interface_name("wg 0").is_err());
        assert!(WireguardService::validate_interface_name("wg0/../x").is_err());
        assert!(WireguardService::validate_interface_name("abcdefghijklmnop").is_err());
    }

    #[test]
    fn config_validation_covers_ports_mtu_and_keys() {
        assert!(WireguardService::validate_config(&config()).is_ok());

        let mut bad = config();
        bad.listen_port = 0;
        assert!(WireguardService::validate_config(&bad).is_err());

        let mut bad = config();
        bad.listen_port = 70000;
        assert!(WireguardService::validate_config(&bad).is_err());

        let mut bad = config();
        bad.mtu = Some(100);
        assert!(WireguardService::validate_config(&bad).is_err());

        let mut bad = config();
        bad.private_key = String::new();
        assert!(WireguardService::validate_config(&bad).is_err());

        let mut bad = config();
        bad.endpoint = Some("vpn.example.com:51820".into());
        assert!(WireguardService::validate_config(&bad).is_err());

        let mut bad = config();
        bad.client_allowed_ips = vec![];
        assert!(WireguardService::validate_config(&bad).is_err());
    }

    #[test]
    fn peer_validation_rules() {
        let cfg = config();

        let good = peer(1, "laptop", PEER_PUB, &["10.8.0.2/32"]);
        assert!(WireguardService::validate_peer(&good, &cfg).is_ok());

        let default_route = peer(1, "laptop", PEER_PUB, &["0.0.0.0/0"]);
        assert!(WireguardService::validate_peer(&default_route, &cfg).is_err());

        let default_v6 = peer(1, "laptop", PEER_PUB, &["::/0"]);
        assert!(WireguardService::validate_peer(&default_v6, &cfg).is_err());

        let swallows_server = peer(1, "laptop", PEER_PUB, &["10.8.0.0/24"]);
        assert!(WireguardService::validate_peer(&swallows_server, &cfg).is_err());

        let server_key = peer(1, "laptop", SERVER_PUB, &["10.8.0.2/32"]);
        assert!(WireguardService::validate_peer(&server_key, &cfg).is_err());

        let bad_key = peer(1, "laptop", "nope", &["10.8.0.2/32"]);
        assert!(WireguardService::validate_peer(&bad_key, &cfg).is_err());

        let no_ips = peer(1, "laptop", PEER_PUB, &[]);
        assert!(WireguardService::validate_peer(&no_ips, &cfg).is_err());

        let bad_name = peer(1, "lap\ntop", PEER_PUB, &["10.8.0.2/32"]);
        assert!(WireguardService::validate_peer(&bad_name, &cfg).is_err());

        let empty_name = peer(1, "  ", PEER_PUB, &["10.8.0.2/32"]);
        assert!(WireguardService::validate_peer(&empty_name, &cfg).is_err());

        let self_overlap = peer(1, "laptop", PEER_PUB, &["10.9.0.0/24", "10.9.0.5/32"]);
        assert!(WireguardService::validate_peer(&self_overlap, &cfg).is_err());

        let mut bad_psk = peer(1, "laptop", PEER_PUB, &["10.8.0.2/32"]);
        bad_psk.preshared_key = Some("bad".into());
        assert!(WireguardService::validate_peer(&bad_psk, &cfg).is_err());

        let mut with_psk = peer(1, "laptop", PEER_PUB, &["10.8.0.2/32"]);
        with_psk.preshared_key = Some(PSK.into());
        assert!(WireguardService::validate_peer(&with_psk, &cfg).is_ok());

        let mut site = peer(1, "branch", PEER_PUB, &["10.8.0.2/32", "192.168.50.0/24"]);
        site.endpoint = Some("branch.example.com:51820".into());
        site.persistent_keepalive = 25;
        assert!(WireguardService::validate_peer(&site, &cfg).is_ok());

        site.endpoint = Some("branch.example.com".into());
        assert!(WireguardService::validate_peer(&site, &cfg).is_err());

        let mut comment = peer(1, "laptop", PEER_PUB, &["10.8.0.2/32"]);
        comment.comment = Some("line1\nline2".into());
        assert!(WireguardService::validate_peer(&comment, &cfg).is_err());

        let mut keepalive = peer(1, "laptop", PEER_PUB, &["10.8.0.2/32"]);
        keepalive.persistent_keepalive = -1;
        assert!(WireguardService::validate_peer(&keepalive, &cfg).is_err());
    }

    #[test]
    fn uniqueness_and_overlap_across_peers() {
        let a = peer(1, "alice", PEER_PUB, &["10.8.0.2/32"]);
        let b = peer(2, "bob", PEER_PUB_2, &["10.8.0.3/32", "192.168.50.0/24"]);
        let others = vec![a.clone(), b.clone()];

        let same_name = WireguardPeer {
            id: None,
            name: "ALICE".into(),
            public_key: "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=".into(),
            ..peer(0, "x", PEER_PUB, &["10.8.0.9/32"])
        };
        assert!(WireguardService::check_unique(&same_name, &others).is_err());

        let same_key = WireguardPeer {
            id: None,
            ..peer(0, "carol", PEER_PUB, &["10.8.0.9/32"])
        };
        assert!(WireguardService::check_unique(&same_key, &others).is_err());

        let fresh = WireguardPeer {
            id: None,
            ..peer(0, "carol", SERVER_PUB, &["10.8.0.9/32"])
        };
        assert!(WireguardService::check_unique(&fresh, &others).is_ok());

        let editing_self = peer(1, "alice", PEER_PUB, &["10.8.0.2/32"]);
        assert!(WireguardService::check_unique(&editing_self, &others).is_ok());
        assert!(WireguardService::check_overlap_with_others(&editing_self, &others).is_ok());

        let clash = peer(0, "carol", SERVER_PUB, &["10.8.0.2/32"]);
        let clash = WireguardPeer { id: None, ..clash };
        assert!(WireguardService::check_overlap_with_others(&clash, &others).is_err());

        let inside_subnet = WireguardPeer {
            id: None,
            ..peer(0, "carol", SERVER_PUB, &["192.168.50.10/32"])
        };
        assert!(WireguardService::check_overlap_with_others(&inside_subnet, &others).is_err());

        let covering = WireguardPeer {
            id: None,
            ..peer(0, "carol", SERVER_PUB, &["192.168.0.0/16"])
        };
        assert!(WireguardService::check_overlap_with_others(&covering, &others).is_err());

        let clear = WireguardPeer {
            id: None,
            ..peer(0, "carol", SERVER_PUB, &["10.8.0.4/32", "172.16.0.0/24"])
        };
        assert!(WireguardService::check_overlap_with_others(&clear, &others).is_ok());
    }

    #[test]
    fn auto_assign_skips_server_and_taken_addresses() {
        let cfg = config();

        assert_eq!(
            WireguardService::next_free_address(&cfg, &[]).unwrap(),
            "10.8.0.2/32"
        );

        let others = vec![
            peer(1, "a", PEER_PUB, &["10.8.0.2/32"]),
            peer(2, "b", PEER_PUB_2, &["10.8.0.3/32"]),
        ];
        assert_eq!(
            WireguardService::next_free_address(&cfg, &others).unwrap(),
            "10.8.0.4/32"
        );

        let gap = vec![
            peer(1, "a", PEER_PUB, &["10.8.0.3/32"]),
            peer(2, "b", PEER_PUB_2, &["10.8.0.2/32"]),
        ];
        assert_eq!(
            WireguardService::next_free_address(&cfg, &gap).unwrap(),
            "10.8.0.4/32"
        );

        let block = vec![peer(1, "a", PEER_PUB, &["10.8.0.0/25"])];
        assert_eq!(
            WireguardService::next_free_address(&cfg, &block).unwrap(),
            "10.8.0.128/32"
        );

        let mut tiny = config();
        tiny.address = "10.8.0.1/30".into();
        let full = vec![peer(1, "a", PEER_PUB, &["10.8.0.2/32"])];
        assert!(WireguardService::next_free_address(&tiny, &full).is_err());

        let mut v6 = config();
        v6.address = "fd00:8::1/64".into();
        assert!(WireguardService::next_free_address(&v6, &[]).is_err());
    }

    #[test]
    fn client_config_contents() {
        let cfg = config();
        let mut p = peer(1, "laptop", PEER_PUB, &["10.8.0.2/32"]);
        p.preshared_key = Some(PSK.into());

        let out = WireguardService::build_client_config(&cfg, PEER_PUB_2, &p).unwrap();

        assert!(out.starts_with("[Interface]\n"));
        assert!(out.contains(&format!("PrivateKey = {}\n", PEER_PUB_2)));
        assert!(out.contains("Address = 10.8.0.2/32\n"));
        assert!(out.contains("DNS = 1.1.1.1, 8.8.8.8\n"));
        assert!(!out.contains("MTU"));
        assert!(out.contains(&format!("PublicKey = {}\n", SERVER_PUB)));
        assert!(out.contains(&format!("PresharedKey = {}\n", PSK)));
        assert!(out.contains("AllowedIPs = 0.0.0.0/0, ::/0\n"));
        assert!(out.contains("Endpoint = vpn.example.com:51820\n"));
        assert!(out.contains("PersistentKeepalive = 25\n"));

        let mut with_mtu = cfg.clone();
        with_mtu.mtu = Some(1380);
        with_mtu.endpoint = Some("2001:db8::1".into());
        with_mtu.dns = None;
        let out = WireguardService::build_client_config(&with_mtu, PEER_PUB_2, &p).unwrap();
        assert!(out.contains("MTU = 1380\n"));
        assert!(out.contains("Endpoint = [2001:db8::1]:51820\n"));
        assert!(!out.contains("DNS"));

        let subnet_first = peer(1, "x", PEER_PUB, &["192.168.50.0/24"]);
        assert!(WireguardService::build_client_config(&cfg, PEER_PUB_2, &subnet_first).is_err());

        let mut no_endpoint = cfg.clone();
        no_endpoint.endpoint = None;
        assert!(WireguardService::build_client_config(&no_endpoint, PEER_PUB_2, &p).is_err());
    }
}
