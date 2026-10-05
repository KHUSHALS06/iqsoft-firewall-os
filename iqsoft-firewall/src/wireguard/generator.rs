use crate::models::wireguard::{WireguardConfig, WireguardPeer};
use crate::services::wireguard_service::WireguardService;
use ipnet::IpNet;
use std::collections::HashSet;
use std::net::IpAddr;

pub struct WireguardGenerator;

impl WireguardGenerator {
    pub fn render(
        config: &WireguardConfig,
        peers: &[WireguardPeer],
    ) -> Result<String, String> {
        if !config.enabled {
            return Ok(String::new());
        }

        WireguardService::validate_config(config)?;

        let mut out = String::new();

        out.push_str("[Interface]\n");
        out.push_str(&format!("Address = {}\n", config.address));
        out.push_str(&format!("ListenPort = {}\n", config.listen_port));
        out.push_str(&format!("PrivateKey = {}\n", config.private_key));

        if let Some(mtu) = config.mtu {
            out.push_str(&format!("MTU = {}\n", mtu));
        }

        out.push_str("SaveConfig = false\n");

        let mut seen_keys: HashSet<String> = HashSet::new();
        let mut claimed: Vec<(IpNet, String)> = Vec::new();

        for peer in peers {
            if !peer.enabled {
                continue;
            }

            if let Err(e) = WireguardService::validate_peer(peer, config) {
                eprintln!("WARNING: skipping WireGuard peer '{}' — {}", peer.name, e);
                continue;
            }

            if seen_keys.contains(&peer.public_key) {
                eprintln!(
                    "WARNING: skipping WireGuard peer '{}' — public key already used by another peer",
                    peer.name
                );
                continue;
            }

            let nets: Vec<IpNet> = peer
                .allowed_ips
                .iter()
                .filter_map(|value| Self::parse_net(value))
                .collect();

            if nets.len() != peer.allowed_ips.len() {
                eprintln!(
                    "WARNING: skipping WireGuard peer '{}' — unreadable allowed IP",
                    peer.name
                );
                continue;
            }

            let clash = claimed.iter().find(|(existing, _)| {
                nets.iter()
                    .any(|net| existing.contains(net) || net.contains(existing))
            });

            if let Some((existing, owner)) = clash {
                eprintln!(
                    "WARNING: skipping WireGuard peer '{}' — allowed IPs overlap {} of peer '{}'",
                    peer.name, existing, owner
                );
                continue;
            }

            seen_keys.insert(peer.public_key.clone());
            for net in &nets {
                claimed.push((*net, peer.name.clone()));
            }

            out.push('\n');
            out.push_str("[Peer]\n");
            out.push_str(&format!("# {}\n", peer.name));
            out.push_str(&format!("PublicKey = {}\n", peer.public_key));

            if let Some(psk) = &peer.preshared_key {
                out.push_str(&format!("PresharedKey = {}\n", psk));
            }

            out.push_str(&format!(
                "AllowedIPs = {}\n",
                nets.iter()
                    .map(|net| net.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));

            if let Some(endpoint) = &peer.endpoint {
                out.push_str(&format!("Endpoint = {}\n", endpoint));
            }

            if peer.persistent_keepalive > 0 {
                out.push_str(&format!(
                    "PersistentKeepalive = {}\n",
                    peer.persistent_keepalive
                ));
            }
        }

        Ok(out)
    }

    fn parse_net(value: &str) -> Option<IpNet> {
        let value = value.trim();

        if let Ok(addr) = value.parse::<IpAddr>() {
            return Some(IpNet::from(addr));
        }

        value.parse::<IpNet>().ok().map(|net| net.trunc())
    }
}

#[cfg(test)]
mod tests {
    use super::WireguardGenerator;
    use crate::models::wireguard::{WireguardConfig, WireguardPeer};

    const SERVER_PUB: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const SERVER_PRIV: &str = "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=";
    const PEER_PUB: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    const PEER_PUB_2: &str = "jrcCyG6FRMkS4vJhpyVWjYoV6lqVEkyr1jPlyJ0uAmw=";

    fn key(c: char) -> String {
        format!("{}A=", c.to_string().repeat(42))
    }

    fn config() -> WireguardConfig {
        WireguardConfig {
            enabled: true,
            interface_name: "wg0".into(),
            listen_port: 51820,
            address: "10.8.0.1/24".into(),
            mtu: None,
            dns: Some("1.1.1.1".into()),
            endpoint: Some("vpn.example.com".into()),
            client_allowed_ips: vec!["0.0.0.0/0".into()],
            private_key: SERVER_PRIV.into(),
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
    fn disabled_renders_nothing_even_with_empty_keys() {
        let mut cfg = config();
        cfg.enabled = false;
        cfg.private_key = String::new();
        assert_eq!(WireguardGenerator::render(&cfg, &[]).unwrap(), "");
    }

    #[test]
    fn enabled_with_missing_keys_is_an_error() {
        let mut cfg = config();
        cfg.private_key = String::new();
        assert!(WireguardGenerator::render(&cfg, &[]).is_err());
    }

    #[test]
    fn interface_section_only() {
        let out = WireguardGenerator::render(&config(), &[]).unwrap();
        assert_eq!(
            out,
            format!(
                "[Interface]\nAddress = 10.8.0.1/24\nListenPort = 51820\nPrivateKey = {}\nSaveConfig = false\n",
                SERVER_PRIV
            )
        );
        assert!(!out.contains("DNS"));
    }

    #[test]
    fn mtu_is_rendered_when_set() {
        let mut cfg = config();
        cfg.mtu = Some(1380);
        let out = WireguardGenerator::render(&cfg, &[]).unwrap();
        assert!(out.contains("MTU = 1380\n"));
    }

    #[test]
    fn peers_render_in_order_with_optional_fields() {
        let mut remote = peer(1, "laptop", PEER_PUB, &["10.8.0.2/32"]);
        remote.preshared_key = Some(PEER_PUB_2.into());

        let mut site = peer(2, "branch office", PEER_PUB_2, &["10.8.0.3/32", "192.168.50.0/24"]);
        site.endpoint = Some("branch.example.com:51820".into());
        site.persistent_keepalive = 25;

        let out = WireguardGenerator::render(&config(), &[remote, site]).unwrap();

        let expected_peers = format!(
            "\n[Peer]\n# laptop\nPublicKey = {}\nPresharedKey = {}\nAllowedIPs = 10.8.0.2/32\n\n[Peer]\n# branch office\nPublicKey = {}\nAllowedIPs = 10.8.0.3/32, 192.168.50.0/24\nEndpoint = branch.example.com:51820\nPersistentKeepalive = 25\n",
            PEER_PUB, PEER_PUB_2, PEER_PUB_2
        );

        assert!(out.ends_with(&expected_peers), "{}", out);
    }

    #[test]
    fn disabled_peers_are_left_out() {
        let mut off = peer(1, "laptop", PEER_PUB, &["10.8.0.2/32"]);
        off.enabled = false;
        let out = WireguardGenerator::render(&config(), &[off]).unwrap();
        assert!(!out.contains("[Peer]"));
    }

    #[test]
    fn invalid_peers_are_skipped_and_valid_ones_kept() {
        let bad_key = peer(1, "bad", "nope", &["10.8.0.2/32"]);
        let default_route = peer(2, "greedy", PEER_PUB_2, &["0.0.0.0/0"]);
        let good = peer(3, "good", PEER_PUB, &["10.8.0.4/32"]);

        let out = WireguardGenerator::render(&config(), &[bad_key, default_route, good]).unwrap();

        assert_eq!(out.matches("[Peer]").count(), 1);
        assert!(out.contains("# good\n"));
        assert!(!out.contains("# bad\n"));
        assert!(!out.contains("# greedy\n"));
    }

    #[test]
    fn overlapping_and_duplicate_peers_keep_only_the_first() {
        let first = peer(1, "first", &key('B'), &["10.8.0.2/32"]);
        let overlap = peer(2, "second", &key('C'), &["10.8.0.2/32"]);
        let same_key = peer(3, "third", &key('B'), &["10.8.0.9/32"]);
        let separate = peer(4, "fourth", &key('D'), &["10.8.0.10/32"]);

        let out = WireguardGenerator::render(
            &config(),
            &[first, overlap, same_key, separate],
        )
        .unwrap();

        assert!(out.contains("# first\n"));
        assert!(!out.contains("# second\n"));
        assert!(!out.contains("# third\n"));
        assert!(out.contains("# fourth\n"));
        assert_eq!(out.matches("[Peer]").count(), 2);
    }

    #[test]
    fn larger_network_after_a_host_inside_it_is_skipped() {
        let host = peer(1, "host", PEER_PUB, &["192.168.50.10/32"]);
        let net = peer(2, "net", PEER_PUB_2, &["192.168.50.0/24"]);

        let out = WireguardGenerator::render(&config(), &[host, net]).unwrap();

        assert!(out.contains("# host\n"));
        assert!(!out.contains("# net\n"));
    }

    #[test]
    fn host_bits_in_allowed_ips_are_normalized() {
        let p = peer(1, "site", PEER_PUB, &["192.168.50.7/24"]);
        let out = WireguardGenerator::render(&config(), &[p]).unwrap();
        assert!(out.contains("AllowedIPs = 192.168.50.0/24\n"));
    }

    #[test]
    fn peer_cannot_inject_extra_lines() {
        let mut p = peer(1, "laptop", PEER_PUB, &["10.8.0.2/32"]);
        p.endpoint = Some("a.example.com:51820\nPostUp = reboot".into());
        let out = WireguardGenerator::render(&config(), &[p]).unwrap();
        assert!(!out.contains("PostUp"));
        assert!(!out.contains("[Peer]"));
    }
}
