use crate::models::wireguard::WireguardPeerStatus;
use std::path::Path;
use tokio::process::Command;

/// What the kernel reports for the WireGuard interface right now.
#[derive(Debug, Clone)]
pub struct WireguardLive {
    pub running: bool,
    pub listen_port: Option<i32>,
    pub peers: Vec<WireguardPeerStatus>,
}

pub struct WireguardStatus;

impl WireguardStatus {
    pub fn interface_exists(name: &str) -> bool {
        Path::new(&format!("/sys/class/net/{}", name)).exists()
    }

    pub async fn read(interface: &str) -> Result<WireguardLive, String> {
        if !Self::interface_exists(interface) {
            return Ok(WireguardLive {
                running: false,
                listen_port: None,
                peers: Vec::new(),
            });
        }

        let output = Command::new("wg")
            .arg("show")
            .arg(interface)
            .arg("dump")
            .output()
            .await
            .map_err(|e| format!("Could not run wg (is wireguard-tools installed?): {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "wg show {} failed: {}",
                interface,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        let (listen_port, peers) = Self::parse_dump(&String::from_utf8_lossy(&output.stdout))?;

        Ok(WireguardLive {
            running: true,
            listen_port,
            peers,
        })
    }

    /// Parses the output of `wg show <interface> dump`.
    ///
    /// The first line describes the interface:
    ///   private-key  public-key  listen-port  fwmark
    /// Every following line describes one peer (tab separated):
    ///   public-key  preshared-key  endpoint  allowed-ips  latest-handshake
    ///   transfer-rx  transfer-tx  persistent-keepalive
    ///
    /// Private and preshared keys are never copied out of this function.
    pub fn parse_dump(text: &str) -> Result<(Option<i32>, Vec<WireguardPeerStatus>), String> {
        let mut lines = text.lines().filter(|line| !line.trim().is_empty());

        let header = lines
            .next()
            .ok_or_else(|| "wg returned no interface information".to_string())?;
        let header_fields: Vec<&str> = header.split('\t').collect();

        if header_fields.len() < 3 {
            return Err("Unexpected output from wg show (interface line)".into());
        }

        let listen_port = header_fields[2].parse::<i32>().ok().filter(|p| *p > 0);

        let mut peers = Vec::new();

        for line in lines {
            let fields: Vec<&str> = line.split('\t').collect();

            if fields.len() < 8 {
                return Err("Unexpected output from wg show (peer line)".into());
            }

            let endpoint = match fields[2] {
                "(none)" | "" => None,
                value => Some(value.to_string()),
            };

            let allowed_ips = match fields[3] {
                "(none)" | "" => Vec::new(),
                value => value.split(',').map(|s| s.trim().to_string()).collect(),
            };

            let latest_handshake = fields[4].parse::<i64>().ok().filter(|t| *t > 0);
            let rx_bytes = fields[5].parse::<i64>().unwrap_or(0);
            let tx_bytes = fields[6].parse::<i64>().unwrap_or(0);

            peers.push(WireguardPeerStatus {
                public_key: fields[0].to_string(),
                endpoint,
                allowed_ips,
                latest_handshake,
                rx_bytes,
                tx_bytes,
            });
        }

        Ok((listen_port, peers))
    }
}

#[cfg(test)]
mod tests {
    use super::WireguardStatus;

    const SERVER_PRIV: &str = "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=";
    const SERVER_PUB: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const PEER_A: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    const PEER_B: &str = "jrcCyG6FRMkS4vJhpyVWjYoV6lqVEkyr1jPlyJ0uAmw=";

    #[test]
    fn parses_interface_and_peers() {
        let dump = format!(
            "{SERVER_PRIV}\t{SERVER_PUB}\t51820\toff\n\
             {PEER_A}\t(none)\t203.0.113.7:40001\t10.8.0.2/32\t1700000000\t1024\t2048\t25\n\
             {PEER_B}\t(none)\t(none)\t10.8.0.3/32,192.168.50.0/24\t0\t0\t0\toff\n"
        );

        let (port, peers) = WireguardStatus::parse_dump(&dump).unwrap();

        assert_eq!(port, Some(51820));
        assert_eq!(peers.len(), 2);

        assert_eq!(peers[0].public_key, PEER_A);
        assert_eq!(peers[0].endpoint.as_deref(), Some("203.0.113.7:40001"));
        assert_eq!(peers[0].allowed_ips, vec!["10.8.0.2/32"]);
        assert_eq!(peers[0].latest_handshake, Some(1_700_000_000));
        assert_eq!(peers[0].rx_bytes, 1024);
        assert_eq!(peers[0].tx_bytes, 2048);

        assert_eq!(peers[1].endpoint, None);
        assert_eq!(peers[1].allowed_ips, vec!["10.8.0.3/32", "192.168.50.0/24"]);
        assert_eq!(peers[1].latest_handshake, None);
    }

    #[test]
    fn interface_without_peers_is_fine() {
        let dump = format!("{SERVER_PRIV}\t{SERVER_PUB}\t51820\toff\n");
        let (port, peers) = WireguardStatus::parse_dump(&dump).unwrap();
        assert_eq!(port, Some(51820));
        assert!(peers.is_empty());
    }

    #[test]
    fn peer_with_no_allowed_ips_has_an_empty_list() {
        let dump = format!(
            "{SERVER_PRIV}\t{SERVER_PUB}\t51820\toff\n\
             {PEER_A}\t(none)\t(none)\t(none)\t0\t0\t0\toff\n"
        );
        let (_, peers) = WireguardStatus::parse_dump(&dump).unwrap();
        assert!(peers[0].allowed_ips.is_empty());
    }

    #[test]
    fn keys_of_the_server_never_end_up_in_the_result() {
        let dump = format!(
            "{SERVER_PRIV}\t{SERVER_PUB}\t51820\toff\n\
             {PEER_A}\t{PEER_B}\t(none)\t10.8.0.2/32\t0\t0\t0\toff\n"
        );
        let (_, peers) = WireguardStatus::parse_dump(&dump).unwrap();
        let debug = format!("{:?}", peers);
        assert!(!debug.contains(SERVER_PRIV));
        // The preshared key column (PEER_B here) is dropped as well.
        assert!(!debug.contains(PEER_B));
    }

    #[test]
    fn garbage_is_an_error() {
        assert!(WireguardStatus::parse_dump("").is_err());
        assert!(WireguardStatus::parse_dump("only\ttwo").is_err());

        let dump = format!("{SERVER_PRIV}\t{SERVER_PUB}\t51820\toff\nshort\tpeer\tline\n");
        assert!(WireguardStatus::parse_dump(&dump).is_err());
    }
}
