use crate::models::interface_config::{InterfaceConfig, MODE_DHCP};
use std::path::PathBuf;

pub const DEFAULT_NETWORKD_DIR: &str = "/etc/systemd/network";

/// Where the systemd-networkd files go. Set IQSOFT_NETWORKD_DIR to use another folder
/// (for example when /etc is read only on the image).
pub fn networkd_dir() -> PathBuf {
    std::env::var("IQSOFT_NETWORKD_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_NETWORKD_DIR))
}

/// "05-" makes these files win over generic ones such as 80-wired.network.
pub fn file_name(port: &str) -> String {
    format!("05-iqsoft-{}.network", port)
}

pub struct InterfaceGenerator;

impl InterfaceGenerator {
    /// The systemd-networkd file for one port.
    pub fn render(cfg: &InterfaceConfig) -> String {
        let mut out = String::new();
        out.push_str("# iqsoft port settings - generated, do not edit\n");
        if let Some(comment) = &cfg.comment {
            out.push_str(&format!("# {}\n", comment.replace(['\n', '\r'], " ")));
        }

        out.push_str("[Match]\n");
        out.push_str(&format!("Name={}\n\n", cfg.name));

        out.push_str("[Link]\n");
        if let Some(mtu) = cfg.mtu {
            out.push_str(&format!("MTUBytes={}\n", mtu));
        }
        if !cfg.enabled {
            out.push_str("ActivationPolicy=always-down\n");
        }
        out.push('\n');

        out.push_str("[Network]\n");
        if cfg.mode == MODE_DHCP {
            out.push_str("DHCP=ipv4\n");
        } else {
            out.push_str("DHCP=no\n");
            out.push_str("ConfigureWithoutCarrier=yes\n");
            for address in &cfg.addresses {
                out.push_str(&format!("Address={}\n", address));
            }
            if let Some(gateway) = &cfg.gateway {
                out.push_str(&format!("Gateway={}\n", gateway));
            }
        }
        for dns in &cfg.dns {
            out.push_str(&format!("DNS={}\n", dns));
        }

        if cfg.mode == MODE_DHCP && !cfg.dns.is_empty() {
            out.push_str("\n[DHCPv4]\nUseDNS=no\n");
        }

        out
    }

    /// Text for the Preview button: every file that would be written.
    pub fn render_all(configs: &[InterfaceConfig]) -> String {
        if configs.is_empty() {
            return "# No port settings saved yet.\n".to_string();
        }
        let dir = networkd_dir();
        let mut out = String::new();
        for cfg in configs {
            out.push_str(&format!(
                "### {}\n",
                dir.join(file_name(&cfg.name)).display()
            ));
            out.push_str(&Self::render(cfg));
            out.push('\n');
        }
        out
    }

    /// `ip` commands that give the same result without systemd-networkd
    /// (used on systems where networkd is not running, for example a plain Ubuntu test box).
    pub fn ip_commands(cfg: &InterfaceConfig) -> Vec<Vec<String>> {
        let name = cfg.name.clone();
        let mut cmds: Vec<Vec<String>> = Vec::new();
        let c = |parts: &[&str]| -> Vec<String> { parts.iter().map(|p| p.to_string()).collect() };

        if let Some(mtu) = cfg.mtu {
            cmds.push(c(&["link", "set", "dev", &name, "mtu", &mtu.to_string()]));
        }

        if !cfg.enabled {
            cmds.push(c(&["link", "set", "dev", &name, "down"]));
            return cmds;
        }

        cmds.push(c(&["addr", "flush", "dev", &name, "scope", "global"]));
        for address in &cfg.addresses {
            cmds.push(c(&["addr", "add", address, "dev", &name]));
        }
        cmds.push(c(&["link", "set", "dev", &name, "up"]));
        if let Some(gateway) = &cfg.gateway {
            cmds.push(c(&["route", "replace", "default", "via", gateway, "dev", &name]));
        }
        cmds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> InterfaceConfig {
        InterfaceConfig {
            name: "enp3s0".into(),
            mode: "static".into(),
            addresses: vec!["192.168.1.1/24".into()],
            gateway: Some("192.168.1.254".into()),
            dns: vec!["1.1.1.1".into()],
            mtu: Some(1500),
            enabled: true,
            comment: None,
        }
    }

    #[test]
    fn static_port_renders_address_gateway_dns_and_mtu() {
        let text = InterfaceGenerator::render(&sample());
        assert!(text.contains("Name=enp3s0"));
        assert!(text.contains("Address=192.168.1.1/24"));
        assert!(text.contains("Gateway=192.168.1.254"));
        assert!(text.contains("DNS=1.1.1.1"));
        assert!(text.contains("MTUBytes=1500"));
        assert!(text.contains("DHCP=no"));
    }

    #[test]
    fn dhcp_port_has_no_static_lines() {
        let mut cfg = sample();
        cfg.mode = "dhcp".into();
        cfg.addresses.clear();
        cfg.gateway = None;
        let text = InterfaceGenerator::render(&cfg);
        assert!(text.contains("DHCP=ipv4"));
        assert!(!text.contains("Address="));
        assert!(text.contains("UseDNS=no"));
    }

    #[test]
    fn disabled_port_stays_down() {
        let mut cfg = sample();
        cfg.enabled = false;
        assert!(InterfaceGenerator::render(&cfg).contains("ActivationPolicy=always-down"));
        let cmds = InterfaceGenerator::ip_commands(&cfg);
        assert_eq!(cmds.last().unwrap().last().unwrap(), "down");
    }

    #[test]
    fn ip_commands_flush_then_add_then_route() {
        let cmds = InterfaceGenerator::ip_commands(&sample());
        let flat: Vec<String> = cmds.iter().map(|c| c.join(" ")).collect();
        let flush = flat.iter().position(|c| c.starts_with("addr flush")).unwrap();
        let add = flat.iter().position(|c| c.starts_with("addr add")).unwrap();
        let route = flat.iter().position(|c| c.starts_with("route replace")).unwrap();
        assert!(flush < add && add < route);
    }
}
