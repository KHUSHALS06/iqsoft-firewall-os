use crate::models::ids::{normalize_home_net, normalize_interfaces, IdsSettings};

const FLOW_MEMCAP: &str = "64mb";
const STREAM_MEMCAP: &str = "32mb";
const REASSEMBLY_MEMCAP: &str = "128mb";
const DEFRAG_MEMCAP: &str = "32mb";
const FIRST_CLUSTER_ID: usize = 99;

pub struct SuricataFiles<'a> {
    pub log_dir: &'a str,
    pub rule_dir: &'a str,
    pub rule_file: &'a str,
    pub config_dir: &'a str,
    pub socket: &'a str,
}

impl Default for SuricataFiles<'static> {
    fn default() -> Self {
        Self {
            log_dir: "/var/log/suricata",
            rule_dir: "/var/lib/suricata/rules",
            rule_file: "suricata.rules",
            config_dir: "/etc/suricata",
            socket: "/run/suricata-command.socket",
        }
    }
}

impl SuricataFiles<'_> {
    pub fn eve_path(&self) -> String {
        format!("{}/eve.json", self.log_dir.trim_end_matches('/'))
    }

    pub fn rules_path(&self) -> String {
        format!(
            "{}/{}",
            self.rule_dir.trim_end_matches('/'),
            self.rule_file
        )
    }
}

fn check_path(label: &str, value: &str) -> Result<(), String> {
    let bad = !value.starts_with('/')
        || value
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '"' || c == '\\' || c == '\'')
        || value.split('/').any(|part| part == "..");

    if bad {
        return Err(format!("{} must be a plain absolute path", label));
    }

    Ok(())
}

fn check_file_name(label: &str, value: &str) -> Result<(), String> {
    let bad = value.is_empty()
        || value.starts_with('.')
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));

    if bad {
        return Err(format!("{} must be a plain file name", label));
    }

    Ok(())
}

fn push_vars(out: &mut String, home_net: &str) {
    out.push_str("vars:\n");
    out.push_str("  address-groups:\n");
    out.push_str(&format!("    HOME_NET: \"{}\"\n", home_net));
    out.push_str("    EXTERNAL_NET: \"!$HOME_NET\"\n");
    out.push_str("    HTTP_SERVERS: \"$HOME_NET\"\n");
    out.push_str("    SMTP_SERVERS: \"$HOME_NET\"\n");
    out.push_str("    SQL_SERVERS: \"$HOME_NET\"\n");
    out.push_str("    DNS_SERVERS: \"$HOME_NET\"\n");
    out.push_str("    TELNET_SERVERS: \"$HOME_NET\"\n");
    out.push_str("    AIM_SERVERS: \"$EXTERNAL_NET\"\n");
    out.push_str("    DC_SERVERS: \"$HOME_NET\"\n");
    out.push_str("    DNP3_SERVER: \"$HOME_NET\"\n");
    out.push_str("    DNP3_CLIENT: \"$HOME_NET\"\n");
    out.push_str("    MODBUS_CLIENT: \"$HOME_NET\"\n");
    out.push_str("    MODBUS_SERVER: \"$HOME_NET\"\n");
    out.push_str("    ENIP_CLIENT: \"$HOME_NET\"\n");
    out.push_str("    ENIP_SERVER: \"$HOME_NET\"\n");
    out.push_str("  port-groups:\n");
    out.push_str("    HTTP_PORTS: \"80\"\n");
    out.push_str("    SHELLCODE_PORTS: \"!80\"\n");
    out.push_str("    ORACLE_PORTS: 1521\n");
    out.push_str("    SSH_PORTS: 22\n");
    out.push_str("    DNP3_PORTS: 20000\n");
    out.push_str("    MODBUS_PORTS: 502\n");
    out.push_str("    FILE_DATA_PORTS: \"[$HTTP_PORTS,110,143]\"\n");
    out.push_str("    FTP_PORTS: 21\n");
    out.push_str("    GENEVE_PORTS: 6081\n");
    out.push_str("    VXLAN_PORTS: 4789\n");
    out.push_str("    TEREDO_PORTS: 3544\n\n");
}

fn push_capture(out: &mut String, inline: bool, fail_open: bool, interfaces: &[String]) {
    if inline {
        out.push_str("nfq:\n");
        out.push_str("  mode: accept\n");
        out.push_str(&format!(
            "  fail-open: {}\n\n",
            if fail_open { "yes" } else { "no" }
        ));
        return;
    }

    out.push_str("af-packet:\n");

    for (index, name) in interfaces.iter().enumerate() {
        out.push_str(&format!("  - interface: {}\n", name));
        out.push_str(&format!("    cluster-id: {}\n", FIRST_CLUSTER_ID + index));
        out.push_str("    cluster-type: cluster_flow\n");
        out.push_str("    defrag: yes\n");
    }

    out.push('\n');
}

pub fn render(
    settings: &IdsSettings,
    interfaces: &[String],
    files: &SuricataFiles<'_>,
) -> Result<String, String> {
    let inline = match settings.mode.as_str() {
        "ips" => true,
        "ids" => false,
        _ => return Err("Mode must be 'ids' or 'ips'".into()),
    };

    let home_net = normalize_home_net(&settings.home_net)?;

    let monitored: Vec<String> = normalize_interfaces(&interfaces.join(","))?
        .split(',')
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect();

    if !inline && monitored.is_empty() {
        return Err("Choose at least one interface to monitor".into());
    }

    check_path("Log directory", files.log_dir)?;
    check_path("Rule directory", files.rule_dir)?;
    check_path("Configuration directory", files.config_dir)?;
    check_path("Command socket", files.socket)?;
    check_file_name("Rule file", files.rule_file)?;

    let mut out = String::new();

    out.push_str("%YAML 1.1\n---\n");
    out.push_str("# Generated by iqsoft-firewall from the IDS/IPS settings. Do not edit by hand.\n\n");

    push_vars(&mut out, &home_net);

    out.push_str(&format!("default-log-dir: {}\n\n", files.log_dir));

    out.push_str("stats:\n  enabled: no\n\n");

    out.push_str("outputs:\n");
    out.push_str("  - eve-log:\n");
    out.push_str("      enabled: yes\n");
    out.push_str("      filetype: regular\n");
    out.push_str("      filename: eve.json\n");
    out.push_str("      types:\n");
    out.push_str("        - alert:\n");
    out.push_str("            payload: no\n");
    out.push_str("            packet: no\n");
    out.push_str("            metadata: no\n");
    out.push_str("            http-body: no\n");
    out.push_str("            tagged-packets: no\n\n");

    out.push_str("logging:\n");
    out.push_str("  default-log-level: notice\n");
    out.push_str("  outputs:\n");
    out.push_str("    - console:\n");
    out.push_str("        enabled: yes\n");
    out.push_str("    - file:\n");
    out.push_str("        enabled: yes\n");
    out.push_str("        level: notice\n");
    out.push_str("        filename: suricata.log\n\n");

    out.push_str("unix-command:\n");
    out.push_str("  enabled: yes\n");
    out.push_str(&format!("  filename: {}\n\n", files.socket));

    push_capture(
        &mut out,
        inline,
        settings.fail_mode == "open",
        &monitored,
    );

    out.push_str("runmode: workers\n\n");
    out.push_str("host-mode: auto\n\n");

    out.push_str("threading:\n");
    out.push_str("  set-cpu-affinity: no\n");
    out.push_str("  detect-thread-ratio: 1.0\n\n");

    out.push_str("flow:\n");
    out.push_str(&format!("  memcap: {}\n", FLOW_MEMCAP));
    out.push_str("  hash-size: 65536\n");
    out.push_str("  prealloc: 10000\n");
    out.push_str("  emergency-recovery: 30\n\n");

    out.push_str("defrag:\n");
    out.push_str(&format!("  memcap: {}\n", DEFRAG_MEMCAP));
    out.push_str("  hash-size: 65536\n");
    out.push_str("  trackers: 65535\n");
    out.push_str("  max-frags: 65535\n");
    out.push_str("  prealloc: yes\n");
    out.push_str("  timeout: 60\n\n");

    out.push_str("stream:\n");
    out.push_str(&format!("  memcap: {}\n", STREAM_MEMCAP));
    out.push_str(&format!(
        "  checksum-validation: {}\n",
        if inline { "no" } else { "yes" }
    ));
    out.push_str("  inline: auto\n");
    out.push_str("  reassembly:\n");
    out.push_str(&format!("    memcap: {}\n", REASSEMBLY_MEMCAP));
    out.push_str("    depth: 1mb\n");
    out.push_str("    toserver-chunk-size: 2560\n");
    out.push_str("    toclient-chunk-size: 2560\n");
    out.push_str("    randomize-chunk-size: yes\n\n");

    out.push_str("app-layer:\n");
    out.push_str("  protocols:\n");
    out.push_str("    http:\n");
    out.push_str("      enabled: yes\n");
    out.push_str("      libhtp:\n");
    out.push_str("        default-config:\n");
    out.push_str("          personality: IDS\n");
    out.push_str("          request-body-limit: 100kb\n");
    out.push_str("          response-body-limit: 100kb\n");
    out.push_str("          request-body-minimal-inspect-size: 32kb\n");
    out.push_str("          request-body-inspect-window: 4kb\n");
    out.push_str("          response-body-minimal-inspect-size: 40kb\n");
    out.push_str("          response-body-inspect-window: 16kb\n\n");

    out.push_str("detect:\n");
    out.push_str("  profile: medium\n");
    out.push_str("  sgh-mpm-context: auto\n\n");

    out.push_str("mpm-algo: auto\n");
    out.push_str("spm-algo: auto\n\n");

    out.push_str(&format!("default-rule-path: {}\n", files.rule_dir));
    out.push_str("rule-files:\n");
    out.push_str(&format!("  - {}\n\n", files.rule_file));

    out.push_str(&format!(
        "classification-file: {}/classification.config\n",
        files.config_dir.trim_end_matches('/')
    ));
    out.push_str(&format!(
        "reference-config-file: {}/reference.config\n",
        files.config_dir.trim_end_matches('/')
    ));

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(mode: &str) -> IdsSettings {
        let mut settings: IdsSettings = serde_json::from_str("{}").unwrap();
        settings.enabled = true;
        settings.mode = mode.into();
        settings
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn passive_mode_listens_on_each_interface_with_its_own_cluster() {
        let text = render(
            &settings("ids"),
            &names(&["enp2s0", "enp3s0"]),
            &SuricataFiles::default(),
        )
        .unwrap();

        assert!(text.contains("af-packet:\n  - interface: enp2s0\n    cluster-id: 99\n"));
        assert!(text.contains("  - interface: enp3s0\n    cluster-id: 100\n"));
        assert!(text.contains("cluster-type: cluster_flow"));
        assert!(!text.contains("nfq:"));
    }

    #[test]
    fn inline_mode_uses_the_netfilter_queue_and_ignores_interfaces() {
        let text = render(&settings("ips"), &names(&["enp2s0"]), &SuricataFiles::default()).unwrap();

        assert!(text.contains("nfq:\n  mode: accept\n  fail-open: yes\n"));
        assert!(!text.contains("af-packet:"));
        assert!(!text.contains("enp2s0"));
    }

    #[test]
    fn fail_open_follows_the_fail_mode() {
        let mut closed = settings("ips");
        closed.fail_mode = "closed".into();

        let text = render(&closed, &[], &SuricataFiles::default()).unwrap();
        assert!(text.contains("fail-open: no"));

        let text = render(&settings("ips"), &[], &SuricataFiles::default()).unwrap();
        assert!(text.contains("fail-open: yes"));
    }

    #[test]
    fn checksum_validation_is_off_only_when_inline() {
        let ids = render(&settings("ids"), &names(&["eth0"]), &SuricataFiles::default()).unwrap();
        assert!(ids.contains("checksum-validation: yes"));

        let ips = render(&settings("ips"), &[], &SuricataFiles::default()).unwrap();
        assert!(ips.contains("checksum-validation: no"));
    }

    #[test]
    fn home_net_is_normalized_and_quoted() {
        let mut custom = settings("ids");
        custom.home_net = " 10.1.2.3/8 , 192.168.1.5 ".into();

        let text = render(&custom, &names(&["eth0"]), &SuricataFiles::default()).unwrap();

        assert!(text.contains("    HOME_NET: \"[10.0.0.0/8,192.168.1.5/32]\"\n"));
    }

    #[test]
    fn every_variable_the_emerging_threats_rules_use_is_defined() {
        let text = render(&settings("ids"), &names(&["eth0"]), &SuricataFiles::default()).unwrap();

        for name in [
            "HOME_NET", "EXTERNAL_NET", "HTTP_SERVERS", "SMTP_SERVERS", "SQL_SERVERS",
            "DNS_SERVERS", "TELNET_SERVERS", "AIM_SERVERS", "DC_SERVERS", "DNP3_SERVER",
            "DNP3_CLIENT", "MODBUS_CLIENT", "MODBUS_SERVER", "ENIP_CLIENT", "ENIP_SERVER",
            "HTTP_PORTS", "SHELLCODE_PORTS", "ORACLE_PORTS", "SSH_PORTS", "DNP3_PORTS",
            "MODBUS_PORTS", "FILE_DATA_PORTS", "FTP_PORTS", "GENEVE_PORTS", "VXLAN_PORTS",
            "TEREDO_PORTS",
        ] {
            assert!(text.contains(&format!("    {}: ", name)), "missing {}", name);
        }
    }

    #[test]
    fn paths_and_files_come_from_the_file_set() {
        let files = SuricataFiles {
            log_dir: "/data/log/",
            rule_dir: "/data/rules",
            rule_file: "custom.rules",
            config_dir: "/data/etc/",
            socket: "/run/ids.sock",
        };

        let text = render(&settings("ids"), &names(&["eth0"]), &files).unwrap();

        assert!(text.contains("default-log-dir: /data/log/\n"));
        assert!(text.contains("default-rule-path: /data/rules\n"));
        assert!(text.contains("rule-files:\n  - custom.rules\n"));
        assert!(text.contains("classification-file: /data/etc/classification.config\n"));
        assert!(text.contains("reference-config-file: /data/etc/reference.config\n"));
        assert!(text.contains("  filename: /run/ids.sock\n"));

        assert_eq!(files.eve_path(), "/data/log/eve.json");
        assert_eq!(files.rules_path(), "/data/rules/custom.rules");
    }

    #[test]
    fn only_alerts_are_written_to_the_event_log() {
        let text = render(&settings("ids"), &names(&["eth0"]), &SuricataFiles::default()).unwrap();

        assert!(text.contains("filename: eve.json"));
        assert!(text.contains("        - alert:\n"));
        assert!(!text.contains("- flow:"));
        assert!(!text.contains("- http:"));
        assert!(!text.contains("- dns:"));
        assert!(!text.contains("- stats:"));
        assert!(text.contains("stats:\n  enabled: no\n"));
    }

    #[test]
    fn passive_mode_needs_an_interface_but_inline_mode_does_not() {
        assert!(render(&settings("ids"), &[], &SuricataFiles::default()).is_err());
        assert!(render(&settings("ips"), &[], &SuricataFiles::default()).is_ok());
    }

    #[test]
    fn unsafe_input_is_refused() {
        let files = SuricataFiles::default();

        assert!(render(&settings("block"), &names(&["eth0"]), &files).is_err());
        assert!(render(&settings("ids"), &names(&["eth0\n  - evil"]), &files).is_err());
        assert!(render(&settings("ids"), &names(&["eth0: yes"]), &files).is_err());

        let mut bad_home = settings("ids");
        bad_home.home_net = "[10.0.0.0/8]\"\nevil: yes".into();
        assert!(render(&bad_home, &names(&["eth0"]), &files).is_err());

        for bad_path in ["relative/dir", "/var/../etc", "/var/log\"x", "/var/lo g", "/var/log\nx"] {
            let mut bad = SuricataFiles::default();
            bad.log_dir = bad_path;
            assert!(render(&settings("ids"), &names(&["eth0"]), &bad).is_err(), "{}", bad_path);
        }

        for bad_name in ["", ".hidden", "a/b.rules", "a b.rules", "x\".rules"] {
            let mut bad = SuricataFiles::default();
            bad.rule_file = bad_name;
            assert!(render(&settings("ids"), &names(&["eth0"]), &bad).is_err(), "{}", bad_name);
        }
    }

    fn suricata_accepts(config: &str, label: &str) {
        use std::process::Command;

        let required = std::env::var("IQSOFT_REQUIRE_SURICATA").is_ok();

        let dir = std::env::temp_dir().join(format!("iqsoft-suricata-{}-{}", std::process::id(), label));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("log")).unwrap();
        std::fs::create_dir_all(dir.join("rules")).unwrap();
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(dir.join("etc/classification.config"), "").unwrap();
        std::fs::write(dir.join("etc/reference.config"), "").unwrap();
        std::fs::write(
            dir.join("rules/suricata.rules"),
            "alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:\"test\"; content:\"x\"; sid:9000001; rev:1;)\n\
             drop tcp any any -> any 6666 (msg:\"drop test\"; sid:9000002; rev:1;)\n",
        )
        .unwrap();
        std::fs::write(dir.join("suricata.yaml"), config).unwrap();

        let result = Command::new("suricata")
            .arg("-T")
            .arg("-c")
            .arg(dir.join("suricata.yaml"))
            .arg("-S")
            .arg(dir.join("rules/suricata.rules"))
            .output();

        let output = match result {
            Ok(output) => output,
            Err(_) => {
                assert!(!required, "suricata is not installed but IQSOFT_REQUIRE_SURICATA is set");
                eprintln!("SKIPPED suricata -T: suricata not found");
                let _ = std::fs::remove_dir_all(&dir);
                return;
            }
        };

        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let _ = std::fs::remove_dir_all(&dir);

        assert!(output.status.success(), "suricata -T failed:\n{}\n{}", text, config);
    }

    fn files_in(dir: &str) -> (String, String, String, String) {
        (
            format!("{}/log", dir),
            format!("{}/rules", dir),
            format!("{}/etc", dir),
            format!("{}/cmd.sock", dir),
        )
    }

    fn render_for_test(mode: &str, label: &str) -> String {
        let dir = std::env::temp_dir()
            .join(format!("iqsoft-suricata-{}-{}", std::process::id(), label))
            .to_string_lossy()
            .to_string();

        let (log, rules, etc, socket) = files_in(&dir);

        let files = SuricataFiles {
            log_dir: &log,
            rule_dir: &rules,
            rule_file: "suricata.rules",
            config_dir: &etc,
            socket: &socket,
        };

        render(&settings(mode), &names(&["lo"]), &files).unwrap()
    }

    #[test]
    fn suricata_accepts_the_passive_configuration() {
        suricata_accepts(&render_for_test("ids", "passive"), "passive");
    }

    #[test]
    fn suricata_accepts_the_inline_configuration() {
        suricata_accepts(&render_for_test("ips", "inline"), "inline");
    }
}
