use serde_json::{json, Value};
use tokio::process::Command;

/// What each port really has right now (MAC, MTU, state and addresses), read from `ip -j addr`.
pub async fn read_live() -> Result<Vec<Value>, String> {
    let output = Command::new("ip")
        .args(["-j", "addr", "show"])
        .output()
        .await
        .map_err(|e| format!("Could not run ip: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    let parsed: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("Could not read the output of ip: {}", e))?;

    let mut ports = Vec::new();

    for item in parsed.as_array().cloned().unwrap_or_default() {
        let name = item
            .get("ifname")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() || name == "lo" {
            continue;
        }

        let addresses: Vec<String> = item
            .get("addr_info")
            .and_then(|v| v.as_array())
            .map(|list| {
                list.iter()
                    .filter_map(|a| {
                        if a.get("scope").and_then(|s| s.as_str()) == Some("link") {
                            return None;
                        }
                        let ip = a.get("local")?.as_str()?;
                        let prefix = a.get("prefixlen")?.as_u64()?;
                        Some(format!("{}/{}", ip, prefix))
                    })
                    .collect()
            })
            .unwrap_or_default();

        ports.push(json!({
            "name": name,
            "mac": item.get("address"),
            "mtu": item.get("mtu"),
            "state": item.get("operstate"),
            "addresses": addresses,
        }));
    }

    Ok(ports)
}
