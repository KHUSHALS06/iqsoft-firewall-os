use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;
use tokio::process::Command;

use crate::{
    app_state::AppState,
    models::wireguard::{
        WireguardConfigUpdate, WireguardPeerInput, WireguardPeerStatus,
    },
    repository::wireguard_repository::WireguardRepository,
    services::wireguard_service::WireguardService,
    wireguard::{commit::WireguardCommit, generator::WireguardGenerator},
};

pub async fn get_config(State(state): State<AppState>) -> impl IntoResponse {
    match WireguardService::get_config(&state.db).await {
        Ok(config) => (StatusCode::OK, Json(json!(config))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn set_config(
    State(state): State<AppState>,
    Json(update): Json<WireguardConfigUpdate>,
) -> impl IntoResponse {
    match WireguardService::set_config(&state.db, update).await {
        Ok(config) => (StatusCode::OK, Json(json!(config))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn list_peers(State(state): State<AppState>) -> impl IntoResponse {
    match WireguardService::list_peers(&state.db).await {
        Ok(peers) => (StatusCode::OK, Json(json!(peers))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

/// When `generate_keys` is true the response carries `client_config`, which
/// holds the client's private key. It is shown only in this response.
pub async fn add_peer(
    State(state): State<AppState>,
    Json(input): Json<WireguardPeerInput>,
) -> impl IntoResponse {
    match WireguardService::add_peer(&state.db, input).await {
        Ok(created) => (StatusCode::OK, Json(json!(created))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn update_peer(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(input): Json<WireguardPeerInput>,
) -> impl IntoResponse {
    match WireguardService::update_peer(&state.db, id, input).await {
        Ok(updated) => (StatusCode::OK, Json(json!(updated))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn delete_peer(
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match WireguardService::delete_peer(&state.db, id).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

/// Shows the config that a commit would write, with every secret hidden.
pub async fn generate_config(State(state): State<AppState>) -> impl IntoResponse {
    let config = match WireguardRepository::get_config(&state.db).await {
        Ok(config) => config,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        }
    };

    let peers = match WireguardRepository::list_peers(&state.db).await {
        Ok(peers) => peers,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        }
    };

    match WireguardGenerator::render(&config, &peers) {
        Ok(text) => (
            StatusCode::OK,
            Json(json!({ "config": redact_secrets(&text) })),
        ),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

/// Live state of the tunnel: which peers have connected and how much they sent.
pub async fn status(State(state): State<AppState>) -> impl IntoResponse {
    let config = match WireguardRepository::get_config(&state.db).await {
        Ok(config) => config,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        }
    };

    let iface = config.interface_name.trim().to_string();

    if !is_safe_iface(&iface) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "WireGuard interface name is not valid" })),
        );
    }

    if !std::path::Path::new(&format!("/sys/class/net/{}", iface)).exists() {
        return (
            StatusCode::OK,
            Json(json!({
                "interface": iface,
                "running": false,
                "peers": Vec::<WireguardPeerStatus>::new(),
            })),
        );
    }

    let output = match Command::new("wg")
        .arg("show")
        .arg(&iface)
        .arg("dump")
        .output()
        .await
    {
        Ok(output) => output,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": format!("Could not run wg (is wireguard-tools installed?): {}", e)
                })),
            )
        }
    };

    if !output.status.success() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": format!(
                    "wg show failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                )
            })),
        );
    }

    let text = String::from_utf8_lossy(&output.stdout);

    (
        StatusCode::OK,
        Json(json!({
            "interface": iface,
            "running": true,
            "peers": parse_dump(&text),
        })),
    )
}

pub async fn commit(State(state): State<AppState>) -> impl IntoResponse {
    match WireguardCommit::commit(&state.db, &state.commit_lock).await {
        Ok(message) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "message": message })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": e })),
        ),
    }
}

pub async fn rollback(State(state): State<AppState>) -> impl IntoResponse {
    match WireguardCommit::rollback(&state.db, &state.commit_lock).await {
        Ok(message) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "message": message })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": e })),
        ),
    }
}

fn is_safe_iface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn redact_secrets(text: &str) -> String {
    text.lines()
        .map(|line| {
            let trimmed = line.trim_start();

            if trimmed.starts_with("PrivateKey") {
                "PrivateKey = (hidden)".to_string()
            } else if trimmed.starts_with("PresharedKey") {
                "PresharedKey = (hidden)".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// `wg show <iface> dump` is tab separated. The first line describes the
/// interface itself, every later line is one peer:
/// public-key, preshared-key, endpoint, allowed-ips, latest-handshake,
/// rx-bytes, tx-bytes, persistent-keepalive.
fn parse_dump(text: &str) -> Vec<WireguardPeerStatus> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();

            if fields.len() < 8 {
                return None;
            }

            let endpoint = match fields[2] {
                "(none)" | "" => None,
                value => Some(value.to_string()),
            };

            let allowed_ips = match fields[3] {
                "(none)" | "" => Vec::new(),
                value => value.split(',').map(|s| s.trim().to_string()).collect(),
            };

            let latest_handshake = match fields[4].parse::<i64>() {
                Ok(0) | Err(_) => None,
                Ok(value) => Some(value),
            };

            Some(WireguardPeerStatus {
                public_key: fields[0].to_string(),
                endpoint,
                allowed_ips,
                latest_handshake,
                rx_bytes: fields[5].parse().unwrap_or(0),
                tx_bytes: fields[6].parse().unwrap_or(0),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{parse_dump, redact_secrets};

    #[test]
    fn secrets_are_hidden_in_generated_output() {
        let text = "[Interface]\nAddress = 10.8.0.1/24\nPrivateKey = abc\n\n[Peer]\nPublicKey = pub\nPresharedKey = psk\nAllowedIPs = 10.8.0.2/32\n";
        let out = redact_secrets(text);

        assert!(!out.contains("abc"));
        assert!(!out.contains("psk"));
        assert!(out.contains("PrivateKey = (hidden)\n"));
        assert!(out.contains("PresharedKey = (hidden)\n"));
        assert!(out.contains("PublicKey = pub\n"));
        assert!(out.contains("Address = 10.8.0.1/24\n"));
    }

    #[test]
    fn dump_is_parsed_into_peers() {
        let text = "serverpriv\tserverpub\t51820\toff\n\
                    peerpub1\tpsk\t203.0.113.5:40000\t10.8.0.2/32\t1700000000\t100\t200\t25\n\
                    peerpub2\t(none)\t(none)\t10.8.0.3/32,192.168.50.0/24\t0\t0\t0\toff\n";

        let peers = parse_dump(text);

        assert_eq!(peers.len(), 2);

        assert_eq!(peers[0].public_key, "peerpub1");
        assert_eq!(peers[0].endpoint.as_deref(), Some("203.0.113.5:40000"));
        assert_eq!(peers[0].allowed_ips, vec!["10.8.0.2/32"]);
        assert_eq!(peers[0].latest_handshake, Some(1700000000));
        assert_eq!(peers[0].rx_bytes, 100);
        assert_eq!(peers[0].tx_bytes, 200);

        assert_eq!(peers[1].endpoint, None);
        assert_eq!(peers[1].latest_handshake, None);
        assert_eq!(peers[1].allowed_ips, vec!["10.8.0.3/32", "192.168.50.0/24"]);
    }

    #[test]
    fn dump_with_only_the_interface_line_has_no_peers() {
        assert!(parse_dump("serverpriv\tserverpub\t51820\toff\n").is_empty());
        assert!(parse_dump("").is_empty());
    }
}
