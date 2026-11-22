use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::json;
use std::{net::IpAddr, sync::Arc};
use tokio::sync::Mutex;

use crate::{
    app_state::AppState,
    models::geoip::{GeoipImportRequest, GeoipPolicy},
    services::geoip_service::GeoipService,
};

// ---------- policies ----------

pub async fn list_policies(State(state): State<AppState>) -> impl IntoResponse {
    match GeoipService::list_policies(&state.db).await {
        Ok(policies) => (StatusCode::OK, Json(json!(policies))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn add_policy(
    State(state): State<AppState>,
    Json(policy): Json<GeoipPolicy>,
) -> impl IntoResponse {
    match GeoipService::add_policy(&state.db, policy).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn update_policy(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(policy): Json<GeoipPolicy>,
) -> impl IntoResponse {
    match GeoipService::update_policy(&state.db, id, policy).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn delete_policy(
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match GeoipService::delete_policy(&state.db, id).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

// ---------- country network lists ----------

pub async fn list_datasets(State(state): State<AppState>) -> impl IntoResponse {
    match GeoipService::list_datasets(&state.db).await {
        Ok(datasets) => (StatusCode::OK, Json(json!(datasets))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

pub async fn import_dataset(
    Path(country): Path<String>,
    State(state): State<AppState>,
    Json(request): Json<GeoipImportRequest>,
) -> impl IntoResponse {
    match GeoipService::import_dataset(&state.db, &country, request).await {
        Ok(result) => (StatusCode::OK, Json(json!(result))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

pub async fn delete_dataset(
    Path(country): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match GeoipService::delete_dataset(&state.db, &country).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

// ---------- locate IPs (dashboard threat map) ----------

/// Most addresses one request may ask about.
const MAX_LOCATE_IPS: usize = 500;

#[derive(Debug, Deserialize)]
pub struct LocateRequest {
    pub ips: Vec<String>,
}

/// Every imported country network, parsed once and reused until a country
/// list is imported or removed.
struct GeoCache {
    signature: String,
    countries: usize,
    networks: Arc<Vec<(IpNet, String)>>,
}

static GEO_CACHE: std::sync::OnceLock<Mutex<Option<GeoCache>>> = std::sync::OnceLock::new();

async fn cached_networks(
    pool: &sqlx::SqlitePool,
) -> Result<(usize, Arc<Vec<(IpNet, String)>>), String> {
    let (count, newest): (i64, String) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(MAX(updated_at), '') FROM geoip_datasets",
    )
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;
    let signature = format!("{}|{}", count, newest);

    let mut guard = GEO_CACHE.get_or_init(|| Mutex::new(None)).lock().await;

    if let Some(cache) = guard.as_ref() {
        if cache.signature == signature {
            return Ok((cache.countries, cache.networks.clone()));
        }
    }

    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT country_code, cidr FROM geoip_networks")
            .fetch_all(pool)
            .await
            .map_err(|e| e.to_string())?;

    let networks: Arc<Vec<(IpNet, String)>> = Arc::new(
        rows.into_iter()
            .filter_map(|(country, cidr)| cidr.parse::<IpNet>().ok().map(|net| (net, country)))
            .collect(),
    );

    *guard = Some(GeoCache {
        signature,
        countries: count as usize,
        networks: networks.clone(),
    });

    Ok((count as usize, networks))
}

/// POST /api/geoip/locate   body: {"ips": ["1.2.3.4", ...]}
/// Answers {"countries": {"1.2.3.4": "US"}, "datasets": 3}. Addresses that are
/// private, invalid, or not in any imported country list are left out.
/// "datasets" is how many country lists are imported (0 = nothing can be located).
pub async fn locate(
    State(state): State<AppState>,
    Json(request): Json<LocateRequest>,
) -> impl IntoResponse {
    if request.ips.len() > MAX_LOCATE_IPS {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("At most {} addresses per request", MAX_LOCATE_IPS) })),
        );
    }

    let (datasets, networks) = match cached_networks(&state.db).await {
        Ok(found) => found,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e })),
            )
        }
    };

    let ips = request.ips;
    let found = tokio::task::spawn_blocking(move || {
        let mut countries = serde_json::Map::new();
        for raw in ips {
            let Ok(ip) = raw.trim().parse::<IpAddr>() else {
                continue;
            };
            if let Some((_, country)) = networks.iter().find(|(net, _)| net.contains(&ip)) {
                countries.insert(raw, json!(country));
            }
        }
        countries
    })
    .await;

    match found {
        Ok(countries) => (
            StatusCode::OK,
            Json(json!({ "countries": countries, "datasets": datasets })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}
