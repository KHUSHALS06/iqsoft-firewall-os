mod api;
mod app_state;
mod database;
mod dhcp;
mod dns;
mod firewall;
mod models;
mod monitor;
mod netconfig;
mod repository;
mod routing;
mod services;
mod sni;
mod threatintel;
mod wireguard;
mod antivirus;
mod sdwan;
mod ids;

use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;

use api::{
    access as access_api,
    address as address_api,
    appcontrol as appcontrol_api,
    audit as audit_api,
    auth as auth_api,
    av as av_api,
    dhcp as dhcp_api,
    dns as dns_api,
    dnsfilter as dnsfilter_api,
    firewall as firewall_api,
    geoip as geoip_api,
    health,
    ids as ids_api,
    interface_config as interface_config_api,
    monitor as monitor_api,
    network_config as network_config_api,
    one_to_one_nat as one_to_one_nat_api,
    port_forward as port_forward_api,
    route as route_api,
    sdwan as sdwan_api,
    sni as sni_api,
    system as system_api,
    threatfeed as threatfeed_api,
    users as users_api,
    wireguard as wireguard_api,
};
use app_state::AppState;
use database::{
    connection::create_pool,
    init::initialize_database,
};
use firewall::{commit::FirewallCommit, safe_commit::SafeCommit};
use netconfig::commit::InterfaceCommit;
use routing::commit::RouteCommit;
use sdwan::commit::SdwanCommit;
use services::{auth_service::AuthService, login_throttle::LoginThrottle};
use wireguard::commit::WireguardCommit;
use tower_http::services::ServeDir;

/// Block lists and country lists can be several MB, more than the 2 MB default.
const MAX_IMPORT_BYTES: usize = 32 * 1024 * 1024;

fn build_router(state: AppState) -> Router {
    let public = Router::new()
        .route("/health", get(health::health))
        .route("/api/auth/login", post(auth_api::login));

    let protected = Router::new()
        .route("/api/auth/logout", post(auth_api::logout))
        .route("/api/auth/me", get(auth_api::me))
        .route(
            "/api/auth/change-password",
            post(auth_api::change_password),
        )
        .route(
            "/api/users",
            get(users_api::list_users).post(users_api::create_user),
        )
        .route(
            "/api/users/{id}",
            put(users_api::update_user).delete(users_api::delete_user),
        )
        .route(
            "/api/roles",
            get(users_api::list_roles).post(users_api::create_role),
        )
        .route(
            "/api/roles/{id}",
            put(users_api::update_role).delete(users_api::delete_role),
        )
        .route("/api/permissions", get(users_api::catalog))
        .route("/api/audit", get(audit_api::list_audit))
        .route("/api/system/info", get(system_api::info))
        .route("/api/system/backup", get(system_api::backup))
        .route(
            "/api/system/restore",
            post(system_api::restore)
                .layer(DefaultBodyLimit::max(system_api::MAX_RESTORE_BYTES))
                .delete(system_api::cancel_restore),
        )
        .route("/api/system/reboot", post(system_api::reboot))
        .route("/api/system/shutdown", post(system_api::shutdown))
        .route(
            "/api/system/settings",
            get(system_api::get_settings).put(system_api::update_settings),
        )
        .route(
            "/api/geoip/policies",
            get(geoip_api::list_policies)
                .post(geoip_api::add_policy),
        )
        .route(
            "/api/geoip/policies/{id}",
            put(geoip_api::update_policy)
                .delete(geoip_api::delete_policy),
        )
        .route(
            "/api/geoip/datasets",
            get(geoip_api::list_datasets),
        )
        .route(
            "/api/geoip/locate",
            post(geoip_api::locate),
        )
        .route(
            "/api/geoip/datasets/{country}",
            put(geoip_api::import_dataset)
                .layer(DefaultBodyLimit::max(MAX_IMPORT_BYTES))
                .delete(geoip_api::delete_dataset),
        )
        .route(
            "/api/dnsfilter/settings",
            get(dnsfilter_api::get_settings)
                .put(dnsfilter_api::set_settings),
        )
        .route(
            "/api/dnsfilter/categories",
            get(dnsfilter_api::list_categories)
                .post(dnsfilter_api::add_category),
        )
        .route(
            "/api/dnsfilter/categories/{name}",
            put(dnsfilter_api::update_category)
                .delete(dnsfilter_api::delete_category),
        )
        .route(
            "/api/dnsfilter/categories/{name}/domains",
            put(dnsfilter_api::import_domains)
                .layer(DefaultBodyLimit::max(MAX_IMPORT_BYTES)),
        )
        .route(
            "/api/dnsfilter/rules",
            get(dnsfilter_api::list_rules)
                .post(dnsfilter_api::add_rule),
        )
        .route(
            "/api/dnsfilter/rules/{id}",
            put(dnsfilter_api::update_rule)
                .delete(dnsfilter_api::delete_rule),
        )
        .route(
            "/api/sni/settings",
            get(sni_api::get_settings)
                .put(sni_api::set_settings),
        )
        .route(
            "/api/sni/rules",
            get(sni_api::list_rules)
                .post(sni_api::add_rule),
        )
        .route(
            "/api/sni/rules/{id}",
            put(sni_api::update_rule)
                .delete(sni_api::delete_rule),
        )
        .route(
            "/api/sni/apps",
            get(appcontrol_api::list_apps),
        )
        .route(
            "/api/sni/apps/{id}",
            put(appcontrol_api::set_app),
        )
        .route(
            "/api/threatfeeds",
            get(threatfeed_api::list_feeds)
                .post(threatfeed_api::add_feed),
        )
        .route(
            "/api/threatfeeds/presets",
            get(threatfeed_api::list_presets),
        )
        .route(
            "/api/threatfeeds/apply",
            post(threatfeed_api::apply_now),
        )
        .route(
            "/api/threatfeeds/{id}",
            put(threatfeed_api::update_feed)
                .delete(threatfeed_api::delete_feed),
        )
        .route(
            "/api/threatfeeds/{id}/refresh",
            post(threatfeed_api::refresh_feed),
        )
        .route(
            "/api/threatfeeds/{id}/entries",
            get(threatfeed_api::list_entries)
                .put(threatfeed_api::import_entries)
                .layer(DefaultBodyLimit::max(MAX_IMPORT_BYTES)),
        )
        .route(
            "/api/av/settings",
            get(av_api::get_settings)
                .put(av_api::set_settings),
        )
        .route(
            "/api/av/exceptions",
            get(av_api::list_exceptions)
                .post(av_api::add_exception),
        )
        .route(
            "/api/av/exceptions/{id}",
            delete(av_api::delete_exception),
        )
        .route(
            "/api/av/events",
            get(av_api::list_events)
                .delete(av_api::clear_events),
        )
        .route(
            "/api/av/summary",
            get(av_api::summary),
        )
        .route(
            "/api/av/status",
            get(av_api::status),
        )
        .route(
            "/api/ids/settings",
            get(ids_api::get_settings)
                .put(ids_api::set_settings),
        )
        .route(
            "/api/ids/overrides",
            get(ids_api::list_overrides)
                .post(ids_api::add_override),
        )
        .route(
            "/api/ids/overrides/{id}",
            delete(ids_api::delete_override),
        )
        .route(
            "/api/ids/events",
            get(ids_api::list_events)
                .delete(ids_api::clear_events),
        )
        .route(
            "/api/ids/summary",
            get(ids_api::summary),
        )
        .route(
            "/api/ids/status",
            get(ids_api::status),
        )
        .route(
            "/api/ids/apply",
            post(ids_api::apply),
        )
        .route(
            "/api/ids/rules/update",
            post(ids_api::update_rules),
        )
        .route(
            "/api/sdwan/settings",
            get(sdwan_api::get_settings)
                .put(sdwan_api::set_settings),
        )
        .route(
            "/api/sdwan/links",
            get(sdwan_api::list_links)
                .post(sdwan_api::add_link),
        )
        .route(
            "/api/sdwan/links/{id}",
            put(sdwan_api::update_link)
                .delete(sdwan_api::delete_link),
        )
        .route(
            "/api/sdwan/rules",
            get(sdwan_api::list_rules)
                .post(sdwan_api::add_rule),
        )
        .route(
            "/api/sdwan/rules/{id}",
            put(sdwan_api::update_rule)
                .delete(sdwan_api::delete_rule),
        )
        .route(
            "/api/sdwan/status",
            get(sdwan_api::status),
        )
        .route(
            "/api/sdwan/generate",
            get(sdwan_api::generate),
        )
        .route(
            "/api/sdwan/probe",
            post(sdwan_api::probe_now),
        )
        .route(
            "/api/sdwan/commit",
            post(sdwan_api::commit),
        )
        .route(
            "/api/sdwan/rollback",
            post(sdwan_api::rollback),
        )
        .route(
            "/api/rules",
            get(firewall_api::list_rules)
                .post(firewall_api::add_rule),
        )
        .route(
            "/api/rules/{id}",
            put(firewall_api::update_rule)
                .delete(firewall_api::delete_rule),
        )
        .route(
            "/api/generate",
            get(firewall_api::generate_config),
        )
        .route(
            "/api/interfaces",
            get(interface_config_api::list),
        )
        .route(
            "/api/interfaces/live",
            get(interface_config_api::live_state),
        )
        .route(
            "/api/interfaces/generate",
            get(interface_config_api::generate),
        )
        .route(
            "/api/interfaces/status",
            get(interface_config_api::status),
        )
        .route(
            "/api/interfaces/commit",
            post(interface_config_api::commit),
        )
        .route(
            "/api/interfaces/confirm",
            post(interface_config_api::confirm),
        )
        .route(
            "/api/interfaces/rollback",
            post(interface_config_api::rollback),
        )
        .route(
            "/api/interfaces/{name}",
            put(interface_config_api::save)
                .delete(interface_config_api::remove),
        )
        .route(
            "/api/network",
            get(network_config_api::get_network_config)
                .put(network_config_api::set_network_config),
        )
        .route(
            "/api/commit",
            post(firewall_api::commit),
        )
        .route(
            "/api/commit/confirm",
            post(firewall_api::confirm_commit),
        )
        .route(
            "/api/commit/status",
            get(firewall_api::commit_status),
        )
        .route(
            "/api/rollback",
            post(firewall_api::rollback),
        )
        .route(
            "/api/dhcp/config",
            get(dhcp_api::get_config)
                .put(dhcp_api::set_config),
        )
        .route(
            "/api/dhcp/reservations",
            get(dhcp_api::list_reservations)
                .post(dhcp_api::add_reservation),
        )
        .route(
            "/api/dhcp/reservations/{id}",
            put(dhcp_api::update_reservation)
                .delete(dhcp_api::delete_reservation),
        )
        .route(
            "/api/dhcp/generate",
            get(dhcp_api::generate_config),
        )
        .route(
            "/api/dhcp/leases",
            get(dhcp_api::leases),
        )
        .route(
            "/api/dhcp/commit",
            post(dhcp_api::commit),
        )
        .route(
            "/api/dhcp/rollback",
            post(dhcp_api::rollback),
        )
        .route(
            "/api/dns/config",
            get(dns_api::get_config)
                .put(dns_api::set_config),
        )
        .route(
            "/api/dns/records",
            get(dns_api::list_records)
                .post(dns_api::add_record),
        )
        .route(
            "/api/dns/records/{id}",
            put(dns_api::update_record)
                .delete(dns_api::delete_record),
        )
        .route(
            "/api/dns/generate",
            get(dns_api::generate_config),
        )
        .route(
            "/api/dns/commit",
            post(dns_api::commit),
        )
        .route(
            "/api/dns/rollback",
            post(dns_api::rollback),
        )
        .route(
            "/api/port-forwards",
            get(port_forward_api::list_rules)
                .post(port_forward_api::add_rule),
        )
        .route(
            "/api/port-forwards/{id}",
            put(port_forward_api::update_rule)
                .delete(port_forward_api::delete_rule),
        )
        .route(
            "/api/one-to-one-nat",
            get(one_to_one_nat_api::list_rules)
                .post(one_to_one_nat_api::add_rule),
        )
        .route(
            "/api/one-to-one-nat/{id}",
            put(one_to_one_nat_api::update_rule)
                .delete(one_to_one_nat_api::delete_rule),
        )
        .route(
            "/api/routes",
            get(route_api::list_routes)
                .post(route_api::add_route),
        )
        .route(
            "/api/routes/{id}",
            put(route_api::update_route)
                .delete(route_api::delete_route),
        )
        .route(
            "/api/routes/generate",
            get(route_api::generate_script),
        )
        .route(
            "/api/routes/commit",
            post(route_api::commit),
        )
        .route(
            "/api/routes/rollback",
            post(route_api::rollback),
        )
        .route(
            "/api/address-objects",
            get(address_api::list_objects)
                .post(address_api::add_object),
        )
        .route(
            "/api/address-objects/{id}",
            put(address_api::update_object)
                .delete(address_api::delete_object),
        )
        .route(
            "/api/address-groups",
            get(address_api::list_groups)
                .post(address_api::add_group),
        )
        .route(
            "/api/address-groups/{id}",
            put(address_api::update_group)
                .delete(address_api::delete_group),
        )
        .route(
            "/api/vpn/config",
            get(wireguard_api::get_config)
                .put(wireguard_api::set_config),
        )
        .route(
            "/api/vpn/peers",
            get(wireguard_api::list_peers)
                .post(wireguard_api::add_peer),
        )
        .route(
            "/api/vpn/peers/{id}",
            put(wireguard_api::update_peer)
                .delete(wireguard_api::delete_peer),
        )
        .route(
            "/api/vpn/generate",
            get(wireguard_api::generate_config),
        )
        .route(
            "/api/vpn/status",
            get(wireguard_api::status),
        )
        .route(
            "/api/vpn/commit",
            post(wireguard_api::commit),
        )
        .route(
            "/api/vpn/rollback",
            post(wireguard_api::rollback),
        )
        .route(
            "/api/monitor/interfaces",
            get(monitor_api::get_interfaces),
        )
        .route(
            "/api/monitor/connections",
            get(monitor_api::get_connections),
        )
        .route(
            "/api/monitor/connection-usage",
            get(monitor_api::get_conntrack_usage),
        )
        .route(
            "/api/monitor/rule-counters",
            get(monitor_api::get_rule_counters),
        )
        .route(
            "/api/monitor/logs",
            get(monitor_api::get_logs),
        )
        .route(
            "/api/monitor/system",
            get(monitor_api::get_system),
        )
        // Layers added later run first: sign-in is checked, then the role's permission.
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            access_api::require_permission,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_api::require_auth,
        ));

    let web_dir = std::env::var("IQSOFT_WEB_DIR").unwrap_or_else(|_| "web".to_string());

    public
        .merge(protected)
        .with_state(state)
        .fallback_service(ServeDir::new(web_dir))
}

#[tokio::main]
async fn main() {
    println!("==================================");
    println!("     IQSOFT Firewall OS");
    println!("==================================");

    let db = create_pool()
        .await
        .expect("Failed to connect to database");

    initialize_database(&db)
        .await
        .expect("Failed to initialize database");

    AuthService::ensure_admin(&db)
        .await
        .expect("Failed to initialize admin user");

    sni::queue::init(&db).await;

    // Start the antivirus proxy before the firewall rules load, so the redirect
    // never points at a port nobody is listening on.
    antivirus::proxy::spawn(db.clone());

    let commit_lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));

    match FirewallCommit::restore_on_boot(&commit_lock).await {
        Ok(message) => println!("{}", message),
        Err(e) => {
            eprintln!(
                "ERROR: could not restore the saved firewall configuration: {}",
                e
            );
            eprintln!(
                "ERROR: the firewall may be running with an empty ruleset until a commit succeeds"
            );
        }
    }

    match InterfaceCommit::restore_on_boot(&commit_lock).await {
        Ok(message) => println!("{}", message),
        Err(e) => {
            eprintln!(
                "ERROR: could not restore the saved port settings: {}",
                e
            );
        }
    }

    match RouteCommit::restore_on_boot(&commit_lock).await {
        Ok(message) => println!("{}", message),
        Err(e) => {
            eprintln!(
                "ERROR: could not restore the saved routing configuration: {}",
                e
            );
            eprintln!(
                "ERROR: static routes may be missing until a routing commit succeeds"
            );
        }
    }

    match WireguardCommit::restore_on_boot(&commit_lock).await {
        Ok(message) => println!("{}", message),
        Err(e) => {
            eprintln!(
                "ERROR: could not restore the saved WireGuard configuration: {}",
                e
            );
            eprintln!(
                "ERROR: the VPN tunnel may be down until a WireGuard commit succeeds"
            );
        }
    }

    let safe_commit = SafeCommit::new();

    match safe_commit.recover_on_boot(&db, &commit_lock).await {
        Ok(message) => println!("{}", message),
        Err(e) => eprintln!("ERROR: {}", e),
    }

    // SD-WAN comes after the firewall recovery above, because loading a firewall ruleset
    // replaces every nftables table, including the SD-WAN packet-marking table.
    match SdwanCommit::restore_on_boot(&db, &commit_lock).await {
        Ok(message) => println!("{}", message),
        Err(e) => {
            eprintln!(
                "ERROR: could not restore the saved SD-WAN configuration: {}",
                e
            );
            eprintln!(
                "ERROR: traffic may use only the default route until an SD-WAN commit succeeds"
            );
        }
    }

    threatintel::scheduler::spawn(db.clone(), commit_lock.clone());

    // Runs after the firewall rules are restored, because the IPS queue rules live in a table
    // of their own that the firewall's `flush ruleset` would otherwise remove. It also starts
    // Suricata if needed (which can take a minute), so it runs in the background.
    ids::scheduler::spawn(db.clone(), commit_lock.clone());

    // Pings every WAN link and moves traffic away from links that stop answering.
    sdwan::monitor::spawn(db.clone(), commit_lock.clone());

    let state = AppState {
        db,
        commit_lock,
        login_throttle: LoginThrottle::new(),
        safe_commit,
    };

    let app = build_router(state);

    let bind =
        std::env::var("IQSOFT_BIND").unwrap_or_else(|_| "127.0.0.1:3000".to_string());

    let addr: SocketAddr = bind
        .parse()
        .expect("IQSOFT_BIND must look like 192.168.1.1:3443");

    let tls_cert = std::env::var("IQSOFT_TLS_CERT").ok();
    let tls_key = std::env::var("IQSOFT_TLS_KEY").ok();

    match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => {
            let _ = rustls::crypto::ring::default_provider().install_default();

            let config = RustlsConfig::from_pem_file(&cert, &key)
                .await
                .expect("Failed to load TLS certificate/key");

            println!("Server running on https://{}", addr);

            axum_server::bind_rustls(addr, config)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("Server failed");
        }
        _ => {
            println!("Server running on http://{}", addr);

            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .expect("Failed to bind server");

            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
                .expect("Server failed");
        }
    }
}
