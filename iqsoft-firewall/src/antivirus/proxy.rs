//! The scanning HTTP proxy.
//!
//! Two ways to reach it:
//! * Transparent: nftables redirects LAN tcp/80 to this port. The original
//!   destination is read from the connection (SO_ORIGINAL_DST).
//! * Explicit: `curl -x http://FIREWALL:3128 http://server/file`. Handy for
//!   testing before the redirect exists.
//!
//! Plain HTTP only. HTTPS needs TLS interception, which is a separate step.
//!
//! What happens to each response (see `filter.rs` for the rules):
//! * Skip      -> streamed straight through, never delayed
//! * Buffer    -> held, scanned (with the verdict cache), then released or
//!                replaced by a block page
//! * Stream    -> sent as it arrives, last bytes held until the verdict
//!                (see `stream.rs`)
//! * Oversize / Unscannable -> over-size action / fail mode
//!
//! `spawn()` starts a supervisor that keeps everything in line with the AV
//! settings by itself: starts and stops the listener, follows port changes,
//! checks clamd, clears the verdict cache after signature updates, and opens
//! or closes the redirect gate in nftables.

use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full};
use hyper::{
    body::{Body, Frame, Incoming},
    header::{self, HeaderMap, HeaderValue},
    http::response::Parts,
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode, Uri, Version,
};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
};
use sqlx::SqlitePool;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, Semaphore},
    task::JoinHandle,
    time::{sleep, timeout},
};

use super::{
    cache::VerdictCache,
    clamd_conf,
    events::{record_scan_event, ScanEventContext},
    filter::{self, ExceptionSet, ResponseInfo, ScanPlan},
    health,
    integration::{scan_and_record_cached, start_stream_scan},
    scanner::{ScanAction, ScannerOutcome},
    stream::{Finish, Push, StreamingScan},
};
use crate::{models::av::AvSettings, services::av_service::AvService};

type RespBody = UnsyncBoxBody<Bytes, io::Error>;
type UpstreamClient = Client<HttpConnector, Incoming>;

const TICK: Duration = Duration::from_secs(5);
/// clamd self-test and version check every `CHECK_EVERY_TICKS` ticks (30 s).
const CHECK_EVERY_TICKS: u64 = 6;
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const MIB: u64 = 1024 * 1024;

// ---------------------------------------------------------------------------
// shared state
// ---------------------------------------------------------------------------

struct Snapshot {
    settings: AvSettings,
    exceptions: ExceptionSet,
}

struct Shared {
    db: SqlitePool,
    snapshot: RwLock<Arc<Snapshot>>,
    client: UpstreamClient,
    cache: VerdictCache,
    permits: Arc<Semaphore>,
}

impl Shared {
    fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn store(&self, snapshot: Snapshot) {
        *self.snapshot.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(snapshot);
    }
}

async fn load_snapshot(db: &SqlitePool) -> Result<Snapshot, String> {
    let settings = AvService::get_settings(db).await?;
    let exceptions = AvService::list_exceptions(db).await?;

    Ok(Snapshot {
        settings,
        exceptions: ExceptionSet::new(&exceptions),
    })
}

fn max_scan_bytes(settings: &AvSettings) -> u64 {
    (settings.max_scan_mb.max(1) as u64).saturating_mul(MIB)
}

fn fail_closed(settings: &AvSettings) -> bool {
    settings.fail_mode != "open"
}

// ---------------------------------------------------------------------------
// supervisor
// ---------------------------------------------------------------------------

/// Start the supervisor. Call once at boot, before the firewall rules load.
pub fn spawn(db: SqlitePool) {
    tokio::spawn(supervisor(db));
}

fn build_client() -> UpstreamClient {
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(Duration::from_secs(10)));
    connector.set_nodelay(true);

    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(30))
        .build(connector)
}

async fn supervisor(db: SqlitePool) {
    let first = loop {
        match load_snapshot(&db).await {
            Ok(snapshot) => break snapshot,
            Err(e) => {
                eprintln!("AV proxy: cannot read settings yet: {e}");
                sleep(TICK).await;
            }
        }
    };

    let threads = clamd_conf::recommended_threads();

    let shared = Arc::new(Shared {
        db: db.clone(),
        snapshot: RwLock::new(Arc::new(first)),
        client: build_client(),
        cache: VerdictCache::new(Duration::from_secs(3600), 4096),
        // At most this many files are being held or streamed at once, which
        // bounds memory and keeps clamd threads free for quick scans.
        permits: Arc::new(Semaphore::new((threads * 2).max(2))),
    });

    let mut listener: Option<(u16, JoinHandle<()>)> = None;
    let mut last_version: Option<String> = None;
    let mut gate: Option<bool> = None;
    let mut tick: u64 = 0;

    loop {
        match load_snapshot(&db).await {
            Ok(snapshot) => shared.store(snapshot),
            Err(e) => eprintln!("AV proxy: cannot reload settings: {e}"),
        }

        let snapshot = shared.snapshot();
        let enabled = snapshot.settings.enabled;
        let wanted_port = if enabled {
            Some(snapshot.settings.proxy_port as u16)
        } else {
            None
        };

        // 1. listener follows the settings (and is restarted if it died)
        let running_port = listener
            .as_ref()
            .and_then(|(port, handle)| if handle.is_finished() { None } else { Some(*port) });

        if running_port != wanted_port {
            if let Some((_, handle)) = listener.take() {
                handle.abort();
                health::set_proxy(false, 0);
                println!("AV proxy: stopped");
            }

            if let Some(port) = wanted_port {
                match start_listener(shared.clone(), port).await {
                    Ok(handle) => {
                        listener = Some((port, handle));
                        health::set_proxy(true, port);
                        println!("AV proxy: listening on port {port}");
                    }
                    Err(e) => eprintln!("AV proxy: {e}"),
                }
            }
        }

        // 2. clamd self-test, and a cache reset when signatures change
        if enabled && tick % CHECK_EVERY_TICKS == 0 {
            health::check_clamd(&snapshot.settings.clamd_socket).await;

            let version = health::clamd_version(&snapshot.settings.clamd_socket).await;
            if version != last_version {
                if last_version.is_some() {
                    shared.cache.clear();
                    println!("AV proxy: ClamAV signatures changed, verdict cache cleared");
                }
                last_version = version;
            }
        }

        // 3. the redirect gate: open while the proxy can take traffic.
        // With fail-closed, the redirect stays open even if the proxy is down,
        // so web traffic is refused instead of passing unscanned.
        let want_gate = enabled && (health::proxy_up() || fail_closed(&snapshot.settings));

        // Re-apply every 30 s while wanted: a firewall commit rebuilds the
        // ruleset and resets the gate.
        if gate != Some(want_gate) || (want_gate && tick % CHECK_EVERY_TICKS == 0) {
            let done = set_gate(want_gate).await;
            gate = Some(want_gate);
            // "Active" only if the element really is in the set, which also
            // proves that the redirect rule has been committed.
            health::set_redirect(want_gate && done);
        }

        tick = tick.wrapping_add(1);
        sleep(TICK).await;
    }
}

/// Open or close the redirect without touching the rest of the firewall.
/// The element lives in the `av_gate` set that the generator creates. Errors
/// are expected (no commit yet, element already in the wanted state).
async fn set_gate(open: bool) -> bool {
    let verb = if open { "add" } else { "delete" };

    let result = tokio::process::Command::new("nft")
        .args([verb, "element", "ip", "nat", "av_gate", "{", "tcp", "}"])
        .output()
        .await;

    match result {
        Ok(output) => output.status.success(),
        Err(e) => {
            eprintln!("AV proxy: cannot run nft: {e}");
            false
        }
    }
}

async fn start_listener(shared: Arc<Shared>, port: u16) -> Result<JoinHandle<()>, String> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
        .await
        .map_err(|e| format!("cannot listen on port {port}: {e}"))?;

    Ok(tokio::spawn(accept_loop(shared, listener)))
}

async fn accept_loop(shared: Arc<Shared>, listener: TcpListener) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                eprintln!("AV proxy: accept failed: {e}");
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        let Ok(local) = stream.local_addr() else { continue };
        let original = original_dst(&stream);
        let _ = stream.set_nodelay(true);

        let shared = shared.clone();
        tokio::spawn(serve_connection(shared, stream, peer, local, original));
    }
}

async fn serve_connection(
    shared: Arc<Shared>,
    stream: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    original: Option<SocketAddr>,
) {
    let service = service_fn(move |req: Request<Incoming>| {
        let shared = shared.clone();
        async move { Ok::<_, Infallible>(handle(shared, peer, local, original, req).await) }
    });

    // A client that disconnects mid-way is normal, not an error worth logging.
    let _ = http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .await;
}

/// Where the client was really going, before nftables redirected it here.
fn original_dst(stream: &TcpStream) -> Option<SocketAddr> {
    const SO_ORIGINAL_DST: libc::c_int = 80;

    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut libc::sockaddr_in as *mut libc::c_void,
            &mut len,
        )
    };

    if rc != 0 {
        return None;
    }

    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);

    Some(SocketAddr::new(IpAddr::V4(ip), port))
}

// ---------------------------------------------------------------------------
// request handling
// ---------------------------------------------------------------------------

struct Target {
    host: String,
    ip: IpAddr,
    port: u16,
    path_and_query: String,
}

async fn handle(
    shared: Arc<Shared>,
    peer: SocketAddr,
    local: SocketAddr,
    original: Option<SocketAddr>,
    req: Request<Incoming>,
) -> Response<RespBody> {
    match handle_inner(&shared, peer, local, original, req).await {
        Ok(response) | Err(response) => response,
    }
}

async fn handle_inner(
    shared: &Arc<Shared>,
    peer: SocketAddr,
    local: SocketAddr,
    original: Option<SocketAddr>,
    req: Request<Incoming>,
) -> Result<Response<RespBody>, Response<RespBody>> {
    if req.method() == Method::CONNECT {
        return Err(page(
            StatusCode::METHOD_NOT_ALLOWED,
            "Not supported",
            "HTTPS tunnelling through this proxy is not enabled.",
        ));
    }

    let snapshot = shared.snapshot();
    let target = resolve_target(req.uri(), req.headers(), local, original).await?;

    let request_file = filter::file_name_from_path(&target.path_and_query);
    let upstream_req = build_upstream_request(req, &target, request_file)?;

    let upstream = match timeout(HEAD_TIMEOUT, shared.client.request(upstream_req)).await {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => {
            return Err(page(
                StatusCode::BAD_GATEWAY,
                "Cannot reach the server",
                &format!("The connection to {} failed: {}", target.host, e),
            ))
        }
        Err(_) => {
            return Err(page(
                StatusCode::GATEWAY_TIMEOUT,
                "The server took too long to answer",
                &format!("{} did not respond in time.", target.host),
            ))
        }
    };

    let (parts, body) = upstream.into_parts();

    if !snapshot.settings.enabled {
        return Ok(forward(parts, body));
    }

    // What does the response look like?
    let header_text = |name: header::HeaderName| -> Option<String> {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string())
    };

    let content_type = header_text(header::CONTENT_TYPE);
    let content_encoding = header_text(header::CONTENT_ENCODING);
    let content_length = header_text(header::CONTENT_LENGTH).and_then(|v| v.trim().parse::<u64>().ok());
    let disposition_name = header_text(header::CONTENT_DISPOSITION)
        .and_then(|v| filter::file_name_from_content_disposition(&v));
    let file_name: Option<String> = disposition_name.or_else(|| request_file.map(|n| n.to_string()));

    let info = ResponseInfo {
        host: &target.host,
        client_ip: Some(peer.ip()),
        server_ip: Some(target.ip),
        status: parts.status.as_u16(),
        content_type: content_type.as_deref(),
        content_length,
        content_encoding: content_encoding.as_deref(),
        file_name: file_name.as_deref(),
    };

    let max = max_scan_bytes(&snapshot.settings);
    let plan = filter::plan(&info, &snapshot.exceptions, max);

    let context = |size: u64| ScanEventContext {
        client_ip: peer.ip().to_string(),
        host: target.host.clone(),
        url: format!("http://{}{}", target.host, target.path_and_query)
            .chars()
            .take(500)
            .collect(),
        file_name: file_name.clone(),
        file_size: size,
    };

    match plan {
        ScanPlan::Skip(_) => Ok(forward(parts, body)),

        ScanPlan::Oversize => {
            let block = snapshot.settings.over_size_action == "block";
            let outcome = ScannerOutcome {
                action: if block { ScanAction::Block } else { ScanAction::Allow },
                infected: false,
                signature: None,
                reason: "File exceeds maximum scanning size".to_string(),
                scanned: false,
            };

            health::count_outcome(&outcome);
            let _ = record_scan_event(&shared.db, context(content_length.unwrap_or(0)), &outcome).await;

            if block {
                Ok(block_page(&outcome))
            } else {
                Ok(forward(parts, body))
            }
        }

        ScanPlan::Unscannable => {
            let closed = fail_closed(&snapshot.settings);
            let outcome = ScannerOutcome {
                action: if closed { ScanAction::Block } else { ScanAction::Allow },
                infected: false,
                signature: None,
                reason: "Antivirus scanning failed: the response is compressed or partial".to_string(),
                scanned: false,
            };

            health::count_outcome(&outcome);
            let _ = record_scan_event(&shared.db, context(content_length.unwrap_or(0)), &outcome).await;

            if closed {
                Ok(block_page(&outcome))
            } else {
                Ok(forward(parts, body))
            }
        }

        ScanPlan::Buffer => Ok(scan_buffered(shared, &snapshot, context(0), parts, body).await),

        ScanPlan::Stream => {
            let scan = match start_stream_scan(&shared.db).await {
                Ok(Some(scan)) => scan,
                Ok(None) => return Ok(forward(parts, body)),
                Err(e) => {
                    eprintln!("AV proxy: cannot start streaming scan: {e}");
                    if fail_closed(&snapshot.settings) {
                        return Ok(page(
                            StatusCode::BAD_GATEWAY,
                            "Antivirus unavailable",
                            "The file could not be scanned.",
                        ));
                    }
                    return Ok(forward(parts, body));
                }
            };

            let permit = match shared.permits.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => return Ok(forward(parts, body)),
            };

            let (tx, rx) = mpsc::channel::<Result<Bytes, io::Error>>(8);

            tokio::spawn(pump_stream(
                body,
                scan,
                tx,
                shared.db.clone(),
                context(0),
                permit,
            ));

            let mut parts = parts;
            strip_hop_by_hop(&mut parts.headers);

            Ok(Response::from_parts(
                parts,
                ChannelBody { rx }.boxed_unsync(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// the three ways a body is handled
// ---------------------------------------------------------------------------

/// Hold the whole file, scan it (with the cache), then release or block it.
async fn scan_buffered(
    shared: &Arc<Shared>,
    snapshot: &Snapshot,
    mut context: ScanEventContext,
    parts: Parts,
    mut body: Incoming,
) -> Response<RespBody> {
    let max = max_scan_bytes(&snapshot.settings) as usize;

    let Ok(_permit) = shared.permits.acquire().await else {
        return forward(parts, body);
    };

    let mut data: Vec<u8> = Vec::new();

    loop {
        match timeout(IDLE_TIMEOUT, body.frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Ok(chunk) = frame.into_data() {
                    data.extend_from_slice(&chunk);

                    // Unknown length and it turned out to be too big.
                    if data.len() > max {
                        let block = snapshot.settings.over_size_action == "block";
                        let outcome = ScannerOutcome {
                            action: if block { ScanAction::Block } else { ScanAction::Allow },
                            infected: false,
                            signature: None,
                            reason: "File exceeds maximum scanning size".to_string(),
                            scanned: false,
                        };

                        health::count_outcome(&outcome);
                        context.file_size = data.len() as u64;
                        let _ = record_scan_event(&shared.db, context, &outcome).await;

                        if block {
                            return block_page(&outcome);
                        }
                        return forward_with_prefix(parts, data, body);
                    }
                }
            }
            Ok(Some(Err(_))) | Err(_) => {
                return page(
                    StatusCode::BAD_GATEWAY,
                    "Download interrupted",
                    "The server stopped sending data.",
                );
            }
            Ok(None) => break,
        }
    }

    match scan_and_record_cached(&shared.db, &shared.cache, context, &data).await {
        Ok(outcome) => {
            health::count_outcome(&outcome);

            if outcome.action == ScanAction::Block {
                block_page(&outcome)
            } else {
                let mut parts = parts;
                strip_hop_by_hop(&mut parts.headers);
                Response::from_parts(parts, full(data))
            }
        }
        Err(e) => {
            eprintln!("AV proxy: scan bookkeeping failed: {e}");

            if fail_closed(&snapshot.settings) {
                page(
                    StatusCode::BAD_GATEWAY,
                    "Antivirus unavailable",
                    "The file could not be scanned.",
                )
            } else {
                let mut parts = parts;
                strip_hop_by_hop(&mut parts.headers);
                Response::from_parts(parts, full(data))
            }
        }
    }
}

/// Feed the download to the client as it arrives, with the tail held back
/// until clamd has judged the whole file.
async fn pump_stream(
    mut body: Incoming,
    mut scan: StreamingScan,
    tx: mpsc::Sender<Result<Bytes, io::Error>>,
    db: SqlitePool,
    mut context: ScanEventContext,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    let aborted = || io::Error::other("download blocked by antivirus");

    loop {
        match timeout(IDLE_TIMEOUT, body.frame()).await {
            Ok(Some(Ok(frame))) => {
                let Ok(chunk) = frame.into_data() else { continue };

                match scan.push(&chunk).await {
                    Push::Send(bytes) => {
                        if !bytes.is_empty() && tx.send(Ok(Bytes::from(bytes))).await.is_err() {
                            return; // the client went away
                        }
                    }
                    Push::Block(outcome) => {
                        context.file_size = scan.total_bytes() as u64;
                        health::count_outcome(&outcome);
                        let _ = record_scan_event(&db, context, &outcome).await;
                        let _ = tx.send(Err(aborted())).await;
                        return;
                    }
                }
            }
            Ok(Some(Err(e))) => {
                let _ = tx.send(Err(io::Error::other(e))).await;
                return;
            }
            Err(_) => {
                let _ = tx
                    .send(Err(io::Error::new(io::ErrorKind::TimedOut, "server stopped sending")))
                    .await;
                return;
            }
            Ok(None) => break,
        }
    }

    context.file_size = scan.total_bytes() as u64;

    match scan.finish().await {
        Finish::Send(tail, outcome) => {
            health::count_outcome(&outcome);
            let _ = record_scan_event(&db, context, &outcome).await;

            if !tail.is_empty() {
                let _ = tx.send(Ok(Bytes::from(tail))).await;
            }
            // dropping `tx` ends the body normally
        }
        Finish::Block(outcome) => {
            health::count_outcome(&outcome);
            let _ = record_scan_event(&db, context, &outcome).await;
            let _ = tx.send(Err(aborted())).await;
        }
    }
}

/// Send what was already collected, then the rest of the body untouched.
fn forward_with_prefix(parts: Parts, prefix: Vec<u8>, mut body: Incoming) -> Response<RespBody> {
    let (tx, rx) = mpsc::channel::<Result<Bytes, io::Error>>(8);

    tokio::spawn(async move {
        if tx.send(Ok(Bytes::from(prefix))).await.is_err() {
            return;
        }

        loop {
            match timeout(IDLE_TIMEOUT, body.frame()).await {
                Ok(Some(Ok(frame))) => {
                    if let Ok(chunk) = frame.into_data() {
                        if tx.send(Ok(chunk)).await.is_err() {
                            return;
                        }
                    }
                }
                Ok(Some(Err(e))) => {
                    let _ = tx.send(Err(io::Error::other(e))).await;
                    return;
                }
                Err(_) => {
                    let _ = tx
                        .send(Err(io::Error::new(io::ErrorKind::TimedOut, "server stopped sending")))
                        .await;
                    return;
                }
                Ok(None) => return,
            }
        }
    });

    let mut parts = parts;
    strip_hop_by_hop(&mut parts.headers);
    Response::from_parts(parts, ChannelBody { rx }.boxed_unsync())
}

// ---------------------------------------------------------------------------
// bodies and pages
// ---------------------------------------------------------------------------

/// A body fed from a channel. An `Err` item aborts the client connection,
/// which is how a blocked download is cut off mid-way.
struct ChannelBody {
    rx: mpsc::Receiver<Result<Bytes, io::Error>>,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn full(data: Vec<u8>) -> RespBody {
    Full::new(Bytes::from(data))
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn forward(parts: Parts, body: Incoming) -> Response<RespBody> {
    let mut parts = parts;
    strip_hop_by_hop(&mut parts.headers);

    Response::from_parts(parts, body.map_err(io::Error::other).boxed_unsync())
}

fn html_escape(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            c if c.is_control() => " ".to_string(),
            c => c.to_string(),
        })
        .collect()
}

fn page(status: StatusCode, title: &str, message: &str) -> Response<RespBody> {
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title>\
         <style>body{{font-family:sans-serif;max-width:40em;margin:4em auto;padding:0 1em}}</style>\
         </head><body><h1>{title}</h1><p>{message}</p><hr><small>IQSOFT Firewall</small></body></html>",
        title = html_escape(title),
        message = html_escape(message),
    );

    let mut response = Response::new(full(html.into_bytes()));
    *response.status_mut() = status;

    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::CONNECTION, HeaderValue::from_static("close"));

    response
}

fn block_page(outcome: &ScannerOutcome) -> Response<RespBody> {
    if outcome.infected {
        let name = outcome.signature.as_deref().unwrap_or("unknown");
        page(
            StatusCode::FORBIDDEN,
            "Download blocked",
            &format!("The antivirus found malware in this file ({name}). It was not delivered."),
        )
    } else {
        page(
            StatusCode::FORBIDDEN,
            "Download blocked",
            &format!("This file was blocked because it could not be checked: {}.", outcome.reason),
        )
    }
}

// ---------------------------------------------------------------------------
// request helpers
// ---------------------------------------------------------------------------

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
}

/// Extensions of things that are plain web content. Requests for anything
/// else that has an extension (setup.exe, download.php, a.zip...) are made
/// without compression or ranges, so the whole file can be scanned.
const PLAIN_WEB_EXTENSIONS: &[&str] = &[
    "html", "htm", "css", "js", "mjs", "json", "map", "txt", "xml", "svg", "ico", "png", "jpg",
    "jpeg", "gif", "webp", "avif", "woff", "woff2", "ttf", "otf", "mp4", "webm", "mp3", "m4a",
    "ogg", "m3u8", "ts",
];

fn needs_whole_file(file_name: Option<&str>) -> bool {
    let Some(name) = file_name else { return false };
    let Some((_, ext)) = name.rsplit_once('.') else { return false };

    let ext = ext.to_ascii_lowercase();
    !ext.is_empty() && !PLAIN_WEB_EXTENSIONS.contains(&ext.as_str())
}

/// Addresses the proxy must never connect to: loopback, link-local, multicast,
/// and anything that belongs to this machine (binding to an address only
/// works when it is local). Without this a LAN client could use the proxy to
/// reach the firewall's own management interface.
fn is_forbidden(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }

    if let IpAddr::V4(v4) = ip {
        if v4.is_link_local() || v4.is_broadcast() {
            return true;
        }
    }

    std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok()
}

async fn resolve_host(host: &str, port: u16) -> Option<IpAddr> {
    let found = timeout(Duration::from_secs(5), tokio::net::lookup_host((host, port)))
        .await
        .ok()?
        .ok()?;

    let list: Vec<SocketAddr> = found.collect();

    list.iter()
        .find(|a| a.is_ipv4())
        .or_else(|| list.first())
        .map(|a| a.ip())
}

async fn resolve_target(
    uri: &Uri,
    headers: &HeaderMap,
    local: SocketAddr,
    original: Option<SocketAddr>,
) -> Result<Target, Response<RespBody>> {
    let path_and_query = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    let (host, ip, port) = if let Some(authority) = uri.authority() {
        // Explicit proxy request: "GET http://host/path".
        if let Some(scheme) = uri.scheme_str() {
            if !scheme.eq_ignore_ascii_case("http") {
                return Err(page(
                    StatusCode::BAD_REQUEST,
                    "Not supported",
                    "Only plain http:// addresses can go through this proxy.",
                ));
            }
        }

        let host = authority.host().to_string();
        let port = authority.port_u16().unwrap_or(80);

        let ip = match host.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => resolve_host(&host, port).await.ok_or_else(|| {
                page(
                    StatusCode::BAD_GATEWAY,
                    "Cannot find the server",
                    &format!("The name {host} could not be resolved."),
                )
            })?,
        };

        (host, ip, port)
    } else {
        // Transparent request: the original destination comes from nftables.
        let destination = match original {
            Some(d) if d != local => d,
            _ => {
                return Err(page(
                    StatusCode::BAD_REQUEST,
                    "This is a web proxy",
                    "Use it as an HTTP proxy, or through the firewall's transparent redirect.",
                ))
            }
        };

        let host = headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string())
            .unwrap_or_else(|| destination.ip().to_string());

        (host, destination.ip(), destination.port())
    };

    if is_forbidden(ip) {
        return Err(page(
            StatusCode::FORBIDDEN,
            "Address not allowed",
            "The proxy does not connect to the firewall itself or to local addresses.",
        ));
    }

    Ok(Target {
        host,
        ip,
        port,
        path_and_query,
    })
}

fn build_upstream_request(
    req: Request<Incoming>,
    target: &Target,
    file_name: Option<&str>,
) -> Result<Request<Incoming>, Response<RespBody>> {
    let (mut parts, body) = req.into_parts();

    let uri: Uri = format!(
        "http://{}{}",
        SocketAddr::new(target.ip, target.port),
        target.path_and_query
    )
    .parse()
    .map_err(|_| {
        page(
            StatusCode::BAD_REQUEST,
            "Bad request",
            "The requested address is not valid.",
        )
    })?;

    parts.uri = uri;
    parts.version = Version::HTTP_11;

    strip_hop_by_hop(&mut parts.headers);

    if needs_whole_file(file_name) {
        parts.headers.remove(header::ACCEPT_ENCODING);
        parts.headers.remove(header::RANGE);
        parts.headers.remove(header::IF_RANGE);
    }

    if !parts.headers.contains_key(header::HOST) {
        if let Ok(value) = HeaderValue::from_str(&target.host) {
            parts.headers.insert(header::HOST, value);
        }
    }

    Ok(Request::from_parts(parts, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_and_local_addresses_are_forbidden() {
        assert!(is_forbidden("127.0.0.1".parse().unwrap()));
        assert!(is_forbidden("0.0.0.0".parse().unwrap()));
        assert!(is_forbidden("169.254.1.1".parse().unwrap()));
        assert!(is_forbidden("224.0.0.1".parse().unwrap()));
        assert!(is_forbidden("::1".parse().unwrap()));
    }

    #[test]
    fn public_addresses_are_allowed() {
        assert!(!is_forbidden("8.8.8.8".parse().unwrap()));
        assert!(!is_forbidden("203.0.113.7".parse().unwrap()));
    }

    #[test]
    fn whole_file_requests_are_chosen_by_extension() {
        assert!(needs_whole_file(Some("setup.exe")));
        assert!(needs_whole_file(Some("download.php")));
        assert!(needs_whole_file(Some("archive.ZIP")));
        assert!(!needs_whole_file(Some("style.css")));
        assert!(!needs_whole_file(Some("clip.mp4")));
        assert!(!needs_whole_file(Some("noextension")));
        assert!(!needs_whole_file(None));
    }

    #[test]
    fn hop_by_hop_headers_are_removed() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("keep-alive"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        headers.insert("content-type", HeaderValue::from_static("text/plain"));

        strip_hop_by_hop(&mut headers);

        assert!(!headers.contains_key("connection"));
        assert!(!headers.contains_key("transfer-encoding"));
        assert!(headers.contains_key("content-type"));
    }

    #[test]
    fn pages_escape_what_they_show() {
        assert_eq!(html_escape("<b>\"x\" & 'y'</b>"), "&lt;b&gt;&quot;x&quot; &amp; &#39;y&#39;&lt;/b&gt;");
    }

    #[test]
    fn block_page_names_the_malware() {
        let outcome = ScannerOutcome {
            action: ScanAction::Block,
            infected: true,
            signature: Some("Eicar-Test-Signature".into()),
            reason: "Malware detected".into(),
            scanned: true,
        };

        let response = block_page(&outcome);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
