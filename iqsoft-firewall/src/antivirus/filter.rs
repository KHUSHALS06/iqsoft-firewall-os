//! Decide what needs scanning, and how (option 2).
//!
//! Most web traffic (images, video, CSS, JSON...) cannot carry malware that
//! ClamAV would detect, so it is skipped and never delayed. What is left is
//! split into:
//!
//! * `Buffer`: hold the whole file, scan it, then release it. Used for
//!   executables, installers, archives, scripts, macro/legacy Office files
//!   and anything unknown or unlabelled (default-deny).
//! * `Stream`: large PDFs and modern Office/OpenDocument files can use the
//!   held-back-tail streaming scan (see `stream.rs`). A truncated copy of
//!   these is normally unusable, and they are big enough to be worth it.
//!
//! Notes for the proxy:
//! * `Unscannable` means "this must be scanned but cannot be scanned as-is"
//!   (compressed body, partial-content response). Treat it like a scan error:
//!   block when fail mode is closed. Remove `Accept-Encoding` and `Range`
//!   from requests so servers rarely answer that way.
//! * `Oversize` means the declared size already exceeds the limit. Apply the
//!   over-size action without downloading anything.
//! * Domain exceptions match the Host the client asked for. A compromised
//!   client can fake that, so in transparent mode also prefer to match the
//!   original destination address.
//! * `.js` is deliberately not treated as an executable: it would make every
//!   website script wait for a scan. A script download is usually served as
//!   `application/octet-stream`, which is scanned.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::models::av::AvException;

/// Files at least this large (and Document class) use the streaming scan.
pub const STREAM_THRESHOLD_BYTES: u64 = 5 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    Exception,
    SafeType,
    NotScannableStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanPlan {
    Skip(SkipReason),
    Buffer,
    Stream,
    Oversize,
    Unscannable,
}

#[derive(Debug, Clone)]
pub struct ResponseInfo<'a> {
    pub host: &'a str,
    pub client_ip: Option<IpAddr>,
    pub server_ip: Option<IpAddr>,
    pub status: u16,
    pub content_type: Option<&'a str>,
    pub content_length: Option<u64>,
    pub content_encoding: Option<&'a str>,
    /// From Content-Disposition, or the last part of the URL path.
    pub file_name: Option<&'a str>,
}

/// The AV exception list, parsed once (rebuild it when settings change).
#[derive(Debug, Clone, Default)]
pub struct ExceptionSet {
    domains: Vec<String>,
    nets: Vec<IpNet>,
}

impl ExceptionSet {
    pub fn new(exceptions: &[AvException]) -> Self {
        let mut domains = Vec::new();
        let mut nets = Vec::new();

        for exception in exceptions {
            match exception.kind.as_str() {
                "domain" => domains.push(
                    exception
                        .value
                        .trim()
                        .trim_end_matches('.')
                        .to_ascii_lowercase(),
                ),
                "cidr" => {
                    if let Ok(net) = exception.value.trim().parse::<IpNet>() {
                        nets.push(net);
                    }
                }
                _ => {}
            }
        }

        Self { domains, nets }
    }

    pub fn matches(
        &self,
        host: &str,
        client_ip: Option<IpAddr>,
        server_ip: Option<IpAddr>,
    ) -> bool {
        let host = host_without_port(host.trim())
            .trim_end_matches('.')
            .to_ascii_lowercase();

        if self.domains.iter().any(|d| domain_matches(&host, d)) {
            return true;
        }

        [client_ip, server_ip]
            .into_iter()
            .flatten()
            .any(|ip| self.nets.iter().any(|net| net.contains(&ip)))
    }
}

fn host_without_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host; // IPv6 literal
    }

    match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => name,
        _ => host,
    }
}

/// `example.com` matches `example.com` and `a.example.com`, not `notexample.com`.
fn domain_matches(host: &str, domain: &str) -> bool {
    if host == domain {
        return true;
    }

    host.len() > domain.len()
        && host.ends_with(domain)
        && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Safe,
    Strict,
    Document,
}

const SAFE_MIME_PREFIXES: &[&str] = &["image/", "audio/", "video/", "font/"];

const SAFE_MIME_EXACT: &[&str] = &[
    "text/css",
    "text/html",
    "text/plain",
    "text/javascript",
    "text/xml",
    "application/javascript",
    "application/x-javascript",
    "application/json",
    "application/ld+json",
    "application/manifest+json",
    "application/xml",
    "application/font-woff",
    "application/font-woff2",
    "application/x-font-ttf",
    "application/vnd.ms-fontobject",
];

const DOCUMENT_MIME_EXACT: &[&str] = &["application/pdf"];

const DOCUMENT_MIME_PREFIXES: &[&str] = &[
    "application/vnd.openxmlformats-officedocument",
    "application/vnd.oasis.opendocument",
];

/// Always fully buffered, whatever the Content-Type says.
const STRICT_EXTENSIONS: &[&str] = &[
    "exe", "dll", "msi", "msp", "scr", "com", "bat", "cmd", "ps1", "vbs", "vbe", "jse", "wsf",
    "wsh", "hta", "lnk", "cpl", "jar", "apk", "dmg", "pkg", "deb", "rpm", "iso", "img", "vhd",
    "vhdx", "zip", "rar", "7z", "gz", "tgz", "bz2", "xz", "tar", "cab", "sh", "bin", "run",
    "appimage", "msix", "appx",
    // Macro-enabled and legacy Office formats, and RTF.
    "docm", "dotm", "xlsm", "xlam", "pptm", "doc", "dot", "xls", "ppt", "rtf",
];

const DOCUMENT_EXTENSIONS: &[&str] = &["pdf", "docx", "xlsx", "pptx", "odt", "ods", "odp"];

fn mime_essence(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

fn extension(file_name: &str) -> Option<String> {
    let (_, ext) = file_name.rsplit_once('.')?;

    if ext.is_empty() || ext.len() > 10 {
        return None;
    }

    Some(ext.to_ascii_lowercase())
}

fn classify(content_type: Option<&str>, file_name: Option<&str>) -> Class {
    // The extension wins over the Content-Type, so an .exe sent as image/png
    // is still treated as an executable.
    if let Some(ext) = file_name.and_then(extension) {
        if STRICT_EXTENSIONS.contains(&ext.as_str()) {
            return Class::Strict;
        }
        if DOCUMENT_EXTENSIONS.contains(&ext.as_str()) {
            return Class::Document;
        }
    }

    let mime = match content_type {
        Some(value) => mime_essence(value),
        None => return Class::Strict,
    };

    if SAFE_MIME_PREFIXES.iter().any(|p| mime.starts_with(p))
        || SAFE_MIME_EXACT.contains(&mime.as_str())
    {
        return Class::Safe;
    }

    if DOCUMENT_MIME_EXACT.contains(&mime.as_str())
        || DOCUMENT_MIME_PREFIXES.iter().any(|p| mime.starts_with(p))
    {
        return Class::Document;
    }

    // Unknown, application/octet-stream, executables, archives...
    Class::Strict
}

fn is_identity(encoding: &str) -> bool {
    let encoding = encoding.trim();
    encoding.is_empty() || encoding.eq_ignore_ascii_case("identity")
}

pub fn plan(info: &ResponseInfo<'_>, exceptions: &ExceptionSet, max_scan_bytes: u64) -> ScanPlan {
    if exceptions.matches(info.host, info.client_ip, info.server_ip) {
        return ScanPlan::Skip(SkipReason::Exception);
    }

    let class = classify(info.content_type, info.file_name);

    if class == Class::Safe {
        return ScanPlan::Skip(SkipReason::SafeType);
    }

    match info.status {
        200 => {}
        // A partial response cannot be judged on its own.
        206 => return ScanPlan::Unscannable,
        _ => return ScanPlan::Skip(SkipReason::NotScannableStatus),
    }

    if let Some(length) = info.content_length {
        if length > max_scan_bytes {
            return ScanPlan::Oversize;
        }
    }

    if let Some(encoding) = info.content_encoding {
        if !is_identity(encoding) {
            return ScanPlan::Unscannable;
        }
    }

    match class {
        Class::Safe => ScanPlan::Skip(SkipReason::SafeType),
        Class::Strict => ScanPlan::Buffer,
        Class::Document => match info.content_length {
            Some(length) if length < STREAM_THRESHOLD_BYTES => ScanPlan::Buffer,
            // Large, or unknown length (chunked): stream, so memory stays small.
            _ => ScanPlan::Stream,
        },
    }
}

/// Last path segment of a request target, without query or fragment.
pub fn file_name_from_path(path_and_query: &str) -> Option<&str> {
    let path = path_and_query.split(['?', '#']).next()?;
    let name = path.rsplit('/').next()?;

    if name.is_empty() { None } else { Some(name) }
}

/// File name from a Content-Disposition header value, if it has one.
pub fn file_name_from_content_disposition(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();

    let (start, extended) = match lower.find("filename*=") {
        Some(i) => (i + "filename*=".len(), true),
        None => (lower.find("filename=")? + "filename=".len(), false),
    };

    let rest = value[start..].split(';').next()?.trim();
    let mut name = rest.trim_matches('"');

    if extended {
        // RFC 5987: charset'language'value
        name = name.rsplit('\'').next().unwrap_or(name);
    }

    // Keep only the final path component.
    let name = name.rsplit(['/', '\\']).next().unwrap_or(name).trim();

    if name.is_empty() { None } else { Some(name.to_string()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: u64 = 25 * 1024 * 1024;

    fn base() -> ResponseInfo<'static> {
        ResponseInfo {
            host: "example.com",
            client_ip: None,
            server_ip: None,
            status: 200,
            content_type: Some("application/octet-stream"),
            content_length: Some(1024),
            content_encoding: None,
            file_name: None,
        }
    }

    fn exceptions() -> ExceptionSet {
        ExceptionSet::new(&[
            AvException {
                id: None,
                kind: "domain".into(),
                value: "trusted.example".into(),
                comment: None,
            },
            AvException {
                id: None,
                kind: "cidr".into(),
                value: "10.9.0.0/16".into(),
                comment: None,
            },
        ])
    }

    #[test]
    fn web_assets_are_skipped() {
        for ct in ["image/png", "text/css", "application/json", "video/mp4; codecs=avc1", "text/html; charset=utf-8"] {
            let info = ResponseInfo { content_type: Some(ct), ..base() };
            assert_eq!(plan(&info, &ExceptionSet::default(), MAX), ScanPlan::Skip(SkipReason::SafeType), "{ct}");
        }
    }

    #[test]
    fn executables_and_unknown_types_are_buffered() {
        let info = base();
        assert_eq!(plan(&info, &ExceptionSet::default(), MAX), ScanPlan::Buffer);

        let info = ResponseInfo { content_type: None, ..base() };
        assert_eq!(plan(&info, &ExceptionSet::default(), MAX), ScanPlan::Buffer);

        let info = ResponseInfo { content_type: Some("application/zip"), ..base() };
        assert_eq!(plan(&info, &ExceptionSet::default(), MAX), ScanPlan::Buffer);
    }

    #[test]
    fn extension_beats_a_lying_content_type() {
        let info = ResponseInfo {
            content_type: Some("image/png"),
            file_name: Some("setup.EXE"),
            ..base()
        };
        assert_eq!(plan(&info, &ExceptionSet::default(), MAX), ScanPlan::Buffer);
    }

    #[test]
    fn documents_stream_only_when_large_or_unknown_length() {
        let small = ResponseInfo { content_type: Some("application/pdf"), content_length: Some(1024 * 1024), ..base() };
        assert_eq!(plan(&small, &ExceptionSet::default(), MAX), ScanPlan::Buffer);

        let large = ResponseInfo { content_type: Some("application/pdf"), content_length: Some(10 * 1024 * 1024), ..base() };
        assert_eq!(plan(&large, &ExceptionSet::default(), MAX), ScanPlan::Stream);

        let chunked = ResponseInfo { content_type: Some("application/pdf"), content_length: None, ..base() };
        assert_eq!(plan(&chunked, &ExceptionSet::default(), MAX), ScanPlan::Stream);
    }

    #[test]
    fn macro_and_legacy_office_files_are_never_streamed() {
        let info = ResponseInfo {
            content_type: Some("application/vnd.ms-excel"),
            content_length: Some(20 * 1024 * 1024),
            file_name: Some("report.xlsm"),
            ..base()
        };
        assert_eq!(plan(&info, &ExceptionSet::default(), MAX), ScanPlan::Buffer);
    }

    #[test]
    fn oversize_encoded_and_partial_responses() {
        let big = ResponseInfo { content_length: Some(MAX + 1), ..base() };
        assert_eq!(plan(&big, &ExceptionSet::default(), MAX), ScanPlan::Oversize);

        let gz = ResponseInfo { content_encoding: Some("gzip"), ..base() };
        assert_eq!(plan(&gz, &ExceptionSet::default(), MAX), ScanPlan::Unscannable);

        let identity = ResponseInfo { content_encoding: Some("identity"), ..base() };
        assert_eq!(plan(&identity, &ExceptionSet::default(), MAX), ScanPlan::Buffer);

        let partial = ResponseInfo { status: 206, ..base() };
        assert_eq!(plan(&partial, &ExceptionSet::default(), MAX), ScanPlan::Unscannable);

        let redirect = ResponseInfo { status: 302, ..base() };
        assert_eq!(plan(&redirect, &ExceptionSet::default(), MAX), ScanPlan::Skip(SkipReason::NotScannableStatus));
    }

    #[test]
    fn exceptions_match_domains_and_networks() {
        let set = exceptions();

        let info = ResponseInfo { host: "trusted.example", ..base() };
        assert_eq!(plan(&info, &set, MAX), ScanPlan::Skip(SkipReason::Exception));

        let info = ResponseInfo { host: "Cdn.Trusted.Example:8080", ..base() };
        assert_eq!(plan(&info, &set, MAX), ScanPlan::Skip(SkipReason::Exception));

        let info = ResponseInfo { host: "nottrusted.example", ..base() };
        assert_eq!(plan(&info, &set, MAX), ScanPlan::Buffer);

        let info = ResponseInfo { client_ip: Some("10.9.4.7".parse().unwrap()), ..base() };
        assert_eq!(plan(&info, &set, MAX), ScanPlan::Skip(SkipReason::Exception));

        let info = ResponseInfo { client_ip: Some("10.8.4.7".parse().unwrap()), ..base() };
        assert_eq!(plan(&info, &set, MAX), ScanPlan::Buffer);
    }

    #[test]
    fn file_name_helpers() {
        assert_eq!(file_name_from_path("/a/b/setup.exe?x=1#y"), Some("setup.exe"));
        assert_eq!(file_name_from_path("/a/b/"), None);

        assert_eq!(
            file_name_from_content_disposition("attachment; filename=\"invoice.pdf\"").as_deref(),
            Some("invoice.pdf")
        );
        assert_eq!(
            file_name_from_content_disposition("attachment; filename*=UTF-8''run%20me.exe").as_deref(),
            Some("run%20me.exe")
        );
        assert_eq!(
            file_name_from_content_disposition("attachment; filename=\"..\\..\\evil.exe\"").as_deref(),
            Some("evil.exe")
        );
        assert_eq!(file_name_from_content_disposition("inline"), None);
    }
}
