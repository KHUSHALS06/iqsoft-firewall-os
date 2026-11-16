// The L7 app control catalog: a fixed list of well-known apps, each mapped to
// the domain names the SNI filter should look for.
//
// The catalog itself lives in code, because it is the same on every box and
// ships with each new version. Only the person's choice per app ("block" or
// "allow") is stored in the database.
//
// No network code lives here, so everything in this file is easy to test.

use serde::{Deserialize, Serialize};

/// One ready-made app in the catalog.
pub struct AppDefinition {
    /// Short stable name used in URLs and in the database, e.g. "whatsapp".
    pub id: &'static str,
    /// Name shown to people, e.g. "WhatsApp".
    pub name: &'static str,
    /// Group for the screen, e.g. "Messaging".
    pub category: &'static str,
    /// A rule for example.com also covers www.example.com and every other
    /// subdomain, so only the main names are listed here.
    pub domains: &'static [&'static str],
    /// A short honest warning when blocking by site name cannot be complete.
    pub note: Option<&'static str>,
}

pub const CATALOG: &[AppDefinition] = &[
    AppDefinition {
        id: "facebook",
        name: "Facebook",
        category: "Social media",
        domains: &[
            "facebook.com",
            "facebook.net",
            "fbcdn.net",
            "fbsbx.com",
            "fb.com",
            "fb.me",
        ],
        note: None,
    },
    AppDefinition {
        id: "whatsapp",
        name: "WhatsApp",
        category: "Messaging",
        domains: &["whatsapp.com", "whatsapp.net", "wa.me"],
        note: Some("Calls and the phone app can fall back to direct IP connections that carry no site name."),
    },
    AppDefinition {
        id: "zoom",
        name: "Zoom",
        category: "Video meetings",
        domains: &["zoom.us", "zoom.com", "zoomgov.com"],
        note: Some("Zoom media can use UDP; the meeting sign-in and web client are what get blocked."),
    },
    AppDefinition {
        id: "teams",
        name: "Microsoft Teams",
        category: "Video meetings",
        domains: &[
            "teams.microsoft.com",
            "teams.live.com",
            "teams.cdn.office.net",
            "lync.com",
        ],
        note: None,
    },
    AppDefinition {
        id: "netflix",
        name: "Netflix",
        category: "Streaming",
        domains: &[
            "netflix.com",
            "netflix.net",
            "nflxvideo.net",
            "nflximg.net",
            "nflximg.com",
            "nflxext.com",
            "nflxso.net",
        ],
        note: None,
    },
    AppDefinition {
        id: "youtube",
        name: "YouTube",
        category: "Streaming",
        domains: &[
            "youtube.com",
            "youtu.be",
            "youtube-nocookie.com",
            "googlevideo.com",
            "ytimg.com",
        ],
        note: Some("Turn on \"Block QUIC\" too, otherwise browsers can reach YouTube over HTTP/3, which hides the site name."),
    },
    AppDefinition {
        id: "telegram",
        name: "Telegram",
        category: "Messaging",
        domains: &[
            "telegram.org",
            "telegram.me",
            "t.me",
            "telegra.ph",
            "tdesktop.com",
            "telesco.pe",
        ],
        note: Some("The mobile app often connects straight to Telegram IP addresses with no site name."),
    },
    AppDefinition {
        id: "steam",
        name: "Steam",
        category: "Gaming",
        domains: &[
            "steampowered.com",
            "steamcommunity.com",
            "steamstatic.com",
            "steamcontent.com",
            "steamgames.com",
            "steamusercontent.com",
        ],
        note: None,
    },
    AppDefinition {
        id: "bittorrent",
        name: "BitTorrent",
        category: "File sharing",
        domains: &[
            "bittorrent.com",
            "utorrent.com",
            "thepiratebay.org",
            "1337x.to",
            "nyaa.si",
            "opentrackr.org",
        ],
        note: Some("Only the client download sites, well-known torrent sites and HTTPS trackers are blocked. Peer-to-peer traffic itself has no site name."),
    },
    AppDefinition {
        id: "dropbox",
        name: "Dropbox",
        category: "Cloud storage",
        domains: &[
            "dropbox.com",
            "dropboxstatic.com",
            "dropboxusercontent.com",
            "dropboxapi.com",
            "db.tt",
        ],
        note: None,
    },
    AppDefinition {
        id: "gmail",
        name: "Gmail",
        category: "Email",
        domains: &["mail.google.com", "gmail.com", "googlemail.com"],
        note: Some("Only the Gmail website and web app. Mail apps that use IMAP or SMTP are not covered."),
    },
];

/// What the API sends to the screen for one app: the catalog entry plus the
/// person's current choice.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct AppEntry {
    pub id: String,
    pub name: String,
    pub category: String,
    pub domains: Vec<String>,
    /// "block", "allow", or "default" (no choice made, the app is not managed).
    pub action: String,
    pub note: Option<String>,
}

/// What the screen sends to change one app.
#[derive(Debug, Deserialize, Clone)]
pub struct AppActionRequest {
    pub action: String,
}

impl AppEntry {
    pub fn from_definition(app: &AppDefinition, action: &str) -> Self {
        Self {
            id: app.id.to_string(),
            name: app.name.to_string(),
            category: app.category.to_string(),
            domains: app.domains.iter().map(|d| d.to_string()).collect(),
            action: action.to_string(),
            note: app.note.map(|n| n.to_string()),
        }
    }
}

/// Finds an app by its id, ignoring capital letters and spaces around it.
pub fn find_app(id: &str) -> Option<&'static AppDefinition> {
    let id = id.trim().to_ascii_lowercase();

    CATALOG.iter().find(|app| app.id == id)
}

/// "block" stops the app, "allow" lets it through even if a DNS filter list
/// blocks it, and "default" removes the choice again.
pub fn normalize_app_action(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "block" => Some("block"),
        "allow" => Some("allow"),
        "default" => Some("default"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::dnsfilter::normalize_domain;
    use std::collections::HashSet;

    #[test]
    fn the_catalog_has_every_preset_app() {
        for id in [
            "facebook", "whatsapp", "zoom", "teams", "netflix", "youtube", "telegram", "steam",
            "bittorrent", "dropbox", "gmail",
        ] {
            assert!(find_app(id).is_some(), "missing app {}", id);
        }

        assert_eq!(CATALOG.len(), 11);
    }

    #[test]
    fn ids_are_unique_and_clean() {
        let mut seen = HashSet::new();

        for app in CATALOG {
            assert!(seen.insert(app.id), "duplicate id {}", app.id);
            assert!(
                app.id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "bad id {}",
                app.id
            );
            assert!(!app.name.is_empty());
            assert!(!app.category.is_empty());
        }
    }

    #[test]
    fn every_domain_is_already_clean_and_has_an_owner() {
        let mut owners: Vec<(&str, &str)> = Vec::new();

        for app in CATALOG {
            assert!(!app.domains.is_empty(), "{} has no domains", app.id);

            for domain in app.domains {
                assert_eq!(
                    normalize_domain(domain).as_deref(),
                    Some(*domain),
                    "unclean domain {} in {}",
                    domain,
                    app.id
                );
                owners.push((domain, app.id));
            }
        }

        // The same domain in two apps would make one app's choice silently win.
        let mut seen = HashSet::new();
        for (domain, app) in owners {
            assert!(seen.insert(domain), "{} is listed twice (again in {})", domain, app);
        }
    }

    #[test]
    fn finding_an_app_ignores_case_and_spaces() {
        assert_eq!(find_app(" WhatsApp ").unwrap().id, "whatsapp");
        assert!(find_app("myspace").is_none());
        assert!(find_app("").is_none());
    }

    #[test]
    fn actions_are_normalized_or_refused() {
        assert_eq!(normalize_app_action(" BLOCK "), Some("block"));
        assert_eq!(normalize_app_action("Allow"), Some("allow"));
        assert_eq!(normalize_app_action("default"), Some("default"));
        assert_eq!(normalize_app_action("deny"), None);
        assert_eq!(normalize_app_action(""), None);
    }

    #[test]
    fn an_entry_carries_the_choice_and_the_catalog_data() {
        let entry = AppEntry::from_definition(find_app("youtube").unwrap(), "block");

        assert_eq!(entry.id, "youtube");
        assert_eq!(entry.name, "YouTube");
        assert_eq!(entry.action, "block");
        assert!(entry.domains.contains(&"googlevideo.com".to_string()));
        assert!(entry.note.is_some());
    }

    #[test]
    fn the_action_request_needs_an_action() {
        let ok: AppActionRequest = serde_json::from_str(r#"{"action":"block"}"#).unwrap();
        assert_eq!(ok.action, "block");

        assert!(serde_json::from_str::<AppActionRequest>("{}").is_err());
    }
}
