use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

fn default_no_name_action() -> String {
    "allow".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SniSettings {
    #[serde(default)]
    pub enabled: bool,

    /// Also block what the enabled DNS filter categories and rules block.
    #[serde(default = "default_true")]
    pub use_dns_filter_lists: bool,

    /// What to do with a handshake that has no site name: "allow" or "block".
    #[serde(default = "default_no_name_action")]
    pub no_name_action: String,

    /// Block handshakes that are broken or use tricks to hide the name.
    #[serde(default = "default_true")]
    pub block_malformed: bool,

    /// Drop UDP 443 (QUIC / HTTP3) so browsers fall back to HTTPS we can read.
    #[serde(default)]
    pub block_quic: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SniRule {
    pub id: Option<i64>,

    pub domain: String,

    /// "block" or "allow"
    pub action: String,

    pub comment: Option<String>,
}

pub fn normalize_no_name_action(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "allow" => Some("allow"),
        "block" => Some("block"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_defaults_are_safe() {
        let settings: SniSettings = serde_json::from_str("{}").unwrap();

        assert!(!settings.enabled);
        assert!(settings.use_dns_filter_lists);
        assert_eq!(settings.no_name_action, "allow");
        assert!(settings.block_malformed);
        assert!(!settings.block_quic);
    }

    #[test]
    fn json_fields_can_be_set() {
        let settings: SniSettings = serde_json::from_str(
            r#"{"enabled":true,"use_dns_filter_lists":false,"no_name_action":"block","block_malformed":false,"block_quic":true}"#,
        )
        .unwrap();

        assert!(settings.enabled);
        assert!(!settings.use_dns_filter_lists);
        assert_eq!(settings.no_name_action, "block");
        assert!(!settings.block_malformed);
        assert!(settings.block_quic);
    }

    #[test]
    fn no_name_action_is_normalized_or_refused() {
        assert_eq!(normalize_no_name_action(" ALLOW "), Some("allow"));
        assert_eq!(normalize_no_name_action("Block"), Some("block"));
        assert_eq!(normalize_no_name_action("maybe"), None);
        assert_eq!(normalize_no_name_action(""), None);
    }

    #[test]
    fn rules_need_a_domain_and_action_but_not_a_comment() {
        let rule: SniRule = serde_json::from_str(r#"{"domain":"tiktok.com","action":"block"}"#).unwrap();

        assert_eq!(rule.id, None);
        assert_eq!(rule.domain, "tiktok.com");
        assert_eq!(rule.action, "block");
        assert!(rule.comment.is_none());

        assert!(serde_json::from_str::<SniRule>(r#"{"action":"block"}"#).is_err());
        assert!(serde_json::from_str::<SniRule>(r#"{"domain":"tiktok.com"}"#).is_err());
    }
}
