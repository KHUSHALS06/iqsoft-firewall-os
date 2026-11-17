use crate::{
    models::threatfeed::ThreatFeed,
    repository::threatfeed_repository::ThreatFeedRepository,
};
use ipnet::IpNet;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::Mutex;

/// The blocklists live in their own nftables table, so they can be replaced on their own
/// (after a download, an import, or switching a feed on or off) without touching the main ruleset.
/// The same text is also appended to every full firewall commit, because `flush ruleset` there removes it.
pub const TABLE_NAME: &str = "iqsoft_threat";

/// Runs before the main filter table (priority 0), so blocked addresses are dropped even on connections
/// that already exist.
const HOOK_PRIORITY: i32 = -10;

struct FeedBlock {
    id: i64,
    v4: Vec<String>,
    v6: Vec<String>,
    inbound: bool,
    outbound: bool,
    log_enabled: bool,
}

#[derive(Clone, Copy)]
enum Chain {
    Input,
    Forward,
    Output,
}

/// Re-checks every stored network at generation time and keeps only the ones that are
/// really networks of the wanted family.
fn clean_networks(raw: &[String], want_v6: bool) -> Vec<String> {
    raw.iter()
        .filter_map(|text| text.parse::<IpNet>().ok())
        .filter(|net| matches!(net, IpNet::V6(_)) == want_v6)
        .filter(|net| net.prefix_len() > 0)
        .map(|net| net.to_string())
        .collect()
}

async fn load_blocks(pool: &SqlitePool) -> Result<Vec<FeedBlock>, String> {
    let feeds: Vec<ThreatFeed> = ThreatFeedRepository::list_enabled_feeds(pool)
        .await
        .map_err(|e| e.to_string())?;

    let mut blocks = Vec::new();

    for feed in feeds {
        let Some(id) = feed.id else { continue };

        if !feed.blocks_inbound() && !feed.blocks_outbound() {
            continue;
        }

        let v4 = ThreatFeedRepository::list_networks(pool, id, "ipv4")
            .await
            .map_err(|e| e.to_string())?;
        let v6 = ThreatFeedRepository::list_networks(pool, id, "ipv6")
            .await
            .map_err(|e| e.to_string())?;

        let v4 = clean_networks(&v4, false);
        let v6 = clean_networks(&v6, true);

        // nftables refuses an empty set, and there is nothing to match anyway.
        if v4.is_empty() && v6.is_empty() {
            continue;
        }

        blocks.push(FeedBlock {
            id,
            v4,
            v6,
            inbound: feed.blocks_inbound(),
            outbound: feed.blocks_outbound(),
            log_enabled: feed.log_enabled,
        });
    }

    Ok(blocks)
}

fn write_sets(output: &mut String, blocks: &[FeedBlock]) {
    for block in blocks {
        for (family, addr_type, elements) in [
            ("v4", "ipv4_addr", &block.v4),
            ("v6", "ipv6_addr", &block.v6),
        ] {
            if elements.is_empty() {
                continue;
            }

            output.push_str(&format!("    set feed_{}_{} {{\n", block.id, family));
            output.push_str(&format!("        type {};\n", addr_type));
            output.push_str("        flags interval;\n");
            output.push_str("        auto-merge;\n");
            output.push_str(&format!(
                "        elements = {{ {} }}\n",
                elements.join(", ")
            ));
            output.push_str("    }\n\n");
        }
    }
}

/// Inbound feeds match the source address (INPUT and FORWARD), outbound feeds match the
/// destination address (FORWARD and OUTPUT).
fn write_chain(output: &mut String, blocks: &[FeedBlock], chain: Chain) {
    let (name, hook) = match chain {
        Chain::Input => ("input", "input"),
        Chain::Forward => ("forward", "forward"),
        Chain::Output => ("output", "output"),
    };

    output.push_str(&format!("    chain {} {{\n", name));
    output.push_str(&format!(
        "        type filter hook {} priority {};\n",
        hook, HOOK_PRIORITY
    ));
    output.push_str("        policy accept;\n");

    let mut first = true;

    for block in blocks {
        let (by_source, by_destination) = match chain {
            Chain::Input => (block.inbound, false),
            Chain::Forward => (block.inbound, block.outbound),
            Chain::Output => (false, block.outbound),
        };

        for (family, ip, elements) in [("v4", "ip", &block.v4), ("v6", "ip6", &block.v6)] {
            if elements.is_empty() {
                continue;
            }

            for (wanted, side) in [(by_source, "saddr"), (by_destination, "daddr")] {
                if !wanted {
                    continue;
                }

                if first {
                    output.push('\n');
                    first = false;
                }

                if block.log_enabled {
                    output.push_str(&format!(
                        "        {} {} @feed_{}_{} limit rate 6/minute log prefix \"iqsoft-threat-{}: \"\n",
                        ip, side, block.id, family, block.id
                    ));
                }

                output.push_str(&format!(
                    "        {} {} @feed_{}_{} counter drop comment \"iqsoft-threat-{}\"\n",
                    ip, side, block.id, family, block.id
                ));
            }
        }
    }

    output.push_str("    }\n");
}

/// The whole `table inet iqsoft_threat { ... }` block for every enabled feed that has networks,
/// or an empty string when there is nothing to block.
pub async fn generate_table(pool: &SqlitePool) -> Result<String, String> {
    let blocks = load_blocks(pool).await?;

    if blocks.is_empty() {
        return Ok(String::new());
    }

    let mut output = String::new();

    output.push_str(&format!("table inet {} {{\n\n", TABLE_NAME));

    write_sets(&mut output, &blocks);

    write_chain(&mut output, &blocks, Chain::Input);
    output.push('\n');
    write_chain(&mut output, &blocks, Chain::Forward);
    output.push('\n');
    write_chain(&mut output, &blocks, Chain::Output);

    output.push_str("}\n");

    Ok(output)
}

/// A script that replaces only this table: it is created if missing, deleted, and written again,
/// all in one nftables transaction. With nothing to block it just removes the table.
pub fn build_apply_script(table_text: &str) -> String {
    format!(
        "add table inet {t}\ndelete table inet {t}\n{body}",
        t = TABLE_NAME,
        body = table_text
    )
}

/// Replaces the blocklist table in the running kernel. Takes the commit lock, because a full
/// commit or a rollback does `flush ruleset` and the two must not interleave.
#[cfg(not(test))]
pub async fn apply_live(pool: &SqlitePool, lock: &Arc<Mutex<()>>) -> Result<(), String> {
    use std::process::Stdio;
    use tokio::{io::AsyncWriteExt, process::Command};

    let script = build_apply_script(&generate_table(pool).await?);

    let _guard = lock.lock().await;

    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("could not run nft: {}", e))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "could not open nft's input".to_string())?;

    stdin
        .write_all(script.as_bytes())
        .await
        .map_err(|e| format!("could not send the blocklists to nft: {}", e))?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("nft did not finish: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "nft refused the blocklists: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(())
}

/// Test builds never touch the kernel, even on a machine where nft is installed and allowed.
#[cfg(test)]
pub async fn apply_live(_pool: &SqlitePool, _lock: &Arc<Mutex<()>>) -> Result<(), String> {
    Err("nft is not touched in test builds".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::init::initialize_database,
        models::threatfeed::ParsedFeed,
    };
    use sqlx::sqlite::SqlitePoolOptions;

    async fn memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        initialize_database(&pool).await.unwrap();
        pool
    }

    fn feed(name: &str) -> ThreatFeed {
        ThreatFeed {
            id: None,
            name: name.to_string(),
            kind: "manual".to_string(),
            url: None,
            enabled: true,
            direction: "both".to_string(),
            refresh_hours: 6,
            log_enabled: false,
            comment: None,
            last_updated: None,
            last_attempt: None,
            last_error: None,
            ipv4_count: 0,
            ipv6_count: 0,
        }
    }

    async fn add_feed(pool: &SqlitePool, feed: ThreatFeed, v4: &[&str], v6: &[&str]) -> i64 {
        let id = ThreatFeedRepository::add_feed(pool, &feed).await.unwrap();

        let parsed = ParsedFeed {
            ipv4: v4.iter().map(|s| s.to_string()).collect(),
            ipv6: v6.iter().map(|s| s.to_string()).collect(),
            skipped: 0,
        };
        ThreatFeedRepository::replace_entries(pool, id, &parsed, 1).await.unwrap();

        id
    }

    fn nft_check(ruleset: &str) {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let required = std::env::var("IQSOFT_REQUIRE_NFT").is_ok();

        let Ok(mut child) = Command::new("nft")
            .args(["--check", "--file", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        else {
            assert!(!required, "nft is not installed but IQSOFT_REQUIRE_NFT is set");
            eprintln!("SKIPPED nft --check: nft not found");
            return;
        };

        child.stdin.take().unwrap().write_all(ruleset.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);

        if err.contains("Operation not permitted") {
            assert!(!required, "nft --check not permitted but IQSOFT_REQUIRE_NFT is set");
            eprintln!("SKIPPED nft --check: operation not permitted");
            return;
        }

        assert!(out.status.success(), "nft --check failed:\n{}\n{}", err, ruleset);
    }

    #[tokio::test]
    async fn no_feeds_means_no_output() {
        let pool = memory_pool().await;
        assert_eq!(generate_table(&pool).await.unwrap(), "");
    }

    #[tokio::test]
    async fn disabled_empty_and_directionless_feeds_are_left_out() {
        let pool = memory_pool().await;

        let mut off = feed("off");
        off.enabled = false;
        add_feed(&pool, off, &["1.2.3.4/32"], &[]).await;

        add_feed(&pool, feed("empty"), &[], &[]).await;

        assert_eq!(generate_table(&pool).await.unwrap(), "");
    }

    #[tokio::test]
    async fn a_two_way_feed_gets_sets_and_rules_in_all_three_chains() {
        let pool = memory_pool().await;
        let id = add_feed(&pool, feed("both"), &["1.2.3.4/32", "5.6.7.0/24"], &["2001:4860::/32"]).await;

        let text = generate_table(&pool).await.unwrap();

        assert!(text.starts_with("table inet iqsoft_threat {\n"));
        assert!(text.contains(&format!(
            "    set feed_{id}_v4 {{\n        type ipv4_addr;\n        flags interval;\n        auto-merge;\n        elements = {{ 1.2.3.4/32, 5.6.7.0/24 }}\n    }}\n"
        )));
        assert!(text.contains(&format!(
            "    set feed_{id}_v6 {{\n        type ipv6_addr;\n        flags interval;\n        auto-merge;\n        elements = {{ 2001:4860::/32 }}\n    }}\n"
        )));

        for chain in ["input", "forward", "output"] {
            assert!(
                text.contains(&format!("    chain {chain} {{\n        type filter hook {chain} priority -10;\n        policy accept;\n")),
                "{chain}"
            );
        }

        // input: source only, forward: both, output: destination only
        assert_eq!(text.matches(&format!("ip saddr @feed_{id}_v4 counter drop")).count(), 2);
        assert_eq!(text.matches(&format!("ip daddr @feed_{id}_v4 counter drop")).count(), 2);
        assert_eq!(text.matches(&format!("ip6 saddr @feed_{id}_v6 counter drop")).count(), 2);
        assert_eq!(text.matches(&format!("ip6 daddr @feed_{id}_v6 counter drop")).count(), 2);
        assert!(text.contains(&format!("comment \"iqsoft-threat-{id}\"")));
        assert!(!text.contains("log prefix"));
    }

    #[tokio::test]
    async fn direction_decides_which_chains_and_sides_are_used() {
        let pool = memory_pool().await;

        let mut inbound = feed("in");
        inbound.direction = "inbound".into();
        let in_id = add_feed(&pool, inbound, &["1.2.3.4/32"], &[]).await;

        let mut outbound = feed("out");
        outbound.direction = "outbound".into();
        let out_id = add_feed(&pool, outbound, &["5.6.7.8/32"], &[]).await;

        let text = generate_table(&pool).await.unwrap();

        assert_eq!(text.matches(&format!("ip saddr @feed_{in_id}_v4 ")).count(), 2);
        assert_eq!(text.matches(&format!("ip daddr @feed_{in_id}_v4 ")).count(), 0);
        assert_eq!(text.matches(&format!("ip daddr @feed_{out_id}_v4 ")).count(), 2);
        assert_eq!(text.matches(&format!("ip saddr @feed_{out_id}_v4 ")).count(), 0);
    }

    #[tokio::test]
    async fn logging_adds_a_rate_limited_log_rule_before_the_drop() {
        let pool = memory_pool().await;

        let mut logged = feed("logged");
        logged.direction = "inbound".into();
        logged.log_enabled = true;
        let id = add_feed(&pool, logged, &["1.2.3.4/32"], &[]).await;

        let text = generate_table(&pool).await.unwrap();

        let log_rule = format!("ip saddr @feed_{id}_v4 limit rate 6/minute log prefix \"iqsoft-threat-{id}: \"");
        let drop_rule = format!("ip saddr @feed_{id}_v4 counter drop comment \"iqsoft-threat-{id}\"");

        assert_eq!(text.matches(&log_rule).count(), 2);
        assert!(text.find(&log_rule).unwrap() < text.find(&drop_rule).unwrap());
    }

    #[tokio::test]
    async fn a_family_without_networks_gets_no_set_and_no_rule() {
        let pool = memory_pool().await;
        let id = add_feed(&pool, feed("v4only"), &["1.2.3.4/32"], &[]).await;

        let text = generate_table(&pool).await.unwrap();

        assert!(text.contains(&format!("set feed_{id}_v4 ")));
        assert!(!text.contains(&format!("feed_{id}_v6")));
    }

    #[tokio::test]
    async fn rows_that_are_not_clean_networks_never_reach_the_ruleset() {
        let pool = memory_pool().await;
        let id = add_feed(&pool, feed("dirty"), &["1.2.3.4/32"], &[]).await;

        for (family, cidr) in [
            ("ipv4", "1.1.1.1; flush ruleset"),
            ("ipv4", "}"),
            ("ipv4", "0.0.0.0/0"),
            ("ipv4", "2001:4860::/32"),
            ("ipv6", "5.6.7.8/32"),
            ("ipv4", "not-an-ip"),
        ] {
            sqlx::query("INSERT INTO threat_feed_entries (feed_id, family, cidr) VALUES (?, ?, ?)")
                .bind(id)
                .bind(family)
                .bind(cidr)
                .execute(&pool)
                .await
                .unwrap();
        }

        let text = generate_table(&pool).await.unwrap();

        assert!(text.contains("elements = { 1.2.3.4/32 }"));
        assert!(!text.contains("flush"));
        assert!(!text.contains("0.0.0.0/0"));
        assert!(!text.contains("not-an-ip"));
        assert!(!text.contains("feed_1_v6"));
        assert_eq!(text.matches("flush ruleset").count(), 0);
    }

    #[tokio::test]
    async fn output_is_deterministic_and_ordered_by_feed_id() {
        let pool = memory_pool().await;
        let first = add_feed(&pool, feed("zzz"), &["1.2.3.4/32"], &[]).await;
        let second = add_feed(&pool, feed("aaa"), &["5.6.7.8/32"], &[]).await;

        let a = generate_table(&pool).await.unwrap();
        let b = generate_table(&pool).await.unwrap();

        assert_eq!(a, b);
        assert!(a.find(&format!("set feed_{first}_v4")).unwrap() < a.find(&format!("set feed_{second}_v4")).unwrap());
    }

    #[tokio::test]
    async fn the_generated_table_passes_nft_check() {
        let pool = memory_pool().await;

        let mut logged = feed("logged");
        logged.log_enabled = true;
        add_feed(&pool, logged, &["1.2.3.4/32", "1.2.3.0/24", "8.8.8.0/24"], &["2001:4860::/32"]).await;

        let mut outbound = feed("out");
        outbound.direction = "outbound".into();
        add_feed(&pool, outbound, &["5.6.7.8/32"], &[]).await;

        let text = generate_table(&pool).await.unwrap();

        nft_check(&text);
        nft_check(&build_apply_script(&text));
    }

    #[test]
    fn the_apply_script_replaces_only_this_table() {
        let script = build_apply_script("table inet iqsoft_threat {\n}\n");

        assert_eq!(
            script,
            "add table inet iqsoft_threat\ndelete table inet iqsoft_threat\ntable inet iqsoft_threat {\n}\n"
        );
        assert!(!script.contains("flush ruleset"));

        let empty = build_apply_script("");
        assert_eq!(empty, "add table inet iqsoft_threat\ndelete table inet iqsoft_threat\n");
    }
}
