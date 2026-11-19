use crate::{
    models::ids::{normalize_interfaces, IdsSettings},
    repository::ids_repository::IdsRepository,
};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::Mutex;

pub const TABLE_NAME: &str = "iqsoft_ids";

const HOOK_PRIORITY: i32 = 10;

#[derive(Clone, Copy)]
enum Chain {
    Input,
    Forward,
    Output,
}

fn queue_statement(queue_num: u16, bypass: bool) -> String {
    if bypass {
        format!("counter queue num {} bypass", queue_num)
    } else {
        format!("counter queue num {}", queue_num)
    }
}

fn interface_set(names: &[String]) -> String {
    let quoted: Vec<String> = names.iter().map(|n| format!("\"{}\"", n)).collect();
    format!("{{ {} }}", quoted.join(", "))
}

fn write_chain(
    output: &mut String,
    chain: Chain,
    interfaces: &[String],
    queue: &str,
) {
    let (name, loopback) = match chain {
        Chain::Input => ("input", "iifname \"lo\" accept"),
        Chain::Forward => ("forward", ""),
        Chain::Output => ("output", "oifname \"lo\" accept"),
    };

    output.push_str(&format!("    chain {} {{\n", name));
    output.push_str(&format!(
        "        type filter hook {} priority {};\n",
        name, HOOK_PRIORITY
    ));
    output.push_str("        policy accept;\n\n");

    if !loopback.is_empty() {
        output.push_str(&format!("        {}\n", loopback));
    }

    if interfaces.is_empty() {
        output.push_str(&format!("        {}\n", queue));
    } else {
        let set = interface_set(interfaces);

        let matches: &[&str] = match chain {
            Chain::Input => &["iifname"],
            Chain::Forward => &["iifname", "oifname"],
            Chain::Output => &["oifname"],
        };

        for keyword in matches {
            output.push_str(&format!("        {} {} {}\n", keyword, set, queue));
        }
    }

    output.push_str("    }\n");
}

pub fn render_table(settings: &IdsSettings) -> String {
    if !settings.enabled || settings.mode != "ips" {
        return String::new();
    }

    let queue_num = match u16::try_from(settings.queue_num) {
        Ok(n) if n != 0 && n != crate::sni::queue::SNI_QUEUE_NUM => n,
        _ => {
            eprintln!(
                "WARNING: IDS queue number {} is not usable - skipping the IPS table",
                settings.queue_num
            );
            return String::new();
        }
    };

    let interfaces: Vec<String> = match normalize_interfaces(&settings.interfaces) {
        Ok(list) => list
            .split(',')
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .collect(),
        Err(e) => {
            eprintln!("WARNING: IDS interface list is invalid ({}) - skipping the IPS table", e);
            return String::new();
        }
    };

    let queue = queue_statement(queue_num, settings.fail_mode == "open");

    let mut output = String::new();
    output.push_str(&format!("table inet {} {{\n\n", TABLE_NAME));
    write_chain(&mut output, Chain::Input, &interfaces, &queue);
    output.push('\n');
    write_chain(&mut output, Chain::Forward, &interfaces, &queue);
    output.push('\n');
    write_chain(&mut output, Chain::Output, &interfaces, &queue);
    output.push_str("}\n");

    output
}

pub async fn generate_table(pool: &SqlitePool) -> Result<String, String> {
    let settings = IdsRepository::get_settings(pool)
        .await
        .map_err(|e| e.to_string())?;

    Ok(render_table(&settings))
}

pub fn build_apply_script(table_text: &str) -> String {
    format!(
        "add table inet {t}\ndelete table inet {t}\n{body}",
        t = TABLE_NAME,
        body = table_text
    )
}

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
        .map_err(|e| format!("could not send the IPS rules to nft: {}", e))?;

    drop(stdin);

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("nft did not finish: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "nft refused the IPS rules: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(())
}

#[cfg(test)]
pub async fn apply_live(_pool: &SqlitePool, _lock: &Arc<Mutex<()>>) -> Result<(), String> {
    Err("nft is not touched in test builds".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::ids_schema::create_ids_tables;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        create_ids_tables(&pool).await.unwrap();
        pool
    }

    fn ips() -> IdsSettings {
        let mut settings: IdsSettings = serde_json::from_str("{}").unwrap();
        settings.enabled = true;
        settings.mode = "ips".into();
        settings
    }

    fn chain_text<'a>(text: &'a str, name: &str) -> &'a str {
        let start = text.find(&format!("chain {} {{", name)).unwrap();
        let rest = &text[start..];
        let end = rest.find("\n    }\n").unwrap();
        &rest[..end]
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

        let kernel_cannot_check = err.contains("Operation not permitted")
            || err.contains("Permission denied")
            || (err.contains("No such file or directory") && !err.contains("syntax error"));

        if !out.status.success() && kernel_cannot_check {
            assert!(!required, "nft --check cannot run fully here: {}", err);
            eprintln!("SKIPPED nft --check: kernel cannot check this ({})", err.trim());
            return;
        }

        assert!(out.status.success(), "nft --check failed: {}\n{}", err, ruleset);
    }

    #[test]
    fn nothing_is_generated_unless_enabled_in_ips_mode() {
        let mut off = ips();
        off.enabled = false;
        assert_eq!(render_table(&off), "");

        let mut passive = ips();
        passive.mode = "ids".into();
        assert_eq!(render_table(&passive), "");

        let defaults: IdsSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(render_table(&defaults), "");
    }

    #[test]
    fn ips_mode_queues_traffic_after_the_main_filter_and_fails_open() {
        let text = render_table(&ips());

        assert!(text.starts_with("table inet iqsoft_ids {"));

        for hook in ["input", "forward", "output"] {
            let chain = chain_text(&text, hook);
            assert!(chain.contains(&format!("type filter hook {} priority 10;", hook)));
            assert!(chain.contains("policy accept;"));
            assert!(chain.contains("counter queue num 200 bypass"));
        }

        assert!(chain_text(&text, "input").contains("iifname \"lo\" accept"));
        assert!(chain_text(&text, "output").contains("oifname \"lo\" accept"));
        assert!(!chain_text(&text, "forward").contains("\"lo\""));
    }

    #[test]
    fn the_loopback_exception_comes_before_the_queue_rule() {
        let text = render_table(&ips());

        for hook in ["input", "output"] {
            let chain = chain_text(&text, hook);
            assert!(chain.find("\"lo\" accept").unwrap() < chain.find("queue num").unwrap());
        }
    }

    #[test]
    fn fail_closed_leaves_out_the_bypass_flag() {
        let mut settings = ips();
        settings.fail_mode = "closed".into();

        let text = render_table(&settings);

        assert!(text.contains("counter queue num 200\n"));
        assert!(!text.contains("bypass"));
    }

    #[test]
    fn a_custom_queue_number_is_used() {
        let mut settings = ips();
        settings.queue_num = 4242;

        let text = render_table(&settings);

        assert!(text.contains("queue num 4242 bypass"));
        assert!(!text.contains("queue num 200"));
    }

    #[test]
    fn listed_interfaces_limit_what_is_queued() {
        let mut settings = ips();
        settings.interfaces = "enp2s0,enp3s0".into();

        let text = render_table(&settings);

        let input = chain_text(&text, "input");
        assert!(input.contains("iifname { \"enp2s0\", \"enp3s0\" } counter queue num 200 bypass"));
        assert!(!input.contains("oifname {"));

        let forward = chain_text(&text, "forward");
        assert!(forward.contains("iifname { \"enp2s0\", \"enp3s0\" } counter queue num 200 bypass"));
        assert!(forward.contains("oifname { \"enp2s0\", \"enp3s0\" } counter queue num 200 bypass"));

        let output = chain_text(&text, "output");
        assert!(output.contains("oifname { \"enp2s0\", \"enp3s0\" } counter queue num 200 bypass"));
        assert!(!output.contains("iifname {"));
    }

    #[test]
    fn unusable_settings_produce_no_table_instead_of_a_broken_one() {
        let mut injected = ips();
        injected.interfaces = "eth0\" accept; #".into();
        assert_eq!(render_table(&injected), "");

        let mut sni_queue = ips();
        sni_queue.queue_num = 100;
        assert_eq!(render_table(&sni_queue), "");

        let mut zero = ips();
        zero.queue_num = 0;
        assert_eq!(render_table(&zero), "");

        let mut huge = ips();
        huge.queue_num = 70_000;
        assert_eq!(render_table(&huge), "");
    }

    #[test]
    fn the_apply_script_replaces_only_this_table() {
        let script = build_apply_script("table inet iqsoft_ids {\n}\n");
        assert_eq!(
            script,
            "add table inet iqsoft_ids\ndelete table inet iqsoft_ids\ntable inet iqsoft_ids {\n}\n"
        );

        assert_eq!(
            build_apply_script(""),
            "add table inet iqsoft_ids\ndelete table inet iqsoft_ids\n"
        );
    }

    #[test]
    fn generated_tables_pass_nft_check() {
        nft_check(&build_apply_script(&render_table(&ips())));

        let mut closed = ips();
        closed.fail_mode = "closed".into();
        nft_check(&build_apply_script(&render_table(&closed)));

        let mut limited = ips();
        limited.interfaces = "enp2s0, enp3s0.10".into();
        limited.queue_num = 4242;
        nft_check(&build_apply_script(&render_table(&limited)));

        nft_check(&build_apply_script(""));
    }

    #[tokio::test]
    async fn the_table_follows_the_saved_settings() {
        let pool = memory_pool().await;

        assert_eq!(generate_table(&pool).await.unwrap(), "");

        let mut settings = IdsRepository::get_settings(&pool).await.unwrap();
        settings.enabled = true;
        settings.mode = "ips".into();
        IdsRepository::set_settings(&pool, &settings).await.unwrap();

        let text = generate_table(&pool).await.unwrap();
        assert!(text.contains("queue num 200 bypass"));

        settings.mode = "ids".into();
        IdsRepository::set_settings(&pool, &settings).await.unwrap();
        assert_eq!(generate_table(&pool).await.unwrap(), "");
    }
}
