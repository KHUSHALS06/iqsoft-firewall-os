#![allow(dead_code)]

use crate::{
    models::sni::SniSettings,
    sni::{
        engine::SniEngine,
        matcher::{Reason, SniPolicy, Verdict},
        packet::{parse_tcp_packet, FlowKey},
        parser::SniResult,
    },
};
use sqlx::SqlitePool;
use std::{
    io::ErrorKind,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

pub const SNI_QUEUE_NUM: u16 = 100;

pub const SNI_TRUST_MARK: u32 = 0x0400_0000;

const QUEUE_MAX_LEN: u32 = 4096;

const RETRY_DELAY: Duration = Duration::from_millis(200);

#[derive(Clone)]
pub struct PolicyHandle {
    inner: Arc<RwLock<Arc<SniPolicy>>>,
}

impl PolicyHandle {
    pub fn new(policy: SniPolicy) -> Self {
        Self { inner: Arc::new(RwLock::new(Arc::new(policy))) }
    }

    pub fn disabled() -> Self {
        let settings = SniSettings {
            enabled: false,
            use_dns_filter_lists: false,
            no_name_action: "allow".to_string(),
            block_malformed: false,
            block_quic: false,
        };

        Self::new(SniPolicy::build(&settings, &[], &[], &[]))
    }

    pub fn get(&self) -> Arc<SniPolicy> {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set(&self, policy: SniPolicy) {
        *self.inner.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(policy);
    }

    pub async fn reload(&self, pool: &SqlitePool) -> Result<usize, String> {
        let policy = SniPolicy::load(pool).await?;
        let rules = policy.rule_count();

        self.set(policy);

        Ok(rules)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judgement {
    pub verdict: Verdict,
    pub trusted: bool,
    pub log: Option<String>,
}

pub fn judge(engine: &mut SniEngine, policy: &SniPolicy, packet: &[u8], now: Instant) -> Judgement {
    let Some(tcp) = parse_tcp_packet(packet) else {
        return match policy.decide(&SniResult::Malformed) {
            Some(decision) if decision.verdict == Verdict::Drop => Judgement {
                verdict: Verdict::Drop,
                trusted: false,
                log: Some("SNI filter dropped an unreadable packet on the HTTPS port".to_string()),
            },
            _ => Judgement { verdict: Verdict::Accept, trusted: false, log: None },
        };
    };

    let outcome = engine.on_packet(&tcp, policy, now);

    let log = outcome
        .decision
        .as_ref()
        .filter(|decision| decision.verdict == Verdict::Drop)
        .map(|decision| describe(&tcp.key, &decision.reason));

    Judgement { verdict: outcome.verdict, trusted: outcome.trusted, log }
}

fn describe(key: &FlowKey, reason: &Reason) -> String {
    let connection = format!("{} -> {}:{}", key.src, key.dst, key.dst_port);

    match reason {
        Reason::Blocked(rule) => format!("SNI filter blocked {} (rule {})", connection, rule),
        Reason::Malformed => format!("SNI filter blocked a malformed TLS handshake {}", connection),
        Reason::NoName => format!("SNI filter blocked a handshake with no site name {}", connection),
        _ => format!("SNI filter blocked {}", connection),
    }
}

pub fn start(policy: PolicyHandle) -> Result<(), String> {
    let mut queue =
        nfq::Queue::open().map_err(|e| format!("could not open the netfilter queue: {}", e))?;

    queue
        .bind(SNI_QUEUE_NUM)
        .map_err(|e| format!("could not bind queue {}: {}", SNI_QUEUE_NUM, e))?;

    queue
        .set_fail_open(SNI_QUEUE_NUM, true)
        .map_err(|e| format!("could not set fail-open on queue {}: {}", SNI_QUEUE_NUM, e))?;

    queue
        .set_queue_max_len(SNI_QUEUE_NUM, QUEUE_MAX_LEN)
        .map_err(|e| format!("could not set the length of queue {}: {}", SNI_QUEUE_NUM, e))?;

    std::thread::Builder::new()
        .name("sni-queue".to_string())
        .spawn(move || run(queue, policy))
        .map_err(|e| format!("could not start the SNI queue thread: {}", e))?;

    Ok(())
}

fn run(mut queue: nfq::Queue, policy: PolicyHandle) {
    let mut engine = SniEngine::new(Instant::now());

    loop {
        let mut message = match queue.recv() {
            Ok(message) => message,
            Err(e) => {
                if e.kind() != ErrorKind::Interrupted {
                    eprintln!("ERROR: SNI queue receive failed: {}", e);
                    std::thread::sleep(RETRY_DELAY);
                }
                continue;
            }
        };

        let snapshot = policy.get();
        let judgement = judge(&mut engine, &snapshot, message.get_payload(), Instant::now());

        if let Some(line) = &judgement.log {
            println!("{}", line);
        }

        if judgement.trusted {
            let mark = message.get_nfmark();
            message.set_nfmark(mark | SNI_TRUST_MARK);
        }

        message.set_verdict(match judgement.verdict {
            Verdict::Accept => nfq::Verdict::Accept,
            Verdict::Drop => nfq::Verdict::Drop,
        });

        if let Err(e) = queue.verdict(message) {
            eprintln!("ERROR: SNI queue verdict failed: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::sni::SniRule;

    fn policy_with(enabled: bool, block_malformed: bool, rules: &[(&str, &str)]) -> SniPolicy {
        let rules: Vec<SniRule> = rules
            .iter()
            .map(|(domain, action)| SniRule {
                id: None,
                domain: domain.to_string(),
                action: action.to_string(),
                comment: None,
            })
            .collect();

        let settings = SniSettings {
            enabled,
            use_dns_filter_lists: false,
            no_name_action: "allow".into(),
            block_malformed,
            block_quic: false,
        };

        SniPolicy::build(&settings, &rules, &[], &[])
    }

    fn client_hello(name: &str) -> Vec<u8> {
        let mut sni = Vec::new();
        sni.extend((name.len() as u16 + 3).to_be_bytes());
        sni.push(0);
        sni.extend((name.len() as u16).to_be_bytes());
        sni.extend(name.as_bytes());

        let mut extensions = Vec::new();
        extensions.extend(0u16.to_be_bytes());
        extensions.extend((sni.len() as u16).to_be_bytes());
        extensions.extend(&sni);

        let mut body = Vec::new();
        body.extend([0x03, 0x03]);
        body.extend([7u8; 32]);
        body.push(0);
        body.extend(2u16.to_be_bytes());
        body.extend([0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend((extensions.len() as u16).to_be_bytes());
        body.extend(&extensions);

        let mut handshake = vec![0x01];
        handshake.extend(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend((handshake.len() as u16).to_be_bytes());
        record.extend(&handshake);
        record
    }

    fn ipv4_tcp(sport: u16, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend(sport.to_be_bytes());
        tcp.extend(443u16.to_be_bytes());
        tcp.extend(seq.to_be_bytes());
        tcp.extend(0u32.to_be_bytes());
        tcp.push(5 << 4);
        tcp.push(flags);
        tcp.extend([0xff, 0xff, 0, 0, 0, 0]);
        tcp.extend(payload);

        let total = 20 + tcp.len();

        let mut ip = vec![0x45, 0];
        ip.extend((total as u16).to_be_bytes());
        ip.extend([0, 1, 0x40, 0, 64, 6, 0, 0]);
        ip.extend([192, 168, 1, 50]);
        ip.extend([93, 184, 216, 34]);
        ip.extend(tcp);
        ip
    }

    const SYN: u8 = 0x02;
    const ACK_PSH: u8 = 0x18;

    fn engine() -> SniEngine {
        SniEngine::new(Instant::now())
    }

    #[test]
    fn blocked_name_is_dropped_and_logged_once() {
        let p = policy_with(true, true, &[("tiktok.com", "block")]);
        let mut e = engine();
        let now = Instant::now();
        let hello = client_hello("www.tiktok.com");

        let syn = judge(&mut e, &p, &ipv4_tcp(50000, 100, SYN, &[]), now);
        assert_eq!(syn, Judgement { verdict: Verdict::Accept, trusted: false, log: None });

        let out = judge(&mut e, &p, &ipv4_tcp(50000, 101, ACK_PSH, &hello), now);
        assert_eq!(out.verdict, Verdict::Drop);
        assert!(!out.trusted);

        let line = out.log.unwrap();
        assert!(line.contains("192.168.1.50 -> 93.184.216.34:443"));
        assert!(line.contains("tiktok.com"));

        let again = judge(&mut e, &p, &ipv4_tcp(50000, 101, ACK_PSH, &hello), now);
        assert_eq!(again, Judgement { verdict: Verdict::Drop, trusted: false, log: None });
    }

    #[test]
    fn allowed_name_is_accepted_and_marked_trusted_without_a_log_line() {
        let p = policy_with(true, true, &[("tiktok.com", "block")]);
        let mut e = engine();
        let now = Instant::now();

        judge(&mut e, &p, &ipv4_tcp(50001, 100, SYN, &[]), now);
        let out = judge(&mut e, &p, &ipv4_tcp(50001, 101, ACK_PSH, &client_hello("example.org")), now);

        assert_eq!(out, Judgement { verdict: Verdict::Accept, trusted: true, log: None });
    }

    #[test]
    fn unreadable_packets_follow_the_malformed_setting() {
        let now = Instant::now();
        let garbage = [0x45u8, 0, 0, 5, 1, 2, 3];

        let strict = policy_with(true, true, &[]);
        let out = judge(&mut engine(), &strict, &garbage, now);
        assert_eq!(out.verdict, Verdict::Drop);
        assert!(out.log.is_some());

        let relaxed = policy_with(true, false, &[]);
        let out = judge(&mut engine(), &relaxed, &garbage, now);
        assert_eq!(out, Judgement { verdict: Verdict::Accept, trusted: false, log: None });

        let off = policy_with(false, true, &[]);
        let out = judge(&mut engine(), &off, &garbage, now);
        assert_eq!(out.verdict, Verdict::Accept);
    }

    #[test]
    fn disabled_policy_marks_everything_trusted() {
        let p = policy_with(false, true, &[("tiktok.com", "block")]);
        let mut e = engine();
        let now = Instant::now();

        let out = judge(&mut e, &p, &ipv4_tcp(50002, 101, ACK_PSH, &client_hello("tiktok.com")), now);
        assert_eq!(out, Judgement { verdict: Verdict::Accept, trusted: true, log: None });
    }

    #[test]
    fn swapping_the_policy_changes_the_next_connection_only() {
        let handle = PolicyHandle::disabled();
        let mut e = engine();
        let now = Instant::now();
        let hello = client_hello("tiktok.com");

        let first = judge(&mut e, &handle.get(), &ipv4_tcp(50003, 101, ACK_PSH, &hello), now);
        assert_eq!(first.verdict, Verdict::Accept);

        handle.set(policy_with(true, true, &[("tiktok.com", "block")]));

        judge(&mut e, &handle.get(), &ipv4_tcp(50004, 100, SYN, &[]), now);
        let second = judge(&mut e, &handle.get(), &ipv4_tcp(50004, 101, ACK_PSH, &hello), now);
        assert_eq!(second.verdict, Verdict::Drop);
    }

    #[test]
    fn a_fresh_handle_starts_disabled() {
        assert!(!PolicyHandle::disabled().get().is_enabled());
    }
}
