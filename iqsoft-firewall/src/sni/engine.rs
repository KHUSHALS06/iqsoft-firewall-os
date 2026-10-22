#![allow(dead_code)]

use crate::sni::{
    matcher::{Decision, SniPolicy, Verdict},
    packet::{FlowKey, TcpPacket},
    parser::{parse_client_hello, SniResult, MAX_HELLO_BYTES},
};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

const MAX_BUFFER: usize = MAX_HELLO_BYTES * 2;

const MAX_DATA_PACKETS: u32 = 64;

const SWEEP_EVERY: Duration = Duration::from_secs(10);

pub const DEFAULT_MAX_FLOWS: usize = 65_536;
pub const DEFAULT_IDLE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub verdict: Verdict,

    pub decision: Option<Decision>,

    pub trusted: bool,
}

impl Outcome {
    fn wait() -> Self {
        Self { verdict: Verdict::Accept, decision: None, trusted: false }
    }

    fn trust(decision: Option<Decision>) -> Self {
        Self { verdict: Verdict::Accept, decision, trusted: true }
    }

    fn deny(decision: Option<Decision>) -> Self {
        Self { verdict: Verdict::Drop, decision, trusted: false }
    }
}

enum Stage {
    Collecting(Collector),
    Passed,
    Blocked,
}

struct Flow {
    stage: Stage,
    last_seen: Instant,
}

struct Collector {
    base: Option<u32>,
    data: Vec<u8>,
    filled: Vec<bool>,
    data_packets: u32,
}

enum Added {
    Stored,
    Ignored,
    Conflict,
}

impl Collector {
    fn new(base: Option<u32>) -> Self {
        Self { base, data: Vec::new(), filled: Vec::new(), data_packets: 0 }
    }

    fn add(&mut self, seq: u32, payload: &[u8]) -> Added {
        let base = *self.base.get_or_insert(seq);
        let offset = seq.wrapping_sub(base);

        if offset >= 0x8000_0000 {
            return Added::Ignored;
        }

        let offset = offset as usize;

        if offset >= MAX_BUFFER {
            return Added::Ignored;
        }

        let end = (offset + payload.len()).min(MAX_BUFFER);

        if self.data.len() < end {
            self.data.resize(end, 0);
            self.filled.resize(end, false);
        }

        for (i, &byte) in payload[..end - offset].iter().enumerate() {
            let at = offset + i;

            if self.filled[at] {
                if self.data[at] != byte {
                    return Added::Conflict;
                }
            } else {
                self.data[at] = byte;
                self.filled[at] = true;
            }
        }

        Added::Stored
    }

    fn contiguous(&self) -> usize {
        self.filled.iter().position(|f| !f).unwrap_or(self.filled.len())
    }

    fn handle(&mut self, seq: u32, payload: &[u8], policy: &SniPolicy) -> Option<Decision> {
        self.data_packets += 1;

        let result = match self.add(seq, payload) {
            Added::Conflict => SniResult::Malformed,
            _ if self.data_packets > MAX_DATA_PACKETS => SniResult::Malformed,
            _ => {
                let have = self.contiguous();

                if have == 0 {
                    SniResult::NeedMore
                } else {
                    match parse_client_hello(&self.data[..have]) {
                        SniResult::NeedMore if have >= MAX_BUFFER => SniResult::Malformed,
                        other => other,
                    }
                }
            }
        };

        policy.decide(&result)
    }
}

pub struct SniEngine {
    flows: HashMap<FlowKey, Flow>,
    max_flows: usize,
    idle: Duration,
    last_sweep: Instant,
}

impl SniEngine {
    pub fn new(now: Instant) -> Self {
        Self::with_limits(now, DEFAULT_MAX_FLOWS, DEFAULT_IDLE)
    }

    pub fn with_limits(now: Instant, max_flows: usize, idle: Duration) -> Self {
        Self {
            flows: HashMap::new(),
            max_flows: max_flows.max(1),
            idle,
            last_sweep: now,
        }
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    pub fn on_packet(&mut self, packet: &TcpPacket<'_>, policy: &SniPolicy, now: Instant) -> Outcome {
        if !policy.is_enabled() {
            return Outcome::trust(None);
        }

        if now.saturating_duration_since(self.last_sweep) >= SWEEP_EVERY {
            self.sweep(now);
        }

        if packet.rst {
            self.flows.remove(&packet.key);
            return Outcome::wait();
        }

        let mut data_seq = packet.seq;

        if packet.syn {
            self.make_room(now);

            let base = packet.seq.wrapping_add(1);

            self.flows.insert(
                packet.key.clone(),
                Flow { stage: Stage::Collecting(Collector::new(Some(base))), last_seen: now },
            );

            data_seq = base;
        } else if !self.flows.contains_key(&packet.key) {
            if packet.payload.is_empty() {
                return Outcome::wait();
            }

            self.make_room(now);

            self.flows.insert(
                packet.key.clone(),
                Flow { stage: Stage::Collecting(Collector::new(None)), last_seen: now },
            );
        }

        let Some(flow) = self.flows.get_mut(&packet.key) else {
            return Outcome::wait();
        };

        flow.last_seen = now;

        let decision = match &mut flow.stage {
            Stage::Passed => return Outcome::trust(None),
            Stage::Blocked => return Outcome::deny(None),
            Stage::Collecting(collector) => {
                if packet.payload.is_empty() {
                    return Outcome::wait();
                }

                match collector.handle(data_seq, packet.payload, policy) {
                    Some(decision) => decision,
                    None => return Outcome::wait(),
                }
            }
        };

        match decision.verdict {
            Verdict::Accept => {
                flow.stage = Stage::Passed;
                Outcome::trust(Some(decision))
            }
            Verdict::Drop => {
                flow.stage = Stage::Blocked;
                Outcome::deny(Some(decision))
            }
        }
    }

    pub fn sweep(&mut self, now: Instant) {
        let idle = self.idle;

        self.flows
            .retain(|_, flow| now.saturating_duration_since(flow.last_seen) < idle);

        self.last_sweep = now;
    }

    fn make_room(&mut self, now: Instant) {
        if self.flows.len() < self.max_flows {
            return;
        }

        self.sweep(now);

        if self.flows.len() < self.max_flows {
            return;
        }

        let mut by_age: Vec<(Instant, FlowKey)> = self
            .flows
            .iter()
            .map(|(key, flow)| (flow.last_seen, key.clone()))
            .collect();

        by_age.sort_by_key(|(seen, _)| *seen);

        let remove = (self.max_flows / 10).max(1);

        for (_, key) in by_age.into_iter().take(remove) {
            self.flows.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        models::sni::{SniRule, SniSettings},
        sni::matcher::Reason,
    };
    use std::net::{IpAddr, Ipv4Addr};

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

    fn policy(rules: &[(&str, &str)]) -> SniPolicy {
        policy_with(true, true, rules)
    }

    fn key(port: u16) -> FlowKey {
        FlowKey {
            src: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            dst: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            src_port: port,
            dst_port: 443,
        }
    }

    fn syn(port: u16, seq: u32) -> TcpPacket<'static> {
        TcpPacket { key: key(port), seq, syn: true, fin: false, rst: false, payload: &[] }
    }

    fn data(port: u16, seq: u32, payload: &[u8]) -> TcpPacket<'_> {
        TcpPacket { key: key(port), seq, syn: false, fin: false, rst: false, payload }
    }

    fn rst(port: u16, seq: u32) -> TcpPacket<'static> {
        TcpPacket { key: key(port), seq, syn: false, fin: false, rst: true, payload: &[] }
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

    fn engine(now: Instant) -> SniEngine {
        SniEngine::new(now)
    }

    #[test]
    fn blocked_name_in_one_packet_is_dropped_and_stays_dropped() {
        let now = Instant::now();
        let p = policy(&[("tiktok.com", "block")]);
        let mut e = engine(now);
        let hello = client_hello("www.tiktok.com");

        assert_eq!(e.on_packet(&syn(40000, 999), &p, now), Outcome::wait());

        let out = e.on_packet(&data(40000, 1000, &hello), &p, now);
        assert_eq!(out.verdict, Verdict::Drop);
        assert!(!out.trusted);
        assert_eq!(out.decision.unwrap().reason, Reason::Blocked("tiktok.com".into()));

        let again = e.on_packet(&data(40000, 1000, &hello), &p, now);
        assert_eq!(again, Outcome::deny(None));
    }

    #[test]
    fn unlisted_name_is_accepted_and_trusted() {
        let now = Instant::now();
        let p = policy(&[("tiktok.com", "block")]);
        let mut e = engine(now);
        let hello = client_hello("example.org");

        e.on_packet(&syn(40001, 0), &p, now);
        let out = e.on_packet(&data(40001, 1, &hello), &p, now);

        assert_eq!(out.verdict, Verdict::Accept);
        assert!(out.trusted);
        assert_eq!(out.decision.unwrap().reason, Reason::NoRule);

        assert_eq!(e.on_packet(&data(40001, 1 + hello.len() as u32, b"more"), &p, now), Outcome::trust(None));
    }

    #[test]
    fn hello_split_over_two_packets_is_decided_on_the_second() {
        let now = Instant::now();
        let p = policy(&[("tiktok.com", "block")]);
        let mut e = engine(now);
        let hello = client_hello("tiktok.com");
        let (a, b) = hello.split_at(30);

        e.on_packet(&syn(40002, 5000), &p, now);

        assert_eq!(e.on_packet(&data(40002, 5001, a), &p, now), Outcome::wait());

        let out = e.on_packet(&data(40002, 5001 + a.len() as u32, b), &p, now);
        assert_eq!(out.verdict, Verdict::Drop);
    }

    #[test]
    fn packets_out_of_order_are_put_back_in_order() {
        let now = Instant::now();
        let p = policy(&[("tiktok.com", "block")]);
        let mut e = engine(now);
        let hello = client_hello("tiktok.com");
        let (a, b) = hello.split_at(30);

        e.on_packet(&syn(40003, 5000), &p, now);

        assert_eq!(e.on_packet(&data(40003, 5001 + a.len() as u32, b), &p, now), Outcome::wait());

        let out = e.on_packet(&data(40003, 5001, a), &p, now);
        assert_eq!(out.verdict, Verdict::Drop);
    }

    #[test]
    fn one_byte_at_a_time_cannot_hide_the_name() {
        let now = Instant::now();
        let p = policy_with(true, true, &[("tiktok.com", "block")]);
        let mut e = engine(now);
        let hello = client_hello("tiktok.com");

        e.on_packet(&syn(40004, 0), &p, now);

        let mut last = Outcome::wait();

        for (i, byte) in hello.iter().enumerate() {
            last = e.on_packet(&data(40004, 1 + i as u32, &[*byte]), &p, now);

            if last.decision.is_some() {
                break;
            }
        }

        assert_eq!(last.verdict, Verdict::Drop);
        assert_eq!(last.decision.unwrap().reason, Reason::Malformed);
    }

    #[test]
    fn two_copies_that_disagree_are_dropped_as_malformed() {
        let now = Instant::now();
        let p = policy(&[("tiktok.com", "block")]);
        let mut e = engine(now);
        let hello = client_hello("example.org");
        let mut other = hello.clone();
        other[20] ^= 0xff;

        e.on_packet(&syn(40005, 0), &p, now);
        assert_eq!(e.on_packet(&data(40005, 1, &hello[..40]), &p, now), Outcome::wait());

        let out = e.on_packet(&data(40005, 1, &other[..40]), &p, now);
        assert_eq!(out.verdict, Verdict::Drop);
        assert_eq!(out.decision.unwrap().reason, Reason::Malformed);
    }

    #[test]
    fn identical_retransmit_is_harmless() {
        let now = Instant::now();
        let p = policy(&[("tiktok.com", "block")]);
        let mut e = engine(now);
        let hello = client_hello("example.org");

        e.on_packet(&syn(40006, 0), &p, now);
        assert_eq!(e.on_packet(&data(40006, 1, &hello[..40]), &p, now), Outcome::wait());
        assert_eq!(e.on_packet(&data(40006, 1, &hello[..40]), &p, now), Outcome::wait());

        let out = e.on_packet(&data(40006, 41, &hello[40..]), &p, now);
        assert_eq!(out.verdict, Verdict::Accept);
        assert!(out.trusted);
    }

    #[test]
    fn data_without_a_syn_is_still_read() {
        let now = Instant::now();
        let p = policy(&[("tiktok.com", "block")]);
        let mut e = engine(now);
        let hello = client_hello("tiktok.com");

        let out = e.on_packet(&data(40007, 777_000, &hello), &p, now);
        assert_eq!(out.verdict, Verdict::Drop);
    }

    #[test]
    fn sequence_numbers_wrap_around_correctly() {
        let now = Instant::now();
        let p = policy(&[("tiktok.com", "block")]);
        let mut e = engine(now);
        let hello = client_hello("tiktok.com");
        let (a, b) = hello.split_at(30);

        e.on_packet(&syn(40008, u32::MAX - 10), &p, now);

        let first = (u32::MAX - 10).wrapping_add(1);
        assert_eq!(e.on_packet(&data(40008, first, a), &p, now), Outcome::wait());

        let out = e.on_packet(&data(40008, first.wrapping_add(a.len() as u32), b), &p, now);
        assert_eq!(out.verdict, Verdict::Drop);
    }

    #[test]
    fn data_on_the_syn_itself_is_read() {
        let now = Instant::now();
        let p = policy(&[("tiktok.com", "block")]);
        let mut e = engine(now);
        let hello = client_hello("tiktok.com");

        let mut packet = syn(40009, 100);
        packet.payload = &hello;

        let out = e.on_packet(&packet, &p, now);
        assert_eq!(out.verdict, Verdict::Drop);
    }

    #[test]
    fn plain_http_on_the_port_is_let_through() {
        let now = Instant::now();
        let p = policy(&[("tiktok.com", "block")]);
        let mut e = engine(now);

        e.on_packet(&syn(40010, 0), &p, now);
        let out = e.on_packet(&data(40010, 1, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), &p, now);

        assert_eq!(out.verdict, Verdict::Accept);
        assert!(out.trusted);
        assert_eq!(out.decision.unwrap().reason, Reason::NotTls);
    }

    #[test]
    fn a_disabled_policy_lets_everything_through_and_tracks_nothing() {
        let now = Instant::now();
        let p = policy_with(false, true, &[("tiktok.com", "block")]);
        let mut e = engine(now);
        let hello = client_hello("tiktok.com");

        assert_eq!(e.on_packet(&syn(40011, 0), &p, now), Outcome::trust(None));
        assert_eq!(e.on_packet(&data(40011, 1, &hello), &p, now), Outcome::trust(None));
        assert_eq!(e.flow_count(), 0);
    }

    #[test]
    fn malformed_handling_follows_the_setting() {
        let now = Instant::now();
        let broken = client_hello("bad name.com");

        for (block, expect) in [(true, Verdict::Drop), (false, Verdict::Accept)] {
            let p = policy_with(true, block, &[]);
            let mut e = engine(now);

            e.on_packet(&syn(40012, 0), &p, now);
            let out = e.on_packet(&data(40012, 1, &broken), &p, now);

            assert_eq!(out.verdict, expect);
            assert_eq!(out.decision.unwrap().reason, Reason::Malformed);
        }
    }

    #[test]
    fn rst_forgets_the_connection_and_bare_acks_are_not_tracked() {
        let now = Instant::now();
        let p = policy(&[("tiktok.com", "block")]);
        let mut e = engine(now);

        assert_eq!(e.on_packet(&data(40013, 1, &[]), &p, now), Outcome::wait());
        assert_eq!(e.flow_count(), 0);

        e.on_packet(&syn(40013, 0), &p, now);
        assert_eq!(e.flow_count(), 1);

        e.on_packet(&rst(40013, 1), &p, now);
        assert_eq!(e.flow_count(), 0);
    }

    #[test]
    fn a_new_syn_on_the_same_ports_starts_a_fresh_decision() {
        let now = Instant::now();
        let mut e = engine(now);
        let hello = client_hello("tiktok.com");

        let blocking = policy(&[("tiktok.com", "block")]);
        e.on_packet(&syn(40014, 0), &blocking, now);
        assert_eq!(e.on_packet(&data(40014, 1, &hello), &blocking, now).verdict, Verdict::Drop);

        let open = policy(&[]);
        e.on_packet(&syn(40014, 5000), &open, now);
        assert_eq!(e.on_packet(&data(40014, 5001, &hello), &open, now).verdict, Verdict::Accept);
    }

    #[test]
    fn a_reloaded_policy_applies_to_the_next_connection() {
        let now = Instant::now();
        let mut e = engine(now);
        let hello = client_hello("tiktok.com");

        let open = policy(&[]);
        e.on_packet(&syn(40015, 0), &open, now);
        assert_eq!(e.on_packet(&data(40015, 1, &hello), &open, now).verdict, Verdict::Accept);

        let blocking = policy(&[("tiktok.com", "block")]);
        e.on_packet(&syn(40016, 0), &blocking, now);
        assert_eq!(e.on_packet(&data(40016, 1, &hello), &blocking, now).verdict, Verdict::Drop);
    }

    #[test]
    fn idle_connections_expire() {
        let now = Instant::now();
        let p = policy(&[]);
        let mut e = SniEngine::with_limits(now, 100, Duration::from_secs(30));

        e.on_packet(&syn(40017, 0), &p, now);
        e.on_packet(&syn(40018, 0), &p, now);
        assert_eq!(e.flow_count(), 2);

        let later = now + Duration::from_secs(25);
        e.on_packet(&data(40018, 1, &[]), &p, later);

        let much_later = now + Duration::from_secs(40);
        e.sweep(much_later);
        assert_eq!(e.flow_count(), 1);
    }

    #[test]
    fn the_table_cannot_grow_past_its_limit() {
        let now = Instant::now();
        let p = policy(&[]);
        let mut e = SniEngine::with_limits(now, 50, Duration::from_secs(60));

        for i in 0..500u16 {
            let at = now + Duration::from_millis(i as u64);
            e.on_packet(&syn(10000 + i, 0), &p, at);
            assert!(e.flow_count() <= 50, "{} flows at step {}", e.flow_count(), i);
        }

        let newest = now + Duration::from_millis(500);
        let hello = client_hello("tiktok.com");
        let blocking = policy(&[("tiktok.com", "block")]);
        assert_eq!(
            e.on_packet(&data(10499, 1, &hello), &blocking, newest).verdict,
            Verdict::Drop
        );
    }

    #[test]
    fn data_far_ahead_of_the_start_is_ignored_not_stored() {
        let now = Instant::now();
        let p = policy(&[("tiktok.com", "block")]);
        let mut e = engine(now);
        let hello = client_hello("tiktok.com");

        e.on_packet(&syn(40019, 0), &p, now);
        assert_eq!(e.on_packet(&data(40019, 5_000_000, &hello), &p, now), Outcome::wait());

        assert_eq!(e.on_packet(&data(40019, 1, &hello), &p, now).verdict, Verdict::Drop);
    }
}
