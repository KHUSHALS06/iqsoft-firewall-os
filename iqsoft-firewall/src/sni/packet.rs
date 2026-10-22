// Reads the IP and TCP headers of a packet the kernel handed to us.
//
// The kernel gives us whole IP packets (IPv4 or IPv6). To follow a TLS
// handshake we need to know which connection a packet belongs to, where its
// data starts in the stream, and what the data is.
//
// Like the TLS parser, this is pure parsing with every read bounds-checked,
// so a broken or hostile packet gives None, never a crash.

// Nothing calls this code until the next steps are added.
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const PROTO_TCP: u8 = 6;
const IPV6_HOP_BY_HOP: u8 = 0;
const IPV6_ROUTING: u8 = 43;
const IPV6_DEST_OPTIONS: u8 = 60;

/// One direction of one connection: who sent the packet and where to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpPacket<'a> {
    pub key: FlowKey,
    /// Sequence number of the first payload byte (or of the SYN).
    pub seq: u32,
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
    pub payload: &'a [u8],
}

/// Returns None for anything that is not a complete, whole TCP packet:
/// other protocols, fragments, cut-off packets and broken headers.
pub fn parse_tcp_packet(data: &[u8]) -> Option<TcpPacket<'_>> {
    match *data.first()? >> 4 {
        4 => parse_v4(data),
        6 => parse_v6(data),
        _ => None,
    }
}

fn parse_v4(data: &[u8]) -> Option<TcpPacket<'_>> {
    if data.len() < 20 {
        return None;
    }

    let header_len = ((data[0] & 0x0f) as usize) * 4;

    if header_len < 20 {
        return None;
    }

    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;

    // Bytes after total_len are padding and are ignored. A packet that claims
    // to be longer than what we got is cut off and cannot be trusted.
    if total_len < header_len || total_len > data.len() {
        return None;
    }

    // "More fragments" or a fragment offset: this is only a piece of a packet.
    let fragment = u16::from_be_bytes([data[6], data[7]]);

    if fragment & 0x3fff != 0 {
        return None;
    }

    if data[9] != PROTO_TCP {
        return None;
    }

    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    parse_tcp(IpAddr::V4(src), IpAddr::V4(dst), &data[header_len..total_len])
}

fn parse_v6(data: &[u8]) -> Option<TcpPacket<'_>> {
    if data.len() < 40 {
        return None;
    }

    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;

    if payload_len == 0 || 40 + payload_len > data.len() {
        return None;
    }

    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&data[8..24]);
    dst.copy_from_slice(&data[24..40]);

    let src = IpAddr::V6(Ipv6Addr::from(src));
    let dst = IpAddr::V6(Ipv6Addr::from(dst));

    let mut next = data[6];
    let mut rest = &data[40..40 + payload_len];

    // Skip the extension headers that can sit in front of TCP. A fragment
    // header (44) or anything unknown means we cannot read the stream.
    for _ in 0..8 {
        match next {
            PROTO_TCP => return parse_tcp(src, dst, rest),
            IPV6_HOP_BY_HOP | IPV6_ROUTING | IPV6_DEST_OPTIONS => {
                if rest.len() < 8 {
                    return None;
                }

                let len = (rest[1] as usize + 1) * 8;

                if rest.len() < len {
                    return None;
                }

                next = rest[0];
                rest = &rest[len..];
            }
            _ => return None,
        }
    }

    None
}

fn parse_tcp(src: IpAddr, dst: IpAddr, segment: &[u8]) -> Option<TcpPacket<'_>> {
    if segment.len() < 20 {
        return None;
    }

    let header_len = ((segment[12] >> 4) as usize) * 4;

    if header_len < 20 || header_len > segment.len() {
        return None;
    }

    let flags = segment[13];

    Some(TcpPacket {
        key: FlowKey {
            src,
            dst,
            src_port: u16::from_be_bytes([segment[0], segment[1]]),
            dst_port: u16::from_be_bytes([segment[2], segment[3]]),
        },
        seq: u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]),
        syn: flags & 0x02 != 0,
        fin: flags & 0x01 != 0,
        rst: flags & 0x04 != 0,
        payload: &segment[header_len..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_segment(sport: u16, dport: u16, seq: u32, flags: u8, options: &[u8], payload: &[u8]) -> Vec<u8> {
        let header_words = ((20 + options.len()) / 4) as u8;

        let mut v = Vec::new();
        v.extend(sport.to_be_bytes());
        v.extend(dport.to_be_bytes());
        v.extend(seq.to_be_bytes());
        v.extend(0u32.to_be_bytes()); // acknowledgement
        v.push(header_words << 4);
        v.push(flags);
        v.extend([0xff, 0xff]); // window
        v.extend([0, 0]); // checksum
        v.extend([0, 0]); // urgent pointer
        v.extend(options);
        v.extend(payload);
        v
    }

    fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, ip_options: &[u8], fragment: u16, body: &[u8]) -> Vec<u8> {
        let header_words = ((20 + ip_options.len()) / 4) as u8;
        let total = 20 + ip_options.len() + body.len();

        let mut v = vec![0x40 | header_words, 0];
        v.extend((total as u16).to_be_bytes());
        v.extend([0, 1]); // identification
        v.extend(fragment.to_be_bytes());
        v.push(64); // ttl
        v.push(proto);
        v.extend([0, 0]); // checksum
        v.extend(src);
        v.extend(dst);
        v.extend(ip_options);
        v.extend(body);
        v
    }

    fn ipv6(src: [u8; 16], dst: [u8; 16], next: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![0x60, 0, 0, 0];
        v.extend((body.len() as u16).to_be_bytes());
        v.push(next);
        v.push(64); // hop limit
        v.extend(src);
        v.extend(dst);
        v.extend(body);
        v
    }

    const CLIENT: [u8; 4] = [192, 168, 10, 50];
    const SERVER: [u8; 4] = [93, 184, 216, 34];

    fn simple_v4(payload: &[u8]) -> Vec<u8> {
        ipv4(CLIENT, SERVER, 6, &[], 0x4000, &tcp_segment(50000, 443, 1000, 0x18, &[], payload))
    }

    fn v6_addr(last: u8) -> [u8; 16] {
        let mut a = [0u8; 16];
        a[0] = 0x20;
        a[1] = 0x01;
        a[2] = 0x0d;
        a[3] = 0xb8;
        a[15] = last;
        a
    }

    #[test]
    fn ipv4_fields_and_payload() {
        let packet = simple_v4(b"hello");
        let parsed = parse_tcp_packet(&packet).unwrap();

        assert_eq!(parsed.key.src, IpAddr::V4(Ipv4Addr::new(192, 168, 10, 50)));
        assert_eq!(parsed.key.dst, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(parsed.key.src_port, 50000);
        assert_eq!(parsed.key.dst_port, 443);
        assert_eq!(parsed.seq, 1000);
        assert_eq!(parsed.payload, b"hello");
        assert!(!parsed.syn && !parsed.fin && !parsed.rst);
    }

    #[test]
    fn a_packet_without_data_has_an_empty_payload() {
        let parsed = parse_tcp_packet(&simple_v4(b"")).unwrap();
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn ip_options_and_tcp_options_are_skipped() {
        let segment = tcp_segment(50000, 443, 7, 0x10, &[1, 1, 1, 1], b"data");
        let packet = ipv4(CLIENT, SERVER, 6, &[1, 1, 1, 0], 0, &segment);

        let parsed = parse_tcp_packet(&packet).unwrap();

        assert_eq!(parsed.payload, b"data");
        assert_eq!(parsed.seq, 7);
        assert_eq!(parsed.key.dst_port, 443);
    }

    #[test]
    fn bytes_after_the_ip_length_are_ignored() {
        let mut packet = simple_v4(b"hello");
        packet.extend([0u8; 12]); // padding

        assert_eq!(parse_tcp_packet(&packet).unwrap().payload, b"hello");
    }

    #[test]
    fn tcp_flags_are_read() {
        let make = |flags: u8| {
            let packet = ipv4(CLIENT, SERVER, 6, &[], 0, &tcp_segment(1, 443, 0, flags, &[], b""));
            let p = parse_tcp_packet(&packet).unwrap();
            (p.syn, p.fin, p.rst)
        };

        assert_eq!(make(0x02), (true, false, false));
        assert_eq!(make(0x01), (false, true, false));
        assert_eq!(make(0x04), (false, false, true));
        assert_eq!(make(0x12), (true, false, false));
        assert_eq!(make(0x10), (false, false, false));
    }

    #[test]
    fn ipv6_fields_and_payload() {
        let segment = tcp_segment(40000, 443, 55, 0x18, &[], b"v6 data");
        let packet = ipv6(v6_addr(1), v6_addr(2), 6, &segment);

        let parsed = parse_tcp_packet(&packet).unwrap();

        assert_eq!(parsed.key.src, IpAddr::V6(Ipv6Addr::from(v6_addr(1))));
        assert_eq!(parsed.key.dst, IpAddr::V6(Ipv6Addr::from(v6_addr(2))));
        assert_eq!(parsed.key.src_port, 40000);
        assert_eq!(parsed.key.dst_port, 443);
        assert_eq!(parsed.seq, 55);
        assert_eq!(parsed.payload, b"v6 data");
    }

    #[test]
    fn ipv6_extension_headers_are_skipped() {
        // Hop-by-hop header: next = TCP, length 0 (= 8 bytes), padding.
        let mut body = vec![6, 0, 1, 4, 0, 0, 0, 0];
        body.extend(tcp_segment(40000, 443, 9, 0x18, &[], b"after ext"));
        let packet = ipv6(v6_addr(1), v6_addr(2), 0, &body);

        assert_eq!(parse_tcp_packet(&packet).unwrap().payload, b"after ext");

        // A fragment header (44) cannot be followed.
        let mut body = vec![6, 0, 0, 0, 0, 0, 0, 0];
        body.extend(tcp_segment(40000, 443, 9, 0x18, &[], b"x"));
        assert!(parse_tcp_packet(&ipv6(v6_addr(1), v6_addr(2), 44, &body)).is_none());
    }

    #[test]
    fn other_protocols_are_not_tcp() {
        let udp = ipv4(CLIENT, SERVER, 17, &[], 0, &[0u8; 30]);
        assert!(parse_tcp_packet(&udp).is_none());

        let icmp = ipv4(CLIENT, SERVER, 1, &[], 0, &[0u8; 30]);
        assert!(parse_tcp_packet(&icmp).is_none());

        let v6_udp = ipv6(v6_addr(1), v6_addr(2), 17, &[0u8; 30]);
        assert!(parse_tcp_packet(&v6_udp).is_none());
    }

    #[test]
    fn fragments_are_refused_but_dont_fragment_is_fine() {
        let body = tcp_segment(1, 443, 0, 0x10, &[], b"x");

        assert!(parse_tcp_packet(&ipv4(CLIENT, SERVER, 6, &[], 0x2000, &body)).is_none()); // more fragments
        assert!(parse_tcp_packet(&ipv4(CLIENT, SERVER, 6, &[], 0x0005, &body)).is_none()); // offset
        assert!(parse_tcp_packet(&ipv4(CLIENT, SERVER, 6, &[], 0x4000, &body)).is_some()); // DF
        assert!(parse_tcp_packet(&ipv4(CLIENT, SERVER, 6, &[], 0x0000, &body)).is_some());
    }

    #[test]
    fn broken_lengths_and_versions_are_refused() {
        let good = simple_v4(b"abc");
        assert!(parse_tcp_packet(&good).is_some());

        let mut p = good.clone();
        p[2..4].copy_from_slice(&10u16.to_be_bytes()); // total shorter than the header
        assert!(parse_tcp_packet(&p).is_none());

        let mut p = good.clone();
        p[2..4].copy_from_slice(&0xffffu16.to_be_bytes()); // total longer than the data
        assert!(parse_tcp_packet(&p).is_none());

        let mut p = good.clone();
        p[0] = 0x44; // header length 16
        assert!(parse_tcp_packet(&p).is_none());

        let mut p = good.clone();
        p[0] = 0x55; // version 5
        assert!(parse_tcp_packet(&p).is_none());

        let mut p = good.clone();
        p[20 + 12] = 0x40; // TCP header length 16
        assert!(parse_tcp_packet(&p).is_none());

        let mut p = good.clone();
        p[20 + 12] = 0xf0; // TCP header longer than the segment
        assert!(parse_tcp_packet(&p).is_none());

        assert!(parse_tcp_packet(&[]).is_none());

        let mut v6 = ipv6(v6_addr(1), v6_addr(2), 6, &tcp_segment(1, 443, 0, 0x10, &[], b"x"));
        v6[4..6].copy_from_slice(&0u16.to_be_bytes()); // payload length 0
        assert!(parse_tcp_packet(&v6).is_none());
    }

    #[test]
    fn every_cut_short_packet_is_refused() {
        let v4 = simple_v4(b"some payload bytes");
        for len in 0..v4.len() {
            assert!(parse_tcp_packet(&v4[..len]).is_none(), "v4 len {}", len);
        }

        let v6 = ipv6(v6_addr(1), v6_addr(2), 6, &tcp_segment(1, 443, 0, 0x18, &[], b"some payload bytes"));
        for len in 0..v6.len() {
            assert!(parse_tcp_packet(&v6[..len]).is_none(), "v6 len {}", len);
        }
    }

    #[test]
    fn random_garbage_never_panics() {
        let mut seed: u64 = 0x0fed_cba9_8765_4321;
        let mut next = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as u8
        };

        for round in 0..5000 {
            let len = (round % 120) + 1;
            let mut data: Vec<u8> = (0..len).map(|_| next()).collect();

            // Make many of them look like real headers so the parser goes deep.
            match round % 3 {
                0 if data.len() > 40 => {
                    data[0] = 0x45;
                    data[2] = 0;
                    data[3] = data.len() as u8;
                    data[6] = 0x40;
                    data[7] = 0;
                    data[9] = 6;
                    data[32] = 0x50;
                }
                1 if data.len() > 60 => {
                    data[0] = 0x60;
                    data[4] = 0;
                    data[5] = (data.len() - 40) as u8;
                    data[6] = if round % 2 == 0 { 6 } else { 0 };
                    data[52] = 0x50;
                }
                _ => {}
            }

            let _ = parse_tcp_packet(&data);
        }
    }
}
