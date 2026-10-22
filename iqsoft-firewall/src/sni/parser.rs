// Reads the server name (SNI) out of a TLS ClientHello.
//
// When a browser opens an HTTPS connection, its first message (the
// ClientHello) is not encrypted and contains the site name. This file only
// reads that name. Nothing is decrypted.
//
// It is pure parsing: bytes in, answer out. It never touches the network,
// which makes it easy to test and safe against hostile input: every read is
// bounds-checked, so bad data gives an answer, never a crash.

// Nothing calls this code until the next steps are added.
#![allow(dead_code)]

/// Longest hostname allowed in DNS.
pub const MAX_NAME_LEN: usize = 253;

/// A TLS record holds at most 16 KB, and no real ClientHello is bigger than a
/// few KB. Anything above this is refused so nobody can make us buffer forever.
pub const MAX_HELLO_BYTES: usize = 16 * 1024;

const RECORD_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: usize = 0x0000;
const NAME_TYPE_HOST: u8 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniResult {
    /// The site name, lowercase, without a trailing dot.
    Name(String),
    /// A complete ClientHello that carries no site name.
    NoName,
    /// This looks like the start of a ClientHello but more bytes are needed.
    /// The caller keeps the bytes and tries again when the next packet arrives.
    NeedMore,
    /// Not TLS at all (or not a ClientHello).
    NotTls,
    /// Looks like a ClientHello but it is broken or the name is not a valid
    /// hostname. Real browsers never send this; evasion tools sometimes do.
    Malformed,
}

/// `data` is the TCP payload of the connection from its very first byte,
/// all packets so far joined together.
pub fn parse_client_hello(data: &[u8]) -> SniResult {
    let mut handshake: Vec<u8> = Vec::new();
    let mut pos = 0usize;

    // A ClientHello can be split over several TLS records. Join them first.
    loop {
        let rest = &data[pos..];

        match rest.first() {
            None => return SniResult::NeedMore,
            Some(&t) if t != RECORD_HANDSHAKE => return SniResult::NotTls,
            Some(_) => {}
        }

        // TLS versions on the wire are 0x0300 to 0x0304.
        if rest.len() >= 2 && rest[1] != 0x03 {
            return SniResult::NotTls;
        }
        if rest.len() >= 3 && rest[2] > 0x04 {
            return SniResult::NotTls;
        }
        if rest.len() < 5 {
            return SniResult::NeedMore;
        }

        let record_len = u16::from_be_bytes([rest[3], rest[4]]) as usize;

        if record_len == 0 || record_len > MAX_HELLO_BYTES {
            return SniResult::NotTls;
        }
        if rest.len() < 5 + record_len {
            return SniResult::NeedMore;
        }

        handshake.extend_from_slice(&rest[5..5 + record_len]);
        pos += 5 + record_len;

        if handshake.len() > MAX_HELLO_BYTES + 4 {
            return SniResult::NotTls;
        }

        if handshake[0] != HANDSHAKE_CLIENT_HELLO {
            return SniResult::NotTls;
        }

        if handshake.len() >= 4 {
            let hello_len = ((handshake[1] as usize) << 16)
                | ((handshake[2] as usize) << 8)
                | (handshake[3] as usize);

            if hello_len > MAX_HELLO_BYTES {
                return SniResult::NotTls;
            }

            if handshake.len() >= 4 + hello_len {
                return parse_body(&handshake[4..4 + hello_len])
                    .unwrap_or(SniResult::Malformed);
            }
        }
        // Not complete yet: read the next record.
    }
}

/// Walks the ClientHello body. None means the bytes ran out where they should not.
fn parse_body(body: &[u8]) -> Option<SniResult> {
    let mut r = Reader::new(body);

    r.skip(2)?; // client version
    r.skip(32)?; // random

    let session_id_len = r.u8()? as usize;
    r.skip(session_id_len)?;

    let cipher_suites_len = r.u16()?;
    r.skip(cipher_suites_len)?;

    let compression_len = r.u8()? as usize;
    r.skip(compression_len)?;

    // Extensions are optional in old TLS versions.
    if r.remaining() == 0 {
        return Some(SniResult::NoName);
    }

    let extensions_len = r.u16()?;
    let mut extensions = Reader::new(r.take(extensions_len)?);

    while extensions.remaining() > 0 {
        let kind = extensions.u16()?;
        let len = extensions.u16()?;
        let data = extensions.take(len)?;

        if kind == EXT_SERVER_NAME {
            return parse_server_name(data);
        }
    }

    Some(SniResult::NoName)
}

fn parse_server_name(data: &[u8]) -> Option<SniResult> {
    let mut r = Reader::new(data);

    let list_len = r.u16()?;
    let mut list = Reader::new(r.take(list_len)?);

    while list.remaining() > 0 {
        let name_type = list.u8()?;
        let len = list.u16()?;
        let name = list.take(len)?;

        if name_type == NAME_TYPE_HOST {
            return Some(match clean_host(name) {
                Some(host) => SniResult::Name(host),
                None => SniResult::Malformed,
            });
        }
    }

    Some(SniResult::NoName)
}

/// Lowercases the name and refuses anything that is not a plausible hostname.
/// Spaces, NUL bytes and non-ASCII are refused because they are only ever
/// used to trick a filter.
fn clean_host(raw: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut host = text.to_ascii_lowercase();

    if host.ends_with('.') {
        host.pop();
    }

    if host.is_empty() || host.len() > MAX_NAME_LEN {
        return None;
    }

    if host.starts_with('.') || host.contains("..") {
        return None;
    }

    if !host
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.' || c == '_')
    {
        return None;
    }

    Some(host)
}

/// A tiny cursor over bytes where every read checks the length first.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.remaining() {
            return None;
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(out)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<usize> {
        self.take(2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut v = kind.to_be_bytes().to_vec();
        v.extend((data.len() as u16).to_be_bytes());
        v.extend(data);
        v
    }

    fn sni_ext(name: &str) -> Vec<u8> {
        let mut entry = vec![0u8];
        entry.extend((name.len() as u16).to_be_bytes());
        entry.extend(name.as_bytes());

        let mut data = (entry.len() as u16).to_be_bytes().to_vec();
        data.extend(entry);

        ext(0, &data)
    }

    fn hello_body(extensions: Option<&[u8]>) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend([7u8; 32]); // random
        body.push(32);
        body.extend([9u8; 32]); // session id
        body.extend([0x00, 0x04, 0x13, 0x01, 0x13, 0x02]); // cipher suites
        body.extend([0x01, 0x00]); // compression

        if let Some(extensions) = extensions {
            body.extend((extensions.len() as u16).to_be_bytes());
            body.extend(extensions);
        }

        body
    }

    fn handshake(body: &[u8]) -> Vec<u8> {
        let len = (body.len() as u32).to_be_bytes();
        let mut v = vec![HANDSHAKE_CLIENT_HELLO, len[1], len[2], len[3]];
        v.extend(body);
        v
    }

    fn record(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x16, 0x03, 0x01];
        v.extend((payload.len() as u16).to_be_bytes());
        v.extend(payload);
        v
    }

    fn hello_with(extensions: &[u8]) -> Vec<u8> {
        record(&handshake(&hello_body(Some(extensions))))
    }

    #[test]
    fn finds_the_name() {
        let data = hello_with(&sni_ext("www.example.com"));
        assert_eq!(parse_client_hello(&data), SniResult::Name("www.example.com".into()));
    }

    #[test]
    fn name_is_lowercased_and_trailing_dot_removed() {
        let data = hello_with(&sni_ext("WWW.Example.COM."));
        assert_eq!(parse_client_hello(&data), SniResult::Name("www.example.com".into()));
    }

    #[test]
    fn name_is_found_after_other_extensions() {
        let mut exts = ext(0x0015, &[0u8; 300]); // padding
        exts.extend(ext(0x002b, &[0x02, 0x03, 0x04])); // supported versions
        exts.extend(sni_ext("tiktok.com"));
        exts.extend(ext(0x000a, &[0x00, 0x02, 0x00, 0x1d]));

        assert_eq!(
            parse_client_hello(&hello_with(&exts)),
            SniResult::Name("tiktok.com".into())
        );
    }

    #[test]
    fn underscores_are_allowed() {
        let data = hello_with(&sni_ext("my_host.example.com"));
        assert_eq!(parse_client_hello(&data), SniResult::Name("my_host.example.com".into()));
    }

    #[test]
    fn hello_without_a_name() {
        let data = hello_with(&ext(0x000a, &[0x00, 0x02, 0x00, 0x1d]));
        assert_eq!(parse_client_hello(&data), SniResult::NoName);
    }

    #[test]
    fn hello_without_any_extensions() {
        let data = record(&handshake(&hello_body(None)));
        assert_eq!(parse_client_hello(&data), SniResult::NoName);
    }

    #[test]
    fn a_non_hostname_entry_means_no_name() {
        let mut entry = vec![1u8]; // name type 1 is not a hostname
        entry.extend(3u16.to_be_bytes());
        entry.extend(b"abc");
        let mut data = (entry.len() as u16).to_be_bytes().to_vec();
        data.extend(entry);

        assert_eq!(parse_client_hello(&hello_with(&ext(0, &data))), SniResult::NoName);
    }

    #[test]
    fn every_cut_short_version_asks_for_more() {
        let full = hello_with(&sni_ext("www.example.com"));

        for len in 0..full.len() {
            assert_eq!(parse_client_hello(&full[..len]), SniResult::NeedMore, "len {}", len);
        }
    }

    #[test]
    fn bytes_after_the_hello_are_ignored() {
        let mut data = hello_with(&sni_ext("example.org"));
        data.extend(b"more data that does not matter");

        assert_eq!(parse_client_hello(&data), SniResult::Name("example.org".into()));
    }

    #[test]
    fn a_hello_split_over_two_tls_records_is_joined() {
        let hs = handshake(&hello_body(Some(&sni_ext("split.example.com"))));
        let (a, b) = hs.split_at(20);

        let first_only = record(a);
        assert_eq!(parse_client_hello(&first_only), SniResult::NeedMore);

        let mut both = record(a);
        both.extend(record(b));
        assert_eq!(parse_client_hello(&both), SniResult::Name("split.example.com".into()));

        let cut = &both[..both.len() - 3];
        assert_eq!(parse_client_hello(cut), SniResult::NeedMore);
    }

    #[test]
    fn plain_http_and_other_traffic_is_not_tls() {
        assert_eq!(parse_client_hello(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), SniResult::NotTls);
        assert_eq!(parse_client_hello(&[0x17, 0x03, 0x03, 0x00, 0x10]), SniResult::NotTls);
        assert_eq!(parse_client_hello(&[0x16, 0x04, 0x01]), SniResult::NotTls);
        assert_eq!(parse_client_hello(&[0x16, 0x03, 0x09]), SniResult::NotTls);
    }

    #[test]
    fn other_handshake_messages_are_not_a_client_hello() {
        let mut hs = handshake(&hello_body(None));
        hs[0] = 0x02; // ServerHello
        assert_eq!(parse_client_hello(&record(&hs)), SniResult::NotTls);
    }

    #[test]
    fn silly_record_sizes_are_refused() {
        assert_eq!(parse_client_hello(&[0x16, 0x03, 0x01, 0x00, 0x00]), SniResult::NotTls);
        assert_eq!(parse_client_hello(&[0x16, 0x03, 0x01, 0xff, 0xff]), SniResult::NotTls);
    }

    #[test]
    fn bad_hostnames_are_malformed() {
        for bad in ["bad host.com", "a\0b.com", "", "a..b.com", ".a.com", "bücher.de", "a/b.com", "a;b.com"] {
            assert_eq!(
                parse_client_hello(&hello_with(&sni_ext(bad))),
                SniResult::Malformed,
                "{:?}",
                bad
            );
        }

        let too_long = format!("{}.com", "a".repeat(260));
        assert_eq!(parse_client_hello(&hello_with(&sni_ext(&too_long))), SniResult::Malformed);
    }

    #[test]
    fn lengths_that_lie_are_malformed() {
        // The name claims 200 bytes but only 3 follow.
        let mut entry = vec![0u8, 0x00, 200];
        entry.extend(b"abc");
        let mut data = (entry.len() as u16).to_be_bytes().to_vec();
        data.extend(entry);

        assert_eq!(parse_client_hello(&hello_with(&ext(0, &data))), SniResult::Malformed);

        // The body stops in the middle of the session id.
        let mut body = vec![0x03, 0x03];
        body.extend([7u8; 32]);
        body.push(255);
        assert_eq!(parse_client_hello(&record(&handshake(&body))), SniResult::Malformed);
    }

    #[test]
    fn random_garbage_never_panics() {
        let mut seed: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as u8
        };

        for round in 0..3000 {
            let len = (round % 200) + 1;
            let mut data: Vec<u8> = (0..len).map(|_| next()).collect();

            // Half of them start like a real hello so the parser goes deep.
            if round % 2 == 0 && data.len() > 10 {
                data[0] = 0x16;
                data[1] = 0x03;
                data[2] = 0x01;
                data[3] = 0x00;
                data[4] = (data.len() - 5) as u8;
                data[5] = 0x01;
            }

            let _ = parse_client_hello(&data);
        }
    }
}
