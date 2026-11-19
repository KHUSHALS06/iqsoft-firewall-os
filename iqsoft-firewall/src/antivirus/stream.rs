//! Streaming scan with a held-back tail (option 1).
//!
//! The proxy feeds every chunk of a download through `push()`. Almost all of
//! it is released to the client immediately, but the last `holdback` bytes are
//! kept back until clamd has given its verdict (`finish()`):
//!
//! * clean    -> the held tail is released and the download completes
//! * infected -> the tail is never sent; close the client connection, so the
//!               client is left with an incomplete file
//!
//! What this does and does not buy you:
//! * The client sees steady progress and nothing times out, instead of
//!   staring at a stalled connection while the proxy buffers the whole file.
//! * The proxy only keeps the tail in memory.
//! * clamd cannot start scanning before it has the whole stream, so the scan
//!   time itself is still paid once, after the last byte. Options 2 and 3
//!   (skip what needs no scan, make clamd fast) are what reduce that.
//! * An incomplete file is not always unusable (some PDFs, for example, are
//!   repaired by readers). Keep executables and archives on full buffering.
//!
//! Proxy loop sketch:
//!
//! ```ignore
//! let Some(mut scan) = integration::start_stream_scan(&pool).await? else { /* AV off */ };
//! while let Some(chunk) = upstream.next_chunk().await {
//!     match scan.push(&chunk).await {
//!         Push::Send(bytes) => client.send(bytes).await?,
//!         Push::Block(outcome) => { record(outcome); client.abort(); return; }
//!     }
//! }
//! match scan.finish().await {
//!     Finish::Send(tail, outcome) => { client.send(tail).await?; record(outcome); }
//!     Finish::Block(outcome) => { record(outcome); client.abort(); }
//! }
//! ```

use std::mem;

use tokio::time::timeout;

use super::clamav::{ClamAvClient, ClamAvSession, ClamAvVerdict};
use super::scanner::{
    FailMode, OversizeAction, ScanAction, ScanMode, ScannerConfig, ScannerOutcome,
};

/// How many bytes at the end of the file are withheld until the verdict.
pub const DEFAULT_HOLDBACK_BYTES: usize = 256 * 1024;

enum State {
    NotStarted,
    Scanning(ClamAvSession),
    /// Scanning was given up on purpose (over-size allowed, or clamd failed in
    /// fail-open mode). Data now passes straight through.
    PassThrough(ScannerOutcome),
    /// The download was blocked. It stays blocked.
    Blocked(ScannerOutcome),
}

/// What to do with the data after `push()`.
#[derive(Debug)]
pub enum Push {
    /// Send these bytes to the client now (may be empty).
    Send(Vec<u8>),
    /// Stop. Close the client connection and send nothing more.
    Block(ScannerOutcome),
}

/// What to do at the end of the download.
#[derive(Debug)]
pub enum Finish {
    /// Send the final held bytes, then record the outcome.
    Send(Vec<u8>, ScannerOutcome),
    /// Do not send the held bytes. Close the client connection.
    Block(ScannerOutcome),
}

pub struct StreamingScan {
    client: ClamAvClient,
    config: ScannerConfig,
    holdback: usize,
    state: State,
    pending: Vec<u8>,
    total: usize,
}

fn failure_outcome(config: &ScannerConfig, error: &str) -> ScannerOutcome {
    let action = match config.fail_mode {
        FailMode::Open => ScanAction::Allow,
        FailMode::Closed => ScanAction::Block,
    };

    ScannerOutcome {
        action,
        infected: false,
        signature: None,
        // events.rs recognises scan errors by this wording.
        reason: format!("Antivirus scanning failed: {error}"),
        scanned: false,
    }
}

impl StreamingScan {
    pub fn new(client: ClamAvClient, config: ScannerConfig, holdback: usize) -> Self {
        Self {
            client,
            config,
            holdback,
            state: State::NotStarted,
            pending: Vec::new(),
            total: 0,
        }
    }

    /// Total bytes pushed so far (useful for the event record).
    pub fn total_bytes(&self) -> usize {
        self.total
    }

    pub async fn push(&mut self, chunk: &[u8]) -> Push {
        self.total = self.total.saturating_add(chunk.len());

        match &self.state {
            State::PassThrough(_) => return Push::Send(chunk.to_vec()),
            State::Blocked(outcome) => return Push::Block(outcome.clone()),
            State::NotStarted | State::Scanning(_) => {}
        }

        if self.total > self.config.max_scan_bytes {
            return self.oversize(chunk);
        }

        let limit = self.config.scan_timeout;

        let mut session = match mem::replace(&mut self.state, State::NotStarted) {
            State::Scanning(session) => session,
            _ => match timeout(limit, self.client.begin_stream()).await {
                Ok(Ok(session)) => session,
                Ok(Err(error)) => return self.fail(&error, chunk),
                Err(_) => return self.fail("ClamAV connection timed out", chunk),
            },
        };

        match timeout(limit, session.send(chunk)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return self.fail(&error, chunk),
            Err(_) => return self.fail("ClamAV scanning timed out", chunk),
        }

        self.state = State::Scanning(session);

        // Release everything except the last `holdback` bytes.
        self.pending.extend_from_slice(chunk);
        let release = self.pending.len().saturating_sub(self.holdback);

        Push::Send(self.pending.drain(..release).collect())
    }

    pub async fn finish(mut self) -> Finish {
        let limit = self.config.scan_timeout;
        let held = mem::take(&mut self.pending);

        let session = match mem::replace(&mut self.state, State::NotStarted) {
            State::Blocked(outcome) => return Finish::Block(outcome),
            State::PassThrough(outcome) => return Finish::Send(held, outcome),
            State::NotStarted => {
                // Nothing was ever pushed (empty body).
                let outcome = ScannerOutcome {
                    action: ScanAction::Allow,
                    infected: false,
                    signature: None,
                    reason: "Empty body, nothing to scan".to_string(),
                    scanned: false,
                };
                return Finish::Send(held, outcome);
            }
            State::Scanning(session) => session,
        };

        let verdict = match timeout(limit, session.finish()).await {
            Ok(result) => result,
            Err(_) => Err("ClamAV scanning timed out".to_string()),
        };

        match verdict {
            Ok(ClamAvVerdict::Clean) => Finish::Send(
                held,
                ScannerOutcome {
                    action: ScanAction::Allow,
                    infected: false,
                    signature: None,
                    reason: "File is clean".to_string(),
                    scanned: true,
                },
            ),
            Ok(ClamAvVerdict::Infected(signature)) => {
                let action = match self.config.mode {
                    ScanMode::Block => ScanAction::Block,
                    ScanMode::Monitor => ScanAction::Allow,
                };
                let block = action == ScanAction::Block;

                let outcome = ScannerOutcome {
                    action,
                    infected: true,
                    signature: Some(signature),
                    reason: "Malware detected".to_string(),
                    scanned: true,
                };

                if block {
                    Finish::Block(outcome)
                } else {
                    Finish::Send(held, outcome)
                }
            }
            Err(error) => {
                let outcome = failure_outcome(&self.config, &error);

                if outcome.action == ScanAction::Block {
                    Finish::Block(outcome)
                } else {
                    Finish::Send(held, outcome)
                }
            }
        }
    }

    /// clamd failed mid-download. Fail-open: stop scanning and release
    /// everything held. Fail-closed: block.
    fn fail(&mut self, error: &str, chunk: &[u8]) -> Push {
        let outcome = failure_outcome(&self.config, error);

        if outcome.action == ScanAction::Allow {
            let mut out = mem::take(&mut self.pending);
            out.extend_from_slice(chunk);
            self.state = State::PassThrough(outcome);
            Push::Send(out)
        } else {
            self.state = State::Blocked(outcome.clone());
            Push::Block(outcome)
        }
    }

    /// The download grew past the scan limit. Dropping the old state closes
    /// the clamd socket, which makes clamd abandon the stream.
    fn oversize(&mut self, chunk: &[u8]) -> Push {
        let action = match self.config.oversize_action {
            OversizeAction::Allow => ScanAction::Allow,
            OversizeAction::Block => ScanAction::Block,
        };
        let allow = action == ScanAction::Allow;

        let outcome = ScannerOutcome {
            action,
            infected: false,
            signature: None,
            reason: "File exceeds maximum scanning size".to_string(),
            scanned: false,
        };

        if allow {
            let mut out = mem::take(&mut self.pending);
            out.extend_from_slice(chunk);
            self.state = State::PassThrough(outcome);
            Push::Send(out)
        } else {
            self.state = State::Blocked(outcome.clone());
            Push::Block(outcome)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    use tokio::sync::oneshot;

    fn sock_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("iqfw-{name}-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    /// Minimal fake clamd: speaks just enough INSTREAM for these tests and
    /// reports every byte it received.
    fn fake_clamd(path: &Path, reply: &'static [u8]) -> oneshot::Receiver<Vec<u8>> {
        let listener = UnixListener::bind(path).unwrap();
        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let Ok((mut s, _)) = listener.accept().await else { return };

            let mut command = [0u8; 10]; // "zINSTREAM\0"
            if s.read_exact(&mut command).await.is_err() {
                return;
            }

            let mut received = Vec::new();
            loop {
                let mut len = [0u8; 4];
                if s.read_exact(&mut len).await.is_err() {
                    return;
                }
                let n = u32::from_be_bytes(len) as usize;
                if n == 0 {
                    break;
                }
                let mut buf = vec![0u8; n];
                if s.read_exact(&mut buf).await.is_err() {
                    return;
                }
                received.extend_from_slice(&buf);
            }

            let _ = s.write_all(reply).await;
            let _ = tx.send(received);
        });

        rx
    }

    fn config(mode: ScanMode, fail: FailMode, max: usize, over: OversizeAction) -> ScannerConfig {
        ScannerConfig {
            enabled: true,
            mode,
            fail_mode: fail,
            max_scan_bytes: max,
            oversize_action: over,
            scan_timeout: Duration::from_secs(5),
        }
    }

    fn scan(path: &Path, config: ScannerConfig, holdback: usize) -> StreamingScan {
        StreamingScan::new(ClamAvClient::with_socket(path), config, holdback)
    }

    fn sample(len: u32) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[tokio::test]
    async fn clean_file_is_released_in_order_after_the_verdict() {
        let path = sock_path("clean");
        let seen = fake_clamd(&path, b"stream: OK\0");
        let mut s = scan(
            &path,
            config(ScanMode::Block, FailMode::Closed, 1 << 20, OversizeAction::Block),
            100,
        );

        let data = sample(1000);
        let mut out = Vec::new();

        for part in data.chunks(300) {
            match s.push(part).await {
                Push::Send(bytes) => out.extend(bytes),
                Push::Block(_) => panic!("clean file was blocked"),
            }
        }

        // The last 100 bytes are still held back.
        assert_eq!(out.len(), 900);

        match s.finish().await {
            Finish::Send(tail, outcome) => {
                out.extend(tail);
                assert!(outcome.scanned && !outcome.infected);
            }
            Finish::Block(_) => panic!("clean file was blocked"),
        }

        assert_eq!(out, data);
        // clamd really saw every byte.
        assert_eq!(seen.await.unwrap(), data);
    }

    #[tokio::test]
    async fn infected_file_is_blocked_and_the_tail_is_never_sent() {
        let path = sock_path("infected");
        let _seen = fake_clamd(&path, b"stream: Eicar-Test-Signature FOUND\0");
        let mut s = scan(
            &path,
            config(ScanMode::Block, FailMode::Closed, 1 << 20, OversizeAction::Block),
            100,
        );

        let data = sample(1000);
        let mut out = Vec::new();

        for part in data.chunks(300) {
            if let Push::Send(bytes) = s.push(part).await {
                out.extend(bytes);
            }
        }

        match s.finish().await {
            Finish::Block(outcome) => {
                assert!(outcome.infected);
                assert_eq!(outcome.signature.as_deref(), Some("Eicar-Test-Signature"));
                assert_eq!(outcome.action, ScanAction::Block);
            }
            Finish::Send(..) => panic!("infected file was released"),
        }

        assert!(out.len() < data.len());
    }

    #[tokio::test]
    async fn monitor_mode_reports_but_releases() {
        let path = sock_path("monitor");
        let _seen = fake_clamd(&path, b"stream: Eicar-Test-Signature FOUND\0");
        let mut s = scan(
            &path,
            config(ScanMode::Monitor, FailMode::Closed, 1 << 20, OversizeAction::Block),
            100,
        );

        let data = sample(500);
        let mut out = Vec::new();

        for part in data.chunks(200) {
            if let Push::Send(bytes) = s.push(part).await {
                out.extend(bytes);
            }
        }

        match s.finish().await {
            Finish::Send(tail, outcome) => {
                out.extend(tail);
                assert!(outcome.infected);
                assert_eq!(outcome.action, ScanAction::Allow);
            }
            Finish::Block(_) => panic!("monitor mode must not block"),
        }

        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn clamd_down_fail_open_passes_everything_through() {
        let path = sock_path("down-open"); // nothing is listening
        let mut s = scan(
            &path,
            config(ScanMode::Block, FailMode::Open, 1 << 20, OversizeAction::Block),
            100,
        );

        match s.push(b"hello").await {
            Push::Send(bytes) => assert_eq!(bytes, b"hello"),
            Push::Block(_) => panic!("fail-open must not block"),
        }
        match s.push(b" world").await {
            Push::Send(bytes) => assert_eq!(bytes, b" world"),
            Push::Block(_) => panic!("fail-open must not block"),
        }
        match s.finish().await {
            Finish::Send(tail, outcome) => {
                assert!(tail.is_empty());
                assert_eq!(outcome.action, ScanAction::Allow);
                assert!(outcome.reason.contains("scanning failed"));
            }
            Finish::Block(_) => panic!("fail-open must not block"),
        }
    }

    #[tokio::test]
    async fn clamd_down_fail_closed_blocks() {
        let path = sock_path("down-closed");
        let mut s = scan(
            &path,
            config(ScanMode::Block, FailMode::Closed, 1 << 20, OversizeAction::Block),
            100,
        );

        assert!(matches!(s.push(b"hello").await, Push::Block(_)));
        // Once blocked, always blocked.
        assert!(matches!(s.push(b"more").await, Push::Block(_)));
        assert!(matches!(s.finish().await, Finish::Block(_)));
    }

    #[tokio::test]
    async fn oversize_allowed_flushes_and_passes_the_rest_through() {
        let path = sock_path("big-allow");
        let _seen = fake_clamd(&path, b"stream: OK\0");
        let mut s = scan(
            &path,
            config(ScanMode::Block, FailMode::Closed, 500, OversizeAction::Allow),
            100,
        );

        let data = sample(900);
        let mut out = Vec::new();

        for part in data.chunks(300) {
            match s.push(part).await {
                Push::Send(bytes) => out.extend(bytes),
                Push::Block(_) => panic!("over-size allow must not block"),
            }
        }

        match s.finish().await {
            Finish::Send(tail, outcome) => {
                out.extend(tail);
                assert!(!outcome.scanned);
                assert!(outcome.reason.contains("maximum scanning size"));
            }
            Finish::Block(_) => panic!("over-size allow must not block"),
        }

        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn oversize_block_stops_the_download() {
        let path = sock_path("big-block");
        let _seen = fake_clamd(&path, b"stream: OK\0");
        let mut s = scan(
            &path,
            config(ScanMode::Block, FailMode::Closed, 500, OversizeAction::Block),
            100,
        );

        assert!(matches!(s.push(&sample(300)).await, Push::Send(_)));
        assert!(matches!(s.push(&sample(300)).await, Push::Block(_)));
        assert!(matches!(s.finish().await, Finish::Block(_)));
    }

    #[tokio::test]
    async fn empty_body_is_not_an_error() {
        let path = sock_path("empty");
        let s = scan(
            &path,
            config(ScanMode::Block, FailMode::Closed, 1 << 20, OversizeAction::Block),
            100,
        );

        match s.finish().await {
            Finish::Send(tail, outcome) => {
                assert!(tail.is_empty());
                assert!(!outcome.scanned && !outcome.infected);
            }
            Finish::Block(_) => panic!("empty body must not be blocked"),
        }
    }
}
