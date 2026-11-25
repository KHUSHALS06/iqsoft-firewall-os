use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

const DEFAULT_SOCKET: &str = "/run/clamav/clamd.ctl";
const CHUNK_SIZE: usize = 64 * 1024;
const MAX_RESPONSE_SIZE: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClamAvVerdict {
    Clean,
    Infected(String),
}

#[derive(Debug, Clone)]
pub struct ClamAvClient {
    socket_path: PathBuf,
}

/// One open INSTREAM conversation with clamd. Data can be sent in several
/// pieces; the verdict only arrives after `finish()`.
///
/// Note: clamd cannot start scanning before it has received the whole stream,
/// so a session does not make the scan itself faster. It only lets the caller
/// hand data over as it arrives instead of holding all of it first.
#[derive(Debug)]
pub struct ClamAvSession {
    stream: UnixStream,
}

impl ClamAvClient {
    pub fn new() -> Self {
        Self {
            socket_path: PathBuf::from(DEFAULT_SOCKET),
        }
    }

    pub fn with_socket(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub async fn ping(&self) -> Result<bool, String> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| format!("Virus scanner connection failed: {e}"))?;

        stream
            .write_all(b"zPING\0")
            .await
            .map_err(|e| format!("Virus scanner PING failed: {e}"))?;

        let response = Self::read_response(&mut stream).await?;

        if response.trim() == "PONG" {
            Ok(true)
        } else {
            Err(format!("Unexpected virus scanner PING response: {response}"))
        }
    }

    /// Open an INSTREAM session (used for streaming scans).
    pub async fn begin_stream(&self) -> Result<ClamAvSession, String> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| format!("Virus scanner connection failed: {e}"))?;

        stream
            .write_all(b"zINSTREAM\0")
            .await
            .map_err(|e| format!("Failed to start INSTREAM: {e}"))?;

        Ok(ClamAvSession { stream })
    }

    /// Scan a complete buffer in one go.
    pub async fn scan_bytes(&self, data: &[u8]) -> Result<ClamAvVerdict, String> {
        let mut session = self.begin_stream().await?;
        session.send(data).await?;
        session.finish().await
    }

    async fn read_response(stream: &mut UnixStream) -> Result<String, String> {
        let mut response = Vec::new();

        loop {
            let mut byte = [0u8; 1];

            let count = stream
                .read(&mut byte)
                .await
                .map_err(|e| format!("Failed to read virus scanner response: {e}"))?;

            if count == 0 {
                return Err("Virus scanner closed the connection unexpectedly".into());
            }

            if byte[0] == 0 {
                break;
            }

            response.push(byte[0]);

            if response.len() > MAX_RESPONSE_SIZE {
                return Err("Virus scanner response exceeded maximum size".into());
            }
        }

        String::from_utf8(response).map_err(|_| "Invalid UTF-8 response from the virus scanner".into())
    }

    fn parse_verdict(response: &str) -> Result<ClamAvVerdict, String> {
        let response = response.trim();

        if response.ends_with(": OK") {
            return Ok(ClamAvVerdict::Clean);
        }

        if response.ends_with(" FOUND") {
            let signature = response
                .split_once(": ")
                .map(|(_, result)| result)
                .unwrap_or(response)
                .trim_end_matches(" FOUND");

            return Ok(ClamAvVerdict::Infected(signature.to_string()));
        }

        Err(format!("Virus scanner scan error: {response}"))
    }
}

impl ClamAvSession {
    /// Send more data. Empty input is ignored: a zero-length chunk would end
    /// the stream, so it must only ever be sent by `finish()`.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), String> {
        for chunk in data.chunks(CHUNK_SIZE) {
            let length = u32::try_from(chunk.len()).map_err(|_| "Invalid chunk size".to_string())?;

            if let Err(e) = self.stream.write_all(&length.to_be_bytes()).await {
                return Err(self.send_error("Failed to send chunk length", e).await);
            }

            if let Err(e) = self.stream.write_all(chunk).await {
                return Err(self.send_error("Failed to send file data", e).await);
            }
        }

        Ok(())
    }

    /// End the stream and wait for clamd's verdict.
    pub async fn finish(mut self) -> Result<ClamAvVerdict, String> {
        self.stream
            .write_all(&0u32.to_be_bytes())
            .await
            .map_err(|e| format!("Failed to finish INSTREAM: {e}"))?;

        self.stream
            .flush()
            .await
            .map_err(|e| format!("Failed to flush virus scanner stream: {e}"))?;

        let response = ClamAvClient::read_response(&mut self.stream).await?;

        ClamAvClient::parse_verdict(&response)
    }

    /// When clamd rejects a stream (for example "size limit exceeded") it
    /// replies and closes the socket, so our next write fails. Try to read
    /// that reply so the error says what actually happened.
    async fn send_error(&mut self, what: &str, error: std::io::Error) -> String {
        match timeout(
            Duration::from_millis(500),
            ClamAvClient::read_response(&mut self.stream),
        )
        .await
        {
            Ok(Ok(message)) if !message.is_empty() => {
                format!("Virus scanner rejected the stream: {message}")
            }
            _ => format!("{what}: {error}"),
        }
    }
}

impl Default for ClamAvClient {
    fn default() -> Self {
        Self::new()
    }
}
