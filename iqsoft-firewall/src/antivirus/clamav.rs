
use std::path::PathBuf;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

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
            .map_err(|e| format!("ClamAV connection failed: {e}"))?;

        stream
            .write_all(b"zPING\0")
            .await
            .map_err(|e| format!("ClamAV PING failed: {e}"))?;

        let response = Self::read_response(&mut stream).await?;

        if response.trim() == "PONG" {
            Ok(true)
        } else {
            Err(format!("Unexpected ClamAV PING response: {response}"))
        }
    }

    pub async fn scan_bytes(
        &self,
        data: &[u8],
    ) -> Result<ClamAvVerdict, String> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| format!("ClamAV connection failed: {e}"))?;

        // Start the ClamAV INSTREAM protocol.
        stream
            .write_all(b"zINSTREAM\0")
            .await
            .map_err(|e| format!("Failed to start INSTREAM: {e}"))?;

        // Send file contents in chunks.
        for chunk in data.chunks(CHUNK_SIZE) {
            let length = u32::try_from(chunk.len())
                .map_err(|_| "Invalid chunk size".to_string())?;

            stream
                .write_all(&length.to_be_bytes())
                .await
                .map_err(|e| format!("Failed to send chunk length: {e}"))?;

            stream
                .write_all(chunk)
                .await
                .map_err(|e| format!("Failed to send file data: {e}"))?;
        }

        // A zero-length chunk marks the end of the stream.
        stream
            .write_all(&0u32.to_be_bytes())
            .await
            .map_err(|e| format!("Failed to finish INSTREAM: {e}"))?;

        stream
            .flush()
            .await
            .map_err(|e| format!("Failed to flush ClamAV stream: {e}"))?;

        let response = Self::read_response(&mut stream).await?;

        Self::parse_verdict(&response)
    }

    async fn read_response(
        stream: &mut UnixStream,
    ) -> Result<String, String> {
        let mut response = Vec::new();

        loop {
            let mut byte = [0u8; 1];

            let count = stream
                .read(&mut byte)
                .await
                .map_err(|e| format!("Failed to read ClamAV response: {e}"))?;

            if count == 0 {
                return Err("ClamAV closed the connection unexpectedly".into());
            }

            if byte[0] == 0 {
                break;
            }

            response.push(byte[0]);

            if response.len() > MAX_RESPONSE_SIZE {
                return Err("ClamAV response exceeded maximum size".into());
            }
        }

        String::from_utf8(response)
            .map_err(|_| "Invalid UTF-8 response from ClamAV".into())
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

        Err(format!("ClamAV scan error: {response}"))
    }
}

impl Default for ClamAvClient {
    fn default() -> Self {
        Self::new()
    }
}

