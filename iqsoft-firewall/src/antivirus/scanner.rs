
use std::time::Duration;

use tokio::time::timeout;

use super::clamav::{ClamAvClient, ClamAvVerdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Block,
    Monitor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailMode {
    Open,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OversizeAction {
    Allow,
    Block,
}

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub enabled: bool,
    pub mode: ScanMode,
    pub fail_mode: FailMode,
    pub max_scan_bytes: usize,
    pub oversize_action: OversizeAction,
    pub scan_timeout: Duration,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: ScanMode::Block,
            fail_mode: FailMode::Closed,
            max_scan_bytes: 25 * 1024 * 1024,
            oversize_action: OversizeAction::Block,
            scan_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanAction {
    Allow,
    Block,
}

#[derive(Debug, Clone)]
pub struct ScannerOutcome {
    pub action: ScanAction,
    pub infected: bool,
    pub signature: Option<String>,
    pub reason: String,
    pub scanned: bool,
}

pub struct AntivirusScanner {
    client: ClamAvClient,
    config: ScannerConfig,
}

impl AntivirusScanner {
    pub fn new(config: ScannerConfig) -> Self {
        Self {
            client: ClamAvClient::new(),
            config,
        }
    }

    pub fn with_client(
        client: ClamAvClient,
        config: ScannerConfig,
    ) -> Self {
        Self { client, config }
    }

    pub async fn scan(&self, data: &[u8]) -> ScannerOutcome {
        // Antivirus disabled.
        if !self.config.enabled {
            return Self::outcome(
                ScanAction::Allow,
                false,
                None,
                "Antivirus is disabled",
                false,
            );
        }

        // File size check.
        if data.len() > self.config.max_scan_bytes {
            let action = match self.config.oversize_action {
                OversizeAction::Allow => ScanAction::Allow,
                OversizeAction::Block => ScanAction::Block,
            };

            return Self::outcome(
                action,
                false,
                None,
                "File exceeds maximum scanning size",
                false,
            );
        }

        // Scan using ClamAV.
        let scan_result = timeout(
            self.config.scan_timeout,
            self.client.scan_bytes(data),
        )
        .await;

        match scan_result {
            Ok(Ok(ClamAvVerdict::Clean)) => {
                Self::outcome(
                    ScanAction::Allow,
                    false,
                    None,
                    "File is clean",
                    true,
                )
            }

            Ok(Ok(ClamAvVerdict::Infected(signature))) => {
                let action = match self.config.mode {
                    ScanMode::Block => ScanAction::Block,
                    ScanMode::Monitor => ScanAction::Allow,
                };

                Self::outcome(
                    action,
                    true,
                    Some(signature),
                    "Malware detected",
                    true,
                )
            }

            Ok(Err(error)) => {
                self.handle_scan_error(error)
            }

            Err(_) => {
                self.handle_scan_error(
                    "ClamAV scanning timed out".to_string(),
                )
            }
        }
    }

    fn handle_scan_error(&self, error: String) -> ScannerOutcome {
        let action = match self.config.fail_mode {
            FailMode::Open => ScanAction::Allow,
            FailMode::Closed => ScanAction::Block,
        };

        Self::outcome(
            action,
            false,
            None,
            &format!("Antivirus scanning failed: {error}"),
            false,
        )
    }

    fn outcome(
        action: ScanAction,
        infected: bool,
        signature: Option<String>,
        reason: &str,
        scanned: bool,
    ) -> ScannerOutcome {
        ScannerOutcome {
            action,
            infected,
            signature,
            reason: reason.to_string(),
            scanned,
        }
    }
}

