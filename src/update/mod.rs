//! Agent auto-update system.
//!
//! This module handles checking for updates, downloading new binaries,
//! verifying signatures, and gracefully restarting the agent.
//!
//! ## Security
//!
//! - All binaries are signed with Ed25519
//! - SHA256 checksum verification
//! - Multiple public keys supported for key rotation
//!
//! ## Update Flow
//!
//! 1. Check coordinator for new version (every 30 min)
//! 2. Download new binary to temp location
//! 3. Verify signature and checksum
//! 4. Wait for active jobs to complete
//! 5. exec() the new binary

mod download;
mod restart;
mod verify;

pub use verify::VerifyError;

use crate::config::AgentConfig;
use semver::Version;
use serde::Deserialize;
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// Default interval between update checks (30 minutes)
const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Jitter range for update checks (±5 minutes)
const CHECK_JITTER: Duration = Duration::from_secs(5 * 60);

/// Update information from coordinator
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateInfo {
    pub update_available: bool,
    pub current_version: String,
    #[serde(default)]
    pub latest_version: Option<String>,
    #[serde(default)]
    pub is_critical: bool,
    #[serde(default)]
    pub download_url: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub checksum_sha256: Option<String>,
    #[serde(default)]
    pub size_bytes: Option<u64>,
    #[serde(default)]
    pub release_notes: Option<String>,
}

/// Update checker that polls the coordinator for new versions
pub struct UpdateChecker {
    coordinator_url: String,
    current_version: Version,
    platform: String,
    host_id: String,
    check_interval: Duration,
    last_check: Option<Instant>,
    http_client: reqwest::Client,
}

impl UpdateChecker {
    /// Create a new update checker
    pub fn new(config: &AgentConfig, host_id: String) -> Result<Self, UpdateError> {
        let current_version = Version::parse(env!("CARGO_PKG_VERSION"))
            .map_err(|e| UpdateError::VersionParse(e.to_string()))?;

        let platform = Self::detect_platform();

        // Extract coordinator URL from NATS URL
        let coordinator_url = Self::extract_coordinator_url(&config.coordinator.nats_url);

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| UpdateError::HttpClient(e.to_string()))?;

        Ok(Self {
            coordinator_url,
            current_version,
            platform,
            host_id,
            check_interval: DEFAULT_CHECK_INTERVAL,
            last_check: None,
            http_client,
        })
    }

    /// Detect the current platform
    fn detect_platform() -> String {
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;

        match (os, arch) {
            ("linux", "x86_64") => "linux-x86_64".to_string(),
            ("linux", "aarch64") => "linux-aarch64".to_string(),
            ("macos", "x86_64") => "darwin-x86_64".to_string(),
            ("macos", "aarch64") => "darwin-aarch64".to_string(),
            ("windows", "x86_64") => "windows-x86_64".to_string(),
            _ => format!("{}-{}", os, arch),
        }
    }

    /// Extract HTTP coordinator URL from NATS URL
    fn extract_coordinator_url(nats_url: &str) -> String {
        // Convert nats://host:4222 to http://host:4000
        nats_url
            .replace("nats://", "http://")
            .replace(":4222", ":4000")
    }

    /// Check if enough time has passed since last check
    fn should_check(&self) -> bool {
        match self.last_check {
            None => true,
            Some(last) => {
                // Add jitter to prevent thundering herd
                let jitter = rand::random::<u64>() % CHECK_JITTER.as_secs();
                let interval = self.check_interval + Duration::from_secs(jitter);
                last.elapsed() >= interval
            }
        }
    }

    /// Check for updates from the coordinator
    pub async fn check_for_update(&mut self) -> Result<Option<UpdateInfo>, UpdateError> {
        if !self.should_check() {
            debug!("Skipping update check (too soon)");
            return Ok(None);
        }

        self.last_check = Some(Instant::now());

        let url = format!(
            "{}/api/v1/agent/update?version={}&platform={}&host_id={}",
            self.coordinator_url, self.current_version, self.platform, self.host_id
        );

        debug!("Checking for updates: {}", url);

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| UpdateError::Request(e.to_string()))?;

        if !response.status().is_success() {
            return Err(UpdateError::Request(format!(
                "Server returned {}",
                response.status()
            )));
        }

        let update_info: UpdateInfo = response
            .json()
            .await
            .map_err(|e| UpdateError::Parse(e.to_string()))?;

        if update_info.update_available {
            info!(
                "Update available: {} -> {}",
                update_info.current_version,
                update_info.latest_version.as_deref().unwrap_or("unknown")
            );

            // Verify the update info has all required fields
            if update_info.download_url.is_none()
                || update_info.signature.is_none()
                || update_info.checksum_sha256.is_none()
            {
                return Err(UpdateError::MissingField(
                    "download_url, signature, or checksum_sha256".to_string(),
                ));
            }

            Ok(Some(update_info))
        } else {
            debug!("No update available");
            Ok(None)
        }
    }

    /// Get the current version
    pub fn current_version(&self) -> &Version {
        &self.current_version
    }

    /// Get the platform
    pub fn platform(&self) -> &str {
        &self.platform
    }

    /// Force an immediate check (ignore interval)
    pub fn force_check(&mut self) {
        self.last_check = None;
    }
}

/// Errors that can occur during update checking
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("Failed to parse version: {0}")]
    VersionParse(String),

    #[error("HTTP client error: {0}")]
    HttpClient(String),

    #[error("Request failed: {0}")]
    Request(String),

    #[error("Failed to parse response: {0}")]
    Parse(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Verification failed: {0}")]
    Verification(#[from] VerifyError),

    #[error("Download failed: {0}")]
    Download(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_platform() {
        let platform = UpdateChecker::detect_platform();
        // Should be one of the known platforms
        assert!(
            platform.contains("-"),
            "Platform should contain a hyphen: {}",
            platform
        );
    }

    #[test]
    fn test_extract_coordinator_url() {
        let nats_url = "nats://localhost:4222";
        let http_url = UpdateChecker::extract_coordinator_url(nats_url);
        assert_eq!(http_url, "http://localhost:4000");
    }
}
