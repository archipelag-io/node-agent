//! Container signature verification using cosign.
//!
//! This module verifies container image signatures before execution.
//! It integrates with Sigstore/cosign to ensure workloads are signed
//! by trusted keys.
//!
//! ## Architecture
//!
//! The agent maintains a list of trusted public keys that can be:
//! 1. Bundled with the agent binary
//! 2. Fetched from the coordinator at startup
//! 3. Specified in the config file
//!
//! Before executing any workload, the agent:
//! 1. Checks if signature verification is required
//! 2. Verifies the image signature against trusted keys
//! 3. Blocks execution if verification fails
//!
//! ## Usage
//!
//! ```ignore
//! let verifier = SignatureVerifier::new(config);
//! match verifier.verify("ghcr.io/example/image@sha256:abc...").await {
//!     Ok(SignatureResult::Valid { key_id }) => println!("Verified with {}", key_id),
//!     Ok(SignatureResult::Skipped) => println!("Verification disabled"),
//!     Err(e) => panic!("Verification failed: {}", e),
//! }
//! ```

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::process::Command;
use tracing::{debug, error, info, warn};

/// Configuration for signature verification
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SigningConfig {
    /// Enable signature verification (default: true in production)
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Require all workloads to have valid signatures
    /// If false, unverified workloads can still run (warn-only mode)
    #[serde(default)]
    pub require_signature: bool,

    /// Trusted public keys for verification
    #[serde(default)]
    pub trusted_keys: Vec<TrustedKey>,

    /// URL to fetch trusted keys from coordinator
    pub keys_url: Option<String>,

    /// Allow unsigned workloads from these registries (for development)
    #[serde(default)]
    pub unsigned_allowed_registries: Vec<String>,

    /// Path to cache fetched keys
    pub key_cache_path: Option<PathBuf>,
}

fn default_enabled() -> bool {
    true
}

/// A trusted public key for signature verification
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TrustedKey {
    /// Unique identifier for this key
    pub key_id: String,

    /// PEM-encoded public key
    pub public_key: String,

    /// Key algorithm (ecdsa-p256, rsa-4096, ed25519)
    #[serde(default = "default_algorithm")]
    pub algorithm: String,

    /// Key issuer (archipelag, github-actions, etc.)
    pub issuer: Option<String>,
}

fn default_algorithm() -> String {
    "ecdsa-p256".to_string()
}

/// Result of signature verification
#[derive(Debug, Clone)]
pub enum SignatureResult {
    /// Signature is valid
    Valid {
        /// Key ID that verified the signature
        key_id: String,
        /// Key issuer
        issuer: Option<String>,
    },
    /// Verification was skipped (disabled or allowed registry)
    Skipped,
}

/// Signature verification errors
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("No trusted keys configured")]
    NoTrustedKeys,

    #[error("Signature verification failed for all trusted keys")]
    VerificationFailed,

    #[error("cosign not found - please install cosign")]
    CosignNotFound,

    #[error("cosign verification failed: {0}")]
    CosignError(String),

    #[error("Failed to write temporary key file: {0}")]
    TempFileError(String),

    #[error("Invalid image reference: {0}")]
    InvalidImageRef(String),
}

/// Verifies container image signatures using cosign
pub struct SignatureVerifier {
    config: SigningConfig,
    /// Cached trusted keys (key_id -> TrustedKey)
    keys: HashMap<String, TrustedKey>,
}

impl SignatureVerifier {
    /// Create a new signature verifier with the given config
    pub fn new(config: SigningConfig) -> Self {
        let mut keys = HashMap::new();

        // Load keys from config
        for key in &config.trusted_keys {
            keys.insert(key.key_id.clone(), key.clone());
        }

        Self { config, keys }
    }

    /// Create a verifier with verification disabled
    pub fn disabled() -> Self {
        Self::new(SigningConfig {
            enabled: false,
            ..Default::default()
        })
    }

    /// Add a trusted key
    pub fn add_key(&mut self, key: TrustedKey) {
        self.keys.insert(key.key_id.clone(), key);
    }

    /// Load keys from coordinator
    pub async fn load_keys_from_coordinator(&mut self) -> Result<usize> {
        let Some(url) = &self.config.keys_url else {
            debug!("No keys URL configured, skipping coordinator key fetch");
            return Ok(0);
        };

        info!("Fetching trusted keys from {}", url);

        let response = reqwest::get(url)
            .await
            .context("Failed to fetch keys from coordinator")?;

        if !response.status().is_success() {
            warn!(
                "Failed to fetch keys from coordinator: HTTP {}",
                response.status()
            );
            return Ok(0);
        }

        let keys: Vec<TrustedKey> = response
            .json()
            .await
            .context("Failed to parse keys response")?;

        let count = keys.len();

        for key in keys {
            self.keys.insert(key.key_id.clone(), key);
        }

        info!("Loaded {} trusted keys from coordinator", count);

        // Cache keys to disk if configured
        if let Some(cache_path) = &self.config.key_cache_path {
            if let Err(e) = self.cache_keys(cache_path).await {
                warn!("Failed to cache keys: {}", e);
            }
        }

        Ok(count)
    }

    /// Cache keys to disk for offline use
    async fn cache_keys(&self, path: &PathBuf) -> Result<()> {
        let keys: Vec<&TrustedKey> = self.keys.values().collect();
        let json = serde_json::to_string_pretty(&keys)?;
        fs::write(path, json).await?;
        debug!("Cached {} keys to {:?}", keys.len(), path);
        Ok(())
    }

    /// Load keys from cache
    pub async fn load_keys_from_cache(&mut self) -> Result<usize> {
        let Some(cache_path) = &self.config.key_cache_path else {
            return Ok(0);
        };

        if !cache_path.exists() {
            return Ok(0);
        }

        let json = fs::read_to_string(cache_path).await?;
        let keys: Vec<TrustedKey> = serde_json::from_str(&json)?;
        let count = keys.len();

        for key in keys {
            self.keys.insert(key.key_id.clone(), key);
        }

        info!("Loaded {} cached keys from {:?}", count, cache_path);
        Ok(count)
    }

    /// Verify an image signature
    ///
    /// Returns Ok(SignatureResult) if verification succeeds or is skipped,
    /// Err if verification fails and is required.
    pub async fn verify(&self, image_ref: &str) -> Result<SignatureResult, SignatureError> {
        // Check if verification is enabled
        if !self.config.enabled {
            debug!("Signature verification disabled, skipping");
            return Ok(SignatureResult::Skipped);
        }

        // Check if this registry allows unsigned images
        if self.is_allowed_unsigned(image_ref) {
            debug!(
                "Registry allows unsigned images, skipping verification for {}",
                image_ref
            );
            return Ok(SignatureResult::Skipped);
        }

        // Verify we have keys
        if self.keys.is_empty() {
            if self.config.require_signature {
                return Err(SignatureError::NoTrustedKeys);
            } else {
                warn!("No trusted keys configured, allowing unsigned workload");
                return Ok(SignatureResult::Skipped);
            }
        }

        // Try each key until one verifies
        for key in self.keys.values() {
            match self.verify_with_key(image_ref, key).await {
                Ok(()) => {
                    info!(
                        "Signature verified for {} with key {}",
                        image_ref, key.key_id
                    );
                    return Ok(SignatureResult::Valid {
                        key_id: key.key_id.clone(),
                        issuer: key.issuer.clone(),
                    });
                }
                Err(e) => {
                    debug!("Key {} did not verify: {}", key.key_id, e);
                    continue;
                }
            }
        }

        // No key verified
        if self.config.require_signature {
            error!("Signature verification failed for {}", image_ref);
            Err(SignatureError::VerificationFailed)
        } else {
            warn!(
                "Signature verification failed for {}, but not required",
                image_ref
            );
            Ok(SignatureResult::Skipped)
        }
    }

    /// Verify an image signature with a specific key
    async fn verify_with_key(&self, image_ref: &str, key: &TrustedKey) -> Result<()> {
        // Write public key to temp file
        let temp_dir = std::env::temp_dir();
        let key_file = temp_dir.join(format!("cosign_key_{}.pub", key.key_id));

        fs::write(&key_file, &key.public_key)
            .await
            .map_err(|e| SignatureError::TempFileError(e.to_string()))?;

        // Run cosign verify
        let output = Command::new("cosign")
            .args(["verify", "--key"])
            .arg(&key_file)
            .arg(image_ref)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    SignatureError::CosignNotFound
                } else {
                    SignatureError::CosignError(e.to_string())
                }
            })?;

        // Clean up temp file
        let _ = fs::remove_file(&key_file).await;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow!("cosign verify failed: {}", stderr))
        }
    }

    /// Check if an image reference is from an allowed unsigned registry
    fn is_allowed_unsigned(&self, image_ref: &str) -> bool {
        for registry in &self.config.unsigned_allowed_registries {
            if image_ref.starts_with(registry) {
                return true;
            }
        }
        false
    }

    /// Check if cosign is available
    pub fn cosign_available() -> bool {
        std::process::Command::new("cosign")
            .arg("version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Get cosign version
    pub async fn cosign_version() -> Option<String> {
        let output = Command::new("cosign").arg("version").output().await.ok()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout
                .lines()
                .find(|l| l.contains("cosign"))
                .map(|l| l.trim().to_string())
        } else {
            None
        }
    }

    /// Get the number of trusted keys
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Check if verification is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check if signatures are required
    pub fn is_required(&self) -> bool {
        self.config.require_signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_verifier() {
        let verifier = SignatureVerifier::disabled();
        assert!(!verifier.is_enabled());
    }

    #[test]
    fn test_allowed_unsigned() {
        let config = SigningConfig {
            enabled: true,
            unsigned_allowed_registries: vec!["localhost:5000".to_string()],
            ..Default::default()
        };
        let verifier = SignatureVerifier::new(config);

        assert!(verifier.is_allowed_unsigned("localhost:5000/test:latest"));
        assert!(!verifier.is_allowed_unsigned("ghcr.io/test/image:latest"));
    }

    #[test]
    fn test_add_key() {
        let mut verifier = SignatureVerifier::new(SigningConfig::default());
        assert_eq!(verifier.key_count(), 0);

        verifier.add_key(TrustedKey {
            key_id: "test-key".to_string(),
            public_key: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----".to_string(),
            algorithm: "ecdsa-p256".to_string(),
            issuer: Some("test".to_string()),
        });

        assert_eq!(verifier.key_count(), 1);
    }
}
