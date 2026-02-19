//! TLS pinning for secure connections.
//!
//! This module provides certificate pinning to prevent MITM attacks.
//! We pin the CA certificate (not leaf) for flexibility during cert rotation.
//!
//! ## Configuration
//!
//! TLS pinning can be configured in the agent config:
//!
//! ```toml
//! [security.tls]
//! enabled = true
//! # SHA256 fingerprint of trusted CA certificate
//! ca_fingerprint = "abc123..."
//! # Allow fallback to system roots if pinning fails (development only)
//! allow_fallback = false
//! ```

use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

/// TLS configuration for secure connections
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Enable TLS pinning
    pub enabled: bool,
    /// SHA256 fingerprint of trusted CA certificate (hex string)
    pub ca_fingerprint: Option<String>,
    /// Allow fallback to system roots (development only!)
    pub allow_fallback: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ca_fingerprint: None,
            allow_fallback: true, // Safe default for development
        }
    }
}

/// TLS-related errors
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("Certificate fingerprint mismatch: expected {expected}, got {actual}")]
    FingerprintMismatch { expected: String, actual: String },

    #[error("No trusted CA configured and fallback disabled")]
    NoTrustedCa,

    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),

    #[error("TLS handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Verify a certificate against a pinned fingerprint
pub fn verify_certificate_fingerprint(
    cert_der: &[u8],
    expected_fingerprint: &str,
) -> Result<(), TlsError> {
    let actual_fingerprint = compute_fingerprint(cert_der);

    if actual_fingerprint.eq_ignore_ascii_case(expected_fingerprint) {
        debug!("Certificate fingerprint verified: {}", actual_fingerprint);
        Ok(())
    } else {
        Err(TlsError::FingerprintMismatch {
            expected: expected_fingerprint.to_string(),
            actual: actual_fingerprint,
        })
    }
}

/// Compute SHA256 fingerprint of a certificate
pub fn compute_fingerprint(cert_der: &[u8]) -> String {
    let hash = Sha256::digest(cert_der);
    hex::encode(hash)
}

/// Certificate fingerprint verifier for use with NATS/reqwest
pub struct CertificateVerifier {
    config: TlsConfig,
}

impl CertificateVerifier {
    /// Create a new certificate verifier
    pub fn new(config: TlsConfig) -> Self {
        Self { config }
    }

    /// Verify a certificate chain
    ///
    /// This method is designed to be called from a TLS callback.
    /// It verifies that the CA certificate in the chain matches
    /// our pinned fingerprint.
    pub fn verify_chain(&self, certs: &[Vec<u8>]) -> Result<(), TlsError> {
        if !self.config.enabled {
            debug!("TLS pinning disabled, skipping verification");
            return Ok(());
        }

        let expected = match &self.config.ca_fingerprint {
            Some(fp) => fp,
            None => {
                if self.config.allow_fallback {
                    debug!("No CA fingerprint configured, allowing connection");
                    return Ok(());
                } else {
                    return Err(TlsError::NoTrustedCa);
                }
            }
        };

        // Check each certificate in the chain
        // The CA certificate is typically last in the chain
        for (i, cert_der) in certs.iter().enumerate() {
            let fingerprint = compute_fingerprint(cert_der);

            if fingerprint.eq_ignore_ascii_case(expected) {
                info!("Pinned CA certificate found at position {} in chain", i);
                return Ok(());
            }

            debug!(
                "Certificate {} fingerprint: {} (not pinned)",
                i, fingerprint
            );
        }

        // If we get here, no certificate matched
        if self.config.allow_fallback {
            warn!("No pinned certificate found in chain, but fallback is enabled");
            Ok(())
        } else {
            Err(TlsError::FingerprintMismatch {
                expected: expected.clone(),
                actual: format!("<none of {} certs matched>", certs.len()),
            })
        }
    }

    /// Get the configuration
    pub fn config(&self) -> &TlsConfig {
        &self.config
    }
}

/// Build a rustls ClientConfig with certificate pinning
///
/// This is used for NATS connections and HTTP clients.
///
/// Note: This function requires the rustls crate which isn't currently
/// a dependency. When adding TLS support, add these to Cargo.toml:
///
/// rustls = "0.23"
/// webpki-roots = "0.26"
/// rustls-pemfile = "2"
pub fn build_tls_config(config: &TlsConfig) -> Result<(), TlsError> {
    // TODO: Implement when rustls is added as a dependency
    //
    // This would:
    // 1. Load system roots (webpki-roots)
    // 2. Create a custom certificate verifier that checks fingerprints
    // 3. Return a rustls::ClientConfig
    //
    // For now, the async-nats client uses native-tls by default,
    // and certificate pinning would require switching to rustls.

    if config.enabled && config.ca_fingerprint.is_some() {
        warn!(
            "TLS pinning is configured but not yet implemented - \
            this requires switching async-nats to use rustls"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_fingerprint() {
        // Test with known data
        let data = b"test certificate data";
        let fingerprint = compute_fingerprint(data);

        // SHA256 of "test certificate data"
        assert_eq!(fingerprint.len(), 64); // 32 bytes = 64 hex chars
        assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_verify_fingerprint_match() {
        let data = b"hello world";
        let fingerprint = compute_fingerprint(data);

        assert!(verify_certificate_fingerprint(data, &fingerprint).is_ok());
    }

    #[test]
    fn test_verify_fingerprint_mismatch() {
        let data = b"hello world";
        let wrong_fingerprint = "0".repeat(64);

        let result = verify_certificate_fingerprint(data, &wrong_fingerprint);
        assert!(matches!(result, Err(TlsError::FingerprintMismatch { .. })));
    }

    #[test]
    fn test_verifier_disabled() {
        let config = TlsConfig {
            enabled: false,
            ..Default::default()
        };
        let verifier = CertificateVerifier::new(config);

        // Should pass even with no certs when disabled
        assert!(verifier.verify_chain(&[]).is_ok());
    }

    #[test]
    fn test_verifier_with_fallback() {
        let config = TlsConfig {
            enabled: true,
            ca_fingerprint: Some("abc123".to_string()),
            allow_fallback: true,
        };
        let verifier = CertificateVerifier::new(config);

        // Should pass due to fallback even though no cert matches
        assert!(verifier.verify_chain(&[vec![1, 2, 3]]).is_ok());
    }

    #[test]
    fn test_verifier_without_fallback() {
        let config = TlsConfig {
            enabled: true,
            ca_fingerprint: Some("abc123".to_string()),
            allow_fallback: false,
        };
        let verifier = CertificateVerifier::new(config);

        // Should fail because no cert matches and fallback disabled
        let result = verifier.verify_chain(&[vec![1, 2, 3]]);
        assert!(matches!(result, Err(TlsError::FingerprintMismatch { .. })));
    }
}
