//! Registry allowlist for container images.
//!
//! This module enforces that only approved container registries
//! can be used for workloads. This prevents:
//! - Pulling malicious images from untrusted sources
//! - Supply chain attacks via image substitution
//!
//! ## Configuration
//!
//! ```toml
//! [security.registry]
//! # Only allow images from these registries
//! allowed = [
//!     "ghcr.io/archipelag-io",
//!     "docker.io/archipelag",
//! ]
//! # Require images to have a digest (sha256:...)
//! require_digest = true
//! ```

use std::collections::HashSet;
use tracing::{debug, info, warn};

/// Registry allowlist configuration
#[derive(Debug, Clone)]
pub struct RegistryAllowlist {
    /// Allowed registry prefixes
    allowed: HashSet<String>,
    /// Require digest pinning (sha256:...)
    require_digest: bool,
    /// Enabled (can be disabled for development)
    enabled: bool,
}

/// Registry-related errors
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("Registry not allowed: {registry}. Image: {image}")]
    RegistryNotAllowed { registry: String, image: String },

    #[error("Image must have a digest: {0}")]
    DigestRequired(String),

    #[error("Invalid image reference: {0}")]
    InvalidImageRef(String),
}

impl Default for RegistryAllowlist {
    fn default() -> Self {
        Self {
            allowed: HashSet::from([
                // Default allowed registries for archipelag.io
                "ghcr.io/archipelag-io".to_string(),
                "docker.io/archipelag".to_string(),
                "docker.io/library".to_string(), // Official images
            ]),
            require_digest: false, // Relaxed by default for development
            enabled: true,
        }
    }
}

impl RegistryAllowlist {
    /// Create a new registry allowlist
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an allowlist with specific registries
    pub fn with_registries(registries: Vec<String>) -> Self {
        Self {
            allowed: registries.into_iter().collect(),
            ..Default::default()
        }
    }

    /// Set whether digest is required
    pub fn with_require_digest(mut self, require: bool) -> Self {
        self.require_digest = require;
        self
    }

    /// Disable the allowlist (for development)
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Check if an image reference is allowed
    ///
    /// # Arguments
    /// * `image_ref` - Full image reference (e.g., "ghcr.io/archipelag-io/llm-chat:v1@sha256:abc...")
    ///
    /// # Returns
    /// * `Ok(())` if the image is allowed
    /// * `Err(RegistryError)` if the image is not allowed
    pub fn check(&self, image_ref: &str) -> Result<(), RegistryError> {
        if !self.enabled {
            debug!("Registry allowlist disabled, allowing: {}", image_ref);
            return Ok(());
        }

        // Parse the image reference
        let parsed = ImageRef::parse(image_ref)?;

        // Check registry
        let registry_with_namespace = format!("{}/{}", parsed.registry, parsed.namespace);

        let allowed = self.allowed.iter().any(|allowed| {
            // Check both "registry/namespace" and just "registry"
            registry_with_namespace.starts_with(allowed) || parsed.registry == *allowed
        });

        if !allowed {
            warn!(
                "Image registry not in allowlist: {} (registry: {})",
                image_ref, registry_with_namespace
            );
            return Err(RegistryError::RegistryNotAllowed {
                registry: registry_with_namespace,
                image: image_ref.to_string(),
            });
        }

        // Check digest requirement
        if self.require_digest && parsed.digest.is_none() {
            warn!("Image missing required digest: {}", image_ref);
            return Err(RegistryError::DigestRequired(image_ref.to_string()));
        }

        info!("Image allowed: {}", image_ref);
        Ok(())
    }

    /// Add a registry to the allowlist
    pub fn allow_registry(&mut self, registry: &str) {
        self.allowed.insert(registry.to_string());
    }

    /// Get the list of allowed registries
    pub fn allowed_registries(&self) -> impl Iterator<Item = &str> {
        self.allowed.iter().map(|s| s.as_str())
    }
}

/// Parsed image reference
#[derive(Debug, Clone)]
struct ImageRef {
    registry: String,
    namespace: String,
    name: String,
    tag: Option<String>,
    digest: Option<String>,
}

impl ImageRef {
    /// Parse an image reference
    ///
    /// Handles formats like:
    /// - `nginx` -> docker.io/library/nginx:latest
    /// - `nginx:1.24` -> docker.io/library/nginx:1.24
    /// - `myuser/myimage` -> docker.io/myuser/myimage:latest
    /// - `ghcr.io/org/image:tag` -> ghcr.io/org/image:tag
    /// - `image@sha256:abc...` -> docker.io/library/image@sha256:abc...
    fn parse(image_ref: &str) -> Result<Self, RegistryError> {
        let image_ref = image_ref.trim();

        if image_ref.is_empty() {
            return Err(RegistryError::InvalidImageRef(
                "Empty image reference".to_string(),
            ));
        }

        // Split off digest first if present
        let (ref_without_digest, digest) = if let Some(pos) = image_ref.find('@') {
            let (before, after) = image_ref.split_at(pos);
            (before, Some(after[1..].to_string()))
        } else {
            (image_ref, None)
        };

        // Split off tag if present
        let (ref_without_tag, tag) = if let Some(pos) = ref_without_digest.rfind(':') {
            // Make sure it's not a port number (registry:port/image)
            let after_colon = &ref_without_digest[pos + 1..];
            if after_colon.contains('/') {
                // It's a port, not a tag
                (ref_without_digest, None)
            } else {
                let (before, after) = ref_without_digest.split_at(pos);
                (before, Some(after[1..].to_string()))
            }
        } else {
            (ref_without_digest, None)
        };

        // Parse registry/namespace/name
        let parts: Vec<&str> = ref_without_tag.split('/').collect();

        let (registry, namespace, name) = match parts.len() {
            1 => {
                // Just name -> docker.io/library/name
                (
                    "docker.io".to_string(),
                    "library".to_string(),
                    parts[0].to_string(),
                )
            }
            2 => {
                // Could be registry/name or namespace/name
                if parts[0].contains('.') || parts[0].contains(':') || parts[0] == "localhost" {
                    // It's a registry
                    (
                        parts[0].to_string(),
                        "library".to_string(),
                        parts[1].to_string(),
                    )
                } else {
                    // It's docker.io/namespace/name
                    (
                        "docker.io".to_string(),
                        parts[0].to_string(),
                        parts[1].to_string(),
                    )
                }
            }
            n if n >= 3 => {
                // registry/namespace/.../name
                let registry = parts[0].to_string();
                let name = parts[n - 1].to_string();
                let namespace = parts[1..n - 1].join("/");
                (registry, namespace, name)
            }
            _ => {
                return Err(RegistryError::InvalidImageRef(format!(
                    "Cannot parse image reference: {}",
                    image_ref
                )));
            }
        };

        Ok(Self {
            registry,
            namespace,
            name,
            tag,
            digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_image() {
        let parsed = ImageRef::parse("nginx").unwrap();
        assert_eq!(parsed.registry, "docker.io");
        assert_eq!(parsed.namespace, "library");
        assert_eq!(parsed.name, "nginx");
        assert!(parsed.tag.is_none());
        assert!(parsed.digest.is_none());
    }

    #[test]
    fn test_parse_image_with_tag() {
        let parsed = ImageRef::parse("nginx:1.24").unwrap();
        assert_eq!(parsed.registry, "docker.io");
        assert_eq!(parsed.namespace, "library");
        assert_eq!(parsed.name, "nginx");
        assert_eq!(parsed.tag, Some("1.24".to_string()));
    }

    #[test]
    fn test_parse_image_with_namespace() {
        let parsed = ImageRef::parse("myuser/myimage").unwrap();
        assert_eq!(parsed.registry, "docker.io");
        assert_eq!(parsed.namespace, "myuser");
        assert_eq!(parsed.name, "myimage");
    }

    #[test]
    fn test_parse_full_reference() {
        let parsed = ImageRef::parse("ghcr.io/archipelag-io/llm-chat:v1").unwrap();
        assert_eq!(parsed.registry, "ghcr.io");
        assert_eq!(parsed.namespace, "archipelag-io");
        assert_eq!(parsed.name, "llm-chat");
        assert_eq!(parsed.tag, Some("v1".to_string()));
    }

    #[test]
    fn test_parse_with_digest() {
        let parsed = ImageRef::parse("nginx@sha256:abc123").unwrap();
        assert_eq!(parsed.digest, Some("sha256:abc123".to_string()));
    }

    #[test]
    fn test_allowlist_default() {
        let allowlist = RegistryAllowlist::default();

        // Allowed
        assert!(allowlist.check("ghcr.io/archipelag-io/test").is_ok());
        assert!(allowlist.check("docker.io/library/nginx").is_ok());
        assert!(allowlist.check("nginx").is_ok()); // Expands to docker.io/library/nginx

        // Not allowed
        assert!(allowlist.check("evil.io/malware").is_err());
        assert!(allowlist.check("quay.io/test/image").is_err());
    }

    #[test]
    fn test_allowlist_require_digest() {
        let allowlist = RegistryAllowlist::default().with_require_digest(true);

        // Without digest - rejected
        assert!(allowlist.check("nginx").is_err());

        // With digest - allowed
        assert!(allowlist.check("nginx@sha256:abc123").is_ok());
    }

    #[test]
    fn test_allowlist_disabled() {
        let allowlist = RegistryAllowlist::disabled();

        // Everything allowed when disabled
        assert!(allowlist.check("evil.io/malware").is_ok());
        assert!(allowlist.check("anything:goes").is_ok());
    }
}
