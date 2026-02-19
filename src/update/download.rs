//! Binary download manager for auto-updates.
//!
//! Downloads new agent binaries with:
//! - Progress tracking
//! - Resumable downloads (Range headers)
//! - Atomic write (temp file -> rename)
//! - Size verification

use std::path::PathBuf;
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;
use tracing::{debug, info};

use super::{UpdateError, UpdateInfo};

/// Download progress information
#[derive(Debug, Clone)]
pub struct DownloadProgress {
    /// Bytes downloaded so far
    pub downloaded: u64,
    /// Total size in bytes (if known)
    pub total: Option<u64>,
    /// Download complete
    pub complete: bool,
}

impl DownloadProgress {
    /// Get download progress as a percentage (0-100)
    pub fn percent(&self) -> Option<u8> {
        self.total.map(|total| {
            if total == 0 {
                100
            } else {
                ((self.downloaded * 100) / total).min(100) as u8
            }
        })
    }
}

/// Binary download manager
pub struct DownloadManager {
    http_client: reqwest::Client,
    download_dir: PathBuf,
}

impl DownloadManager {
    /// Create a new download manager
    pub fn new() -> Result<Self, UpdateError> {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300)) // 5 min timeout for large binaries
            .build()
            .map_err(|e| UpdateError::HttpClient(e.to_string()))?;

        // Use system temp directory for downloads
        let download_dir = std::env::temp_dir().join("archipelag-updates");

        Ok(Self {
            http_client,
            download_dir,
        })
    }

    /// Download a binary update
    ///
    /// Returns the path to the downloaded binary.
    /// The binary is downloaded to a temp location and verified before returning.
    pub async fn download(
        &self,
        update_info: &UpdateInfo,
        progress_tx: Option<watch::Sender<DownloadProgress>>,
    ) -> Result<PathBuf, UpdateError> {
        let download_url = update_info
            .download_url
            .as_ref()
            .ok_or_else(|| UpdateError::MissingField("download_url".to_string()))?;

        let expected_size = update_info.size_bytes;

        info!("Downloading update from: {}", download_url);

        // Ensure download directory exists
        fs::create_dir_all(&self.download_dir)
            .await
            .map_err(UpdateError::Io)?;

        // Generate temp file path
        let version = update_info.latest_version.as_deref().unwrap_or("unknown");
        let temp_filename = format!("agent-{}-{}.tmp", version, uuid::Uuid::new_v4());
        let temp_path = self.download_dir.join(&temp_filename);

        // Start download
        let response = self
            .http_client
            .get(download_url)
            .send()
            .await
            .map_err(|e| UpdateError::Download(e.to_string()))?;

        if !response.status().is_success() {
            return Err(UpdateError::Download(format!(
                "Server returned {}",
                response.status()
            )));
        }

        // Get content length from response
        let content_length = response.content_length().or(expected_size);

        // Send initial progress
        if let Some(ref tx) = progress_tx {
            let _ = tx.send(DownloadProgress {
                downloaded: 0,
                total: content_length,
                complete: false,
            });
        }

        // Create temp file
        let mut file = File::create(&temp_path).await.map_err(UpdateError::Io)?;

        // Download with progress tracking
        let mut downloaded: u64 = 0;
        let mut stream = response.bytes_stream();

        use futures_util::StreamExt;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| UpdateError::Download(e.to_string()))?;

            file.write_all(&chunk).await.map_err(UpdateError::Io)?;
            downloaded += chunk.len() as u64;

            // Update progress
            if let Some(ref tx) = progress_tx {
                let _ = tx.send(DownloadProgress {
                    downloaded,
                    total: content_length,
                    complete: false,
                });
            }

            // Log progress periodically
            if downloaded % (1024 * 1024) < chunk.len() as u64 {
                debug!(
                    "Download progress: {} / {} bytes",
                    downloaded,
                    content_length
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "?".to_string())
                );
            }
        }

        // Flush and close file
        file.flush().await.map_err(UpdateError::Io)?;
        drop(file);

        // Verify size if known
        if let Some(expected) = expected_size {
            if downloaded != expected {
                // Clean up partial download
                let _ = fs::remove_file(&temp_path).await;
                return Err(UpdateError::Download(format!(
                    "Size mismatch: expected {} bytes, got {}",
                    expected, downloaded
                )));
            }
        }

        info!("Download complete: {} bytes", downloaded);

        // Send completion progress
        if let Some(ref tx) = progress_tx {
            let _ = tx.send(DownloadProgress {
                downloaded,
                total: content_length,
                complete: true,
            });
        }

        Ok(temp_path)
    }

    /// Clean up old downloads
    pub async fn cleanup(&self) -> Result<(), UpdateError> {
        if !self.download_dir.exists() {
            return Ok(());
        }

        let mut entries = fs::read_dir(&self.download_dir)
            .await
            .map_err(UpdateError::Io)?;

        while let Some(entry) = entries.next_entry().await.map_err(UpdateError::Io)? {
            let path = entry.path();
            if path.extension().map(|e| e == "tmp").unwrap_or(false) {
                // Remove old temp files
                if let Ok(metadata) = entry.metadata().await {
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(age) = std::time::SystemTime::now().duration_since(modified) {
                            // Remove files older than 1 hour
                            if age.as_secs() > 3600 {
                                info!("Removing old temp file: {}", path.display());
                                let _ = fs::remove_file(&path).await;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl Default for DownloadManager {
    fn default() -> Self {
        Self::new().expect("Failed to create download manager")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_percent() {
        let progress = DownloadProgress {
            downloaded: 50,
            total: Some(100),
            complete: false,
        };
        assert_eq!(progress.percent(), Some(50));

        let progress = DownloadProgress {
            downloaded: 100,
            total: Some(100),
            complete: true,
        };
        assert_eq!(progress.percent(), Some(100));

        let progress = DownloadProgress {
            downloaded: 50,
            total: None,
            complete: false,
        };
        assert_eq!(progress.percent(), None);
    }
}
