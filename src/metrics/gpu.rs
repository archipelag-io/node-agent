//! GPU metrics collection via nvidia-smi.
//!
//! This module collects GPU metrics by parsing nvidia-smi output.
//! This approach is used instead of NVML bindings for simplicity
//! and to avoid runtime library dependencies.
//!
//! ## Collected Metrics
//!
//! - Utilization percentage
//! - Memory used/total
//! - Temperature
//! - Power draw
//!
//! ## Future Improvements
//!
//! For production, consider using the nvml-wrapper crate for:
//! - More efficient metric collection
//! - Lower latency
//! - More detailed metrics

use serde::{Deserialize, Serialize};
use std::process::Command;
use std::time::{Duration, Instant};
use tracing::{debug, trace, warn};

/// GPU information (static properties)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    /// GPU index
    pub index: u32,
    /// GPU name/model
    pub name: String,
    /// GPU UUID
    pub uuid: String,
    /// Total memory in MB
    pub memory_total_mb: u64,
    /// CUDA compute capability
    pub compute_capability: Option<String>,
    /// Driver version
    pub driver_version: Option<String>,
}

/// GPU metrics (dynamic properties)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuMetrics {
    /// GPU index
    pub index: u32,
    /// GPU utilization percentage (0-100)
    pub utilization_percent: u32,
    /// Memory used in MB
    pub memory_used_mb: u64,
    /// Memory total in MB
    pub memory_total_mb: u64,
    /// Temperature in Celsius
    pub temperature_c: u32,
    /// Power draw in Watts
    pub power_draw_w: f32,
    /// Power limit in Watts
    pub power_limit_w: f32,
    /// Timestamp when collected (Unix ms)
    pub timestamp: u64,
}

/// GPU metrics collector
pub struct GpuMetricsCollector {
    /// Cached GPU info
    gpu_info: Option<Vec<GpuInfo>>,
    /// Last metrics collection time
    last_collection: Option<Instant>,
    /// Minimum interval between collections
    min_interval: Duration,
    /// Cached metrics
    cached_metrics: Option<Vec<GpuMetrics>>,
}

impl Default for GpuMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl GpuMetricsCollector {
    /// Create a new GPU metrics collector
    pub fn new() -> Self {
        Self {
            gpu_info: None,
            last_collection: None,
            min_interval: Duration::from_secs(5), // Min 5s between collections
            cached_metrics: None,
        }
    }

    /// Check if nvidia-smi is available
    pub fn is_available() -> bool {
        Command::new("nvidia-smi")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Get GPU information (cached)
    pub fn get_gpu_info(&mut self) -> Option<&[GpuInfo]> {
        if self.gpu_info.is_none() {
            self.refresh_gpu_info();
        }
        self.gpu_info.as_deref()
    }

    /// Refresh GPU info from nvidia-smi
    fn refresh_gpu_info(&mut self) {
        let output = Command::new("nvidia-smi")
            .args([
                "--query-gpu=index,name,uuid,memory.total,compute_cap,driver_version",
                "--format=csv,noheader,nounits",
            ])
            .output();

        match output {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let gpus: Vec<GpuInfo> = stdout.lines().filter_map(parse_gpu_info_line).collect();

                if !gpus.is_empty() {
                    debug!("Found {} GPU(s)", gpus.len());
                    self.gpu_info = Some(gpus);
                } else {
                    debug!("No GPUs found in nvidia-smi output");
                }
            }
            Ok(output) => {
                warn!(
                    "nvidia-smi failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(e) => {
                // This is expected if no NVIDIA GPU is present
                trace!("nvidia-smi not available: {}", e);
            }
        }
    }

    /// Collect current GPU metrics
    pub fn collect(&mut self) -> Option<Vec<GpuMetrics>> {
        // Rate limiting
        if let Some(last) = self.last_collection {
            if last.elapsed() < self.min_interval {
                return self.cached_metrics.clone();
            }
        }

        let output = Command::new("nvidia-smi")
            .args([
                "--query-gpu=index,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw,power.limit",
                "--format=csv,noheader,nounits",
            ])
            .output();

        match output {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                let metrics: Vec<GpuMetrics> = stdout
                    .lines()
                    .filter_map(|line| parse_gpu_metrics_line(line, timestamp))
                    .collect();

                if !metrics.is_empty() {
                    self.last_collection = Some(Instant::now());
                    self.cached_metrics = Some(metrics.clone());
                    return Some(metrics);
                }
            }
            Ok(output) => {
                warn!(
                    "nvidia-smi metrics query failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(e) => {
                trace!("nvidia-smi not available for metrics: {}", e);
            }
        }

        None
    }

    /// Get the number of GPUs
    pub fn gpu_count(&mut self) -> usize {
        self.get_gpu_info().map(|info| info.len()).unwrap_or(0)
    }
}

/// Parse a line of GPU info output
fn parse_gpu_info_line(line: &str) -> Option<GpuInfo> {
    let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
    if parts.len() < 6 {
        return None;
    }

    Some(GpuInfo {
        index: parts[0].parse().ok()?,
        name: parts[1].to_string(),
        uuid: parts[2].to_string(),
        memory_total_mb: parts[3].parse().ok()?,
        compute_capability: if parts[4].is_empty() || parts[4] == "[N/A]" {
            None
        } else {
            Some(parts[4].to_string())
        },
        driver_version: if parts[5].is_empty() || parts[5] == "[N/A]" {
            None
        } else {
            Some(parts[5].to_string())
        },
    })
}

/// Parse a line of GPU metrics output
fn parse_gpu_metrics_line(line: &str, timestamp: u64) -> Option<GpuMetrics> {
    let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
    if parts.len() < 7 {
        return None;
    }

    // Handle [N/A] values from nvidia-smi
    let parse_u32 = |s: &str| -> u32 {
        if s == "[N/A]" || s.is_empty() {
            0
        } else {
            s.parse().unwrap_or(0)
        }
    };

    let parse_u64 = |s: &str| -> u64 {
        if s == "[N/A]" || s.is_empty() {
            0
        } else {
            s.parse().unwrap_or(0)
        }
    };

    let parse_f32 = |s: &str| -> f32 {
        if s == "[N/A]" || s.is_empty() {
            0.0
        } else {
            s.parse().unwrap_or(0.0)
        }
    };

    Some(GpuMetrics {
        index: parts[0].parse().ok()?,
        utilization_percent: parse_u32(parts[1]),
        memory_used_mb: parse_u64(parts[2]),
        memory_total_mb: parse_u64(parts[3]),
        temperature_c: parse_u32(parts[4]),
        power_draw_w: parse_f32(parts[5]),
        power_limit_w: parse_f32(parts[6]),
        timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gpu_info_line() {
        let line = "0, NVIDIA GeForce RTX 3090, GPU-abc123, 24576, 8.6, 535.154.05";
        let info = parse_gpu_info_line(line).expect("Should parse");

        assert_eq!(info.index, 0);
        assert_eq!(info.name, "NVIDIA GeForce RTX 3090");
        assert_eq!(info.uuid, "GPU-abc123");
        assert_eq!(info.memory_total_mb, 24576);
        assert_eq!(info.compute_capability, Some("8.6".to_string()));
        assert_eq!(info.driver_version, Some("535.154.05".to_string()));
    }

    #[test]
    fn test_parse_gpu_metrics_line() {
        let line = "0, 45, 8192, 24576, 62, 150.00, 350.00";
        let metrics = parse_gpu_metrics_line(line, 1000).expect("Should parse");

        assert_eq!(metrics.index, 0);
        assert_eq!(metrics.utilization_percent, 45);
        assert_eq!(metrics.memory_used_mb, 8192);
        assert_eq!(metrics.memory_total_mb, 24576);
        assert_eq!(metrics.temperature_c, 62);
        assert!((metrics.power_draw_w - 150.0).abs() < 0.01);
        assert!((metrics.power_limit_w - 350.0).abs() < 0.01);
        assert_eq!(metrics.timestamp, 1000);
    }

    #[test]
    fn test_parse_gpu_metrics_with_na() {
        let line = "0, [N/A], 8192, 24576, 62, [N/A], [N/A]";
        let metrics = parse_gpu_metrics_line(line, 1000).expect("Should parse");

        assert_eq!(metrics.utilization_percent, 0); // N/A becomes 0
        assert_eq!(metrics.memory_used_mb, 8192);
        assert!((metrics.power_draw_w - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_collector_new() {
        let collector = GpuMetricsCollector::new();
        assert!(collector.gpu_info.is_none());
        assert!(collector.cached_metrics.is_none());
    }
}
