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
use std::collections::HashMap;
use std::process::Command;
use std::sync::LazyLock;
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

// ============================================================================
// GPU Memory Bandwidth Lookup
// ============================================================================

/// GPU memory bandwidth table (GB/s) for performance estimation.
/// Used to estimate LLM tokens/second: tok/s ≈ bandwidth / model_size_GB × efficiency
static GPU_BANDWIDTH: LazyLock<HashMap<&'static str, f32>> = LazyLock::new(|| {
    HashMap::from([
        // NVIDIA Data Center / HPC
        ("h100 sxm", 3350.0),
        ("h100 pcie", 2039.0),
        ("h100", 3350.0),
        ("h200", 4800.0),
        ("a100 80gb", 2039.0),
        ("a100 40gb", 1555.0),
        ("a100", 2039.0),
        ("a40", 696.0),
        ("a30", 933.0),
        ("a10g", 600.0),
        ("a10", 600.0),
        ("l40s", 864.0),
        ("l40", 864.0),
        ("l4", 300.0),
        ("v100", 900.0),
        ("t4", 320.0),
        ("p100", 732.0),
        // NVIDIA Workstation
        ("rtx a6000", 768.0),
        ("rtx a5000", 768.0),
        ("rtx a4000", 448.0),
        ("a6000", 768.0),
        ("a5000", 768.0),
        ("a4000", 448.0),
        // NVIDIA GeForce RTX 50 series
        ("rtx 5090", 1792.0),
        ("rtx 5080", 960.0),
        ("rtx 5070 ti", 896.0),
        ("rtx 5070", 672.0),
        // NVIDIA GeForce RTX 40 series
        ("rtx 4090", 1008.0),
        ("rtx 4080 super", 736.0),
        ("rtx 4080", 716.8),
        ("rtx 4070 ti super", 672.0),
        ("rtx 4070 ti", 504.0),
        ("rtx 4070 super", 504.0),
        ("rtx 4070", 504.0),
        ("rtx 4060 ti", 288.0),
        ("rtx 4060", 272.0),
        // NVIDIA GeForce RTX 30 series
        ("rtx 3090 ti", 1008.0),
        ("rtx 3090", 936.2),
        ("rtx 3080 ti", 912.4),
        ("rtx 3080", 760.3),
        ("rtx 3070 ti", 608.3),
        ("rtx 3070", 448.0),
        ("rtx 3060 ti", 448.0),
        ("rtx 3060", 360.0),
        ("rtx 3050", 224.0),
        // NVIDIA GeForce RTX 20 series
        ("titan rtx", 672.0),
        ("rtx 2080 ti", 616.0),
        ("rtx 2080 super", 496.0),
        ("rtx 2080", 448.0),
        ("rtx 2070 super", 448.0),
        ("rtx 2070", 448.0),
        ("rtx 2060 super", 448.0),
        ("rtx 2060", 336.0),
        // NVIDIA GeForce GTX 10/16 series
        ("gtx 1080 ti", 484.0),
        ("gtx 1080", 320.0),
        ("gtx 1070 ti", 256.3),
        ("gtx 1070", 256.3),
        ("gtx 1060", 192.0),
        ("gtx 1660 super", 336.0),
        ("gtx 1660 ti", 288.0),
        ("gtx 1660", 192.0),
        ("gtx 1650 super", 192.0),
        ("gtx 1650", 128.0),
        // AMD Radeon RX 7000 series
        ("rx 7900 xtx", 960.0),
        ("rx 7900 xt", 800.0),
        ("rx 7800 xt", 624.0),
        ("rx 7700 xt", 432.0),
        ("rx 7600", 288.0),
        // AMD Radeon RX 6000 series
        ("rx 6950 xt", 576.0),
        ("rx 6900 xt", 512.0),
        ("rx 6800 xt", 512.0),
        ("rx 6800", 512.0),
        ("rx 6700 xt", 384.0),
        ("rx 6600 xt", 256.0),
        ("rx 6600", 224.0),
        // AMD Instinct
        ("mi300x", 5300.0),
        ("mi250x", 3276.0),
        ("mi250", 3276.0),
        ("mi210", 1638.0),
        ("mi100", 1228.0),
        // Apple Silicon
        ("apple m4 ultra", 819.2),
        ("apple m4 max", 546.0),
        ("apple m4 pro", 273.0),
        ("apple m4", 120.0),
        ("apple m3 ultra", 800.0),
        ("apple m3 max", 400.0),
        ("apple m3 pro", 150.0),
        ("apple m3", 100.0),
        ("apple m2 ultra", 800.0),
        ("apple m2 max", 400.0),
        ("apple m2 pro", 200.0),
        ("apple m2", 100.0),
        ("apple m1 ultra", 800.0),
        ("apple m1 max", 400.0),
        ("apple m1 pro", 200.0),
        ("apple m1", 68.25),
        // Intel Arc
        ("arc a770", 560.0),
        ("arc a750", 512.0),
        ("arc a380", 186.0),
    ])
});

/// Look up GPU memory bandwidth in GB/s from a GPU model name.
///
/// Normalizes the input (strips vendor prefix, lowercases) and tries
/// exact match first, then substring match (longest key wins).
pub fn lookup_bandwidth(gpu_model: &str) -> Option<f32> {
    let normalized = normalize_gpu_name(gpu_model);

    // Exact match first
    if let Some(&bw) = GPU_BANDWIDTH.get(normalized.as_str()) {
        return Some(bw);
    }

    // Fuzzy: find longest key contained in the normalized string
    GPU_BANDWIDTH
        .iter()
        .filter(|(key, _)| normalized.contains(**key))
        .max_by_key(|(key, _)| key.len())
        .map(|(_, &bw)| bw)
}

/// Estimate bandwidth from VRAM when GPU model is unknown (conservative: ~40 GB/s per GB VRAM).
pub fn estimate_bandwidth_from_vram(vram_mb: u32) -> f32 {
    if vram_mb == 0 {
        return 200.0;
    }
    let vram_gb = vram_mb as f32 / 1024.0;
    vram_gb * 40.0
}

/// Get bandwidth for a GPU, falling back to VRAM-based estimate.
pub fn bandwidth_for_gpu(gpu_model: Option<&str>, gpu_vram_mb: Option<u32>) -> f32 {
    if let Some(model) = gpu_model {
        if let Some(bw) = lookup_bandwidth(model) {
            return bw;
        }
    }
    estimate_bandwidth_from_vram(gpu_vram_mb.unwrap_or(0))
}

/// Normalize GPU model string for matching.
fn normalize_gpu_name(name: &str) -> String {
    let lower = name.to_lowercase();
    // Strip common vendor prefixes
    let stripped = lower
        .replace("nvidia", "")
        .replace("geforce", "")
        .replace("amd", "")
        .replace("radeon", "")
        .replace("intel", "");
    // Collapse whitespace
    stripped.split_whitespace().collect::<Vec<_>>().join(" ")
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

    #[test]
    fn test_lookup_bandwidth_known_gpu() {
        let bw = lookup_bandwidth("NVIDIA GeForce RTX 3090").unwrap();
        assert!((bw - 936.2).abs() < 0.1);
    }

    #[test]
    fn test_lookup_bandwidth_case_insensitive() {
        let bw = lookup_bandwidth("nvidia geforce rtx 4090").unwrap();
        assert!((bw - 1008.0).abs() < 0.1);
    }

    #[test]
    fn test_lookup_bandwidth_unknown() {
        assert!(lookup_bandwidth("Mystery GPU 9000").is_none());
    }

    #[test]
    fn test_bandwidth_for_gpu_with_known_model() {
        let bw = bandwidth_for_gpu(Some("NVIDIA GeForce RTX 3090"), Some(24576));
        assert!((bw - 936.2).abs() < 0.1);
    }

    #[test]
    fn test_bandwidth_for_gpu_unknown_model_falls_back_to_vram() {
        let bw = bandwidth_for_gpu(Some("Unknown GPU"), Some(8192));
        // 8 GB * 40 = 320
        assert!((bw - 320.0).abs() < 1.0);
    }

    #[test]
    fn test_bandwidth_for_gpu_no_gpu() {
        let bw = bandwidth_for_gpu(None, None);
        assert!((bw - 200.0).abs() < 0.1);
    }

    #[test]
    fn test_estimate_bandwidth_from_vram() {
        assert!((estimate_bandwidth_from_vram(24576) - 960.0).abs() < 1.0);
        assert!((estimate_bandwidth_from_vram(0) - 200.0).abs() < 0.1);
    }
}
