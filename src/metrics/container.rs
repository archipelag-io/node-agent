//! Container metrics collection via Docker stats API.
//!
//! This module collects resource metrics from running containers
//! using the Docker API.

use bollard::container::{Stats, StatsOptions};
use bollard::Docker;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::warn;

/// Container metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerMetrics {
    /// Container ID
    pub container_id: String,
    /// CPU usage percentage
    pub cpu_percent: f64,
    /// Memory used in MB
    pub memory_used_mb: u64,
    /// Memory limit in MB
    pub memory_limit_mb: u64,
    /// Memory usage percentage
    pub memory_percent: f64,
    /// Network bytes received
    pub network_rx_bytes: u64,
    /// Network bytes transmitted
    pub network_tx_bytes: u64,
    /// Block I/O read bytes
    pub block_read_bytes: u64,
    /// Block I/O write bytes
    pub block_write_bytes: u64,
    /// Timestamp (Unix ms)
    pub timestamp: u64,
}

/// Container stats collector
pub struct ContainerStats {
    docker: Docker,
}

impl ContainerStats {
    /// Create a new container stats collector
    pub fn new(docker: Docker) -> Self {
        Self { docker }
    }

    /// Get current metrics for a container
    pub async fn get_metrics(&self, container_id: &str) -> Option<ContainerMetrics> {
        let options = StatsOptions {
            stream: false,
            one_shot: true,
        };

        let mut stream = self.docker.stats(container_id, Some(options));

        // Get a single stats snapshot
        if let Some(Ok(stats)) = stream.next().await {
            return Some(calculate_metrics(container_id, &stats));
        }

        None
    }

    /// Stream metrics for a container
    pub async fn stream_metrics(
        &self,
        container_id: &str,
    ) -> impl futures_util::Stream<Item = ContainerMetrics> + '_ {
        let options = StatsOptions {
            stream: true,
            one_shot: false,
        };

        let container_id = container_id.to_string();
        self.docker
            .stats(&container_id, Some(options))
            .filter_map(move |result| {
                let container_id = container_id.clone();
                async move {
                    match result {
                        Ok(stats) => Some(calculate_metrics(&container_id, &stats)),
                        Err(e) => {
                            warn!("Error reading container stats: {}", e);
                            None
                        }
                    }
                }
            })
    }
}

/// Calculate metrics from raw Docker stats
fn calculate_metrics(container_id: &str, stats: &Stats) -> ContainerMetrics {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // CPU percentage calculation
    let cpu_percent = calculate_cpu_percent(stats);

    // Memory metrics
    let memory_used = stats.memory_stats.usage.unwrap_or(0);
    let memory_limit = stats.memory_stats.limit.unwrap_or(1);
    let memory_used_mb = memory_used / (1024 * 1024);
    let memory_limit_mb = memory_limit / (1024 * 1024);
    let memory_percent = if memory_limit > 0 {
        (memory_used as f64 / memory_limit as f64) * 100.0
    } else {
        0.0
    };

    // Network metrics
    let (network_rx, network_tx) = calculate_network_bytes(stats);

    // Block I/O metrics
    let (block_read, block_write) = calculate_block_io(stats);

    ContainerMetrics {
        container_id: container_id.to_string(),
        cpu_percent,
        memory_used_mb,
        memory_limit_mb,
        memory_percent,
        network_rx_bytes: network_rx,
        network_tx_bytes: network_tx,
        block_read_bytes: block_read,
        block_write_bytes: block_write,
        timestamp,
    }
}

/// Calculate CPU percentage from Docker stats
fn calculate_cpu_percent(stats: &Stats) -> f64 {
    let cpu_delta = stats
        .cpu_stats
        .cpu_usage
        .total_usage
        .saturating_sub(stats.precpu_stats.cpu_usage.total_usage);

    let system_delta = stats
        .cpu_stats
        .system_cpu_usage
        .unwrap_or(0)
        .saturating_sub(stats.precpu_stats.system_cpu_usage.unwrap_or(0));

    let num_cpus = stats
        .cpu_stats
        .cpu_usage
        .percpu_usage
        .as_ref()
        .map(|v| v.len())
        .unwrap_or(1);

    if system_delta > 0 && cpu_delta > 0 {
        (cpu_delta as f64 / system_delta as f64) * (num_cpus as f64) * 100.0
    } else {
        0.0
    }
}

/// Calculate network bytes from Docker stats
fn calculate_network_bytes(stats: &Stats) -> (u64, u64) {
    stats
        .networks
        .as_ref()
        .map(|networks| {
            networks.values().fold((0u64, 0u64), |(rx, tx), net| {
                (rx + net.rx_bytes, tx + net.tx_bytes)
            })
        })
        .unwrap_or((0, 0))
}

/// Calculate block I/O from Docker stats
fn calculate_block_io(stats: &Stats) -> (u64, u64) {
    stats
        .blkio_stats
        .io_service_bytes_recursive
        .as_ref()
        .map(|io_stats| {
            io_stats
                .iter()
                .fold((0u64, 0u64), |(read, write), stat| match stat.op.as_str() {
                    "Read" | "read" => (read + stat.value, write),
                    "Write" | "write" => (read, write + stat.value),
                    _ => (read, write),
                })
        })
        .unwrap_or((0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a running Docker daemon
    // They are marked as ignored by default

    #[test]
    fn test_container_metrics_fields() {
        let metrics = ContainerMetrics {
            container_id: "test123".into(),
            cpu_percent: 50.0,
            memory_used_mb: 1024,
            memory_limit_mb: 2048,
            memory_percent: 50.0,
            network_rx_bytes: 1000,
            network_tx_bytes: 2000,
            block_read_bytes: 5000,
            block_write_bytes: 3000,
            timestamp: 1234567890,
        };

        assert_eq!(metrics.container_id, "test123");
        assert!((metrics.cpu_percent - 50.0).abs() < 0.01);
        assert_eq!(metrics.memory_used_mb, 1024);
    }
}
