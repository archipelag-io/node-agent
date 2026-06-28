//! Exo multi-Island cluster execution.
//!
//! Unlike pipeline/expert (which do layer/expert compute in-process), this runtime
//! delegates all sharding to a local **Exo** process. Every node in the cluster:
//!   1. starts `exo` with a shared `EXO_LIBP2P_NAMESPACE` (cluster isolation),
//!   2. waits until the local node's `/state` shows the full cluster has formed,
//!   3. signals `ready` to the coordinator.
//!
//! The **primary** node (position 0) then receives the prompt, calls Exo's
//! OpenAI-compatible `/v1/chat/completions` (streaming), and relays each token to
//! the coordinator over NATS. Workers participate in the cluster silently.
//!
//! NOTE: This is built against Exo's documented API (see .claude/EXO_SPIKE.md) and
//! has NOT yet been validated by the hardware spike. Behaviours marked below may
//! need adjustment once the spike runs (cluster-formation signal, model IDs, SSE
//! shape, failure semantics).

use anyhow::{Context, Result};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::select;
use tokio::sync::{watch, RwLock};
use tracing::{error, info};

use crate::nats::{AssignJob, NatsAgent};
use crate::state::StateManager;

/// Cluster formation timeout — how long to wait for all peers to join.
const CLUSTER_FORM_TIMEOUT: Duration = Duration::from_secs(150);
/// Overall inference timeout for the primary.
const INFERENCE_TIMEOUT: Duration = Duration::from_secs(300);

/// Exo configuration sent by the coordinator.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExoConfig {
    pub group_id: String,
    /// "primary" | "worker"
    pub role: String,
    #[serde(default)]
    pub is_primary: bool,
    /// Shared libp2p namespace that isolates this cluster from all others.
    pub namespace: String,
    /// Exo model id (as returned by `/v1/models`).
    pub model: String,
    /// Number of nodes the cluster should contain before we consider it formed.
    pub node_count: u32,
    #[serde(default)]
    pub peers: Vec<String>,
    pub subjects: ExoSubjects,
}

/// NATS subjects for exo cluster coordination.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExoSubjects {
    pub control: String,
    pub output: String,
    pub status: String,
}

/// Execute an exo job — start the local Exo node, join the cluster, and (if
/// primary) drive inference.
pub async fn execute_exo_job(
    nats: &NatsAgent,
    _state: &Arc<RwLock<StateManager>>,
    job: &AssignJob,
    exo_config: ExoConfig,
    mut cancel_rx: watch::Receiver<bool>,
) -> Result<()> {
    let job_id = &job.job_id;
    let group_id = &exo_config.group_id;
    let role = &exo_config.role;
    let port = api_port_for(group_id);

    info!(
        job_id,
        group_id,
        role,
        port,
        "Starting exo node (namespace {}, {} nodes, model {})",
        exo_config.namespace,
        exo_config.node_count,
        exo_config.model,
    );

    // 1. Spawn the local Exo process in this cluster's namespace. kill_on_drop
    //    guarantees the subprocess is reaped if we return early or error out.
    let mut child = Command::new("exo")
        .arg("--api-port")
        .arg(port.to_string())
        .env("EXO_LIBP2P_NAMESPACE", &exo_config.namespace)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("Failed to spawn `exo` — is it installed and on PATH?")?;

    // Ensure cleanup on every exit path below.
    let result = run_node(nats, job, &exo_config, port, &mut cancel_rx).await;

    let _ = child.start_kill();

    if let Err(ref e) = result {
        error!(job_id, group_id, "Exo node failed: {:#}", e);
        let _ = publish_failed(nats, &exo_config, &format!("{:#}", e)).await;
    }

    result
}

async fn run_node(
    nats: &NatsAgent,
    job: &AssignJob,
    cfg: &ExoConfig,
    port: u16,
    cancel_rx: &mut watch::Receiver<bool>,
) -> Result<()> {
    let job_id = &job.job_id;

    // 2. Wait for the cluster to form (all node_count nodes visible in /state).
    wait_for_cluster(port, cfg.node_count, cancel_rx)
        .await
        .context("Cluster did not form in time")?;

    // 3. Signal ready.
    nats.publish_raw(
        &cfg.subjects.status,
        serde_json::to_vec(&json!({
            "host_id": nats.host_id(),
            "status": "ready",
            "role": cfg.role,
        }))?,
    )
    .await?;

    info!(job_id, role = %cfg.role, "Exo node ready, cluster formed");

    // 4. Subscribe to control. The primary waits for the prompt; workers wait for
    //    stop (their Exo process serves shards as part of the cluster).
    let mut control_sub = nats
        .subscribe_ring(&cfg.subjects.control)
        .await
        .context("Failed to subscribe to exo control")?;

    loop {
        select! {
            msg = control_sub.next() => {
                match msg {
                    Some(msg) => {
                        let action = serde_json::from_slice::<serde_json::Value>(&msg.payload)
                            .ok()
                            .and_then(|v| v.get("action").and_then(|a| a.as_str()).map(String::from));

                        match action.as_deref() {
                            Some("prompt") if cfg.is_primary => {
                                run_primary_inference(nats, job, cfg, port, cancel_rx).await?;
                                return Ok(());
                            }
                            Some("stop") => {
                                info!(job_id, "Exo node received stop");
                                return Ok(());
                            }
                            _ => {}
                        }
                    }
                    None => return Ok(()),
                }
            }
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    info!(job_id, "Exo node cancelled");
                    nats.publish_status(job_id, "cancelled", None).await?;
                    return Ok(());
                }
            }
        }
    }
}

/// Poll the local Exo `/state` until at least `node_count` nodes are visible.
async fn wait_for_cluster(
    port: u16,
    node_count: u32,
    cancel_rx: &mut watch::Receiver<bool>,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?;
    let url = format!("http://127.0.0.1:{}/state", port);
    let deadline = tokio::time::Instant::now() + CLUSTER_FORM_TIMEOUT;

    loop {
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for {} nodes", node_count);
        }
        if *cancel_rx.borrow() {
            anyhow::bail!("cancelled during cluster formation");
        }

        if let Ok(resp) = client.get(&url).send().await {
            if let Ok(state) = resp.json::<serde_json::Value>().await {
                if count_nodes(&state) >= node_count {
                    return Ok(());
                }
            }
        }

        select! {
            _ = tokio::time::sleep(Duration::from_millis(750)) => {}
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    anyhow::bail!("cancelled during cluster formation");
                }
            }
        }
    }
}

/// Count distinct nodes in an Exo `/state` payload (camelCase JSON). Tries the
/// fields Exo is documented to expose, in order of reliability.
fn count_nodes(state: &serde_json::Value) -> u32 {
    for key in ["topology", "lastSeen", "nodeIdentities", "nodeMemory"] {
        if let Some(obj) = state.get(key).and_then(|v| v.as_object()) {
            if !obj.is_empty() {
                return obj.len() as u32;
            }
        }
    }
    0
}

/// Primary node: drive inference against the local Exo API and relay tokens.
async fn run_primary_inference(
    nats: &NatsAgent,
    job: &AssignJob,
    cfg: &ExoConfig,
    port: u16,
    cancel_rx: &mut watch::Receiver<bool>,
) -> Result<()> {
    let job_id = &job.job_id;
    let client = reqwest::Client::builder()
        .timeout(INFERENCE_TIMEOUT)
        .build()?;
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", port);

    let mut body = json!({
        "model": cfg.model,
        "messages": build_messages(&job.input),
        "stream": true,
    });
    if let Some(t) = job.model_temperature {
        body["temperature"] = json!(t);
    }
    if let Some(mt) = max_tokens(&job.input) {
        body["max_tokens"] = json!(mt);
    }

    info!(job_id, "Primary sending prompt to Exo cluster");

    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .context("Exo chat request failed")?;

    if !resp.status().is_success() {
        anyhow::bail!("Exo returned HTTP {}", resp.status());
    }

    let mut stream = resp.bytes_stream();
    let mut buf = String::new();

    loop {
        select! {
            chunk = stream.next() => {
                match chunk {
                    Some(Ok(bytes)) => {
                        buf.push_str(&String::from_utf8_lossy(&bytes));
                        if drain_sse(nats, cfg, &mut buf).await? {
                            // [DONE] seen — finalize.
                            return finalize(nats, cfg).await;
                        }
                    }
                    Some(Err(e)) => anyhow::bail!("stream error: {}", e),
                    None => {
                        // Stream ended without [DONE]; finalize anyway.
                        return finalize(nats, cfg).await;
                    }
                }
            }
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    nats.publish_status(job_id, "cancelled", None).await?;
                    return Ok(());
                }
            }
        }
    }
}

/// Parse complete SSE lines from `buf`, publishing token chunks. Returns `true`
/// when the terminal `data: [DONE]` marker is seen.
async fn drain_sse(nats: &NatsAgent, cfg: &ExoConfig, buf: &mut String) -> Result<bool> {
    while let Some(idx) = buf.find('\n') {
        let line: String = buf.drain(..=idx).collect();
        let line = line.trim_end();

        // Exo emits `: prefill_progress {...}` SSE comments — skip them.
        if line.is_empty() || line.starts_with(':') {
            continue;
        }

        let Some(data) = line.strip_prefix("data: ") else {
            continue;
        };

        if data == "[DONE]" {
            return Ok(true);
        }

        if let Ok(v) = serde_json::from_str::<serde_json::Value>(data) {
            if let Some(content) = v
                .pointer("/choices/0/delta/content")
                .and_then(|c| c.as_str())
            {
                if !content.is_empty() {
                    nats.publish_raw(
                        &cfg.subjects.output,
                        serde_json::to_vec(&json!({ "chunk": content, "is_final": false }))?,
                    )
                    .await?;
                }
            }
        }
    }
    Ok(false)
}

/// Send the terminal output chunk + completion status.
async fn finalize(nats: &NatsAgent, cfg: &ExoConfig) -> Result<()> {
    nats.publish_raw(
        &cfg.subjects.output,
        serde_json::to_vec(&json!({ "chunk": "", "is_final": true }))?,
    )
    .await?;
    nats.publish_raw(
        &cfg.subjects.status,
        serde_json::to_vec(&json!({ "status": "complete" }))?,
    )
    .await?;
    Ok(())
}

async fn publish_failed(nats: &NatsAgent, cfg: &ExoConfig, error: &str) -> Result<()> {
    nats.publish_raw(
        &cfg.subjects.status,
        serde_json::to_vec(&json!({
            "host_id": nats.host_id(),
            "status": "failed",
            "error": error,
        }))?,
    )
    .await?;
    Ok(())
}

/// Build an OpenAI `messages` array from the job input, which may be a chat
/// payload (`{"messages": [...]}`), a `{"prompt": "..."}`, or a bare string.
fn build_messages(input: &serde_json::Value) -> serde_json::Value {
    if let Some(messages) = input.get("messages") {
        if messages.is_array() {
            return messages.clone();
        }
    }

    let content = input
        .get("prompt")
        .and_then(|p| p.as_str())
        .or_else(|| input.as_str())
        .unwrap_or("");

    json!([{ "role": "user", "content": content }])
}

fn max_tokens(input: &serde_json::Value) -> Option<u64> {
    input.get("max_tokens").and_then(|v| v.as_u64())
}

/// Derive a stable local API port from the group id to reduce the chance of two
/// concurrent exo jobs on the same Island colliding on a port.
fn api_port_for(group_id: &str) -> u16 {
    let sum: u32 = group_id.bytes().map(|b| b as u32).sum();
    52415u16.wrapping_add((sum % 1000) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_messages_from_chat() {
        let input = json!({"messages": [{"role": "user", "content": "hi"}]});
        assert_eq!(build_messages(&input), json!([{"role": "user", "content": "hi"}]));
    }

    #[test]
    fn build_messages_from_prompt() {
        let input = json!({"prompt": "hello"});
        assert_eq!(build_messages(&input), json!([{"role": "user", "content": "hello"}]));
    }

    #[test]
    fn build_messages_from_string() {
        let input = json!("plain");
        assert_eq!(build_messages(&input), json!([{"role": "user", "content": "plain"}]));
    }

    #[test]
    fn counts_nodes_from_topology() {
        let state = json!({"topology": {"a": {}, "b": {}}});
        assert_eq!(count_nodes(&state), 2);
    }

    #[test]
    fn port_is_stable_and_in_range() {
        let p1 = api_port_for("exo-abc");
        let p2 = api_port_for("exo-abc");
        assert_eq!(p1, p2);
        assert!(p1 >= 52415 && p1 < 53415);
    }
}
