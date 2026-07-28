//! Read-only DAG-frontier observability for the node's JSON-RPC (Eixo-2 / G3).
//!
//! ──────────────────────────────────────────────────────────────────────────────
//! G3 FEASIBILITY VERDICT — pool-influenced MULTI-TIP is NOT achievable on
//! this node without a node change; per-worker tip steering is a NO-OP by
//! GhostDAG design. The honesty ships in the code so nobody re-litigates it:
//!
//!   (1) Via stratum :3333 — the node's `session.rs::install_fresh_template`
//!       builds EVERY job's parents from `d.tips()` (ALL current DAG tips).
//!       There is no stratum message a miner/pool can send to select or
//!       subset tips; the node picks parents internally. Every job already
//!       merges every tip, so "mine different tips" is inherently a no-op.
//!
//!   (2) Via RPC `getblocktemplate` (:16210, `rpc/mod.rs` "getblocktemplate")
//!       — it ALSO snapshots `d.tips()` as `parents` and accepts NO `parents`
//!       argument. You cannot request a template built on specific / subset
//!       tips; parent selection is not part of the request.
//!
//!   (3) `submitblock` (`rpc/mod.rs` "submitblock") requires a fully
//!       assembled, PoW-solved block via `Block::from_bitcoin_bytes`. This
//!       proxy deliberately computes no SHA-256d and rebuilds no templates,
//!       and cannot without linking consensus (forbidden by the crate's
//!       zero-consensus-dep rule). So an "RPC-templated multi-parent job
//!       manager" is out: the RPC neither takes parent selection nor accepts
//!       share-derived work.
//!
//! ACHIEVABLE SLICE (what this module actually delivers): a read-only
//! DAG-frontier OBSERVER. It polls `getdaginfo`
//! (tip / tip_count / block_count / tip_blue_score / tip_height / tips[]) and
//! `getblocktemplate` (parents[] / height / blue_score) and exports
//! `bloch_pool_dag_*`, `bloch_pool_template_parent_count` and
//! `bloch_pool_rpc_poll_failures_total`. This gives real, honest
//! DAG-widening / split visibility (tip_count spikes) with ZERO fake
//! steering. TRUE multi-tip would need a NEW `getblocktemplate` that accepts
//! an explicit `parents` array PLUS a per-parent share/submit path — neither
//! exists today. This module never steers; it only observes.
//! ──────────────────────────────────────────────────────────────────────────────
//!
//! Transport: a minimal, dependency-free JSON-RPC-over-HTTP/1.1 client that
//! mirrors `metrics.rs`'s hand-rolled HTTP style — tokio + serde_json only,
//! no reqwest / hyper, no new deps. The node RPC is an axum `POST /` handler
//! that reads a JSON body (`rpc/mod.rs` `Json(req)`) and, for localhost reads
//! under `trust_private_ranges`, needs no key; an optional `X-API-Key` header
//! is sent when configured. Every response field is parsed DEFENSIVELY:
//! missing or wrong-typed fields degrade to `None` / `0`, and untrusted
//! bytes never `unwrap`/panic — a down or hostile node can only produce an
//! `Err`, never a crash, and the observer keeps looping regardless.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::types::{Metrics, PoolError, ProxyConfig};

/// Total per-call deadline (connect + write + read). The client holds no
/// timeout in its constructed signature, so this bounds a stalled or
/// black-holed node so a poll can never wedge the observer loop forever.
const RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest RPC response we will buffer. `getblocktemplate` can carry a couple
/// thousand transactions, so this is generous; anything larger is treated as
/// a protocol error rather than being read unbounded into memory.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Floor on the poll interval. Guards against a `rpc_poll_secs = 0` config
/// turning the observer into a busy-loop that hammers the node and pins a
/// core.
const MIN_POLL_SECS: u64 = 1;

// ──────────────────────────────────────────────────────────────────────────────
// Parsed, defensively-typed views of the two RPC results we consume.
// ──────────────────────────────────────────────────────────────────────────────

/// Frontier snapshot from `getdaginfo`. Every field defaults on absence /
/// wrong type — a partial or garbage result yields an all-zero/empty
/// `DagInfo`, never a panic.
#[derive(Clone, Debug, Default)]
pub struct DagInfo {
    /// The node's selected tip hash (hex), or `None` if the node reports none
    /// (e.g. still syncing genesis) or the field is missing/mistyped.
    pub selected_tip: Option<String>,
    /// Number of current DAG tips. Spikes here are the honest "DAG widening"
    /// signal the observer exists to surface.
    pub tip_count: u64,
    /// Total blocks the node has in its DAG.
    pub block_count: u64,
    /// Blue score of the selected tip.
    pub tip_blue_score: u64,
    /// Height of the selected tip.
    pub tip_height: u64,
    /// All current tip hashes (hex). May be empty.
    pub tips: Vec<String>,
}

/// Parent/frontier view from `getblocktemplate`. `parents` mirrors the node's
/// `d.tips()` snapshot at template time; its length is exported as
/// `bloch_pool_template_parent_count`.
#[derive(Clone, Debug, Default)]
pub struct TemplateInfo {
    /// Parent tip hashes the node would build the next block on (hex).
    pub parents: Vec<String>,
    /// Template height.
    pub height: u64,
    /// Template blue score.
    pub blue_score: u64,
}

// ──────────────────────────────────────────────────────────────────────────────
// The hand-rolled JSON-RPC-over-HTTP/1.1 client.
// ──────────────────────────────────────────────────────────────────────────────

/// A tiny, read-only JSON-RPC client for the node's HTTP RPC endpoint.
///
/// One-shot per call: it opens a fresh TCP connection, sends a single
/// `POST /` with `Connection: close`, reads the whole response, and closes.
/// This keeps the code trivial and stateless — polling every few seconds
/// does not need connection pooling — and matches the deliberately minimal
/// hand-rolled HTTP in `metrics.rs`.
#[derive(Clone, Debug)]
pub struct RpcClient {
    addr: String,
    api_key: Option<String>,
}

impl RpcClient {
    /// Build a client targeting `addr` (e.g. `127.0.0.1:16210`), sending the
    /// optional `X-API-Key` header when `api_key` is `Some` and non-empty.
    pub fn new(addr: String, api_key: Option<String>) -> Self {
        Self { addr, api_key }
    }

    /// Invoke `method` with `params`, returning the JSON-RPC `result` value.
    ///
    /// Bounded by [`RPC_TIMEOUT`]. Any transport, HTTP, or JSON failure — and
    /// any JSON-RPC-level `error` — is returned as a [`PoolError`]; this
    /// function never panics on node output.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, PoolError> {
        match tokio::time::timeout(RPC_TIMEOUT, self.call_inner(method, params)).await {
            Ok(res) => res,
            Err(_) => Err(PoolError::Timeout(format!(
                "rpc {} to {} timed out after {:?}",
                method, self.addr, RPC_TIMEOUT
            ))),
        }
    }

    async fn call_inner(&self, method: &str, params: Value) -> Result<Value, PoolError> {
        // Build the JSON-RPC 2.0 request body.
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let body = serde_json::to_string(&req)
            .map_err(|e| PoolError::Protocol(format!("rpc: encode request: {}", e)))?;

        // Assemble the HTTP/1.1 request head. Host is informational for the
        // node; `Connection: close` lets us read to EOF for the body.
        let mut head = format!(
            "POST / HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n",
            host = self.addr,
            len = body.len(),
        );
        // Optional API key. Guard against header injection from a stray
        // control char in the configured key (config is trusted, but cheap
        // to be safe).
        if let Some(key) = self.api_key.as_deref() {
            if !key.is_empty() && !key.contains(['\r', '\n']) {
                head.push_str("X-API-Key: ");
                head.push_str(key);
                head.push_str("\r\n");
            }
        }
        head.push_str("\r\n");

        // Serialise head+body into ONE buffer and write it in a single call.
        // A peer that reads the head, replies, and closes before we send a
        // separately-written body would reset our second write; one write
        // avoids that race entirely.
        let mut wire = Vec::with_capacity(head.len() + body.len());
        wire.extend_from_slice(head.as_bytes());
        wire.extend_from_slice(body.as_bytes());

        // Connect, send, read.
        let mut stream = TcpStream::connect(&self.addr).await?;
        stream.write_all(&wire).await?;
        stream.flush().await?;

        let raw = read_response_bounded(&mut stream).await?;
        let _ = stream.shutdown().await; // best-effort clean close

        // Split head/body, check status, parse JSON, extract `result`.
        let (status, json_body) = split_http_response(&raw)?;
        if status != 200 {
            return Err(PoolError::Protocol(format!(
                "rpc {} to {} returned HTTP {}",
                method, self.addr, status
            )));
        }
        let value: Value = serde_json::from_slice(json_body)
            .map_err(|e| PoolError::Protocol(format!("rpc: response not JSON: {}", e)))?;

        if let Some(result) = value.get("result") {
            Ok(result.clone())
        } else if let Some(err) = value.get("error") {
            Err(PoolError::Protocol(format!("rpc {} error: {}", method, err)))
        } else {
            Err(PoolError::Protocol(format!(
                "rpc {}: response missing both result and error",
                method
            )))
        }
    }

    /// Poll `getdaginfo` and project it into a [`DagInfo`].
    pub async fn get_dag_info(&self) -> Result<DagInfo, PoolError> {
        let v = self.call("getdaginfo", Value::Null).await?;
        Ok(parse_dag_info(&v))
    }

    /// Poll `getblocktemplate` and project it into a [`TemplateInfo`].
    pub async fn get_block_template(&self) -> Result<TemplateInfo, PoolError> {
        let v = self.call("getblocktemplate", Value::Null).await?;
        Ok(parse_template_info(&v))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Defensive JSON projection (never panics; missing/mistyped -> default).
// ──────────────────────────────────────────────────────────────────────────────

fn parse_dag_info(v: &Value) -> DagInfo {
    DagInfo {
        selected_tip: v.get("tip").and_then(Value::as_str).map(str::to_string),
        tip_count: v.get("tip_count").and_then(Value::as_u64).unwrap_or(0),
        block_count: v.get("block_count").and_then(Value::as_u64).unwrap_or(0),
        tip_blue_score: v.get("tip_blue_score").and_then(Value::as_u64).unwrap_or(0),
        tip_height: v.get("tip_height").and_then(Value::as_u64).unwrap_or(0),
        tips: parse_hex_array(v.get("tips")),
    }
}

fn parse_template_info(v: &Value) -> TemplateInfo {
    TemplateInfo {
        parents: parse_hex_array(v.get("parents")),
        height: v.get("height").and_then(Value::as_u64).unwrap_or(0),
        blue_score: v.get("blue_score").and_then(Value::as_u64).unwrap_or(0),
    }
}

/// Collect the string elements of a JSON array, dropping any non-string
/// entries. `None` / non-array input yields an empty vec.
fn parse_hex_array(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

// ──────────────────────────────────────────────────────────────────────────────
// Minimal HTTP/1.1 response parsing.
// ──────────────────────────────────────────────────────────────────────────────

/// Read the full response into a bounded buffer (peer sends
/// `Connection: close`, so EOF terminates). Errors if it exceeds
/// [`MAX_RESPONSE_BYTES`] rather than growing memory unbounded.
async fn read_response_bounded(stream: &mut TcpStream) -> Result<Vec<u8>, PoolError> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if buf.len() + n > MAX_RESPONSE_BYTES {
            return Err(PoolError::Protocol("rpc: response exceeds size cap".to_string()));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

/// Split an HTTP response into `(status_code, body_bytes)`.
///
/// Parses only the status line and the header terminator — enough to locate
/// the body — and tolerates a missing/garbled status line by erroring rather
/// than panicking. Assumes the node's `Content-Length` framing (axum `Json`
/// responses set it); a chunked body would simply fail the later JSON parse,
/// still an `Err`, never a panic.
fn split_http_response(raw: &[u8]) -> Result<(u16, &[u8]), PoolError> {
    let sep = find_subslice(raw, b"\r\n\r\n")
        .ok_or_else(|| PoolError::Protocol("rpc: no HTTP header terminator".to_string()))?;
    let head = &raw[..sep];
    let body = &raw[sep + 4..];

    // First line: "HTTP/1.1 200 OK" — code is the second whitespace token.
    let first_line_end = find_subslice(head, b"\r\n").unwrap_or(head.len());
    let status_line = String::from_utf8_lossy(&head[..first_line_end]);
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| PoolError::Protocol("rpc: unparseable HTTP status line".to_string()))?;

    Ok((code, body))
}

/// First index of `needle` within `haystack`, or `None`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ──────────────────────────────────────────────────────────────────────────────
// The observer loop (spawned by the server, module 5).
// ──────────────────────────────────────────────────────────────────────────────

/// Poll the node's DAG frontier forever, exporting gauges via `metrics`.
///
/// Every `cfg.rpc_poll_secs` (floored at [`MIN_POLL_SECS`]): fetch
/// `getdaginfo` + `getblocktemplate`. On full success, publish the frontier
/// gauges and log at debug. On ANY error — connection refused, timeout,
/// non-200, malformed JSON — bump `rpc_poll_failed()`, log a WARN, and keep
/// looping. This function NEVER returns and NEVER panics: a down or refusing
/// node degrades observability but must not take the proxy down.
pub async fn run_dag_observer(cfg: Arc<ProxyConfig>, metrics: Arc<Metrics>) {
    let client = RpcClient::new(cfg.rpc_addr.clone(), cfg.rpc_api_key.clone());
    let interval = Duration::from_secs(cfg.rpc_poll_secs.max(MIN_POLL_SECS));
    log::info!(
        "dag observer starting: rpc={} interval={:?}",
        cfg.rpc_addr,
        interval
    );

    loop {
        match poll_once(&client).await {
            Ok((dag, template)) => {
                metrics.set_dag(
                    dag.tip_count as i64,
                    dag.block_count as i64,
                    dag.tip_blue_score as i64,
                    dag.tip_height as i64,
                );
                metrics.set_template_parent_count(template.parents.len() as i64);
                log::debug!(
                    "dag poll ok: tips={} blocks={} tip_blue_score={} tip_height={} template_parents={}",
                    dag.tip_count,
                    dag.block_count,
                    dag.tip_blue_score,
                    dag.tip_height,
                    template.parents.len(),
                );
            }
            Err(e) => {
                metrics.rpc_poll_failed();
                log::warn!("dag poll failed (node down/refusing?): {}", e);
            }
        }
        tokio::time::sleep(interval).await;
    }
}

/// One combined poll: both RPCs must succeed for the poll to count as a
/// success. Split out so the fetch/parse path is unit-testable without the
/// infinite loop.
async fn poll_once(client: &RpcClient) -> Result<(DagInfo, TemplateInfo), PoolError> {
    let dag = client.get_dag_info().await?;
    let template = client.get_block_template().await?;
    Ok((dag, template))
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use tokio::net::TcpListener;

    /// Stand up a one-shot mock HTTP node that replies to the first
    /// connection with `body` wrapped as a `200 OK`, then returns its addr.
    async fn mock_node_ok(body: &'static str) -> String {
        mock_node_raw(format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        ))
        .await
    }

    /// Stand up a one-shot mock node that writes `raw` verbatim (lets a test
    /// inject a malformed status line / body).
    async fn mock_node_raw(raw: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                // Drain the request head so the client's write completes.
                let mut scratch = [0u8; 4096];
                let _ = stream.read(&mut scratch).await;
                let _ = stream.write_all(raw.as_bytes()).await;
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
            }
        });
        addr
    }

    /// An addr that will refuse connections: bind, capture the port, drop.
    async fn dead_addr() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        addr
    }

    #[tokio::test]
    async fn client_parses_getdaginfo() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{
            "tip":"aabb","tip_blue_score":1234,"tip_height":56,
            "block_count":789,"tip_count":3,
            "tips":["aabb","ccdd","eeff"],"chain_length":10,"k":18}}"#;
        let addr = mock_node_ok(body).await;
        let client = RpcClient::new(addr, None);
        let dag = client.get_dag_info().await.unwrap();
        assert_eq!(dag.selected_tip.as_deref(), Some("aabb"));
        assert_eq!(dag.tip_blue_score, 1234);
        assert_eq!(dag.tip_height, 56);
        assert_eq!(dag.block_count, 789);
        assert_eq!(dag.tip_count, 3);
        assert_eq!(dag.tips, vec!["aabb", "ccdd", "eeff"]);
    }

    #[tokio::test]
    async fn client_parses_getblocktemplate() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{
            "parents":["1111","2222"],"height":42,"blue_score":99,
            "bits":486604799,"transactions":[]}}"#;
        let addr = mock_node_ok(body).await;
        let client = RpcClient::new(addr, None);
        let t = client.get_block_template().await.unwrap();
        assert_eq!(t.parents, vec!["1111", "2222"]);
        assert_eq!(t.height, 42);
        assert_eq!(t.blue_score, 99);
    }

    #[tokio::test]
    async fn api_key_is_sent_when_configured() {
        // Custom mock that captures the request head and asserts the header.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut scratch = vec![0u8; 4096];
            let n = stream.read(&mut scratch).await.unwrap();
            let head = String::from_utf8_lossy(&scratch[..n]).to_string();
            let body = r#"{"result":{"tip_count":1}}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.shutdown().await;
            head
        });
        let client = RpcClient::new(addr, Some("s3cr3t".to_string()));
        let _ = client.get_dag_info().await.unwrap();
        let head = handle.await.unwrap();
        assert!(head.contains("X-API-Key: s3cr3t"), "head was: {}", head);
    }

    #[tokio::test]
    async fn malformed_body_is_err_not_panic() {
        let addr = mock_node_ok("this is not json at all <<<").await;
        let client = RpcClient::new(addr, None);
        let res = client.get_dag_info().await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn partial_json_missing_result_is_err() {
        // Valid JSON, but no `result` and no `error` field.
        let addr = mock_node_ok(r#"{"jsonrpc":"2.0","id":1}"#).await;
        let client = RpcClient::new(addr, None);
        assert!(client.get_dag_info().await.is_err());
    }

    #[tokio::test]
    async fn non_200_status_is_err() {
        let body = r#"{"error":{"code":-32001,"message":"unauthorized"}}"#;
        let raw = format!(
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let addr = mock_node_raw(raw).await;
        let client = RpcClient::new(addr, None);
        assert!(client.get_dag_info().await.is_err());
    }

    #[tokio::test]
    async fn garbage_http_head_is_err_not_panic() {
        let addr = mock_node_raw("not even http\r\n\r\n{}".to_string()).await;
        let client = RpcClient::new(addr, None);
        assert!(client.get_dag_info().await.is_err());
    }

    #[test]
    fn dag_info_defaults_on_missing_fields() {
        // Empty object -> everything defaults, no panic.
        let d = parse_dag_info(&serde_json::json!({}));
        assert_eq!(d.selected_tip, None);
        assert_eq!(d.tip_count, 0);
        assert_eq!(d.block_count, 0);
        assert_eq!(d.tip_blue_score, 0);
        assert_eq!(d.tip_height, 0);
        assert!(d.tips.is_empty());
    }

    #[test]
    fn dag_info_ignores_wrong_types() {
        // Fields present but wrong type -> defaults, non-string tips dropped.
        let d = parse_dag_info(&serde_json::json!({
            "tip": 12345,
            "tip_count": "not a number",
            "block_count": true,
            "tips": ["good", 7, null, "also_good"],
        }));
        assert_eq!(d.selected_tip, None);
        assert_eq!(d.tip_count, 0);
        assert_eq!(d.block_count, 0);
        assert_eq!(d.tips, vec!["good", "also_good"]);
    }

    #[test]
    fn template_info_defaults_on_missing_fields() {
        let t = parse_template_info(&serde_json::json!({}));
        assert!(t.parents.is_empty());
        assert_eq!(t.height, 0);
        assert_eq!(t.blue_score, 0);
    }

    #[test]
    fn template_info_parses_and_defaults_mixed() {
        let t = parse_template_info(&serde_json::json!({
            "parents": ["aa", "bb"],
            "height": 5,
            // blue_score missing -> 0
        }));
        assert_eq!(t.parents, vec!["aa", "bb"]);
        assert_eq!(t.height, 5);
        assert_eq!(t.blue_score, 0);
    }

    #[test]
    fn find_subslice_basic() {
        assert_eq!(find_subslice(b"abcXYdef", b"XY"), Some(3));
        assert_eq!(find_subslice(b"abc", b"XY"), None);
        assert_eq!(find_subslice(b"abc", b""), None);
        assert_eq!(find_subslice(b"", b"XY"), None);
    }

    #[test]
    fn split_http_response_extracts_status_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        let (code, body) = split_http_response(raw).unwrap();
        assert_eq!(code, 200);
        assert_eq!(body, b"{}");
    }

    #[test]
    fn split_http_response_no_terminator_is_err() {
        assert!(split_http_response(b"HTTP/1.1 200 OK\r\nno end").is_err());
    }

    #[tokio::test]
    async fn observer_counts_failures_when_endpoint_refuses() {
        // Point the observer at a refusing addr; the first poll runs
        // immediately (before the first sleep) and must bump the failure
        // counter without panicking or exiting.
        let addr = dead_addr().await;
        let mut cfg = ProxyConfig::default();
        cfg.rpc_addr = addr;
        cfg.rpc_poll_secs = 1;
        let cfg = Arc::new(cfg);
        let metrics = Arc::new(Metrics::new());

        let m = metrics.clone();
        let handle = tokio::spawn(async move {
            run_dag_observer(cfg, m).await;
        });

        // Connection-refused is immediate; give the first iteration a moment.
        for _ in 0..50 {
            if metrics.rpc_poll_failures.load(Ordering::Relaxed) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            metrics.rpc_poll_failures.load(Ordering::Relaxed) >= 1,
            "observer did not record a poll failure against a refusing endpoint"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn poll_once_errors_against_dead_endpoint() {
        let addr = dead_addr().await;
        let client = RpcClient::new(addr, None);
        assert!(poll_once(&client).await.is_err());
    }
}
