//! Prometheus text rendering + a tiny hand-rolled HTTP/1.1 endpoint.
//!
//! Module 5 (server) owns metrics exposition. This file renders the shared
//! `Arc<Metrics>` snapshot as Prometheus text (`bloch_pool_*` series, naming
//! mirrors the node's `bloch_*` convention) and serves it over a minimal,
//! dependency-free HTTP/1.1 server.
//!
//! ### Sprint-2 additions (D5)
//!
//! * The renderer now emits the G2 extranonce re-dial counters
//!   (`bloch_pool_extranonce1_redials_total`,
//!   `bloch_pool_extranonce1_unresolved_total`), the G3 read-only DAG-frontier
//!   gauges (`bloch_pool_dag_*`, `bloch_pool_template_parent_count`,
//!   `bloch_pool_rpc_poll_failures_total`), and the G1 pool-wide PPLNS window
//!   gauges (`bloch_pool_pplns_window_shares`, `..._window_weight`,
//!   `..._distinct_workers`) rendered from a [`PplnsSnapshot`].
//! * The endpoint now does MINIMAL path routing: a request whose target path
//!   starts with `/pplns` returns `200 application/json` carrying
//!   `serde_json(ledger.credit())` — the G1 query surface a payout job
//!   consumes. Any other path returns the Prometheus text exactly as before.
//! * The request-head read loop is wrapped in a bounded
//!   [`tokio::time::timeout`] (advisor LOW) so a peer that opens a socket and
//!   then stalls cannot pin a spawned task forever, and the end-of-head scan
//!   now runs over the ACCUMULATED buffer rather than only the last chunk, so
//!   the `\r\n\r\n` marker is never missed when split across reads.
//!
//! Deliberately trivial: no external HTTP crate (the crate's dep set is
//! tokio + serde + log only), and untrusted request bytes are read into a
//! bounded buffer, so a malformed request can neither panic nor grow memory.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::pplns::{PplnsLedger, PplnsSnapshot};
use crate::types::{Metrics, MetricsSnapshot, PoolError};

/// Largest request head we will read before responding. A scraper sends a
/// short `GET`; anything past this we simply stop reading and answer anyway.
const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// Per-connection ceiling on how long we will wait for the request head. A
/// slow/stalled peer that never sends the blank-line terminator (or the byte
/// cap) is answered with `408` and dropped rather than pinning a task.
const READ_HEAD_TIMEOUT: Duration = Duration::from_secs(5);

/// Content type Prometheus expects (same string the node emits).
const PROM_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Render a metrics snapshot + PPLNS-window snapshot as Prometheus exposition
/// text.
///
/// Every series carries a `# HELP` and `# TYPE` line, gauges for levels and
/// `_total` counters for monotonic tallies, matching the node's series
/// style. Output is deterministic (fixed field order) so scrapers and tests
/// see a stable document.
pub fn render_prometheus(snap: &MetricsSnapshot, pplns: &PplnsSnapshot) -> String {
    // Pre-size roughly: ~23 metrics * ~3 lines * ~40 bytes.
    let mut out = String::with_capacity(2800);

    gauge(
        &mut out,
        "bloch_pool_workers_active",
        "Downstream miner connections currently established.",
        snap.workers_active,
    );
    counter(
        &mut out,
        "bloch_pool_workers_total",
        "Total downstream miner connections accepted since start.",
        snap.workers_total,
    );
    counter(
        &mut out,
        "bloch_pool_shares_accepted_total",
        "Shares accepted upstream (includes shares that solved a block).",
        snap.shares_accepted,
    );
    counter(
        &mut out,
        "bloch_pool_shares_rejected_total",
        "Shares rejected upstream for any reason.",
        snap.shares_rejected,
    );
    counter(
        &mut out,
        "bloch_pool_shares_stale_total",
        "Shares rejected as stale / job-not-found (error 21).",
        snap.shares_stale,
    );
    counter(
        &mut out,
        "bloch_pool_shares_duplicate_total",
        "Shares rejected as duplicate (error 22).",
        snap.shares_duplicate,
    );
    counter(
        &mut out,
        "bloch_pool_blocks_found_total",
        // Advisor LOW: do not advertise a live signal. A stratum result:true
        // cannot distinguish a solved block from an ordinary accepted share,
        // so this stays 0 unless a future block-detection hook lands.
        "Sprint-2 STUB: always 0 unless a future block-detection hook lands (a stratum result:true cannot distinguish a block from an ordinary share).",
        snap.blocks_found,
    );
    counter(
        &mut out,
        "bloch_pool_upstream_reconnects_total",
        "Successful upstream reconnects to the node's stratum.",
        snap.upstream_reconnects,
    );
    counter(
        &mut out,
        "bloch_pool_upstream_connect_failures_total",
        "Failed attempts to connect an upstream to the node's stratum.",
        snap.upstream_connect_failures,
    );
    counter(
        &mut out,
        "bloch_pool_extranonce1_collisions_total",
        "Node-assigned extranonce1 values found already in use by another live worker (duplicated search space).",
        snap.extranonce1_collisions,
    );
    // ── G2: re-dial-until-unique extranonce guard ────────────────────────
    counter(
        &mut out,
        "bloch_pool_extranonce1_redials_total",
        "Upstream re-dials performed to obtain a not-in-use extranonce1 after a collision.",
        snap.extranonce1_redials,
    );
    counter(
        &mut out,
        "bloch_pool_extranonce1_unresolved_total",
        "Colliding workers served after the re-dial budget was exhausted without a unique extranonce1 (still overlapping search space).",
        snap.extranonce1_unresolved,
    );
    // ── G3: read-only DAG-frontier observer (no steering) ────────────────
    gauge(
        &mut out,
        "bloch_pool_dag_tip_count",
        "Current DAG tip count reported by the node (getdaginfo) — GhostDAG frontier width; spikes are the honest DAG-widening signal.",
        snap.dag_tip_count,
    );
    gauge(
        &mut out,
        "bloch_pool_dag_block_count",
        "Total blocks in the node's DAG (getdaginfo).",
        snap.dag_block_count,
    );
    gauge(
        &mut out,
        "bloch_pool_dag_tip_blue_score",
        "Blue score of the node's selected tip (getdaginfo).",
        snap.dag_tip_blue_score,
    );
    gauge(
        &mut out,
        "bloch_pool_dag_tip_height",
        "Height of the node's selected tip (getdaginfo).",
        snap.dag_tip_height,
    );
    gauge(
        &mut out,
        "bloch_pool_template_parent_count",
        "Parent count of the latest getblocktemplate the observer polled (multi-parent frontier width).",
        snap.template_parent_count,
    );
    counter(
        &mut out,
        "bloch_pool_rpc_poll_failures_total",
        "Failed read-only RPC polls of the node (getdaginfo/getblocktemplate) by the DAG observer.",
        snap.rpc_poll_failures,
    );
    // ── G1: pool-wide PPLNS sliding window ───────────────────────────────
    gauge(
        &mut out,
        "bloch_pool_pplns_window_shares",
        "Accepted shares currently retained in the pool-wide PPLNS sliding window.",
        pplns.window_len as i64,
    );
    gauge_f64(
        &mut out,
        "bloch_pool_pplns_window_weight",
        "Total difficulty weight of the shares in the PPLNS window (the payout-credit denominator).",
        pplns.total_weight,
    );
    gauge(
        &mut out,
        "bloch_pool_pplns_distinct_workers",
        "Distinct workers with at least one share in the PPLNS window.",
        pplns.distinct_workers as i64,
    );
    // ── byte counters (last, as in Sprint 1) ─────────────────────────────
    counter(
        &mut out,
        "bloch_pool_bytes_up_total",
        "Bytes forwarded from miners toward the node (upstream).",
        snap.bytes_up,
    );
    counter(
        &mut out,
        "bloch_pool_bytes_down_total",
        "Bytes forwarded from the node toward miners (downstream).",
        snap.bytes_down,
    );

    out
}

fn gauge(out: &mut String, name: &str, help: &str, value: i64) {
    header(out, name, help, "gauge");
    out.push_str(name);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

fn gauge_f64(out: &mut String, name: &str, help: &str, value: f64) {
    header(out, name, help, "gauge");
    out.push_str(name);
    out.push(' ');
    // Rust's Display for f64 never uses scientific notation and always emits a
    // finite decimal for finite inputs; a non-finite weight (should never
    // occur — weights are clamped to unit on non-positive difficulty upstream)
    // renders as `NaN`/`inf`, which Prometheus tolerates. Never panics.
    out.push_str(&value.to_string());
    out.push('\n');
}

fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    header(out, name, help, "counter");
    out.push_str(name);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

/// Emit the shared `# HELP` / `# TYPE` preamble for one series.
fn header(out: &mut String, name: &str, help: &str, kind: &str) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push(' ');
    out.push_str(kind);
    out.push('\n');
}

/// Bind `addr` and serve the metrics endpoint forever. Returns only on a
/// fatal bind error; per-connection errors are logged and swallowed so one
/// bad scraper never takes the endpoint down.
pub async fn serve_metrics(
    addr: &str,
    metrics: Arc<Metrics>,
    ledger: Arc<PplnsLedger>,
) -> Result<(), PoolError> {
    let listener = TcpListener::bind(addr).await.map_err(|e| {
        PoolError::Config(format!("cannot bind metrics endpoint {}: {}", addr, e))
    })?;
    log::info!("metrics endpoint listening on {}", addr);
    serve_metrics_on(listener, metrics, ledger).await
}

/// Accept-loop half of [`serve_metrics`], split out so tests can drive it on
/// an OS-assigned ephemeral port.
pub(crate) async fn serve_metrics_on(
    listener: TcpListener,
    metrics: Arc<Metrics>,
    ledger: Arc<PplnsLedger>,
) -> Result<(), PoolError> {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                // Transient accept errors (fd exhaustion, reset) must not kill
                // the endpoint; log and keep going.
                log::warn!("metrics accept error: {}", e);
                continue;
            }
        };
        let m = metrics.clone();
        let l = ledger.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, &m, &l).await {
                log::debug!("metrics conn {} ended: {}", peer, e);
            }
        });
    }
}

/// Read the request head (bounded in both bytes AND time), then write the
/// appropriate response: PPLNS JSON for a `/pplns*` target, Prometheus text
/// for anything else. Thin wrapper around [`handle_conn_inner`] pinning the
/// production [`READ_HEAD_TIMEOUT`].
async fn handle_conn(
    stream: TcpStream,
    metrics: &Metrics,
    ledger: &PplnsLedger,
) -> std::io::Result<()> {
    handle_conn_inner(stream, metrics, ledger, READ_HEAD_TIMEOUT).await
}

/// [`handle_conn`] with an explicit head-read deadline, so tests can exercise
/// the timeout path deterministically with a short real-time bound instead of
/// a flaky paused clock over live sockets.
async fn handle_conn_inner(
    mut stream: TcpStream,
    metrics: &Metrics,
    ledger: &PplnsLedger,
    head_timeout: Duration,
) -> std::io::Result<()> {
    // Drain the request head up to the blank line (or the byte cap), bounded
    // by `head_timeout` so a stalled peer cannot pin this task. We keep the
    // accumulated head so we can route on the request target.
    let mut head: Vec<u8> = Vec::with_capacity(1024);
    match timeout(head_timeout, read_request_head(&mut stream, &mut head)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_elapsed) => {
            // Timed out waiting for the head: answer 408 and drop the peer.
            let resp = http_response("408 Request Timeout", "text/plain", "request timeout\n");
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
            return Ok(());
        }
    }

    let response = if wants_pplns(&head) {
        // G1 query surface: the exact credit vector a payout job consumes.
        // Serialization of a `Vec<PplnsCredit>` cannot fail, but degrade to an
        // empty array rather than ever unwrapping on untrusted-adjacent state.
        let body = serde_json::to_string(&ledger.credit()).unwrap_or_else(|_| "[]".to_string());
        http_response("200 OK", "application/json", &body)
    } else {
        let body = render_prometheus(&metrics.snapshot(), &ledger.snapshot());
        http_response("200 OK", PROM_CONTENT_TYPE, &body)
    };

    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    // Best-effort clean close; ignore errors from an already-gone peer.
    let _ = stream.shutdown().await;
    Ok(())
}

/// Read bytes into `head` until the end-of-head marker is seen anywhere in the
/// ACCUMULATED buffer, the byte cap is reached, or the peer closes. Never
/// interprets the bytes here — routing happens after — but bounds memory.
async fn read_request_head(stream: &mut TcpStream, head: &mut Vec<u8>) -> std::io::Result<()> {
    let mut buf = [0u8; 1024];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break; // client closed before finishing; caller replies anyway.
        }
        head.extend_from_slice(&buf[..n]);
        // Scan the accumulated buffer (fix vs. only-latest-chunk) so the
        // `\r\n\r\n` marker is found even when split across reads. Cap the
        // scanned/kept head so a flood cannot grow memory.
        if head.len() >= MAX_REQUEST_BYTES {
            head.truncate(MAX_REQUEST_BYTES);
            break;
        }
        if contains_head_end(head) {
            break;
        }
    }
    Ok(())
}

/// Cheap check for the end-of-headers marker anywhere within `head`.
fn contains_head_end(head: &[u8]) -> bool {
    head.windows(4).any(|w| w == b"\r\n\r\n") || head.windows(2).any(|w| w == b"\n\n")
}

/// Does the request target begin with `/pplns`? Parses only the request line
/// (`METHOD SP TARGET SP VERSION`); any malformed / missing head routes to the
/// Prometheus default. Never panics on hostile bytes.
fn wants_pplns(head: &[u8]) -> bool {
    request_target(head)
        .map(|t| t.starts_with("/pplns"))
        .unwrap_or(false)
}

/// Extract the request target (second whitespace token of the first line).
fn request_target(head: &[u8]) -> Option<String> {
    let end = head.iter().position(|&b| b == b'\n')?;
    let mut line = &head[..end];
    if line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    let s = std::str::from_utf8(line).ok()?;
    let mut it = s.split(' ');
    let _method = it.next()?;
    let target = it.next()?;
    if target.is_empty() {
        return None;
    }
    Some(target.to_string())
}

/// Build a complete HTTP/1.1 response carrying `body` with the given status
/// line (e.g. `"200 OK"`) and content type.
fn http_response(status: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {ct}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        status = status,
        ct = content_type,
        len = body.len(),
        body = body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ProxyConfig, ShareOutcome, WorkerId};
    use std::sync::atomic::Ordering;

    fn snap_with(f: impl FnOnce(&Metrics)) -> MetricsSnapshot {
        let m = Metrics::new();
        f(&m);
        m.snapshot()
    }

    /// A zeroed PPLNS-window snapshot for render tests that only assert on the
    /// metric SHAPE (HELP/TYPE lines are emitted regardless of value).
    fn empty_pplns() -> PplnsSnapshot {
        PplnsSnapshot::default()
    }

    fn test_ledger() -> Arc<PplnsLedger> {
        Arc::new(PplnsLedger::new(&ProxyConfig::default()))
    }

    #[test]
    fn render_has_help_type_and_values() {
        let snap = snap_with(|m| {
            m.worker_connected();
            m.worker_connected();
            m.shares_accepted.fetch_add(7, Ordering::Relaxed);
            m.blocks_found.fetch_add(1, Ordering::Relaxed);
            m.bytes_down.fetch_add(4096, Ordering::Relaxed);
        });
        let text = render_prometheus(&snap, &empty_pplns());

        assert!(text.contains("# HELP bloch_pool_workers_active"));
        assert!(text.contains("# TYPE bloch_pool_workers_active gauge"));
        assert!(text.contains("\nbloch_pool_workers_active 2\n"));

        assert!(text.contains("# TYPE bloch_pool_shares_accepted_total counter"));
        assert!(text.contains("\nbloch_pool_shares_accepted_total 7\n"));
        assert!(text.contains("\nbloch_pool_workers_total 2\n"));
        assert!(text.contains("\nbloch_pool_blocks_found_total 1\n"));
        assert!(text.contains("\nbloch_pool_bytes_down_total 4096\n"));
    }

    #[test]
    fn render_default_is_all_zero_and_well_formed() {
        let text = render_prometheus(&MetricsSnapshot::default(), &empty_pplns());
        // Every declared series must appear exactly once as a HELP line.
        for name in [
            "bloch_pool_workers_active",
            "bloch_pool_workers_total",
            "bloch_pool_shares_accepted_total",
            "bloch_pool_shares_rejected_total",
            "bloch_pool_shares_stale_total",
            "bloch_pool_shares_duplicate_total",
            "bloch_pool_blocks_found_total",
            "bloch_pool_upstream_reconnects_total",
            "bloch_pool_upstream_connect_failures_total",
            "bloch_pool_extranonce1_collisions_total",
            "bloch_pool_bytes_up_total",
            "bloch_pool_bytes_down_total",
        ] {
            let help = format!("# HELP {}", name);
            assert_eq!(text.matches(&help).count(), 1, "missing/dup HELP for {name}");
        }
        // No trailing garbage; ends with a newline.
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn render_includes_all_new_sprint2_series() {
        // Populate the new counters/gauges so both HELP and the value line are
        // exercised; PPLNS window shape comes from a live snapshot.
        let snap = snap_with(|m| {
            m.extranonce1_redial();
            m.extranonce1_redial();
            m.extranonce1_unresolved();
            m.set_dag(3, 4200, 99, 88);
            m.set_template_parent_count(5);
            m.rpc_poll_failed();
        });
        let ledger = PplnsLedger::new(&ProxyConfig::default());
        ledger.record(WorkerId(1), "j", 8.0, &ShareOutcome::Accepted);
        ledger.record(WorkerId(2), "j", 4.0, &ShareOutcome::Accepted);
        let text = render_prometheus(&snap, &ledger.snapshot());

        for name in [
            "bloch_pool_extranonce1_redials_total",
            "bloch_pool_extranonce1_unresolved_total",
            "bloch_pool_dag_tip_count",
            "bloch_pool_dag_block_count",
            "bloch_pool_dag_tip_blue_score",
            "bloch_pool_dag_tip_height",
            "bloch_pool_template_parent_count",
            "bloch_pool_rpc_poll_failures_total",
            "bloch_pool_pplns_window_shares",
            "bloch_pool_pplns_window_weight",
            "bloch_pool_pplns_distinct_workers",
        ] {
            let help = format!("# HELP {}", name);
            assert_eq!(text.matches(&help).count(), 1, "missing/dup HELP for {name}");
        }

        // Spot-check some values flowed through correctly.
        assert!(text.contains("\nbloch_pool_extranonce1_redials_total 2\n"));
        assert!(text.contains("\nbloch_pool_extranonce1_unresolved_total 1\n"));
        assert!(text.contains("\nbloch_pool_dag_tip_count 3\n"));
        assert!(text.contains("\nbloch_pool_dag_block_count 4200\n"));
        assert!(text.contains("\nbloch_pool_template_parent_count 5\n"));
        assert!(text.contains("\nbloch_pool_rpc_poll_failures_total 1\n"));
        // Two accepted shares, two distinct workers, weight 8+4=12.
        assert!(text.contains("\nbloch_pool_pplns_window_shares 2\n"));
        assert!(text.contains("\nbloch_pool_pplns_distinct_workers 2\n"));
        assert!(text.contains("\nbloch_pool_pplns_window_weight 12\n"));
    }

    #[test]
    fn blocks_found_help_is_marked_a_stub() {
        // Operators must not read 0 blocks as "pool never wins" — the HELP has
        // to flag it as a Sprint-2 stub.
        let text = render_prometheus(&MetricsSnapshot::default(), &empty_pplns());
        let help_line = text
            .lines()
            .find(|l| l.starts_with("# HELP bloch_pool_blocks_found_total"))
            .expect("blocks_found HELP present");
        assert!(
            help_line.to_lowercase().contains("stub"),
            "blocks_found HELP must be marked a stub, got: {help_line}"
        );
    }

    #[test]
    fn http_response_sets_content_length_to_body_len() {
        let body = "hello metrics\n";
        let resp = http_response("200 OK", PROM_CONTENT_TYPE, body);
        assert!(resp.contains(&format!("Content-Length: {}", body.len())));
        assert!(resp.contains("Content-Type: text/plain; version=0.0.4"));
        assert!(resp.ends_with(body));
    }

    #[test]
    fn head_end_detection_scans_whole_buffer() {
        assert!(contains_head_end(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(contains_head_end(b"GET / HTTP/1.1\n\n"));
        assert!(!contains_head_end(b"GET / HTTP/1.1\r\nHost: x\r\n"));
        // The marker split across what would have been two chunks is still
        // found because we scan the accumulated buffer.
        assert!(contains_head_end(b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody"));
    }

    #[test]
    fn request_target_parses_or_defaults() {
        assert_eq!(
            request_target(b"GET /pplns HTTP/1.1\r\n\r\n").as_deref(),
            Some("/pplns")
        );
        assert_eq!(
            request_target(b"GET /metrics?foo=1 HTTP/1.1\r\n").as_deref(),
            Some("/metrics?foo=1")
        );
        // Garbage / empty must not panic — just yield None (→ Prometheus).
        assert_eq!(request_target(b""), None);
        assert_eq!(request_target(b"garbage-no-newline"), None);
        assert!(!wants_pplns(b"GET /metrics HTTP/1.1\r\n\r\n"));
        assert!(wants_pplns(b"GET /pplns HTTP/1.1\r\n\r\n"));
    }

    #[tokio::test]
    async fn end_to_end_scrape_returns_prometheus() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let metrics = Arc::new(Metrics::new());
        metrics.shares_accepted.fetch_add(5, Ordering::Relaxed);
        metrics.worker_connected();
        let ledger = test_ledger();

        let m = metrics.clone();
        let l = ledger.clone();
        tokio::spawn(async move {
            let _ = serve_metrics_on(listener, m, l).await;
        });

        let mut conn = TcpStream::connect(addr).await.unwrap();
        conn.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        conn.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);

        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("Content-Type: text/plain; version=0.0.4"));
        assert!(text.contains("\nbloch_pool_shares_accepted_total 5\n"));
        assert!(text.contains("\nbloch_pool_workers_active 1\n"));
        // New Sprint-2 series are present over the wire too.
        assert!(text.contains("bloch_pool_pplns_window_shares"));
        assert!(text.contains("bloch_pool_dag_tip_count"));
    }

    #[tokio::test]
    async fn pplns_endpoint_returns_json_credit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let metrics = Arc::new(Metrics::new());
        let ledger = test_ledger();
        // Record an accepted share so the credit vector is non-empty.
        ledger.record(WorkerId(1), "job", 8.0, &ShareOutcome::Accepted);

        let m = metrics.clone();
        let l = ledger.clone();
        tokio::spawn(async move {
            let _ = serve_metrics_on(listener, m, l).await;
        });

        let mut conn = TcpStream::connect(addr).await.unwrap();
        conn.write_all(b"GET /pplns HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        conn.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);

        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("Content-Type: application/json"));
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
        assert!(
            body.trim_start().starts_with('['),
            "pplns body is not a JSON array: {body}"
        );
        // The serialized PplnsCredit exposes the worker + payout fraction.
        assert!(body.contains("\"worker\""), "body: {body}");
        assert!(body.contains("\"fraction\""), "body: {body}");
    }

    #[tokio::test]
    async fn empty_pplns_endpoint_is_empty_json_array() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let metrics = Arc::new(Metrics::new());
        let ledger = test_ledger();

        let m = metrics.clone();
        let l = ledger.clone();
        tokio::spawn(async move {
            let _ = serve_metrics_on(listener, m, l).await;
        });

        let mut conn = TcpStream::connect(addr).await.unwrap();
        conn.write_all(b"GET /pplns HTTP/1.1\r\n\r\n").await.unwrap();
        let mut buf = Vec::new();
        conn.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
        assert_eq!(body, "[]");
    }

    /// A peer that opens a socket and sends a partial request head (no
    /// end-of-head marker) must be timed out and answered `408`, not pin the
    /// task. Driven through `handle_conn_inner` with a short real-time deadline
    /// so it is deterministic and fast.
    #[tokio::test]
    async fn slow_client_hits_read_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let metrics = Arc::new(Metrics::new());
        let ledger = test_ledger();
        let srv = tokio::spawn(async move {
            let _ =
                handle_conn_inner(server, &metrics, &ledger, Duration::from_millis(50)).await;
        });

        // Partial head: a request line but never the blank-line terminator.
        client.write_all(b"GET /metrics HTTP/1.1\r\n").await.unwrap();
        client.flush().await.unwrap();

        // The server must time out, answer 408, and close.
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.starts_with("HTTP/1.1 408"),
            "expected a 408 after the head-read timeout, got: {text}"
        );
        let _ = srv.await;
    }
}
