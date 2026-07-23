//! Prometheus text rendering + a tiny hand-rolled HTTP/1.1 endpoint.
//!
//! Module 5 (server) owns metrics exposition. This file renders the shared
//! `Arc<Metrics>` snapshot as Prometheus text (`bloch_pool_*` series, naming
//! mirrors the node's `bloch_*` convention) and serves it over a minimal,
//! dependency-free HTTP/1.1 server: any `GET` returns `200 text/plain` with
//! the current snapshot. There is no routing — a scrape on any path works,
//! which is all Prometheus needs.
//!
//! Deliberately trivial: no external HTTP crate (the crate's dep set is
//! tokio + serde + log only), and untrusted request bytes are read into a
//! bounded buffer and otherwise ignored, so a malformed request can neither
//! panic nor grow memory.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::types::{Metrics, MetricsSnapshot, PoolError};

/// Largest request head we will read before responding. A scraper sends a
/// short `GET`; anything past this we simply stop reading and answer anyway.
const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// Content type Prometheus expects (same string the node emits).
const PROM_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Render a metrics snapshot as Prometheus exposition text.
///
/// Every series carries a `# HELP` and `# TYPE` line, gauges for levels and
/// `_total` counters for monotonic tallies, matching the node's series
/// style. Output is deterministic (fixed field order) so scrapers and tests
/// see a stable document.
pub fn render_prometheus(snap: &MetricsSnapshot) -> String {
    // Pre-size roughly: 11 metrics * ~3 lines * ~40 bytes.
    let mut out = String::with_capacity(1400);

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
        "Accepted shares that solved a real block (block-detection hook).",
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
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push_str(" gauge\n");
    out.push_str(name);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push_str(" counter\n");
    out.push_str(name);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

/// Bind `addr` and serve the metrics endpoint forever. Returns only on a
/// fatal bind error; per-connection errors are logged and swallowed so one
/// bad scraper never takes the endpoint down.
pub async fn serve_metrics(addr: &str, metrics: Arc<Metrics>) -> Result<(), PoolError> {
    let listener = TcpListener::bind(addr).await.map_err(|e| {
        PoolError::Config(format!("cannot bind metrics endpoint {}: {}", addr, e))
    })?;
    log::info!("metrics endpoint listening on {}", addr);
    serve_metrics_on(listener, metrics).await
}

/// Accept-loop half of [`serve_metrics`], split out so tests can drive it on
/// an OS-assigned ephemeral port.
pub(crate) async fn serve_metrics_on(
    listener: TcpListener,
    metrics: Arc<Metrics>,
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
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, &m).await {
                log::debug!("metrics conn {} ended: {}", peer, e);
            }
        });
    }
}

/// Read (and discard) the request head, then write a Prometheus response.
async fn handle_conn(mut stream: TcpStream, metrics: &Metrics) -> std::io::Result<()> {
    // Drain the request head up to the blank line (or the byte cap). We do
    // not interpret it — any GET gets the same answer — but we must consume
    // enough that the peer's write completes and the socket is in a sane
    // state before we reply.
    let mut buf = [0u8; 1024];
    let mut total = 0usize;
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break; // client closed before finishing; reply anyway below.
        }
        total += n;
        // End-of-head marker or cap reached: stop reading.
        if total >= MAX_REQUEST_BYTES || contains_head_end(&buf[..n]) {
            break;
        }
    }

    let body = render_prometheus(&metrics.snapshot());
    let response = http_ok(&body);
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    // Best-effort clean close; ignore errors from an already-gone peer.
    let _ = stream.shutdown().await;
    Ok(())
}

/// Cheap check for the end-of-headers marker within the latest chunk. We only
/// look at the tail chunk, which is sufficient to terminate promptly on the
/// common single-read case; the byte cap bounds the pathological case.
fn contains_head_end(chunk: &[u8]) -> bool {
    chunk.windows(4).any(|w| w == b"\r\n\r\n") || chunk.windows(2).any(|w| w == b"\n\n")
}

/// Build a complete HTTP/1.1 `200 OK` response carrying `body`.
fn http_ok(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: {ct}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        ct = PROM_CONTENT_TYPE,
        len = body.len(),
        body = body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn snap_with(f: impl FnOnce(&Metrics)) -> MetricsSnapshot {
        let m = Metrics::new();
        f(&m);
        m.snapshot()
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
        let text = render_prometheus(&snap);

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
        let text = render_prometheus(&MetricsSnapshot::default());
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
    fn http_ok_sets_content_length_to_body_len() {
        let body = "hello metrics\n";
        let resp = http_ok(body);
        assert!(resp.contains(&format!("Content-Length: {}", body.len())));
        assert!(resp.contains("Content-Type: text/plain; version=0.0.4"));
        assert!(resp.ends_with(body));
    }

    #[test]
    fn head_end_detection() {
        assert!(contains_head_end(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(contains_head_end(b"GET / HTTP/1.1\n\n"));
        assert!(!contains_head_end(b"GET / HTTP/1.1\r\nHost: x\r\n"));
    }

    #[tokio::test]
    async fn end_to_end_scrape() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let metrics = Arc::new(Metrics::new());
        metrics.shares_accepted.fetch_add(5, Ordering::Relaxed);
        metrics.worker_connected();

        let m = metrics.clone();
        tokio::spawn(async move {
            let _ = serve_metrics_on(listener, m).await;
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
    }
}
