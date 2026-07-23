//! upstream — one dedicated node connection per downstream worker.
//!
//! This module owns the mechanism that normally makes every worker's search
//! space disjoint: it opens ONE upstream Stratum V1 TCP connection to the
//! node's `:3333` for each downstream worker. The node assigns an
//! `extranonce1` to every connection at `mining.subscribe` time (see the
//! node's `src/stratum/session.rs::handle_subscribe`), so workers normally
//! do not collide in nonce space. That extranonce1 is only 32 bits and is
//! NOT enforced unique by the node, so collisions are possible and the
//! router (not this module) guards against them. The proxy never rebuilds
//! templates and never
//! computes SHA-256d — it only replays the miner's opening handshake up to
//! the node and then observes the stream.
//!
//! Responsibilities:
//!   * dial + handshake replay (`configure?` then `subscribe`), capturing
//!     the node-assigned [`SubscribeResult`];
//!   * read + classify node lines into [`ServerMsg`] (never panics on
//!     malformed input — unclassifiable lines become `Passthrough` and are
//!     forwarded verbatim by the router);
//!   * forward raw miner lines (`authorize` / `submit` / …) up unchanged;
//!   * reconnect-with-exponential-backoff, re-replaying the handshake and
//!     surfacing the fresh `extranonce1` so the router can push a
//!     downstream `mining.set_extranonce`.
//!
//! Classification of the *node→proxy* stream lives here (this module's job
//! is to "read/classify node lines"); the sibling `codec` module owns the
//! *miner→proxy* classification and any shared framing helpers. To keep
//! this file independently compilable and self-contained, the small server
//! framer/classifier are implemented locally against the shared `types`
//! contract only.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::types::{
    error_codes, methods, Framed, HandshakeReplay, Job, Metrics, PoolError, ProxyConfig,
    ServerMsg, ShareOutcome, SubscribeResult, WorkerId, MAX_LINE_BYTES,
};

// ─────────────────────────────────────────────────────────────────────────
// Public connection type
// ─────────────────────────────────────────────────────────────────────────

/// One upstream Stratum connection dedicated to a single downstream worker.
///
/// After [`UpstreamConn::connect`] returns, the node has assigned this
/// worker its own `extranonce1` (exposed as [`UpstreamConn::extranonce1`]).
/// The router then loops on [`UpstreamConn::read`] to receive node lines
/// and calls [`UpstreamConn::write`] to forward miner lines up. On EOF the
/// router calls [`UpstreamConn::reconnect`].
pub struct UpstreamConn {
    /// The worker this connection belongs to (stable for its lifetime).
    pub worker: WorkerId,
    /// Node-assigned extranonce1 (hex) for THIS connection — the proof the
    /// worker is on a disjoint search space. Updated on every reconnect.
    pub extranonce1: String,
    /// extranonce2 size in bytes the node expects (node returns 4).
    pub extranonce2_size: usize,

    /// Buffered lines observed during the initial handshake (including the
    /// subscribe result). Drained first by `read` so the router can forward
    /// the node's subscribe response downstream verbatim. Empty after
    /// reconnect (the miner already subscribed once; the router uses
    /// `mining.set_extranonce` instead).
    prelude: VecDeque<Framed<ServerMsg>>,

    framer: LineFramer<OwnedReadHalf>,
    writer: OwnedWriteHalf,

    cfg: Arc<ProxyConfig>,
    metrics: Arc<Metrics>,

    /// Current reconnect backoff (grows min..max across failed dials).
    backoff: Duration,
}

/// Internal bundle returned by a successful dial + handshake.
struct Established {
    framer: LineFramer<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    sub: SubscribeResult,
    prelude: VecDeque<Framed<ServerMsg>>,
}

impl UpstreamConn {
    /// Dial `cfg.upstream_addr` (TCP_NODELAY, `cfg.connect_timeout`), replay
    /// the handshake (`configure?` then `subscribe`), block until the node's
    /// `SubscribeResult`, and return a ready connection. Bumps
    /// `upstream_connect_failures` on dial failure.
    pub async fn connect(
        cfg: Arc<ProxyConfig>,
        metrics: Arc<Metrics>,
        worker: WorkerId,
        replay: HandshakeReplay,
    ) -> Result<Self, PoolError> {
        let est = establish(&cfg, &metrics, &replay).await?;
        let backoff = cfg.reconnect_backoff_min;
        Ok(Self {
            worker,
            extranonce1: est.sub.extranonce1,
            extranonce2_size: est.sub.extranonce2_size,
            prelude: est.prelude,
            framer: est.framer,
            writer: est.writer,
            cfg,
            metrics,
            backoff,
        })
    }

    /// Read + classify the next node line. Returns `None` on EOF (the router
    /// then calls [`UpstreamConn::reconnect`]). Handshake lines buffered at
    /// connect time are yielded first, in order, so the router can forward
    /// the node's subscribe response downstream verbatim.
    pub async fn read(&mut self) -> Result<Option<Framed<ServerMsg>>, PoolError> {
        if let Some(framed) = self.prelude.pop_front() {
            return Ok(Some(framed));
        }
        match self.framer.next_line().await? {
            None => Ok(None),
            Some(line) => {
                // +1 approximates the stripped newline for byte accounting.
                self.metrics.add_bytes_down(line.len() as u64 + 1);
                Ok(Some(classify_server_line(line)))
            }
        }
    }

    /// Forward a raw miner line (authorize / submit / etc.) to the node
    /// verbatim. A trailing newline is ensured (added only if missing).
    /// Bumps `metrics.bytes_up`.
    pub async fn write(&mut self, line: &str) -> Result<(), PoolError> {
        write_line(&mut self.writer, line, &self.metrics).await
    }

    /// Re-dial with exponential backoff (`reconnect_backoff_min` ..
    /// `reconnect_backoff_max`) and re-replay `replay`, returning the fresh
    /// [`SubscribeResult`] so the router can emit a downstream
    /// `mining.set_extranonce`. Retries indefinitely on dial/handshake
    /// failure (each failure bumps `upstream_connect_failures` and grows the
    /// backoff); bumps `upstream_reconnects` once on success.
    ///
    /// Note: `replay` carries only `configure?`+`subscribe`, so after a
    /// reconnect the node connection is Subscribed but not Authorized —
    /// re-sending `mining.authorize` (via [`UpstreamConn::write`]) is the
    /// router's responsibility, matching the initial-connect flow where
    /// authorize travels through the live pump rather than the handshake.
    pub async fn reconnect(
        &mut self,
        replay: &HandshakeReplay,
    ) -> Result<SubscribeResult, PoolError> {
        self.backoff = self.cfg.reconnect_backoff_min;
        loop {
            match establish(&self.cfg, &self.metrics, replay).await {
                Ok(est) => {
                    self.framer = est.framer;
                    self.writer = est.writer;
                    // Do NOT re-forward the handshake responses downstream:
                    // the miner already subscribed. The router pushes
                    // set_extranonce from the returned SubscribeResult.
                    self.prelude = VecDeque::new();
                    self.extranonce1 = est.sub.extranonce1.clone();
                    self.extranonce2_size = est.sub.extranonce2_size;
                    self.metrics.upstream_reconnected();
                    return Ok(est.sub);
                }
                Err(e) => {
                    log::warn!(
                        "upstream {} reconnect attempt failed: {} (backoff {:?})",
                        self.worker,
                        e,
                        self.backoff
                    );
                    tokio::time::sleep(self.backoff).await;
                    // Grow, clamped to max; never below 1ms so a misconfigured
                    // zero floor can't spin.
                    let grown = self.backoff.max(Duration::from_millis(1)) * 2;
                    self.backoff = grown.min(self.cfg.reconnect_backoff_max);
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Dial + handshake
// ─────────────────────────────────────────────────────────────────────────

/// Dial the node, split the socket, replay the handshake and wait for the
/// subscribe result. Bumps `upstream_connect_failures` on any dial failure.
async fn establish(
    cfg: &Arc<ProxyConfig>,
    metrics: &Arc<Metrics>,
    replay: &HandshakeReplay,
) -> Result<Established, PoolError> {
    // TCP connect, bounded by cfg.connect_timeout.
    let stream = match timeout(cfg.connect_timeout, TcpStream::connect(&cfg.upstream_addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            metrics.upstream_connect_failed();
            return Err(PoolError::Io(e));
        }
        Err(_) => {
            metrics.upstream_connect_failed();
            return Err(PoolError::Timeout(format!(
                "connect to {} timed out after {:?}",
                cfg.upstream_addr, cfg.connect_timeout
            )));
        }
    };
    // Latency matters for share submission; ignore the (rare) set error.
    let _ = stream.set_nodelay(true);

    let (read_half, write_half) = stream.into_split();
    let mut framer = LineFramer::new(read_half);
    let mut writer = write_half;

    // Replay: configure (if the miner sent one) BEFORE subscribe.
    if let Some(configure) = replay.configure.as_deref() {
        write_line(&mut writer, configure, metrics).await?;
    }
    write_line(&mut writer, &replay.subscribe, metrics).await?;

    // Await the subscribe result, buffering everything seen along the way.
    let (sub, prelude) = match timeout(
        cfg.connect_timeout,
        await_subscribe(&mut framer, metrics),
    )
    .await
    {
        Ok(res) => res?,
        Err(_) => {
            return Err(PoolError::Timeout(
                "handshake timed out awaiting subscribe result".to_string(),
            ))
        }
    };

    Ok(Established {
        framer,
        writer,
        sub,
        prelude,
    })
}

/// Read node lines until the subscribe result arrives. Every line read is
/// classified and buffered (including the subscribe result itself) so the
/// caller can forward the node's responses downstream verbatim.
async fn await_subscribe(
    framer: &mut LineFramer<OwnedReadHalf>,
    metrics: &Arc<Metrics>,
) -> Result<(SubscribeResult, VecDeque<Framed<ServerMsg>>), PoolError> {
    let mut prelude: VecDeque<Framed<ServerMsg>> = VecDeque::new();
    loop {
        match framer.next_line().await? {
            None => {
                return Err(PoolError::UpstreamClosed(
                    "node closed connection during handshake".to_string(),
                ))
            }
            Some(line) => {
                metrics.add_bytes_down(line.len() as u64 + 1);
                let framed = classify_server_line(line);
                if let ServerMsg::SubscribeResult(sr) = &framed.parsed {
                    let sr = sr.clone();
                    prelude.push_back(framed);
                    return Ok((sr, prelude));
                }
                prelude.push_back(framed);
            }
        }
    }
}

/// Write one line to the upstream, ensuring exactly one trailing newline,
/// flushing, and accounting the bytes as `bytes_up`.
async fn write_line<W: AsyncWrite + Unpin>(
    w: &mut W,
    line: &str,
    metrics: &Arc<Metrics>,
) -> Result<(), PoolError> {
    let needs_newline = !line.ends_with('\n');
    w.write_all(line.as_bytes()).await?;
    let mut written = line.len();
    if needs_newline {
        w.write_all(b"\n").await?;
        written += 1;
    }
    w.flush().await?;
    metrics.add_bytes_up(written as u64);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// Line framing (newline-delimited, MAX_LINE_BYTES capped)
// ─────────────────────────────────────────────────────────────────────────

/// A newline-delimited line reader over any async source. Enforces
/// [`MAX_LINE_BYTES`]: a line that grows past the cap without a terminator
/// is a protocol violation (returns `PoolError::Protocol`) rather than an
/// unbounded allocation — untrusted network input must never OOM us.
struct LineFramer<R> {
    inner: R,
    /// Bytes read but not yet split into a complete line.
    buf: Vec<u8>,
    /// Scratch read buffer.
    tmp: Box<[u8; 8192]>,
}

impl<R: AsyncRead + Unpin> LineFramer<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(1024),
            tmp: Box::new([0u8; 8192]),
        }
    }

    /// Return the next complete line (without its trailing `\n`, and with a
    /// trailing `\r` stripped for CRLF tolerance), `None` on clean EOF, or a
    /// `Protocol` error if a single line exceeds [`MAX_LINE_BYTES`].
    async fn next_line(&mut self) -> Result<Option<String>, PoolError> {
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                let mut line: Vec<u8> = self.buf.drain(..=pos).collect();
                line.pop(); // drop the '\n'
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                // Lossy is safe: stratum is ASCII/JSON; classification is
                // tolerant and always falls back to Passthrough.
                return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
            }
            if self.buf.len() > MAX_LINE_BYTES {
                return Err(PoolError::Protocol(format!(
                    "upstream line exceeds {} byte limit",
                    MAX_LINE_BYTES
                )));
            }
            let n = self.inner.read(&mut self.tmp[..]).await?;
            if n == 0 {
                // Clean EOF. Any trailing partial (no newline) is discarded.
                return Ok(None);
            }
            self.buf.extend_from_slice(&self.tmp[..n]);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Server-line classification (node → proxy)
// ─────────────────────────────────────────────────────────────────────────

/// Classify one raw node line into a [`Framed<ServerMsg>`]. Never panics and
/// never errors on content: anything unrecognized becomes `Passthrough`,
/// keeping the proxy transparent (the `raw` bytes are what the router
/// forwards regardless of classification).
fn classify_server_line(raw: String) -> Framed<ServerMsg> {
    let parsed = parse_server(&raw);
    Framed { raw, parsed }
}

fn parse_server(raw: &str) -> ServerMsg {
    let value: Value = match serde_json::from_str(raw.trim()) {
        Ok(v) => v,
        Err(_) => return ServerMsg::Passthrough,
    };

    // Server-initiated notification: has a `method`.
    if let Some(method) = value.get("method").and_then(Value::as_str) {
        return parse_notification(method, &value);
    }

    // Response to something we forwarded: has an `id`, no `method`.
    if value.get("id").is_some() {
        return parse_response(&value);
    }

    ServerMsg::Passthrough
}

fn parse_notification(method: &str, value: &Value) -> ServerMsg {
    let params = value.get("params");
    match method {
        methods::NOTIFY => {
            let arr = match params.and_then(Value::as_array) {
                Some(a) => a,
                None => return ServerMsg::Passthrough,
            };
            let job_id = match arr.first().and_then(Value::as_str) {
                Some(s) => s.to_string(),
                None => return ServerMsg::Passthrough,
            };
            // notify params[8] == clean_jobs.
            let clean_jobs = arr.get(8).and_then(Value::as_bool).unwrap_or(false);
            ServerMsg::Notify(Job {
                job_id,
                clean_jobs,
                received_at: Instant::now(),
            })
        }
        methods::SET_DIFFICULTY => {
            match params
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(Value::as_f64)
            {
                Some(d) => ServerMsg::SetDifficulty(d),
                None => ServerMsg::Passthrough,
            }
        }
        methods::SET_EXTRANONCE => {
            let arr = match params.and_then(Value::as_array) {
                Some(a) => a,
                None => return ServerMsg::Passthrough,
            };
            let extranonce1 = match arr.first().and_then(Value::as_str) {
                Some(s) => s.to_string(),
                None => return ServerMsg::Passthrough,
            };
            let extranonce2_size = arr.get(1).and_then(Value::as_u64).unwrap_or(4) as usize;
            ServerMsg::SetExtranonce {
                extranonce1,
                extranonce2_size,
            }
        }
        _ => ServerMsg::Passthrough,
    }
}

fn parse_response(value: &Value) -> ServerMsg {
    let id = value.get("id").cloned();

    // Error responses: `error` is `[code, "msg", null]`.
    if let Some(arr) = value.get("error").and_then(Value::as_array) {
        if !arr.is_empty() {
            let code = arr.first().and_then(Value::as_i64).unwrap_or(error_codes::OTHER);
            let message = arr
                .get(1)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            return ServerMsg::SubmitResult {
                id,
                outcome: ShareOutcome::from_error_code(code, message),
            };
        }
    }

    match value.get("result") {
        // A subscribe result: [subscriptions, extranonce1_hex, extranonce2_size].
        Some(Value::Array(arr)) => match parse_subscribe_result(arr) {
            Some(sr) => ServerMsg::SubscribeResult(sr),
            None => ServerMsg::Passthrough,
        },
        // A boolean ack. NOTE: `mining.authorize` also returns `true`; the
        // router disambiguates by matching `id` against its pending-submit
        // set, and forwards `raw` verbatim either way, so treating a bare
        // boolean ack as a share outcome here is harmless.
        Some(Value::Bool(accepted)) => {
            let outcome = if *accepted {
                ShareOutcome::Accepted
            } else {
                ShareOutcome::Rejected {
                    code: error_codes::OTHER,
                    message: "rejected".to_string(),
                }
            };
            ServerMsg::SubmitResult { id, outcome }
        }
        _ => ServerMsg::Passthrough,
    }
}

/// Parse `[subscriptions, extranonce1_hex, extranonce2_size]`. Returns
/// `None` (→ Passthrough) if the shape doesn't match, so a non-subscribe
/// array result is never mistaken for one.
fn parse_subscribe_result(arr: &[Value]) -> Option<SubscribeResult> {
    let extranonce1 = arr.get(1)?.as_str()?.to_string();
    if extranonce1.is_empty() {
        return None;
    }
    let extranonce2_size = arr.get(2)?.as_u64()? as usize;
    Some(SubscribeResult {
        extranonce1,
        extranonce2_size,
    })
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn test_cfg(upstream_addr: String) -> Arc<ProxyConfig> {
        Arc::new(ProxyConfig {
            upstream_addr,
            connect_timeout: Duration::from_secs(2),
            reconnect_backoff_min: Duration::from_millis(1),
            reconnect_backoff_max: Duration::from_millis(20),
            ..ProxyConfig::default()
        })
    }

    // ── classification ────────────────────────────────────────────────

    #[test]
    fn classifies_subscribe_result() {
        let line = r#"{"id":1,"result":[[["mining.set_difficulty","deadbeef"],["mining.notify","deadbeef"]],"deadbeef",4],"error":null}"#;
        match parse_server(line) {
            ServerMsg::SubscribeResult(sr) => {
                assert_eq!(sr.extranonce1, "deadbeef");
                assert_eq!(sr.extranonce2_size, 4);
            }
            other => panic!("expected SubscribeResult, got {:?}", other),
        }
    }

    #[test]
    fn classifies_notify_with_clean_jobs() {
        let line = r#"{"id":null,"method":"mining.notify","params":["job42","ph","c1","c2",[],"20000000","1a2b3c4d","5f5e100",true]}"#;
        match parse_server(line) {
            ServerMsg::Notify(job) => {
                assert_eq!(job.job_id, "job42");
                assert!(job.clean_jobs);
            }
            other => panic!("expected Notify, got {:?}", other),
        }
    }

    #[test]
    fn notify_defaults_clean_jobs_false_when_absent() {
        let line = r#"{"id":null,"method":"mining.notify","params":["j","ph","c1","c2",[],"20000000","1a2b3c4d","5f5e100"]}"#;
        match parse_server(line) {
            ServerMsg::Notify(job) => assert!(!job.clean_jobs),
            other => panic!("expected Notify, got {:?}", other),
        }
    }

    #[test]
    fn classifies_set_difficulty() {
        let line = r#"{"id":null,"method":"mining.set_difficulty","params":[1024.0]}"#;
        match parse_server(line) {
            ServerMsg::SetDifficulty(d) => assert!((d - 1024.0).abs() < f64::EPSILON),
            other => panic!("expected SetDifficulty, got {:?}", other),
        }
    }

    #[test]
    fn classifies_set_extranonce() {
        let line = r#"{"id":null,"method":"mining.set_extranonce","params":["cafebabe",4]}"#;
        match parse_server(line) {
            ServerMsg::SetExtranonce {
                extranonce1,
                extranonce2_size,
            } => {
                assert_eq!(extranonce1, "cafebabe");
                assert_eq!(extranonce2_size, 4);
            }
            other => panic!("expected SetExtranonce, got {:?}", other),
        }
    }

    #[test]
    fn classifies_accepted_submit() {
        let line = r#"{"id":7,"result":true,"error":null}"#;
        match parse_server(line) {
            ServerMsg::SubmitResult { id, outcome } => {
                assert_eq!(id, Some(Value::from(7)));
                assert_eq!(outcome, ShareOutcome::Accepted);
            }
            other => panic!("expected SubmitResult, got {:?}", other),
        }
    }

    #[test]
    fn classifies_error_outcomes() {
        let cases = [
            (r#"{"id":8,"result":null,"error":[21,"stale",null]}"#, ShareOutcome::Stale),
            (r#"{"id":9,"result":null,"error":[22,"dup",null]}"#, ShareOutcome::Duplicate),
            (r#"{"id":10,"result":null,"error":[23,"low",null]}"#, ShareOutcome::LowDifficulty),
        ];
        for (line, want) in cases {
            match parse_server(line) {
                ServerMsg::SubmitResult { outcome, .. } => assert_eq!(outcome, want),
                other => panic!("expected SubmitResult for {line}, got {:?}", other),
            }
        }
    }

    #[test]
    fn generic_rejection_carries_code_and_message() {
        let line = r#"{"id":11,"result":null,"error":[20,"nope",null]}"#;
        match parse_server(line) {
            ServerMsg::SubmitResult { outcome, .. } => match outcome {
                ShareOutcome::Rejected { code, message } => {
                    assert_eq!(code, 20);
                    assert_eq!(message, "nope");
                }
                other => panic!("expected Rejected, got {:?}", other),
            },
            other => panic!("expected SubmitResult, got {:?}", other),
        }
    }

    #[test]
    fn unclassifiable_and_malformed_become_passthrough() {
        assert!(matches!(parse_server("not json at all"), ServerMsg::Passthrough));
        assert!(matches!(parse_server("{}"), ServerMsg::Passthrough));
        // An array result that isn't a subscribe result.
        assert!(matches!(
            parse_server(r#"{"id":1,"result":[1,2,3],"error":null}"#),
            ServerMsg::Passthrough
        ));
    }

    // ── line framer ──────────────────────────────────────────────────

    #[tokio::test]
    async fn framer_splits_lines_and_strips_crlf() {
        let (mut a, b) = tokio::io::duplex(4096);
        a.write_all(b"line one\r\nline two\n").await.unwrap();
        drop(a); // EOF after the two lines
        let mut framer = LineFramer::new(b);
        assert_eq!(framer.next_line().await.unwrap().as_deref(), Some("line one"));
        assert_eq!(framer.next_line().await.unwrap().as_deref(), Some("line two"));
        assert_eq!(framer.next_line().await.unwrap(), None);
    }

    #[tokio::test]
    async fn framer_handles_line_split_across_reads() {
        let (mut a, b) = tokio::io::duplex(4096);
        let mut framer = LineFramer::new(b);
        a.write_all(b"par").await.unwrap();
        a.write_all(b"tial line\n").await.unwrap();
        drop(a);
        assert_eq!(
            framer.next_line().await.unwrap().as_deref(),
            Some("partial line")
        );
        assert_eq!(framer.next_line().await.unwrap(), None);
    }

    #[tokio::test]
    async fn framer_rejects_oversize_line() {
        let (mut a, b) = tokio::io::duplex(MAX_LINE_BYTES * 4);
        // No newline, well over the cap.
        let giant = vec![b'x'; MAX_LINE_BYTES * 2];
        a.write_all(&giant).await.unwrap();
        let mut framer = LineFramer::new(b);
        match framer.next_line().await {
            Err(PoolError::Protocol(_)) => {}
            other => panic!("expected Protocol error, got {:?}", other),
        }
    }

    // ── connect / read / reconnect against a mock node ───────────────

    /// Minimal mock node: for each expected connection, read until it sees a
    /// `mining.subscribe`, reply with a subscribe result carrying the given
    /// extranonce1, then push one `mining.notify`. Sockets are kept alive
    /// until the task ends so the client can drain buffered bytes.
    async fn spawn_mock_node(extranonces: Vec<&'static str>) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = tokio::spawn(async move {
            let mut keep = Vec::new();
            for en1 in extranonces {
                let (mut sock, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                let mut acc = String::new();
                let mut buf = [0u8; 1024];
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if acc.contains("mining.subscribe") {
                        break;
                    }
                }
                let result = format!(
                    "{{\"id\":1,\"result\":[[[\"mining.set_difficulty\",\"{en1}\"],[\"mining.notify\",\"{en1}\"]],\"{en1}\",4],\"error\":null}}\n"
                );
                let _ = sock.write_all(result.as_bytes()).await;
                let notify = "{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"job1\",\"ph\",\"c1\",\"c2\",[],\"20000000\",\"1a2b3c4d\",\"5f5e100\",true]}\n";
                let _ = sock.write_all(notify.as_bytes()).await;
                let _ = sock.flush().await;
                keep.push(sock);
            }
            // Hold connections briefly so the client can drain.
            tokio::time::sleep(Duration::from_millis(200)).await;
            drop(keep);
        });
        (addr, handle)
    }

    fn subscribe_replay() -> HandshakeReplay {
        HandshakeReplay {
            configure: None,
            subscribe: r#"{"id":1,"method":"mining.subscribe","params":["test-miner/1.0"]}"#.to_string(),
        }
    }

    #[tokio::test]
    async fn connect_captures_extranonce_and_forwards_prelude() {
        let (addr, _mock) = spawn_mock_node(vec!["deadbeef"]).await;
        let cfg = test_cfg(addr);
        let metrics = Arc::new(Metrics::new());

        let mut conn = UpstreamConn::connect(cfg, metrics.clone(), WorkerId(1), subscribe_replay())
            .await
            .expect("connect should succeed");

        assert_eq!(conn.extranonce1, "deadbeef");
        assert_eq!(conn.extranonce2_size, 4);

        // First read drains the buffered subscribe result (forwarded downstream).
        match conn.read().await.unwrap() {
            Some(f) => assert!(matches!(f.parsed, ServerMsg::SubscribeResult(_))),
            None => panic!("expected buffered subscribe result"),
        }
        // Then the live notify.
        match conn.read().await.unwrap() {
            Some(f) => match f.parsed {
                ServerMsg::Notify(job) => assert_eq!(job.job_id, "job1"),
                other => panic!("expected Notify, got {:?}", other),
            },
            None => panic!("expected notify"),
        }
        assert!(metrics.snapshot().bytes_up > 0);
    }

    #[tokio::test]
    async fn write_forwards_and_accounts_bytes() {
        let (addr, _mock) = spawn_mock_node(vec!["deadbeef"]).await;
        let cfg = test_cfg(addr);
        let metrics = Arc::new(Metrics::new());
        let mut conn = UpstreamConn::connect(cfg, metrics.clone(), WorkerId(2), subscribe_replay())
            .await
            .unwrap();

        let before = metrics.snapshot().bytes_up;
        conn.write(r#"{"id":2,"method":"mining.authorize","params":["addr","x"]}"#)
            .await
            .unwrap();
        assert!(metrics.snapshot().bytes_up > before);
    }

    #[tokio::test]
    async fn reconnect_returns_fresh_extranonce() {
        let (addr, _mock) = spawn_mock_node(vec!["deadbeef", "cafebabe"]).await;
        let cfg = test_cfg(addr);
        let metrics = Arc::new(Metrics::new());
        let mut conn = UpstreamConn::connect(cfg, metrics.clone(), WorkerId(3), subscribe_replay())
            .await
            .unwrap();
        assert_eq!(conn.extranonce1, "deadbeef");

        let replay = subscribe_replay();
        let sr = conn.reconnect(&replay).await.expect("reconnect should succeed");
        assert_eq!(sr.extranonce1, "cafebabe");
        assert_eq!(conn.extranonce1, "cafebabe");
        assert_eq!(metrics.snapshot().upstream_reconnects, 1);
    }

    #[tokio::test]
    async fn connect_dial_failure_bumps_metric() {
        // Nothing listening on this port.
        let cfg = test_cfg("127.0.0.1:1".to_string());
        let metrics = Arc::new(Metrics::new());
        let res =
            UpstreamConn::connect(cfg, metrics.clone(), WorkerId(4), subscribe_replay()).await;
        assert!(res.is_err());
        assert!(metrics.snapshot().upstream_connect_failures >= 1);
    }
}
