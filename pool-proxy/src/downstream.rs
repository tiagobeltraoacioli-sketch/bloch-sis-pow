//! Module `downstream` — the miner-facing side of the smart Stratum proxy.
//!
//! Owns the accepted downstream `TcpStream` (split into owned halves) for
//! ONE worker. It:
//!
//!   * reads + classifies inbound miner lines (via `crate::codec`),
//!     stamping every `mining.submit` with this worker's id and the
//!     difficulty last advertised to it (shares carry no difficulty on the
//!     wire — the pool derives it from session state);
//!   * writes node lines back to the miner verbatim, accounting bytes and
//!     refreshing the keepalive idle timer;
//!   * caches per-worker session state — current difficulty, the last
//!     `mining.notify` (both parsed metadata and the raw line), and the
//!     descriptive `WorkerInfo` — as the handshake progresses;
//!   * re-feeds the last job after `keepalive_idle` of downstream silence,
//!     exactly like the reference python proxy, so idle ASICs don't drop;
//!   * houses the `VardiffController`, which in the Sprint-1 MVP is a
//!     transparent pass-through (the node's own per-connection
//!     `set_difficulty` flows through untouched) and whose override path is
//!     wired but inert behind `cfg.vardiff_override`.
//!
//! This module reimplements NO PoW and rebuilds NO templates. It only
//! observes the byte stream. Correctness of the disjoint search space is a
//! property of the one-upstream-per-worker architecture, not of anything
//! done here.
//!
//! Everything shared with the other four modules comes from `crate::types`
//! (the interface contract) and the line classifier from `crate::codec`.
//! The single point of coupling to the codec is [`classify_client`], which
//! is expected to expose:
//!
//! ```ignore
//! pub fn classify_client(raw: &str) -> Result<Framed<ClientMsg>, PoolError>;
//! ```
//!
//! It returns the untouched `raw` line alongside a `parsed` classification.
//! For a `mining.submit` the codec fills placeholder identity/difficulty on
//! the `Share`; this module overwrites both from authoritative session
//! state before the router ever sees the share.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

use crate::types::{
    ClientMsg, Framed, Job, Metrics, PoolError, ProxyConfig, ServerMsg, WorkerId, WorkerInfo,
    MAX_LINE_BYTES,
};

// ─────────────────────────────────────────────────────────────────────────
// DownstreamConn
// ─────────────────────────────────────────────────────────────────────────

/// One accepted miner connection and all per-worker session state derived
/// from observing its stream.
pub struct DownstreamConn {
    /// Monotonic worker id assigned by the accept loop (module 5).
    pub worker: WorkerId,
    /// Slowly-changing descriptive facts, filled as the handshake proceeds.
    pub info: WorkerInfo,

    /// Miner → proxy half, buffered for line framing.
    reader: BufReader<OwnedReadHalf>,
    /// Proxy → miner half.
    writer: OwnedWriteHalf,

    cfg: Arc<ProxyConfig>,
    metrics: Arc<Metrics>,

    /// Difficulty last advertised to this worker (last `set_difficulty`
    /// observed for it). Stamped onto every outgoing `Share`.
    current_difficulty: f64,
    /// Last parsed job, kept for metadata (clean_jobs / age).
    last_job: Option<Job>,
    /// Raw last `mining.notify` line (newline-terminated) for keepalive
    /// re-feed — mirrors the reference python proxy's `last_notify`.
    last_notify_raw: Option<String>,
    /// Wall-clock of the last byte written downstream; the keepalive timer
    /// measures silence from here.
    last_down_send: Instant,

    /// Partial-line accumulator, retained ACROSS `read` calls. The router
    /// polls `read()` inside a `tokio::select!`, so the read future can be
    /// dropped mid-line (another branch fired); keeping the already-consumed
    /// bytes here — rather than in a local — means a cancelled read loses
    /// nothing and the stream never desyncs.
    partial: Vec<u8>,

    /// Proxy-side vardiff. Inert pass-through in the Sprint-1 MVP.
    vardiff: VardiffController,
}

impl DownstreamConn {
    /// Wrap a freshly-accepted miner stream. Sets `TCP_NODELAY` (stratum is
    /// latency-sensitive, tiny JSON lines) and records the peer address.
    /// Worker-lifecycle metrics (`worker_connected`/`worker_disconnected`)
    /// are owned by the accept loop, not this constructor, to avoid double
    /// counting.
    pub fn new(
        stream: TcpStream,
        worker: WorkerId,
        cfg: Arc<ProxyConfig>,
        metrics: Arc<Metrics>,
    ) -> Self {
        // Best-effort: a failure to set NODELAY is not fatal to the session.
        let _ = stream.set_nodelay(true);
        let peer = stream.peer_addr().ok().map(|a| a.to_string());

        let (rd, wr) = stream.into_split();
        let vardiff = VardiffController::new(&cfg);

        let info = WorkerInfo {
            peer,
            ..WorkerInfo::default()
        };

        Self {
            worker,
            info,
            reader: BufReader::new(rd),
            writer: wr,
            cfg,
            metrics,
            current_difficulty: 0.0,
            last_job: None,
            last_notify_raw: None,
            last_down_send: Instant::now(),
            partial: Vec::with_capacity(256),
            vardiff,
        }
    }

    /// Read and classify the next miner line. `Ok(None)` on clean EOF.
    ///
    /// On a `Submit`, the share's `worker` and `difficulty` are stamped
    /// from authoritative session state (the wire carries neither). Opening
    /// handshake facts (`authorized_user`, `user_agent`) are folded into
    /// `self.info` as they arrive. Never panics on hostile input: an
    /// oversized line, invalid UTF-8, or malformed JSON returns a
    /// `PoolError::Protocol` instead.
    pub async fn read(&mut self) -> Result<Option<Framed<ClientMsg>>, PoolError> {
        let raw = match self.read_line_bounded().await? {
            Some(line) => line,
            None => return Ok(None),
        };

        let mut framed = classify_client(&raw, self.worker)?;

        match &mut framed.parsed {
            ClientMsg::Submit(share) => {
                // The wire has no worker or difficulty field for a submit;
                // both come from what THIS session knows.
                share.worker = self.worker;
                share.difficulty = self.current_difficulty;
            }
            ClientMsg::Authorize { user, .. } => {
                self.info.authorized_user = Some(user.clone());
            }
            ClientMsg::Subscribe { params, .. } => {
                if self.info.user_agent.is_none() {
                    if let Some(ua) = params.get(0).and_then(|v| v.as_str()) {
                        if !ua.is_empty() {
                            self.info.user_agent = Some(ua.to_string());
                        }
                    }
                }
            }
            _ => {}
        }

        Ok(Some(framed))
    }

    /// Write a raw node line to the miner verbatim. Ensures a single
    /// trailing newline (stratum is newline-delimited), bumps
    /// `metrics.bytes_down`, refreshes the keepalive idle timer, and — like
    /// the reference proxy — snapshots the line if it is a `mining.notify`
    /// so keepalive can re-feed it.
    pub async fn write(&mut self, line: &str) -> Result<(), PoolError> {
        let bytes = line.as_bytes();
        let already_terminated = bytes.last() == Some(&b'\n');

        self.writer.write_all(bytes).await?;
        let mut written = bytes.len();
        if !already_terminated {
            self.writer.write_all(b"\n").await?;
            written += 1;
        }
        self.writer.flush().await?;

        self.metrics.add_bytes_down(written as u64);
        self.last_down_send = Instant::now();

        // Cheap substring gate identical to the reference python proxy.
        // Cache the newline-terminated form so keepalive re-sends it as-is.
        if line.contains(crate::types::methods::NOTIFY) {
            let stored = if already_terminated {
                line.to_string()
            } else {
                let mut s = String::with_capacity(line.len() + 1);
                s.push_str(line);
                s.push('\n');
                s
            };
            self.last_notify_raw = Some(stored);
        }

        Ok(())
    }

    /// Fold an upstream (node→proxy) message into cached session state so
    /// keepalive and vardiff have what they need. Called by the router for
    /// every classified `ServerMsg`; forwarding of the raw line still goes
    /// through [`write`](Self::write).
    pub fn observe_server(&mut self, msg: &ServerMsg) {
        match msg {
            ServerMsg::SetDifficulty(d) => {
                self.current_difficulty = *d;
                self.vardiff.observe_difficulty(*d);
            }
            ServerMsg::Notify(job) => {
                self.last_job = Some(job.clone());
            }
            ServerMsg::SubscribeResult(res) => {
                self.info.extranonce1 = Some(res.extranonce1.clone());
            }
            ServerMsg::SetExtranonce { extranonce1, .. } => {
                self.info.extranonce1 = Some(extranonce1.clone());
            }
            ServerMsg::SubmitResult { .. } | ServerMsg::Passthrough => {}
        }
    }

    /// Re-feed the last `mining.notify` if nothing has been written
    /// downstream for at least `cfg.keepalive_idle`. No-op if no job has
    /// been seen yet or the connection is not idle. Meant to be polled from
    /// the router's `select!` loop.
    pub async fn keepalive_tick(&mut self) -> Result<(), PoolError> {
        if self.last_down_send.elapsed() < self.cfg.keepalive_idle {
            return Ok(());
        }
        // Clone out before the mutable `write` borrow.
        let notify = match &self.last_notify_raw {
            Some(n) => n.clone(),
            None => return Ok(()),
        };
        self.write(&notify).await
    }

    /// Difficulty last advertised to this worker.
    pub fn current_difficulty(&self) -> f64 {
        self.current_difficulty
    }

    /// Most recently cached job (metadata only).
    pub fn last_job(&self) -> Option<&Job> {
        self.last_job.as_ref()
    }

    // ── internals ────────────────────────────────────────────────────

    /// Read one newline-delimited line with a hard `MAX_LINE_BYTES` cap,
    /// without ever unbounded-buffering a peer that never sends `\n`.
    /// Returns `Ok(None)` on clean EOF, the line (sans trailing `\r?\n`) on
    /// success, or `PoolError::Protocol` on overflow / invalid UTF-8.
    async fn read_line_bounded(&mut self) -> Result<Option<String>, PoolError> {
        // Accumulate into `self.partial`, NOT a local, so a cancelled read
        // future (the router polls this inside `select!`) retains every byte
        // it already consumed from the BufReader.
        loop {
            let available = self.reader.fill_buf().await?;
            if available.is_empty() {
                // EOF. A trailing line without a newline is still delivered
                // once; a clean close with nothing buffered is `None`.
                if self.partial.is_empty() {
                    return Ok(None);
                }
                let line = std::mem::take(&mut self.partial);
                return finish_line(line);
            }

            if let Some(pos) = available.iter().position(|&b| b == b'\n') {
                self.partial.extend_from_slice(&available[..pos]);
                let consumed = pos + 1; // include the delimiter
                self.reader.consume(consumed);
                if self.partial.len() > MAX_LINE_BYTES {
                    return Err(PoolError::Protocol(format!(
                        "downstream line exceeds {} bytes",
                        MAX_LINE_BYTES
                    )));
                }
                let line = std::mem::take(&mut self.partial);
                return finish_line(line);
            } else {
                let n = available.len();
                self.partial.extend_from_slice(available);
                self.reader.consume(n);
            }

            if self.partial.len() > MAX_LINE_BYTES {
                return Err(PoolError::Protocol(format!(
                    "downstream line exceeds {} bytes",
                    MAX_LINE_BYTES
                )));
            }
        }
    }
}

/// Thin wrapper over the codec's client-line classifier — the single point
/// of coupling to `crate::codec`. Isolated here so a rename in the codec is
/// a one-line change in this module.
#[inline]
fn classify_client(raw: &str, worker: WorkerId) -> Result<Framed<ClientMsg>, PoolError> {
    crate::codec::classify_client(raw, worker)
}

/// Finalize a fully-accumulated line: strip a trailing `\r` (CRLF tolerance)
/// and validate UTF-8.
fn finish_line(mut line: Vec<u8>) -> Result<Option<String>, PoolError> {
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    match String::from_utf8(line) {
        Ok(s) => Ok(Some(s)),
        Err(_) => Err(PoolError::Protocol(
            "downstream line is not valid UTF-8".to_string(),
        )),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// VardiffController
// ─────────────────────────────────────────────────────────────────────────

/// Sliding window of accepted-share timestamps used to retarget difficulty.
const VARDIFF_WINDOW: usize = 8;
/// Only retarget when the observed share interval is outside this band
/// around the target, to avoid thrashing.
const VARDIFF_LOW_TOLERANCE: f64 = 0.75;
const VARDIFF_HIGH_TOLERANCE: f64 = 1.33;
/// Clamp any single retarget step to this multiplicative range.
const VARDIFF_STEP_MIN: f64 = 0.25;
const VARDIFF_STEP_MAX: f64 = 4.0;
/// Never suggest a non-positive difficulty.
const VARDIFF_MIN_DIFF: f64 = 0.001;

/// Per-connection variable-difficulty controller.
///
/// Sprint-1 MVP: a transparent pass-through. When `cfg.vardiff_override`
/// is `false` (the default), [`suggested_difficulty`](Self::suggested_difficulty)
/// always returns `None` and the router simply forwards the node's own
/// `set_difficulty` values. The override machinery below is fully wired but
/// inert until an operator opts in, at which point it steers each worker's
/// difficulty toward `cfg.vardiff_target_secs` seconds per share.
pub struct VardiffController {
    enabled: bool,
    target_secs: f64,
    window: usize,
    /// Baseline / last-controlled difficulty. Seeded from the first
    /// node-advertised difficulty so a retarget scales a real value.
    current: f64,
    /// Timestamps of the most recent accepted shares (bounded to `window`).
    samples: VecDeque<Instant>,
}

impl VardiffController {
    pub fn new(cfg: &ProxyConfig) -> Self {
        Self {
            enabled: cfg.vardiff_override,
            target_secs: cfg.vardiff_target_secs,
            window: VARDIFF_WINDOW,
            current: 0.0,
            samples: VecDeque::with_capacity(VARDIFF_WINDOW),
        }
    }

    /// Record an accepted share. No-op unless the override is enabled.
    pub fn observe_accepted_share(&mut self, at: Instant) {
        if !self.enabled {
            return;
        }
        if self.samples.len() == self.window {
            self.samples.pop_front();
        }
        self.samples.push_back(at);
    }

    /// Seed / track the node-advertised difficulty as the baseline to scale
    /// from. Seeds once; later node changes are absorbed as the new
    /// baseline only while the controller has not produced its own value.
    /// (Beyond the three contract methods; used internally by
    /// `DownstreamConn::observe_server`.)
    pub fn observe_difficulty(&mut self, d: f64) {
        if self.current <= 0.0 && d > 0.0 {
            self.current = d;
        }
    }

    /// `Some(new_diff)` only when the override is enabled AND a retarget is
    /// due; `None` in the MVP pass-through, or when there is not yet enough
    /// data. On a retarget the window is cleared and `current` advances.
    pub fn suggested_difficulty(&mut self) -> Option<f64> {
        if !self.enabled || self.current <= 0.0 || self.samples.len() < self.window {
            return None;
        }

        let first = *self.samples.front()?;
        let last = *self.samples.back()?;
        let span = last.saturating_duration_since(first).as_secs_f64();
        let intervals = (self.samples.len() - 1) as f64;
        if span <= 0.0 || intervals <= 0.0 {
            return None;
        }
        let avg = span / intervals;

        let low = self.target_secs * VARDIFF_LOW_TOLERANCE;
        let high = self.target_secs * VARDIFF_HIGH_TOLERANCE;
        if avg >= low && avg <= high {
            // Comfortably on target — leave difficulty alone.
            return None;
        }

        // Shares too fast (avg < target) → raise difficulty (factor > 1).
        // Shares too slow (avg > target) → lower difficulty (factor < 1).
        let factor = (self.target_secs / avg).clamp(VARDIFF_STEP_MIN, VARDIFF_STEP_MAX);
        let next = (self.current * factor).max(VARDIFF_MIN_DIFF);

        self.samples.clear();
        self.current = next;
        Some(next)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // `super::*` already brings the `AsyncBufReadExt` / `AsyncWriteExt`
    // traits and tokio's `BufReader` into scope for the miner side.
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;

    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = TcpStream::connect(addr).await.expect("connect");
        let (server, _) = listener.accept().await.expect("accept");
        (server, client)
    }

    fn test_conn(server: TcpStream) -> DownstreamConn {
        let cfg = Arc::new(ProxyConfig::default());
        let metrics = Arc::new(Metrics::new());
        DownstreamConn::new(server, WorkerId(7), cfg, metrics)
    }

    fn test_conn_with(server: TcpStream, cfg: ProxyConfig) -> (DownstreamConn, Arc<Metrics>) {
        let metrics = Arc::new(Metrics::new());
        let conn = DownstreamConn::new(server, WorkerId(7), Arc::new(cfg), metrics.clone());
        (conn, metrics)
    }

    #[tokio::test]
    async fn reads_a_simple_line_without_terminator_bytes() {
        let (server, mut miner) = connected_pair().await;
        let mut conn = test_conn(server);

        miner.write_all(b"hello world\n").await.unwrap();
        miner.flush().await.unwrap();

        let line = conn.read_line_bounded().await.expect("ok");
        assert_eq!(line.as_deref(), Some("hello world"));
    }

    #[tokio::test]
    async fn strips_crlf() {
        let (server, mut miner) = connected_pair().await;
        let mut conn = test_conn(server);

        miner.write_all(b"crlf-line\r\n").await.unwrap();
        miner.flush().await.unwrap();

        let line = conn.read_line_bounded().await.expect("ok");
        assert_eq!(line.as_deref(), Some("crlf-line"));
    }

    #[tokio::test]
    async fn clean_eof_yields_none() {
        let (server, miner) = connected_pair().await;
        let mut conn = test_conn(server);

        drop(miner); // close the miner side
        let line = conn.read_line_bounded().await.expect("ok");
        assert_eq!(line, None);
    }

    #[tokio::test]
    async fn oversized_line_is_a_protocol_error() {
        let (server, mut miner) = connected_pair().await;
        let mut conn = test_conn(server);

        // No newline: force the bounded reader to trip its cap.
        let giant = vec![b'x'; MAX_LINE_BYTES + 64];
        miner.write_all(&giant).await.unwrap();
        miner.flush().await.unwrap();

        match conn.read_line_bounded().await {
            Err(PoolError::Protocol(_)) => {}
            other => panic!("expected protocol error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn write_appends_newline_and_counts_bytes() {
        let (server, miner) = connected_pair().await;
        let (mut conn, metrics) = test_conn_with(server, ProxyConfig::default());

        let before = conn.last_down_send;
        // Ensure the timestamp actually advances.
        tokio::time::sleep(Duration::from_millis(2)).await;

        conn.write("{\"id\":1,\"result\":true}").await.expect("write");

        let mut reader = BufReader::new(miner);
        let mut got = String::new();
        reader.read_line(&mut got).await.unwrap();
        assert_eq!(got, "{\"id\":1,\"result\":true}\n");

        // 22 payload bytes + 1 appended newline.
        assert_eq!(metrics.snapshot().bytes_down, 23);
        assert!(conn.last_down_send > before);
    }

    #[tokio::test]
    async fn write_does_not_double_terminate() {
        let (server, miner) = connected_pair().await;
        let (mut conn, metrics) = test_conn_with(server, ProxyConfig::default());

        conn.write("already\n").await.expect("write");

        let mut reader = BufReader::new(miner);
        let mut got = String::new();
        reader.read_line(&mut got).await.unwrap();
        assert_eq!(got, "already\n");
        assert_eq!(metrics.snapshot().bytes_down, 8);
    }

    #[tokio::test]
    async fn write_caches_raw_notify_for_keepalive() {
        let (server, _miner) = connected_pair().await;
        let mut conn = test_conn(server);

        assert!(conn.last_notify_raw.is_none());
        conn.write(r#"{"id":null,"method":"mining.notify","params":["job1"]}"#)
            .await
            .expect("write");
        assert!(conn.last_notify_raw.is_some());
        assert!(conn
            .last_notify_raw
            .as_ref()
            .unwrap()
            .ends_with("]}\n"));
    }

    #[tokio::test]
    async fn keepalive_refeeds_last_job_when_idle() {
        let mut cfg = ProxyConfig::default();
        cfg.keepalive_idle = Duration::from_millis(10);
        let (server, miner) = connected_pair().await;
        let (mut conn, _metrics) = test_conn_with(server, cfg);

        let notify = r#"{"id":null,"method":"mining.notify","params":["j"]}"#;
        conn.write(notify).await.expect("first notify");

        // Force the idle threshold to be exceeded.
        conn.last_down_send = Instant::now() - Duration::from_secs(1);
        conn.keepalive_tick().await.expect("keepalive");

        let mut reader = BufReader::new(miner);
        let mut first = String::new();
        let mut second = String::new();
        reader.read_line(&mut first).await.unwrap();
        reader.read_line(&mut second).await.unwrap();
        assert_eq!(first, format!("{}\n", notify));
        assert_eq!(second, format!("{}\n", notify)); // re-fed copy
    }

    #[tokio::test]
    async fn keepalive_is_noop_without_a_job() {
        let mut cfg = ProxyConfig::default();
        cfg.keepalive_idle = Duration::from_millis(1);
        let (server, _miner) = connected_pair().await;
        let (mut conn, metrics) = test_conn_with(server, cfg);

        conn.last_down_send = Instant::now() - Duration::from_secs(1);
        conn.keepalive_tick().await.expect("keepalive");
        assert_eq!(metrics.snapshot().bytes_down, 0);
    }

    #[tokio::test]
    async fn observe_server_caches_difficulty_and_job() {
        let (server, _miner) = connected_pair().await;
        let mut conn = test_conn(server);

        conn.observe_server(&ServerMsg::SetDifficulty(1024.0));
        assert_eq!(conn.current_difficulty(), 1024.0);

        let job = Job {
            job_id: "abc".to_string(),
            clean_jobs: true,
            received_at: Instant::now(),
        };
        conn.observe_server(&ServerMsg::Notify(job));
        assert_eq!(conn.last_job().map(|j| j.job_id.as_str()), Some("abc"));
        assert_eq!(conn.last_job().map(|j| j.clean_jobs), Some(true));
    }

    #[tokio::test]
    async fn observe_server_records_extranonce1() {
        use crate::types::SubscribeResult;
        let (server, _miner) = connected_pair().await;
        let mut conn = test_conn(server);

        conn.observe_server(&ServerMsg::SubscribeResult(SubscribeResult {
            extranonce1: "deadbeef".to_string(),
            extranonce2_size: 4,
        }));
        assert_eq!(conn.info.extranonce1.as_deref(), Some("deadbeef"));

        conn.observe_server(&ServerMsg::SetExtranonce {
            extranonce1: "cafebabe".to_string(),
            extranonce2_size: 4,
        });
        assert_eq!(conn.info.extranonce1.as_deref(), Some("cafebabe"));
    }

    #[test]
    fn vardiff_is_inert_in_mvp_passthrough() {
        let cfg = ProxyConfig::default(); // vardiff_override = false
        let mut vd = VardiffController::new(&cfg);
        vd.observe_difficulty(1000.0);
        let base = Instant::now();
        for i in 0..(VARDIFF_WINDOW as u32 + 4) {
            vd.observe_accepted_share(base + Duration::from_millis(500 * i as u64));
        }
        assert_eq!(vd.suggested_difficulty(), None);
    }

    #[test]
    fn vardiff_raises_difficulty_when_shares_are_too_fast() {
        let mut cfg = ProxyConfig::default();
        cfg.vardiff_override = true;
        cfg.vardiff_target_secs = 10.0;
        let mut vd = VardiffController::new(&cfg);
        vd.observe_difficulty(1000.0);

        // 8 shares 0.5s apart → avg 0.5s ≪ 10s target → raise difficulty.
        let base = Instant::now();
        for i in 0..VARDIFF_WINDOW as u32 {
            vd.observe_accepted_share(base + Duration::from_millis(500 * i as u64));
        }
        let suggested = vd.suggested_difficulty().expect("retarget due");
        assert!(suggested > 1000.0, "expected raise, got {}", suggested);
        // Step is clamped to 4x.
        assert!(suggested <= 4000.0 + f64::EPSILON);
    }

    #[test]
    fn vardiff_holds_when_on_target() {
        let mut cfg = ProxyConfig::default();
        cfg.vardiff_override = true;
        cfg.vardiff_target_secs = 10.0;
        let mut vd = VardiffController::new(&cfg);
        vd.observe_difficulty(1000.0);

        // 8 shares 10s apart → exactly on target → no change.
        let base = Instant::now();
        for i in 0..VARDIFF_WINDOW as u32 {
            vd.observe_accepted_share(base + Duration::from_secs(10 * i as u64));
        }
        assert_eq!(vd.suggested_difficulty(), None);
    }

    #[test]
    fn vardiff_needs_a_full_window() {
        let mut cfg = ProxyConfig::default();
        cfg.vardiff_override = true;
        let mut vd = VardiffController::new(&cfg);
        vd.observe_difficulty(1000.0);
        let base = Instant::now();
        vd.observe_accepted_share(base);
        vd.observe_accepted_share(base + Duration::from_millis(10));
        assert_eq!(vd.suggested_difficulty(), None);
    }
}
