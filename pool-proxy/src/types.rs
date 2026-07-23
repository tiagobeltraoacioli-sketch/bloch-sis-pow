#![allow(dead_code)]
//! Shared interface contract for the Bloch smart Stratum proxy / mini-pool.
//!
//! EVERY module in the crate codes against the types in THIS file and
//! nothing else of each other's internals. If it is exchanged between two
//! of the five modules, it lives here. Changing a signature here is the
//! only thing that forces cross-team coordination — treat it as the API.
//!
//! Sprint-1 architecture recap (why these types look the way they do):
//!
//! ```text
//!   miner/ASIC ── TCP :3335 ──▶ [downstream]      one dedicated
//!                                    │             UPSTREAM per worker
//!                                    ▼
//!                                 [router] ──▶ [upstream] ── TCP :3333 ──▶ node
//! ```
//!
//! The node assigns an `extranonce1` to every upstream TCP connection at
//! `mining.subscribe` time (see the node's
//! `src/stratum/session.rs::handle_subscribe`). Because the proxy opens
//! one upstream per downstream worker and forwards the node's subscribe
//! RESULT verbatim, each worker normally searches a disjoint extranonce
//! space — no nonce-space reimplementation, no SHA-256d in the proxy.
//!
//! IMPORTANT: this disjointness is NOT provable "by construction". The
//! node's extranonce1 is a 32-bit value with no uniqueness registry, so
//! two upstreams CAN be handed the same extranonce1 and then duplicate all
//! work. The proxy therefore keeps a live-extranonce1 collision guard (see
//! `router::ExtranonceRegistry`) that logs + counts a metric when a
//! collision is observed. The proxy only observes the stream for
//! accounting, vardiff, keepalive and metrics.

use std::fmt;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ─────────────────────────────────────────────────────────────────────────
// Identity
// ─────────────────────────────────────────────────────────────────────────

/// Monotonic per-process worker id. Assigned by the server accept-loop
/// (module 5) the instant a downstream TCP connection is accepted, and
/// carried through every `Share`, log line and metric label thereafter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WorkerId(pub u64);

impl fmt::Display for WorkerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "w{}", self.0)
    }
}

/// Slowly-changing descriptive facts about a worker, filled in as the
/// handshake progresses. Kept separate from `WorkerId` so the id stays a
/// cheap `Copy` key.
#[derive(Clone, Debug, Default)]
pub struct WorkerInfo {
    /// Downstream peer address (miner side), as `ip:port`.
    pub peer: Option<String>,
    /// The bech32 address the miner authorized with (node validates it).
    pub authorized_user: Option<String>,
    /// User-agent string from `mining.subscribe` params[0], if present.
    pub user_agent: Option<String>,
    /// Node-assigned extranonce1 for THIS worker's upstream connection.
    /// Normally distinct per worker (hence a disjoint search space), but
    /// NOT guaranteed unique by the node — the router cross-checks it
    /// against other live workers and counts collisions.
    pub extranonce1: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────
// Wire message types (Stratum V1, newline-delimited JSON-RPC)
// ─────────────────────────────────────────────────────────────────────────

/// One newline-terminated wire line. The proxy is transparent: the raw
/// bytes a party sent are forwarded UNCHANGED (`raw` on the classified
/// structs below); classification is purely observational.
pub type Line = String;

/// Hard cap on a single stratum line, matching the node
/// (`src/stratum/protocol.rs::MAX_LINE_BYTES`). A longer line is a
/// protocol violation and closes the session.
pub const MAX_LINE_BYTES: usize = 8 * 1024;

/// Raw request off the wire (client→server direction).
#[derive(Clone, Debug, Deserialize)]
pub struct RawRequest {
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// Raw response off the wire (server→client, carries the request `id`).
#[derive(Clone, Debug, Deserialize)]
pub struct RawResponse {
    #[serde(default)]
    pub id: Option<Value>,
    #[serde(default)]
    pub result: Value,
    #[serde(default)]
    pub error: Value,
}

/// Raw server-initiated notification (no id, e.g. `mining.notify`).
#[derive(Clone, Debug, Deserialize)]
pub struct RawNotification {
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// A classified line plus its untouched original bytes. `parsed` tells the
/// router what to DO; `raw` is what it FORWARDS. The two never diverge in
/// Sprint 1 (the proxy rewrites nothing on the wire).
#[derive(Clone, Debug)]
pub struct Framed<T> {
    pub raw: Line,
    pub parsed: T,
}

/// Classification of a downstream (miner→proxy) line. The codec produces
/// these; the router acts on them.
#[derive(Clone, Debug)]
pub enum ClientMsg {
    /// `mining.subscribe` — bootstraps this worker's dedicated upstream.
    Subscribe { id: Option<Value>, params: Value },
    /// `mining.configure` — must be replayed to the node BEFORE subscribe.
    Configure { id: Option<Value>, params: Value },
    /// `mining.authorize` — flows through the pump; node validates address.
    Authorize { id: Option<Value>, user: String, params: Value },
    /// `mining.submit` — the accounting-bearing message.
    Submit(Share),
    /// `mining.suggest_difficulty` / `suggest_target` — vardiff hint.
    SuggestDifficulty { id: Option<Value>, value: f64 },
    /// Anything else — forward verbatim, no special handling.
    Passthrough,
}

/// Classification of an upstream (node→proxy) line.
#[derive(Clone, Debug)]
pub enum ServerMsg {
    /// Result of `mining.subscribe`: carries the node-assigned extranonce1.
    SubscribeResult(SubscribeResult),
    /// `mining.notify` — a job. Cached for keepalive re-feed.
    Notify(Job),
    /// `mining.set_difficulty` — the node's per-connection vardiff value.
    SetDifficulty(f64),
    /// `mining.set_extranonce` — mid-session extranonce reassignment.
    SetExtranonce { extranonce1: String, extranonce2_size: usize },
    /// Result of a `mining.submit` we forwarded upstream, matched by `id`.
    SubmitResult { id: Option<Value>, outcome: ShareOutcome },
    /// Anything else — forward verbatim.
    Passthrough,
}

/// Parsed `mining.subscribe` result. Shape (node
/// `handle_subscribe`): `[[["mining.set_difficulty",en1],["mining.notify",en1]],
/// extranonce1_hex, extranonce2_size]`.
#[derive(Clone, Debug)]
pub struct SubscribeResult {
    /// Node-assigned extranonce1 (hex). Normally distinct across upstream
    /// conns (so workers search disjoint spaces), but the node does not
    /// enforce uniqueness on its 32-bit value — the router guards against
    /// collisions rather than assuming they cannot happen.
    pub extranonce1: String,
    /// extranonce2 size in bytes (node returns 4).
    pub extranonce2_size: usize,
}

/// A parsed `mining.notify` job. The proxy never rebuilds templates; it
/// only remembers the last job per worker so keepalive can re-feed it.
#[derive(Clone, Debug)]
pub struct Job {
    pub job_id: String,
    /// notify params[8] — true means abandon in-flight work.
    pub clean_jobs: bool,
    pub received_at: Instant,
}

// ─────────────────────────────────────────────────────────────────────────
// Shares & outcomes (accounting)
// ─────────────────────────────────────────────────────────────────────────

/// A parsed `mining.submit`. Params order (Bitcoin stratum):
/// `[worker_name, job_id, extranonce2, ntime, nonce]`.
#[derive(Clone, Debug)]
pub struct Share {
    pub worker: WorkerId,
    pub job_id: String,
    pub extranonce2: String,
    pub ntime: String,
    pub nonce: String,
    /// The difficulty this worker was at when the share was found
    /// (last `mining.set_difficulty` seen for the worker). Filled by the
    /// router from session state, not present on the wire.
    pub difficulty: f64,
    pub submitted_at: Instant,
}

/// Outcome of a submitted share, derived from the node's submit response.
/// Error codes mirror the node (`src/stratum/protocol.rs::ErrorCode`).
#[derive(Clone, Debug, PartialEq)]
pub enum ShareOutcome {
    /// `result: true`. Counted toward PPLNS.
    Accepted,
    /// Accepted AND it solved a real block. Sprint-1 note: the stratum
    /// `result:true` alone cannot distinguish a block from a share; this
    /// variant is produced only by the optional block-detection hook
    /// (`RouterHooks`) — otherwise a block reads as `Accepted`.
    Block,
    /// error 21 — job not found / share above target (stale).
    Stale,
    /// error 22 — duplicate share.
    Duplicate,
    /// error 23 — low difficulty share.
    LowDifficulty,
    /// Any other rejection: code + node message.
    Rejected { code: i64, message: String },
}

impl ShareOutcome {
    /// Map a stratum error array `[code, msg, null]` to an outcome.
    pub fn from_error_code(code: i64, message: String) -> Self {
        match code {
            21 => ShareOutcome::Stale,
            22 => ShareOutcome::Duplicate,
            23 => ShareOutcome::LowDifficulty,
            _ => ShareOutcome::Rejected { code, message },
        }
    }
    pub fn is_accepted(&self) -> bool {
        matches!(self, ShareOutcome::Accepted | ShareOutcome::Block)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Upstream handshake replay
// ─────────────────────────────────────────────────────────────────────────

/// The minimal set of downstream lines the upstream connection must replay
/// to the node — in this exact order — to bring a fresh upstream to the
/// point where the node streams jobs. Assembled by the router from the
/// miner's opening messages, consumed by `upstream`.
#[derive(Clone, Debug, Default)]
pub struct HandshakeReplay {
    /// Raw `mining.configure` line, if the miner sent one (Antminer/
    /// Whatsminer do). Replayed BEFORE subscribe when present.
    pub configure: Option<Line>,
    /// Raw `mining.subscribe` line. Required; without it the node assigns
    /// no extranonce1 and streams no work.
    pub subscribe: Line,
}

// ─────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────

/// Runtime configuration. Loaded by module 5 from env / args (see
/// `ProxyConfig::from_env`). Every other module receives it as
/// `Arc<ProxyConfig>` and only reads.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Where miners connect. Default `0.0.0.0:3335` (matches the reference
    /// keepalive proxy it replaces).
    pub listen_addr: String,
    /// The node's Stratum V1 endpoint. Default `127.0.0.1:3333`.
    pub upstream_addr: String,
    /// Prometheus text endpoint. Default `127.0.0.1:9333`.
    pub metrics_addr: String,
    /// TCP connect timeout to the upstream node.
    pub connect_timeout: Duration,
    /// Bound on how long a freshly-accepted downstream miner may take to
    /// complete its opening handshake (up to `mining.subscribe`). Guards a
    /// slowloris peer from pinning a worker slot by connecting and then
    /// staying silent. Default 15s.
    pub handshake_timeout: Duration,
    /// Reconnect backoff floor / ceiling (exponential between).
    pub reconnect_backoff_min: Duration,
    pub reconnect_backoff_max: Duration,
    /// Re-feed the worker's last `mining.notify` if no line has flowed
    /// downstream for this long (idle ASIC keepalive). Default 20s, as in
    /// the reference python proxy.
    pub keepalive_idle: Duration,
    /// Proxy-side vardiff. Sprint-1 MVP: `false` = transparently pass the
    /// node's own per-connection `set_difficulty` through untouched. When
    /// `true`, module 2's `VardiffController` may override downstream.
    pub vardiff_override: bool,
    /// Target seconds-per-share for the vardiff controller when enabled.
    pub vardiff_target_secs: f64,
    /// PPLNS sliding window length (number of most-recent accepted shares
    /// retained for the payout stub). 0 disables accounting retention.
    pub pplns_window_shares: usize,
    /// Max downstream connections accepted concurrently (fd guard).
    pub max_workers: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:3335".to_string(),
            upstream_addr: "127.0.0.1:3333".to_string(),
            metrics_addr: "127.0.0.1:9333".to_string(),
            connect_timeout: Duration::from_secs(15),
            handshake_timeout: Duration::from_secs(15),
            reconnect_backoff_min: Duration::from_millis(500),
            reconnect_backoff_max: Duration::from_secs(30),
            keepalive_idle: Duration::from_secs(20),
            vardiff_override: false,
            vardiff_target_secs: 10.0,
            pplns_window_shares: 100_000,
            max_workers: 4096,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────

/// Unified error type. Every module returns `Result<_, PoolError>` on its
/// public async surface so the router can treat any failure uniformly
/// (log, bump a metric, tear the worker down, maybe reconnect upstream).
#[derive(Debug)]
pub enum PoolError {
    /// Underlying socket / IO failure.
    Io(std::io::Error),
    /// Malformed or unexpected stratum content (never echoed to peers).
    Protocol(String),
    /// The node side closed or timed out; router decides on reconnect.
    UpstreamClosed(String),
    /// The miner side closed; router tears the worker down.
    DownstreamClosed(String),
    /// A bounded wait elapsed (connect, handshake, write).
    Timeout(String),
    /// Bad configuration at startup.
    Config(String),
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoolError::Io(e) => write!(f, "io: {}", e),
            PoolError::Protocol(m) => write!(f, "protocol: {}", m),
            PoolError::UpstreamClosed(m) => write!(f, "upstream closed: {}", m),
            PoolError::DownstreamClosed(m) => write!(f, "downstream closed: {}", m),
            PoolError::Timeout(m) => write!(f, "timeout: {}", m),
            PoolError::Config(m) => write!(f, "config: {}", m),
        }
    }
}

impl std::error::Error for PoolError {}

impl From<std::io::Error> for PoolError {
    fn from(e: std::io::Error) -> Self {
        PoolError::Io(e)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Metrics (shared atomics; module 5 renders them)
// ─────────────────────────────────────────────────────────────────────────

/// Process-wide counters. Shared as `Arc<Metrics>`; every module bumps the
/// relevant field. Naming mirrors the node's `bloch_*` Prometheus series.
/// Module 5 turns `snapshot()` into text — no module reads the atomics
/// directly except through `snapshot()`.
#[derive(Debug, Default)]
pub struct Metrics {
    pub workers_active: AtomicI64,
    pub workers_total: AtomicU64,
    pub shares_accepted: AtomicU64,
    pub shares_rejected: AtomicU64,
    pub shares_stale: AtomicU64,
    pub shares_duplicate: AtomicU64,
    pub blocks_found: AtomicU64,
    pub upstream_reconnects: AtomicU64,
    pub upstream_connect_failures: AtomicU64,
    /// Times a node-assigned extranonce1 was found already in use by another
    /// live worker (duplicated search space — see `ExtranonceRegistry`).
    pub extranonce1_collisions: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn worker_connected(&self) {
        self.workers_active.fetch_add(1, Ordering::Relaxed);
        self.workers_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn worker_disconnected(&self) {
        self.workers_active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Single place to fold a share outcome into the counters.
    pub fn record_outcome(&self, outcome: &ShareOutcome) {
        match outcome {
            ShareOutcome::Accepted => {
                self.shares_accepted.fetch_add(1, Ordering::Relaxed);
            }
            ShareOutcome::Block => {
                self.shares_accepted.fetch_add(1, Ordering::Relaxed);
                self.blocks_found.fetch_add(1, Ordering::Relaxed);
            }
            ShareOutcome::Stale => {
                self.shares_rejected.fetch_add(1, Ordering::Relaxed);
                self.shares_stale.fetch_add(1, Ordering::Relaxed);
            }
            ShareOutcome::Duplicate => {
                self.shares_rejected.fetch_add(1, Ordering::Relaxed);
                self.shares_duplicate.fetch_add(1, Ordering::Relaxed);
            }
            ShareOutcome::LowDifficulty | ShareOutcome::Rejected { .. } => {
                self.shares_rejected.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn add_bytes_up(&self, n: u64) {
        self.bytes_up.fetch_add(n, Ordering::Relaxed);
    }
    pub fn add_bytes_down(&self, n: u64) {
        self.bytes_down.fetch_add(n, Ordering::Relaxed);
    }
    pub fn upstream_reconnected(&self) {
        self.upstream_reconnects.fetch_add(1, Ordering::Relaxed);
    }
    pub fn upstream_connect_failed(&self) {
        self.upstream_connect_failures.fetch_add(1, Ordering::Relaxed);
    }
    pub fn extranonce1_collision(&self) {
        self.extranonce1_collisions.fetch_add(1, Ordering::Relaxed);
    }

    /// Plain-old-data snapshot for rendering. Reading atomics is `Relaxed`;
    /// a snapshot is not globally consistent, which is fine for metrics.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            workers_active: self.workers_active.load(Ordering::Relaxed),
            workers_total: self.workers_total.load(Ordering::Relaxed),
            shares_accepted: self.shares_accepted.load(Ordering::Relaxed),
            shares_rejected: self.shares_rejected.load(Ordering::Relaxed),
            shares_stale: self.shares_stale.load(Ordering::Relaxed),
            shares_duplicate: self.shares_duplicate.load(Ordering::Relaxed),
            blocks_found: self.blocks_found.load(Ordering::Relaxed),
            upstream_reconnects: self.upstream_reconnects.load(Ordering::Relaxed),
            upstream_connect_failures: self.upstream_connect_failures.load(Ordering::Relaxed),
            extranonce1_collisions: self.extranonce1_collisions.load(Ordering::Relaxed),
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
        }
    }
}

/// Flat copy of the counters for the Prometheus renderer.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct MetricsSnapshot {
    pub workers_active: i64,
    pub workers_total: u64,
    pub shares_accepted: u64,
    pub shares_rejected: u64,
    pub shares_stale: u64,
    pub shares_duplicate: u64,
    pub blocks_found: u64,
    pub upstream_reconnects: u64,
    pub upstream_connect_failures: u64,
    pub extranonce1_collisions: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

// ─────────────────────────────────────────────────────────────────────────
// Eixo-2 (multi-tip DAG dispatch) — DOCUMENTED STUB ONLY, do not implement
// ─────────────────────────────────────────────────────────────────────────

/// Sprint-2 seam. GhostDAG can expose several valid tips at once; a future
/// version may steer distinct workers at distinct tips to spread work
/// across the DAG frontier. Sprint 1 leaves this inert: the field is
/// populated opportunistically if the node ever tags a job with a tip, and
/// the router's `RouterHooks::on_tip_hint` is a no-op. NOTHING in Sprint 1
/// reads it to make routing decisions.
#[derive(Clone, Debug, Default)]
pub struct TipHint {
    pub blue_score: Option<u64>,
    pub selected_tip: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────
// Stratum method names & error codes (mirror the node)
// ─────────────────────────────────────────────────────────────────────────

pub mod methods {
    pub const SUBSCRIBE: &str = "mining.subscribe";
    pub const AUTHORIZE: &str = "mining.authorize";
    pub const SUBMIT: &str = "mining.submit";
    pub const CONFIGURE: &str = "mining.configure";
    pub const EXTRANONCE_SUBSCRIBE: &str = "mining.extranonce.subscribe";
    pub const SUGGEST_DIFFICULTY: &str = "mining.suggest_difficulty";
    pub const SUGGEST_TARGET: &str = "mining.suggest_target";
    pub const NOTIFY: &str = "mining.notify";
    pub const SET_DIFFICULTY: &str = "mining.set_difficulty";
    pub const SET_EXTRANONCE: &str = "mining.set_extranonce";
}

/// Stratum error codes (Bitcoin convention, identical to the node).
pub mod error_codes {
    pub const OTHER: i64 = 20;
    pub const JOB_NOT_FOUND_OR_STALE: i64 = 21;
    pub const DUPLICATE_SHARE: i64 = 22;
    pub const LOW_DIFFICULTY: i64 = 23;
    pub const UNAUTHORIZED: i64 = 24;
    pub const NOT_SUBSCRIBED: i64 = 25;
}