//! Per-connection session state + I/O loop.
//!
//! Owns the TcpStream split into read/write halves, maintains the
//! subscribe→authorize→authorized state machine, dispatches requests
//! to protocol handlers, and delivers server-initiated notifications.
//!
//! State transitions:
//!
//! ```text
//!   Fresh       -- mining.subscribe --> Subscribed
//!   Subscribed  -- mining.authorize --> Authorized
//!   Authorized  (submit/resubscribe)
//! ```
//!
//! Timeouts:
//! - auth_deadline: 30s from connection to reach Authorized, else close
//! - line read: 10min idle poll interval. UNAUTHORIZED sessions are
//!   closed at the auth deadline; AUTHORIZED sessions are NOT dropped
//!   for inbound silence — a solo miner legitimately says nothing
//!   between shares (possibly hours) while it still needs
//!   mining.notify pushes. Authorized sessions end on EOF, read
//!   error, or a writer-side TCP failure.

use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;
use std::time::Duration;
use parking_lot::Mutex;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::mpsc;
use serde_json::{json, Value};
use log::{info, warn, debug};

use crate::address;
use super::jobs::Template;
use super::protocol::{
    methods, ErrorCode, StratumError, StratumRequest, StratumResponse, StratumNotification,
    MAX_LINE_BYTES,
};
use super::submit::{handle_submit, AcceptBlockFn};
use super::TemplateContext;

/// Sprint 2.d — Build a fresh Template from the current DAG + mempool
/// state with `session`'s authorized address in the coinbase output,
/// install it on the session, and dispatch `mining.notify`.
///
/// `clean_jobs=true` asks the miner to abandon any in-flight work
/// (used on tip changes where the old work can no longer win). False
/// is a mempool-driven refresh — miner may finish the current job.
///
/// Returns Err(&'static str) for diagnostic logging. Never panics.
pub fn install_fresh_template(
    session:    &std::sync::Arc<Session>,
    ctx:        &TemplateContext,
    clean_jobs: bool,
) -> Result<(), &'static str> {
    // 1. Extract authorized address. If the session is not yet
    //    authorized this is a bug in the caller — log and bail.
    let addr_str = match session.authorized_addr() {
        Some(a) => a,
        None    => return Err("install_fresh_template called on un-authorized session"),
    };

    let parsed_addr = match address::Address::parse(&addr_str) {
        Ok(a)  => a,
        Err(_) => return Err("stored address no longer parses — set_authorized_addr bypassed validation?"),
    };
    let miner_spk: Vec<u8> = parsed_addr.hash().to_vec();

    // 2. Snapshot DAG state: best BODIED tip for height/blue_score,
    //    bodied_tips() for parents. A header-only tip (body never arrived
    //    over headers-first sync) is unmineable — the assembled block can't
    //    be validated by accept_block, so building on it silently stalls the
    //    miner on a phantom parent. Nested scope drops the read lock before
    //    we touch mempool/storage.
    let (parents, height, blue_score) = {
        let has_body = |h: &[u8; 32]| ctx.store.get_block(h).ok().flatten().is_some();
        let d = ctx.dag.read();
        let tip_hash = match d.best_bodied_tip(has_body) {
            Some(h) => h,
            None    => return Err("DAG has no bodied tip — node not ready?"),
        };
        let data = match d.get_block_data(&tip_hash) {
            Some(dd) => dd.clone(),
            None     => return Err("DAG bodied tip missing block data — inconsistent state"),
        };
        let parents_vec: Vec<[u8; 32]> = d.bodied_tips(has_body);
        // Next block extends the tip.
        (parents_vec, data.height + 1, data.blue_score + 1)
    };

    // 3. Current difficulty target. FAIL CLOSED: if current_bits is
    //    unreadable we must NOT guess diff-1 — on the live chain (~4.35) that
    //    is EASIER than reality, so shares would pass the local gate but the
    //    assembled block would be rejected by the node, silently burning the
    //    miner's work. Skip the notify instead.
    let bits = match read_current_bits(ctx) {
        Some(b) => b,
        None    => return Err("current_bits unreadable — refusing to notify on a guessed target"),
    };

    // Net difficulty is the HARD CAP on this session's share difficulty: a
    // share is never harder than a real block. Recompute per template because
    // bits move at retarget windows. Clamp the session's current share diff
    // down if the network got easier since it was last set.
    let net_diff = crate::core::difficulty_from_bits(bits);
    {
        let cur = session.share_difficulty();
        let cap = net_diff.max(f64::MIN_POSITIVE);
        let lo  = min_share_diff().min(cap);
        let capped = cur.clamp(lo, cap);
        if (capped - cur).abs() > f64::EPSILON {
            session.set_share_difficulty(capped);
        }
    }

    // 4. Pull top-fee transactions from mempool.
    //    Note: 2000 is an upper bound; Template::build will drop any
    //    that don't fit the block size budget.
    let other_txs = ctx.mempool.get_for_block(2000);
    let total_fees: u64 = other_txs.iter()
        .map(|tx| ctx.mempool.get_entry(&tx.txid())
            .map(|e| e.fee)
            .unwrap_or(0))
        .sum();

    // 5. Unique job id — timestamp + session id + atomic counter.
    //    Format is opaque to miners; only needs uniqueness per session.
    let job_id = {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let c = CTR.fetch_add(1, Ordering::Relaxed);
        format!("{:x}-{}-{:x}", session.id, height, c)
    };

    // 6. Build the template.
    let template = Template::build(
        parents,
        height,
        blue_score,
        bits,
        &miner_spk,
        total_fees,
        other_txs,
        ctx.coinbase_tag.as_bytes(),
        job_id,
    );

    // 7. Install on session (either replace-all or append) and send notify.
    if clean_jobs {
        session.replace_templates(template.clone());
    } else {
        session.push_template(template.clone());
    }

    // Vardiff: mining.set_difficulty MUST precede the mining.notify it
    // applies to. Emit it now if the current share difficulty differs from
    // what the miner was last told (covers the initial send — last_sent==0 —
    // the per-template net cap, and any retarget applied since the last
    // notify). The channel is FIFO so this lands before the notify below.
    {
        let cur  = session.share_difficulty();
        let last = session.last_sent_difficulty();
        if last <= 0.0 || (cur - last).abs() > f64::EPSILON {
            let _ = session.send_set_difficulty(cur);
        }
    }

    // Build the mining.notify JSON-RPC notification.
    // Template::to_notify_params renders the 9-element params array in
    // the canonical stratum order (job_id, prevhash, coinb1, coinb2,
    // merkle_branches, version, bits, ntime, clean_jobs).
    let notify = StratumNotification::new(
        methods::NOTIFY,
        template.to_notify_params(clean_jobs),
    );
    let _ = session.send_line(notify.to_line());

    info!(
        "stratum: session {} notified h={} bits=0x{:08x} job={} clean={} {} txs",
        session.id, template.height, template.bits, template.job_id, clean_jobs,
        template.other_txs.len(),
    );
    Ok(())
}

/// Session-level state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// TCP accept complete, no subscribe yet.
    Fresh,
    /// Received mining.subscribe, awaiting mining.authorize.
    Subscribed,
    /// Authorized; miner can receive jobs and submit shares.
    Authorized,
    /// Marked for removal; I/O loop will exit shortly.
    Dead,
}

/// How long a peer has to move Fresh → Authorized before we close them.
pub const AUTH_TIMEOUT_SECS: u64 = 30;

/// Read-poll interval. For AUTHORIZED sessions this is only how often
/// the reader wakes up to re-check liveness (writer-detected death) —
/// inbound silence never closes an authorized miner, since solo miners
/// only speak when they find a share. Unauthorized sessions are bounded
/// by AUTH_TIMEOUT_SECS instead.
pub const IDLE_TIMEOUT_SECS: u64 = 600;

/// Max submissions per minute per session. Anti-flood.
pub const SUBMIT_RATE_PER_MIN: u32 = 30;

/// Max number of templates retained per session. Miners may submit
/// against any of the last N jobs (stale but within retention window).
/// Older than this returns error-21 (JobNotFoundOrStale).
pub const MAX_TEMPLATES_PER_SESSION: usize = 16;

/// Soft cap on the duplicate-share cache. Keyed by (job_id, en2_hex,
/// ntime_hex, nonce_hex). Cleared when a new template evicts old jobs.
pub const MAX_SUBMITTED_ENTRIES: usize = 4096;

/// Reject `job_id` values longer than this. Legit ids are
/// `{sid:x}-{height}-{ctr:x}`, well under 64 chars; a longer one is an
/// attacker padding the dedup set for memory amplification.
pub const MAX_JOB_ID_LEN: usize = 64;

// ── Vardiff (per-connection share difficulty) ─────────────────────────
//
// GOAL: adapt each miner's share difficulty to its hashrate so it submits
// roughly one share every TARGET_SHARE_INTERVAL_SEC — always EASIER than a
// real block, never harder. This is the exact inverse of the deployed
// fixed-16384 defect. Consensus is untouched: the block's nbits stays
// `template.bits`; the share target is used ONLY for miner-facing
// accept/reject and accounting.

/// Starting share difficulty seeded on authorize. Small so a CPU miner gets
/// shares within seconds on a devnet at difficulty 1. Override via
/// `BLOCH_STRATUM_START_DIFF` for cpuminer bring-up (e.g. 0.001).
pub const START_SHARE_DIFF: f64 = 0.01;

/// Absolute floor on share difficulty (soft — the net-difficulty hard cap
/// wins when the network is easier than this, see the submit path). Override
/// via `BLOCH_STRATUM_MIN_DIFF`.
pub const MIN_SHARE_DIFF: f64 = 0.001;

/// Desired seconds between accepted shares. The retarget steers the observed
/// interval toward this. 10s (6 shares/min) sits comfortably under the
/// SUBMIT_RATE_PER_MIN=30 (1 per 2s) anti-flood cap, so vardiff never fights
/// the limiter.
pub const TARGET_SHARE_INTERVAL_SEC: f64 = 10.0;

/// Minimum shares in a window before we retarget at all.
pub const RETARGET_MIN_SHARES: u32 = 4;
/// Retarget early once this many shares land (whichever comes first with the
/// interval, provided RETARGET_MIN_SHARES is met).
pub const RETARGET_TRIGGER_SHARES: u32 = 8;
/// ...or after this many seconds with >= RETARGET_MIN_SHARES shares.
pub const RETARGET_INTERVAL_SEC: f64 = 90.0;

/// Per-retarget change-factor bounds (anti-oscillation).
pub const STEP_CLAMP_MIN: f64 = 0.25;
pub const STEP_CLAMP_MAX: f64 = 4.0;

/// Only re-send mining.set_difficulty when the new value differs from the
/// last-sent by more than this fraction (or a clamp boundary was hit).
pub const SEND_THRESHOLD: f64 = 0.10;

/// Bounded outbound channel depth. Ample for a healthy miner (one
/// set_difficulty + one notify per tip); a sustained-full channel means the
/// peer stopped draining its TCP window — we mark it Dead and reclaim the fd
/// rather than queue forever (unbounded-memory-per-session DoS).
pub const OUTBOUND_CHANNEL_BOUND: usize = 256;

/// Per-write timeout inside the writer loop. A peer that stops draining must
/// not block the writer task indefinitely.
pub const WRITE_TIMEOUT_SECS: u64 = 10;

/// How long teardown waits for the writer task to finish before aborting it
/// (which drops the write half and closes the fd deterministically).
pub const WRITER_JOIN_TIMEOUT_SECS: u64 = 2;

fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v > 0.0)
        .unwrap_or(default)
}

/// Effective starting share difficulty (env-overridable for bring-up).
pub fn start_share_diff() -> f64 { env_f64("BLOCH_STRATUM_START_DIFF", START_SHARE_DIFF) }
/// Effective minimum share difficulty (env-overridable for bring-up).
pub fn min_share_diff() -> f64 { env_f64("BLOCH_STRATUM_MIN_DIFF", MIN_SHARE_DIFF) }

/// Read the consensus `current_bits` from storage. Returns None if the meta
/// key is missing or malformed — callers FAIL CLOSED (skip notify) rather
/// than substitute a guessed diff-1 target, which on the live chain (~4.35)
/// would pass the local share gate yet produce blocks the node rejects,
/// silently burning the miner's work.
fn read_current_bits(ctx: &TemplateContext) -> Option<u32> {
    ctx.store.get_meta("current_bits").ok().flatten()
        .and_then(|b| b.as_slice().try_into().ok().map(u32::from_le_bytes))
}

/// Network difficulty implied by the current consensus bits, if readable.
fn current_net_diff(ctx: &TemplateContext) -> Option<f64> {
    read_current_bits(ctx).map(crate::core::difficulty_from_bits)
}

/// A single stratum client session.
///
/// Shared via Arc between the server registry (for broadcasting
/// notifications) and the per-session task (for I/O). Interior
/// mutability via Mutex where needed.
pub struct Session {
    pub id:              u64,
    pub peer_addr:       SocketAddr,
    pub created_at:      Instant,

    /// Random 4-byte extranonce1 assigned at subscribe time.
    /// Unique per session (server guarantees no collision).
    pub extranonce1:     [u8; 4],

    /// Channel to the session writer task. Notifications and
    /// responses enter here and are serialized out in order. BOUNDED
    /// (OUTBOUND_CHANNEL_BOUND): a full channel means a non-draining peer,
    /// which send_line converts into a Dead session + prompt fd reclaim
    /// instead of unbounded per-session memory growth.
    tx_out:              Mutex<Option<mpsc::Sender<String>>>,

    /// Current state. Atomic for cheap lock-free reads from the
    /// registry (snapshots, health checks) while the I/O task
    /// mutates it.
    state:               Mutex<SessionState>,

    /// The miner's bech32 address from mining.authorize.
    authorized_addr:     Mutex<Option<String>>,

    /// Rate-limit counter + window start for submission flood.
    submit_counter:      AtomicU32,
    submit_window_start: AtomicU64,  // secs since UNIX_EPOCH

    /// Recent job templates pushed to this session. Bounded by
    /// MAX_TEMPLATES_PER_SESSION (LRU, oldest first).
    templates:           Mutex<VecDeque<Template>>,

    /// Duplicate-share detection cache. Bounded; entries for a job_id
    /// are dropped when that template evicts from `templates`. Keyed by
    /// (job_id, en2_hex, ntime_hex, nonce_hex) — ntime is part of the key so
    /// ntime-rolled distinct solutions (cpuminer rolls ntime by default) are
    /// not falsely rejected as duplicates.
    submitted:           Mutex<HashSet<(String, String, String, String)>>,

    // ── Vardiff state (all interior-mutable) ──────────────────────────
    /// Current per-miner share difficulty. Seeded on authorize, adapted by
    /// `record_share_and_maybe_retarget`.
    share_difficulty:     Mutex<f64>,
    /// The value last actually pushed via mining.set_difficulty. 0.0 means
    /// "never sent" and forces the first send.
    last_sent_difficulty: Mutex<f64>,
    /// Start of the current retarget observation window.
    share_window_start:   Mutex<Instant>,
    /// Accepted shares counted in the current window.
    shares_in_window:     AtomicU32,
}

impl Session {
    pub fn new(id: u64, peer_addr: SocketAddr) -> Self {
        let mut extranonce1 = [0u8; 4];
        // Seed with a mix of id + time so multiple sessions don't collide.
        // Cryptographic randomness isn't strictly required here; uniqueness is.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);
        let seed = id.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(now);
        extranonce1.copy_from_slice(&seed.to_le_bytes()[..4]);

        Self {
            id,
            peer_addr,
            created_at:          Instant::now(),
            extranonce1,
            tx_out:              Mutex::new(None),
            state:               Mutex::new(SessionState::Fresh),
            authorized_addr:     Mutex::new(None),
            submit_counter:      AtomicU32::new(0),
            submit_window_start: AtomicU64::new(0),
            templates:           Mutex::new(VecDeque::with_capacity(MAX_TEMPLATES_PER_SESSION)),
            submitted:           Mutex::new(HashSet::new()),
            share_difficulty:     Mutex::new(start_share_diff()),
            last_sent_difficulty: Mutex::new(0.0), // 0 => force first set_difficulty
            share_window_start:   Mutex::new(Instant::now()),
            shares_in_window:     AtomicU32::new(0),
        }
    }

    pub fn state(&self) -> SessionState { *self.state.lock() }
    pub fn is_authorized(&self) -> bool { self.state() == SessionState::Authorized }
    pub fn is_dead(&self) -> bool       { self.state() == SessionState::Dead }

    pub fn set_state(&self, s: SessionState) {
        *self.state.lock() = s;
    }

    pub fn authorized_addr(&self) -> Option<String> {
        self.authorized_addr.lock().clone()
    }

    /// Set authorized address — used by the authorize handler.
    pub(super) fn set_authorized_addr(&self, addr: String) {
        *self.authorized_addr.lock() = Some(addr);
    }

    /// Push a new template into the session's LRU buffer. When the
    /// buffer is full, the oldest template is evicted; submitted-share
    /// entries tied to that template are also dropped.
    pub fn push_template(&self, t: Template) {
        let mut templates = self.templates.lock();
        if templates.len() >= MAX_TEMPLATES_PER_SESSION {
            if let Some(evicted) = templates.pop_front() {
                // Drop submitted entries keyed by the evicted job_id.
                let mut submitted = self.submitted.lock();
                submitted.retain(|(jid, _, _, _)| jid != &evicted.job_id);
            }
        }
        templates.push_back(t);
    }

    /// Replace the entire template buffer — used on tip change with
    /// `clean_jobs=true`. Clears submitted cache too; old shares are
    /// no longer meaningful.
    pub fn replace_templates(&self, t: Template) {
        let mut templates = self.templates.lock();
        templates.clear();
        templates.push_back(t);

        let mut submitted = self.submitted.lock();
        submitted.clear();
    }

    /// Look up a template by job_id. Returns a clone to avoid holding
    /// the lock during block validation.
    pub fn find_template(&self, job_id: &str) -> Option<Template> {
        self.templates.lock().iter().rev().find(|t| t.job_id == job_id).cloned()
    }

    /// Mark a submission as seen. Returns Ok(()) if new, Err if duplicate.
    /// Automatically trims the cache if it grows too large.
    pub fn record_submission(
        &self,
        job_id:    &str,
        en2_hex:   &str,
        ntime_hex: &str,
        nonce_hex: &str,
    ) -> Result<(), ()> {
        let key = (
            job_id.to_string(),
            en2_hex.to_string(),
            ntime_hex.to_string(),
            nonce_hex.to_string(),
        );
        let mut submitted = self.submitted.lock();
        if submitted.contains(&key) {
            return Err(());
        }
        if submitted.len() >= MAX_SUBMITTED_ENTRIES {
            // Cap the cache size; drop a random entry to make room.
            // This is defensive — in practice the eviction path on
            // push_template keeps this well under the cap.
            if let Some(evict) = submitted.iter().next().cloned() {
                submitted.remove(&evict);
            }
        }
        submitted.insert(key);
        Ok(())
    }

    /// Register the outbound channel. Called once from `run`.
    fn install_writer(&self, tx: mpsc::Sender<String>) {
        *self.tx_out.lock() = Some(tx);
    }

    // ── Vardiff accessors ─────────────────────────────────────────────

    /// Current per-miner share difficulty.
    pub fn share_difficulty(&self) -> f64 { *self.share_difficulty.lock() }

    /// Overwrite the current share difficulty (used by suggest_difficulty and
    /// the install-time net-difficulty cap).
    pub fn set_share_difficulty(&self, d: f64) { *self.share_difficulty.lock() = d; }

    /// The difficulty value last actually pushed via mining.set_difficulty.
    pub fn last_sent_difficulty(&self) -> f64 { *self.last_sent_difficulty.lock() }

    /// Push mining.set_difficulty([d]) to the miner and record it as
    /// last-sent so install_fresh_template won't redundantly resend. The
    /// caller is responsible for ordering this BEFORE any notify it applies
    /// to (the channel is FIFO, so enqueue-order == wire-order).
    pub fn send_set_difficulty(&self, d: f64) -> Result<(), &'static str> {
        let n = StratumNotification::new(methods::SET_DIFFICULTY, json!([d]));
        let r = self.send_line(n.to_line());
        if r.is_ok() {
            *self.last_sent_difficulty.lock() = d;
        }
        r
    }

    /// Count one ACCEPTED share and, if the window criteria are met, retarget
    /// the share difficulty toward one share per TARGET_SHARE_INTERVAL_SEC.
    ///
    /// `net_diff` is the HARD CAP (share never harder than a block). Returns
    /// `Some(new_diff)` when the caller should push a fresh
    /// mining.set_difficulty (the change cleared SEND_THRESHOLD or hit a clamp
    /// boundary); `None` when the difficulty is unchanged-on-the-wire. The new
    /// difficulty is always applied to the session regardless of the return.
    ///
    /// Called once per accepted share; submissions are serialized on the
    /// per-session reader task, so the counter/window need no cross-task
    /// synchronization beyond their atomics/mutexes.
    pub fn record_share_and_maybe_retarget(&self, net_diff: f64) -> Option<f64> {
        let count = self.shares_in_window.fetch_add(1, Ordering::Relaxed) + 1;
        if count < RETARGET_MIN_SHARES {
            return None;
        }
        let elapsed = self.share_window_start.lock().elapsed().as_secs_f64();
        if count < RETARGET_TRIGGER_SHARES && elapsed < RETARGET_INTERVAL_SEC {
            return None;
        }

        // Observed seconds-per-share. Shares too FAST => observed < target =>
        // ratio > 1 => difficulty UP; too slow => ratio < 1 => difficulty DOWN.
        let observed = (elapsed / count as f64).max(f64::MIN_POSITIVE);
        let ratio = (TARGET_SHARE_INTERVAL_SEC / observed)
            .clamp(STEP_CLAMP_MIN, STEP_CLAMP_MAX);

        let min_d = min_share_diff();
        // The net-difficulty HARD CAP wins over the MIN floor: if the network
        // is easier than MIN, the cap keeps the share no harder than a block.
        let cap = net_diff.max(f64::MIN_POSITIVE);
        let lo  = min_d.min(cap);

        let cur = *self.share_difficulty.lock();
        let new_diff = (cur * ratio).clamp(lo, cap);

        // Reset the window and apply the new difficulty.
        *self.share_window_start.lock() = Instant::now();
        self.shares_in_window.store(0, Ordering::Relaxed);
        *self.share_difficulty.lock() = new_diff;

        let last_sent = *self.last_sent_difficulty.lock();
        let at_boundary = new_diff <= lo || new_diff >= cap;
        let changed = last_sent <= 0.0
            || (new_diff / last_sent - 1.0).abs() > SEND_THRESHOLD
            || (at_boundary && (new_diff - last_sent).abs() > f64::EPSILON);

        if changed { Some(new_diff) } else { None }
    }

    /// Drop the outbound channel sender. Called from `run` teardown so
    /// the writer task's `rx.recv()` returns None once the queue is
    /// drained. Without this the Session (kept alive by the writer
    /// task's own Arc) holds the last sender forever, the writer never
    /// exits, the OwnedWriteHalf is never dropped, and the peer's TCP
    /// connection stays half-open indefinitely.
    fn clear_writer(&self) {
        *self.tx_out.lock() = None;
    }

    /// Send a fully-rendered line to this session's writer task.
    ///
    /// Non-blocking (try_send on a bounded channel): a Full channel means the
    /// peer stopped draining its TCP receive window — we mark the session Dead
    /// so teardown reclaims the fd promptly instead of queueing forever. A
    /// Closed channel (writer already gone) likewise marks Dead. Returns Err
    /// in both cases so callers stop feeding a doomed socket.
    pub fn send_line(&self, line: String) -> Result<(), &'static str> {
        let g = self.tx_out.lock();
        // `peer_failed` distinguishes a live-but-broken peer (Full/Closed —
        // reclaim the fd) from "no writer installed" (unit-test path — leave
        // state untouched).
        let (res, peer_failed) = match g.as_ref() {
            Some(tx) => match tx.try_send(line) {
                Ok(())                                    => (Ok(()), false),
                Err(mpsc::error::TrySendError::Full(_))   => (Err("writer backpressure — peer not draining"), true),
                Err(mpsc::error::TrySendError::Closed(_)) => (Err("writer closed"), true),
            },
            None => (Err("writer not installed"), false),
        };
        drop(g);
        if peer_failed {
            self.set_state(SessionState::Dead);
        }
        res
    }

    /// Send a server-initiated notification (mining.notify, etc).
    pub fn notify(&self, method: &str, params: Value) -> Result<(), &'static str> {
        let n = StratumNotification::new(method, params);
        self.send_line(n.to_line())
    }

    /// Check-and-increment rate limiter. Returns Ok if the
    /// submission is allowed, Err with a diagnostic if not.
    pub fn check_submit_rate(&self) -> Result<(), StratumError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let window_start = self.submit_window_start.load(Ordering::Relaxed);

        if now.saturating_sub(window_start) >= 60 {
            // New minute window
            self.submit_window_start.store(now, Ordering::Relaxed);
            self.submit_counter.store(1, Ordering::Relaxed);
            Ok(())
        } else {
            let count = self.submit_counter.fetch_add(1, Ordering::Relaxed) + 1;
            if count > SUBMIT_RATE_PER_MIN {
                Err(StratumError::new(
                    ErrorCode::Other,
                    format!("submit rate exceeded ({}/min cap)", SUBMIT_RATE_PER_MIN),
                ))
            } else {
                Ok(())
            }
        }
    }
}

/// Per-session I/O task. Reads lines, dispatches, and handles
/// outbound notifications via an mpsc channel feeding the write half.
///
/// `accept_block` is the hook into the node's accept_block path. When
/// provided, submit validation produces real blocks and emits them
/// via this callback. When None, submit returns the legacy
/// placeholder error — useful for unit tests that don't need the DAG.
pub async fn run(
    session:       std::sync::Arc<Session>,
    socket:        TcpStream,
    accept_block:  Option<std::sync::Arc<AcceptBlockFn>>,
    // Sprint 2.d: template generation context. When None, handle_authorize
    // will not install a template (backward-compatible with protocol-only
    // smoke tests).
    node_ctx:      Option<std::sync::Arc<TemplateContext>>,
) -> std::io::Result<()> {
    // Disable Nagle for interactive JSON-RPC.
    let _ = socket.set_nodelay(true);

    let (rd, wr) = socket.into_split();

    // Outbound channel: session.send_line() enqueues here, writer task
    // flushes to the TCP socket. BOUNDED — a sustained-full channel is a
    // non-draining peer; send_line marks it Dead rather than buffering
    // without limit (per-session memory DoS).
    let (out_tx, out_rx) = mpsc::channel::<String>(OUTBOUND_CHANNEL_BOUND);
    session.install_writer(out_tx);

    // Spawn writer half.
    let session_for_writer = session.clone();
    let mut writer_handle = tokio::spawn(async move {
        writer_loop(wr, out_rx, session_for_writer).await;
    });

    // Reader half: parse lines and dispatch. `line_buf` accumulates bytes
    // across read-poll timeouts (a cancelled read keeps any partial line), and
    // read_bounded_line enforces MAX_LINE_BYTES DURING accumulation so a
    // slowloris peer that never sends '\n' cannot grow it without bound.
    let mut reader = BufReader::with_capacity(MAX_LINE_BYTES + 256, rd);
    let mut line_buf: Vec<u8> = Vec::with_capacity(512);

    let auth_deadline = Instant::now() + Duration::from_secs(AUTH_TIMEOUT_SECS);

    line_buf.clear();

    loop {
        // Writer task marks the session Dead on TCP write failure —
        // stop reading from a peer we can no longer write to.
        if session.is_dead() {
            debug!("stratum: session {} writer reported dead peer", session.id);
            break;
        }

        // Check auth timeout before each read.
        if !session.is_authorized() && Instant::now() > auth_deadline {
            warn!("stratum: session {} auth timeout ({}s)", session.id, AUTH_TIMEOUT_SECS);
            let err = StratumError::new(ErrorCode::Unauthorized, "authorization timeout");
            let _ = session.send_line(StratumResponse::error(None, err).to_line());
            break;
        }

        // Bound the read: unauthorized peers get only what is left of
        // the auth window (previously a silent peer lived the full
        // idle window before the 30s deadline was ever re-checked);
        // authorized peers get the liveness-poll interval — expiry is
        // NOT a reason to drop them, see below.
        let read_timeout = if session.is_authorized() {
            Duration::from_secs(IDLE_TIMEOUT_SECS)
        } else {
            auth_deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(IDLE_TIMEOUT_SECS))
        };

        let read_result = tokio::time::timeout(
            read_timeout,
            read_bounded_line(&mut reader, &mut line_buf),
        ).await;

        match read_result {
            Ok(Ok(0)) => {
                // EOF — peer closed.
                debug!("stratum: session {} peer closed", session.id);
                break;
            }
            Ok(Ok(_)) => {
                // Dispatch the line. Non-UTF8 is a protocol violation but not
                // fatal — reply error-20 and keep the session open.
                let cb_ref = accept_block.as_deref();
                let ctx_ref = node_ctx.as_deref();
                let dispatched = match std::str::from_utf8(&line_buf) {
                    Ok(line) => dispatch(&session, line, cb_ref, ctx_ref).await,
                    Err(_)   => Err("non-utf8 line".to_string()),
                };
                match dispatched {
                    Ok(Some(response)) => {
                        if session.send_line(response.to_line()).is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        // Handler already sent (or the request was a notification).
                    }
                    Err(e) => {
                        warn!("stratum: session {} dispatch error: {}", session.id, e);
                        // Send a generic error-20 and keep session open.
                        let err = StratumError::new(ErrorCode::Other, "malformed request");
                        let _ = session.send_line(StratumResponse::error(None, err).to_line());
                    }
                }
                line_buf.clear();
                // Reclaim memory if a large (but in-bound) line ballooned the
                // buffer, so an authorized long-lived session doesn't retain it.
                if line_buf.capacity() > MAX_LINE_BYTES {
                    line_buf.shrink_to(512);
                }
            }
            Ok(Err(e)) => {
                debug!("stratum: session {} read error: {}", session.id, e);
                break;
            }
            Err(_) => {
                // Read-poll expired with no inbound line.
                //
                // For an AUTHORIZED miner this is NORMAL: a solo miner
                // says nothing between shares (possibly hours) while it
                // still needs mining.notify pushes. Dropping it here
                // was the session-notify bug — the registry emptied and
                // every tip change logged "notifying 0 sessions" while
                // cpuminer kept grinding stale work. Keep the session;
                // a genuinely dead peer is caught by EOF or by the
                // writer failing a notify push (which marks us Dead —
                // checked at the top of the loop).
                //
                // A cancelled read_line keeps any partial line in
                // line_buf; the next iteration resumes appending, so no
                // in-flight submit is corrupted.
                if session.is_authorized() {
                    debug!(
                        "stratum: session {} quiet for {}s — keeping authorized session alive",
                        session.id, IDLE_TIMEOUT_SECS
                    );
                    continue;
                }
                // Unauthorized: the auth window has elapsed.
                warn!("stratum: session {} auth timeout ({}s)", session.id, AUTH_TIMEOUT_SECS);
                let err = StratumError::new(ErrorCode::Unauthorized, "authorization timeout");
                let _ = session.send_line(StratumResponse::error(None, err).to_line());
                break;
            }
        }
    }

    session.set_state(SessionState::Dead);

    // Close the outbound path deterministically: dropping the sender
    // stored in the session lets the writer drain any final queued
    // lines (e.g. the auth-timeout error), observe channel closure,
    // shut the socket down, and exit. Previously the sender was never
    // dropped — the writer task's own Arc<Session> kept it alive — so
    // the writer leaked and the peer's connection stayed half-open
    // forever. The bound is defensive against a peer that stops
    // draining its receive window.
    session.clear_writer();
    // Give the writer a bounded window to drain the final queued line(s) and
    // shut the socket down. If it doesn't finish (a peer that stopped draining
    // its receive window would otherwise leave the OwnedWriteHalf owned by a
    // live task => half-open CLOSE-WAIT fd), ABORT it: dropping the task drops
    // the write half and closes the fd deterministically.
    if tokio::time::timeout(
        Duration::from_secs(WRITER_JOIN_TIMEOUT_SECS),
        &mut writer_handle,
    ).await.is_err() {
        writer_handle.abort();
    }
    Ok(())
}

/// Read one newline-terminated line into `buf`, enforcing MAX_LINE_BYTES
/// DURING accumulation. Appends to `buf` (so a partial line survives a
/// cancelled poll — the caller clears `buf` only after a full line is
/// dispatched). Returns:
/// - `Ok(len)` with the total buffered length when a '\n' is consumed,
/// - `Ok(0)` on EOF,
/// - `Err(InvalidData)` the instant accumulated bytes exceed MAX_LINE_BYTES.
///
/// Cancellation-safe: `fill_buf().await` is the only suspension point, and it
/// consumes nothing on its own — bytes are only moved into `buf` after it
/// resolves, so a cancelled read never loses data mid-accumulation.
async fn read_bounded_line<R>(reader: &mut R, buf: &mut Vec<u8>) -> std::io::Result<usize>
where
    R: AsyncBufReadExt + Unpin,
{
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(0); // EOF
        }
        if let Some(i) = available.iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&available[..=i]);
            let consumed = i + 1;
            reader.consume(consumed);
            return Ok(buf.len());
        }
        let n = available.len();
        buf.extend_from_slice(available);
        reader.consume(n);
        if buf.len() > MAX_LINE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "stratum line exceeds MAX_LINE_BYTES",
            ));
        }
    }
}

/// Writer task: drains the outbound channel into the TCP stream.
///
/// Exits when the channel closes (run() drops the session's sender in
/// teardown) — after draining any final queued lines, so a last error
/// response (e.g. the auth-timeout message) still reaches the peer —
/// or on TCP write failure, which marks the session Dead so the reader
/// loop stops serving a peer we can no longer reach.
async fn writer_loop(
    mut wr: OwnedWriteHalf,
    mut rx: mpsc::Receiver<String>,
    session: std::sync::Arc<Session>,
) {
    while let Some(line) = rx.recv().await {
        // Bound each write: a peer that stops draining its receive window must
        // not block the writer task forever (that would pin the fd open). On
        // write error OR timeout, mark Dead so the reader stops serving a peer
        // we can no longer reach, and exit.
        let write = tokio::time::timeout(
            Duration::from_secs(WRITE_TIMEOUT_SECS),
            async {
                wr.write_all(line.as_bytes()).await?;
                wr.flush().await
            },
        ).await;
        match write {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => {
                session.set_state(SessionState::Dead);
                break;
            }
        }
    }
    // Half-close gracefully.
    let _ = wr.shutdown().await;
}

/// Request dispatcher. Parses a JSON line into a StratumRequest and
/// routes to the appropriate handler. Returns the response to send,
/// or None if the handler has already emitted output itself.
///
/// When `accept_block` is Some, mining.submit goes to the full
/// validation path in submit.rs. When None (e.g., in unit tests or
/// before the DAG wiring in main.rs is complete), submit returns
/// the legacy placeholder error.
async fn dispatch(
    session:       &std::sync::Arc<Session>,
    line:          &str,
    accept_block:  Option<&AcceptBlockFn>,
    node_ctx:      Option<&TemplateContext>,
) -> Result<Option<StratumResponse>, String> {
    let req = StratumRequest::parse(line)?;

    match req.method.as_str() {
        methods::SUBSCRIBE => Ok(Some(handle_subscribe(session, &req))),
        methods::AUTHORIZE => {
            // handle_authorize emits its own wire messages in the load-bearing
            // order authorize-result -> set_difficulty -> notify, so dispatch
            // must NOT re-send the returned response.
            let _ = handle_authorize(session, &req, node_ctx);
            Ok(None)
        }
        methods::SUBMIT    => Ok(Some(handle_submit_dispatch(session, &req, accept_block))),
        methods::CONFIGURE => Ok(Some(handle_configure(session, &req))),
        methods::EXTRANONCE_SUBSCRIBE => Ok(Some(StratumResponse::ok(req.id, Value::from(true)))),
        methods::SUGGEST_DIFFICULTY | methods::SUGGEST_TARGET => {
            Ok(Some(handle_suggest_difficulty(session, &req, node_ctx)))
        }
        other => {
            warn!("stratum: session {} unknown method: {}", session.id, other);
            Ok(Some(StratumResponse::error(
                req.id,
                StratumError::new(ErrorCode::Other, format!("unknown method: {}", other)),
            )))
        }
    }
}

/// mining.subscribe handler.
///
/// Returns: [[["mining.set_difficulty", sub_id], ["mining.notify", sub_id]],
///          extranonce1_hex, extranonce2_size]
fn handle_subscribe(session: &std::sync::Arc<Session>, req: &StratumRequest) -> StratumResponse {
    if session.state() != SessionState::Fresh {
        return StratumResponse::error(
            req.id.clone(),
            StratumError::new(ErrorCode::Other, "already subscribed"),
        );
    }

    session.set_state(SessionState::Subscribed);

    let extranonce1_hex = hex::encode(session.extranonce1);
    let subscriptions = json!([
        [methods::SET_DIFFICULTY, extranonce1_hex.clone()],
        [methods::NOTIFY,         extranonce1_hex.clone()],
    ]);

    info!("stratum: session {} subscribed (extranonce1={})", session.id, extranonce1_hex);

    StratumResponse::ok(req.id.clone(), json!([
        subscriptions,
        extranonce1_hex,
        4u32,  // extranonce2_size (bytes)
    ]))
}

/// mining.authorize handler.
///
/// Strict validation: the username must parse as a valid Bloch-SIS Protocol
/// bech32 address. Invalid addresses get a code-24 error and the
/// session stays in Subscribed (not Authorized).
fn handle_authorize(
    session:   &std::sync::Arc<Session>,
    req:       &StratumRequest,
    node_ctx:  Option<&TemplateContext>,
) -> StratumResponse {
    // Small helper: send an error on the wire AND return it (unit tests call
    // this handler directly and inspect the returned value; over a live socket
    // dispatch discards the return and relies on this send).
    let send_err = |code, msg: &str| -> StratumResponse {
        let e = StratumResponse::error(req.id.clone(), StratumError::new(code, msg.to_string()));
        let _ = session.send_line(e.to_line());
        e
    };

    if session.state() == SessionState::Fresh {
        return send_err(ErrorCode::NotSubscribed, "must subscribe before authorizing");
    }

    // params: [username, password]
    let params = match req.params.as_array() {
        Some(a) if !a.is_empty() => a,
        _ => return send_err(ErrorCode::Unauthorized, "authorize requires [username, password]"),
    };

    let username = match params[0].as_str() {
        Some(s) => s,
        None    => return send_err(ErrorCode::Unauthorized, "username must be a string"),
    };

    // Validate as a Bloch-SIS Protocol bech32 address.
    match address::Address::parse(username) {
        Ok(_) => {
            session.set_authorized_addr(username.to_string());
            session.set_state(SessionState::Authorized);
            info!("stratum: session {} authorized {}", session.id, username);

            // Seed vardiff: clamp the (env-overridable) start difficulty to the
            // net-difficulty hard cap so a share is never harder than a block.
            if let Some(ctx) = node_ctx {
                let start = start_share_diff();
                let seed = match current_net_diff(ctx) {
                    Some(net) => {
                        let cap = net.max(f64::MIN_POSITIVE);
                        start.clamp(min_share_diff().min(cap), cap)
                    }
                    None => start,
                };
                session.set_share_difficulty(seed);
            }

            let ok = StratumResponse::ok(req.id.clone(), Value::from(true));

            // Wire ORDER is load-bearing: authorize-result FIRST — strict
            // firmwares (and some MRR proxies) discard a notify that arrives
            // before authorize is confirmed. Send it, THEN let
            // install_fresh_template emit mining.set_difficulty followed by the
            // first mining.notify (that ordering is enforced inside it).
            let _ = session.send_line(ok.to_line());

            if let Some(ctx) = node_ctx {
                if let Err(reason) = install_fresh_template(session, ctx, true) {
                    warn!("stratum: session {} authorize OK but template install failed: {}",
                          session.id, reason);
                }
            }

            ok
        }
        Err(e) => {
            warn!("stratum: session {} invalid address '{}': {}", session.id, username, e);
            send_err(ErrorCode::Unauthorized, &format!("invalid address: {}", e))
        }
    }
}

/// mining.configure handler.
///
/// This is the FIRST message Antminer (BMMiner) / Whatsminer (BTMiner) / MRR
/// proxies send. We DECLINE version-rolling (`{"version-rolling": false}`):
/// compliant firmware then stops rolling the version bit, the header version
/// stays 1, the server reproduces the miner's hash, and accept_block (which is
/// unchanged) validates the block. This is strictly better than letting it
/// fall through to the error-20 catch-all, which causes disconnect/reconnect
/// churn. Full version-rolling is a deferred follow-up gated on a consensus
/// review of the header.version field.
fn handle_configure(session: &std::sync::Arc<Session>, req: &StratumRequest) -> StratumResponse {
    info!("stratum: session {} mining.configure — declining version-rolling", session.id);
    StratumResponse::ok(req.id.clone(), json!({ "version-rolling": false }))
}

/// mining.suggest_difficulty / mining.suggest_target handler.
///
/// Parses a numeric suggested difficulty, clamps it to
/// [min_share_diff(), net_difficulty], seeds the session's share difficulty,
/// and confirms with mining.set_difficulty. Always returns Ok(true).
/// suggest_target (a hex target string) is accepted as a no-op seed.
fn handle_suggest_difficulty(
    session:  &std::sync::Arc<Session>,
    req:      &StratumRequest,
    node_ctx: Option<&TemplateContext>,
) -> StratumResponse {
    if let Some(d) = req.params.as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_f64())
    {
        if d.is_finite() && d > 0.0 {
            // Cap to net difficulty when known; otherwise accept the suggestion
            // as-is (install_fresh_template re-applies the net cap on the first
            // notify regardless).
            let cap = node_ctx.and_then(current_net_diff)
                .map(|n| n.max(f64::MIN_POSITIVE))
                .unwrap_or(d);
            let clamped = d.clamp(min_share_diff().min(cap), cap);
            session.set_share_difficulty(clamped);
            let _ = session.send_set_difficulty(clamped);
        }
    }
    StratumResponse::ok(req.id.clone(), Value::from(true))
}

/// Thin wrapper that delegates to the real submit handler in submit.rs
/// when an accept_block callback is available, otherwise returns the
/// AA.1-pt-1 placeholder error for unit tests that don't wire the
/// callback.
fn handle_submit_dispatch(
    session:        &std::sync::Arc<Session>,
    req:            &StratumRequest,
    accept_block:   Option<&AcceptBlockFn>,
) -> StratumResponse {
    match accept_block {
        Some(cb) => handle_submit(session, req, cb),
        None => handle_submit_placeholder(session, req),
    }
}

/// AA.1-pt-1 placeholder kept for standalone dispatch paths that don't
/// yet carry an accept_block callback (e.g., unit tests).
fn handle_submit_placeholder(session: &std::sync::Arc<Session>, req: &StratumRequest) -> StratumResponse {
    if !session.is_authorized() {
        return StratumResponse::error(
            req.id.clone(),
            StratumError::new(ErrorCode::Unauthorized, "unauthorized worker"),
        );
    }
    if let Err(e) = session.check_submit_rate() {
        return StratumResponse::error(req.id.clone(), e);
    }
    // Real handler lands next commit; for now, signal stale to any submission.
    StratumResponse::error(
        req.id.clone(),
        StratumError::new(
            ErrorCode::JobNotFoundOrStale,
            "submission path not yet implemented — expect error-21 until AA.1 pt 2 ships",
        ),
    )
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn mk_session() -> std::sync::Arc<Session> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        std::sync::Arc::new(Session::new(1, addr))
    }

    #[test]
    fn session_starts_fresh() {
        let s = mk_session();
        assert_eq!(s.state(), SessionState::Fresh);
        assert!(!s.is_authorized());
    }

    #[test]
    fn extranonce1_is_four_bytes() {
        let s = mk_session();
        assert_eq!(s.extranonce1.len(), 4);
    }

    #[test]
    fn extranonce1_differs_between_sessions() {
        // Session ids 1 and 2 → different extranonce1. Uses time+id,
        // so this can theoretically collide if two sessions
        // construct in the same microsecond with specific ids.
        // Extremely unlikely in practice.
        let a = std::sync::Arc::new(Session::new(1, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)));
        std::thread::sleep(std::time::Duration::from_micros(2));
        let b = std::sync::Arc::new(Session::new(2, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)));
        assert_ne!(a.extranonce1, b.extranonce1);
    }

    #[test]
    fn subscribe_advances_state_and_returns_extranonce() {
        let s = mk_session();
        let req = StratumRequest {
            id:     Some(Value::from(1)),
            method: methods::SUBSCRIBE.to_string(),
            params: json!(["cpuminer/2.5"]),
        };
        let resp = handle_subscribe(&s, &req);
        assert_eq!(s.state(), SessionState::Subscribed);
        // result is [subs_array, extranonce1_hex, 4]
        let result = &resp.result;
        assert!(result.is_array());
        let arr = result.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[2].as_u64(), Some(4));
    }

    #[test]
    fn subscribe_twice_errors() {
        let s = mk_session();
        let req = StratumRequest {
            id:     Some(Value::from(1)),
            method: methods::SUBSCRIBE.to_string(),
            params: json!([]),
        };
        let _ = handle_subscribe(&s, &req);
        let resp = handle_subscribe(&s, &req);
        assert!(resp.error.is_some(), "second subscribe must error");
    }

    #[test]
    fn authorize_rejects_invalid_address() {
        let s = mk_session();
        // Put session in Subscribed first.
        s.set_state(SessionState::Subscribed);

        let req = StratumRequest {
            id:     Some(Value::from(2)),
            method: methods::AUTHORIZE.to_string(),
            params: json!(["not-a-valid-address", "x"]),
        };
        let resp = handle_authorize(&s, &req, None);
        assert!(resp.error.is_some(), "invalid address must error");
        assert_eq!(s.state(), SessionState::Subscribed, "session stays unauthorized on bad address");
    }

    #[test]
    fn authorize_before_subscribe_errors() {
        let s = mk_session();
        let req = StratumRequest {
            id:     Some(Value::from(1)),
            method: methods::AUTHORIZE.to_string(),
            params: json!(["bloch1q4fbcd3b3fae5de3e2b4015ca132c8744b8af170a79e4eb45", "x"]),
        };
        let resp = handle_authorize(&s, &req, None);
        assert!(resp.error.is_some());
    }

    #[test]
    fn submit_while_unauthorized_errors_24() {
        let s = mk_session();
        let req = StratumRequest {
            id:     Some(Value::from(3)),
            method: methods::SUBMIT.to_string(),
            params: json!([]),
        };
        let resp = handle_submit_placeholder(&s, &req);
        let err_arr = resp.error.as_ref().and_then(|v| v.as_array()).unwrap();
        assert_eq!(err_arr[0].as_u64(), Some(24));
    }

    #[test]
    fn submit_rate_limiter_cuts_off_after_cap() {
        let s = mk_session();
        for _ in 0..SUBMIT_RATE_PER_MIN {
            assert!(s.check_submit_rate().is_ok());
        }
        // One more should trip.
        assert!(s.check_submit_rate().is_err());
    }

    // ── Vardiff retarget math ────────────────────────────────────

    #[test]
    fn retarget_needs_minimum_shares() {
        let s = mk_session();
        // Fewer than RETARGET_MIN_SHARES => never retargets, never returns Some.
        for _ in 0..(RETARGET_MIN_SHARES - 1) {
            assert!(s.record_share_and_maybe_retarget(1.0).is_none());
        }
    }

    #[test]
    fn fast_shares_raise_difficulty_slow_shares_lower_it() {
        // FAST: shares arrive far quicker than the 10s target => difficulty up.
        let fast = mk_session();
        fast.set_share_difficulty(0.1);
        // Force the window to look old enough only via share count trigger:
        // submit RETARGET_TRIGGER_SHARES back-to-back (elapsed ~0 => observed
        // << target => ratio clamps to STEP_CLAMP_MAX, diff rises).
        let mut raised = None;
        for _ in 0..RETARGET_TRIGGER_SHARES {
            if let Some(d) = fast.record_share_and_maybe_retarget(1.0) { raised = Some(d); }
        }
        let d = raised.expect("a retarget should have fired at the trigger count");
        assert!(d > 0.1, "fast shares must raise difficulty, got {}", d);
        assert!(d <= 1.0, "must not exceed the net-difficulty cap");
        // never below the floor
        assert!(d >= MIN_SHARE_DIFF.min(1.0));
    }

    #[test]
    fn retarget_respects_net_difficulty_cap() {
        let s = mk_session();
        s.set_share_difficulty(10.0); // already above cap
        let mut last = None;
        for _ in 0..RETARGET_TRIGGER_SHARES {
            if let Some(d) = s.record_share_and_maybe_retarget(2.0) { last = Some(d); }
        }
        if let Some(d) = last {
            assert!(d <= 2.0, "share diff must be capped at net_diff=2.0, got {}", d);
        }
    }

    #[test]
    fn configure_declines_version_rolling() {
        let s = mk_session();
        let req = StratumRequest {
            id:     Some(Value::from(9)),
            method: methods::CONFIGURE.to_string(),
            params: json!([["version-rolling"], {"version-rolling.mask": "1fffe000"}]),
        };
        let resp = handle_configure(&s, &req);
        assert!(resp.error.is_none());
        // result carries {"version-rolling": false}
        assert_eq!(resp.result.get("version-rolling").and_then(|v| v.as_bool()), Some(false));
    }

    // ── Session lifetime over a real socket ──────────────────────
    //
    // Regression tests for the "notifying 0 sessions" bug: an
    // authorized-but-quiet miner was dropped by the read idle timeout
    // (and the leaked writer task kept its TCP socket half-open, so
    // cpuminer kept grinding stale work with no fresh notify ever
    // arriving). start_paused lets the tokio clock auto-advance
    // through the 600s poll windows instantly.

    const VALID_ADDR: &str = "bloch1q4fbcd3b3fae5de3e2b4015ca132c8744b8af170a79e4eb45";

    /// Bind a loopback listener, connect a client, and spawn
    /// session::run for the accepted socket. Returns (client, session).
    async fn spawn_session_pair() -> (TcpStream, std::sync::Arc<Session>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server_sock, peer) = listener.accept().await.unwrap();
        let session = std::sync::Arc::new(Session::new(1, peer));
        let s2 = session.clone();
        tokio::spawn(async move {
            let _ = run(s2, server_sock, None, None).await;
        });
        (client, session)
    }

    async fn send_json<W: AsyncWriteExt + Unpin>(client: &mut W, line: &str) {
        client.write_all(line.as_bytes()).await.unwrap();
        client.write_all(b"\n").await.unwrap();
        client.flush().await.unwrap();
    }

    async fn read_json_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> String {
        let mut buf = String::new();
        let n = reader.read_line(&mut buf).await.unwrap();
        assert!(n > 0, "peer closed unexpectedly");
        buf
    }

    #[tokio::test]
    async fn authorized_quiet_session_survives_idle_windows() {
        let (client, session) = spawn_session_pair().await;
        let (rd, mut wr) = client.into_split();
        let mut rdr = BufReader::new(rd);

        // Handshake on the REAL clock: pausing here would let tokio's
        // auto-advance jump past the 30s auth deadline while the
        // subscribe line is still in flight on the loopback socket.
        send_json(&mut wr, r#"{"id":1,"method":"mining.subscribe","params":["cpuminer/2.5"]}"#).await;
        let _sub_resp = read_json_line(&mut rdr).await;

        send_json(&mut wr, &format!(
            r#"{{"id":2,"method":"mining.authorize","params":["{}","x"]}}"#, VALID_ADDR)).await;
        let auth_resp = read_json_line(&mut rdr).await;
        assert!(auth_resp.contains("true"), "authorize should succeed: {}", auth_resp);
        assert_eq!(session.state(), SessionState::Authorized);

        // Now simulate a miner that is quiet for several idle windows —
        // it is hashing, not talking. Pause the clock so auto-advance
        // steps through each 600s read-poll expiry instantly.
        tokio::time::pause();
        tokio::time::sleep(Duration::from_secs(IDLE_TIMEOUT_SECS * 3 + 5)).await;
        tokio::time::resume();

        // The session must still be alive, authorized, and reachable
        // by server-initiated pushes.
        assert_eq!(session.state(), SessionState::Authorized,
            "quiet authorized session must not be dropped");
        session.notify(methods::SET_DIFFICULTY, json!([1])).expect("writer must still be installed");
        let pushed = read_json_line(&mut rdr).await;
        assert!(pushed.contains(methods::SET_DIFFICULTY));

        // And it still answers requests. suggest_difficulty now also pushes a
        // mining.set_difficulty (vardiff seed confirmation) BEFORE the id:3
        // result, so read forward until we see the response.
        send_json(&mut wr, r#"{"id":3,"method":"mining.suggest_difficulty","params":[1]}"#).await;
        let mut saw_response = false;
        for _ in 0..3 {
            let line = read_json_line(&mut rdr).await;
            if line.contains("\"id\":3") { saw_response = true; break; }
            // otherwise it's the set_difficulty confirmation — keep reading.
            assert!(line.contains(methods::SET_DIFFICULTY),
                "unexpected line before suggest_difficulty result: {}", line);
        }
        assert!(saw_response, "session must still dispatch the suggest_difficulty result");
    }

    #[tokio::test(start_paused = true)]
    async fn unauthorized_session_closed_at_auth_deadline() {
        let (client, session) = spawn_session_pair().await;
        let (rd, _wr) = client.into_split();
        let mut rdr = BufReader::new(rd);

        // Say nothing. The session must be closed at the 30s auth
        // deadline (not the 600s idle window), the error must actually
        // be flushed, and the socket must reach EOF — i.e. the writer
        // task exited and dropped the write half instead of leaking.
        let mut all = String::new();
        let read_all = tokio::time::timeout(
            Duration::from_secs(AUTH_TIMEOUT_SECS + 30),
            async {
                loop {
                    let mut line = String::new();
                    match rdr.read_line(&mut line).await {
                        Ok(0) => break,          // EOF — socket fully closed
                        Ok(_) => all.push_str(&line),
                        Err(_) => break,
                    }
                }
            },
        ).await;
        assert!(read_all.is_ok(), "socket must close at the auth deadline, not linger");
        assert!(all.contains("authorization timeout"),
            "auth-timeout error must be flushed before close, got: {}", all);
        assert!(session.is_dead());
    }
}
