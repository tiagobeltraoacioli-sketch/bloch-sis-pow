//! router — the per-worker integrator/orchestrator for the Bloch smart
//! Stratum proxy.
//!
//! One `run_worker` future owns the whole lifecycle of a single downstream
//! miner/ASIC:
//!
//!   1. read the miner's opening `mining.configure?` / `mining.subscribe`
//!      to assemble a [`HandshakeReplay`],
//!   2. open the dedicated [`UpstreamConn`] to the node (the node hands this
//!      upstream a DISJOINT `extranonce1`, which is the whole point),
//!   3. forward the node's subscribe-result downstream verbatim so the miner
//!      inherits that disjoint extranonce space,
//!   4. run a transparent bidirectional pump with `tokio::select!` over
//!      downstream reads, upstream reads and a keepalive idle timer.
//!
//! The pump forwards every line UNCHANGED. It only *observes*: it caches the
//! last `mining.notify` for keepalive re-feed, tracks the per-connection
//! difficulty, and — for `mining.submit` — records a [`Share`] and folds the
//! node's response ([`ShareOutcome`]) into [`Metrics`], the PPLNS window and
//! the block-found hook.
//!
//! ### Sibling interfaces (the ACTUAL module APIs)
//!
//! This module is wired against the real public surfaces of `downstream`
//! and `upstream`:
//!
//! ```ignore
//! // crate::downstream::DownstreamConn
//! //   pub worker: WorkerId            (field, not a method)
//! //   async fn read(&mut self) -> Result<Option<Framed<ClientMsg>>, PoolError>
//! //   async fn write(&mut self, line: &str) -> Result<(), PoolError>
//! //
//! // crate::upstream::UpstreamConn
//! //   pub extranonce1: String; pub extranonce2_size: usize   (fields)
//! //   async fn connect(cfg, metrics, worker, replay: HandshakeReplay) -> Result<Self>
//! //   async fn read(&mut self) -> Result<Option<Framed<ServerMsg>>, PoolError>
//! //     (the node's subscribe-result / notify prelude is delivered here,
//! //      buffered, so the router just forwards those raw lines downstream)
//! //   async fn write(&mut self, line: &str) -> Result<(), PoolError>
//! //   async fn reconnect(&mut self, &HandshakeReplay) -> Result<SubscribeResult, PoolError>
//! ```
//!
//! Keepalive is kept entirely inside the router as a router-owned
//! `tokio::time::Sleep` rather than a `downstream.keepalive_tick()` branch:
//! `select!` cannot hold two `&mut down` borrows at once (read + keepalive),
//! so folding the idle timer into the router is the borrow-clean equivalent.
//! byte counters and worker connect/disconnect counters are owned by the conn
//! and server modules respectively; the router only records share outcomes.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde_json::Value;

use crate::downstream::DownstreamConn;
use crate::upstream::UpstreamConn;

use crate::types::{
    methods, ClientMsg, Framed, HandshakeReplay, Line, Metrics, PoolError, ProxyConfig, RawRequest,
    ServerMsg, Share, ShareOutcome, SubscribeResult, TipHint, WorkerId,
};

// ─────────────────────────────────────────────────────────────────────────
// Guards
// ─────────────────────────────────────────────────────────────────────────

/// Cap on `mining.submit`s awaiting a node response. A well-behaved miner
/// has at most a handful in flight; the cap bounds memory against a
/// misbehaving one that never gets (or ignores) results.
const PENDING_CAP: usize = 4096;

/// Cap on non-`subscribe` lines a miner may send before it subscribes.
/// Bounds the pre-handshake buffer against a peer that never subscribes.
const PRE_SUBSCRIBE_CAP: usize = 32;

// ─────────────────────────────────────────────────────────────────────────
// Extranonce1 collision guard
// ─────────────────────────────────────────────────────────────────────────

/// Process-wide registry of the `extranonce1` values currently assigned to
/// live workers.
///
/// The node's extranonce1 is a 32-bit value with NO uniqueness registry
/// (see the node's `session.rs::handle_subscribe`), so two upstreams can be
/// handed the same value and then duplicate ALL work silently. This registry
/// makes that observable: when a worker is assigned an extranonce1 already
/// held by another live worker, the proxy logs a WARN and bumps
/// `bloch_pool_extranonce1_collisions_total` instead of silently colliding.
#[derive(Debug, Default)]
pub struct ExtranonceRegistry {
    live: Mutex<HashSet<String>>,
}

impl ExtranonceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to claim `en1`. Returns `true` if it was unique (now registered),
    /// `false` if another live worker already holds it (a collision — the
    /// caller must NOT treat the search space as disjoint).
    fn try_claim(&self, en1: &str) -> bool {
        // A poisoned lock only means a previous holder panicked; the set is
        // still usable, so recover rather than propagate.
        let mut g = self.live.lock().unwrap_or_else(|e| e.into_inner());
        g.insert(en1.to_string())
    }

    /// Release `en1` (called when the claiming worker drops it or exits).
    fn release(&self, en1: &str) {
        let mut g = self.live.lock().unwrap_or_else(|e| e.into_inner());
        g.remove(en1);
    }

    #[cfg(test)]
    fn contains(&self, en1: &str) -> bool {
        self.live.lock().unwrap_or_else(|e| e.into_inner()).contains(en1)
    }
}

/// RAII holder of ONE worker's current extranonce1 claim. Registers the
/// claim on [`assign`](WorkerExtranonce::assign) (logging + counting a
/// collision if the value is already live), moves the claim on reassignment
/// (reconnect), and releases it on drop so a worker that exits — normally,
/// by error, or by panic — never leaks its extranonce1.
struct WorkerExtranonce {
    registry: Arc<ExtranonceRegistry>,
    /// The extranonce1 THIS worker currently owns a registry slot for, if
    /// any. `None` when the current value collided with another worker (we
    /// leave that other worker as the owner) or before the first assign.
    held: Option<String>,
}

impl WorkerExtranonce {
    fn new(registry: Arc<ExtranonceRegistry>) -> Self {
        Self { registry, held: None }
    }

    /// Adopt `en1` as this worker's extranonce1. Releases any previously
    /// held value first. On a collision, counts the metric and warns but
    /// proceeds (the proxy stays transparent; it does not drop the worker).
    fn assign(&mut self, en1: &str, metrics: &Metrics, worker: WorkerId) {
        if self.held.as_deref() == Some(en1) {
            return; // unchanged
        }
        if let Some(prev) = self.held.take() {
            self.registry.release(&prev);
        }
        if self.registry.try_claim(en1) {
            self.held = Some(en1.to_string());
        } else {
            metrics.extranonce1_collision();
            log::warn!(
                "{worker}: node assigned extranonce1 {en1} already in use by another live \
                 worker — search spaces OVERLAP; work will be duplicated"
            );
            // Leave `held` = None: the other worker owns the slot, so we must
            // not remove it on our drop.
        }
    }
}

impl Drop for WorkerExtranonce {
    fn drop(&mut self) {
        if let Some(en1) = self.held.take() {
            self.registry.release(&en1);
        }
    }
}

/// Build a downstream `mining.set_extranonce` notification from a fresh
/// subscribe result, so an idle-through-reconnect miner picks up its new
/// extranonce1 instead of mining dead work on the stale one.
fn build_set_extranonce(sub: &SubscribeResult) -> String {
    format!(
        r#"{{"id":null,"method":"{}","params":["{}",{}]}}"#,
        methods::SET_EXTRANONCE,
        sub.extranonce1,
        sub.extranonce2_size
    )
}

// ─────────────────────────────────────────────────────────────────────────
// Accounting + PPLNS stub
// ─────────────────────────────────────────────────────────────────────────

/// One retained accepted share (the PPLNS window is a ring of these).
#[derive(Clone, Debug)]
pub struct ShareRecord {
    pub worker: WorkerId,
    pub job_id: String,
    pub difficulty: f64,
    pub outcome: ShareOutcome,
    pub at: Instant,
}

/// Per-worker share accounting plus a PPLNS stub.
///
/// The window retains only *accepted* shares (difficulty-weighted, capped at
/// `cfg.pplns_window_shares`); the running totals count every outcome. Payout
/// settlement is out of Sprint-1 scope — [`Accounting::pplns_credit`] returns
/// proportional credit fractions only.
#[derive(Debug)]
pub struct Accounting {
    window: VecDeque<ShareRecord>,
    cap: usize,
    total_accepted: u64,
    total_rejected: u64,
    total_stale: u64,
    total_duplicate: u64,
    total_blocks: u64,
}

impl Accounting {
    pub fn new(cfg: &ProxyConfig) -> Self {
        Self {
            window: VecDeque::new(),
            cap: cfg.pplns_window_shares,
            total_accepted: 0,
            total_rejected: 0,
            total_stale: 0,
            total_duplicate: 0,
            total_blocks: 0,
        }
    }

    /// Fold one share result: bump the totals for every outcome, and push the
    /// share onto the PPLNS window if it was accepted (and retention is on).
    pub fn record(&mut self, share: &Share, outcome: &ShareOutcome) {
        match outcome {
            ShareOutcome::Accepted => self.total_accepted += 1,
            ShareOutcome::Block => {
                self.total_accepted += 1;
                self.total_blocks += 1;
            }
            ShareOutcome::Stale => {
                self.total_rejected += 1;
                self.total_stale += 1;
            }
            ShareOutcome::Duplicate => {
                self.total_rejected += 1;
                self.total_duplicate += 1;
            }
            ShareOutcome::LowDifficulty | ShareOutcome::Rejected { .. } => {
                self.total_rejected += 1;
            }
        }

        if outcome.is_accepted() && self.cap > 0 {
            self.window.push_back(ShareRecord {
                worker: share.worker,
                job_id: share.job_id.clone(),
                difficulty: share.difficulty,
                outcome: outcome.clone(),
                at: Instant::now(),
            });
            while self.window.len() > self.cap {
                self.window.pop_front();
            }
        }
    }

    pub fn window_len(&self) -> usize {
        self.window.len()
    }

    /// PPLNS stub: proportional (difficulty-weighted) credit across the shares
    /// currently in the window. Fractions sum to ~1.0; an empty window (or one
    /// with no positive weight) yields an empty map. A non-positive share
    /// difficulty is treated as unit weight so credit is never lost.
    pub fn pplns_credit(&self) -> HashMap<WorkerId, f64> {
        let mut per: HashMap<WorkerId, f64> = HashMap::new();
        let mut total = 0.0f64;
        for rec in &self.window {
            let w = if rec.difficulty > 0.0 { rec.difficulty } else { 1.0 };
            *per.entry(rec.worker).or_insert(0.0) += w;
            total += w;
        }
        if total <= 0.0 {
            return HashMap::new();
        }
        for v in per.values_mut() {
            *v /= total;
        }
        per
    }

    pub fn total_accepted(&self) -> u64 {
        self.total_accepted
    }
    pub fn total_rejected(&self) -> u64 {
        self.total_rejected
    }
    pub fn total_stale(&self) -> u64 {
        self.total_stale
    }
    pub fn total_duplicate(&self) -> u64 {
        self.total_duplicate
    }
    pub fn total_blocks(&self) -> u64 {
        self.total_blocks
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Eixo-2 seam (all no-ops in Sprint 1)
// ─────────────────────────────────────────────────────────────────────────

/// Stable call sites for Sprint-2 multi-tip DAG dispatch. Every method is a
/// no-op today; they exist so the pump does not need editing when Eixo-2
/// lands.
#[derive(Clone, Debug, Default)]
pub struct RouterHooks;

impl RouterHooks {
    pub fn new() -> Self {
        RouterHooks
    }

    /// Sprint-2 will steer distinct workers at distinct DAG tips. Inert now.
    pub fn on_tip_hint(&self, _hint: &TipHint) {}

    /// Optional block detection (e.g. an RPC cross-check). The Sprint-1
    /// default returns the outcome unchanged, so a solved block reads as
    /// `Accepted`; an override may upgrade it to [`ShareOutcome::Block`].
    ///
    /// TODO(sprint2): [LOW] wire real block detection by cross-checking an
    /// accepted submit against the node's JSON-RPC tip/height; until then
    /// `bloch_pool_blocks_found_total` is a stub that stays 0.
    pub fn classify_block(&self, outcome: ShareOutcome) -> ShareOutcome {
        outcome
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Small pure helpers (unit-tested)
// ─────────────────────────────────────────────────────────────────────────

/// Extract the JSON-RPC `id` from a raw request line, if it parses. Used to
/// correlate a forwarded `mining.submit` with the node's later
/// `SubmitResult` (both carry the same id — the proxy rewrites nothing).
fn extract_request_id(raw: &str) -> Option<Value> {
    serde_json::from_str::<RawRequest>(raw)
        .ok()
        .and_then(|r| r.id)
}

/// Normalize an optional JSON id to a stable string key. `5` → `"5"`,
/// `"abc"` → `"\"abc\""`, absent → `"null"`.
fn id_key(id: &Option<Value>) -> String {
    match id {
        Some(v) => v.to_string(),
        None => "null".to_string(),
    }
}

/// Whether an upstream error should trigger a reconnect rather than a
/// teardown. Transport-level failures are transient; protocol/config are not.
fn is_transient(e: &PoolError) -> bool {
    matches!(
        e,
        PoolError::Io(_) | PoolError::UpstreamClosed(_) | PoolError::Timeout(_)
    )
}

// ─────────────────────────────────────────────────────────────────────────
// Worker lifecycle
// ─────────────────────────────────────────────────────────────────────────

/// Full lifecycle of one worker. Spawned per accepted connection by the
/// server. Never panics; returns `Ok(())` after either side closes cleanly,
/// or `Err` on an unrecoverable transport/protocol fault.
pub async fn run_worker(
    mut down: DownstreamConn,
    cfg: Arc<ProxyConfig>,
    metrics: Arc<Metrics>,
    registry: Arc<ExtranonceRegistry>,
) -> Result<(), PoolError> {
    let worker = down.worker;

    // ── 1. Assemble the handshake from the miner's opening lines ──────────
    //
    // Bounded by cfg.handshake_timeout: a peer that connects and then stays
    // silent (or trickles bytes with no `\n`) must not pin this worker slot
    // forever — that is a trivial slowloris capacity-exhaustion DoS. On
    // elapse we drop the worker (the WorkerGuard releases the slot).
    let replay = match tokio::time::timeout(
        cfg.handshake_timeout,
        read_handshake(&mut down, worker),
    )
    .await
    {
        Ok(res) => res?,
        Err(_) => {
            return Err(PoolError::Timeout(format!(
                "{worker}: downstream handshake did not complete within {:?}",
                cfg.handshake_timeout
            )));
        }
    };

    // ── 2. Open the dedicated upstream (node assigns this worker an en1) ──
    // `connect` consumes the replay; keep a clone for later reconnects.
    let mut upstream =
        UpstreamConn::connect(cfg.clone(), metrics.clone(), worker, replay.clone()).await?;

    // Track this worker's extranonce1 in the process-wide collision guard.
    let mut wx = WorkerExtranonce::new(registry);
    wx.assign(&upstream.extranonce1, &metrics, worker);
    log::info!(
        "{worker}: upstream established (extranonce1={})",
        upstream.extranonce1
    );

    // The node's subscribe-result / notify prelude is buffered inside the
    // upstream and delivered by the first `upstream.read()` calls, so the
    // pump below forwards those raw lines downstream verbatim — no separate
    // handshake-replay step is needed here.

    // ── 3. Transparent bidirectional pump ────────────────────────────────
    let mut accounting = Accounting::new(&cfg);
    let hooks = RouterHooks::new();
    let mut current_difficulty = 0.0f64;
    let mut last_notify_raw: Option<Line> = None;
    // The miner's raw `mining.authorize` line, captured as it flows through
    // the pump. Replayed to the node after any upstream reconnect — a fresh
    // node session is Subscribed-but-NOT-Authorized, so without this every
    // post-reconnect submit is rejected (error 24).
    let mut authorize_line: Option<Line> = None;
    // Whether the miner sent `mining.extranonce.subscribe`; decides how a
    // reconnect that changes extranonce1 is surfaced downstream.
    let mut miner_wants_extranonce = false;
    // id_key -> pending submitted share, FIFO, capped.
    let mut pending: VecDeque<(String, Share)> = VecDeque::new();

    let keepalive = tokio::time::sleep(cfg.keepalive_idle);
    tokio::pin!(keepalive);

    loop {
        tokio::select! {
            // ── miner → node ────────────────────────────────────────────
            down_res = down.read() => {
                match down_res {
                    Ok(None) => {
                        log::info!("{worker}: downstream closed");
                        break;
                    }
                    Ok(Some(framed)) => {
                        let Framed { raw, parsed } = framed;

                        // Note interesting client messages BEFORE forwarding.
                        match &parsed {
                            ClientMsg::Authorize { .. } => {
                                authorize_line = Some(raw.clone());
                            }
                            ClientMsg::Passthrough => {
                                if crate::codec::method_of(&raw).as_deref()
                                    == Some(methods::EXTRANONCE_SUBSCRIBE)
                                {
                                    miner_wants_extranonce = true;
                                }
                            }
                            _ => {}
                        }

                        // Transparent: forward the exact bytes upstream. A
                        // transient write fault (node restarted) triggers the
                        // same reconnect path as an upstream read EOF, then we
                        // re-forward this very line — rather than tearing the
                        // miner down.
                        if let Err(e) = upstream.write(&raw).await {
                            if is_transient(&e) {
                                log::warn!("{worker}: upstream write failed ({e}) — reconnecting");
                                if !reconnect_upstream(
                                    &mut upstream, &mut down, &replay, &authorize_line,
                                    miner_wants_extranonce, &mut wx, &metrics, worker,
                                ).await? {
                                    break;
                                }
                                upstream.write(&raw).await?;
                                keepalive.as_mut().reset(
                                    tokio::time::Instant::now() + cfg.keepalive_idle,
                                );
                            } else {
                                return Err(e);
                            }
                        }

                        if let ClientMsg::Submit(mut share) = parsed {
                            // Fill in the fields only the router knows.
                            share.worker = worker;
                            share.difficulty = current_difficulty;
                            let key = id_key(&extract_request_id(&raw));
                            if pending.len() >= PENDING_CAP {
                                pending.pop_front();
                            }
                            pending.push_back((key, share));
                        }
                    }
                    Err(e) => {
                        log::warn!("{worker}: downstream read error: {e}");
                        return Err(e);
                    }
                }
            }

            // ── node → miner ────────────────────────────────────────────
            up_res = upstream.read() => {
                match up_res {
                    Ok(None) => {
                        log::warn!("{worker}: upstream EOF — reconnecting");
                        if !reconnect_upstream(
                            &mut upstream, &mut down, &replay, &authorize_line,
                            miner_wants_extranonce, &mut wx, &metrics, worker,
                        ).await? {
                            break;
                        }
                        keepalive
                            .as_mut()
                            .reset(tokio::time::Instant::now() + cfg.keepalive_idle);
                    }
                    Ok(Some(framed)) => {
                        let Framed { raw, parsed } = framed;
                        // Transparent: forward the exact bytes downstream.
                        down.write(&raw).await?;
                        keepalive
                            .as_mut()
                            .reset(tokio::time::Instant::now() + cfg.keepalive_idle);

                        match parsed {
                            ServerMsg::Notify(_job) => {
                                // Cache raw job for keepalive re-feed.
                                last_notify_raw = Some(raw);
                            }
                            ServerMsg::SetDifficulty(d) => {
                                current_difficulty = d;
                            }
                            ServerMsg::SubmitResult { id, outcome } => {
                                let key = id_key(&id);
                                let outcome = hooks.classify_block(outcome);
                                // A bare boolean ack (authorize / configure /
                                // suggest_difficulty) classifies as SubmitResult
                                // too, so only fold into counters + accounting
                                // when the id actually matches a submit we
                                // forwarded. Non-matching acks are forwarded
                                // downstream verbatim (already done) but NOT
                                // counted.
                                if let Some(pos) =
                                    pending.iter().position(|(k, _)| *k == key)
                                {
                                    metrics.record_outcome(&outcome);
                                    if let Some((_, share)) = pending.remove(pos) {
                                        accounting.record(&share, &outcome);
                                    }
                                } else {
                                    log::debug!(
                                        "{worker}: response id={key} matched no pending submit \
                                         (authorize/configure/suggest ack) — not counted"
                                    );
                                }
                            }
                            ServerMsg::SubscribeResult(_)
                            | ServerMsg::SetExtranonce { .. }
                            | ServerMsg::Passthrough => {}
                        }
                    }
                    Err(ref e) if is_transient(e) => {
                        log::warn!("{worker}: upstream error ({e}) — reconnecting");
                        if !reconnect_upstream(
                            &mut upstream, &mut down, &replay, &authorize_line,
                            miner_wants_extranonce, &mut wx, &metrics, worker,
                        ).await? {
                            break;
                        }
                        keepalive
                            .as_mut()
                            .reset(tokio::time::Instant::now() + cfg.keepalive_idle);
                    }
                    Err(e) => {
                        log::error!("{worker}: fatal upstream error: {e}");
                        return Err(e);
                    }
                }
            }

            // ── keepalive: re-feed last job to an idle miner ────────────
            _ = &mut keepalive => {
                // TODO(sprint2): [LOW] re-feeding the cached notify can
                // manufacture stale rejects if the node's template moved on
                // while both sides were idle. Prefer re-feeding only when the
                // cached job age < a staleness bound, and force clean_jobs=false
                // on the re-fed copy so it doesn't trigger a work reset.
                if let Some(job) = last_notify_raw.clone() {
                    log::debug!("{worker}: keepalive re-feed of last job");
                    down.write(&job).await?;
                }
                keepalive
                    .as_mut()
                    .reset(tokio::time::Instant::now() + cfg.keepalive_idle);
            }
        }
    }

    log::info!(
        "{worker}: worker finished (accepted={}, rejected={}, blocks={}, window={})",
        accounting.total_accepted(),
        accounting.total_rejected(),
        accounting.total_blocks(),
        accounting.window_len()
    );
    Ok(())
}

/// Re-establish the upstream after a transient fault, then bring the fresh
/// node session back to a working state:
///
///   1. re-dial + re-subscribe (via `upstream.reconnect`, which yields the
///      node's fresh `SubscribeResult`),
///   2. update the extranonce1 collision guard,
///   3. REPLAY `mining.authorize` upstream — a reconnected session is
///      Subscribed but NOT Authorized, so without this every subsequent
///      submit is rejected as unauthorized (error 24),
///   4. if the node handed out a NEW extranonce1, surface it downstream:
///      push `mining.set_extranonce` if the miner subscribed to extranonce
///      updates, otherwise signal the caller to DROP the downstream so the
///      miner reconnects and re-subscribes on a clean session (an ASIC that
///      never sent `mining.extranonce.subscribe` would otherwise keep mining
///      dead work on the stale extranonce1).
///
/// Returns `Ok(true)` to keep pumping, `Ok(false)` to drop the downstream.
#[allow(clippy::too_many_arguments)]
async fn reconnect_upstream(
    upstream: &mut UpstreamConn,
    down: &mut DownstreamConn,
    replay: &HandshakeReplay,
    authorize_line: &Option<Line>,
    miner_wants_extranonce: bool,
    wx: &mut WorkerExtranonce,
    metrics: &Metrics,
    worker: WorkerId,
) -> Result<bool, PoolError> {
    let old_en1 = upstream.extranonce1.clone();
    let sub = upstream.reconnect(replay).await?;

    // Refresh the collision guard with the (possibly new) extranonce1.
    wx.assign(&sub.extranonce1, metrics, worker);

    // Re-authorize: the fresh session is Subscribed but not Authorized.
    if let Some(auth) = authorize_line {
        upstream.write(auth).await?;
    } else {
        log::warn!(
            "{worker}: reconnected but no cached mining.authorize to replay — \
             submits may be rejected as unauthorized until the miner re-authorizes"
        );
    }

    // Propagate a changed extranonce1 to the miner, or drop so it re-subscribes.
    if sub.extranonce1 != old_en1 {
        if miner_wants_extranonce {
            let line = build_set_extranonce(&sub);
            down.write(&line).await?;
            log::info!(
                "{worker}: extranonce1 changed {old_en1}->{} on reconnect; sent set_extranonce",
                sub.extranonce1
            );
        } else {
            log::warn!(
                "{worker}: extranonce1 changed {old_en1}->{} on reconnect but miner did not \
                 subscribe to extranonce updates — dropping downstream so it re-subscribes",
                sub.extranonce1
            );
            return Ok(false);
        }
    }
    Ok(true)
}

/// Read the miner's opening lines until it subscribes, assembling the
/// [`HandshakeReplay`] the upstream will replay to the node. A
/// `mining.submit` before subscribe, an over-long preamble, or EOF are all
/// hard failures.
async fn read_handshake(
    down: &mut DownstreamConn,
    worker: WorkerId,
) -> Result<HandshakeReplay, PoolError> {
    let mut replay = HandshakeReplay::default();
    let mut preamble = 0usize;

    loop {
        match down.read().await {
            Ok(Some(framed)) => {
                let Framed { raw, parsed } = framed;
                match parsed {
                    ClientMsg::Configure { .. } => {
                        replay.configure = Some(raw);
                    }
                    ClientMsg::Subscribe { .. } => {
                        replay.subscribe = raw;
                        return Ok(replay);
                    }
                    ClientMsg::Submit(_) => {
                        return Err(PoolError::Protocol(format!(
                            "{worker}: mining.submit before mining.subscribe"
                        )));
                    }
                    // Authorize / suggest_difficulty / passthrough before
                    // subscribe are unusual; bound them and let the node
                    // reject if it must (they are not part of the replay).
                    _ => {
                        preamble += 1;
                        if preamble > PRE_SUBSCRIBE_CAP {
                            return Err(PoolError::Protocol(format!(
                                "{worker}: too many pre-subscribe lines"
                            )));
                        }
                    }
                }
            }
            Ok(None) => {
                return Err(PoolError::DownstreamClosed(format!(
                    "{worker}: closed before subscribe"
                )));
            }
            Err(e) => return Err(e),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ProxyConfig, Share, ShareOutcome, WorkerId};

    fn mk_share(worker: u64, job: &str, diff: f64) -> Share {
        Share {
            worker: WorkerId(worker),
            job_id: job.to_string(),
            extranonce2: "00000000".to_string(),
            ntime: "60000000".to_string(),
            nonce: "deadbeef".to_string(),
            difficulty: diff,
            submitted_at: Instant::now(),
        }
    }

    fn cfg_with_window(n: usize) -> ProxyConfig {
        ProxyConfig {
            pplns_window_shares: n,
            ..ProxyConfig::default()
        }
    }

    #[test]
    fn accepted_share_enters_window_and_totals() {
        let mut acc = Accounting::new(&cfg_with_window(10));
        acc.record(&mk_share(1, "j1", 4.0), &ShareOutcome::Accepted);
        assert_eq!(acc.window_len(), 1);
        assert_eq!(acc.total_accepted(), 1);
        assert_eq!(acc.total_rejected(), 0);
    }

    #[test]
    fn rejected_outcomes_touch_totals_not_window() {
        let mut acc = Accounting::new(&cfg_with_window(10));
        acc.record(&mk_share(1, "j1", 4.0), &ShareOutcome::Stale);
        acc.record(&mk_share(1, "j2", 4.0), &ShareOutcome::Duplicate);
        acc.record(&mk_share(1, "j3", 4.0), &ShareOutcome::LowDifficulty);
        acc.record(
            &mk_share(1, "j4", 4.0),
            &ShareOutcome::Rejected { code: 20, message: "nope".into() },
        );
        assert_eq!(acc.window_len(), 0);
        assert_eq!(acc.total_rejected(), 4);
        assert_eq!(acc.total_stale(), 1);
        assert_eq!(acc.total_duplicate(), 1);
        assert_eq!(acc.total_accepted(), 0);
    }

    #[test]
    fn block_counts_as_accepted_plus_block() {
        let mut acc = Accounting::new(&cfg_with_window(10));
        acc.record(&mk_share(7, "j1", 1.0), &ShareOutcome::Block);
        assert_eq!(acc.total_accepted(), 1);
        assert_eq!(acc.total_blocks(), 1);
        assert_eq!(acc.window_len(), 1);
    }

    #[test]
    fn window_is_capped_and_drops_oldest() {
        let mut acc = Accounting::new(&cfg_with_window(3));
        for i in 0..5 {
            acc.record(&mk_share(1, &format!("j{i}"), 1.0), &ShareOutcome::Accepted);
        }
        assert_eq!(acc.window_len(), 3);
        assert_eq!(acc.total_accepted(), 5);
    }

    #[test]
    fn zero_window_disables_retention_but_keeps_totals() {
        let mut acc = Accounting::new(&cfg_with_window(0));
        acc.record(&mk_share(1, "j1", 4.0), &ShareOutcome::Accepted);
        assert_eq!(acc.window_len(), 0);
        assert_eq!(acc.total_accepted(), 1);
        assert!(acc.pplns_credit().is_empty());
    }

    #[test]
    fn pplns_credit_is_difficulty_weighted_and_normalized() {
        let mut acc = Accounting::new(&cfg_with_window(100));
        // worker 1: 3 + 1 = 4 weight; worker 2: 4 weight → 50/50.
        acc.record(&mk_share(1, "j", 3.0), &ShareOutcome::Accepted);
        acc.record(&mk_share(1, "j", 1.0), &ShareOutcome::Accepted);
        acc.record(&mk_share(2, "j", 4.0), &ShareOutcome::Accepted);

        let credit = acc.pplns_credit();
        let c1 = *credit.get(&WorkerId(1)).unwrap();
        let c2 = *credit.get(&WorkerId(2)).unwrap();
        assert!((c1 - 0.5).abs() < 1e-9, "c1={c1}");
        assert!((c2 - 0.5).abs() < 1e-9, "c2={c2}");
        assert!(((c1 + c2) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn pplns_treats_nonpositive_difficulty_as_unit_weight() {
        let mut acc = Accounting::new(&cfg_with_window(100));
        acc.record(&mk_share(1, "j", 0.0), &ShareOutcome::Accepted);
        acc.record(&mk_share(2, "j", 0.0), &ShareOutcome::Accepted);
        let credit = acc.pplns_credit();
        assert!((credit.get(&WorkerId(1)).unwrap() - 0.5).abs() < 1e-9);
        assert!((credit.get(&WorkerId(2)).unwrap() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn empty_window_has_empty_credit() {
        let acc = Accounting::new(&cfg_with_window(100));
        assert!(acc.pplns_credit().is_empty());
    }

    #[test]
    fn hooks_default_is_identity_and_noop() {
        let hooks = RouterHooks::new();
        // classify_block returns the outcome unchanged in Sprint 1.
        assert_eq!(
            hooks.classify_block(ShareOutcome::Accepted),
            ShareOutcome::Accepted
        );
        assert_eq!(
            hooks.classify_block(ShareOutcome::Stale),
            ShareOutcome::Stale
        );
        // on_tip_hint must not panic.
        hooks.on_tip_hint(&TipHint::default());
    }

    #[test]
    fn id_key_normalizes_number_string_and_null() {
        assert_eq!(id_key(&Some(Value::from(5u64))), "5");
        assert_eq!(id_key(&Some(Value::from("abc"))), "\"abc\"");
        assert_eq!(id_key(&None), "null");
        // Distinct id kinds must not collide.
        assert_ne!(id_key(&Some(Value::from(5u64))), id_key(&Some(Value::from("5"))));
    }

    #[test]
    fn extract_request_id_reads_id_or_none() {
        let raw = r#"{"id":7,"method":"mining.submit","params":["w","j","00","60","de"]}"#;
        assert_eq!(extract_request_id(raw), Some(Value::from(7u64)));

        let raw_str = r#"{"id":"abc","method":"mining.submit","params":[]}"#;
        assert_eq!(extract_request_id(raw_str), Some(Value::from("abc")));

        // Garbage must not panic — just yields None.
        assert_eq!(extract_request_id("not json at all"), None);
        // Well-formed but id-less.
        assert_eq!(
            extract_request_id(r#"{"method":"mining.notify","params":[]}"#),
            None
        );
    }

    #[test]
    fn submit_result_correlates_to_pending_share_by_id() {
        // Mirror the pump's correlation logic in isolation.
        let mut pending: VecDeque<(String, Share)> = VecDeque::new();
        let id = Some(Value::from(42u64));
        pending.push_back((id_key(&id), mk_share(1, "j1", 8.0)));

        let mut acc = Accounting::new(&cfg_with_window(100));
        let key = id_key(&id);
        let pos = pending.iter().position(|(k, _)| *k == key).unwrap();
        let (_, share) = pending.remove(pos).unwrap();
        acc.record(&share, &ShareOutcome::Accepted);

        assert!(pending.is_empty());
        assert_eq!(acc.window_len(), 1);
        let credit = acc.pplns_credit();
        assert!((credit.get(&WorkerId(1)).unwrap() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn extranonce_registry_flags_collisions_and_counts_metric() {
        let reg = Arc::new(ExtranonceRegistry::new());
        let metrics = Metrics::new();

        // Worker A claims "aaaa" — unique.
        let mut a = WorkerExtranonce::new(reg.clone());
        a.assign("aaaa", &metrics, WorkerId(1));
        assert!(reg.contains("aaaa"));
        assert_eq!(metrics.snapshot().extranonce1_collisions, 0);

        // Worker B is handed the SAME "aaaa" — collision counted, A keeps slot.
        let mut b = WorkerExtranonce::new(reg.clone());
        b.assign("aaaa", &metrics, WorkerId(2));
        assert_eq!(metrics.snapshot().extranonce1_collisions, 1);
        assert!(reg.contains("aaaa"));

        // B dropping must NOT evict A's still-live claim.
        drop(b);
        assert!(reg.contains("aaaa"), "B's drop wrongly released A's extranonce1");

        // A dropping releases it.
        drop(a);
        assert!(!reg.contains("aaaa"));
    }

    #[test]
    fn extranonce_reassign_moves_the_claim() {
        let reg = Arc::new(ExtranonceRegistry::new());
        let metrics = Metrics::new();
        let mut w = WorkerExtranonce::new(reg.clone());

        w.assign("1111", &metrics, WorkerId(1));
        assert!(reg.contains("1111"));

        // Reconnect hands out a fresh extranonce1: old released, new claimed.
        w.assign("2222", &metrics, WorkerId(1));
        assert!(!reg.contains("1111"));
        assert!(reg.contains("2222"));
        assert_eq!(metrics.snapshot().extranonce1_collisions, 0);

        // Re-assigning the SAME value is a no-op (no self-collision).
        w.assign("2222", &metrics, WorkerId(1));
        assert_eq!(metrics.snapshot().extranonce1_collisions, 0);
        assert!(reg.contains("2222"));
    }

    #[test]
    fn build_set_extranonce_is_valid_notification() {
        let sub = SubscribeResult {
            extranonce1: "cafebabe".to_string(),
            extranonce2_size: 4,
        };
        let line = build_set_extranonce(&sub);
        // Must classify back as a SetExtranonce carrying the fresh values.
        let framed = crate::codec::classify_server(&line).expect("valid json");
        match framed.parsed {
            ServerMsg::SetExtranonce { extranonce1, extranonce2_size } => {
                assert_eq!(extranonce1, "cafebabe");
                assert_eq!(extranonce2_size, 4);
            }
            other => panic!("expected SetExtranonce, got {other:?}"),
        }
    }

    #[test]
    fn is_transient_classifies_reconnectable_errors() {
        assert!(is_transient(&PoolError::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "x"
        ))));
        assert!(is_transient(&PoolError::UpstreamClosed("eof".into())));
        assert!(is_transient(&PoolError::Timeout("slow".into())));
        assert!(!is_transient(&PoolError::Protocol("bad".into())));
        assert!(!is_transient(&PoolError::Config("bad".into())));
        assert!(!is_transient(&PoolError::DownstreamClosed("bye".into())));
    }
}
