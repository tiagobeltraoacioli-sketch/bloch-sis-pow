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
//! node's response ([`ShareOutcome`]) into [`Metrics`], the pool-wide PPLNS
//! ledger ([`crate::pplns::PplnsLedger`]) and the block-found hook.
//!
//! ### Sprint-2 module split (was inline in Sprint 1)
//!
//! Two pieces that lived in this file in Sprint 1 now live in sibling modules
//! so the four Sprint-2 devs edit disjoint files:
//!
//!   * the extranonce1 collision guard (`ExtranonceRegistry` /
//!     `WorkerExtranonce`) plus the new *re-dial-until-unique* helper
//!     [`claim_unique`] → `crate::extranonce` (G2);
//!   * per-worker `Accounting` → the pool-wide [`crate::pplns::PplnsLedger`]
//!     (G1), so payout-share can span every worker rather than being trapped
//!     inside each `run_worker`.
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
//! //
//! // crate::extranonce::claim_unique(&mut upstream, &replay, &mut wx, &cfg,
//! //     &metrics, worker, initial) -> Result<(), PoolError>
//! //   (assigns wx to a not-in-use extranonce1, re-dialing the upstream up
//! //    to cfg.extranonce_redial_max times; falls back to log+count+serve)
//! //
//! // crate::pplns::PplnsLedger::record(worker, job_id, difficulty, outcome)
//! ```
//!
//! Keepalive is kept entirely inside the router as a router-owned
//! `tokio::time::Sleep` rather than a `downstream.keepalive_tick()` branch:
//! `select!` cannot hold two `&mut down` borrows at once (read + keepalive),
//! so folding the idle timer into the router is the borrow-clean equivalent.
//! byte counters and worker connect/disconnect counters are owned by the conn
//! and server modules respectively; the router only records share outcomes.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use serde_json::Value;

use crate::downstream::DownstreamConn;
use crate::upstream::UpstreamConn;

use crate::extranonce::{claim_unique, ExtranonceRegistry, WorkerExtranonce};
use crate::pplns::PplnsLedger;
use crate::vardiff::Vardiff;
use crate::validator;

use crate::types::{
    methods, ClientMsg, Framed, HandshakeReplay, Line, Metrics, PoolError,
    ProxyConfig, RawRequest, ServerMsg, Share, ShareOutcome, SubscribeResult, TipHint, WorkerId,
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
// Downstream extranonce reassignment helper
// ─────────────────────────────────────────────────────────────────────────

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
// Eixo-2 seam (all no-ops in Sprint 1; G3 observability annotates it)
// ─────────────────────────────────────────────────────────────────────────

/// Stable call sites for Sprint-2 multi-tip DAG dispatch. Every method is a
/// no-op today; they exist so the pump does not need editing when Eixo-2
/// lands. Sprint 2's HONEST verdict is that pool-influenced multi-tip is not
/// achievable without a node change (the node's stratum/RPC build every job's
/// parents from ALL current DAG tips and accept no parent selection), so this
/// seam is fed by the read-only DAG-frontier observer (`crate::rpc`) as
/// OBSERVABILITY only, never as steering.
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

/// Render a JSON-RPC `id` for a proxy-authored response line. `5` → `5`,
/// `"abc"` → `"abc"` (quoted), absent → `null`.
fn id_json(id: &Option<Value>) -> String {
    match id {
        Some(v) => v.to_string(),
        None => "null".to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Worker lifecycle
// ─────────────────────────────────────────────────────────────────────────

/// Full lifecycle of one worker. Spawned per accepted connection by the
/// server. Never panics; returns `Ok(())` after either side closes cleanly,
/// or `Err` on an unrecoverable transport/protocol fault.
///
/// `registry` is the process-wide extranonce1 collision guard; `ledger` is
/// the pool-wide PPLNS ledger every worker records accepted shares into.
pub async fn run_worker(
    mut down: DownstreamConn,
    cfg: Arc<ProxyConfig>,
    metrics: Arc<Metrics>,
    registry: Arc<ExtranonceRegistry>,
    ledger: Arc<PplnsLedger>,
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

    // Track this worker's extranonce1 in the process-wide collision guard,
    // re-dialing the upstream (bounded by cfg.extranonce_redial_max) until the
    // node hands a not-in-use value, or falling back to log+count+serve. On
    // initial connect (`true`) the re-dial preserves the subscribe-result
    // prelude so the miner still inherits the FINAL extranonce1 downstream.
    let mut wx = WorkerExtranonce::new(registry);
    claim_unique(&mut upstream, &replay, &mut wx, &cfg, &metrics, worker, true).await?;
    log::info!(
        "{worker}: upstream established (extranonce1={})",
        upstream.extranonce1
    );

    // The node's subscribe-result / notify prelude is buffered inside the
    // upstream and delivered by the first `upstream.read()` calls, so the
    // pump below forwards those raw lines downstream verbatim — no separate
    // handshake-replay step is needed here.

    // ── 3. Transparent bidirectional pump (the NODE is authoritative) ─────
    //
    // Every miner line — INCLUDING `mining.submit` (with its optional 6th
    // version-rolling param) — is forwarded to the node VERBATIM; the node
    // validates each submit and its accept/reject flows back as a
    // `SubmitResult`, which the proxy RELAYS downstream and folds into
    // metrics/PPLNS. The proxy performs NO local header reconstruction and NO
    // local accept/reject. Its only editorial acts are (a) suppressing the
    // node's `set_difficulty` in favour of announcing its OWN per-worker
    // vardiff share-target, and (b) answering `mining.configure` in the
    // handshake (see `read_handshake`) so version-rolling ASICs subscribe.
    let hooks = RouterHooks::new();
    let mut vardiff = Vardiff::from_cfg(&cfg);
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

                        // Transparent: forward the EXACT bytes upstream. For a
                        // `mining.submit` this INCLUDES the optional 6th
                        // version-rolling param, which lives verbatim in `raw`
                        // — so an AsicBoost/BIP310 miner's rolled nVersion
                        // reaches the node and the node reconstructs the header
                        // it ACTUALLY hashed (dropping the 6th param made the
                        // node rebuild with the static version and reject). A
                        // transient write fault triggers the same reconnect-
                        // and-re-forward path as an upstream read EOF rather
                        // than tearing the miner down.
                        if let Err(e) = upstream.write(&raw).await {
                            if is_transient(&e) {
                                log::warn!("{worker}: upstream write failed ({e}) — reconnecting");
                                if !reconnect_upstream(
                                    &mut upstream, &mut down, &replay, &authorize_line,
                                    miner_wants_extranonce, &mut wx, &cfg, &metrics, worker,
                                ).await? {
                                    break;
                                }
                                // A fresh upstream re-announces our difficulty.
                                vardiff.reset_announced();
                                upstream.write(&raw).await?;
                                keepalive.as_mut().reset(
                                    tokio::time::Instant::now() + cfg.keepalive_idle,
                                );
                            } else {
                                return Err(e);
                            }
                        }

                        // A forwarded `mining.submit` is remembered so the
                        // node's later `SubmitResult` (same JSON-RPC id) can be
                        // correlated → counted → relayed. The NODE — not the
                        // proxy — decides accept/reject.
                        if let ClientMsg::Submit(mut share) = parsed {
                            share.worker = worker;
                            share.difficulty = vardiff.current();
                            let key = id_key(&extract_request_id(&raw));
                            if pending.len() >= PENDING_CAP {
                                pending.pop_front();
                            }
                            pending.push_back((key, share));
                            keepalive.as_mut().reset(
                                tokio::time::Instant::now() + cfg.keepalive_idle,
                            );
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
                            miner_wants_extranonce, &mut wx, &cfg, &metrics, worker,
                        ).await? {
                            break;
                        }
                        vardiff.reset_announced();
                        keepalive
                            .as_mut()
                            .reset(tokio::time::Instant::now() + cfg.keepalive_idle);
                    }
                    Ok(Some(framed)) => {
                        let Framed { raw, parsed } = framed;
                        keepalive
                            .as_mut()
                            .reset(tokio::time::Instant::now() + cfg.keepalive_idle);

                        // Forward PER classification: everything reaches the
                        // miner EXCEPT the node's `set_difficulty`, which the
                        // proxy suppresses in favour of its own vardiff target.
                        match parsed {
                            ServerMsg::Notify(_job) => {
                                // Announce OUR vardiff share-target before the
                                // first job so the miner mines at the proxy's
                                // target, not the node's default.
                                if vardiff.needs_announce() {
                                    down.write(&vardiff.set_difficulty_line()).await?;
                                    vardiff.mark_announced();
                                }
                                down.write(&raw).await?; // forward the real job
                                last_notify_raw = Some(raw);
                            }
                            ServerMsg::SetDifficulty(_d) => {
                                // SUPPRESS: we serve our own per-worker vardiff.
                            }
                            ServerMsg::SubmitResult { id, outcome } => {
                                let key = id_key(&id);
                                let outcome = hooks.classify_block(outcome);
                                if let Some(pos) =
                                    pending.iter().position(|(k, _)| *k == key)
                                {
                                    // Correlates to a submit we forwarded: the
                                    // NODE decided accept/reject. RELAY its
                                    // verdict downstream verbatim, then fold the
                                    // node's outcome into metrics + PPLNS, and
                                    // drive vardiff off the node's acceptance.
                                    down.write(&raw).await?;
                                    metrics.record_outcome(&outcome);
                                    if let Some((_, share)) = pending.remove(pos) {
                                        ledger.record(
                                            worker, &share.job_id, share.difficulty, &outcome,
                                        );
                                        if matches!(
                                            outcome,
                                            ShareOutcome::Accepted | ShareOutcome::Block
                                        ) && vardiff
                                            .on_accepted(Instant::now(), share.difficulty)
                                            .is_some()
                                        {
                                            down.write(&vardiff.set_difficulty_line()).await?;
                                            vardiff.mark_announced();
                                        }
                                    }
                                } else {
                                    // A bare boolean ack (authorize / configure /
                                    // suggest_difficulty) matches no pending
                                    // submit: forward downstream verbatim but do
                                    // NOT count it as a share.
                                    down.write(&raw).await?;
                                }
                            }
                            ServerMsg::SetExtranonce { .. } => {
                                // Forward the reassignment downstream verbatim.
                                down.write(&raw).await?;
                            }
                            ServerMsg::SubscribeResult(_)
                            | ServerMsg::Passthrough => {
                                down.write(&raw).await?;
                            }
                        }
                    }
                    Err(ref e) if is_transient(e) => {
                        log::warn!("{worker}: upstream error ({e}) — reconnecting");
                        if !reconnect_upstream(
                            &mut upstream, &mut down, &replay, &authorize_line,
                            miner_wants_extranonce, &mut wx, &cfg, &metrics, worker,
                        ).await? {
                            break;
                        }
                        vardiff.reset_announced();
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

    log::info!("{worker}: worker finished");
    Ok(())
}

/// Re-establish the upstream after a transient fault, then bring the fresh
/// node session back to a working state:
///
///   1. re-dial + re-subscribe (via `upstream.reconnect`, which yields the
///      node's fresh `SubscribeResult`),
///   2. claim a not-in-use extranonce1 in the collision guard, re-dialing
///      (bounded) if the node handed one already live (via [`claim_unique`]),
///   3. REPLAY `mining.authorize` upstream — a reconnected session is
///      Subscribed but NOT Authorized, so without this every subsequent
///      submit is rejected as unauthorized (error 24),
///   4. if the effective extranonce1 CHANGED, surface it downstream:
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
    cfg: &Arc<ProxyConfig>,
    metrics: &Arc<Metrics>,
    worker: WorkerId,
) -> Result<bool, PoolError> {
    let old_en1 = upstream.extranonce1.clone();
    upstream.reconnect(replay).await?;

    // Refresh the collision guard with the (possibly new) extranonce1, and
    // re-dial for a unique one if it collided. This may itself re-dial the
    // upstream, so read the EFFECTIVE extranonce1 back off `upstream`
    // afterwards rather than trusting the pre-claim reconnect result.
    claim_unique(upstream, replay, wx, cfg, metrics, worker, false).await?;
    let new_en1 = upstream.extranonce1.clone();

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
    if new_en1 != old_en1 {
        if miner_wants_extranonce {
            let sub = SubscribeResult {
                extranonce1: new_en1.clone(),
                extranonce2_size: upstream.extranonce2_size,
            };
            let line = build_set_extranonce(&sub);
            down.write(&line).await?;
            log::info!(
                "{worker}: extranonce1 changed {old_en1}->{new_en1} on reconnect; sent set_extranonce"
            );
        } else {
            log::warn!(
                "{worker}: extranonce1 changed {old_en1}->{new_en1} on reconnect but miner did not \
                 subscribe to extranonce updates — dropping downstream so it re-subscribes"
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
                    ClientMsg::Configure { id, .. } => {
                        // AsicBoost / BIP310 version-rolling miners send
                        // `mining.configure` FIRST and BLOCK until they receive
                        // the server's response before they will send
                        // `mining.subscribe`. Previously this arm only stashed
                        // the line for later upstream replay and looped straight
                        // back to `down.read()` waiting for a subscribe that the
                        // miner is (correctly) refusing to send — so the
                        // handshake hung and every version-rolling ASIC timed out
                        // with 0 shares. Answer the configure here so the miner
                        // proceeds, offering the pool-wide version-rolling mask.
                        let resp = format!(
                            r#"{{"id":{},"result":{{"version-rolling":true,"version-rolling.mask":"{:08x}"}},"error":null}}"#,
                            id_json(&id),
                            validator::VERSION_ROLLING_MASK,
                        );
                        down.write(&resp).await?;
                        // Still keep the raw line so the upstream session
                        // negotiates version-rolling with the node too.
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
    use crate::types::{Share, ShareOutcome, WorkerId};
    use std::time::Instant;

    fn mk_share(worker: u64, job: &str, diff: f64) -> Share {
        Share {
            worker: WorkerId(worker),
            job_id: job.to_string(),
            extranonce2: "00000000".to_string(),
            ntime: "60000000".to_string(),
            nonce: "deadbeef".to_string(),
            version: None,
            difficulty: diff,
            submitted_at: Instant::now(),
        }
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
        // Mirror the pump's correlation logic in isolation: a SubmitResult is
        // folded into accounting only when its id matches a pending submit.
        let mut pending: VecDeque<(String, Share)> = VecDeque::new();
        let id = Some(Value::from(42u64));
        pending.push_back((id_key(&id), mk_share(1, "j1", 8.0)));

        // Matching id removes exactly the pending share.
        let key = id_key(&id);
        let pos = pending.iter().position(|(k, _)| *k == key).unwrap();
        let (_, share) = pending.remove(pos).unwrap();
        assert_eq!(share.worker, WorkerId(1));
        assert!(pending.is_empty());

        // A non-matching id (e.g. an authorize ack) finds nothing to fold.
        pending.push_back((id_key(&Some(Value::from(1u64))), mk_share(1, "j2", 8.0)));
        let ack_key = id_key(&Some(Value::from(99u64)));
        assert!(pending.iter().position(|(k, _)| *k == ack_key).is_none());
        assert_eq!(pending.len(), 1);
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

    #[tokio::test]
    async fn handshake_answers_configure_then_reads_subscribe() {
        use crate::types::{Metrics, ProxyConfig, WorkerId};
        use std::sync::Arc;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::{TcpListener, TcpStream};

        // A wired-up miner<->proxy socket pair, proxy side wrapped in a
        // DownstreamConn just like the accept loop does.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let miner = TcpStream::connect(addr).await.expect("connect");
        let (server, _) = listener.accept().await.expect("accept");
        let mut down = DownstreamConn::new(
            server,
            WorkerId(7),
            Arc::new(ProxyConfig::default()),
            Arc::new(Metrics::new()),
        );

        // Drive a version-rolling ASIC: send configure, WAIT for the reply
        // (as a real AsicBoost miner does) and only THEN send subscribe.
        let miner_task = tokio::spawn(async move {
            let (rd, mut wr) = miner.into_split();
            let mut lines = BufReader::new(rd).lines();

            wr.write_all(
                b"{\"id\":1,\"method\":\"mining.configure\",\
                  \"params\":[[\"version-rolling\"],{\"version-rolling.mask\":\"ffffffff\"}]}\n",
            )
            .await
            .unwrap();
            wr.flush().await.unwrap();

            // The proxy MUST answer configure before the miner will subscribe.
            let resp = lines.next_line().await.unwrap().expect("configure reply");
            assert!(resp.contains("\"version-rolling\":true"), "resp={resp}");
            assert!(resp.contains("\"version-rolling.mask\":\"1fffe000\""), "resp={resp}");
            assert!(resp.contains("\"id\":1"), "resp={resp}");

            wr.write_all(
                b"{\"id\":2,\"method\":\"mining.subscribe\",\"params\":[\"cgminer/4.11\"]}\n",
            )
            .await
            .unwrap();
            wr.flush().await.unwrap();
        });

        // With the configure reply in place the handshake completes:
        // configure is captured for upstream replay, subscribe terminates it.
        let replay = read_handshake(&mut down, WorkerId(7))
            .await
            .expect("handshake completes");
        assert!(replay.configure.is_some(), "configure captured for replay");
        assert!(
            replay.subscribe.contains("mining.subscribe"),
            "subscribe line captured: {}",
            replay.subscribe
        );
        miner_task.await.unwrap();
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
