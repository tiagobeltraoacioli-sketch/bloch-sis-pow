// SPDX-License-Identifier: AGPL-3.0-or-later

//! Operational metrics + health endpoint for the Genesis-4 node.
//!
//! ## Why this exists (audit C-R6-2)
//!
//! Observability regressed to ZERO across the PoS migration: the retired
//! Genesis-3 node had a full Prometheus stack
//! (`legacy/genesis3-node/src/metrics/`), the pool proxy has one
//! (`pool-proxy/src/metrics.rs`), and the binary the live chain actually runs
//! had nothing — no `/health`, no counters, no way to alert on the incidents
//! the fleet has already hit for real: OOM/restart loops, a validator that
//! boots but never signs, disk-full, finality stalls, nodes silently behind
//! the wall clock, the 21-minute mute replay window.
//!
//! ## Shape
//!
//! Same conventions as `pool-proxy/src/metrics.rs`, same server discipline as
//! `rpc.rs`: no external HTTP crate, blocking `std::net`, one thread per
//! connection, bounded reads, `Connection: close`. Series are `bloch_pos_*`
//! (the proxy's are `bloch_pool_*`, the G3 node's were `bloch_*`).
//!
//! The registry is a process-wide `static` of const-initialised atomics
//! rather than an `Arc` threaded through every constructor. That is a
//! deliberate trade: the engine has dozens of test constructors and this
//! module must never force consensus code to change shape to be observed.
//! Every write is a relaxed atomic store/add — nothing here synchronises
//! anything, decides anything, or can fail.
//!
//! ## What this must never become
//!
//! A read layer only. It observes committed state and process events; it must
//! never feed a value BACK into consensus, gate a duty, or grow a write
//! endpoint. The server answers GET and nothing else.
//!
//! ## Health contract (for systemd/uptime probes and the fleet monitor)
//!
//! `GET /health` answers `200 {"status":"ok",...}` when the consensus thread
//! has proven itself alive recently (its slot loop stamps
//! [`NodeMetrics::heartbeat_unix`] every turn, and turns are bounded at
//! 500 ms), and `503 {"status":"stalled",...}` when that stamp is older than
//! [`HEALTH_STALE_SECS`]. A booting node that is still replaying its block
//! log has never stamped at all and reports `503 {"status":"starting"}` —
//! which is exactly right for a readiness probe: the RPC is mute during
//! replay too (the 2026-08-21 incident), and this is the first endpoint that
//! can say so from the outside.
//!
//! `GET /metrics` is the Prometheus text exposition. Everything `/health`
//! decides on is also exported there, so alerting can be richer than the
//! binary ok/stalled — `behind_by_slots`, `is_syncing`, peer counts, epochs
//! since finality advanced, and the incident counters.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// `/health` reports `stalled` when the engine's heartbeat is older than
/// this. The slot loop stamps it at least every 500 ms (`recv_timeout` is
/// clamped to 500 ms), so 30 s of silence means the consensus thread is
/// wedged, not busy.
///
/// R3 M-5: this threshold ALONE used to decide `stalled`, and that premise is
/// false under RPC load — `EngineEvent::Rpc` is drained on the SAME loop that
/// stamps the heartbeat (`engine.rs`'s metrics-turn block runs once per
/// outer-loop iteration, before waiting on the next batch of events), so a
/// burst of heavy queries that takes longer than 30 s to work through leaves
/// the heartbeat stale while the node is doing exactly what it was asked.
/// See [`NodeMetrics::health`] for the corroborated verdict this now feeds;
/// this constant keeps its old meaning as the floor under
/// `last_applied_unix`'s age, and as the sole signal when a caller has never
/// populated the slot-progress gauges at all (a bare test registry, say).
pub const HEALTH_STALE_SECS: u64 = 30;

/// `/health`'s slot-progress corroboration (R3 M-5): even with a fresh
/// heartbeat, a head more than this many slots behind a LIVE computation of
/// the wall clock (`now - genesis_unix`, divided by `slot_secs` — not the
/// stored `wall_slot` gauge, which a truly wedged engine thread would freeze
/// right alongside the heartbeat) means this node has genuinely stopped
/// making consensus progress. Four slots is a small multiple of ordinary
/// proposal/network jitter — enough grace to absorb a legitimate RPC burst
/// (which the heartbeat-only check above would flag as an urgent 30 s
/// heartbeat problem) without masking a real stall, which needs BOTH this
/// lag and a stale `last_applied_unix` to fire (see `health`).
pub const HEALTH_MAX_SLOT_LAG: u64 = 4;

/// Socket read/write timeout — same rationale as `rpc.rs::IO_TIMEOUT`, but
/// shorter: a scrape is a GET with no body.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest request head accepted. A Prometheus scrape's head is <200 bytes.
const MAX_HEAD_BYTES: usize = 8 * 1024;

/// Connections served concurrently. A scraper plus a probe plus slack; past
/// this the listener answers 503 and closes rather than spawning threads.
const MAX_CONNECTIONS: usize = 16;

/// The process-wide registry. Const-initialised, so incrementing from
/// anywhere in the binary is one relaxed atomic op with no setup and no
/// locking; see the module doc for why this is a `static` and not an `Arc`.
pub static NODE: NodeMetrics = NodeMetrics::new();

/// Every counter and gauge the node exports. Counters end in `_total` and
/// only ever go up (within one process); gauges are point-in-time samples the
/// slot loop refreshes every turn.
pub struct NodeMetrics {
    // ── Incident counters — one per failure class the fleet actually hit ──
    /// Incremented exactly once, at boot. Under systemd `Restart=always` a
    /// crash/OOM loop shows up as this counter resetting to 1 over and over —
    /// `resets(bloch_pos_process_starts_total[1h])` IS the restart alarm.
    pub process_starts_total: AtomicU64,
    /// Block-log or index writes that failed (`ENOSPC` = the disk-full
    /// incident). The append failure is fatal by design (`engine.rs` exits
    /// rather than diverging RAM from disk), so this counts the moments
    /// BEFORE the exit — a scrape that catches 1 here, or a restart loop with
    /// `data_dir_fs_free_bytes` at zero, is the diagnosis.
    pub store_append_failures_total: AtomicU64,
    /// A keystore was loaded but the node cannot act as that validator (not
    /// in the committed registry / pending activation). The "validator was
    /// down and nothing said so" incident: the process is healthy, follows
    /// the chain, and signs nothing.
    pub validator_not_started_total: AtomicU64,
    /// Transitions into a finality stall (finalized epoch stopped advancing
    /// for [`crate::engine`]'s configured window while the wall clock moved
    /// on). Counts EDGES, not scrapes: a 3-hour stall is one increment.
    pub finality_stalls_total: AtomicU64,
    /// Blocks applied to the canonical chain (replay included).
    pub blocks_applied_total: AtomicU64,
    /// Blocks rejected by validation.
    pub blocks_rejected_total: AtomicU64,
    /// Equivocations captured by the gossip pool (two attestations, one
    /// validator, one slot). Logged loudly at the capture site (`engine.rs`'s
    /// `apply_decision`) since 2026-08's fix wave; this is the same event,
    /// exported so it can be alerted on rather than only grepped for.
    pub equivocations_observed_total: AtomicU64,
    /// Reorgs refused because they would have cut canonical history below
    /// this node's finality latch (R3 M-1). Mirrors
    /// `Engine::finality_rewinds_refused` every turn — see that field's doc
    /// in `engine.rs` for why the latch exists and why an unexported counter
    /// made the 6 -> 4 -> 2 -> 0 rewind a silent self-partition risk.
    pub finality_rewinds_refused_total: AtomicU64,

    // ── Gauges — sampled by the slot loop every turn ──
    /// Slot of the node's committed head.
    pub head_slot: AtomicU64,
    /// Slot the wall clock says it is.
    pub wall_slot: AtomicU64,
    /// `wall_slot - head_slot` (saturating). The "node is quietly behind"
    /// signal; on a healthy node this is 0 or 1.
    pub behind_by_slots: AtomicU64,
    /// Committed finalized epoch.
    pub finalized_epoch: AtomicU64,
    /// Committed justified epoch.
    pub justified_epoch: AtomicU64,
    /// Peers across whichever transports are live (devnet + libp2p summed).
    pub peer_count: AtomicU64,
    /// Devnet transport peers, or 0 if that transport is not running. There
    /// is no way to tell "not running" from "running with zero peers" here —
    /// unlike `net::Net::peer_counts`, which answers with `Option` — because
    /// a gauge has no absent state; a node running neither devnet nor libp2p
    /// is not a shape this binary supports, so the ambiguity is theoretical.
    pub peer_count_devnet: AtomicU64,
    /// Production (libp2p) transport peers, or 0 if not running. Same caveat
    /// as `peer_count_devnet`.
    pub peer_count_p2p: AtomicU64,
    /// Mempool entries.
    pub mempool_size: AtomicU64,
    /// 1 while the node considers itself syncing (behind and requesting
    /// blocks), else 0.
    pub is_syncing: AtomicU64,
    /// 1 when a keystore is loaded AND its key matches the committed registry
    /// (the node performs duties); 0 on an observer or a pending-activation
    /// validator. `avg_over_time` of this against the roster is the
    /// "validator-not-started" alarm.
    pub validator_active: AtomicU64,
    /// Unix seconds of the last time the finalized epoch advanced (stamped at
    /// boot to the boot time, so the gauge is never 0 on a live node).
    pub last_finality_advance_unix: AtomicU64,
    /// Unix seconds of the slot loop's most recent turn. Part of the liveness
    /// signal (see [`NodeMetrics::health`]); 0 until the loop first runs —
    /// i.e. for the whole replay window.
    pub heartbeat_unix: AtomicU64,
    /// Free bytes on the filesystem holding the data dir (0 if unreadable).
    /// The disk-full early warning; sampled once per slot.
    pub data_dir_fs_free_bytes: AtomicU64,
    /// Unix seconds the process started. Prometheus'
    /// `process_start_time_seconds` convention, exported under our prefix.
    pub process_start_unix: AtomicU64,
    /// Unix seconds of the last time a block was applied to the canonical
    /// chain — set from `Engine::last_applied_ms`, which moves on
    /// `apply_canonical` and `do_reorg` alone, never on a mere turn of the
    /// slot loop. R3 M-5's slot-progress signal: unlike `heartbeat_unix`,
    /// this cannot be kept fresh by RPC traffic alone, only by real consensus
    /// progress.
    pub last_applied_unix: AtomicU64,
    /// This node's manifest genesis time, in Unix seconds. Set once, at
    /// boot, and never again — used by `/health` to compute the CURRENT wall
    /// slot independently of the (possibly stale, if the engine thread is
    /// truly wedged) `wall_slot` gauge above. 0 means "never configured",
    /// which `health` treats as "no slot-progress data available" and falls
    /// back to heartbeat-only liveness (see `health`'s doc).
    pub genesis_unix: AtomicU64,
    /// This manifest's slot duration, in seconds (`max(1)` already applied at
    /// the write site — see `engine.rs`'s own `max(1)` precedent on the same
    /// division). Set once, at boot, alongside `genesis_unix`.
    pub slot_secs: AtomicU64,
    /// 1 when the on-disk keystore is sealed (`BPOSKEY2`), 0 when it is
    /// plaintext (`BPOSKEY1`) or absent (observer mode — nothing to seal).
    /// Read directly from the file's magic at boot, without depending on
    /// `keys.rs`'s internals, so a fleet upgrading ahead of the
    /// `LEAK_RECOVERY` flag day (which refuses a plaintext keystore) can
    /// alert on this BEFORE the flag day makes a plaintext key fatal.
    pub keystore_sealed: AtomicU64,
    /// Blocks parked rather than admitted to the canonical set right now:
    /// orphans waiting on a missing parent, plus branches parked by the
    /// finality latch (R3 M-1) rather than deleted. Zero on a healthy,
    /// caught-up node; sustained growth is the same "sync trouble" the
    /// orphan pool's own counters diagnose, made visible without a log grep.
    pub blocks_parked: AtomicU64,
    /// Network events reserved in the engine queue budget and not yet handled
    /// (`net::QueueBudget`, external audit 2026-09-07 O06). Bounded by
    /// `net::ENGINE_QUEUE_CAP`; sustained at the cap means the engine is not
    /// keeping up with its transports.
    pub net_queue_inflight: AtomicU64,
    /// Bytes reserved in the engine queue budget and not yet handled. Bounded
    /// by `net::ENGINE_QUEUE_BYTES_CAP` (64 MiB): the queue's whole
    /// contribution to resident memory, by construction.
    pub net_queue_bytes: AtomicU64,
    /// Blocks shed at admission because the budget was full. Any non-zero
    /// rate on a caught-up node is worth a look; on a replaying node it is
    /// expected and harmless (the sync pump asks again).
    pub net_shed_blocks_total: AtomicU64,
    /// Attestations shed at admission (re-gossiped by their authors).
    pub net_shed_attestations_total: AtomicU64,
    /// Transactions shed at admission (re-broadcast by their wallets). The
    /// first class to be shed under pressure, by policy.
    pub net_shed_transactions_total: AtomicU64,
}

impl NodeMetrics {
    pub const fn new() -> Self {
        Self {
            process_starts_total: AtomicU64::new(0),
            store_append_failures_total: AtomicU64::new(0),
            validator_not_started_total: AtomicU64::new(0),
            finality_stalls_total: AtomicU64::new(0),
            blocks_applied_total: AtomicU64::new(0),
            blocks_rejected_total: AtomicU64::new(0),
            equivocations_observed_total: AtomicU64::new(0),
            finality_rewinds_refused_total: AtomicU64::new(0),
            head_slot: AtomicU64::new(0),
            wall_slot: AtomicU64::new(0),
            behind_by_slots: AtomicU64::new(0),
            finalized_epoch: AtomicU64::new(0),
            justified_epoch: AtomicU64::new(0),
            peer_count: AtomicU64::new(0),
            peer_count_devnet: AtomicU64::new(0),
            peer_count_p2p: AtomicU64::new(0),
            mempool_size: AtomicU64::new(0),
            is_syncing: AtomicU64::new(0),
            validator_active: AtomicU64::new(0),
            last_finality_advance_unix: AtomicU64::new(0),
            heartbeat_unix: AtomicU64::new(0),
            data_dir_fs_free_bytes: AtomicU64::new(0),
            process_start_unix: AtomicU64::new(0),
            last_applied_unix: AtomicU64::new(0),
            genesis_unix: AtomicU64::new(0),
            slot_secs: AtomicU64::new(0),
            keystore_sealed: AtomicU64::new(0),
            blocks_parked: AtomicU64::new(0),
            net_queue_inflight: AtomicU64::new(0),
            net_queue_bytes: AtomicU64::new(0),
            net_shed_blocks_total: AtomicU64::new(0),
            net_shed_attestations_total: AtomicU64::new(0),
            net_shed_transactions_total: AtomicU64::new(0),
        }
    }

    /// One relaxed increment. Counters only.
    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// One relaxed store. Gauges only.
    pub fn set(gauge: &AtomicU64, v: u64) {
        gauge.store(v, Ordering::Relaxed);
    }

    fn get(&self, g: &AtomicU64) -> u64 {
        g.load(Ordering::Relaxed)
    }

    /// Render the Prometheus text exposition format. A pure projection of the
    /// atomics — testable without a socket, same principle as
    /// `rpc.rs`'s formatting free functions.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(4096);
        let mut series = |name: &str, kind: &str, help: &str, v: u64| {
            out.push_str("# HELP ");
            out.push_str(name);
            out.push(' ');
            out.push_str(help);
            out.push_str("\n# TYPE ");
            out.push_str(name);
            out.push(' ');
            out.push_str(kind);
            out.push('\n');
            out.push_str(name);
            out.push(' ');
            out.push_str(&v.to_string());
            out.push('\n');
        };
        series(
            "bloch_pos_process_starts_total",
            "counter",
            "Process boots; resets to 1 on every restart, so Prometheus resets() is the restart/OOM-loop alarm",
            self.get(&self.process_starts_total),
        );
        series(
            "bloch_pos_store_append_failures_total",
            "counter",
            "Block-log/index writes that failed (ENOSPC = disk full); the node exits after the first",
            self.get(&self.store_append_failures_total),
        );
        series(
            "bloch_pos_validator_not_started_total",
            "counter",
            "Boots where a keystore was present but the validator could not arm (not in registry / pending activation)",
            self.get(&self.validator_not_started_total),
        );
        series(
            "bloch_pos_finality_stalls_total",
            "counter",
            "Transitions into a finality stall (finalized epoch stopped advancing against the wall clock)",
            self.get(&self.finality_stalls_total),
        );
        series(
            "bloch_pos_blocks_applied_total",
            "counter",
            "Blocks applied to the canonical chain, replay included",
            self.get(&self.blocks_applied_total),
        );
        series(
            "bloch_pos_blocks_rejected_total",
            "counter",
            "Blocks rejected by validation",
            self.get(&self.blocks_rejected_total),
        );
        series(
            "bloch_pos_equivocations_observed_total",
            "counter",
            "Equivocations captured by the gossip pool (two attestations, one validator, one slot)",
            self.get(&self.equivocations_observed_total),
        );
        series(
            "bloch_pos_finality_rewinds_refused_total",
            "counter",
            "Reorgs refused because they would cut canonical history below this node's finality latch (R3 M-1)",
            self.get(&self.finality_rewinds_refused_total),
        );
        series(
            "bloch_pos_head_slot",
            "gauge",
            "Slot of the committed head",
            self.get(&self.head_slot),
        );
        series(
            "bloch_pos_wall_slot",
            "gauge",
            "Slot the wall clock says it is",
            self.get(&self.wall_slot),
        );
        series(
            "bloch_pos_behind_by_slots",
            "gauge",
            "wall_slot minus head_slot; 0-1 on a healthy node",
            self.get(&self.behind_by_slots),
        );
        series(
            "bloch_pos_finalized_epoch",
            "gauge",
            "Committed finalized epoch",
            self.get(&self.finalized_epoch),
        );
        series(
            "bloch_pos_justified_epoch",
            "gauge",
            "Committed justified epoch",
            self.get(&self.justified_epoch),
        );
        series(
            "bloch_pos_peer_count",
            "gauge",
            "Connected peers across live transports",
            self.get(&self.peer_count),
        );
        series(
            "bloch_pos_peer_count_devnet",
            "gauge",
            "Connected peers on the devnet transport (0 if not running)",
            self.get(&self.peer_count_devnet),
        );
        series(
            "bloch_pos_peer_count_p2p",
            "gauge",
            "Connected peers on the production libp2p transport (0 if not running)",
            self.get(&self.peer_count_p2p),
        );
        series(
            "bloch_pos_mempool_size",
            "gauge",
            "Mempool entries",
            self.get(&self.mempool_size),
        );
        series(
            "bloch_pos_is_syncing",
            "gauge",
            "1 while behind and requesting blocks, else 0",
            self.get(&self.is_syncing),
        );
        series(
            "bloch_pos_validator_active",
            "gauge",
            "1 when this node performs validator duties, 0 on an observer or unarmed validator",
            self.get(&self.validator_active),
        );
        series(
            "bloch_pos_last_finality_advance_unix",
            "gauge",
            "Unix seconds when the finalized epoch last advanced",
            self.get(&self.last_finality_advance_unix),
        );
        series(
            "bloch_pos_heartbeat_unix",
            "gauge",
            "Unix seconds of the slot loop's latest turn; 0 during boot/replay",
            self.get(&self.heartbeat_unix),
        );
        series(
            "bloch_pos_data_dir_fs_free_bytes",
            "gauge",
            "Free bytes on the filesystem holding the data dir",
            self.get(&self.data_dir_fs_free_bytes),
        );
        series(
            "bloch_pos_process_start_unix",
            "gauge",
            "Unix seconds the process started",
            self.get(&self.process_start_unix),
        );
        series(
            "bloch_pos_last_applied_unix",
            "gauge",
            "Unix seconds a block was last applied to the canonical chain (R3 M-5 slot-progress signal)",
            self.get(&self.last_applied_unix),
        );
        series(
            "bloch_pos_keystore_sealed",
            "gauge",
            "1 if the on-disk keystore is sealed (BPOSKEY2), 0 if plaintext or absent",
            self.get(&self.keystore_sealed),
        );
        series(
            "bloch_pos_blocks_parked",
            "gauge",
            "Blocks parked rather than admitted: orphans plus finality-latch-refused branches (R3 M-1)",
            self.get(&self.blocks_parked),
        );
        series(
            "bloch_pos_net_queue_inflight",
            "gauge",
            "Network events reserved in the engine queue budget and not yet handled (cap 4096; audit 2026-09-07 O06)",
            self.get(&self.net_queue_inflight),
        );
        series(
            "bloch_pos_net_queue_bytes",
            "gauge",
            "Bytes reserved in the engine queue budget and not yet handled (cap 64 MiB; audit 2026-09-07 O06)",
            self.get(&self.net_queue_bytes),
        );
        series(
            "bloch_pos_net_shed_blocks_total",
            "counter",
            "Blocks shed at queue admission because the budget was full (recoverable: the sync pump asks again)",
            self.get(&self.net_shed_blocks_total),
        );
        series(
            "bloch_pos_net_shed_attestations_total",
            "counter",
            "Attestations shed at queue admission because the budget was full (recoverable: re-gossiped)",
            self.get(&self.net_shed_attestations_total),
        );
        series(
            "bloch_pos_net_shed_transactions_total",
            "counter",
            "Transactions shed at queue admission because the budget was full (recoverable: re-broadcast); shed first by policy",
            self.get(&self.net_shed_transactions_total),
        );
        out
    }

    /// The `/health` verdict: `(http_status, body)`. Pure function of the
    /// atomics and `now`, so every threshold below is testable without
    /// sleeping.
    ///
    /// R3 M-5: `stalled` used to be decided by `heartbeat_unix` alone, and
    /// that premise is false under RPC load (see [`HEALTH_STALE_SECS`]'s
    /// updated doc). It is now corroborated by slot progress — a real
    /// consensus signal a heavy query burst does not move — before 503 is
    /// served for anything but "never started at all":
    ///
    /// 1. `heartbeat_unix == 0`: never started a turn — booting/replaying.
    ///    Unchanged from before; this is the state the mute-replay incident
    ///    needed a `/health` for in the first place.
    /// 2. Otherwise, **stalled** requires BOTH: the head is more than
    ///    [`HEALTH_MAX_SLOT_LAG`] slots behind a wall-clock slot computed
    ///    LIVE from `genesis_unix`/`slot_secs` (not the stored `wall_slot`
    ///    gauge, which a truly wedged engine thread would freeze right
    ///    alongside the heartbeat and so could never show growing lag), AND
    ///    `last_applied_unix` — which only a real `apply_canonical`/`do_reorg`
    ///    moves, never a mere turn of the loop — is older than
    ///    [`HEALTH_STALE_SECS`]. A node merely busy draining RPC calls keeps
    ///    both of those fresh (or at worst mildly behind, within the slack)
    ///    even while its heartbeat momentarily lags; a node that has
    ///    genuinely wedged fails BOTH, and fails them by a growing margin the
    ///    longer it stays wedged, since `now_unix` keeps moving even when
    ///    nothing else does.
    /// 3. If `genesis_unix` was never configured (0) — a bare test registry
    ///    that only ever stamps `heartbeat_unix`, say — there is no
    ///    slot-progress data to corroborate with, so this falls back to the
    ///    OLD, heartbeat-only rule: exactly [`HEALTH_STALE_SECS`] alone.
    pub fn health(&self, now_unix: u64) -> (u16, String) {
        let hb = self.get(&self.heartbeat_unix);
        let (status, word) = if hb == 0 {
            // The slot loop has never run: booting/replaying. Not ready, and
            // says so — this is the endpoint the mute-replay incident needed.
            (503u16, "starting")
        } else if self.stalled(now_unix) {
            (503, "stalled")
        } else if self.get(&self.is_syncing) == 1 {
            // Alive but catching up: readiness probes should not route
            // queries here yet, but systemd must NOT restart it either —
            // 200 keeps liveness happy, the field tells readiness the truth.
            (200, "syncing")
        } else {
            (200, "ok")
        };
        let body = format!(
            "{{\"status\":\"{word}\",\"head_slot\":{},\"behind_by_slots\":{},\
             \"finalized_epoch\":{},\"peer_count\":{},\"is_syncing\":{},\
             \"validator_active\":{},\"heartbeat_age_secs\":{}}}",
            self.get(&self.head_slot),
            self.get(&self.behind_by_slots),
            self.get(&self.finalized_epoch),
            self.get(&self.peer_count),
            self.get(&self.is_syncing) == 1,
            self.get(&self.validator_active) == 1,
            if hb == 0 { now_unix } else { now_unix.saturating_sub(hb) },
        );
        (status, body)
    }

    /// The slot-progress-corroborated stall check described on
    /// [`NodeMetrics::health`]. Split out so each half is independently
    /// testable.
    fn stalled(&self, now_unix: u64) -> bool {
        let genesis = self.get(&self.genesis_unix);
        if genesis == 0 {
            // No slot-progress data was ever configured: fall back to the
            // pre-existing heartbeat-only rule so a bare test registry (or
            // any caller that only ever stamps `heartbeat_unix`) keeps its
            // old meaning exactly.
            return now_unix.saturating_sub(self.get(&self.heartbeat_unix)) > HEALTH_STALE_SECS;
        }
        let slot_secs = self.get(&self.slot_secs).max(1);
        // Computed LIVE from `now_unix` and the two boot-time constants —
        // deliberately NOT read from the `wall_slot` gauge, which a wedged
        // engine thread would freeze at the same instant it stops updating
        // `head_slot`, hiding the very lag this is meant to catch.
        // cannot divide by zero: slot_secs is `.max(1)` above.
        #[allow(clippy::arithmetic_side_effects)]
        let wall_now = now_unix.saturating_sub(genesis) / slot_secs;
        let behind_slots = wall_now.saturating_sub(self.get(&self.head_slot));
        let last_applied = self.get(&self.last_applied_unix);
        // Never applied anything: cannot be corroborated as healthy, so this
        // reads as maximally stale rather than as evidence of health — fail
        // closed, per the "no unwarranted trust in absent data" rule.
        let applied_age = if last_applied == 0 {
            u64::MAX
        } else {
            now_unix.saturating_sub(last_applied)
        };
        behind_slots > HEALTH_MAX_SLOT_LAG && applied_age > HEALTH_STALE_SECS
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Sample free bytes on the filesystem holding `path`. Unix-only (the fleet
/// is Linux; dev boxes are macOS — both have `statvfs`); 0 on error rather
/// than an error type, because a metric sampler must never take the node down.
pub fn fs_free_bytes(path: &std::path::Path) -> u64 {
    use std::os::unix::ffi::OsStrExt;
    let Ok(cpath) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return 0;
    };
    // SAFETY: statvfs writes into the zeroed struct we hand it and reads only
    // the NUL-terminated path; both live on this stack frame.
    unsafe {
        let mut vfs: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(cpath.as_ptr(), &mut vfs) == 0 {
            // f_bavail = blocks available to unprivileged users — the number
            // that matters, since the node does not run as root.
            (vfs.f_bavail as u64).saturating_mul(vfs.f_frsize as u64)
        } else {
            0
        }
    }
}

// ─── The HTTP server ────────────────────────────────────────────────────────

/// Serve `GET /health` and `GET /metrics` on `bind:port`. Same accept-thread
/// shape as `rpc::serve`; GET-only, no body read, so the request handling is
/// a fraction of the RPC's. Returns the bound address (port 0 supported, for
/// tests).
pub fn serve(bind_addr: &str, port: u16, metrics: &'static NodeMetrics) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind((bind_addr, port))?;
    let local = listener.local_addr()?;
    let live = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut sock) = conn else { continue };
            if live.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                live.fetch_sub(1, Ordering::SeqCst);
                let _ = respond(&mut sock, 503, "text/plain", "too many connections");
                continue;
            }
            let live = live.clone();
            thread::spawn(move || {
                serve_connection(&mut sock, metrics);
                live.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    Ok(local)
}

fn serve_connection(sock: &mut TcpStream, metrics: &NodeMetrics) {
    let _ = sock.set_read_timeout(Some(IO_TIMEOUT));
    let _ = sock.set_write_timeout(Some(IO_TIMEOUT));

    // Read the request head, bounded. The body (there should be none on a
    // GET) is ignored: we answer and close.
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        if buf.len() > MAX_HEAD_BYTES {
            let _ = respond(sock, 431, "text/plain", "request header too large");
            return;
        }
        match sock.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };

    let head = String::from_utf8_lossy(&buf[..head_end]);
    let request_line = head.split("\r\n").next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let verb = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    if !verb.eq_ignore_ascii_case("GET") {
        let _ = respond(sock, 405, "text/plain", "GET only");
        return;
    }
    // Route on the path WITHOUT any query string.
    let path = path.split('?').next().unwrap_or("");
    match path {
        "/health" | "/health/" => {
            let (status, body) = metrics.health(now_unix());
            let _ = respond(sock, status, "application/json", &body);
        }
        "/metrics" | "/metrics/" | "/" => {
            let _ = respond(
                sock,
                200,
                "text/plain; version=0.0.4; charset=utf-8",
                &metrics.render(),
            );
        }
        _ => {
            let _ = respond(sock, 404, "text/plain", "try /health or /metrics");
        }
    }
}

fn respond(sock: &mut TcpStream, status: u16, ctype: &str, body: &str) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    sock.write_all(head.as_bytes())?;
    sock.write_all(body.as_bytes())?;
    sock.flush()
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Mutation-style: an increment must be VISIBLE in the rendered text. If
    /// any `inc` call or the render line for the series is deleted, this
    /// fails.
    #[test]
    fn counter_increment_changes_render() {
        let m = NodeMetrics::new();
        assert!(m.render().contains("bloch_pos_store_append_failures_total 0"));
        NodeMetrics::inc(&m.store_append_failures_total);
        NodeMetrics::inc(&m.store_append_failures_total);
        let text = m.render();
        assert!(
            text.contains("bloch_pos_store_append_failures_total 2"),
            "increments not reflected: {text}"
        );
        // Every series the finding names must exist in the exposition.
        for name in [
            "bloch_pos_process_starts_total",   // OOM/restart
            "bloch_pos_validator_not_started_total",
            "bloch_pos_data_dir_fs_free_bytes", // disk-full
            "bloch_pos_finality_stalls_total",
            "bloch_pos_peer_count",
            "bloch_pos_behind_by_slots",
            "bloch_pos_is_syncing",
            // R3 metrics-gap follow-up: equivocations, the finality-latch
            // refusal counter, per-transport peer counts, the sealed-keystore
            // gauge and the parked-blocks gauge.
            "bloch_pos_equivocations_observed_total",
            "bloch_pos_finality_rewinds_refused_total",
            "bloch_pos_peer_count_devnet",
            "bloch_pos_peer_count_p2p",
            "bloch_pos_keystore_sealed",
            "bloch_pos_blocks_parked",
            "bloch_pos_last_applied_unix",
            "bloch_pos_net_queue_inflight",
            "bloch_pos_net_queue_bytes",
            "bloch_pos_net_shed_blocks_total",
            "bloch_pos_net_shed_attestations_total",
            "bloch_pos_net_shed_transactions_total",
        ] {
            assert!(text.contains(name), "missing series {name}");
            assert!(text.contains(&format!("# TYPE {name}")), "missing TYPE for {name}");
        }
    }

    /// The health verdict is a pure function of heartbeat age and sync state.
    #[test]
    fn health_verdicts() {
        let m = NodeMetrics::new();
        // Never heartbeaten: booting/replaying => 503 starting.
        let (s, body) = m.health(1_000_000);
        assert_eq!(s, 503);
        assert!(body.contains("\"status\":\"starting\""), "{body}");

        // Fresh heartbeat => 200 ok.
        NodeMetrics::set(&m.heartbeat_unix, 1_000_000);
        let (s, body) = m.health(1_000_000 + 5);
        assert_eq!(s, 200);
        assert!(body.contains("\"status\":\"ok\""), "{body}");

        // Fresh heartbeat but syncing => 200 syncing (liveness must not
        // restart a catching-up node).
        NodeMetrics::set(&m.is_syncing, 1);
        let (s, body) = m.health(1_000_000 + 5);
        assert_eq!(s, 200);
        assert!(body.contains("\"status\":\"syncing\""), "{body}");
        NodeMetrics::set(&m.is_syncing, 0);

        // Stale heartbeat => 503 stalled, even past the sync check. No
        // slot-progress data was ever configured on `m`, so this exercises
        // the heartbeat-only fallback (`genesis_unix == 0`) — unchanged from
        // before this fix.
        let (s, body) = m.health(1_000_000 + HEALTH_STALE_SECS + 1);
        assert_eq!(s, 503);
        assert!(body.contains("\"status\":\"stalled\""), "{body}");
    }

    /// R3 M-5: with slot-progress data configured, a stale heartbeat ALONE
    /// must NOT report `stalled` — this is the exact false positive the
    /// finding names ("`/health` reports `stalled` when the node is merely
    /// busy"): a heavy burst of RPC calls pauses the metrics-turn block (so
    /// `heartbeat_unix` goes stale) without the chain actually falling
    /// behind. Real slot lag AND a stale `last_applied_unix` together are
    /// what must flip it to `stalled` — either alone must not.
    #[test]
    fn health_does_not_stall_on_heartbeat_alone_when_slot_progress_is_fine() {
        let m = NodeMetrics::new();
        let genesis = 1_000_000u64;
        let slot_secs = 30u64;
        NodeMetrics::set(&m.genesis_unix, genesis);
        NodeMetrics::set(&m.slot_secs, slot_secs);

        // `now` is slot 100 by construction (genesis + 100*30s). The node is
        // caught up (head == wall slot) and applied a block 10s ago — both
        // fresh — but its heartbeat has NOT ticked in far longer than
        // HEALTH_STALE_SECS, simulating a long synchronous RPC burst that
        // blocked the metrics-turn block without stalling consensus.
        let now = genesis + 100 * slot_secs;
        NodeMetrics::set(&m.head_slot, 100);
        NodeMetrics::set(&m.last_applied_unix, now - 10);
        NodeMetrics::set(&m.heartbeat_unix, now - HEALTH_STALE_SECS - 1_000);

        let (s, body) = m.health(now);
        assert_eq!(s, 200, "a busy-but-progressing node must not be reported stalled: {body}");
        assert!(body.contains("\"status\":\"ok\""), "{body}");
    }

    /// R3 M-5, the other half: genuine lack of progress — the head is far
    /// behind the LIVE wall slot AND no block has been applied in a long
    /// time — must still report `stalled`, with a FRESH heartbeat, proving
    /// this is not merely "heartbeat-only, renamed": a node whose event loop
    /// is ticking (heartbeat fresh) but whose consensus has genuinely wedged
    /// is exactly the case slot-progress corroboration must still catch.
    #[test]
    fn health_stalls_on_genuine_slot_lag_even_with_fresh_heartbeat() {
        let m = NodeMetrics::new();
        let genesis = 1_000_000u64;
        let slot_secs = 30u64;
        NodeMetrics::set(&m.genesis_unix, genesis);
        NodeMetrics::set(&m.slot_secs, slot_secs);

        let now = genesis + 100 * slot_secs; // wall slot 100
        NodeMetrics::set(&m.head_slot, 10); // 90 slots behind — way past HEALTH_MAX_SLOT_LAG
        NodeMetrics::set(&m.last_applied_unix, now - 10 * 3600); // nothing applied in hours
        NodeMetrics::set(&m.heartbeat_unix, now); // heartbeat itself is perfectly fresh

        let (s, body) = m.health(now);
        assert_eq!(s, 503, "real, sustained slot lag must still be reported stalled: {body}");
        assert!(body.contains("\"status\":\"stalled\""), "{body}");
    }

    /// A truly wedged engine thread: every gauge the thread itself writes
    /// (`head_slot`, `wall_slot`, `last_applied_unix`, `heartbeat_unix`) froze
    /// at the moment it died. `health` must still detect this GROWING lag as
    /// real time passes, because it computes the current wall slot LIVE from
    /// `genesis_unix`/`slot_secs`+`now_unix` rather than trusting the frozen
    /// `wall_slot` gauge — a wedged thread cannot keep that gauge honest
    /// either, so trusting it would hide the exact failure this exists to
    /// catch.
    #[test]
    fn health_detects_a_wedged_engine_via_live_wall_clock() {
        let m = NodeMetrics::new();
        let genesis = 1_000_000u64;
        let slot_secs = 30u64;
        NodeMetrics::set(&m.genesis_unix, genesis);
        NodeMetrics::set(&m.slot_secs, slot_secs);

        // The thread died at slot 100, having JUST applied a block and
        // ticked its heartbeat.
        let died_at = genesis + 100 * slot_secs;
        NodeMetrics::set(&m.head_slot, 100);
        NodeMetrics::set(&m.last_applied_unix, died_at);
        NodeMetrics::set(&m.heartbeat_unix, died_at);
        // Right at the moment of death, nothing looks wrong yet.
        assert_eq!(m.health(died_at).0, 200, "must not be stalled at the instant of death");

        // An hour of real time passes. Every gauge above is still frozen —
        // nothing in this process touches them again — but `now_unix` has
        // moved, so the LIVE wall slot has moved with it while `head_slot`
        // has not.
        let (s, body) = m.health(died_at + 3600);
        assert_eq!(s, 503, "a wedged engine must eventually be detected: {body}");
        assert!(body.contains("\"status\":\"stalled\""), "{body}");
    }

    /// End to end over a real socket: /health answers, and a simulated
    /// incident (a store append failure) increments a counter that the next
    /// /metrics scrape reports. This is the acceptance test the finding asks
    /// for. Uses the process-global registry — the same one the node wires —
    /// and asserts on the DELTA so other tests sharing the static cannot
    /// break it.
    #[test]
    fn health_returns_and_counter_increments_over_http() {
        let addr = serve("127.0.0.1", 0, &NODE).expect("bind");

        let get = |path: &str| -> (u16, String) {
            let mut sock = TcpStream::connect(addr).expect("connect");
            write!(sock, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
            let mut resp = String::new();
            sock.read_to_string(&mut resp).expect("read");
            let status: u16 = resp
                .split(' ')
                .nth(1)
                .and_then(|s| s.parse().ok())
                .expect("status line");
            let body = resp
                .split("\r\n\r\n")
                .nth(1)
                .unwrap_or("")
                .to_string();
            (status, body)
        };

        // /health returns (503 starting here: no engine loop stamps the
        // global heartbeat inside a unit test).
        let (status, body) = get("/health");
        assert_eq!(status, 503);
        assert!(body.contains("\"status\":\"starting\""), "{body}");

        // And with a heartbeat it flips to 200 — proving the verdict is read
        // from the same registry the endpoint serves.
        NodeMetrics::set(&NODE.heartbeat_unix, now_unix());
        let (status, body) = get("/health");
        assert_eq!(status, 200, "{body}");

        let read_counter = |body: &str| -> u64 {
            body.lines()
                .find(|l| l.starts_with("bloch_pos_store_append_failures_total "))
                .and_then(|l| l.split(' ').nth(1))
                .and_then(|v| v.parse().ok())
                .expect("counter series present")
        };
        let before = read_counter(&get("/metrics").1);

        // Simulated incident: the exact call site engine.rs runs on a failed
        // block-log append.
        NodeMetrics::inc(&NODE.store_append_failures_total);

        let after = read_counter(&get("/metrics").1);
        assert_eq!(after, before + 1, "counter did not increment across scrape");

        // Unknown path and non-GET are refused, not misrouted.
        assert_eq!(get("/nope").0, 404);
        let mut sock = TcpStream::connect(addr).unwrap();
        write!(sock, "POST /metrics HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n").unwrap();
        let mut resp = String::new();
        sock.read_to_string(&mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 405"), "{resp}");
    }

    /// R3 M-5's second half: `/health` and `/metrics` must be served off the
    /// accept thread so a slow scraper cannot stall accepts. A dedicated
    /// static registry (not the shared `NODE`) so this cannot race the
    /// counter-delta test above.
    ///
    /// A connection that never finishes sending its request head is held
    /// open by `serve_connection` — reading forever inside `IO_TIMEOUT` —
    /// with no bytes sent back. If the accept loop and connection handling
    /// shared one thread, that alone would stop this listener from ever
    /// accepting a second connection; `serve` spawns a thread per accepted
    /// connection specifically so it does not.
    #[test]
    fn a_slow_connection_does_not_stall_other_connections() {
        static SLOW_TEST_METRICS: NodeMetrics = NodeMetrics::new();
        let addr = serve("127.0.0.1", 0, &SLOW_TEST_METRICS).expect("bind");

        // The "slow scraper": connected, but never sends a complete request
        // head — `serve_connection` is left blocked reading it.
        let slow = TcpStream::connect(addr).expect("connect (slow)");

        // A second, well-behaved client must still be accepted and served
        // promptly, independent of the slow one.
        let mut fast = TcpStream::connect(addr).expect("connect (fast)");
        fast.set_read_timeout(Some(Duration::from_secs(2))).expect("set timeout");
        write!(fast, "GET /health HTTP/1.1\r\nHost: x\r\n\r\n").expect("write request");
        let mut resp = String::new();
        fast.read_to_string(&mut resp)
            .expect("the fast connection must be served without waiting on the slow one");
        assert!(resp.starts_with("HTTP/1.1 "), "{resp}");

        drop(slow);
    }

    /// The sampler answers for a real path and never errors.
    #[test]
    fn fs_free_bytes_samples() {
        let free = fs_free_bytes(std::path::Path::new("/"));
        assert!(free > 0, "statvfs on / returned 0");
        assert_eq!(fs_free_bytes(std::path::Path::new("/nonexistent-zzz")), 0);
    }
}
