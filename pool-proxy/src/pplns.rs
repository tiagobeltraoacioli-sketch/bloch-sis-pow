//! pplns — the POOL-WIDE, thread-safe PPLNS ledger.
//!
//! Sprint 1 shipped a *per-worker* `Accounting` struct that lived inside each
//! `run_worker` future (see the Sprint-1 `router.rs`). Because every worker
//! owned a private share window, cross-worker payout credit could never be
//! computed: PPLNS is by definition a *pool-wide* sliding window of the most
//! recent N shares, spanning all miners. Sprint 2 (G1) replaces that stub with
//! a single [`PplnsLedger`] shared as `Arc<PplnsLedger>` by every worker task.
//!
//! ### Design
//!
//! * **Interior mutability.** One `Arc<PplnsLedger>` is handed to all worker
//!   tasks; each calls [`record`](PplnsLedger::record) through `&self`. The
//!   state lives behind a `Mutex<Inner>`, so there is no outer lock and no
//!   `&mut` threading through the router pump.
//!
//! * **Bounded sliding window.** Only *accepted* shares (`Accepted` / `Block`)
//!   are retained, difficulty-weighted. The window is bounded by BOTH:
//!     - `cfg.pplns_window_shares` — a hard count cap (0 disables retention),
//!     - `cfg.pplns_window_secs`   — a time bound in seconds (0 disables the
//!       time bound). On each `record` the front is evicted while the window
//!       is over the count cap OR the front share is older than the time bound.
//!
//! * **Difficulty-weighted, normalized credit.** [`credit`](PplnsLedger::credit)
//!   returns each worker's share of the window as a fraction that sums to ~1.0.
//!   A non-positive difficulty is treated as **unit weight** so a miner is
//!   never silently dropped from the payout split. An empty (or zero-weight)
//!   window yields an empty credit vector.
//!
//! * **Totals count everything.** Every outcome — accepted, rejected, stale,
//!   duplicate, block — is folded into the pool-wide [`LedgerTotals`],
//!   independent of whether it entered the retention window.
//!
//! No custody, no payout sending: this is *accounting only*, shaped so a
//! downstream payout job can consume [`credit`](PplnsLedger::credit) verbatim.
//! `std` only, no new dependencies, and no method panics on any input.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::types::{ProxyConfig, ShareOutcome, WorkerId};

// ─────────────────────────────────────────────────────────────────────────
// Public value types (consumed by the D2 router + D5 metrics endpoint)
// ─────────────────────────────────────────────────────────────────────────

/// One worker's slice of the current PPLNS window.
///
/// `fraction` is the normalized payout share (all workers' fractions sum to
/// ~1.0); `weight` is that worker's raw difficulty-weighted contribution and
/// `shares` is the count of retained accepted shares behind it.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct PplnsCredit {
    pub worker: WorkerId,
    pub shares: u64,
    pub weight: f64,
    pub fraction: f64,
}

/// Cheap snapshot of the window's shape, for metrics/observability.
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct PplnsSnapshot {
    pub window_len: usize,
    pub total_weight: f64,
    pub distinct_workers: usize,
    pub window_cap: usize,
}

/// Pool-wide lifetime counters. Every share outcome ever recorded is folded
/// here, regardless of retention.
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct LedgerTotals {
    pub accepted: u64,
    pub rejected: u64,
    pub stale: u64,
    pub duplicate: u64,
    pub blocks: u64,
}

// ─────────────────────────────────────────────────────────────────────────
// Internal window entry + guarded state
// ─────────────────────────────────────────────────────────────────────────

/// One retained accepted share. `weight` is the pre-computed contribution
/// (difficulty, or `1.0` for a non-positive difficulty) so credit math never
/// has to re-derive it; `at` is the retention timestamp for the time bound.
#[derive(Clone, Debug)]
struct Entry {
    worker: WorkerId,
    weight: f64,
    at: Instant,
}

/// All mutable ledger state, guarded by a single `Mutex` in [`PplnsLedger`].
#[derive(Debug)]
struct Inner {
    window: VecDeque<Entry>,
    /// Count cap (`cfg.pplns_window_shares`); 0 disables retention entirely.
    cap: usize,
    /// Time bound in seconds (`cfg.pplns_window_secs`); 0 disables the bound.
    window_secs: u64,
    totals: LedgerTotals,
}

impl Inner {
    /// Fold one outcome into the lifetime totals. Mirrors the node/metrics
    /// outcome taxonomy exactly (accepted, block, stale, duplicate, other
    /// rejects).
    fn bump_totals(&mut self, outcome: &ShareOutcome) {
        match outcome {
            ShareOutcome::Accepted => self.totals.accepted += 1,
            ShareOutcome::Block => {
                self.totals.accepted += 1;
                self.totals.blocks += 1;
            }
            ShareOutcome::Stale => {
                self.totals.rejected += 1;
                self.totals.stale += 1;
            }
            ShareOutcome::Duplicate => {
                self.totals.rejected += 1;
                self.totals.duplicate += 1;
            }
            ShareOutcome::LowDifficulty | ShareOutcome::Rejected { .. } => {
                self.totals.rejected += 1;
            }
        }
    }

    /// Evict from the front while the window is over the count cap OR the
    /// front share is older than the time bound. Both bounds are independent;
    /// either can be disabled with 0.
    fn evict(&mut self, now: Instant) {
        // Count cap. When `cap == 0` retention is off — this drains any
        // residue (there should be none, since `record` never pushes then).
        while self.window.len() > self.cap {
            self.window.pop_front();
        }
        // Time bound. The window is append-ordered, so the front is always the
        // oldest; stop at the first entry still inside the bound.
        if self.window_secs > 0 {
            let bound = Duration::from_secs(self.window_secs);
            while let Some(front) = self.window.front() {
                // `saturating_duration_since` never panics even if a caller
                // supplied a `now` earlier than an entry's timestamp.
                if now.saturating_duration_since(front.at) > bound {
                    self.window.pop_front();
                } else {
                    break;
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// The ledger
// ─────────────────────────────────────────────────────────────────────────

/// Pool-wide PPLNS ledger. Construct one, wrap it in `Arc`, and share it
/// across every worker task; all mutation goes through `&self`.
#[derive(Debug)]
pub struct PplnsLedger {
    inner: Mutex<Inner>,
}

impl PplnsLedger {
    /// Build a ledger from config. Reads `cfg.pplns_window_shares` (count cap)
    /// and `cfg.pplns_window_secs` (time bound, seconds; 0 = disabled).
    pub fn new(cfg: &ProxyConfig) -> Self {
        Self {
            inner: Mutex::new(Inner {
                window: VecDeque::new(),
                cap: cfg.pplns_window_shares,
                window_secs: cfg.pplns_window_secs,
                totals: LedgerTotals::default(),
            }),
        }
    }

    /// Lock the inner state, recovering from a poisoned mutex rather than
    /// propagating a panic: a poisoned lock only means a prior holder panicked
    /// while holding it; the accounting data itself is still usable.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Record one share result. Bumps the pool-wide totals for EVERY outcome,
    /// and — only for accepted/block outcomes, and only when count retention is
    /// enabled (`cap > 0`) — pushes a difficulty-weighted entry onto the
    /// window, then evicts anything past the count cap or time bound.
    ///
    /// `&self` + interior mutability: safe to call concurrently from many
    /// worker tasks sharing one `Arc<PplnsLedger>`. `job_id` is accepted for a
    /// stable call-site shape (and future per-job accounting) but is not
    /// retained today. Never panics on any input.
    pub fn record(&self, worker: WorkerId, job_id: &str, difficulty: f64, outcome: &ShareOutcome) {
        let _ = job_id; // reserved; not retained in the current window model
        let now = Instant::now();
        let mut inner = self.lock();

        inner.bump_totals(outcome);

        if outcome.is_accepted() && inner.cap > 0 {
            let weight = if difficulty > 0.0 { difficulty } else { 1.0 };
            inner.window.push_back(Entry { worker, weight, at: now });
        }

        inner.evict(now);
    }

    /// Difficulty-weighted, normalized payout credit across the current
    /// window. Sorted by `worker.0` ascending; each `fraction` is the worker's
    /// weight over the total window weight, so fractions sum to ~1.0. An empty
    /// or zero-weight window returns an empty vector.
    pub fn credit(&self) -> Vec<PplnsCredit> {
        let inner = self.lock();

        // BTreeMap keyed by WorkerId gives the required ascending order for
        // free (WorkerId derives Ord over its u64).
        let mut per: BTreeMap<WorkerId, (u64, f64)> = BTreeMap::new();
        let mut total = 0.0f64;
        for e in &inner.window {
            let slot = per.entry(e.worker).or_insert((0, 0.0));
            slot.0 += 1;
            slot.1 += e.weight;
            total += e.weight;
        }

        if total <= 0.0 {
            return Vec::new();
        }

        per.into_iter()
            .map(|(worker, (shares, weight))| PplnsCredit {
                worker,
                shares,
                weight,
                fraction: weight / total,
            })
            .collect()
    }

    /// Shape of the current window (length, total weight, distinct workers,
    /// configured count cap) for metrics.
    pub fn snapshot(&self) -> PplnsSnapshot {
        let inner = self.lock();
        let mut total_weight = 0.0f64;
        let mut workers: HashSet<WorkerId> = HashSet::new();
        for e in &inner.window {
            total_weight += e.weight;
            workers.insert(e.worker);
        }
        PplnsSnapshot {
            window_len: inner.window.len(),
            total_weight,
            distinct_workers: workers.len(),
            window_cap: inner.cap,
        }
    }

    /// Pool-wide lifetime outcome totals.
    pub fn totals(&self) -> LedgerTotals {
        self.lock().totals
    }

    /// Test-only: record with an explicit retention timestamp, so time-bound
    /// eviction can be exercised without real sleeps.
    #[cfg(test)]
    fn record_at(&self, worker: WorkerId, difficulty: f64, outcome: &ShareOutcome, at: Instant) {
        let mut inner = self.lock();
        inner.bump_totals(outcome);
        if outcome.is_accepted() && inner.cap > 0 {
            let weight = if difficulty > 0.0 { difficulty } else { 1.0 };
            inner.window.push_back(Entry { worker, weight, at });
        }
        // Evict relative to "now" so a backdated entry is judged against real
        // wall-clock age.
        inner.evict(Instant::now());
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Config with a count cap and no time bound.
    fn cfg_cap(n: usize) -> ProxyConfig {
        ProxyConfig {
            pplns_window_shares: n,
            pplns_window_secs: 0,
            ..ProxyConfig::default()
        }
    }

    /// Config with both a count cap and a time bound (seconds).
    fn cfg_full(n: usize, secs: u64) -> ProxyConfig {
        ProxyConfig {
            pplns_window_shares: n,
            pplns_window_secs: secs,
            ..ProxyConfig::default()
        }
    }

    fn w(id: u64) -> WorkerId {
        WorkerId(id)
    }

    // ── Ported from the Sprint-1 router.rs Accounting tests ────────────────

    #[test]
    fn accepted_share_enters_window_and_totals() {
        let led = PplnsLedger::new(&cfg_cap(10));
        led.record(w(1), "j1", 4.0, &ShareOutcome::Accepted);
        assert_eq!(led.snapshot().window_len, 1);
        assert_eq!(led.totals().accepted, 1);
        assert_eq!(led.totals().rejected, 0);
    }

    #[test]
    fn rejected_outcomes_touch_totals_not_window() {
        let led = PplnsLedger::new(&cfg_cap(10));
        led.record(w(1), "j1", 4.0, &ShareOutcome::Stale);
        led.record(w(1), "j2", 4.0, &ShareOutcome::Duplicate);
        led.record(w(1), "j3", 4.0, &ShareOutcome::LowDifficulty);
        led.record(
            w(1),
            "j4",
            4.0,
            &ShareOutcome::Rejected { code: 20, message: "nope".into() },
        );
        assert_eq!(led.snapshot().window_len, 0);
        assert_eq!(led.totals().rejected, 4);
        assert_eq!(led.totals().stale, 1);
        assert_eq!(led.totals().duplicate, 1);
        assert_eq!(led.totals().accepted, 0);
    }

    #[test]
    fn block_counts_as_accepted_plus_block() {
        let led = PplnsLedger::new(&cfg_cap(10));
        led.record(w(7), "j1", 1.0, &ShareOutcome::Block);
        assert_eq!(led.totals().accepted, 1);
        assert_eq!(led.totals().blocks, 1);
        assert_eq!(led.snapshot().window_len, 1);
    }

    #[test]
    fn window_is_capped_and_drops_oldest() {
        let led = PplnsLedger::new(&cfg_cap(3));
        for i in 0..5 {
            led.record(w(1), &format!("j{i}"), 1.0, &ShareOutcome::Accepted);
        }
        assert_eq!(led.snapshot().window_len, 3);
        assert_eq!(led.totals().accepted, 5);
    }

    #[test]
    fn zero_window_disables_retention() {
        let led = PplnsLedger::new(&cfg_cap(0));
        led.record(w(1), "j1", 4.0, &ShareOutcome::Accepted);
        assert_eq!(led.snapshot().window_len, 0);
        assert_eq!(led.totals().accepted, 1);
        assert!(led.credit().is_empty());
    }

    #[test]
    fn pplns_credit_is_difficulty_weighted_and_normalized() {
        let led = PplnsLedger::new(&cfg_cap(100));
        // worker 1: 3 + 1 = 4 weight; worker 2: 4 weight → 50/50.
        led.record(w(1), "j", 3.0, &ShareOutcome::Accepted);
        led.record(w(1), "j", 1.0, &ShareOutcome::Accepted);
        led.record(w(2), "j", 4.0, &ShareOutcome::Accepted);

        let credit = led.credit();
        let c1 = credit.iter().find(|c| c.worker == w(1)).unwrap().fraction;
        let c2 = credit.iter().find(|c| c.worker == w(2)).unwrap().fraction;
        assert!((c1 - 0.5).abs() < 1e-9, "c1={c1}");
        assert!((c2 - 0.5).abs() < 1e-9, "c2={c2}");
        assert!(((c1 + c2) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn pplns_treats_nonpositive_difficulty_as_unit_weight() {
        let led = PplnsLedger::new(&cfg_cap(100));
        led.record(w(1), "j", 0.0, &ShareOutcome::Accepted);
        led.record(w(2), "j", -5.0, &ShareOutcome::Accepted);
        let credit = led.credit();
        let c1 = credit.iter().find(|c| c.worker == w(1)).unwrap();
        let c2 = credit.iter().find(|c| c.worker == w(2)).unwrap();
        assert!((c1.fraction - 0.5).abs() < 1e-9);
        assert!((c2.fraction - 0.5).abs() < 1e-9);
        // Unit weight applied, credit never lost.
        assert!((c1.weight - 1.0).abs() < 1e-9);
        assert!((c2.weight - 1.0).abs() < 1e-9);
    }

    #[test]
    fn empty_window_has_empty_credit() {
        let led = PplnsLedger::new(&cfg_cap(100));
        assert!(led.credit().is_empty());
    }

    // ── New Sprint-2 tests ─────────────────────────────────────────────────

    #[test]
    fn time_based_eviction_drops_old_keeps_fresh() {
        let led = PplnsLedger::new(&cfg_full(100, 5));
        // An entry timestamped 20s ago is beyond the 5s bound → evicted on the
        // very record that inserts it, but its outcome still counts.
        led.record_at(w(1), 1.0, &ShareOutcome::Accepted, Instant::now() - Duration::from_secs(20));
        assert_eq!(led.snapshot().window_len, 0);
        assert_eq!(led.totals().accepted, 1);

        // A fresh share stays in the window.
        led.record(w(1), "j", 1.0, &ShareOutcome::Accepted);
        assert_eq!(led.snapshot().window_len, 1);
        assert_eq!(led.totals().accepted, 2);
    }

    #[test]
    fn zero_time_bound_disables_time_eviction() {
        // Count cap on, time bound off: an ancient entry is retained.
        let led = PplnsLedger::new(&cfg_full(100, 0));
        led.record_at(
            w(1),
            1.0,
            &ShareOutcome::Accepted,
            Instant::now() - Duration::from_secs(100_000),
        );
        assert_eq!(led.snapshot().window_len, 1);
    }

    #[test]
    fn distinct_workers_snapshot() {
        let led = PplnsLedger::new(&cfg_cap(100));
        led.record(w(1), "j", 1.0, &ShareOutcome::Accepted);
        led.record(w(1), "j", 1.0, &ShareOutcome::Accepted);
        led.record(w(2), "j", 1.0, &ShareOutcome::Accepted);
        let snap = led.snapshot();
        assert_eq!(snap.window_len, 3);
        assert_eq!(snap.distinct_workers, 2);
        assert_eq!(snap.window_cap, 100);
        assert!((snap.total_weight - 3.0).abs() < 1e-9);
    }

    #[test]
    fn credit_vec_is_ordered_and_sums_to_one() {
        let led = PplnsLedger::new(&cfg_cap(100));
        // Insert out of order; credit() must return ascending by worker.0.
        led.record(w(3), "j", 2.0, &ShareOutcome::Accepted);
        led.record(w(1), "j", 1.0, &ShareOutcome::Accepted);
        led.record(w(2), "j", 1.0, &ShareOutcome::Accepted);

        let credit = led.credit();
        let order: Vec<u64> = credit.iter().map(|c| c.worker.0).collect();
        assert_eq!(order, vec![1, 2, 3]);

        let sum: f64 = credit.iter().map(|c| c.fraction).sum();
        assert!((sum - 1.0).abs() < 1e-9, "sum={sum}");

        // Per-worker share counts are exposed too.
        assert_eq!(credit.iter().find(|c| c.worker == w(3)).unwrap().shares, 1);
    }

    #[test]
    fn concurrent_record_from_two_tasks_does_not_deadlock() {
        // Arc + interior mutability: two OS threads hammer the same ledger.
        let led = Arc::new(PplnsLedger::new(&cfg_cap(10_000)));
        let mut handles = Vec::new();
        for t in 0..2u64 {
            let l = led.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..500 {
                    l.record(WorkerId(t), "j", 1.0, &ShareOutcome::Accepted);
                    // Interleave reads to shake out any read/write deadlock.
                    let _ = l.credit();
                    let _ = l.snapshot();
                }
            }));
        }
        for h in handles {
            h.join().expect("worker thread panicked");
        }
        assert_eq!(led.totals().accepted, 1000);
        // Two distinct workers present in the window.
        assert_eq!(led.snapshot().distinct_workers, 2);
    }

    #[test]
    fn cap_zero_disables_retention_but_keeps_totals() {
        let led = PplnsLedger::new(&cfg_cap(0));
        for _ in 0..10 {
            led.record(w(1), "j", 4.0, &ShareOutcome::Accepted);
        }
        led.record(w(1), "j", 4.0, &ShareOutcome::Stale);
        assert_eq!(led.snapshot().window_len, 0);
        assert!(led.credit().is_empty());
        // Totals are untouched by the retention setting.
        assert_eq!(led.totals().accepted, 10);
        assert_eq!(led.totals().rejected, 1);
        assert_eq!(led.totals().stale, 1);
    }

    #[test]
    fn no_panic_on_extreme_and_nan_difficulty() {
        let led = PplnsLedger::new(&cfg_cap(100));
        led.record(w(1), "j", f64::NAN, &ShareOutcome::Accepted);
        led.record(w(2), "j", f64::INFINITY, &ShareOutcome::Accepted);
        led.record(w(3), "j", f64::NEG_INFINITY, &ShareOutcome::Accepted);
        // NaN is not > 0.0 → unit weight; -inf → unit weight; +inf stays inf.
        let credit = led.credit();
        // Must not panic; every recorded worker appears.
        assert_eq!(credit.len(), 3);
    }
}
