// SPDX-License-Identifier: AGPL-3.0-or-later

//! Phase timers for the replay benchmark — **instrumentation only**.
//!
//! Nothing here participates in consensus. Every counter is thread-local and
//! write-only from the point of view of the transition; no rule reads one, no
//! state root depends on one, and the whole module compiles to nothing unless
//! the `perf-timing` feature is on.
//!
//! # Why a feature and not a plain `Instant`
//!
//! The measurement has to run through the *production* code path — a harness
//! that reimplements `apply_block` measures the harness. But a timer left in
//! the production path is a clock inside consensus, and this project has
//! already paid for node-local mutable state leaking into a consensus
//! decision (`expected_bits`, 2026-08-08). So the timers exist, and the
//! release binary cannot contain them: without `perf-timing`, [`span`]
//! returns a zero-sized struct with no `Drop`, and every call site optimises
//! away.
//!
//! # Self time, not inclusive time
//!
//! Phases nest — `compute_post_state` clones the state, then rolls epoch
//! boundaries, then the caller hashes the root. Summing inclusive times over
//! nested spans double-counts, and a breakdown that adds up to 180% of the
//! wall clock is worse than no breakdown. So the recorder keeps a stack: on
//! entering a span the parent's accrued time is banked and its clock reset;
//! on leaving, the child banks its own and the parent's clock restarts. Each
//! phase therefore reports the time spent *in that phase and not in a deeper
//! one*, and the phases are disjoint by construction. What is left over —
//! wall clock minus the sum — is honestly "everything else", which is a
//! number the optimisation work needs to know.

/// The phases the replay benchmark attributes time to.
///
/// Deliberately coarse. A finer split is a profiler's job; this exists to
/// answer one question — of a block's replay cost, how much is the state
/// root, how much is fork choice, how much is the epoch boundary, and how
/// much is none of those.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Phase {
    /// `CommittedState::compute_root` — the full re-derivation of the
    /// committed state root (transition.rs, the `state_root_with_eutxo_leaves`
    /// call).
    StateRoot = 0,
    /// `pre.clone()` at the head of `compute_post_state`: the whole committed
    /// state, eUTXO set included, copied before a single transaction runs.
    StateClone = 1,
    /// `close_epoch` — epoch-boundary accounting (rewards, participation
    /// rotation, finality roll-over), whether reached through
    /// `process_epoch` or through `compute_post_state`'s boundary roll.
    EpochBoundary = 2,
    /// The node's `Engine::forkchoice_head` — one LMD-GHOST head computation
    /// over every block seen.
    ForkChoice = 3,
    /// The node's `Engine::rolled_to` — a state clone plus an epoch roll,
    /// paid per duty computation.
    RolledTo = 4,
    /// The node's `Engine::do_reorg` — self time only, so the `apply_block`
    /// calls inside it are attributed to their own phases.
    Reorg = 5,
}

/// How many phases there are, for the fixed-size accumulator.
pub const N_PHASES: usize = 6;

/// Human names, index-aligned with [`Phase`].
pub const PHASE_NAMES: [&str; N_PHASES] = [
    "state_root",
    "state_clone",
    "epoch_boundary",
    "forkchoice",
    "rolled_to",
    "reorg",
];

#[cfg(feature = "perf-timing")]
mod imp {
    use super::{Phase, N_PHASES};
    use std::cell::RefCell;
    use std::time::{Duration, Instant};

    thread_local! {
        /// Banked self time and entry count per phase.
        static TOTALS: RefCell<[(Duration, u64); N_PHASES]> =
            const { RefCell::new([(Duration::ZERO, 0); N_PHASES]) };
        /// The open spans, innermost last, each with the instant its own
        /// (uninterrupted) stretch of self time began.
        static STACK: RefCell<Vec<(usize, Instant)>> = const { RefCell::new(Vec::new()) };
    }

    /// An open span. Banks its self time on drop.
    pub struct Span(usize);

    #[inline]
    pub fn span(p: Phase) -> Span {
        let idx = p as usize;
        let now = Instant::now();
        STACK.with(|s| {
            let mut s = s.borrow_mut();
            if let Some((parent, since)) = s.last_mut() {
                let elapsed = now.saturating_duration_since(*since);
                let parent = *parent;
                TOTALS.with(|t| t.borrow_mut()[parent].0 += elapsed);
            }
            s.push((idx, now));
        });
        TOTALS.with(|t| t.borrow_mut()[idx].1 += 1);
        Span(idx)
    }

    impl Drop for Span {
        fn drop(&mut self) {
            let now = Instant::now();
            STACK.with(|s| {
                let mut s = s.borrow_mut();
                if let Some((idx, since)) = s.pop() {
                    debug_assert_eq!(idx, self.0, "perf spans must nest");
                    let elapsed = now.saturating_duration_since(since);
                    TOTALS.with(|t| t.borrow_mut()[idx].0 += elapsed);
                }
                if let Some((_, since)) = s.last_mut() {
                    *since = Instant::now();
                }
            });
        }
    }

    /// Read and zero this thread's counters: `(self time, entries)` per phase.
    pub fn take() -> [(Duration, u64); N_PHASES] {
        TOTALS.with(|t| {
            let mut t = t.borrow_mut();
            let out = *t;
            *t = [(Duration::ZERO, 0); N_PHASES];
            out
        })
    }

    /// Whether the counters are live in this build.
    pub const ENABLED: bool = true;
}

#[cfg(not(feature = "perf-timing"))]
mod imp {
    use super::{Phase, N_PHASES};
    use std::time::Duration;

    /// Zero-sized, no `Drop`: the call site vanishes.
    pub struct Span;

    #[inline(always)]
    pub fn span(_p: Phase) -> Span {
        Span
    }

    pub fn take() -> [(Duration, u64); N_PHASES] {
        [(Duration::ZERO, 0); N_PHASES]
    }

    pub const ENABLED: bool = false;
}

pub use imp::{span, take, Span, ENABLED};
