// SPDX-License-Identifier: AGPL-3.0-or-later
//! # The Genesis-4 fleet memory projection, as a checked artefact
//!
//! There is a date on which 9 validators per Edgevana box exhaust 31,866 MiB.
//! The fleet programme sequences around it. It has been an arithmetic sketch
//! resting partly on numbers with no commit behind them — and every headline
//! number in this programme that lacked a commit behind it has turned out to
//! be wrong.
//!
//! So this crate does three things, and refuses to do a fourth.
//!
//! 1. It states the projection with **every input traceable** to a
//!    measurement, or explicitly marked [`Standing::Modelled`]. See [`INPUTS`].
//! 2. It **recomputes the dates from the live fleet's own numbers**, read out
//!    of `scripts/fleet-memory-observations.tsv`, which
//!    `scripts/fleet-memory-observe.sh` regenerates read-only.
//! 3. Its tests **fail when the fleet stops matching what the projection
//!    assumes** — not when someone edits a constant. A test that re-asserts a
//!    constant proves only that nobody retyped the line.
//!
//! The fourth thing, which it does not do: pretend the growth stops. See
//! [`WHAT_THIS_CANNOT_DO`].
//!
//! ## The denominator is SLOTS, not blocks
//!
//! This is the correction that matters most, and it arrived late enough to
//! have nearly been missed. Interval-by-interval on a real log, growth
//! measured **per block** comes out at 0.005, 0.032 and 0.011 MiB/block — a
//! sixfold disagreement, and any two endpoints would have produced any one of
//! them. The same intervals measured **per slot** are far steadier. Between
//! h=10,000 and h=15,000 the chain burned 21,187 slots to produce 5,000
//! blocks, and memory followed the slots.
//!
//! That matters because slots advance at exactly [`SLOTS_PER_DAY`] on the
//! wall clock whether or not anybody produces a block, while this chain's
//! block cadence has run anywhere from 24% to 100% of slots. Denominating in
//! blocks folds a variable that has moved by 4x into the rate. Denominating
//! in slots removes it, and the date becomes a function of the calendar
//! alone.
//!
//! The block cadence is therefore **no longer an input to the arithmetic** —
//! [`tests::the_date_does_not_move_when_only_the_block_cadence_moves`] proves
//! it is not — but it remains in the snapshot as a **tripwire**, because it
//! is the hidden variable that was hiding. If it moves again,
//! [`tests::the_slot_to_block_relation_is_still_what_the_projection_was_derived_under`]
//! fires, and that is the natural experiment which would confirm or refute
//! the slot hypothesis on live data.
//!
//! ## Peak and steady state are two curves, not one
//!
//! RSS is **not monotone across a replay**. On a real log it climbs while the
//! block map fills, peaks around h≈17,000–20,000, and then *falls* before the
//! replay ends: `VmHWM` 762.0 MiB against `VmRSS` 709.6 at h=20,000 and 675.3
//! at the end. So `/usr/bin/time -v`'s maximum answers a different question
//! from "how much is resident once the chain is loaded", and the two answers
//! enter this projection at different moments:
//!
//! * the **steady curve** is what a box carries between restarts. It grows.
//! * the **peak curve** is what a box must survive *during a replay*. It is
//!   the steady curve plus a premium, and it is paid at **every restart**.
//!
//! A box that survives running can still die in replay. That is why there are
//! two dates below and why the roll date is the earlier one.
//!
//! ## Why VmHWM is free evidence, and why it is only a floor
//!
//! Linux keeps `VmHWM` per process for the process's whole lifetime, so for
//! every validator the fleet is running right now, the boot peak it actually
//! paid is already recorded, kernel-measured, with no experiment. That is why
//! this projection can be checked against reality rather than against a model.
//!
//! It comes with one hard rule: **a mark set days ago was set against a
//! shorter chain, so it is a floor and never headroom.** Reading `MAX_HWM` as
//! spare capacity is the most available way to get this wrong in the
//! dangerous direction, so [`Snapshot::mark_staleness_blocks`] surfaces the age
//! of every mark and
//! [`tests::roll_arm_rests_on_marks_that_are_still_informative`] fails when no
//! mark is recent enough to bound a boot today.

use std::collections::BTreeMap;
use std::fmt::Write as _;

// ─────────────────────────────────────────────────────────────── inputs ────

/// How much we are entitled to believe a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// Read off a running kernel, a real chain, or an instrumented run on a
    /// real block log. `source` names where.
    Measured,
    /// Chosen, extrapolated, or assumed. Not wrong — but not evidence, and
    /// the error bars must be read as excluding it.
    Modelled,
    /// Correctly measured, in a denominator that turned out to be the wrong
    /// one. Kept visible because the number is still true of what it measured
    /// and will otherwise be quoted again.
    Superseded,
    /// Was published, was used, and is now known to be wrong. Recorded so it
    /// cannot quietly return. Never read by the arithmetic.
    Discredited,
}

/// One input, with its standing and its provenance.
#[derive(Debug, Clone, Copy)]
pub struct Input {
    pub name: &'static str,
    pub value: f64,
    pub unit: &'static str,
    pub standing: Standing,
    pub source: &'static str,
}

/// Validators per box the projection is built on. **Verified four ways on all
/// seven boxes** (argv `run`+`--data-dir`, `pgrep -f bloch-pos`, systemd
/// `bloch-n*.service` units, distinct `--data-dir` values): all four return 9,
/// 63 total, indices n00..n62 on stride 7.
///
/// A briefing correction put this at 10, which would drop the per-validator
/// ceiling from 3,199 to 2,879 MiB. It does not hold on the live fleet. The
/// count is nevertheless the input most worth guarding, because a tenancy
/// change is invisible in every downstream number.
pub const EXPECTED_VALIDATORS_PER_BOX: usize = 9;

/// Slots per day. Exact: `SLOT_DURATION_SECS` is 30, asserted at
/// `crates/bloch-pos-node/src/main.rs:914`. Retained because it makes the
/// block cadence a measurable ratio rather than a free parameter.
pub const SLOTS_PER_DAY: f64 = 2880.0;

// ── the three curves, each in its own denominator ─────────────────────────

/// **PEAK curve** — what a box must survive during a replay, per block.
/// MEASURED: 0.01718 MiB/block, reproduced to four digits across three chain
/// lengths and two chains, back to back on one box against an identical
/// 410 MB log. The mechanism is confirmed numerically, not asserted: the term
/// store-backing removes is 13.9–14.6 KB/block against a measured on-disk
/// envelope of [`ENVELOPE_BYTES_PER_BLOCK`]. Same magnitude, same denominator.
pub const PEAK_MIB_PER_BLOCK_BASELINE: f64 = 0.01718;

/// **STEADY curve** — what an already-running validator adds per block at the
/// tip. MEASURED ON THE LIVE FLEET rather than extrapolated from a replay: 63
/// validators, three read-only sweeps over 5,235 s, summed VmRSS 75,794.1 →
/// 75,883.4 MiB across ~174 blocks. Sub-intervals give 22.5 and 25.4
/// MiB/day/validator; the full baseline gives 23.4, i.e. 0.00814 MiB/block.
///
/// This settles the input previously listed as never measured — whether a
/// single-node replay rate transfers to a nine-per-box fleet. It does not:
/// fleet steady growth is 2.1x BELOW the replay slope, which is exactly where
/// a steady curve should sit relative to a peak curve.
///
/// Caveat, plainly: the baseline is 1.45 hours. It wants a day.
pub const STEADY_MIB_PER_BLOCK_FLEET: f64 = 0.00814;

/// The peak curve with the block map moved to the store. MEASURED across
/// three lengths and two chains.
pub const PEAK_MIB_PER_BLOCK_STOREBACKED_LO: f64 = 0.00276;
pub const PEAK_MIB_PER_BLOCK_STOREBACKED_HI: f64 = 0.00335;

/// One-off drop in the LEVEL: same box, back to back, identical 410 MB log,
/// final code. Twelve replays (2 snapshots x 3 lengths x 2 binaries), every
/// state root matched its pair, two checked against three live validators.
pub const BASELINE_PEAK_MIB: f64 = 1045.6;
pub const STOREBACKED_PEAK_MIB: f64 = 635.2;

/// On-disk block envelope: the dimensional anchor that turns the store-backed
/// saving from a claim into a confirmed mechanism.
pub const ENVELOPE_BYTES_PER_BLOCK: f64 = 13934.0;

/// **STATE curve** — what survives store-backing, and it is not the block map.
/// Of the ~0.0031 MiB/block residual the block map is only 0.00029; ~90% is
/// the committed state, the eUTXO ledger, measured in a window carrying 1,048
/// transactions across 29,472 blocks — 0.0356 tx/block, a nearly empty chain.
/// The eUTXO set grows with TRANSACTIONS, not blocks and not the calendar.
pub const STOREBACKED_RESIDUAL_MIB_PER_BLOCK: f64 = 0.0031;
pub const RESIDUAL_BLOCK_MAP_MIB_PER_BLOCK: f64 = 0.00029;
pub const STATE_SHARE_OF_RESIDUAL: f64 = 0.90;
pub const TX_PER_BLOCK_MEASURED: f64 = 1048.0 / 29472.0;

/// Derived: MiB of resident state per transaction. Arithmetic on measured
/// inputs, not a measurement, resting on one low-volume window — but it is
/// the number that decides whether store-backing buys eight months or ten
/// days.
pub const STATE_MIB_PER_TX: f64 =
    (STOREBACKED_RESIDUAL_MIB_PER_BLOCK * STATE_SHARE_OF_RESIDUAL) / TX_PER_BLOCK_MEASURED;

// ── the peak is copy-on-write, not a term that grows on its own ───────────

/// The peak transient has a mechanism, found by measurement and with the
/// alternatives eliminated by measurement rather than by argument.
///
/// `REORG_STATE_WINDOW` holding an old state makes the eUTXO `Arc` **shared**;
/// a shared `Arc` sends the next mutation through `Arc::make_mut`, which
/// clones the whole [`COW_MAP_ENTRIES`]-entry map — [`COW_MAP_COPY_MIB`] a
/// time. Counted directly over one replay: [`COW_COPYING_MUTATIONS`] mutations
/// copied the entire map, [`COW_INPLACE_MUTATIONS`] mutated in place. The
/// sampled curve steps in units of exactly 52.4 MiB and releases exactly two
/// of them in a single 50 ms sample.
///
/// The consequence for this projection is structural: the transient scales
/// with **the size of the eUTXO map**, not with chain length. The map grows
/// with transactions, and at the measured 0.0356 tx/block it is very nearly
/// constant. So the boot premium is a roughly fixed 1–2 x 52.4 MiB, and it
/// will grow only when usage does — the same back wall as
/// [`STATE_MIB_PER_TX`], reached by a different road.
pub const COW_MAP_ENTRIES: u64 = 452_726;
pub const COW_MAP_COPY_MIB: f64 = 52.4;
pub const COW_COPYING_MUTATIONS: u64 = 892;
pub const COW_INPLACE_MUTATIONS: u64 = 384_638;

// ── the replay curve, 50 ms sampling, five runs, noise floor 8 kB ─────────

/// RSS is **not monotone**: the peak falls at t≈253 s of a 376 s run, at
/// height ~17,663 of 29,377 — 60% of the blocks — and the run then gives back
/// 96 MiB. End of replay 666.1 MiB against `VmHWM` 761.9.
pub const REPLAY_BLOCKS_MEASURED: f64 = 29_377.0;
pub const REPLAY_PEAK_AT_HEIGHT: u64 = 17_663;
pub const END_OF_REPLAY_RSS_MIB: f64 = 666.1;
pub const REPLAY_VMHWM_MIB: f64 = 761.9;

/// Footprint before the replay starts. The number that explains the gap.
pub const PRE_REPLAY_RSS_MIB: f64 = 317.2;
pub const PRE_REPLAY_HWM_MIB: f64 = 350.2;

/// What the replay itself retains, in both runs. 666.1 = 317.2 + 348.9, to
/// within a tenth of a MiB — so the refuted model had costed the state and
/// omitted the chain entirely. See [`WHY_THE_MODEL_GAP_IS_A_LEVEL`].
pub const REPLAY_RETENTION_MIB: f64 = 348.9;

/// Per block, the replay's retention is 348.9 / 29,377. This is a **third
/// independent route** to the block-map term: 0.01188 MiB/block here, against
/// a 13,934 B/block on-disk envelope (0.01329) and a store-backed removed term
/// of 13.9–14.6 KB/block. Three methods, one number.
pub const REPLAY_RETENTION_MIB_PER_BLOCK: f64 = REPLAY_RETENTION_MIB / REPLAY_BLOCKS_MEASURED;

/// Four extra mainnet-sized states, measured: 320 **kB**, because
/// `EutxoSet.entries` is an `Arc<BTreeMap>` and holding a state is a refcount
/// increment. See the discredited 60 MB/state entry in [`INPUTS`].
pub const MEMO_FOUR_STATES_KIB: f64 = 320.0;

/// Bounds on the boot premium, as a multiple of the steady state. The
/// mechanism now predicts what these should be: 1–2 whole-map copy-on-write
/// copies of [`COW_MAP_COPY_MIB`] on top of a ~1,200 MiB validator, i.e.
/// roughly 1.04x–1.09x. The band is kept wider than that because the fleet's
/// VmHWM marks are stale floors and because the mechanism does not yet close
/// the arithmetic against the reproduced peak slope.
pub const PEAK_PREMIUM_FRACTION_LO: f64 = 1.02;
pub const PEAK_PREMIUM_FRACTION_HI: f64 = 1.60;

/// RAM held back for page cache and the OS. MODELLED — an operator choice.
/// The boxes were observed holding 5,135–8,148 MiB of page cache, so 3,072 is
/// if anything low, and a low reserve makes these dates LATER than the truth.
pub const RESERVE_MIB_DEFAULT: f64 = 3072.0;

/// Blocks per day the dates were derived under. Unlike the retired
/// slot-denominated model the cadence IS an input again: the dominant term is
/// one envelope per BLOCK, and an empty slot creates no envelope.
pub const BLOCKS_PER_DAY_AT_DERIVATION: f64 = 2827.0;
pub const BLOCKS_PER_DAY_TOLERANCE: f64 = 0.10;

/// Non-canonical blocks held whole in RAM, read off the node as
/// `blocks_known - height`: 225, 226, 226 on three independent validators.
/// The alarm is generous because this term has no ceiling — the test exists
/// to notice it moving, not to bound it.
pub const FORK_OVERHANG_AT_DERIVATION: u64 = 226;
pub const FORK_OVERHANG_ALARM: u64 = 2000;

/// Every input, with its standing. The report prints this verbatim so nobody
/// has to take the arithmetic on trust.
pub const INPUTS: &[Input] = &[
    Input { name: "box RAM", value: 31866.0, unit: "MiB",
        standing: Standing::Measured,
        source: "/proc/meminfo on all 7 grandes; 31,866 on six, 31,867 on 149.28.180.128" },
    Input { name: "validators per box", value: 9.0, unit: "processes",
        standing: Standing::Measured,
        source: "four independent lenses on all 7 boxes -- argv, pgrep, systemd units, distinct --data-dir -- all return 9; 63 total" },
    Input { name: "steady resident, worst box", value: 11376.0, unit: "MiB",
        standing: Standing::Measured,
        source: "sum of VmRSS on 139.84.201.52; range across the 7 boxes 10,429-11,376 MiB; fleet mean 1,204 MiB/validator" },
    Input { name: "boot peak, per validator", value: 1517.0, unit: "MiB",
        standing: Standing::Measured,
        source: "max VmHWM, kernel-retained for the process lifetime; range across 63 processes 1,145-1,517 MiB" },
    Input { name: "PEAK curve growth, baseline", value: PEAK_MIB_PER_BLOCK_BASELINE, unit: "MiB/block",
        standing: Standing::Measured,
        source: "store-backed A/B: three lengths, two chains, reproduced to four digits; 12 replays, every state root matched its pair" },
    Input { name: "STEADY curve growth, live fleet", value: STEADY_MIB_PER_BLOCK_FLEET, unit: "MiB/block",
        standing: Standing::Measured,
        source: "63 live validators, three read-only sweeps over 5,235 s: 75,794.1 -> 75,883.4 MiB summed VmRSS. Baseline only 1.45 h" },
    Input { name: "PEAK growth, store-backed", value: PEAK_MIB_PER_BLOCK_STOREBACKED_HI, unit: "MiB/block",
        standing: Standing::Measured,
        source: "0.00276-0.00335 across three lengths and two chains, same A/B harness" },
    Input { name: "peak level, store-backed", value: STOREBACKED_PEAK_MIB, unit: "MiB",
        standing: Standing::Measured,
        source: "635.2 against 1,045.6 MiB baseline, same box, back to back, identical 410 MB log, final code: -39.3% memory, -3.3% clock" },
    Input { name: "on-disk block envelope", value: ENVELOPE_BYTES_PER_BLOCK, unit: "B/block",
        standing: Standing::Measured,
        source: "the dimensional anchor: the term removed from RAM is 13.9-14.6 KB/block, so the mechanism is confirmed rather than asserted" },
    Input { name: "fork overhang", value: 226.0, unit: "non-canonical blocks in RAM",
        standing: Standing::Measured,
        source: "blocks_known - height read off three validators: 225, 226, 226. Unbounded and unaddressed" },
    Input { name: "block cadence", value: BLOCKS_PER_DAY_AT_DERIVATION, unit: "blocks/day",
        standing: Standing::Measured,
        source: "2,827/day over slot 49,382-55,000; 2,861/day over the last 83 minutes; 0.98 blocks/slot" },
    Input { name: "state per transaction", value: STATE_MIB_PER_TX, unit: "MiB/tx (DERIVED)",
        standing: Standing::Modelled,
        source: "arithmetic on measured inputs: 90% of a 0.0031 MiB/block residual over a 0.0356 tx/block window. One low-volume window" },
    Input { name: "page-cache reserve", value: RESERVE_MIB_DEFAULT, unit: "MiB",
        standing: Standing::Modelled,
        source: "operator choice inherited from fleet-memory-gate.sh; boxes observed holding 5,135-8,148 MiB of cache" },
    Input { name: "store-backed level ratio transfers to a fleet validator", value: STOREBACKED_PEAK_MIB / BASELINE_PEAK_MIB, unit: "x (assumed)",
        standing: Standing::Modelled,
        source: "measured on a ~1,046 MiB isolated node; fleet validators peak near 1,517 MiB and carry a consensus working set the isolated run does not" },
    Input { name: "growth stays linear past today", value: 1.0, unit: "assumed",
        standing: Standing::Modelled,
        source: "the dates extrapolate several times past the longest log ever replayed (~30,600 blocks)" },
    Input { name: "0.001234 MiB/block, end-of-replay all", value: 0.001234, unit: "MiB/block",
        standing: Standing::Discredited,
        source: "a two-point fit over h=15,000->29,630 whose window is dominated by an interval measuring EXACTLY 0.00000; see the module header" },
    Input { name: "10 validators per box", value: 10.0, unit: "processes",
        standing: Standing::Discredited,
        source: "REFUTED on the live fleet: four independent lenses on all 7 boxes return 9. Would have cut the ceiling 3,199 -> 2,879 MiB" },
    Input { name: "1,032 MiB mean resident per validator", value: 1032.0, unit: "MiB",
        standing: Standing::Superseded,
        source: "the fleet now measures 1,204 MiB. At the measured 23.4 MiB/day drift, 1,032 is a correct reading about seven days old" },
    Input { name: "the slot-denominated model", value: 0.01719, unit: "MiB/block",
        standing: Standing::Superseded,
        source: "it rested on the end-of-replay interval series; a contaminated series is not decontaminated by changing its unit" },
    Input { name: "60 MB per CommittedState (240 MB full memo)", value: 60.0, unit: "MB/state",
        standing: Standing::Discredited,
        source: "REFUTED by ~750x: four extra mainnet-sized states measure 320 kB. EutxoSet.entries is an Arc<BTreeMap>, so states DO structurally share and holding one is a refcount increment. Still live at crates/bloch-pos-node/src/engine.rs:274-277; not mine to edit, and it needs to go" },
    Input { name: "MEMO_CAP = 4 costs ~240 MB during replay", value: 240.0, unit: "MB",
        standing: Standing::Discredited,
        source: "eliminated twice: rolled_to performed ZERO rolls across the whole replay, so the memo is never populated at all, and the four states would be 320 kB if it were" },
    Input { name: "the boot premium is a constant additive term", value: 1.0, unit: "assumed",
        standing: Standing::Superseded,
        source: "replaced by a mechanism: the premium is 1-2 whole-map copy-on-write copies of 52.4 MiB, so it scales with the eUTXO map, not with chain length" },
    Input { name: "0.0198 MiB/block", value: 0.0198, unit: "MiB/block",
        standing: Standing::Discredited,
        source: "measured on a tree lacking the boot-copy fix; overestimates; behind the retired 'early October' sketch" },
    Input { name: "86.1% of Engine::blocks is signature material", value: 0.861, unit: "fraction",
        standing: Standing::Discredited,
        source: "refuted: the proposer signature is 32.9% of a frame; the ~90% figure counts attestations too" },
];

/// Whether the refuted model's 1.8–1.9x gap moves the **date** or only the
/// **level**. Printed by the report because it is the question that was asked
/// and the answer is not the intuitive one.
pub const WHY_THE_MODEL_GAP_IS_A_LEVEL: &str = "\
THE 1.8x END-OF-REPLAY GAP: LEVEL, NOT SLOPE -- AND NOT THIS DATE

  The model predicted 344-375 MiB at end of replay. Measured: 666.1. The
  peak/end distinction accounts for only 96 MiB of a ~300 MiB gap, so
  non-monotonicity does not rescue it: RSS is non-monotone AND the model is
  refuted. Both, not one.

  The measurer's hypothesis holds exactly. Pre-replay VmRSS is 317.2 MiB and
  the replay retains +348.9 MiB in both runs; 317.2 + 348.9 = 666.1, to within
  a tenth of a MiB. The model costed the state and omitted the chain the
  replay retains. That is a missing ADDITIVE TERM -- a level error.

  It does not move the dates here, and the reason is not luck. This projection
  never reads a predicted level: it reads VmRSS and VmHWM off 63 live
  validators. A model that mis-predicts the level cannot move a date computed
  from a measured level. Any date computed FROM that model moves a great deal.

  And the missing term confirms the slope rather than changing it. Spread over
  the 29,377 blocks replayed, 348.9 MiB is 0.01188 MiB/block -- a third
  independent route to the block-map term, against 0.01329 MiB/block of
  on-disk envelope and a store-backed removed term of 13.9-14.6 KB/block.
  Three methods, three directions, one number. The gap is the strongest
  evidence yet FOR the block-map slope.";

/// What no arrangement of these numbers can deliver.
pub const WHAT_THIS_CANNOT_DO: &str = "\
WHAT THIS PROJECTION CANNOT DO

  Growth is linear in chain length -- and the three measured intervals are
  RISING, so linear is the optimistic reading. Nothing on the table makes
  memory bounded. Removing the signature term multiplies the date; it does
  not move it to infinity, because what is left is still a line with positive
  slope. Every improvement in flight removes a CONSTANT FACTOR from a curve
  that still rises forever. The date returns.

  A bounded design would be O(unfinalized + state), not O(chain): resident
  cost set by the unfinalized suffix (85 blocks today) plus the state, with
  history paged from the log. No current workstream aims there. Saying so is
  not a criticism of the work in flight, which is real and measured; it is
  the difference between postponing a date and removing one.

  And the irreducible term is not constant either. What survives every
  optimisation is the carryover eUTXO set, and that grows with USAGE, not
  with time. The validator-opening programme exists to add users. The one
  term nobody can optimise away is the one the roadmap is designed to grow.

  Two of the three ways this projection can be wrong point the same way --
  later than the truth. The VmHWM marks it reads are floors; the reserve it
  holds back is smaller than the page cache the boxes actually use; and the
  growth intervals are rising rather than flat. Read the dates as an upper
  bound on the time available, not as a forecast.";

// ──────────────────────────────────────────────────────────── the data ────

/// One validator process as the kernel reported it.
#[derive(Debug, Clone)]
pub struct Observation {
    pub box_ip: String,
    pub box_host: String,
    pub mem_total_mib: f64,
    pub mem_avail_mib: f64,
    pub cached_mib: f64,
    pub nproc: u32,
    pub unit: String,
    pub pid: u32,
    /// Peak resident set, kernel-retained for the process's lifetime.
    pub vmhwm_mib: f64,
    /// Resident set right now.
    pub vmrss_mib: f64,
    pub started_unix: i64,
    pub mark_age_s: i64,
    /// Chain height when this process started, read out of the archive.
    pub boot_height: Option<u64>,
    /// Four INDEPENDENT counts of how many validators this box is running.
    /// They exist because one lens that under-counts is invisible: it moves
    /// the date in the SAFE direction and every check built on it still
    /// passes. A tenancy claim of 10-per-box was refuted by their agreement.
    pub lens_argv: u32,
    pub lens_pgrep: u32,
    pub lens_units: u32,
    pub lens_datadirs: u32,
}

/// A box, rolled up.
#[derive(Debug, Clone)]
pub struct BoxRollup {
    pub ip: String,
    pub host: String,
    pub mem_total_mib: f64,
    pub cached_mib: f64,
    pub validators: usize,
    pub sum_rss_mib: f64,
    pub sum_hwm_mib: f64,
    pub max_hwm_mib: f64,
    pub max_hwm_unit: String,
    pub lens_argv: u32,
    pub lens_pgrep: u32,
    pub lens_units: u32,
    pub lens_datadirs: u32,
}

/// A kernel-measured reading of the whole fleet at one instant.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub captured_unix: i64,
    pub chain_height: u64,
    pub chain_slot: u64,
    pub genesis_unix: i64,
    pub slot_secs: f64,
    /// Tripwire, not an input. See the module header.
    pub blocks_per_slot_measured: Option<f64>,
    pub blocks_per_day_measured: Option<f64>,
    pub cadence_window: String,
    /// Non-canonical blocks held whole in RAM (`blocks_known - height`).
    pub fork_overhang_blocks: Option<u64>,
    pub rows: Vec<Observation>,
}

impl Snapshot {
    /// `BLOCH_FLEET_OBSERVATIONS` overrides the path. That is how
    /// `scripts/memoria-projecao-violacao.sh` proves these checks bite: point
    /// it at a deliberately falsified snapshot and watch them fail.
    pub fn default_path() -> std::path::PathBuf {
        if let Ok(p) = std::env::var("BLOCH_FLEET_OBSERVATIONS") {
            return std::path::PathBuf::from(p);
        }
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/fleet-memory-observations.tsv")
    }

    pub fn load_default() -> Result<Self, String> {
        let p = Self::default_path();
        let text = std::fs::read_to_string(&p).map_err(|e| {
            format!(
                "cannot read the fleet snapshot at {}: {e}\n\
                 Regenerate it, read-only, with:  scripts/fleet-memory-observe.sh",
                p.display()
            )
        })?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let mut meta: BTreeMap<&str, &str> = BTreeMap::new();
        let mut rows = Vec::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("# ") {
                let mut it = rest.splitn(2, '\t');
                if let (Some(k), Some(v)) = (it.next(), it.next()) {
                    meta.insert(k.trim(), v.trim());
                }
                continue;
            }
            if line.starts_with('#') || line.trim().is_empty() || line.starts_with("box_ip\t") {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 17 {
                return Err(format!(
                    "malformed observation row ({} fields): {line}",
                    f.len()
                ));
            }
            let num = |i: usize| -> Result<f64, String> {
                f[i].parse::<f64>().map_err(|_| {
                    format!(
                        "field {i} of an observation row is not a number: {:?}.\n\
                         A comma decimal separator here means the collector ran under a\n\
                         non-C locale; scripts/fleet-memory-observe.sh pins LC_ALL=C.",
                        f[i]
                    )
                })
            };
            rows.push(Observation {
                box_ip: f[0].to_string(),
                box_host: f[1].to_string(),
                mem_total_mib: num(2)?,
                mem_avail_mib: num(3)?,
                cached_mib: num(4)?,
                nproc: num(5)? as u32,
                unit: f[6].to_string(),
                pid: num(7)? as u32,
                vmhwm_mib: num(8)?,
                vmrss_mib: num(9)?,
                started_unix: num(10)? as i64,
                mark_age_s: num(11)? as i64,
                boot_height: f[12].parse::<u64>().ok(),
                lens_argv: num(13)? as u32,
                lens_pgrep: num(14)? as u32,
                lens_units: num(15)? as u32,
                lens_datadirs: num(16)? as u32,
            });
        }
        if rows.is_empty() {
            return Err("snapshot carries no validator rows".to_string());
        }
        let need = |k: &str| -> Result<&str, String> {
            meta.get(k)
                .copied()
                .ok_or_else(|| format!("snapshot has no `# {k}` header"))
        };
        let getf = |k: &str| meta.get(k).and_then(|v| v.parse::<f64>().ok());
        Ok(Snapshot {
            captured_unix: need("captured_unix")?
                .parse()
                .map_err(|_| "bad captured_unix")?,
            chain_height: need("chain_height")?
                .parse()
                .map_err(|_| "bad chain_height")?,
            chain_slot: need("chain_slot")?.parse().map_err(|_| "bad chain_slot")?,
            genesis_unix: need("genesis_unix")?
                .parse()
                .map_err(|_| "bad genesis_unix")?,
            slot_secs: getf("slot_secs").unwrap_or(30.0),
            blocks_per_slot_measured: getf("blocks_per_slot_measured"),
            blocks_per_day_measured: getf("blocks_per_day_measured"),
            fork_overhang_blocks: meta
                .get("fork_overhang_blocks")
                .and_then(|v| v.parse().ok()),
            cadence_window: meta
                .get("blocks_per_day_window")
                .copied()
                .unwrap_or("unrecorded")
                .to_string(),
            rows,
        })
    }

    pub fn boxes(&self) -> Vec<BoxRollup> {
        let mut by: BTreeMap<&str, Vec<&Observation>> = BTreeMap::new();
        for r in &self.rows {
            by.entry(r.box_ip.as_str()).or_default().push(r);
        }
        by.into_iter()
            .map(|(ip, rs)| {
                let top = rs
                    .iter()
                    .max_by(|a, b| a.vmhwm_mib.total_cmp(&b.vmhwm_mib))
                    .expect("non-empty");
                BoxRollup {
                    ip: ip.to_string(),
                    host: rs[0].box_host.clone(),
                    mem_total_mib: rs[0].mem_total_mib,
                    cached_mib: rs[0].cached_mib,
                    validators: rs.len(),
                    sum_rss_mib: rs.iter().map(|r| r.vmrss_mib).sum(),
                    sum_hwm_mib: rs.iter().map(|r| r.vmhwm_mib).sum(),
                    max_hwm_mib: top.vmhwm_mib,
                    max_hwm_unit: top.unit.clone(),
                    lens_argv: rs[0].lens_argv,
                    lens_pgrep: rs[0].lens_pgrep,
                    lens_units: rs[0].lens_units,
                    lens_datadirs: rs[0].lens_datadirs,
                }
            })
            .collect()
    }

    /// The slot at which a process started. Exact: slots are a fixed
    /// `slot_secs` off genesis, so this is arithmetic on the wall clock and
    /// not an inference from block heights.
    pub fn boot_slot(&self, o: &Observation) -> u64 {
        ((o.started_unix - self.genesis_unix).max(0) as f64 / self.slot_secs) as u64
    }

    /// **Slots** — not blocks — since the most recently booted validator set
    /// its mark. Slots, because that is what the growth follows; measuring
    /// this staleness in blocks would understate it by 1/cadence exactly when
    /// the chain is slow, which is exactly when it matters.
    pub fn mark_staleness_blocks(&self) -> u64 {
        let newest = self
            .rows
            .iter()
            .filter_map(|o| o.boot_height)
            .max()
            .unwrap_or(0);
        self.chain_height.saturating_sub(newest)
    }

    /// **Why the fleet's own VmHWM spread cannot be used as a growth rate.**
    ///
    /// It is tempting: 63 validators booted at 63 different chain lengths, so
    /// regressing VmHWM on boot height looks like a free, kernel-measured
    /// rate. Doing it yields 0.17–0.30 MiB/block within six of the seven
    /// boxes at r = 0.84–0.99 — ten to twenty times any replay-measured rate
    /// — and the seventh box returns a NEGATIVE rate at r = -0.51.
    ///
    /// It is not a rate. The fleet was migrated in batches, so within a box
    /// the k-th validator to boot is *both* the k-th highest boot height *and*
    /// the one that booted with k-1 siblings already resident and competing
    /// for page cache. Boot order and chain length are perfectly collinear
    /// within a box, and the batches interleaved across boxes, so nothing in
    /// this data separates them. The negative box is the tell.
    ///
    /// Recorded here so the next person does not spend the afternoon
    /// rediscovering it and, worse, publishing the answer.
    pub const fn fleet_slope_is_confounded() -> &'static str {
        "boot order and boot height are collinear within a box; not separable from this data"
    }

    /// The box that binds, in each regime. Chosen by days-to-exhaustion, not
    /// by raw headroom: the boxes are the same size today, but a PMO
    /// reservation table may not leave them that way, and a selector that
    /// assumes uniformity would quietly report the wrong box the day it stops
    /// being true.
    fn binding_box(
        &self,
        reserve: f64,
        rate: f64,
        bpd: f64,
        need: impl Fn(&BoxRollup) -> f64,
    ) -> BoxRollup {
        let mut b = self.boxes();
        b.sort_by(|x, y| {
            let d = |c: &BoxRollup| {
                days_until(
                    c.mem_total_mib - reserve - need(c),
                    rate,
                    bpd,
                    c.validators as f64,
                )
            };
            d(x).total_cmp(&d(y))
        });
        b.remove(0)
    }
}

// ────────────────────────────────────────────────────────── projection ────

/// Days until a box runs out, given headroom, a **per-block** growth rate and
/// the block cadence.
///
/// The denominator is the block, not the slot. That is a reversal of the
/// previous model and it is decided by mechanism, not by fit: the dominant
/// term is one envelope per BLOCK ([`ENVELOPE_BYTES_PER_BLOCK`]), and an empty
/// slot creates no envelope. At today's cadence of 0.98 blocks/slot the two
/// denominators are numerically indistinguishable on live data, so the live
/// chain cannot currently settle it — which is precisely why the mechanism has
/// to, and why the cadence tripwire is kept.
pub fn days_until(
    headroom_mib: f64,
    mib_per_block: f64,
    blocks_per_day: f64,
    validators: f64,
) -> f64 {
    let burn = validators * mib_per_block * blocks_per_day;
    // Order matters. Folding `headroom <= 0` into the same branch as
    // `burn <= 0` returns INFINITY for a box ALREADY over capacity, which
    // sorts the most endangered box in the fleet as the safest and drops it
    // out of every binding-box selection. Exhausted is zero days.
    if headroom_mib <= 0.0 {
        return 0.0;
    }
    if burn <= 0.0 {
        return f64::INFINITY;
    }
    headroom_mib / burn
}

/// A date expressed as a band, because a single date would misrepresent the
/// width of the inputs.
#[derive(Debug, Clone, Copy)]
pub struct Band {
    /// Days from capture at the binding (most recent, fastest) rate.
    pub days_lo: f64,
    /// Days from capture at the optimistic (oldest, slowest) rate.
    pub days_hi: f64,
    pub unix_lo: i64,
    pub unix_hi: i64,
}

impl Band {
    fn new(captured: i64, days_lo: f64, days_hi: f64) -> Self {
        // The optimistic arm can be genuinely infinite, and
        // `captured + (f64::INFINITY * 86400.0) as i64` overflows i64 and
        // panics in a debug build. Saturate.
        let at = |d: f64| -> i64 {
            if !d.is_finite() {
                i64::MAX
            } else {
                captured.saturating_add((d * 86400.0) as i64)
            }
        };
        Band {
            days_lo,
            days_hi,
            unix_lo: at(days_lo),
            unix_hi: at(days_hi),
        }
    }
    pub fn lo_date(&self) -> String {
        ymd(self.unix_lo)
    }
    pub fn hi_date(&self) -> String {
        if self.days_hi.is_finite() {
            ymd(self.unix_hi)
        } else {
            "unbounded".into()
        }
    }
}

#[derive(Debug, Clone)]
pub struct Projection {
    pub captured_unix: i64,
    pub chain_height: u64,
    pub chain_slot: u64,
    pub blocks_per_day: f64,
    pub reserve_mib: f64,
    /// Nine validators booting at once, current binary. The PEAK curve, and
    /// the earlier date: the one an operator plans a roll against.
    pub roll: Band,
    /// Nine validators resident, nobody touching them. The STEADY curve,
    /// measured on the live fleet rather than extrapolated from a replay.
    pub drift: Band,
    /// The same two with the block map moved to the store.
    pub roll_storebacked: Band,
    pub drift_storebacked: Band,
    pub roll_box: BoxRollup,
    pub drift_box: BoxRollup,
    pub reserve_sensitivity_days: f64,
    pub box_spread_days: f64,
    pub mark_staleness_blocks: u64,
    pub fork_overhang_blocks: Option<u64>,
    /// Days the store-backed fleet survives if transaction volume reaches one
    /// per block. The wall behind the wall.
    pub storebacked_days_at_one_tx_per_block: f64,
}

/// Build the projection **from the snapshot**. Box size, validator count,
/// resident set, boot peaks, block cadence and fork overhang all come off the
/// live fleet. Only the growth rates are constants, and even the steady one is
/// now a fleet measurement rather than a single-node extrapolation.
///
/// The two curves take **different rates**, which is the substantive change
/// here: the peak grows at 0.01718 MiB/block and the steady at 0.00814, so the
/// boot premium is not constant — it grows at their difference. Using one rate
/// for both was the previous model's largest error.
pub fn project(snap: &Snapshot, reserve_mib: f64) -> Projection {
    let bpd = snap
        .blocks_per_day_measured
        .unwrap_or(BLOCKS_PER_DAY_AT_DERIVATION);
    let peak = PEAK_MIB_PER_BLOCK_BASELINE;
    let steady = STEADY_MIB_PER_BLOCK_FLEET;

    // Nine SIMULTANEOUS peaks is max_hwm x N, not the sum of the nine marks.
    // The nine marks were set minutes-to-days apart, each with a different
    // number of siblings already resident, so their sum is not a picture of
    // nine peaks at once and is systematically too small.
    let roll_need = |b: &BoxRollup| b.max_hwm_mib * b.validators as f64;
    let drift_need = |b: &BoxRollup| b.sum_rss_mib;

    let rbox = snap.binding_box(reserve_mib, peak, bpd, roll_need);
    let dbox = snap.binding_box(reserve_mib, REPLAY_RETENTION_MIB_PER_BLOCK, bpd, drift_need);

    let rn = rbox.validators as f64;
    let dn = dbox.validators as f64;
    let rhead = rbox.mem_total_mib - reserve_mib - roll_need(&rbox);
    let dhead = dbox.mem_total_mib - reserve_mib - drift_need(&dbox);

    // A single rate per curve, so each Band is a point until the store-backed
    // arm widens it. The width now lives in the store-backed arm and in the
    // transaction scenario, not in a disagreement between two fits.
    let roll = Band::new(
        snap.captured_unix,
        days_until(rhead, peak, bpd, rn),
        days_until(rhead, peak, bpd, rn),
    );
    // The drift band has two ENDS with two provenances, not one rate twice.
    // The binding end is the replay's own retention rate (0.01188 MiB/block);
    // the optimistic end is what the live fleet is currently adding
    // (0.00814). The fleet reading is the LOWER bound of the two on purpose:
    // a validator at the tip is filling allocator slack the replay transient
    // left behind, so short-run RSS growth understates the durable rate until
    // that slack is gone. Taking the fleet number alone would be optimistic.
    let drift = Band::new(
        snap.captured_unix,
        days_until(dhead, REPLAY_RETENTION_MIB_PER_BLOCK, bpd, dn),
        days_until(dhead, steady, bpd, dn),
    );

    // Store-backed: the level drops by the measured ratio AND the rate drops.
    // Applying the isolated node's level ratio to a fleet validator is the
    // modelled step; both rates are measured.
    let lvl = STOREBACKED_PEAK_MIB / BASELINE_PEAK_MIB;
    let rhead_sb = rbox.mem_total_mib - reserve_mib - roll_need(&rbox) * lvl;
    let dhead_sb = dbox.mem_total_mib - reserve_mib - drift_need(&dbox) * lvl;
    let roll_storebacked = Band::new(
        snap.captured_unix,
        days_until(rhead_sb, PEAK_MIB_PER_BLOCK_STOREBACKED_HI, bpd, rn),
        days_until(rhead_sb, PEAK_MIB_PER_BLOCK_STOREBACKED_LO, bpd, rn),
    );
    let drift_storebacked = Band::new(
        snap.captured_unix,
        days_until(dhead_sb, PEAK_MIB_PER_BLOCK_STOREBACKED_HI, bpd, dn),
        days_until(dhead_sb, PEAK_MIB_PER_BLOCK_STOREBACKED_LO, bpd, dn),
    );

    // The wall behind the wall. At one transaction per block the committed
    // state term alone is STATE_MIB_PER_TX per block -- far above the baseline
    // block-map term store-backing removed.
    let storebacked_days_at_one_tx_per_block =
        days_until(rhead_sb, STATE_MIB_PER_TX * 1.0, bpd, rn);

    let rhead_half = rbox.mem_total_mib - reserve_mib / 2.0 - roll_need(&rbox);
    let best = snap
        .boxes()
        .into_iter()
        .map(|b| {
            days_until(
                b.mem_total_mib - reserve_mib - roll_need(&b),
                peak,
                bpd,
                b.validators as f64,
            )
        })
        .fold(f64::NEG_INFINITY, f64::max);

    Projection {
        captured_unix: snap.captured_unix,
        chain_height: snap.chain_height,
        chain_slot: snap.chain_slot,
        blocks_per_day: bpd,
        reserve_mib,
        roll,
        drift,
        roll_storebacked,
        drift_storebacked,
        reserve_sensitivity_days: days_until(rhead_half, peak, bpd, rn) - roll.days_lo,
        box_spread_days: best - roll.days_lo,
        mark_staleness_blocks: snap.mark_staleness_blocks(),
        fork_overhang_blocks: snap.fork_overhang_blocks,
        roll_box: rbox,
        drift_box: dbox,
        storebacked_days_at_one_tx_per_block,
    }
}

// ─────────────────────────────────────────────────────── documented claim ──

/// The dates this repo publishes, as days from the snapshot that produced
/// them. The tests recompute from a fresh snapshot and fail when reality has
/// moved them by more than [`CLAIM_TOLERANCE_DAYS`]. That is the staleness
/// alarm: nobody has to remember to look.
pub const CLAIMED_ROLL_DAYS: f64 = 34.6;
pub const CLAIMED_DRIFT_DAYS: f64 = 57.6;
/// Seven days: less than that and the programme's sequencing does not change;
/// more and a week of plan rests on a number that no longer holds.
pub const CLAIM_TOLERANCE_DAYS: f64 = 7.0;

/// Snapshot older than this and the projection is not evidence any more.
pub const SNAPSHOT_MAX_AGE_DAYS: f64 = 14.0;

/// If the freshest VmHWM on the fleet was set more blocks ago than this, no
/// mark on the fleet bounds a boot today and the roll arm is unsupported.
/// 20,000 blocks is about a week at the measured cadence.
pub const MARK_MAX_STALENESS_BLOCKS: u64 = 20_000;

// ───────────────────────────────────────────────────────────── reporting ───

fn ymd(unix: i64) -> String {
    // civil_from_days, Howard Hinnant. No dependency is worth a date.
    let z = unix.div_euclid(86400) + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{:02}-{:02}", if m <= 2 { y + 1 } else { y }, m, d)
}

impl Projection {
    pub fn report(&self, snap: &Snapshot) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "GENESIS-4 FLEET MEMORY PROJECTION");
        let _ = writeln!(
            s,
            "recomputed from scripts/fleet-memory-observations.tsv, not restated\n"
        );
        let _ = writeln!(
            s,
            "snapshot   {}   chain height {}   slot {}   cadence {:.0} blocks/day MEASURED",
            ymd(self.captured_unix),
            self.chain_height,
            self.chain_slot,
            self.blocks_per_day
        );
        let _ = writeln!(
            s,
            "reserve    {:.0} MiB held for page cache (MODELLED)\n",
            self.reserve_mib
        );

        let _ = writeln!(
            s,
            "{:<16} {:>6} {:>3} {:>4} {:>9} {:>9}",
            "BOX", "TOTAL", "N", "LENS", "SUM_RSS", "MAX_HWM"
        );
        for b in snap.boxes() {
            let agree = b.lens_argv == b.lens_pgrep
                && b.lens_pgrep == b.lens_units
                && b.lens_units == b.lens_datadirs;
            let _ = writeln!(
                s,
                "{:<16} {:>6.0} {:>3} {:>4} {:>9.1} {:>9.1}",
                b.ip,
                b.mem_total_mib,
                b.validators,
                if agree { "4/4" } else { "DIS" },
                b.sum_rss_mib,
                b.max_hwm_mib
            );
        }
        let _ = writeln!(
            s,
            "\nLENS is the number of INDEPENDENT enumerations of tenancy that agree\n\
             (argv, pgrep, systemd units, distinct --data-dir). A briefing put this\n\
             fleet at 10 validators per box, which would cut the per-validator ceiling\n\
             from 3,199 to 2,879 MiB. All four lenses on all seven boxes return {}.",
            EXPECTED_VALIDATORS_PER_BOX
        );

        let _ = writeln!(s, "\nTWO CURVES, TWO DATES. They are not the same risk.\n");
        let _ = writeln!(
            s,
            "  ROLL   nine boot at once -- the PEAK curve, paid at every restart\n\
             \x20        {}   ({:.1} days)   binds on {} ({})\n\
             \x20        need {:.0} MiB = 9 x {:.1} peak against {:.0} MiB of capacity\n\
             \x20        at {:.5} MiB/block, reproduced to four digits over three lengths",
            self.roll.lo_date(),
            self.roll.days_lo,
            self.roll_box.ip,
            self.roll_box.max_hwm_unit,
            self.roll_box.max_hwm_mib * self.roll_box.validators as f64,
            self.roll_box.max_hwm_mib,
            self.roll_box.mem_total_mib - self.reserve_mib,
            PEAK_MIB_PER_BLOCK_BASELINE
        );
        let _ = writeln!(
            s,
            "\n  DRIFT  nine resident, nobody touching them -- the STEADY curve\n\
             \x20        {} .. {}   ({:.1}-{:.1} days)   binds on {}\n\
             \x20        need {:.1} MiB resident against {:.0} MiB of capacity\n\
             \x20        binding end {:.5} MiB/block (the replay's own retention rate)\n\
             \x20        optimistic end {:.5} MiB/block (63 live validators, 1.45 h)",
            self.drift.lo_date(),
            self.drift.hi_date(),
            self.drift.days_lo,
            self.drift.days_hi,
            self.drift_box.ip,
            self.drift_box.sum_rss_mib,
            self.drift_box.mem_total_mib - self.reserve_mib,
            REPLAY_RETENTION_MIB_PER_BLOCK,
            STEADY_MIB_PER_BLOCK_FLEET
        );

        let _ = writeln!(
            s,
            "\nWHY THE PEAK IS ABOVE THE STEADY STATE -- A MECHANISM, NOT A SLOPE\n\n\
             \x20 RSS is NOT monotone across a replay. Sampled at 50 ms over five runs\n\
             \x20 (noise floor 8 kB), the peak lands at t~253 s of a 376 s run, at height\n\
             \x20 ~{} of {:.0} -- 60% of the blocks -- and the run then GIVES BACK 96 MiB.\n\
             \x20 End of replay {:.1} MiB against VmHWM {:.1}.\n\n\
             \x20 The transient has a cause, and the alternatives were eliminated by\n\
             \x20 measurement rather than by argument. Carryover and state-root work\n\
             \x20 finish at t~0.5 s and t~52 s, long before the peak. MEMO_CAP is\n\
             \x20 eliminated twice over: rolled_to performed ZERO rolls in the entire\n\
             \x20 replay, and four extra mainnet-sized states measure {:.0} kB anyway.\n\n\
             \x20 What remains: REORG_STATE_WINDOW holding a state makes the eUTXO Arc\n\
             \x20 SHARED, and a shared Arc sends the next mutation through Arc::make_mut\n\
             \x20 -- a clone of the whole {}-entry map, {:.1} MiB a time. Counted:\n\
             \x20 {} mutations copied the map, {} mutated in place. The curve steps in\n\
             \x20 units of exactly {:.1} MiB and releases exactly two in one 50 ms sample.\n\n\
             \x20 So the retention window is the ENABLER, not the cost. And the peak\n\
             \x20 scales with the SIZE OF THE eUTXO MAP, not with chain length: at the\n\
             \x20 measured 0.0356 tx/block the map is near-constant, so the premium is a\n\
             \x20 roughly fixed 1-2 copies and grows only when usage does.\n\n\
             \x20 OPEN, and stated rather than smoothed over: a constant transient does\n\
             \x20 not by itself explain a peak slope of {:.5} MiB/block reproduced to four\n\
             \x20 digits across three lengths. The mechanism is confirmed; it does not yet\n\
             \x20 close the arithmetic. Counting live CoW copies against replay length is\n\
             \x20 the next measurement, and until it exists the roll arm keeps the\n\
             \x20 reproduced slope rather than the mechanism's prediction.",
            REPLAY_PEAK_AT_HEIGHT,
            REPLAY_BLOCKS_MEASURED,
            END_OF_REPLAY_RSS_MIB,
            REPLAY_VMHWM_MIB,
            MEMO_FOUR_STATES_KIB,
            COW_MAP_ENTRIES,
            COW_MAP_COPY_MIB,
            COW_COPYING_MUTATIONS,
            COW_INPLACE_MUTATIONS,
            COW_MAP_COPY_MIB,
            PEAK_MIB_PER_BLOCK_BASELINE
        );

        let _ = writeln!(s, "\n{WHY_THE_MODEL_GAP_IS_A_LEVEL}");

        let _ = writeln!(
            s,
            "\nSECOND ARM -- block map moved to the store\n\n\
             \x20 ROLL   {} .. {}   ({:.0}-{:.0} days)\n\
             \x20 DRIFT  {} .. {}   ({:.0}-{:.0} days)\n\n\
             \x20 Level: {:.1} -> {:.1} MiB peak, same box, back to back, identical 410 MB\n\
             \x20 log, final code -- -39.3% memory and -3.3% on the clock. Rate:\n\
             \x20 {:.5} -> {:.5}-{:.5} MiB/block. Twelve replays (2 snapshots x 3 lengths\n\
             \x20 x 2 binaries), EVERY state root matched its pair, two checked against\n\
             \x20 three live validators.\n\n\
             \x20 The mechanism is confirmed numerically, not asserted: the term removed\n\
             \x20 is 13.9-14.6 KB/block against a measured on-disk envelope of {:.0}\n\
             \x20 B/block. Applying the isolated node's LEVEL ratio to a fleet validator\n\
             \x20 is the one modelled step; both rates are measured.",
            self.roll_storebacked.lo_date(),
            self.roll_storebacked.hi_date(),
            self.roll_storebacked.days_lo,
            self.roll_storebacked.days_hi,
            self.drift_storebacked.lo_date(),
            self.drift_storebacked.hi_date(),
            self.drift_storebacked.days_lo,
            self.drift_storebacked.days_hi,
            BASELINE_PEAK_MIB,
            STOREBACKED_PEAK_MIB,
            PEAK_MIB_PER_BLOCK_BASELINE,
            PEAK_MIB_PER_BLOCK_STOREBACKED_LO,
            PEAK_MIB_PER_BLOCK_STOREBACKED_HI,
            ENVELOPE_BYTES_PER_BLOCK
        );

        let _ = writeln!(
            s,
            "\nTHE WALL BEHIND THE WALL -- STORE-BACKING CLEARS THE FRONT ONE ONLY\n\n\
             \x20 What survives store-backing is NOT the block map (0.00029 of a per BLOCK\n\
             \x20 0.0031 MiB/block residual). About 90% of the residual is the committed\n\
             \x20 state -- the eUTXO ledger -- measured across a window carrying 1,048\n\
             \x20 transactions in 29,472 blocks. That is {:.4} tx/block: a nearly empty\n\
             \x20 chain.\n\n\
             \x20 The eUTXO set grows with USAGE, not with blocks and not with the\n\
             \x20 calendar. Dividing through gives {:.4} MiB of resident state per\n\
             \x20 transaction (DERIVED -- arithmetic on measured inputs, one low-volume\n\
             \x20 window). At ONE transaction per block the state term alone is {:.4}\n\
             \x20 MiB/block, which is {:.1}x the baseline block-map term store-backing\n\
             \x20 removed, and the store-backed fleet exhausts a box in {:.0} DAYS.\n\n\
             \x20 The date does not merely return. It arrives sooner than it would have\n\
             \x20 without the fix, because the fix removed the term that does NOT grow\n\
             \x20 with usage. And the validator-opening programme exists to add users.",
            TX_PER_BLOCK_MEASURED,
            STATE_MIB_PER_TX,
            STATE_MIB_PER_TX,
            STATE_MIB_PER_TX / PEAK_MIB_PER_BLOCK_BASELINE,
            self.storebacked_days_at_one_tx_per_block
        );

        let _ = writeln!(
            s,
            "\nWHAT SETS THE WIDTH, AND WHAT IS NOT IN IT\n\n\
             \x20 drift band, two provenances        {:.1} days\n\
             \x20 page-cache reserve, if halved      {:.1} days\n\
             \x20 best box vs worst box              {:.1} days\n\n\
             \x20 Not in the band, and larger than everything in it: the chain is {} slots\n\
             \x20 old and the ROLL date is slot ~{:.0}, {:.1}x the chain that exists today,\n\
             \x20 while every rate behind it was measured on a log of at most ~30,600\n\
             \x20 blocks. A band cannot express an extrapolation.",
            self.drift.days_hi - self.drift.days_lo,
            self.reserve_sensitivity_days,
            self.box_spread_days,
            self.chain_slot,
            self.chain_slot as f64 + self.roll.days_lo * SLOTS_PER_DAY,
            (self.chain_slot as f64 + self.roll.days_lo * SLOTS_PER_DAY) / self.chain_slot as f64
        );

        let _ = writeln!(
            s,
            "\nFLOOR, NOT HEADROOM\n\n\
             \x20 The freshest VmHWM on the fleet was set {} blocks ago ({:.1} days). Every\n\
             \x20 peak above is a LOWER BOUND on what a boot costs today.\n\
             \x20 Do NOT restart a validator to refresh a mark -- that is a double-signing\n\
             \x20 risk incurred for a number. Measure a candidate boot on an IDLE box at\n\
             \x20 tip height and pass it to scripts/fleet-memory-gate.sh as --peak-mib.",
            self.mark_staleness_blocks,
            self.mark_staleness_blocks as f64 / self.blocks_per_day
        );

        match self.fork_overhang_blocks {
            Some(f) => {
                let _ = writeln!(
                    s,
                    "\nFORK OVERHANG -- the term with no plan\n\n\
                     \x20 {f} non-canonical blocks held whole in RAM (blocks_known - height;\n\
                     \x20 read 225/226/226 on three validators). About {:.1} MiB at the measured\n\
                     \x20 envelope. Small today, unbounded in principle, and the only growing\n\
                     \x20 term here with no workstream aimed at it -- including the store-backed\n\
                     \x20 change, which moves the CANONICAL map to disk.",
                    f as f64 * ENVELOPE_BYTES_PER_BLOCK / 1_048_576.0
                );
            }
            None => {
                let _ = writeln!(
                    s,
                    "\nFORK OVERHANG\n\n\
                     \x20 Not recorded in this snapshot. Re-run the collector: it is the one\n\
                     \x20 growing term with no workstream aimed at it."
                );
            }
        }

        let _ = writeln!(s, "\nINPUTS\n");
        for i in INPUTS {
            let tag = match i.standing {
                Standing::Measured => "MEASURED   ",
                Standing::Modelled => "MODELLED   ",
                Standing::Superseded => "SUPERSEDED ",
                Standing::Discredited => "DISCREDITED",
            };
            let _ = writeln!(s, "  {tag} {:<48} {:.5} {}", i.name, i.value, i.unit);
            let _ = writeln!(s, "              {}", i.source);
        }
        let _ = writeln!(s, "\n{WHAT_THIS_CANNOT_DO}");
        s
    }
}

#[cfg(test)]
mod tests;
