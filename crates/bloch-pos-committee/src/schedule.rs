// SPDX-License-Identifier: MIT OR Apache-2.0

//! Slot/epoch scheduling and proposer assignment (§5.1, §5.2 of the migration
//! design).
//!
//! With GhostDAG retired (§5.2), Genesis-4 is a linear chain: exactly one
//! validator is *designated* to propose in each 30-second slot, and concurrency
//! becomes an anomaly instead of the norm. This module is where that
//! designation lives — slot/epoch/time arithmetic plus the stake-weighted
//! proposer draw, both as pure functions of their arguments.
//!
//! ## Time never comes from inside
//!
//! Every function here takes `genesis_time` (and, where relevant, a timestamp)
//! as an argument. None of them reads the system clock. This is the §5.5 rule
//! again — the one written in blood after `expected_bits` was derived from
//! node-local mutable state and split a fleet of byte-identical binaries on
//! 2026-08-08. A consensus function that consults `SystemTime::now()` is a
//! consensus function whose output differs across nodes by construction. The
//! caller (the node's non-consensus shell) owns the clock; this module owns
//! only the arithmetic.
//!
//! All arithmetic is total: overflow and before-genesis inputs return `None`
//! rather than panicking, because a consensus path that can panic on a
//! remote-supplied value is a remote crash button.
//!
//! ## The sortition is public — on purpose (§6.4)
//!
//! The obvious design would be VRF-based *private* sortition (Algorand-style),
//! where a proposer proves its eligibility only when it reveals its block.
//! That is not available post-quantum:
//!
//! - **ML-DSA signatures are not unique** (FIPS 204 is randomised; many valid
//!   signatures exist per (key, message) pair), so "hash of a signature" as a
//!   VRF output is grindable — a proposer could re-sign until the draw favours
//!   it. Falcon is not unique either, and the hybrid is not unique twice over.
//! - Lattice VRFs (LB-VRF et al.) achieve uniqueness only for a bounded number
//!   of evaluations per key. Research-grade, not a mainnet foundation in 2026.
//!
//! Consequence, accepted deliberately: **anyone who knows the beacon mix and
//! the validator set can compute the full proposer schedule.** That is a real
//! DoS surface — an attacker can aim traffic at the next proposer — and it is
//! documented here rather than hidden. The mitigations, none of which live in
//! this file's code but all of which shape its API:
//!
//! - **The schedule is only *knowable* a bounded distance ahead.** The beacon
//!   mix that seeds epoch `E` is fixed when epoch
//!   `E − 1 − MIN_SEED_LOOKAHEAD_EPOCHS` closes (the F6 look-ahead — see
//!   [`crate::committees::MIN_SEED_LOOKAHEAD_EPOCHS`]), so the exposure window
//!   is bounded at about two epochs (~32 min), not the whole future. The
//!   look-ahead *widens* this window by one epoch relative to the pre-F6 rule;
//!   what it buys is that no proposer of epoch `E − 1` can re-sort epoch `E`'s
//!   duties by withholding reveals. This module will happily compute any epoch
//!   you hand it a mix for — the horizon is a property of *when the mix
//!   exists*, enforced by the beacon, not by hiding a capability here.
//! - **A proposer is an index, not a network address.** Everything returned
//!   here is a `u32` into the active validator registry. Mapping that index to
//!   an IP requires deanonymising the validator's networking, which is what
//!   sentry-node topologies exist to prevent.
//! - A PQ-VRF research track (§14) can upgrade this to private sortition later
//!   without touching anything downstream of the returned index.
//!
//! ## Why the proposer draw reuses [`Role::SlotSubcommittee`]
//!
//! The proposer for slot `s` is the *first* validator drawn from the same XOF
//! stream that produces the slot-`s` subcommittee: a `k = 1` call to
//! [`sample`] with the same `(beacon_mix, slot, role)` tuple. Two reasons:
//!
//! - **One definition of the draw.** A separate proposer role would be a
//!   second sampling code path that must never disagree with the first in any
//!   corner case. Same argument as [`crate::sample::is_selected`]: fewer
//!   independent definitions, fewer ways to split consensus.
//! - **The proposer sits in its own subcommittee.** Because `sample` consumes
//!   the XOF deterministically, the first accepted draw of the `k = 8` call is
//!   exactly the `k = 1` result, so the proposer always carries fork-choice
//!   weight in its own slot. This is pinned by a test, not just asserted here.

use crate::params::{SLOTS_PER_EPOCH, SLOT_DURATION_SECS};
use crate::sample::{sample, Role, Validator};

/// The slot whose window opens exactly at `genesis_time`.
pub const GENESIS_SLOT: u64 = 0;

// ── slot ↔ epoch ↔ time arithmetic ──────────────────────────────────────────
//
// `const fn` throughout: these are pure integer maps, and keeping them `const`
// is a compiler-enforced guarantee that they cannot grow a clock read, an
// allocation, or any other effect later.

/// Slot whose window contains `timestamp` (Unix seconds).
///
/// `None` before genesis: there is no "slot -1", and mapping pre-genesis time
/// to slot 0 would make two distinct instants claim the same slot — the kind
/// of edge that turns into an off-by-one at the transition seam (§5.2).
pub const fn slot_at(genesis_time: u64, timestamp: u64) -> Option<u64> {
    match timestamp.checked_sub(genesis_time) {
        Some(elapsed) => Some(elapsed / SLOT_DURATION_SECS),
        None => None,
    }
}

/// Unix time at which `slot`'s window opens. `None` on `u64` overflow.
pub const fn slot_start(genesis_time: u64, slot: u64) -> Option<u64> {
    match slot.checked_mul(SLOT_DURATION_SECS) {
        Some(offset) => genesis_time.checked_add(offset),
        None => None,
    }
}

/// First slot of `epoch`. `None` on overflow.
pub const fn first_slot_of_epoch(epoch: u64) -> Option<u64> {
    epoch.checked_mul(SLOTS_PER_EPOCH)
}

/// Last slot of `epoch` — the one carrying the full committee's finality vote
/// (see [`crate::is_epoch_boundary`]). `None` on overflow.
pub const fn last_slot_of_epoch(epoch: u64) -> Option<u64> {
    match first_slot_of_epoch(epoch) {
        Some(first) => first.checked_add(SLOTS_PER_EPOCH - 1),
        None => None,
    }
}

/// Epoch whose window contains `timestamp`. `None` before genesis.
///
/// Defined as [`slot_at`] composed with [`crate::epoch_of`] rather than as
/// independent arithmetic, so the two views of time cannot drift apart.
pub const fn epoch_at(genesis_time: u64, timestamp: u64) -> Option<u64> {
    match slot_at(genesis_time, timestamp) {
        Some(slot) => Some(crate::epoch_of(slot)),
        None => None,
    }
}

/// Unix time at which `epoch`'s first slot opens. `None` on overflow.
pub const fn epoch_start(genesis_time: u64, epoch: u64) -> Option<u64> {
    match first_slot_of_epoch(epoch) {
        Some(first) => slot_start(genesis_time, first),
        None => None,
    }
}

// ── proposer designation ────────────────────────────────────────────────────

/// The validator designated to propose in `slot`, or `None` if no validator
/// has positive effective stake.
///
/// A `k = 1` stake-weighted draw via [`sample`] under [`Role::SlotSubcommittee`]
/// — deliberately the same `(beacon_mix, index, role)` tuple as
/// [`crate::slot_subcommittee`], so the proposer is always the first-drawn
/// member of its own slot's subcommittee (see the module docs for why).
///
/// An empty result is not an error: a slot with no eligible proposer is simply
/// skipped, exactly like a proposer that withholds (§6.3), and the caller's
/// fork choice treats it as an empty slot.
pub fn proposer(beacon_mix: &[u8; 32], slot: u64, validators: &[Validator]) -> Option<u32> {
    sample(beacon_mix, slot, Role::SlotSubcommittee, validators, 1).first().copied()
}

/// The full proposer roster for one epoch: who proposes in each of its
/// [`SLOTS_PER_EPOCH`] slots.
///
/// Computable the moment the seeding beacon mix exists — i.e. one epoch ahead
/// (§6.3/§6.4) — which is exactly how validators learn their upcoming duties
/// without any per-slot recomputation or coordination message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochSchedule {
    /// The epoch this roster covers.
    pub epoch: u64,
    /// `proposers[i]` proposes in slot `first_slot_of_epoch(epoch) + i`.
    /// `None` means the slot has no eligible proposer and will be skipped.
    pub proposers: [Option<u32>; SLOTS_PER_EPOCH as usize],
}

impl EpochSchedule {
    /// Proposer for an **absolute** slot number.
    ///
    /// `None` both when the slot lies outside this epoch and when the slot has
    /// no proposer. Callers that need to distinguish the two should range-check
    /// with [`crate::epoch_of`] first; conflating them here is deliberate —
    /// "look up a slot in the wrong epoch's schedule" must never yield a
    /// validator index that looks authoritative.
    pub fn proposer_at(&self, slot: u64) -> Option<u32> {
        if crate::epoch_of(slot) != self.epoch {
            return None;
        }
        // epoch_of(slot) == self.epoch implies first_slot_of_epoch cannot
        // have overflowed, so the subtraction is in range.
        let first = first_slot_of_epoch(self.epoch)?;
        self.proposers[(slot - first) as usize]
    }
}

/// Compute the proposer roster for `epoch` from the beacon mix that seeds it.
///
/// `beacon_mix` must be the seed selected by [`crate::committees::seed_mix`] —
/// the mix as fixed at the close of epoch
/// `epoch − 1 − MIN_SEED_LOOKAHEAD_EPOCHS` (finding F6). Passing any other mix
/// produces a well-formed but wrong schedule, and nothing here can detect that
/// — the binding of mix to epoch is the beacon's job, not the scheduler's.
///
/// `None` only when the epoch's slot numbers are not representable in `u64`
/// (an epoch ~5.4 × 10¹⁷ — unreachable in practice, but a consensus function
/// is not allowed to panic on *any* input).
pub fn epoch_schedule(
    beacon_mix: &[u8; 32],
    epoch: u64,
    validators: &[Validator],
) -> Option<EpochSchedule> {
    let first = first_slot_of_epoch(epoch)?;
    // If the last slot overflows, part of the roster would be unaddressable;
    // reject the whole epoch rather than return a half-valid schedule.
    last_slot_of_epoch(epoch)?;
    let mut proposers = [None; SLOTS_PER_EPOCH as usize];
    for (i, p) in proposers.iter_mut().enumerate() {
        // Each slot is an independent draw: `sample` mixes the slot number
        // into the XOF seed, so one epoch's roster is 32 separate weighted
        // draws, not 32 reads of one shuffled list. A validator's chance in
        // slot n is therefore independent of who got slot n-1 — with heavily
        // skewed stake the same validator legitimately repeats.
        *p = proposer(beacon_mix, first + i as u64, validators);
    }
    Some(EpochSchedule { epoch, proposers })
}
