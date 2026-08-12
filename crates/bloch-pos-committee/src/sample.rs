// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic stake-weighted committee sampling.
//!
//! Every node must derive the identical committee for a given slot or epoch
//! from the identical inputs, with no reference to node-local state. That is
//! the rule §5.5 of the migration design exists to enforce, and the reason the
//! entry points here take *everything* explicitly: the beacon mix, the index,
//! and the active validator set as committed by the parent block. There is no
//! constructor that reads a clock, a config file, or a cached set.

use crate::params::{DS_SORTITION, ROLE_EPOCH, ROLE_SLOT};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// One active validator, as committed in the parent block's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validator {
    /// Index into the active validator registry.
    pub index: u32,
    /// Effective stake in satoshis, already clamped by `MAX_VALIDATOR_STAKE`
    /// and already zero for anything ineligible (§4.1 taint rules).
    pub effective_stake: u64,
}

/// Which committee is being drawn. Distinct roles must never collide, or the
/// per-slot subcommittee would be a predictable subset of the epoch committee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Per-slot fork-choice sample (`SLOT_SUBCOMMITTEE_SIZE`).
    SlotSubcommittee,
    /// Epoch-boundary finality committee (`COMMITTEE_SIZE`).
    EpochCommittee,
}

impl Role {
    fn tag(self) -> u8 {
        match self {
            Role::SlotSubcommittee => ROLE_SLOT,
            Role::EpochCommittee => ROLE_EPOCH,
        }
    }
}

/// Draw `k` distinct validators, with probability proportional to effective
/// stake, deterministically.
///
/// Returns indices **sorted ascending**, so the result is canonical: two nodes
/// cannot agree on membership but disagree on encoding.
///
/// Selection is by rejection sampling over the cumulative-stake array. Two
/// details matter for consensus and are tested:
///
/// - **No modulo bias.** A draw is a 128-bit value reduced by rejection, not by
///   `%`. With `%`, low validator indices would be very slightly over-selected
///   — a bias no test would notice and an attacker eventually would.
/// - **Total, never looping.** If rejection cannot fill the committee within
///   [`MAX_DRAWS_PER_SLOT`] draws (possible when a few validators hold nearly
///   all stake), the remainder is filled from the unselected validators in
///   ascending index order. Deterministic, and it terminates. A consensus
///   function that can diverge on retry count is worse than one that is
///   slightly less random in a pathological distribution.
///
/// Validators with zero effective stake are never selected — not by the
/// weighted draw and not by the fallback.
pub fn sample(
    beacon_mix: &[u8; 32],
    index: u64,
    role: Role,
    validators: &[Validator],
    k: usize,
) -> Vec<u32> {
    let mut eligible: Vec<&Validator> =
        validators.iter().filter(|v| v.effective_stake > 0).collect();
    if eligible.is_empty() || k == 0 {
        return Vec::new();
    }
    // Canonicalise by validator index before anything else.
    //
    // The cumulative-stake array is built in iteration order, so without this
    // the draw is a function of how the caller happened to lay the registry
    // out in memory — two nodes with identical state but different ordering
    // would compute different committees and split consensus. This is the same
    // failure shape as `expected_bits` reading node-local mutable state
    // (§5.5); it is cheap to prevent and near-impossible to debug in the wild.
    eligible.sort_unstable_by_key(|v| v.index);

    // A duplicate validator index is a malformed registry, and the sampler used
    // to accept it silently: both entries occupied adjacent cumulative-stake
    // ranges and both could be drawn, so one validator took two seats and the
    // committee had one fewer distinct member than its size claims — found by
    // property test, 2026-08-11.
    //
    // Deduplicating keeps the function total and deterministic, which a panic
    // would not: a consensus function that aborts on malformed committed state
    // takes the node down instead of rejecting a block. Keeping the first
    // occurrence after the index sort is order-independent, since the sort key
    // is the index itself. Summing the stakes instead would be worse — it would
    // silently grant the duplicate more weight, which is exactly the outcome a
    // corrupt registry would be trying to buy.
    eligible.dedup_by_key(|v| v.index);
    // Fewer eligible validators than seats: everyone serves. Not an error —
    // it is the expected state of a young network, and the caller decides
    // whether that quorum is acceptable.
    if eligible.len() <= k {
        let mut out: Vec<u32> = eligible.iter().map(|v| v.index).collect();
        out.sort_unstable();
        return out;
    }

    // Cumulative stake in u128: 100e9 BLCH × 1e8 sat fits u64 (barely — 54%
    // of u64::MAX, see tokenomics_v4's headroom asserts), but the running
    // sum of a large set does not comfortably, and overflow here would be a
    // consensus split.
    let mut cumulative: Vec<u128> = Vec::with_capacity(eligible.len());
    let mut total: u128 = 0;
    for v in &eligible {
        total += v.effective_stake as u128;
        cumulative.push(total);
    }

    let mut xof = {
        let mut h = Shake256::default();
        h.update(&DS_SORTITION);
        h.update(beacon_mix);
        h.update(&index.to_le_bytes());
        h.update(&[role.tag()]);
        h.finalize_xof()
    };

    // Largest multiple of `total` that fits in u128; draws at or above this
    // are rejected so the accepted range is an exact multiple of `total`.
    let limit = (u128::MAX / total) * total;

    let mut chosen: Vec<u32> = Vec::with_capacity(k);
    let mut taken = vec![false; eligible.len()];
    let mut draws = 0usize;

    while chosen.len() < k && draws < crate::params::MAX_DRAWS_PER_SLOT {
        draws += 1;
        let r = loop {
            let mut buf = [0u8; 16];
            xof.read(&mut buf);
            let v = u128::from_le_bytes(buf);
            if v < limit {
                break v % total;
            }
            // Rejected draw still consumes XOF output, which keeps the stream
            // position a deterministic function of the inputs.
        };
        let pos = cumulative.partition_point(|&c| c <= r);
        if !taken[pos] {
            taken[pos] = true;
            chosen.push(eligible[pos].index);
        }
    }

    // Deterministic fallback (see doc comment).
    if chosen.len() < k {
        for (i, v) in eligible.iter().enumerate() {
            if chosen.len() == k {
                break;
            }
            if !taken[i] {
                taken[i] = true;
                chosen.push(v.index);
            }
        }
    }

    chosen.sort_unstable();
    chosen
}

/// Whether `validator` is in the committee drawn for `index` under `role`.
///
/// Deliberately implemented as membership in the full draw rather than as a
/// standalone predicate: a per-validator shortcut that disagreed with `sample`
/// in any corner case would be a consensus split, so there is only one
/// definition of membership.
pub fn is_selected(
    beacon_mix: &[u8; 32],
    index: u64,
    role: Role,
    validators: &[Validator],
    k: usize,
    validator: u32,
) -> bool {
    sample(beacon_mix, index, role, validators, k).binary_search(&validator).is_ok()
}
