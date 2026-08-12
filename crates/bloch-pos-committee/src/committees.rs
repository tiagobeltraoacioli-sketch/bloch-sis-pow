// SPDX-License-Identifier: AGPL-3.0-or-later

//! Epoch committees — the active set **partitioned**, not sampled.
//!
//! # The bug this replaces
//!
//! The first design sampled 128 validators to vote at the epoch boundary. The
//! adversarial review (finding F1) showed the quorum denominator had no
//! coherent reading, and that both candidates fail:
//!
//! - **Denominator = network stake.** A 128-validator sample cannot hold two
//!   thirds of the network's stake once the network has more than ~192
//!   validators — and gate G4 *requires* at least 200. Finality would be
//!   structurally unreachable and the inactivity leak would fire forever.
//! - **Denominator = committee stake.** A 128-member sample has enough variance
//!   that an adversary holding ~30% of network stake exceeds one third of the
//!   committee in roughly one epoch in five, and can stall finality well below
//!   the nominal threshold.
//!
//! # The fix
//!
//! Partition instead of sampling: shuffle the active set deterministically and
//! cut it into [`SLOTS_PER_EPOCH`] committees, one per slot. Every active
//! validator lands in exactly one committee and votes exactly once per epoch,
//! so the union of an epoch's committees **is** the active set. The quorum
//! denominator is then total active stake with no ambiguity and no sampling
//! variance — the same property Ethereum gets, and for the same reason.
//!
//! This also removes finding F2. Under independent per-slot draws a validator
//! was routinely selected in several slots of one epoch, emitting several
//! attestations with the same `target_epoch` — which
//! [`crate::attestation::AttestationData::is_double_vote`] correctly flags as a
//! slashable double vote. Honest validators slashed themselves. Under a
//! partition each validator attests once per epoch, so two attestations sharing
//! a target epoch really are equivocation.
//!
//! # What it costs
//!
//! Per epoch the network carries one hybrid signature per active validator
//! (≈ 4,589 B), against 384 under the sampled design. **Partitioning is cheaper
//! below 384 validators** — which is where gate G4 puts the launch — and more
//! expensive above it. That is the honest trade: correctness now, and a scaling
//! ceiling at roughly 4,096 validators (128 per slot, ≈ 574 KB/slot) where
//! sub-sampling would have to return and F1 with it. Aggregation would lift the
//! ceiling, and the measured in-circuit cost (`spikes/prover-cost/RESULTS.md`)
//! says that is research, not engineering.
//!
//! # Which mix seeds which epoch
//!
//! The partition for epoch `N` is seeded by the mix fixed at the close of
//! epoch `N − 1 − `[`MIN_SEED_LOOKAHEAD_EPOCHS`] — see the constant's docs for
//! the attack this closes (finding F6: trailing-slot withholding re-sorting
//! the next epoch's partition) and the residual it does not.

use crate::params::{DS_SORTITION, SLOTS_PER_EPOCH};
use crate::sample::Validator;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// Role tag for the epoch partition. Distinct from the sortition roles so the
/// partition can never coincide with a proposer draw.
const ROLE_PARTITION: u8 = 0x03;

// ────────────────────────────────────────────────────────────────────────────
// Seed look-ahead (finding F6)
// ────────────────────────────────────────────────────────────────────────────

/// Seed look-ahead, in epochs (adversarial review, finding F6).
///
/// The partition for epoch `N` is seeded by the beacon mix as fixed at the
/// **close of epoch `N − 1 − MIN_SEED_LOOKAHEAD_EPOCHS`** — with a look-ahead
/// of one, the close of epoch `N − 2`. Ethereum's `MIN_SEED_LOOKAHEAD` is the
/// same device at the same value, for the same reason.
///
/// **What it closes.** Without the look-ahead, epoch `N` was seeded by the mix
/// at the close of epoch `N − 1`, so whoever proposed the last `t` slots of
/// `N − 1` could choose reveal-or-withhold per slot, grind `2^t` candidate
/// mixes, and pick the one whose epoch-`N` partition placed the most of their
/// own validators where they wanted them — re-sorting the body that decides
/// finality, not just one proposer slot. With the look-ahead, the seed for
/// epoch `N` is already fixed before epoch `N − 1` begins: **no slot the
/// adversary proposes in `N − 1` can influence `N`'s partition at all.**
///
/// **What it does not close — stated so nobody reads more into it.** The
/// last-revealer bias is displaced, not eliminated: the trailing proposers of
/// epoch `E` still bias the partition of epoch `E + 1 + MIN_SEED_LOOKAHEAD_EPOCHS`
/// by the standard one bit per withheld slot (§6.3), at the price of the
/// forfeited proposer rewards. That residual is inherent to RANDAO and is the
/// same one Ethereum accepts. Raising the look-ahead does not shrink it; it
/// only moves the target epoch further out.
///
/// **What it costs.** Duties become computable earlier: the schedule for epoch
/// `N` is public from the close of `N − 2`, widening the F7 DoS warning window
/// from one epoch to two (~32 min). That trade is deliberate — grinding the
/// finality partition is strictly worse than a longer warning for a DoS
/// surface that is public by design anyway (§6.4).
pub const MIN_SEED_LOOKAHEAD_EPOCHS: u64 = 1;

/// The epoch whose **closing** mix seeds `epoch`'s partition:
/// `epoch − 1 − MIN_SEED_LOOKAHEAD_EPOCHS`.
///
/// `None` for the first `MIN_SEED_LOOKAHEAD_EPOCHS + 1` epochs, which have no
/// usable boundary behind them and are seeded by the genesis mix instead
/// (see [`seed_mix`]). Those early epochs still partition differently from
/// each other because the epoch number is folded into the XOF seed.
pub const fn seed_epoch(epoch: u64) -> Option<u64> {
    epoch.checked_sub(MIN_SEED_LOOKAHEAD_EPOCHS + 1)
}

/// Select the mix that seeds `epoch`'s partition out of committed beacon
/// history.
///
/// `boundary_mixes[e]` must be the accumulated mix at the **close** of epoch
/// `e` — i.e. after the reveal of `e`'s last non-skipped slot was folded in.
/// This slice-from-genesis shape is the reference form; a node only ever needs
/// the last `MIN_SEED_LOOKAHEAD_EPOCHS + 1` boundary mixes at once (that is
/// exactly the two-epoch retention `StateReader::randao_mix_at` commits to).
///
/// Returns `None` when the needed boundary mix is missing from the slice.
/// Missing history is a caller bug and must fail loudly: silently falling
/// back to a newer mix would reintroduce F6 in the fallback path.
pub fn seed_mix(
    genesis_mix: &[u8; 32],
    boundary_mixes: &[[u8; 32]],
    epoch: u64,
) -> Option<[u8; 32]> {
    match seed_epoch(epoch) {
        None => Some(*genesis_mix),
        Some(e) => boundary_mixes.get(e as usize).copied(),
    }
}

/// [`epoch_committees`] with the F6 look-ahead applied — the safe entry point.
///
/// Callers that already hold the correct seed (because the beacon layer
/// selected it) may call [`epoch_committees`] directly; every other caller
/// should go through here so the mix-to-epoch binding is decided in exactly
/// one place. `None` propagates [`seed_mix`]'s missing-history failure.
pub fn seeded_epoch_committees(
    genesis_mix: &[u8; 32],
    boundary_mixes: &[[u8; 32]],
    epoch: u64,
    validators: &[Validator],
) -> Option<Vec<Vec<u32>>> {
    let mix = seed_mix(genesis_mix, boundary_mixes, epoch)?;
    Some(epoch_committees(&mix, epoch, validators))
}

/// Partition the active set into one committee per slot of `epoch`.
///
/// `beacon_mix` must be the seed selected by [`seed_mix`] — the mix at the
/// close of epoch `epoch − 1 − MIN_SEED_LOOKAHEAD_EPOCHS`, not the current
/// mix. Passing a later mix reintroduces finding F6: the trailing proposers
/// of the previous epoch regain the power to re-sort this epoch's partition
/// by withholding reveals. [`seeded_epoch_committees`] does the selection.
///
/// Returns `SLOTS_PER_EPOCH` committees, each sorted ascending, together
/// covering every eligible validator exactly once. Committee `i` serves slot
/// `i` of the epoch: its members carry that slot's fork-choice weight, and
/// their votes accumulate toward the epoch's justification.
///
/// Validators with zero effective stake are excluded entirely — ineligible
/// under §4.1, exited, or slashed.
///
/// Sizes differ by at most one. Members are assigned by count, not by stake,
/// which is safe because `MAX_VALIDATOR_STAKE` already caps any single
/// validator at 1% of active stake: no committee can be dominated by one member
/// unless the cap itself has been defeated.
pub fn epoch_committees(
    beacon_mix: &[u8; 32],
    epoch: u64,
    validators: &[Validator],
) -> Vec<Vec<u32>> {
    let n_slots = SLOTS_PER_EPOCH as usize;

    // Canonicalise before anything else. The order the caller happened to hold
    // the registry in must never reach the result — the same rule the sampler
    // learned the hard way.
    let mut eligible: Vec<u32> = validators
        .iter()
        .filter(|v| v.effective_stake > 0)
        .map(|v| v.index)
        .collect();
    eligible.sort_unstable();
    eligible.dedup();

    if eligible.is_empty() {
        return vec![Vec::new(); n_slots];
    }

    let mut xof = {
        let mut h = Shake256::default();
        h.update(&DS_SORTITION);
        h.update(beacon_mix);
        h.update(&epoch.to_le_bytes());
        h.update(&[ROLE_PARTITION]);
        h.finalize_xof()
    };

    // Fisher-Yates over the canonical order. Each draw is reduced by rejection
    // rather than by `%`: a modulo would bias low indices toward the tail of the
    // shuffle, which is a bias in committee membership, not a rounding detail.
    let len = eligible.len();
    for i in (1..len).rev() {
        let bound = (i + 1) as u128;
        let limit = (u128::MAX / bound) * bound;
        let j = loop {
            let mut buf = [0u8; 16];
            xof.read(&mut buf);
            let v = u128::from_le_bytes(buf);
            if v < limit {
                break (v % bound) as usize;
            }
            // A rejected draw still consumes XOF output, keeping the stream
            // position a deterministic function of the inputs.
        };
        eligible.swap(i, j);
    }

    // Cut into contiguous chunks. Sizes differ by at most one, and the larger
    // chunks go to the earliest slots — an arbitrary choice, but identical on
    // every node, which is the only property that matters.
    let base = len / n_slots;
    let extra = len % n_slots;
    let mut out = Vec::with_capacity(n_slots);
    let mut pos = 0usize;
    for slot in 0..n_slots {
        let take = base + usize::from(slot < extra);
        let mut c: Vec<u32> = eligible[pos..pos + take].to_vec();
        pos += take;
        c.sort_unstable();
        out.push(c);
    }
    out
}

/// The committee serving `slot` within its epoch.
///
/// Same seed contract as [`epoch_committees`]: `beacon_mix` is the F6-selected
/// seed for the slot's epoch, not the current mix.
pub fn committee_for_slot(
    beacon_mix: &[u8; 32],
    slot: u64,
    validators: &[Validator],
) -> Vec<u32> {
    let epoch = slot / SLOTS_PER_EPOCH;
    let idx = (slot % SLOTS_PER_EPOCH) as usize;
    epoch_committees(beacon_mix, epoch, validators)
        .into_iter()
        .nth(idx)
        .unwrap_or_default()
}

/// Total active stake — **the quorum denominator**, stated once so it cannot be
/// read two ways.
///
/// Justification requires attesting stake `w` with `3·w ≥ 2·total_active_stake`,
/// where the total is over the whole active set, not over any committee. That is
/// only a coherent rule because the epoch's committees partition the active set:
/// every validator gets exactly one chance to contribute, so the denominator is
/// reachable by construction.
pub fn total_active_stake(validators: &[Validator]) -> u128 {
    validators.iter().map(|v| v.effective_stake as u128).sum()
}

/// Does `stake_for` meet the two-thirds threshold of `total_active_stake`?
///
/// Integer form `3·w ≥ 2·total` — never floating point, and never
/// `w >= total * 2 / 3`, whose truncation admits a quorum one satoshi short.
/// Rounding here is consensus.
pub fn is_supermajority(stake_for: u128, total_active_stake: u128) -> bool {
    total_active_stake > 0 && stake_for.saturating_mul(3) >= total_active_stake.saturating_mul(2)
}
