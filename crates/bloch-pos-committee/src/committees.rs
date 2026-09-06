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
    Digest, Sha3_256, Shake256,
};
use std::cell::RefCell;

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

/// Mutation switch for the roster-split regression. `cfg(test)`, so it cannot
/// exist in a shipped binary — same idiom as
/// [`crate::params::rehearsal::MUTATE_SEED`] and
/// `finality`'s `IGNORE_LEAK_IN_DENOMINATOR`.
///
/// `true` restores the pre-2026-08-24 `effective_stake > 0` filter *before* the
/// shuffle, i.e. it puts the defect back. A regression test that cannot be made
/// to fail is not testing anything, so
/// `tests::rehearsal_restoring_the_filter_reopens_the_roster_split` flips this
/// and proves the pinning assertion goes red.
///
/// Constant `false` in every build that is not a test build, so the branch in
/// [`epoch_committees`] folds away.
#[inline]
fn mutation_restores_zero_stake_filter() -> bool {
    #[cfg(test)]
    {
        return crate::params::rehearsal::RESTORE_ZERO_STAKE_FILTER
            .load(std::sync::atomic::Ordering::Relaxed);
    }
    #[cfg(not(test))]
    false
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
/// # Membership is a pure function of the index set — stake decides WEIGHT only
///
/// Every validator in `validators` gets a seat. There is **no stake filter**
/// here, and the absence is load-bearing rather than an oversight: it is what
/// makes the partition *leak-invariant*, so no call path can change the
/// committees by holding a different variant of the same roster.
///
/// Until 2026-08-24 this function filtered `effective_stake > 0` **before** the
/// Fisher-Yates shuffle. A shuffle's XOF draws are length-dependent, so a list
/// of 64 and a list of 63 are not "the same permutation minus one element" —
/// they are entirely different permutations. `transition.rs` holds two rosters
/// for one epoch (`consensus_roster_at`, leak-applied, and `duty_roster_at`,
/// not), and `with_leak_applied` uses `saturating_sub`, which *keeps* a
/// fully-leaked validator at `effective_stake = 0` rather than dropping it. So
/// the moment the inactivity leak zeroed anybody, the two rosters reached this
/// function at different lengths, the inclusion check at step 8 of
/// `compute_post_state` and the boundary tally in `close_epoch` partitioned
/// differently, and attestations the block had *admitted* were dropped at the
/// tally. Measured: 63 of 64 honest validators voting the same root, the
/// boundary keeping 4 of them (6.3%), justification `None`. Pinned by
/// `finality::tests::a_single_fully_leaked_validator_makes_the_two_rosters_partition_differently`.
///
/// Why the filter was removed rather than the leaked validator dropped on both
/// paths — the four reasons, in the order that decided it:
///
/// 1. **The filter had no other live effect.** `duty_roster_at`
///    (transition.rs) already excludes slashed, pre-activation and exited
///    records; they never reach this function. Dropping leaked-to-zero
///    validators was the filter's *only* remaining behaviour — i.e. it existed
///    only to cause this bug.
/// 2. **Leak-invariance by construction.** The leaked and unleaked rosters
///    carry the same index set and differ only in stake. With no filter, the
///    permutation cannot see the difference, so the two call paths cannot
///    diverge no matter which variant each one happens to hold.
/// 3. **The alternative touches quorum arithmetic.** Dropping the zeroed
///    validator on both paths would require the finality path to apply the
///    leak too — but `finality::process_epoch` re-subtracts its own `leaked`
///    map from whatever roster it is handed, so feeding it a leak-applied
///    roster double-charges the quorum denominator. More risk, less coverage,
///    in the exact arithmetic that decides finality.
/// 4. **It fixes the class, not the instance.** At the time of this fix,
///    `derive::active_validators` was a fourth roster producer: registry
///    stake only, no delegation, no cohort cap, no leak, and no zero-stake
///    filter. No amount of leak bookkeeping could have made it agree with
///    `transition.rs`, because it had no leak information at all. (That
///    fourth producer no longer exists — R1 H3, 2026-09-06, deleted
///    `derive::active_validators` along with the rest of the divergent
///    second state-root/schedule derivation it belonged to; see `derive.rs`.
///    This point is kept for the historical record: it is why the fix below
///    targets the *predicate*, not a specific caller, which is what let the
///    predicate keep holding after one of the four producers it names was
///    later deleted entirely.) With the filter gone, the remaining producers
///    compute the same membership predicate — `activation_epoch <= epoch
///    && epoch < exit_epoch && !slashed` — and therefore the same partition.
///
/// That last point is not theoretical. A FIFTH divergent view was measured on
/// 2026-08-24: an 8.27% weight asymmetry between the stake table
/// `forkchoice_head` feeds LMD-GHOST (the node's OWN head state) and the
/// `staked_sat` that `close_epoch` inflates for validators that attested on the
/// branch that node happened to apply. It is real, it is out of scope here, and
/// it is the same shape as this defect: a consensus quantity derived from a
/// node-local view of which roster is the roster. Every producer this crate can
/// make agree by construction, it should — which is the argument for making
/// membership a function of the index set and nothing else.
///
/// **A zero-weight member holds an INERT seat.** Quorum is stake-weighted over
/// the whole active set (`finality`'s `total_active`), so a zero-stake member
/// contributes 0 to the numerator and 0 to the denominator. The liveness the
/// inactivity leak buys back comes from the shrinking denominator and from
/// proposer selection (`schedule::sample` is stake-weighted and still never
/// draws a zero-stake validator) — never from committee membership. Being in a
/// committee is permission to be counted, not weight.
///
/// **The residual, stated rather than filtered.** A validator with genuinely
/// zero stake — not merely leaked to zero — would now take an inert seat. Every
/// runtime path that can create a validator record forbids that state:
/// `staking::validate_deposit` and the `Deposit` handler both reject below
/// `MIN_DEPOSIT_SAT` (25,000 BLCH); `staked_sat` thereafter only ever grows,
/// except in `apply_slashing_evidence`, which sets `slashed = true` in the same
/// statement and so removes the record from every roster; and
/// `genesis_cohort::apply_cohort_cap` cannot scale a member to zero, because
/// `s_i * cap / S` needs `s_i * cap < S`, and with `s_i >= MIN_DEPOSIT_SAT`
/// (2.5e12 sat) and `cap >= MIN_DEPOSIT_SAT / 2` (the deferral floor) the
/// numerator is >= 3.1e24 while `S` is bounded by the whole V4 supply, 1e19.
/// The one remaining producer is a hand-written genesis config, which does not
/// check `staked_sat` — an operator error, not an attacker-reachable state, and
/// its whole effect is one inert zero-weight seat. It is deliberately NOT
/// filtered here: a stake predicate in this function is what the four producers
/// cannot share, which is finding 4 above rebuilt.
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
    // R1 M8: memoised. `committee_for_slot` — the live per-block call
    // (`transition.rs` step 8, once per block) — used to call straight
    // through to the uncached body below and throw away 31 of every 32
    // slot-chunks the Fisher-Yates shuffle produced, because the beacon mix
    // and the active roster are BOTH fixed for an entire epoch
    // (`seed_for_epoch`/`consensus_roster_at` do not change mid-block), so
    // the same shuffle was recomputed from scratch on every one of an
    // epoch's 32 blocks. See [`partition_cache_get`]/[`partition_cache_put`]
    // for the replay-safety argument; the short version is that a cache hit
    // is required to be byte-identical to a fresh computation (proved by
    // `partition_cache_matches_uncached_computation` below), so this changes
    // latency only, never a state root, and needs no activation gate.
    let key = partition_cache_key(beacon_mix, epoch, validators);
    if let Some(hit) = partition_cache_get(&key) {
        return hit;
    }
    let out = epoch_committees_uncached(beacon_mix, epoch, validators);
    partition_cache_put(key, out.clone());
    out
}

/// The Fisher-Yates partition itself, with no cache in front of it — kept
/// as its own function so [`epoch_committees`]'s memoisation and the
/// underlying computation can each be read (and tested against each other)
/// without the other in the way.
fn epoch_committees_uncached(
    beacon_mix: &[u8; 32],
    epoch: u64,
    validators: &[Validator],
) -> Vec<Vec<u32>> {
    PARTITION_RECOMPUTATIONS.with(|c| c.set(c.get().wrapping_add(1)));
    let n_slots = SLOTS_PER_EPOCH as usize;

    // Canonicalise before anything else. The order the caller happened to hold
    // the registry in must never reach the result — the same rule the sampler
    // learned the hard way.
    let mut eligible: Vec<u32> = validators
        .iter()
        // NO STAKE FILTER — see the "Membership is a pure function of the
        // index set" section above. The only thing that reads stake in this
        // function is the mutation hook above, and that is `cfg(test)`.
        .filter(|v| !mutation_restores_zero_stake_filter() || v.effective_stake > 0)
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
        // The mutation switch that gives the epoch-partition invariant a real
        // input: duplicate one index, lose another, keep the length. `false` in
        // every build that is not a test build, so this folds away.
        #[cfg(test)]
        if crate::params::rehearsal::PARTITION_DUPLICATES_AN_INDEX
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            eligible[i] = eligible[j];
            continue;
        }
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

// ────────────────────────────────────────────────────────────────────────────
// Epoch-partition memoisation (R1 M8)
// ────────────────────────────────────────────────────────────────────────────
//
// INVARIANT (R1 M8): a cache hit MUST be byte-identical to what
// `epoch_committees_uncached` would have returned for the same arguments —
// this cache may change how many times the shuffle runs, never what any
// shuffle produces. That is enforced by construction (a hit is only ever a
// stored, previously-computed output, verbatim) and pinned by
// `partition_cache_matches_uncached_computation` (a differential property
// test) and `partition_cache_hit_is_identical_to_a_fresh_miss` (a unit test
// that fails if the cache ever returns anything but the fresh value).
//
// REPLAY-SAFETY: this cache holds no committed or cross-node state — it is a
// per-OS-thread, in-process memo (`thread_local!`), never serialized, never
// read by any other node, and empty again the moment the process restarts.
// The node's consensus engine is documented (`lib.rs`, `engine.rs`) to run on
// one dedicated thread, so this cache sees exactly the sequence of calls that
// thread makes — typically 32 calls per epoch sharing one (seed, epoch,
// roster) key, since both are fixed for the whole epoch — and returns exactly
// what each of those 32 calls would have computed alone. Two nodes, or two
// threads on one node, therefore compute identical partitions regardless of
// whether either one's cache happens to hit; only wall-clock time differs,
// never the value, so this needs no `*_ACTIVATION_EPOCH` gate — there is no
// new consensus RULE here, only a faster path to the existing one.
//
// KEY: (beacon_mix, epoch, a fingerprint of `validators`, and — test builds
// only — the state of the `PARTITION_DUPLICATES_AN_INDEX` rehearsal switch,
// because that switch changes `epoch_committees_uncached`'s OUTPUT and a
// cache that ignored it could serve a pre-mutation result to a post-mutation
// call on the same thread, or vice versa, silently defeating the mutation
// test the switch exists for).

/// Cheap, order- and stake-sensitive fingerprint of a roster for use ONLY as
/// a cache key — never a consensus digest, so it needs no `params::DS_*`
/// domain tag (nothing here is ever serialized, compared across nodes, or
/// folded into a state root).
///
/// `epoch_committees_uncached` canonicalises its input (sorts, dedups, drops
/// stake) before it matters to the output, which means two DIFFERENT
/// `validators` slices can legitimately produce the SAME partition. This
/// fingerprint deliberately does not attempt to recognise that — reproducing
/// the canonicalisation just to build a cache key would spend close to the
/// work the cache exists to avoid paying twice. Hashing the literal input
/// order and stake instead is strictly conservative: it can only ever cause
/// an extra cache MISS (recomputed correctly) on an equivalent-but
/// differently-shaped input, never a wrong HIT — the property the whole
/// cache depends on.
fn roster_fingerprint(validators: &[Validator]) -> [u8; 32] {
    // `Digest::update`, qualified: this module also imports `Update` (for the
    // Shake256 XOF above), and `Digest: Update` makes plain `h.update(..)`
    // genuinely ambiguous between the two trait methods — not a style choice.
    let mut h = Sha3_256::new();
    Digest::update(&mut h, (validators.len() as u64).to_le_bytes());
    for v in validators {
        Digest::update(&mut h, v.index.to_le_bytes());
        Digest::update(&mut h, v.effective_stake.to_le_bytes());
    }
    h.finalize().into()
}

type PartitionCacheKey = ([u8; 32], u64, [u8; 32], bool);

fn partition_cache_key(beacon_mix: &[u8; 32], epoch: u64, validators: &[Validator]) -> PartitionCacheKey {
    #[cfg(test)]
    let mutation = crate::params::rehearsal::PARTITION_DUPLICATES_AN_INDEX
        .load(std::sync::atomic::Ordering::Relaxed);
    #[cfg(not(test))]
    let mutation = false;
    (*beacon_mix, epoch, roster_fingerprint(validators), mutation)
}

thread_local! {
    // Single most-recent entry, not a map: consensus replay is a strictly
    // sequential walk of one chain on one thread, so "the previous call's key"
    // is the only key worth remembering — it is what every call after the
    // first of an epoch's 32 will match, and an epoch boundary is exactly one
    // guaranteed miss either way. A map would grow without the bound this
    // single slot gets for free and would need an eviction policy to reason
    // about; this needs none.
    static PARTITION_CACHE: RefCell<Option<(PartitionCacheKey, Vec<Vec<u32>>)>> =
        const { RefCell::new(None) };
}

fn partition_cache_get(key: &PartitionCacheKey) -> Option<Vec<Vec<u32>>> {
    PARTITION_CACHE.with(|c| match &*c.borrow() {
        Some((k, v)) if k == key => Some(v.clone()),
        _ => None,
    })
}

fn partition_cache_put(key: PartitionCacheKey, value: Vec<Vec<u32>>) {
    PARTITION_CACHE.with(|c| *c.borrow_mut() = Some((key, value)));
}

thread_local! {
    /// How many times [`epoch_committees_uncached`] — the Fisher-Yates
    /// shuffle itself — actually ran on this thread.
    ///
    /// **Observability only** (same device as `transition::eutxo_map_deep_copies`
    /// / `root_computations`): no consensus rule reads it, nothing branches on
    /// it, never committed. It exists because R1 M8 is a pure latency change —
    /// the cache's whole point is that its presence is unobservable in any
    /// OUTPUT — so the only way to write a test that goes red if the
    /// memoisation is ever deleted is to count the expensive step directly,
    /// the way the eUTXO instrumentation above already does for the same
    /// reason.
    static PARTITION_RECOMPUTATIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The calling thread's [`PARTITION_RECOMPUTATIONS`]. Observability only.
pub fn partition_recomputations() -> u64 {
    PARTITION_RECOMPUTATIONS.with(|c| c.get())
}

/// Zero the calling thread's [`PARTITION_RECOMPUTATIONS`], so a measurement
/// can be taken across one test rather than across a whole test binary.
pub fn reset_partition_recomputations() {
    PARTITION_RECOMPUTATIONS.with(|c| c.set(0));
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

// ────────────────────────────────────────────────────────────────────────────
// The roster unification, pinned
// ────────────────────────────────────────────────────────────────────────────
//
// These are unit tests, not integration tests in `tests/committee.rs`, for one
// reason: the mutation switch is `#[cfg(test)]`, and `#[cfg(test)]` items do
// not exist in the library an integration test links against. A mutation that
// can be reached from `tests/` is a mutation that exists in a shipped binary.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::rehearsal::{HOOK, PARTITION_DUPLICATES_AN_INDEX, RESTORE_ZERO_STAKE_FILTER};
    use std::sync::atomic::Ordering::Relaxed;

    const STAKE: u64 = 32_000 * 100_000_000;

    fn set(n: u32) -> Vec<Validator> {
        (0..n).map(|index| Validator { index, effective_stake: STAKE }).collect()
    }

    /// `transition::with_leak_applied`'s exact shape: `saturating_sub`, so a
    /// fully-leaked validator STAYS in the list at `effective_stake = 0`.
    fn with_leak(roster: &[Validator], zeroed: &[u32]) -> Vec<Validator> {
        roster
            .iter()
            .map(|v| Validator {
                index: v.index,
                effective_stake: if zeroed.contains(&v.index) {
                    v.effective_stake.saturating_sub(v.effective_stake.saturating_mul(2))
                } else {
                    v.effective_stake
                },
            })
            .collect()
    }

    /// The assertion the fix exists to make true, factored out so the mutation
    /// test below can run *this exact body* with the defect restored and show
    /// it panic. A regression test that cannot be made to fail is not testing
    /// anything.
    fn assert_the_two_rosters_partition_identically() {
        let seed = [0x5Au8; 32];
        for epoch in [0u64, 1, 7, 1_400] {
            // `duty_roster_at`-shaped: no leak, 64 validators, all funded.
            let duty = set(64);
            // `consensus_roster_at`-shaped: the same 64 indices, with the
            // inactivity leak having eaten one validator's whole stake.
            let consensus = with_leak(&duty, &[7]);
            assert_eq!(
                consensus.len(),
                duty.len(),
                "the leak must not drop the record — if it did, this test is not \
                 exercising the shape transition.rs actually produces"
            );
            assert_eq!(
                consensus.iter().find(|v| v.index == 7).unwrap().effective_stake,
                0,
                "fixture must actually zero somebody"
            );

            let boundary = epoch_committees(&seed, epoch, &duty);
            let step8 = epoch_committees(&seed, epoch, &consensus);
            assert_eq!(
                step8, boundary,
                "epoch {epoch}: the leaked and unleaked rosters must partition \
                 identically — membership is (seed, epoch, index set), stake is weight"
            );
            // And the zeroed validator keeps an inert seat rather than vanishing.
            assert!(
                step8.iter().any(|c| c.contains(&7)),
                "epoch {epoch}: the fully-leaked validator must keep its (zero-weight) seat"
            );
            assert_eq!(
                step8.iter().map(Vec::len).sum::<usize>(),
                64,
                "epoch {epoch}: the partition must still cover the whole roster once"
            );
        }
    }

    /// The two call paths in `transition.rs` — step 8's `consensus_roster_at`
    /// and `close_epoch`'s `duty_roster_at` — must produce IDENTICAL
    /// committees, with and without a fully-leaked validator present.
    ///
    /// Asserted against the real production function, not a reimplementation.
    #[test]
    fn the_two_rosters_partition_identically_with_and_without_a_leaked_validator() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        RESTORE_ZERO_STAKE_FILTER.store(false, Relaxed);
        assert_the_two_rosters_partition_identically();
    }

    /// **MUTATION TEST.** Restore the pre-2026-08-24 `effective_stake > 0`
    /// filter before the shuffle — the defect — and the assertion above must go
    /// red. Run it and watch it happen:
    ///
    /// ```text
    /// cargo test -p bloch-pos-committee --lib \
    ///   committees::tests::rehearsal_restoring_the_filter_reopens_the_roster_split \
    ///   -- --nocapture
    /// ```
    ///
    /// The panic is caught rather than allowed to fail the run, so the suite
    /// stays green while still proving the pinning assertion is load-bearing.
    /// The switch is `#[cfg(test)]`, so it cannot exist in a shipped binary.
    #[test]
    fn rehearsal_restoring_the_filter_reopens_the_roster_split() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());

        // Control first: with the mutation OFF the assertion passes. Without
        // this half, a panic below could be coming from anywhere.
        RESTORE_ZERO_STAKE_FILTER.store(false, Relaxed);
        assert_the_two_rosters_partition_identically();

        RESTORE_ZERO_STAKE_FILTER.store(true, Relaxed);
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // the failure is the result, not noise
        let red = std::panic::catch_unwind(assert_the_two_rosters_partition_identically);
        std::panic::set_hook(prev);
        RESTORE_ZERO_STAKE_FILTER.store(false, Relaxed);

        let msg = red
            .err()
            .map(|e| {
                e.downcast_ref::<String>()
                    .cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default()
            })
            .expect(
                "MUTATION DID NOT GO RED: the zero-stake filter was restored and the two \
                 rosters still partitioned identically. Either the mutation switch is not \
                 wired into epoch_committees any more, or the assertion is vacuous.",
            );
        println!("MUTATION WENT RED, as it must. First failure:\n  {msg}");

        // And the measurement, so the size of the defect is on the record and
        // not just its existence.
        RESTORE_ZERO_STAKE_FILTER.store(true, Relaxed);
        let duty = set(64);
        let consensus = with_leak(&duty, &[7]);
        let seed = [0x5Au8; 32];
        let step8 = epoch_committees(&seed, 1, &consensus);
        let boundary = epoch_committees(&seed, 1, &duty);
        let admitted: usize = step8.iter().map(Vec::len).sum();
        let agreeing: usize = step8
            .iter()
            .zip(boundary.iter())
            .map(|(a, b)| a.iter().filter(|v| b.binary_search(*v).is_ok()).count())
            .sum();
        RESTORE_ZERO_STAKE_FILTER.store(false, Relaxed);
        println!(
            "WITH THE DEFECT RESTORED: of {admitted} attestations step 8 would admit, the \
             boundary partition still seats {agreeing} in the same slot ({:.1}%). One \
             validator at zero stake was enough.",
            agreeing as f64 / admitted as f64 * 100.0
        );
        assert!(
            agreeing * 3 < admitted,
            "the restored defect kept {agreeing} of {admitted} in place — if most survive, \
             this mutation is not reproducing the mechanism it names"
        );
    }

    /// Property: for a random index set and a random leak pattern, **membership
    /// is invariant under any stake change that does not change the index
    /// set.** Only the weights may move.
    ///
    /// Deterministic LCG rather than a random source: a property test in a
    /// consensus crate that cannot be replayed from its seed is a flake
    /// generator.
    #[test]
    fn membership_is_invariant_under_any_stake_change() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        RESTORE_ZERO_STAKE_FILTER.store(false, Relaxed);

        let mut rng: u64 = 0x2026_0824_DEAD_BEEF;
        let mut next = move || {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            rng >> 11
        };

        for case in 0..200u32 {
            // A random index set — sparse indices, not 0..n, so the test also
            // covers the case where the index is not the position.
            let n = 1 + (next() % 96) as usize;
            let mut idx: Vec<u32> = Vec::with_capacity(n);
            let mut cursor = 0u32;
            for _ in 0..n {
                cursor = cursor.wrapping_add(1 + (next() % 5) as u32);
                idx.push(cursor);
            }

            let base: Vec<Validator> = idx
                .iter()
                .map(|&index| Validator { index, effective_stake: 1 + (next() % 1_000_000) as u64 })
                .collect();
            // Arbitrary stake perturbation over the SAME index set: some
            // validators fully leaked to zero, others rescaled.
            let perturbed: Vec<Validator> = base
                .iter()
                .map(|v| Validator {
                    index: v.index,
                    effective_stake: match next() % 3 {
                        0 => 0,
                        1 => v.effective_stake.saturating_mul(1 + (next() % 64)),
                        _ => v.effective_stake / (1 + (next() % 8)),
                    },
                })
                .collect();
            let epoch = next() % 4_096;
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&next().to_le_bytes());
            assert_eq!(
                epoch_committees(&seed, epoch, &base),
                epoch_committees(&seed, epoch, &perturbed),
                "case {case}: membership moved under a pure stake change (n={n}, epoch={epoch})"
            );
        }
        // The all-zero end of the range is not left to the generator — at
        // n up to 96 it would fire in maybe half of runs, which is a flake,
        // not coverage. It has its own test below.
    }

    /// The degenerate end of the same rule: an all-zero-stake roster is still
    /// seated. It used to collapse to 32 empty committees, which is how a
    /// stake filter turns "everyone is broke" into "the epoch has no
    /// committees at all".
    #[test]
    fn an_all_zero_stake_roster_is_still_partitioned() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        RESTORE_ZERO_STAKE_FILTER.store(false, Relaxed);
        let zeroed: Vec<Validator> =
            (0..40u32).map(|index| Validator { index, effective_stake: 0 }).collect();
        let cs = epoch_committees(&[0x11u8; 32], 3, &zeroed);
        assert_eq!(cs.iter().map(Vec::len).sum::<usize>(), 40);
        // Weight, however, is still zero — the seats are inert.
        assert_eq!(total_active_stake(&zeroed), 0);
        assert!(!is_supermajority(0, total_active_stake(&zeroed)));
        // An genuinely empty set is still 32 empty committees, unchanged.
        let empty = epoch_committees(&[0x11u8; 32], 3, &[]);
        assert!(empty.iter().all(Vec::is_empty));
        assert_eq!(empty.len(), SLOTS_PER_EPOCH as usize);
    }

    // ── R1 M8: epoch-partition memoisation ──────────────────────────────────

    /// **Fails before the fix, passes after it.** Before R1 M8,
    /// `committee_for_slot` (and any direct `epoch_committees` caller) paid
    /// one full Fisher-Yates shuffle PER CALL even when the immediately
    /// preceding call used the identical (seed, epoch, roster) — the shape of
    /// `transition.rs` step 8, called once per block, 32 times an epoch, off
    /// an epoch-constant seed and roster. Reverting the fix — making
    /// `epoch_committees` call `epoch_committees_uncached` directly, with no
    /// cache in front of it — makes this test RED: the second, third and
    /// fourth calls below would each recompute, and the assertion that only
    /// the first one does would fail.
    #[test]
    fn repeated_calls_with_the_same_key_recompute_only_once() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        RESTORE_ZERO_STAKE_FILTER.store(false, Relaxed);
        reset_partition_recomputations();
        let seed = [0x33u8; 32];
        let roster = set(64);

        let first = epoch_committees(&seed, 12, &roster);
        assert_eq!(partition_recomputations(), 1, "the first call must be a real computation");

        for _ in 0..3 {
            let again = epoch_committees(&seed, 12, &roster);
            assert_eq!(again, first, "a cache hit must equal the original computation");
        }
        assert_eq!(
            partition_recomputations(),
            1,
            "R1 M8 regressed: a repeat call with an unchanged (seed, epoch, roster) \
             recomputed the Fisher-Yates shuffle instead of hitting the cache"
        );

        // A genuinely different key (new epoch) must still recompute — the
        // cache is one entry, not a black hole that stops all future work.
        let _ = epoch_committees(&seed, 13, &roster);
        assert_eq!(
            partition_recomputations(),
            2,
            "a call with a different epoch must still trigger a real computation"
        );
    }

    /// Deterministic splitmix64 PRNG — same device `tests/properties.rs` uses
    /// crate-wide, so this differential test is replayable from its seed
    /// rather than a flake generator.
    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Rng {
            Rng(seed)
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn below(&mut self, n: u32) -> u32 {
            self.next_u32() % n.max(1)
        }
    }

    fn random_roster(rng: &mut Rng, n: u32) -> Vec<Validator> {
        // Duplicate-index-free by construction (`0..n`), matching every real
        // registry-derived roster (§ real callers dedup upstream); indices
        // shuffled and stakes randomised so two rosters covering the same set
        // rarely share a byte-for-byte representation, which is exactly the
        // case the fingerprint-based cache key must still get right.
        let mut idx: Vec<u32> = (0..n).collect();
        for i in (1..idx.len()).rev() {
            let j = rng.below((i + 1) as u32) as usize;
            idx.swap(i, j);
        }
        idx.into_iter()
            .map(|index| Validator { index, effective_stake: 1 + rng.next_u64() % 1_000_000 })
            .collect()
    }

    /// **The R1 M8 invariant, stated as code**: the memoised entry point and
    /// the uncached computation must agree for every input, whether the call
    /// is a cache miss (first call with a key) or a cache hit (a repeat).
    /// Randomised over seed, epoch, and roster shape/order/stake so this is
    /// not just re-checking the one fixture the unit tests already use.
    ///
    /// Reverting the fix (deleting the memoisation and calling
    /// `epoch_committees_uncached` directly) makes this test PASS, not fail —
    /// a differential test can only go red against a BROKEN cache, so the
    /// complementary `partition_cache_hit_is_identical_to_a_fresh_miss` and
    /// `stale_cache_entry_is_never_served_for_a_different_roster` tests below
    /// are written to fail if the caching logic itself regresses (e.g. a key
    /// that forgets to include the roster or the mutation switch).
    #[test]
    fn partition_cache_matches_uncached_computation() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        RESTORE_ZERO_STAKE_FILTER.store(false, Relaxed);
        let mut rng = Rng::new(0xC0FF_EE00_1234_5678);
        for _ in 0..200 {
            let mut seed = [0u8; 32];
            for b in seed.iter_mut() {
                *b = rng.next_u32() as u8;
            }
            let epoch = rng.next_u64() % 5_000;
            let n = 1 + rng.below(40);
            let roster = random_roster(&mut rng, n);

            let expected = epoch_committees_uncached(&seed, epoch, &roster);
            // First call: necessarily a miss (fresh seed/epoch/roster nearly
            // every iteration; a rare accidental repeat only exercises the
            // hit path too, which is still a valid check).
            let first = epoch_committees(&seed, epoch, &roster);
            assert_eq!(first, expected, "cache miss produced a different partition");
            // Second call, identical arguments: must be a hit, and the hit
            // must be byte-identical to the uncached value.
            let second = epoch_committees(&seed, epoch, &roster);
            assert_eq!(second, expected, "cache hit produced a different partition");
        }
    }

    /// Focused version of the property above: construct an exact cache hit
    /// (same seed, epoch, and roster slice) and check the two calls are not
    /// merely "both correct" but literally `==`, catching any drift a
    /// probabilistic property test could in principle miss.
    #[test]
    fn partition_cache_hit_is_identical_to_a_fresh_miss() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        RESTORE_ZERO_STAKE_FILTER.store(false, Relaxed);
        let seed = [0x77u8; 32];
        let roster = set(64);
        let miss = epoch_committees(&seed, 42, &roster);
        let hit = epoch_committees(&seed, 42, &roster);
        assert_eq!(miss, hit);
        assert_eq!(hit, epoch_committees_uncached(&seed, 42, &roster));
    }

    /// A cache keyed on the wrong thing would serve validator set A's
    /// partition to a same-(seed, epoch) call for validator set B. This test
    /// fails if the roster fingerprint is ever dropped from, or weakened in,
    /// the cache key: call with roster A (populates the cache), then
    /// immediately with a DIFFERENT roster B at the identical (seed, epoch),
    /// and require the second call to answer for B, not to replay A's cached
    /// result.
    #[test]
    fn stale_cache_entry_is_never_served_for_a_different_roster() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        RESTORE_ZERO_STAKE_FILTER.store(false, Relaxed);
        let seed = [0x88u8; 32];
        let a = set(64);
        let b: Vec<Validator> =
            (0..64u32).map(|index| Validator { index: index + 1000, effective_stake: STAKE }).collect();

        let expected_a = epoch_committees_uncached(&seed, 9, &a);
        let expected_b = epoch_committees_uncached(&seed, 9, &b);
        assert_ne!(expected_a, expected_b, "fixture bug: A and B must partition differently");

        let got_a = epoch_committees(&seed, 9, &a); // populates the cache under A's key
        assert_eq!(got_a, expected_a);
        let got_b = epoch_committees(&seed, 9, &b); // same (seed, epoch), different roster
        assert_eq!(got_b, expected_b, "the cache served roster A's partition for roster B");
    }

    /// **Mutation-switch test for the cache key itself.** `epoch_committees`'s
    /// OUTPUT depends on `PARTITION_DUPLICATES_AN_INDEX` in test builds (the
    /// switch `rehearsal_restoring_the_filter_reopens_the_roster_split`'s
    /// sibling exercises). If the cache key ever stopped including that
    /// switch's state, flipping it between two calls with the same (seed,
    /// epoch, roster) would silently serve the PRE-flip result post-flip —
    /// exactly the kind of stale-cache bug this test exists to catch. Same
    /// `HOOK` discipline as the other rehearsal tests: the switch is global
    /// per thread, so only one test may drive it at a time.
    #[test]
    fn mutation_switch_state_is_part_of_the_cache_key() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        RESTORE_ZERO_STAKE_FILTER.store(false, Relaxed);
        PARTITION_DUPLICATES_AN_INDEX.store(false, Relaxed);
        let seed = [0x99u8; 32];
        let roster = set(64);

        let clean = epoch_committees(&seed, 5, &roster);
        assert_eq!(clean, epoch_committees_uncached(&seed, 5, &roster));

        PARTITION_DUPLICATES_AN_INDEX.store(true, Relaxed);
        let mutated = epoch_committees(&seed, 5, &roster);
        // Comparison value computed WHILE the switch is still on — comparing
        // against a value computed after flipping it back off would compare
        // a mutated result against an unmutated one and fail for the wrong
        // reason (that bug shipped in an earlier draft of this test).
        let mutated_expected = epoch_committees_uncached(&seed, 5, &roster);
        PARTITION_DUPLICATES_AN_INDEX.store(false, Relaxed);
        assert_eq!(
            mutated, mutated_expected,
            "post-flip call did not recompute — the cache ignored the mutation switch"
        );
        // Guard against a vacuous test: the mutation must actually have
        // changed something, or the assertion above is trivially true.
        // (`with_leak`/`assert_the_two_rosters_partition_identically`'s own
        // mutation test already measures the magnitude; this only checks the
        // cache did not paper over the difference.)
        PARTITION_DUPLICATES_AN_INDEX.store(true, Relaxed);
        let mutated_uncached_only = epoch_committees_uncached(&seed, 5, &roster);
        PARTITION_DUPLICATES_AN_INDEX.store(false, Relaxed);
        assert_ne!(
            clean, mutated_uncached_only,
            "fixture bug: PARTITION_DUPLICATES_AN_INDEX did not change the uncached output \
             either, so this test cannot tell a correct cache from a broken one"
        );
    }
}
