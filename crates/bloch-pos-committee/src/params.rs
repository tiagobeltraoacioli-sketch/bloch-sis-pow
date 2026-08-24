// SPDX-License-Identifier: AGPL-3.0-or-later

//! Consensus constants for the committee layer.
//!
//! Values come from §5.1 and §6.5.2 of the migration design, which in turn come
//! from the measured in-circuit cost of the hybrid signature
//! (`spikes/prover-cost/RESULTS.md`): 7,274,849 RV32IM instructions per
//! ML-DSA-65 ‖ Falcon-1024 verification, and a 4,589-byte signature.
//!
//! Nothing here is active. There is no activation height in this crate because
//! the crate is not wired into the node; when it is, activation follows the
//! height-gated flag-day idiom used by `STATE_ROOT_ACTIVATION_HEIGHT`.

/// Full committee, voting once at each epoch boundary for justification and
/// finality. At 4,589 B per signature this is ≈ 588 KB in the epoch-boundary
/// block and ≈ 19.3 GB/year.
pub const COMMITTEE_SIZE: usize = 128;

/// Per-slot sample, voting only to give LMD-GHOST its fork-choice weight.
///
/// Why this exists at all: epoch-only voting would leave no attestation weight
/// between epoch boundaries, so intra-epoch ordering would rest on slot number
/// and the proposer signature alone, and short reorgs would be cheap. Ethereum
/// avoids this by slicing the validator set into one committee per slot; the
/// measured cost of a 4.6 KB signature makes that too expensive here, so the
/// design keeps a small sample instead.
pub const SLOT_SUBCOMMITTEE_SIZE: usize = 8;

/// Slots per epoch (§5.1).
pub const SLOTS_PER_EPOCH: u64 = 32;

/// Seconds per slot (§5.1) — identical to today's PoW block target, so the
/// transition adds no new propagation pressure.
pub const SLOT_DURATION_SECS: u64 = 30;

/// Upper bound on weighted draws before the deterministic fallback in
/// [`crate::sample::sample`] fills the remaining seats in index order.
///
/// Reached only when stake is so concentrated that rejection keeps hitting the
/// same few validators — which is exactly the distribution the G1–G4 gates
/// exist to prevent from ever reaching mainnet.
pub const MAX_DRAWS_PER_SLOT: usize = 4096;

/// Length of the RANDAO hash chain committed at registration (§6.3, Appendix
/// A). A validator's commitment supports exactly this many reveals — one per
/// slot it actually proposes — before a re-commit transaction is required.
///
/// At one reveal per proposed slot, 8,192 reveals is years of proposing for
/// any validator in a set of realistic size, so re-commits are rare; but the
/// exhaustion path must still exist and be enforced, because a chain that
/// silently accepted reveal 8,193 would be accepting a value with no
/// registered commitment behind it.
pub const RANDAO_CHAIN_LENGTH: u32 = 8_192;
/// Epochs of non-finality tolerated before the inactivity leak switches on
/// (§5.1: "quadratic after 4 epochs of non-finality"). Below this, a stall is
/// treated as transient — leaking on every hiccup would punish ordinary
/// network jitter; above it, the set is presumed partitioned or abandoned and
/// liveness is bought back by shrinking the absent stake.
pub const INACTIVITY_LEAK_THRESHOLD_EPOCHS: u64 = 4;

/// Divisor of the per-epoch inactivity bite: an absent validator loses
/// `stake * t / QUOTIENT` in the t-th epoch beyond the threshold, so the
/// cumulative loss grows quadratically. 64 is sized for recovery in tens of
/// epochs (≈ hours at 16 min/epoch), not days: with a 40%-absent set, the
/// live 60% regains a 2/3 supermajority after ~6 leak epochs. Like every
/// §5.1 value this is a Phase-1 proposal needing a KAT and a devnet sweep.
pub const INACTIVITY_LEAK_QUOTIENT: u128 = 64;

/// Divisor of the per-epoch **recovery** of the inactivity leak, once finality
/// is healthy again: `leaked -= max(leaked / QUOTIENT, 1)` on every epoch that
/// is *not* leaking. This is the whole answer to "the relaunch inherits a
/// collapsed denominator".
///
/// # Why the accumulator had to become recoverable
///
/// Before this constant, `FinalityState::leaked` had **exactly one write
/// path** — `+= bite` — with no decay, no reset and no removal anywhere in the
/// crate. The quorum denominator subtracts that accumulator, so the
/// denominator shrank monotonically and never came back: once enough stake had
/// leaked, a handful of nodes — one, even — held two thirds of what remained
/// and finalized entirely alone. That is the ratchet behind the 2026-08-24
/// incident, where three nodes finalized epoch 986 under three different roots
/// and no amount of arriving blocks could reunify them.
///
/// # Why it lives HERE and not in a migration
///
/// `CommittedState` has no constructor that reads a database
/// (`transition.rs`, struct docs) and the node's storage is an **append-only
/// block log**: restart means replaying every block through the same
/// `Transition` (`bloch-pos-node/src/store.rs` module docs). So the leak is
/// not a value sitting in storage that an operator can edit before the
/// relaunch — it is re-derived from the block log on every boot. A one-shot
/// storage migration has nothing to migrate, and zeroing "at load" would make
/// a node disagree with its own replay, which is the `expected_bits` defect
/// class this repo has already paid for twice. The only place the accumulator
/// can be changed deterministically on 64 machines is inside the fold, which
/// is where this is.
///
/// # The rate, and the sawtooth it buys
///
/// 16 means a healthy epoch returns 1/16 of the outstanding leak, so the
/// accumulator halves about every 11 epochs and drains completely in a bounded
/// number (the `max(·, 1)` floor guarantees termination). It is deliberately
/// SLOWER than accrual: recovery must not instantly undo the very leak that
/// bought the recovery. It does not remove that tension — a validator set that
/// is permanently short of a supermajority will oscillate between leaking and
/// recovering rather than stalling forever, and the honest fix for stake that
/// is never coming back is EJECTION from the registry, not a perpetual leak.
/// That is a validator-set change and deliberately not in this fold.
pub const INACTIVITY_LEAK_RECOVERY_QUOTIENT: u64 = 16;

/// The quorum denominator may never fall below this fraction of the
/// **unleaked** active stake: `MIN_QUORUM_DENOMINATOR_NUM /
/// MIN_QUORUM_DENOMINATOR_DEN`. One half.
///
/// `process_epoch` already guarded `total_active == 0`. It had no guard for
/// "total_active is small", and small is where the damage is: at 6.25% of the
/// original stake a 4-of-64 partition reaches two thirds of what is left and
/// justifies its own branch (`finality::tests::
/// a_partitioned_minority_finalizes_because_the_leak_shrinks_the_denominator`
/// measures it: epoch 25, after 92.2% of network stake has leaked).
///
/// # What the floor is worth, exactly
///
/// Write `p` for the present fraction of the ORIGINAL active stake. Once the
/// absent stake has fully leaked, the 2/3 test is `3p ≥ 2·max(p, 1/2)`, which
/// for `p < 1/2` is `3p ≥ 1`, i.e. **`p ≥ 1/3`**. So:
///
/// - a set holding **at least a third** of the original stake can still be
///   rescued by the leak — which is the entire reason the leak exists, and the
///   §5.1 recovery property is unchanged (pinned by
///   `inactivity_leak_recovers_finality`, whose 60/40 stall still recovers on
///   the same epoch it always did);
/// - a set holding **less than a third** can never justify, no matter how long
///   it waits. The 2026-08-24 partitions were 4 of 64.
///
/// # The residual, stated rather than glossed
///
/// A floor of one half admits at most three pairwise-disjoint sets of exactly
/// one third each, so it bounds the divergence from "any handful of nodes" to
/// "at most three ways" — it does not make the justified root unique. Full
/// uniqueness needs a minimum recovering fraction strictly above one half,
/// i.e. a floor above 3/4, at the price of never recovering from an outage of
/// more than half the stake. Which of those two the chain wants is a founder
/// decision about safety versus liveness, not an implementation detail, and
/// it is one constant away.
pub const MIN_QUORUM_DENOMINATOR_NUM: u128 = 1;
/// Denominator of [`MIN_QUORUM_DENOMINATOR_NUM`].
pub const MIN_QUORUM_DENOMINATOR_DEN: u128 = 2;

/// Flag-day epoch at which the inactivity leak starts reaching the **duty
/// roster**, and not only the quorum denominator.
///
/// `u64::MAX` means INERT: every node ships the code and none of it changes a
/// single committee or proposer draw until this constant is lowered and the
/// fleet is rebuilt together. Same idiom as `STATE_ROOT_ACTIVATION_HEIGHT` —
/// a consensus rule arrives by flag day, never by whoever restarts first.
///
/// # The defect this closes
///
/// The chain carried two disagreeing stake views. `finality::process_epoch`
/// subtracts each validator's accrued leak before it measures the quorum, so
/// the denominator shrinks to the set that is actually voting and finality
/// heals itself. `CommittedState::duty_roster_at` never subtracted it — and
/// the proposer draw (`schedule::proposer` → `sample`, weighted by
/// `effective_stake`) and the committee partition (`committees::
/// epoch_committees`, which admits every validator with `effective_stake > 0`)
/// both read *that* roster. A validator the finality layer had already written
/// off kept winning proposer draws and kept holding committee seats.
///
/// The asymmetry is the whole bug: **finality recovers on its own and block
/// production never does.** Nothing feeds the leak back into the schedule, so
/// a slot drawn for an absent validator stays empty for as long as the chain
/// runs.
///
/// Measured on Genesis-4 mainnet, 2026-08-21: seven live validators held
/// 6.19% of unleaked stake; blocks arrived every 19.2 slots against the 16.2
/// that `1 / 0.0619` predicts — ~94% of slots drawn for validators that
/// counted for nothing and produced nothing. `SLOT_DURATION_SECS` is 30, so
/// the chain ran at roughly ten minutes a block while finalising every epoch.
///
/// # Choosing the epoch
///
/// Proposer selection and committee membership both change the moment this
/// binds, so a node still on the old value computes a different schedule and
/// forks. Set it far enough ahead that every validator is rebuilt first, and
/// treat "the fleet is on the new binary" as a precondition, not a hope.
///
/// The choice procedure, the fleet-rollout order, the readiness predicate and
/// the post-activation observables live in `docs/LEAKED-ROSTER-FLAG-DAY.md`.
/// The armed value below was produced by that runbook; the tripwire test in
/// `transition.rs` pins it, so it cannot drift without failing the suite.
///
/// ARMED 2026-08-24 at epoch 1400 — 2026-08-29 10:51:19 UTC. Rehearsed first on
/// a two-node devnet WITH the control the repo's testing rule requires: the
/// armed and inert halves produced an identical 143 blocks before the
/// boundary, neither forked, and only the armed half's slot occupancy moved
/// after it (68.1% -> 72.8%).
pub const LEAKED_ROSTER_ACTIVATION_EPOCH: u64 = 1400;

/// Flag-day epoch at which the deduplicated transfer format (`TransferV2`,
/// wire tag `0x06`) becomes acceptable in blocks.
///
/// `u64::MAX` means INERT: every node ships the decoder and the apply path
/// and none of it changes what a block may carry until this constant is
/// lowered and the fleet is rebuilt together. Same idiom as
/// `LEAKED_ROSTER_ACTIVATION_EPOCH` — a consensus rule arrives by flag day,
/// never by whoever restarts first. The V1 format (tag `0x01`) stays valid
/// forever; this gate only *adds* an encoding, it retires nothing.
///
/// # The defect this closes
///
/// A V1 transfer carries one full witness per input: txid 32 + vout 4 +
/// pubkey 3,749 + signature 4,775 = 8,560 B, so `MAX_BLOCK_TX_BYTES`
/// (262,144) fits ~30 inputs per block. A consolidation's inputs are almost
/// always one owner's, and there is ONE signing root per transfer
/// ([`crate::transition::PosTransaction::spend_signing_root`]) — so those 30
/// witnesses are 30 copies of the same key carrying 30 proofs of the same
/// statement, 30 hybrid verifications (145 µs each, measured 2026-08-21) to
/// establish what one establishes. V2 carries a witness table with one
/// (pubkey, signature) entry per owner and 40-byte inputs (txid + vout +
/// key_index): a 30-input single-owner consolidation drops from ~256,800 B
/// to ~9,700 B, ~6,300 inputs fit in a block, and verification is one hybrid
/// check per owner. That matters because the dominant per-block cost is the
/// state root, LINEAR in the UTXO set size (51 s cold / 0.59 s warm over
/// today's 452,726-entry carryover) — consolidation is how the set shrinks,
/// and this format is what makes consolidation cheap.
///
/// # Why a mixed fleet agrees before the flag day
///
/// A pre-activation block carrying `0x06` is rejected by BOTH binaries, for
/// different proximate reasons and the same verdict: the old binary fails to
/// decode the body (`TxDecodeError::UnknownTag(0x06)`), the new one decodes
/// it and refuses it at the gate
/// ([`crate::interfaces::TransferReject::FormatNotActive`]). Either way the
/// block is invalid everywhere, so no honest proposer produces one and no
/// fork opens. AFTER activation the two binaries diverge — the old one still
/// rejects what the new one accepts — so "the fleet is on the new binary" is
/// a precondition of lowering this, not a hope. The gate reads the COMMITTED
/// epoch (`CommittedState::epoch`, already rolled to the block's epoch),
/// never node-local state — the 2026-08-08 `expected_bits` fork is the
/// standing reason.
pub const TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH: u64 = 800;

/// Flag day for the 512 KiB block payload cap
/// ([`crate::fee_market::MAX_BLOCK_TX_BYTES_V2`]).
///
/// From this epoch a block may carry 524,288 payload bytes instead of
/// 262,144, and the EIP-1559 byte target moves with it — the two are one
/// switch, never two. Splitting them would price a half-full block as
/// congested: the controller reads utilisation as `tx_bytes / target`, so a
/// doubled cap over an undoubled target makes 300 KiB — well under the new
/// cap — read as 2.3x over target and push the base fee up on a block that is
/// not scarce at all.
///
/// `u64::MAX` until the founder sets it. Below it every node computes the old
/// cap and the old target, so a mixed fleet reaches one verdict on every
/// block; at and above it they diverge on both, so **the fleet must be
/// rebuilt before this constant is ever lowered**. Same idiom as
/// [`LEAKED_ROSTER_ACTIVATION_EPOCH`], and the gate reads the epoch derived
/// from the block's own header slot — never node-local state, which is what
/// the 2026-08-08 `expected_bits` fork cost us.
pub const BLOCK_BYTES_V2_ACTIVATION_EPOCH: u64 = 800;

/// **The F6 seed look-ahead is UNCONDITIONAL.** There is no flag day.
///
/// `CommittedState::seed_for_epoch` seeds epoch `E` from the mix at the close
/// of `E − 1 − `[`crate::committees::MIN_SEED_LOOKAHEAD_EPOCHS`], always. It
/// was written behind an inert `ANCESTRY_SEED_ACTIVATION_EPOCH` gate first,
/// and the gate was REMOVED on the founder's instruction (2026-08-24): the
/// relaunch is a coordinated convergence — one storage state installed on all
/// 64 validators, all restarted together — so there is no live network for a
/// gradual rollout to split, which is the only thing the gate bought. Deleting
/// it also deletes the way it could go wrong: an activation epoch armed in the
/// past, which is how 1,600,000 BLCH once escaped a write-off that never
/// fired.
///
/// **What this means for anyone reading later.** The rule is now implicit in
/// the binary rather than dated in a constant, so "which seed rule does this
/// chain run" is answered by the release, not by the state. Any FUTURE change
/// to `seed_for_epoch` on a live network needs a gate again — this note is not
/// a precedent for changing consensus without one.
///
/// # What the look-ahead closes
///
/// F6, proposer grinding: at `back = 1` the seed for `E` is the mix at the
/// close of `E − 1`, so the trailing proposers of `E − 1` see the partition
/// their own reveal produces before they must publish it, and can re-sort `E`
/// by withholding.
///
/// It also removes the sub-epoch-lag case of the duty-view ANCHOR defect,
/// because the `E − 2` mix is frozen before `E − 1` begins. It is a mitigation
/// of that defect, not a fix; the fix is anchoring the duty view to the
/// ancestry of the thing being judged (`bloch-pos-node/src/engine.rs`).
///
/// # It costs nothing at the seam
///
/// `close_epoch` retains [`crate::state_root::RANDAO_BOUNDARIES_RETAINED`]` =
/// 2` boundaries, so while `E` is open the state holds `{E − 2, E − 1}`. The
/// rule reads `E − 2`, already there. No retention change, and therefore no
/// state-root change — `state_root::randao_window` folds exactly the retained
/// boundaries into the tree. Pinned by
/// `the_rule_reads_a_boundary_the_state_still_retains`.

/// Test-only rehearsal hook. `cfg(test)`, so it cannot exist in a shipped
/// binary. Flips one bit of every seed, so the deterministic chain comparator
/// can be shown to go red on a planted difference — a comparator that cannot
/// see one is not comparing anything.
#[cfg(test)]
pub mod rehearsal {
    use std::sync::atomic::AtomicBool;
    pub static MUTATE_SEED: AtomicBool = AtomicBool::new(false);
}

/// Domain separation tags (§6.1). Fixed 16 bytes, right-padded with zeros, so
/// no tag can be a prefix of another.
pub const DS_SORTITION: [u8; 16] = *b"BLCH4:SORTIT\0\0\0\0";
/// Attestation signing root domain.
pub const DS_ATTEST: [u8; 16] = *b"BLCH4:ATTEST\0\0\0\0";
/// Block identity (§5.4). The one and only block identifier is
/// `SHA3-256(DS_BLOCK ‖ canonical header)` — the tag is what guarantees a block
/// id can never collide with any other domain's digest of the same bytes.
pub const DS_BLOCK: [u8; 16] = *b"BLCH4:BLOCK\0\0\0\0\0";
/// Transaction Merkle tree (`body_root`).
pub const DS_BODY: [u8; 16] = *b"BLCH4:BODY\0\0\0\0\0\0";
/// State SMT nodes (`state_root`).
pub const DS_STATE: [u8; 16] = *b"BLCH4:STATE\0\0\0\0\0";
/// Beacon mixing (§6.3): `mix' = SHA3-256(DS_RANDAO ‖ mix ‖ reveal)`.
pub const DS_RANDAO: [u8; 16] = *b"BLCH4:RANDAO\0\0\0\0";
/// Deposit message signing root (§7.1 proof of possession).
pub const DS_DEPOSIT: [u8; 16] = *b"BLCH4:DEPOSIT\0\0\0";
/// The signing root an eUTXO spend authorisation covers: the domain under
/// which an output's owner authorises *this* transfer and no other.
///
/// Its own tag, and not `DS_BODY` or `DS_TXID`, for the reason every tag in
/// this table exists: a spend authorisation must not be replayable as any
/// other signed message, and a digest that identifies a transaction must not
/// double as the digest a key signed. The preimage covers the spend points,
/// the outputs, the declared size and the tip — everything except the
/// witnesses, which cannot be inside a root they are produced over.
pub const DS_SPEND: [u8; 16] = *b"BLCH4:SPEND\0\0\0\0\0";
/// Transaction identity: `txid = SHA3-256(DS_TXID ‖ spend signing root)`.
///
/// Derived from the witness-free signing root, so a transaction's id — and
/// therefore the keys of every output it creates — cannot be changed by
/// anyone re-encoding its signatures. A txid taken over the full encoding
/// would make an unrelated party able to re-key a payment already in flight,
/// which is the malleability class that made Bitcoin's chained-transaction
/// wallets unsafe before segwit.
pub const DS_TXID: [u8; 16] = *b"BLCH4:TXID\0\0\0\0\0\0";
/// Slashing evidence and voluntary-exit signing roots (§7.2, §7.3).
pub const DS_SLASH: [u8; 16] = *b"BLCH4:SLASH\0\0\0\0\0";
/// Proposer signature domain over the header.
///
/// **Not in the §6.1 table** — the spec assigns a tag to block identity but
/// none to the proposer's signature, leaving the signature to cover the same
/// domain-tagged bytes as the id. Signing the id would work, but a signature
/// domain that is also an identifier domain invites exactly the cross-protocol
/// replay games domain separation exists to end, so this crate freezes a
/// distinct tag and the spec table needs the row added (flagged in
/// `BLOCH-POS-INTERFACES.md`).
pub const DS_PROPOSE: [u8; 16] = *b"BLCH4:PROPOSE\0\0\0";
/// Deposit proof-of-possession domain (§6.1, §7.1). A PoP bound to its own
/// domain cannot be replayed as an attestation or a block signature — the tag
/// is what makes a signature mean one thing only.
/// Voluntary-exit signing domain (§7.2). Not in the §6.1 table by name, but
/// the exit is "a hybrid-signed message" and every signed message gets its own
/// tag; all tags are fixed 16 bytes, so no tag can prefix another.
pub const DS_EXIT: [u8; 16] = *b"BLCH4:EXIT\0\0\0\0\0\0";
/// Weak-subjectivity checkpoint digest domain
/// (`BLOCH-WEAK-SUBJECTIVITY.md` §2.1). The checkpoint is signed and verified
/// out of band, at boot — its digest must live in its own domain so a signed
/// checkpoint can never be replayed as any in-protocol message, nor vice versa.
pub const DS_WSCKPT: [u8; 16] = *b"BLCH4:WSCKPT\0\0\0\0";
/// Header `coherence_root` mirror binding (§6.6.2):
/// `coherence_root = SHA3-256(DS_COHERENCE ‖ accumulator_root ‖ nullifier_root)`.
///
/// This tags the header *encoding* of the two Coherence roots, not anything
/// inside the pool: the accumulator itself stays SHAKE-256 under the C1-frozen
/// `bloch:coherence:*:v1` domains (`crates/coherence-core`), untouched by the
/// BLCH4 sweep — §6.6 says the migration brings the rest of the chain to where
/// Coherence already is, and this tag is on the "rest of the chain" side of
/// that line.
pub const DS_COHERENCE: [u8; 16] = *b"BLCH4:COHERE\0\0\0\0";
/// State SMT node domain (§6.1) — every hash in [`crate::state_root`] starts
/// with this tag so a state-tree node can never collide with a block id, a
/// transaction Merkle node, or any other SHA3 use in the protocol.
/// Slashing-evidence identity domain (anti-replay key, §7.3).

/// Role tags, mixed into the sortition seed so the per-slot subcommittee is not
/// a predictable subset of the epoch committee.
pub(crate) const ROLE_SLOT: u8 = 0x01;
pub(crate) const ROLE_EPOCH: u8 = 0x02;
