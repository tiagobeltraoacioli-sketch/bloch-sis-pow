// SPDX-License-Identifier: MIT OR Apache-2.0

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
/// State SMT node domain (§6.1) — every hash in [`crate::state_root`] starts
/// with this tag so a state-tree node can never collide with a block id, a
/// transaction Merkle node, or any other SHA3 use in the protocol.

/// Role tags, mixed into the sortition seed so the per-slot subcommittee is not
/// a predictable subset of the epoch committee.
pub(crate) const ROLE_SLOT: u8 = 0x01;
pub(crate) const ROLE_EPOCH: u8 = 0x02;
