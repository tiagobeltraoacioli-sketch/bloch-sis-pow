// SPDX-License-Identifier: AGPL-3.0-or-later

//! The **derivations `transition` genuinely shares** with the rest of the
//! crate: the two body Merkle roots and the Coherence header mirror.
//!
//! ## What used to be here — deleted 2026-09-06, R1 H3
//!
//! This module used to be much larger: a `produce()` block builder plus a
//! full second derivation of the state root and the proposer schedule
//! (`ChainState`, `ParentState`, `active_validators`, `sortition_seed`,
//! `scheduled_proposer`, `randao_transition`, `expected_finality`,
//! `expected_coherence`, `validate_included_attestation`, `post_chain_state`,
//! `post_state_root`). The comparison at the deletion site (search "deleted
//! 2026-09-06" below) is the same shape as `derive::validate_block`'s removal
//! on 2026-08-12: a second stack, unreachable from the node, that had already
//! drifted from the one stack that runs. `crate::produce` is gone with it.
//!
//! ## What remains, and why it is different
//!
//! [`body_root`] and [`attestation_root`] (the two Merkle roots) and
//! [`coherence_binding`] (the §6.6.2 header mirror) are not a second
//! derivation of anything: [`crate::transition::Transition::apply_block`]
//! calls these exact functions to check the header fields it validates
//! (`transition.rs`, `derive::body_root`/`derive::attestation_root`/
//! `derive::coherence_binding`), so there is one definition, one caller
//! family, and no seam left to drift. That is the property the deleted code
//! only pretended to have.
//!
//! ## Purity
//!
//! Everything below is a pure function of its arguments. No clocks, no
//! caches, no interior mutability (§5.5).

use crate::attestation::Attestation;
use crate::params::DS_BODY;
use sha3::{Digest, Sha3_256};

/// The §6.6.2 header mirror: `SHA3-256(DS_COHERENCE ‖ accumulator_root ‖
/// nullifier_root)` — the one encoding of the two committed Coherence roots
/// that `BlockHeaderV4.coherence_root` carries.
///
/// This binds the header field to the same two values `state_root` commits as
/// SMT leaves (`TAG_COHERENCE_ACCUMULATOR` / `TAG_COHERENCE_NULLIFIERS`), so
/// the mirror can never drift from the committed state. It does **not**
/// re-root the pool: the accumulator root is an input, computed once by the
/// C1-frozen SHAKE-256 tree in `coherence-core` and carried as a value —
/// §6.6.1's no-re-rooting rule is about that tree, not about how the header
/// encodes its root.
///
/// The genesis ceremony (`tools/genesis4-ceremony`) stamps the genesis header
/// with this same function over the carried pool's roots, which is what makes
/// "carried verbatim" a chain anchored in a checkable commitment instead of an
/// arbitrary constant.
pub fn coherence_binding(accumulator_root: &[u8; 32], nullifier_root: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(crate::params::DS_COHERENCE);
    h.update(accumulator_root);
    h.update(nullifier_root);
    h.finalize().into()
}

// `nullifier_set_root` used to live here. It is gone, and its absence is the
// point: the nullifier-set root is a **Coherence** object, and this crate's
// posture toward Coherence is carried-never-recomputed (§6.6.1). Computing it
// here — under a `BLCH4:` tag, with SHA3-256, in the consensus crate — was the
// PoS layer reaching into the shielded pool's business, and it produced an
// interim commitment that would have had to change before the ceremony,
// changing the genesis identity with it.
//
// The ratified definition is `coherence_core::NullifierSet` (a SHAKE-256
// sparse Merkle tree under `bloch:coherence:nfset:v1`, with non-membership
// proofs), specified in `docs/specs/COHERENCE-C1.1.md`. Whoever supplies
// `coherence_nullifier_root` — the genesis ceremony, and later the node's
// Coherence engine — computes it there, with the same code the SP1 guest runs.
//
// `expected_coherence(parent: &ParentState<'_>)` used to live here too: a
// one-line wrapper applying `coherence_binding` to `parent.chain`'s two
// carried roots. Deleted 2026-09-06 (R1 H3) with the rest of the `ParentState`
// seam — `transition.rs` never called it; it read the parent's committed
// state via `derive.rs`'s OWN second copy of that state (`ChainState`), which
// is exactly the divergence this deletion removes. `transition.rs` computes
// the same binding directly, over the state it actually committed
// (`CommittedState::coherence_root`, `crate::derive::coherence_binding(&self.
// coherence_accumulator_root, &self.coherence_nullifier_root)`), which is the
// one real derivation.

// ── Body commitments (DS_BODY domain, §6.1) ─────────────────────────────────
//
// Two Merkle trees, one domain tag, disjoint preimages: every hash starts
// with DS_BODY, then a marker byte (leaf/node/empty), then the tree kind
// (transactions vs attestations). Marker separation is what kills the classic
// "internal node presented as a leaf" second-preimage trick; kind separation
// is what keeps a transaction commitment from ever aliasing an attestation
// commitment. Attestations get their own tree (not a shared one) so a
// finalized epoch's signatures can be pruned without disturbing the
// transaction commitment (§6.5.1).

const MARK_LEAF: u8 = 0x00;
const MARK_NODE: u8 = 0x01;
const MARK_EMPTY: u8 = 0x02;
const KIND_TX: u8 = 0x01;
const KIND_ATTESTATION: u8 = 0x02;

fn body_sha3(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DS_BODY);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Binary Merkle root with odd nodes promoted unchanged.
///
/// Promotion (instead of Bitcoin-style duplication of the last node) cannot
/// introduce ambiguity here because leaves and internal nodes live in
/// disjoint marked preimages — a promoted leaf can never be re-read as the
/// node of some other tree. Duplication, by contrast, is exactly what made
/// two distinct transaction lists share a root in CVE-2012-2459.
fn merkle_root(kind: u8, mut level: Vec<[u8; 32]>) -> [u8; 32] {
    if level.is_empty() {
        // A *defined* empty-tree value, not all-zeros: "no transactions" must
        // be a hash output the domain produced, not a magic constant another
        // computation could accidentally emit.
        return body_sha3(&[&[MARK_EMPTY], &[kind]]);
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 2 {
                next.push(body_sha3(&[&[MARK_NODE], &[kind], &pair[0], &pair[1]]));
            } else {
                next.push(pair[0]);
            }
        }
        level = next;
    }
    level[0]
}

/// Merkle root committing the block's transactions — what
/// `BlockHeaderV4::body_root` must equal. Transactions are opaque bytes to
/// this crate; each leaf length-prefixes its bytes so `[b"ab", b"c"]` and
/// `[b"a", b"bc"]` cannot commit identically.
pub fn body_root(transactions: &[Vec<u8>]) -> [u8; 32] {
    let leaves = transactions
        .iter()
        .map(|tx| {
            body_sha3(&[&[MARK_LEAF], &[KIND_TX], &(tx.len() as u64).to_le_bytes(), tx])
        })
        .collect();
    merkle_root(KIND_TX, leaves)
}

/// Canonical encoding of one attestation for the quorum commitment: the
/// signed data (fixed widths, declaration order), the validator index, and
/// the length-prefixed signature. The signature *is* committed — an
/// attestation in a block is evidence, and evidence whose signature could be
/// swapped without moving the root would not be evidence.
fn attestation_leaf(att: &Attestation) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(128 + att.signature.len());
    bytes.extend_from_slice(&att.data.slot.to_le_bytes());
    bytes.extend_from_slice(&att.data.head);
    bytes.extend_from_slice(&att.data.source_epoch.to_le_bytes());
    bytes.extend_from_slice(&att.data.source_root);
    bytes.extend_from_slice(&att.data.target_epoch.to_le_bytes());
    bytes.extend_from_slice(&att.data.target_root);
    bytes.extend_from_slice(&att.validator.to_le_bytes());
    bytes.extend_from_slice(&(att.signature.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&att.signature);
    body_sha3(&[&[MARK_LEAF], &[KIND_ATTESTATION], &bytes])
}

/// Root over the attestation quorum carried in the body — what
/// `BlockHeaderV4::attestation_root` must equal.
pub fn attestation_root(attestations: &[Attestation]) -> [u8; 32] {
    merkle_root(KIND_ATTESTATION, attestations.iter().map(attestation_leaf).collect())
}

// ────────────────────────────────────────────────────────────────────────────
// The second state-root/schedule derivation that used to live here —
// deleted 2026-09-06, R1 H3
// ────────────────────────────────────────────────────────────────────────────
//
// `active_validators`, `sortition_seed`, `scheduled_proposer`,
// `RandaoRejection`, `randao_transition`, `expected_finality`,
// `expected_coherence`, `validate_included_attestation`, `post_chain_state`,
// `post_state_root`, and the `ChainState`/`ParentState` types they were built
// on, stood here — the machinery `crate::produce::produce` (also deleted)
// used to assemble a block, sharing it with nothing `transition.rs` runs.
//
// R1 H3 found that this "shared" derivation had already drifted from the one
// the node actually uses, `Transition::compute_post_state` /
// `Transition::apply_block`:
//
//   * `post_chain_state` advanced only the RANDAO window and participation —
//     never `randao_commitment`/`reveals_used` (which
//     `compute_post_state` step 5 advances on every block), never
//     `pending_votes`/fork-choice messages, never a single transaction. Its
//     `root()` disagreed with `compute_post_state`'s for every block.
//   * `scheduled_proposer` drew from `active_validators` — registry stake
//     only, no delegation, no genesis-cohort cap, no inactivity leak — while
//     `compute_post_state` step 4 draws from `consensus_roster_at` (all
//     three applied).
//   * `sortition_seed` seeded epoch 0 with `[0u8; 32]` while
//     `CommittedState::seed_for_epoch` seeds it with `genesis_mix`
//     (`transition.rs`).
//
// A validator client built to this module's own documented contract — "the
// producer and validator must both use these functions" — would have stamped
// a `state_root` and a proposer schedule every honest node rejects. Verified
// (grep across `crates/`, `tools/`, `legacy/`, this crate's own tests): the
// live node never called `produce`, `ChainState`, `ParentState`, or any
// function in this list except through `produce.rs` itself and this module's
// own now-deleted tests — no non-test caller existed anywhere in the
// repository. `tools/genesis4-ceremony` calls [`coherence_binding`], which
// this deletion keeps.
//
// This is the same shape as `validate_block`'s removal below (2026-08-12): a
// second stack, unreachable, that had already drifted from the one stack
// that runs. Unlike that removal, there is no comparison table here, because
// there is no second checklist to reconcile against — `body_root`,
// `attestation_root` and `coherence_binding` (kept, below and above) were
// never duplicated by this deleted code; they were the one place the two
// former stacks actually agreed, which is exactly why they are the only
// three that survive.
//
// Replay-safety, stated so it can be checked: `Engine::ingest` /
// `Engine::propose` never called any deleted symbol (confirmed above), so no
// block in `blocks.log` was ever produced or validated through this code.
// Deleting it changes zero bytes of any state root any node has ever
// computed; replaying the existing log is byte-identical before and after
// this commit. No `*_ACTIVATION_EPOCH` gate applies — there is no consensus
// rule here to gate, only dead code to remove.

// ────────────────────────────────────────────────────────────────────────────
// The validator that used to live here — deleted 2026-08-12
// ────────────────────────────────────────────────────────────────────────────
//
// `validate_block(parent, envelope, verifier) -> Result<(), TransitionError>`
// stood here: a complete second block validator, with its own frozen error
// order, **and no caller**. The node runs `transition::Transition::apply_block`
// (`bloch-pos-node/src/engine.rs` binds that seam explicitly). Nothing outside
// this crate's own tests ever called this one.
//
// Two validation stacks with divergent error orders is precisely the condition
// that produced this week's defects: two block-identity functions, two state
// -root derivations (`state_root::randao_window` exists because of it), and a
// header that committed to nothing — that last one *because* the three
// commitment checks lived only here, in the stack nobody ran, so the stack that
// did run accepted any `body_root` at all for 178 green tests. A rule that
// exists twice is a rule that is enforced once and believed twice.
//
// THE COMPARISON, so the deletion is not a deletion of coverage. Left column:
// what `validate_block` checked. Right: where `transition` checks it.
//
//   parent linkage      → step 2, `header.parent != pre.head`. Same rule; the
//                         transition compares against an id IT derived rather
//                         than against a header field, which is stricter.
//   slot monotonicity   → step 1, plus a rule this seam had no way to state:
//                         a block in an epoch already processed past is also
//                         `NonMonotonicSlot`.
//   scheduled proposer  → step 4, via `schedule::proposer` off the same seed.
//   version             → step 3.
//   RANDAO reveal + mix → step 5, via `beacon::process_reveal`, and it ADVANCES
//                         the committed chain head, which this seam could not.
//   attestations        → step 8. Different committee rule, and the transition's
//                         is the current one: `committees::committee_for_slot`
//                         (the F1 partition) against this seam's
//                         `slot_subcommittee` (the superseded sampled draw —
//                         see the lib.rs banner). Plus a same-epoch bound.
//   attestation_root    → step 3b, same `attestation_root` function.
//   body_root           → step 3b, same `body_root` function.
//   finality carry-over → step 6, against the committed finality ENGINE rather
//                         than against the parent header's copied field.
//   coherence_root      → step 3b, same `coherence_binding`.
//   state_root          → step 12, over the state the transition actually
//                         computed (registry, finality, fees and all), not over
//                         a state whose components this seam carried unchanged.
//   proposer signature  → step 7, moved EARLIER on purpose: one hybrid verify
//                         before N attestation verifies is the cheap-first
//                         order the transition's docs freeze.
//
// Nothing was checked here and only here. What WAS only here was two negative
// tests — `WrongVersion` and proposer `BadSignature` had no regression test in
// the transition, only in `produce.rs`'s tamper table against this function.
// Those are migrated to `transition::tests` (`wrong_version_rejected`,
// `bad_proposer_signature_rejected`); deleting a checker while dropping the
// tests that prove the check exists is how a check becomes a comment.
//
// Everything ABOVE this comment stays as of the 2026-08-12 deletion this
// block documents: `active_validators`, `sortition_seed`, `scheduled_proposer`,
// `randao_transition`, `expected_finality`, `coherence_binding`,
// `expected_coherence`, `body_root`, `attestation_root`,
// `validate_included_attestation`, `post_chain_state`, `post_state_root`. Only
// the parallel validator died that day.
//
// UPDATE, 2026-09-06 (R1 H3): everything in that list except `body_root`,
// `attestation_root` and `coherence_binding` is gone too now — see the block
// above this one, which is the current, accurate map of what survives.

#[cfg(test)]
mod coherence_tests {
    // R1 H3 (2026-09-06): this module used to carry two more tests,
    // `expected_coherence_derives_from_committed_state_not_the_parent_header`
    // and `post_chain_state_carries_both_coherence_roots_unchanged`, built on
    // `ChainState`/`ParentState`/`expected_coherence`/`post_chain_state` — the
    // deleted second derivation. Coverage of the real thing did not move: the
    // property they were guarding (the header's `coherence_root` is a
    // rederivation from committed state, not a copied field) is exactly what
    // `transition::tests` proves against `CommittedState::coherence_root` /
    // `Transition::apply_block`, which is the code that actually runs. What
    // remains here is the one test about `coherence_binding` itself — a pure
    // function with no dependency on the deleted types.
    use super::*;

    /// The mirror is a function of the two roots and nothing else, and it is
    /// injective over each input (no zero-absorption: an all-zero root pair
    /// still produces a real digest — "empty pool" is a hash output, never
    /// the magic constant `[0u8; 32]` the old genesis stamped).
    #[test]
    fn binding_depends_on_both_roots_and_is_never_zero() {
        let a = coherence_binding(&[1u8; 32], &[2u8; 32]);
        assert_eq!(a, coherence_binding(&[1u8; 32], &[2u8; 32]));
        assert_ne!(a, coherence_binding(&[3u8; 32], &[2u8; 32]));
        assert_ne!(a, coherence_binding(&[1u8; 32], &[4u8; 32]));
        // Swapping the operands must not commute — acc and nf are different
        // objects and the binding must tell them apart.
        assert_ne!(
            coherence_binding(&[1u8; 32], &[2u8; 32]),
            coherence_binding(&[2u8; 32], &[1u8; 32])
        );
        assert_ne!(coherence_binding(&[0u8; 32], &[0u8; 32]), [0u8; 32]);
    }
}
