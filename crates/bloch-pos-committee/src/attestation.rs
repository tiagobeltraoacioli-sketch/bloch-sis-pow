// SPDX-License-Identifier: AGPL-3.0-or-later

//! Attestation payload and its signing root.
//!
//! The crate deliberately does **not** depend on the signature stack. It takes
//! a verifier through [`SignatureVerifier`] instead, for two reasons: the
//! committee logic is testable without dragging in PQClean C code, and the
//! choice of verifier (the C FFI stack today, a pure-Rust one if the in-circuit
//! path is ever taken — see `spikes/prover-cost/`) stays a caller decision.

use crate::params::DS_ATTEST;
use sha3::{Digest, Sha3_256};

/// What a validator signs.
///
/// `slot` and `head` carry the fork-choice vote; `target`/`source` carry the
/// finality vote. A per-slot subcommittee attestation and an epoch-boundary
/// attestation use the same struct — what differs is which committee the
/// signer had to be in, and whether the vote counts toward weight, finality,
/// or both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestationData {
    /// Slot this attestation is for.
    pub slot: u64,
    /// Block root the validator considers the head.
    pub head: [u8; 32],
    /// Epoch of the justified checkpoint the validator builds on.
    pub source_epoch: u64,
    /// Root of the justified checkpoint.
    pub source_root: [u8; 32],
    /// Epoch being voted as the new justified checkpoint.
    pub target_epoch: u64,
    /// Root of the target checkpoint.
    pub target_root: [u8; 32],
}

impl AttestationData {
    /// Domain-separated SHA3-256 root the signature covers.
    ///
    /// Every field is fixed-width and length-prefixed by construction, so no
    /// two distinct attestations can serialize to the same bytes.
    pub fn signing_root(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(DS_ATTEST);
        h.update(self.slot.to_le_bytes());
        h.update(self.head);
        h.update(self.source_epoch.to_le_bytes());
        h.update(self.source_root);
        h.update(self.target_epoch.to_le_bytes());
        h.update(self.target_root);
        h.finalize().into()
    }

    /// Casper-style surround: does `self` surround `other`?
    ///
    /// Signing two attestations where one surrounds the other is slashable
    /// (§7.3). Kept here beside the data it judges so the rule cannot drift
    /// away from the struct it applies to.
    pub fn surrounds(&self, other: &AttestationData) -> bool {
        self.source_epoch < other.source_epoch && other.target_epoch < self.target_epoch
    }

    /// Double vote: two different attestations for the same target epoch.
    /// Also slashable.
    pub fn is_double_vote(&self, other: &AttestationData) -> bool {
        self.target_epoch == other.target_epoch && self != other
    }
}

/// A signed attestation as it travels on the wire.
///
/// `PartialEq`/`Eq` exist because an attestation rides inside
/// [`crate::interfaces::SlashingEvidence`], which rides inside the node's
/// transaction type — and transaction types are compared in tests and dedup
/// paths. Equality is structural (data, validator, signature bytes); it is
/// NOT the anti-replay identity of evidence, which deliberately excludes
/// signature bytes (`slashing::SlashingEvidence::id`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    pub data: AttestationData,
    /// Index into the active validator registry.
    pub validator: u32,
    /// Hybrid ML-DSA-65 ‖ Falcon-1024 signature, ≈ 4,589 B. Opaque here.
    pub signature: Vec<u8>,
}

/// Injected signature verification, so this crate stays free of the PQ stack.
///
/// ## Why there is no `verify(validator_index, ..)` here any more
///
/// There used to be one, and it was the whole defect. An index-keyed method
/// forces the *verifier* to own a table mapping index → key, and the only
/// table the node could build at construction time was the genesis manifest's
/// — built once at boot, never rebuilt after sync or replay. A validator added
/// later by an on-chain deposit registered, activated, entered the roster and
/// was drawn for committees, and then every signature it produced was rejected
/// as [`RejectReason::BadSignature`], because `pubkeys.get(index)` returned
/// `None`. Its committee seats were unfillable: a deposit landing before this
/// change silently subtracts from finality.
///
/// The registry already commits the full ≈3,745-byte key per validator
/// (`state_root::ValidatorRecord::pubkey`, whose own doc says "the registry
/// *is* the authoritative key store"). The verifier simply did not read it.
///
/// So the index form is **deleted rather than deprecated**. Every consensus
/// call site must now resolve the key itself, out of a registry it names, and
/// pass it to [`Self::verify_with_key`]. That turns "did I find every call
/// site?" from a review question into a compiler question: any site still
/// expecting an index lookup fails to build.
pub trait SignatureVerifier {
    /// Verify `signature` over `signing_root` against a public key given
    /// directly.
    ///
    /// This is now the *only* verification entry point, and it serves two
    /// different key spaces on purpose:
    ///
    /// - an eUTXO is owned by whoever can produce the key its `script_hash`
    ///   commits to, and that key is in no registry;
    /// - a validator's key is in the registry, and the caller — not this
    ///   trait — decides *which* registry state answers (see
    ///   [`KeyLookup`]).
    ///
    /// Must verify **both** halves of the hybrid suite. An implementation
    /// that checked one half for spending and two for attesting would make
    /// spending cheaper to forge than attesting.
    fn verify_with_key(&self, pubkey: &[u8], signing_root: &[u8; 32], signature: &[u8]) -> bool;
}

/// Resolves a validator index to its registered public key.
///
/// ## The whole point of this trait is *which state* implements it
///
/// This is the dangerous half of the fix, not the plumbing. A verdict on a
/// signature is a consensus verdict, and deriving one from node-local mutable
/// state is exactly the shape that forked this chain on 2026-08-08
/// (`expected_bits` read from a locally-updated `current_bits` instead of from
/// ancestry, so nodes running an identical binary disagreed).
///
/// The rule this codebase now follows, per call site:
///
/// - **Inside the state transition** (proposer signature, attestations in a
///   block, slashing evidence in a block): the registry of the **block's
///   pre-state** — the parent's post-state — and nothing else. That keeps
///   `apply_block` a pure function of (parent state, block), which is the
///   property that makes two honest nodes agree on validity. It is *not*
///   this node's head, not `rolled_to`, not the finalized state.
///
/// - **On the gossip ingest path**: the same `rolled_to(epoch)` projection
///   that the path *already* used to draw the committee it checks membership
///   against. This introduces no new node-local dependency — it removes an
///   inconsistency, because membership and key now come from one snapshot
///   instead of membership from committed state and key from a boot-time
///   constant. A gossip verdict is a relay/scoring decision, re-judged by the
///   transition against the block's pre-state if the attestation is ever
///   included, so a disagreement here costs propagation, never a fork.
///
/// ## Why getting it wrong is survivable here, and the proof of that
///
/// Two registries can disagree about an index only by *presence*, never by
/// *content*, because the registry is append-only in three independent ways:
///
/// 1. indices are allocated `keys().next_back() + 1` — monotonic, never
///    reused (`transition.rs`, "a deterministic function of the registry,
///    never of anything local");
/// 2. no production path mutates `ValidatorRecord::pubkey` after insertion;
/// 3. nothing ever removes from the registry — exit and slashing set fields
///    (`exit_epoch`, `slashed`), they do not delete the record.
///
/// So index → key is injective, permanent, and total once assigned. A stale
/// registry can only be *missing* an index; it can never hold a *different*
/// key at one. That downgrades a wrong choice of state from a safety failure
/// (two nodes accept different keys for one index) to a liveness one (a
/// behind node declines a signature it cannot yet resolve). It is still worth
/// getting right, and the per-site rule above is the right answer — but the
/// blast radius is bounded by construction, and that is why this can ship and
/// soak ahead of the deposit flag day.
pub trait KeyLookup {
    /// The registered key for `validator`, or `None` if this registry has no
    /// such index. `None` must be treated as a verification failure by the
    /// caller — never as "skip the check".
    fn pubkey(&self, validator: u32) -> Option<&[u8]>;
}

/// Why an attestation was rejected. Distinct variants because "invalid" alone
/// makes a divergence impossible to debug from logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// Signer is not in the committee drawn for this slot/epoch.
    NotInCommittee,
    /// Signature failed verification.
    BadSignature,
    /// The signer is in the committee but the registry the caller named has
    /// no key for its index.
    ///
    /// Distinct from [`Self::BadSignature`] on purpose, and the distinction is
    /// the whole diagnostic value of this change: "the key is not in the
    /// registry I am judging against" and "the bytes do not verify under the
    /// key" are different failures with different causes. Collapsing them is
    /// what made the original defect invisible — a deposit-added validator
    /// signing perfectly well was reported as `BadSignature`, which sends
    /// every reader to look at the signature instead of at the lookup.
    UnknownValidator,
    /// Attestation is for a future slot.
    FutureSlot,
    /// Source epoch is not before the target epoch.
    NonMonotonicCheckpoints,
}

/// Validate one attestation against a committee drawn by the caller, using
/// the keys of a registry the caller names.
///
/// Committee membership is checked **before** the signature: verifying a 4.6 KB
/// hybrid signature costs far more than a membership lookup, so an attacker
/// spamming attestations from non-members should be rejected on the cheap
/// check. Order matters for DoS resistance, not just correctness.
///
/// `keys` is taken as a lookup rather than a resolved key so that the registry
/// read stays *after* the cheap checks, preserving that ordering exactly: a
/// non-member still costs one binary search and no registry probe.
///
/// `committee` and `keys` must be drawn from the **same** state. Passing a
/// committee from one state and keys from another is the defect this whole
/// change exists to remove — see [`KeyLookup`] for which state that is at
/// each call site.
pub fn validate(
    att: &Attestation,
    committee: &[u32],
    current_slot: u64,
    verifier: &dyn SignatureVerifier,
    keys: &dyn KeyLookup,
) -> Result<(), RejectReason> {
    if committee.binary_search(&att.validator).is_err() {
        return Err(RejectReason::NotInCommittee);
    }
    if att.data.slot > current_slot {
        return Err(RejectReason::FutureSlot);
    }
    if att.data.source_epoch >= att.data.target_epoch {
        return Err(RejectReason::NonMonotonicCheckpoints);
    }
    // The registry read, last, beside the verify it feeds. A committee member
    // with no registry key cannot be dismissed as a bad signature: it means
    // this registry does not know the validator, which is a different fact.
    let Some(pubkey) = keys.pubkey(att.validator) else {
        return Err(RejectReason::UnknownValidator);
    };
    if !verifier.verify_with_key(pubkey, &att.data.signing_root(), &att.signature) {
        return Err(RejectReason::BadSignature);
    }
    Ok(())
}
