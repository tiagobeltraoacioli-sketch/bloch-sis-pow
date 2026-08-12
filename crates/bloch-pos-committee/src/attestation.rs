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
pub trait SignatureVerifier {
    /// Verify `signature` over `signing_root` for the given validator index.
    /// Must verify **both** halves of the hybrid suite.
    fn verify(&self, validator: u32, signing_root: &[u8; 32], signature: &[u8]) -> bool;
}

/// Why an attestation was rejected. Distinct variants because "invalid" alone
/// makes a divergence impossible to debug from logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// Signer is not in the committee drawn for this slot/epoch.
    NotInCommittee,
    /// Signature failed verification.
    BadSignature,
    /// Attestation is for a future slot.
    FutureSlot,
    /// Source epoch is not before the target epoch.
    NonMonotonicCheckpoints,
}

/// Validate one attestation against a committee drawn by the caller.
///
/// Committee membership is checked **before** the signature: verifying a 4.6 KB
/// hybrid signature costs far more than a membership lookup, so an attacker
/// spamming attestations from non-members should be rejected on the cheap
/// check. Order matters for DoS resistance, not just correctness.
pub fn validate(
    att: &Attestation,
    committee: &[u32],
    current_slot: u64,
    verifier: &dyn SignatureVerifier,
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
    if !verifier.verify(att.validator, &att.data.signing_root(), &att.signature) {
        return Err(RejectReason::BadSignature);
    }
    Ok(())
}
