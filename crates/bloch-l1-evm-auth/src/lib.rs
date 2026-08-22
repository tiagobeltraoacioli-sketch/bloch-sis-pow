// SPDX-License-Identifier: AGPL-3.0-or-later
//! # bloch-l1-evm-auth — the PQ-typed EVM transaction, built inert
//!
//! Implements §6.1 (the PQ-typed transaction) and §6.2 (the hybrid-verify
//! precompile) of `docs/specs/BLOCH-L1-EVM-AUTHORIZATION.md`, to the letter of
//! `docs/specs/BLOCH-L1-EVM-PQ-TX.md`. Nothing else.
//!
//! ## The posture, stated before anything else
//!
//! **The EVM is not at L1 and this crate does not put it there.** It is a
//! standalone, pure, dependency-light vehicle behind a flag day pinned at
//! [`ACTIVATION_EPOCH`] = `u64::MAX`, with **no call site anywhere in the
//! node's state-transition path**. It is not a dependency of `bloch-pos-node`
//! or `bloch-pos-committee`. Wiring it in collides with ADR-040 and with the
//! SR-2 single-re-freeze rule; activation is a separate founder decision and
//! lands as milestone X2, after X1, with the fleet rebuilt first.
//!
//! ## The decision this crate is the vehicle of (D-AUTH)
//!
//! The founder chose **option 2** on 2026-08-21: PQ-only accounts — EVM
//! semantics without EVM signing. Restated here because every document that
//! touches this crate has to restate it:
//!
//! - **MetaMask never works. No hardware wallet works.**
//! - **Throughput is authorizations-scale, single-digit tx/s.** The unit is a
//!   signature, not an effect. A steady-state transaction is ≈ 4,700 B and a
//!   first authorization ≈ 8,453 B; against the 524,288 B payload cap that is
//!   ≤ 111 authorizations per block ≈ 3.7/s *if the entire payload were EVM*,
//!   which it is not — the cap is shared with eUTXO and everything else.
//!
//! The compensation is that no authorization path here is breakable by a
//! quantum adversary, which closes the stolen-funds-to-stake path
//! (`BLOCH-L1-EVM-AUTHORIZATION.md` §3.4.2) that options 1 and 3 leave open.
//!
//! ## How the flag day is read — the 2026-08-08 rule
//!
//! Every entry point takes `epoch` as an **explicit parameter**, derived by
//! the caller from the block's own header slot. This crate cannot read node
//! state — it has no way to. That is structural, not a convention: on
//! 2026-08-08 this chain forked because `expected_bits` came from local
//! mutable state and nodes with identical binaries diverged.
//!
//! ## Scope boundary
//!
//! Not here, deliberately: §6.3 enshrined account abstraction (phase 2),
//! §6.4 PQ-bounded secp session keys (deferred), §6.5 secp for
//! "non-value-moving" calls (rejected). No secp256k1 verifier anywhere. No
//! touching `state_root.rs`, the closed component list, `EvmCommitment`, the
//! gas schedule, or `bloch-euvm`. An implementer who finds they need one of
//! those has found scope movement, and the answer is to stop and escalate.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod codec;

pub mod batch;
pub mod precompile;
pub mod root;
pub mod tx;
pub mod verify;

pub use batch::BatchCall;
pub use codec::CodecError;
pub use precompile::{PrecompileOutput, PQ_VERIFY_BASE_GAS};
pub use tx::BlochTx;
pub use verify::{AuthReject, Authorized};

// ---------------------------------------------------------------------------
// The flag day
// ---------------------------------------------------------------------------

/// Epoch at which PQ-typed EVM transactions become authorizable.
///
/// `u64::MAX` — inert, and inert is the point. Lowering this is a founder
/// decision that lands with the wiring PR (X2), *after* G10 has its second
/// line (attestation floor plus an EVM tx budget, ≥ 14 days on the real
/// fleet) and *after* the fleet is rebuilt.
///
/// **Where this constant lives, and why it is here rather than in
/// `params.rs`.** Putting it in the consensus crate today means editing
/// `bloch-pos-committee` for a rule with no consensus reader. The wiring PR
/// relocates it beside `LEAKED_ROSTER_ACTIVATION_EPOCH` and
/// `BLOCK_BYTES_V2_ACTIVATION_EPOCH` **in the same PR that adds the gate**, so
/// it is never defined in two places at once.
pub const ACTIVATION_EPOCH: u64 = u64::MAX;

// ---------------------------------------------------------------------------
// Transaction type bytes
// ---------------------------------------------------------------------------

/// EIP-2718 leading byte for a single PQ-authorized call.
///
/// `0x50` sits in the unreserved custom range under both readings on record —
/// `0x05..0x7f` (`BLOCH-L1-EVM-AUTHORIZATION.md` §6.1) and `0x40..0x7f`
/// (`BLOCH-L1-EVM-RPC-SURFACE.md` §5.2, which suggests `0x50`). Picking the
/// value that satisfies both ends the question of which document is right.
pub const TX_TYPE_PQ_CALL: u8 = 0x50;

/// EIP-2718 leading byte for the call-batch kind (§6): one ≈ 4.6 KB signature
/// amortized over many operations, which is what makes the throughput claim in
/// the dossier's §4.3 mean anything.
///
/// The *encoding* is frozen here. The **semantics are not**: `msg.sender` for
/// every sub-call, atomicity, and per-sub-call gas metering are new consensus
/// surface and are ratified by the founder at wiring time, not by this crate.
pub const TX_TYPE_PQ_BATCH: u8 = 0x51;

// ---------------------------------------------------------------------------
// Suite geometry
// ---------------------------------------------------------------------------

/// The only suite this transaction accepts: ML-DSA-65 ‖ Falcon-1024.
pub const SUITE_MLDSA65_FALCON1024: u16 = 0x0001;

/// The single-family escape hatch, restated **so that it can be rejected by
/// name**.
///
/// It stays exactly as available and exactly as unused as it is in staking
/// (`staking.rs:52-56`): a single-family suite would silently drop the hybrid
/// property for that account's entire lifetime. Never valid here.
pub const SUITE_MLDSA65_ONLY: u16 = 0x0002;

/// Suite envelope magic: `0xB1 0x0C`.
pub const SUITE_MAGIC: [u8; 2] = [0xB1, 0x0C];

/// Suite envelope header length: magic (2) + little-endian `u16` suite id (2).
pub const SUITE_HEADER_LEN: usize = 4;

/// ML-DSA-65 public key size in bytes.
pub const MLDSA65_PK_BYTES: usize = 1952;

/// Falcon-1024 public key size in bytes.
pub const FALCON1024_PK_BYTES: usize = 1793;

/// Hybrid public key body: ML-DSA-65 pk ‖ Falcon-1024 pk.
pub const HYBRID_PK_BYTES: usize = MLDSA65_PK_BYTES + FALCON1024_PK_BYTES;

/// The fixed positional split of the hybrid signature.
///
/// ML-DSA-65 signatures are fixed size; Falcon-1024 signatures are variable
/// (≈ 1,280 B). The hybrid signature therefore splits **positionally**: the
/// first `MLDSA65_SIG_BYTES` are the ML-DSA half, everything after is the
/// Falcon half. A length prefix would admit two encodings of one signature; a
/// fixed split point admits exactly one. Restated from `staking.rs:65-70` as a
/// consensus constant of this module, the same way staking restates it.
pub const MLDSA65_SIG_BYTES: usize = 3309;

/// Address payload length. Bloch base addresses are already 20 bytes —
/// `SHA3-256(enveloped pk)[..20]` — so a PQ account fits the EVM's `address`
/// type, `msg.sender`, and the ABI with no width change. That accident of
/// history is the reason option 2 is smaller than it sounds.
pub const ADDRESS_BYTES: usize = 20;

// ---------------------------------------------------------------------------
// Domain-separation tags — the params.rs pattern, followed exactly
// ---------------------------------------------------------------------------

/// Domain tag for the transaction signing root (§4.1).
///
/// 16 bytes, right-padded with zeros so no tag prefixes another — the
/// `params.rs` `DS_*` pattern.
pub const DS_EVM_TX: [u8; 16] = *b"BLCH4:EVMTX\0\0\0\0\0";

/// Domain tag for transaction identity (§4.2), derived from the witness-free
/// signing root — the `DS_TXID` idiom, so nobody can re-key a transaction in
/// flight by re-encoding its witness.
pub const DS_EVM_TXID: [u8; 16] = *b"BLCH4:EVMTXID\0\0\0";

/// Domain tag for the precompile's message (§8.2).
///
/// The precompile verifies over `SHA3(DS_EVM_CALL ‖ chain_id ‖ msg32)`, never
/// over `msg32` directly. Without it a contract can hand a user an arbitrary
/// 32-byte digest to sign — and a digest is a digest: if it happens to be some
/// transaction's signing root, the "signature over a message" is also a
/// signature that moves that user's funds.
pub const DS_EVM_CALL: [u8; 16] = *b"BLCH4:EVMCALL\0\0\0";

// ---------------------------------------------------------------------------
// Gas constants restated from fee_market
// ---------------------------------------------------------------------------

/// `fee_market::HYBRID_VERIFY_GAS`, restated. `tests/gas_alignment.rs` asserts
/// it still equals the original, so the restatement cannot silently drift.
pub const HYBRID_VERIFY_GAS: u64 = 72_748;

/// `fee_market::GAS_PER_BYTE`, restated. Same test, same reason.
pub const GAS_PER_BYTE: u64 = 16;

// ---------------------------------------------------------------------------
// The seams
// ---------------------------------------------------------------------------

/// Injected verification of the two halves of the hybrid suite.
///
/// Identical in shape to `staking::HybridKeyVerifier`, and deliberately so:
/// the halves are exposed **separately** so that no implementation can degrade
/// the hybrid to an OR by construction. The AND-composition lives in
/// [`verify::verify`], here, not in whatever the caller injects.
///
/// The node supplies the real implementation over `bloch_crypto`'s raw-half
/// entry points at wiring time. This crate does not link the PQClean FFI.
pub trait HybridKeyVerifier {
    /// Verify the ML-DSA-65 half. `pubkey` is exactly [`MLDSA65_PK_BYTES`].
    fn verify_mldsa65(&self, pubkey: &[u8], signing_root: &[u8; 32], sig: &[u8]) -> bool;
    /// Verify the Falcon-1024 half. `pubkey` is exactly [`FALCON1024_PK_BYTES`].
    fn verify_falcon1024(&self, pubkey: &[u8], signing_root: &[u8; 32], sig: &[u8]) -> bool;
}

/// Read-only view of the account → public key map.
///
/// That map lives **inside the EVM state** (`BLOCH-L1-EVM-AUTHORIZATION.md`
/// §8.1); it is not a second state-root component and this crate must not
/// create one. The crate never writes: on success it *returns* the key the
/// caller must record, and recording is the execution layer's job.
pub trait PubkeyDirectory {
    /// The enveloped hybrid public key already recorded for this account, or
    /// `None` if the account has never authorized a transaction.
    fn pubkey_of(&self, sender: &[u8; ADDRESS_BYTES]) -> Option<&[u8]>;
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The 20-byte account address of an **enveloped** hybrid public key:
/// `SHA3-256(enveloped pk)[..20]`.
///
/// The preimage is the *enveloped* bytes — `0xB1 0x0C ‖ suite_le ‖ mldsa_pk ‖
/// falcon_pk` — matching `bloch_crypto::address_from_pubkey`, which is the
/// decided derivation. (`BLOCH-L1-EVM-RPC-SURFACE.md` §5.2 describes a
/// different preimage; that sentence is wrong and is corrected separately. Two
/// preimages would mean two addresses for one key.)
pub fn address_from_pubkey(enveloped_pk: &[u8]) -> [u8; ADDRESS_BYTES] {
    use sha3::{Digest, Sha3_256};
    let digest = Sha3_256::digest(enveloped_pk);
    let mut out = [0u8; ADDRESS_BYTES];
    out.copy_from_slice(&digest[..ADDRESS_BYTES]);
    out
}

/// Parse a suite envelope **strictly**: magic, then the little-endian suite
/// id, then the body. `None` if the header is absent or the magic is wrong.
///
/// There is deliberately **no legacy fallback here**.
/// `bloch_crypto::parse_envelope_or_legacy` treats a bare `mldsa ‖ falcon`
/// blob as suite `0x0001` because carry-over wallets predate the envelope.
/// There is no carry-over EVM account — the plane does not exist yet — so this
/// path requires the explicit envelope. Accepting both would also mean two
/// addresses for one key, since the address hashes the *enveloped* bytes. That
/// is why this crate parses envelopes itself rather than handing bytes to
/// `bloch_crypto::verify`.
pub fn parse_envelope_strict(bytes: &[u8]) -> Option<(u16, &[u8])> {
    if bytes.len() < SUITE_HEADER_LEN {
        return None;
    }
    if bytes[0] != SUITE_MAGIC[0] || bytes[1] != SUITE_MAGIC[1] {
        return None;
    }
    let suite = u16::from_le_bytes([bytes[2], bytes[3]]);
    Some((suite, &bytes[SUITE_HEADER_LEN..]))
}

/// Wrap a body in a suite envelope. Provided for callers and fixtures that
/// have to build the wire form; the format is defined in exactly one place.
pub fn wrap_envelope(suite: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SUITE_HEADER_LEN + body.len());
    out.extend_from_slice(&SUITE_MAGIC);
    out.extend_from_slice(&suite.to_le_bytes());
    out.extend_from_slice(body);
    out
}

// ---------------------------------------------------------------------------
// Compile-time invariants
// ---------------------------------------------------------------------------

const _: () = assert!(HYBRID_PK_BYTES == 3745);
const _: () = assert!(DS_EVM_TX.len() == 16 && DS_EVM_TXID.len() == 16 && DS_EVM_CALL.len() == 16);
const _: () = assert!(TX_TYPE_PQ_CALL != TX_TYPE_PQ_BATCH);
// The flag day is inert. If this ever fails, someone lowered it without the
// founder decision, the G10 second line, and the fleet rebuild.
const _: () = assert!(ACTIVATION_EPOCH == u64::MAX);
