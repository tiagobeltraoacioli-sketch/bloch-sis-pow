// SPDX-License-Identifier: AGPL-3.0-or-later
//! `bloch-evm-pq-precompile` — BLOCH-L1-EVM-AUTHORIZATION §6.2.
//!
//! The hybrid-verify precompile: `SUITE_MLDSA65_FALCON1024` verification
//! callable from inside the EVM. Without it, option 2 (PQ-only accounts) has
//! no way for a contract to check its own chain's signatures, and every
//! authorize-by-signature pattern — EIP-2612 `permit`, EIP-2771 meta-tx,
//! Safe-style signature checks, bridge validator sets, Ustav/Kirpich charter
//! checks — is simply dead.
//!
//! # INERT. This is a vehicle, not a wiring.
//!
//! The EVM is not on L1 and nothing in this crate puts it there. No crate in
//! the tree depends on this one; it is not reachable from
//! `bloch-pos-node`'s state-transition path; it adds no constant to
//! `params.rs` and no component tag to `state_root.rs`. [`is_active`] reads a
//! flag-day epoch pinned at [`u64::MAX`] and every call site must pass the
//! epoch **derived from the block being validated** — never node-local state.
//! That rule is not stylistic: on 2026-08-08 this chain lost consensus
//! because `expected_bits` was computed from mutable node-local state and
//! nodes on an identical binary diverged.
//!
//! # What this adds on top of `bloch_crypto::verify`
//!
//! Three rules the base verifier does not impose, because it must stay
//! bug-compatible with pre-envelope carry-over wallets:
//!
//! 1. **Strict envelope.** [`bloch_crypto::crypto::verify`] falls back to
//!    `parse_envelope_or_legacy`, which reads an un-headered blob as suite
//!    `0x0001`. Inside the EVM that would mean *one authorization with two
//!    valid encodings* — signature malleability, which breaks every contract
//!    that de-duplicates by `keccak256(sig)`. Here the header is mandatory on
//!    both objects.
//! 2. **One suite.** Only `SUITE_MLDSA65_FALCON1024` (`0x0001`).
//!    `SUITE_MLDSA65_ONLY` (`0x0002`) is exactly as available and exactly as
//!    unused as it is in staking (`staking.rs:52-56`).
//! 3. **Exact framing.** The declared lengths must account for every byte of
//!    input: no trailing data, no short read, no second encoding of one call.
//!
//! # Totality
//!
//! [`pq_verify_raw`] is a **total function of its input bytes**: it never
//! panics, never reverts, reads no state, allocates nothing beyond a 32-byte
//! digest, and returns the same 32 bytes for the same input on every node.
//! It is therefore safe under `STATICCALL`. Failure is the all-zero word,
//! not a revert — the ecrecover convention, so the caller decides.

#![forbid(unsafe_code)]

use bloch_crypto::crypto::{
    self, MLDSA_SIG_LEN, SUITE_HEADER_LEN, SUITE_MLDSA65_FALCON1024,
};
use bloch_pos_committee::fee_market::{
    BLOCK_GAS_LIMIT, HYBRID_VERIFY_GAS, HYBRID_VERIFY_INSTRUCTIONS, INSTRUCTIONS_PER_GAS,
};
use bloch_pos_committee::staking::HYBRID_PK_BYTES;
use sha3::{Digest, Sha3_256};

// ── Address ─────────────────────────────────────────────────────────────────

/// Address of the hybrid-verify precompile: `0x…B10C0001`.
///
/// Sixteen zero bytes, then the `B1 0C` suite magic reused as a *namespace*
/// magic, then a big-endian `u16` index. Two reasons for a reserved block
/// rather than the next free low number: upstream Ethereum keeps assigning
/// `0x01..0x0a…` (a future EIP landing on the same address would silently
/// change meaning), and the sibling state-model front needs precompile
/// addresses of its own. Index `0x0001` is this one; `0x0002` and up are left
/// for that front to assign.
pub const PQ_VERIFY_ADDRESS: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xB1, 0x0C, 0x00, 0x01,
];

// ── Input geometry ──────────────────────────────────────────────────────────

/// `msg32 ‖ u256(pk_len) ‖ u256(sig_len)` — the fixed head of every call.
pub const HEADER_LEN: usize = 32 * 3;

/// Enveloped hybrid public key: 4-byte suite header + `HYBRID_PK_BYTES`.
/// Fixed — ML-DSA-65 and Falcon-1024 public keys are both fixed size.
pub const ENVELOPED_PK_LEN: usize = SUITE_HEADER_LEN + HYBRID_PK_BYTES;

/// Longest Falcon-1024 signature `pqcrypto-falcon` 0.4 (PQClean, non-padded)
/// will hand back. Pinned against the linked library by
/// `max_falcon_sig_len_matches_the_linked_library`.
pub const MAX_FALCON_SIG_BYTES: usize = 1462;

/// Shortest signature the hybrid verifier can accept: the ML-DSA half is
/// fixed and `verify_hybrid_mldsa_falcon` requires the body to be *strictly*
/// longer, so at least one Falcon byte must follow.
pub const MIN_ENVELOPED_SIG_LEN: usize = SUITE_HEADER_LEN + MLDSA_SIG_LEN + 1;

/// Longest signature that can exist under this suite.
pub const MAX_ENVELOPED_SIG_LEN: usize = SUITE_HEADER_LEN + MLDSA_SIG_LEN + MAX_FALCON_SIG_BYTES;

/// Largest well-formed call: 8,620 bytes.
pub const MAX_INPUT_BYTES: usize = HEADER_LEN + ENVELOPED_PK_LEN + MAX_ENVELOPED_SIG_LEN;

/// Smallest call that can reach the verifier at all: 7,159 bytes. This is the
/// input length that sets the worst case for gas-versus-CPU, because it is
/// the cheapest call that still costs a full hybrid verification.
pub const MIN_VERIFYING_INPUT_BYTES: usize =
    HEADER_LEN + ENVELOPED_PK_LEN + MIN_ENVELOPED_SIG_LEN;

// ── Gas ─────────────────────────────────────────────────────────────────────

/// Base charge: **the same number the fee market already pays for a hybrid
/// verification on the transaction path**, taken from
/// `fee_market::HYBRID_VERIFY_GAS` rather than re-derived.
///
/// The argument is short: a hybrid verification does not get cheaper because
/// a contract asked for it instead of a transaction envelope. If the two
/// prices ever diverge, the cheaper one becomes the attack surface. Two
/// modules deciding one rule is this repository's recurring failure mode, so
/// this is a re-export, not a second opinion.
pub const PQ_VERIFY_BASE_GAS: u64 = HYBRID_VERIFY_GAS;

/// Per 32-byte word of input: 39 gas.
///
/// Derived, not chosen. The only per-byte work in this precompile is copying
/// the input and hashing the public key with SHA3-256 for the address. From
/// `spikes/prover-cost/RESULTS.md` one Keccak-f permutation costs ≈ 16,300
/// RV32IM instructions (16,386 and 16,270 in two independent implementations
/// — the cross-check that says the measurement is real). SHA3-256 absorbs 136
/// bytes per permutation:
///
/// ```text
/// 16,300 / 136          = 119.9  instructions/byte
/// 119.9 × 32            = 3,836  instructions/word
/// 3,836 / 100           = 38.4   gas/word   (INSTRUCTIONS_PER_GAS)
///                       → 39     rounded up
/// ```
///
/// It is ≈ 6.5× the EVM's own `SHA3` opcode (6 gas/word), and that gap is a
/// finding about the opcode schedule, not about this precompile: the anchor
/// used here is the one tied to a measurement of *this chain's* code. The
/// cost of preferring it is bounded and small — 10,530 gas at the maximum
/// input against a 72,748 base, 12.7% — and it cannot grow, because the
/// public key length is fixed and [`MAX_INPUT_BYTES`] caps the rest.
pub const PQ_VERIFY_GAS_PER_WORD: u64 = 39;

/// Gas for a call with `input_len` bytes of input.
///
/// **Charged from the length alone**, before any parsing, and identical for a
/// valid signature, an invalid one, and 96 bytes of garbage. A malformed
/// 96-byte call therefore pays 72,865 gas for no work at all. That
/// overcharge is deliberate: an early-out discount would hand an attacker a
/// cheap probe and would make the price a function of the *data*. On a chain
/// that has already lost consensus once to a rule computed from mutable
/// local state, "gas is a pure function of one integer" is worth more than
/// the gas it wastes.
pub const fn pq_verify_gas(input_len: usize) -> u64 {
    let words = (input_len as u64).saturating_add(31) / 32;
    PQ_VERIFY_BASE_GAS.saturating_add(PQ_VERIFY_GAS_PER_WORD.saturating_mul(words))
}

// The claim the DoS argument rests on, checked by the compiler.
//
// (1) The cheapest call that can reach the verifier must still pay for the
//     instructions that verification costs. Note that the base alone does
//     NOT: HYBRID_VERIFY_GAS truncates 7,274,849/100 to 72,748, which
//     under-sells by 49 instructions. The per-word term covers it ~178×.
const _: () = assert!(
    pq_verify_gas(MIN_VERIFYING_INPUT_BYTES) as u128 * INSTRUCTIONS_PER_GAS as u128
        >= HYBRID_VERIFY_INSTRUCTIONS as u128,
    "a call that costs a hybrid verification must pay for one"
);

// (2) A whole block spent in this precompile cannot exceed the instruction
//     budget the block gas limit already implies. This is what pricing on
//     the fee market's anchor *means*, and it is the reason the precompile
//     does not need a per-block invocation cap of its own.
const _: () = assert!(
    (BLOCK_GAS_LIMIT / pq_verify_gas(MIN_VERIFYING_INPUT_BYTES)) as u128
        * HYBRID_VERIFY_INSTRUCTIONS as u128
        <= BLOCK_GAS_LIMIT as u128 * INSTRUCTIONS_PER_GAS as u128,
    "a block full of pq_verify must fit the block's instruction budget"
);

// (3) The base is the fee market's number, unedited.
const _: () = assert!(PQ_VERIFY_BASE_GAS == 72_748);

// ── Activation ──────────────────────────────────────────────────────────────

/// Flag day, pinned inert.
///
/// **This is not yet a consensus constant.** When the founder decides to wire
/// the EVM in, this moves to `bloch_pos_committee::params` next to
/// `LEAKED_ROSTER_ACTIVATION_EPOCH` and `BLOCK_BYTES_V2_ACTIVATION_EPOCH`,
/// and this one is deleted — one rule, one home. It lives here now so that
/// "inert" is a testable property of the code rather than a promise in a
/// document.
pub const PQ_PRECOMPILE_ACTIVATION_EPOCH: u64 = u64::MAX;

/// Whether the precompile exists at `epoch`.
///
/// `epoch` MUST be derived from the header of the block being validated.
/// A gate read from node-local state is how a fleet on one binary splits
/// (2026-08-08).
pub const fn is_active(epoch: u64) -> bool {
    epoch >= PQ_PRECOMPILE_ACTIVATION_EPOCH
}

// ── The precompile ──────────────────────────────────────────────────────────

/// The all-zero word: "this input did not authorize anything".
pub const REJECTED: [u8; 32] = [0u8; 32];

/// The call ran out of gas. The host consumes everything it offered, as it
/// does for any precompile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutOfGas;

/// What the EVM gets back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrecompileOutput {
    pub gas_used: u64,
    /// 12 zero bytes ‖ the 20-byte signer address, or 32 zero bytes.
    pub output: [u8; 32],
}

/// Metered entry point.
pub fn pq_verify(input: &[u8], gas_limit: u64) -> Result<PrecompileOutput, OutOfGas> {
    let gas_used = pq_verify_gas(input.len());
    if gas_used > gas_limit {
        return Err(OutOfGas);
    }
    Ok(PrecompileOutput { gas_used, output: pq_verify_raw(input) })
}

/// The unmetered kernel — a total function of `input`.
///
/// Returns `12 zero bytes ‖ SHA3-256(enveloped pk)[..20]` when the signature
/// is valid under all three added rules, and 32 zero bytes otherwise.
///
/// # Why the address and not a bool
///
/// A `bool` would force every caller to trust a signer address handed to it
/// *alongside* the signature, because a contract cannot derive one itself:
/// Solidity's `keccak256` (and the EVM's `SHA3` opcode) is Keccak-256, and a
/// Bloch address is FIPS-202 **SHA3-256** — a different padding rule, so no
/// amount of Solidity reproduces `address_from_pubkey`. Returning the address
/// makes the precompile the single authority on that derivation, which is
/// also what keeps it in step with the §6.1 transaction `sender` field.
pub fn pq_verify_raw(input: &[u8]) -> [u8; 32] {
    // Framing. Every check below is on lengths only — no data-dependent path.
    if input.len() < HEADER_LEN || input.len() > MAX_INPUT_BYTES {
        return REJECTED;
    }
    let msg = &input[..32];
    let pk_len = match u256_as_len(&input[32..64]) {
        Some(n) => n,
        None => return REJECTED,
    };
    let sig_len = match u256_as_len(&input[64..96]) {
        Some(n) => n,
        None => return REJECTED,
    };
    // Exact framing: the declared lengths must account for every byte.
    match HEADER_LEN.checked_add(pk_len).and_then(|n| n.checked_add(sig_len)) {
        Some(total) if total == input.len() => {}
        _ => return REJECTED,
    }
    if pk_len != ENVELOPED_PK_LEN {
        return REJECTED;
    }
    if sig_len < MIN_ENVELOPED_SIG_LEN || sig_len > MAX_ENVELOPED_SIG_LEN {
        return REJECTED;
    }
    let pk = &input[HEADER_LEN..HEADER_LEN + pk_len];
    // Sliced by the DECLARED length, not "everything left". With the exact-sum
    // check above the two are identical; keeping them separate means the sum
    // check is the *only* thing standing between one call and many encodings,
    // rather than being quietly propped up by the slicing.
    let sig = &input[HEADER_LEN + pk_len..HEADER_LEN + pk_len + sig_len];

    // Strict envelope, one suite — on BOTH objects. `crypto::verify` would
    // accept an un-headered blob here; that second encoding is the
    // malleability this precompile exists to refuse.
    if !is_hybrid_envelope(pk, HYBRID_PK_BYTES) {
        return REJECTED;
    }
    if !is_hybrid_envelope_longer_than(sig, MLDSA_SIG_LEN) {
        return REJECTED;
    }

    if !crypto::verify(pk, msg, sig) {
        return REJECTED;
    }

    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&Sha3_256::digest(pk)[..20]);
    out
}

/// A 32-byte big-endian word as a length. `None` unless the top 24 bytes are
/// zero — a length is not a place to accept 2^256 encodings of one number.
fn u256_as_len(word: &[u8]) -> Option<usize> {
    debug_assert_eq!(word.len(), 32);
    if word[..24].iter().any(|&b| b != 0) {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&word[24..]);
    usize::try_from(u64::from_be_bytes(buf)).ok()
}

/// Enveloped under suite `0x0001` with a body of exactly `body_len`.
///
/// `pub` on purpose. This predicate IS rule 2 of §3.2 — "one suite" — and
/// end to end that rule is currently unobservable: `crypto::verify`
/// dispatches on the tag itself, so a `0x0002`-tagged hybrid body fails
/// there anyway, and mutation M3 (accept any suite) survived the behavioural
/// suite because of it. Exporting the predicate lets the rule be tested AS A
/// RULE, so the day `bloch-crypto` grows a suite whose bodies are the same
/// size, the check is still pinned.
pub fn is_hybrid_envelope(obj: &[u8], body_len: usize) -> bool {
    match crypto::split_envelope(obj) {
        Some((SUITE_MLDSA65_FALCON1024, body)) => body.len() == body_len,
        _ => false,
    }
}

/// Enveloped under suite `0x0001` with a body strictly longer than `min` —
/// the Falcon half is variable, so the signature body cannot be pinned to a
/// single length the way the public key can.
///
/// `pub` for the same reason as [`is_hybrid_envelope`]: this is rule 1 of
/// §3.2, and it must be testable as a rule and not only through the one
/// end-to-end case (a stripped signature) that happens to expose it.
pub fn is_hybrid_envelope_longer_than(obj: &[u8], min: usize) -> bool {
    match crypto::split_envelope(obj) {
        Some((SUITE_MLDSA65_FALCON1024, body)) => body.len() > min,
        _ => false,
    }
}

/// Build a well-formed call. Exposed because the test suite, the cost
/// harness, and any future wallet-side tooling must agree on the encoding
/// byte for byte, and a second copy of it is a second format.
pub fn encode_input(msg32: &[u8; 32], pk: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(HEADER_LEN + pk.len() + sig.len());
    v.extend_from_slice(msg32);
    v.extend_from_slice(&len_word(pk.len()));
    v.extend_from_slice(&len_word(sig.len()));
    v.extend_from_slice(pk);
    v.extend_from_slice(sig);
    v
}

fn len_word(n: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&(n as u64).to_be_bytes());
    w
}
