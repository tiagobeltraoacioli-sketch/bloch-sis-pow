// SPDX-License-Identifier: AGPL-3.0-or-later
//! `pq_verify` — the §6.2 hybrid-verification precompile, reference implementation.
//!
//! NORMATIVE SPEC: `docs/specs/BLOCH-L1-EVM-PQ-PRECOMPILE.md`. This crate is the
//! executable half of that document. It is a **standalone spike**: not a workspace
//! member, no revm dependency, no node wiring, no consensus reachability. The EVM
//! is not at L1 and nothing here puts it there (ADR-040 / SR-2).
//!
//! What it is: a pure function `bytes -> 32 bytes` plus a gas function
//! `usize -> u64`. That is the entire consensus surface a precompile has.
//!
//! Three rules this file exists to enforce, none of which
//! `bloch_crypto::verify` enforces on its own:
//!
//! 1. **Strict envelope.** `bloch_crypto::verify` falls back to the LEGACY
//!    pre-envelope encoding (`parse_envelope_or_legacy`, crypto/mod.rs:173) so
//!    carry-over wallets stay spendable. Inside the EVM that fallback would give
//!    one key two accepted encodings with two different derived addresses. The
//!    precompile parses the envelope itself and rejects anything un-headered.
//! 2. **One suite.** Only `SUITE_MLDSA65_FALCON1024`. `SUITE_MLDSA65_ONLY`
//!    (0x0002) is a strictly weaker authorization at the same gas price and the
//!    same address space; staking already refuses it (staking.rs:52-56) and so
//!    does this.
//! 3. **Exact framing.** One call, one encoding: fixed pubkey length, bounded
//!    signature length, no trailing bytes.

use sha3::{Digest, Sha3_256};

// ── Sizes, from `crates/bloch-crypto` and `crates/bloch-pos-committee` ────────
/// `SUITE_HEADER_LEN` (crypto/mod.rs): magic `B1 0C` + u16 LE suite id.
pub const SUITE_HEADER_LEN: usize = 4;
/// `SUITE_MLDSA65_FALCON1024` — the only suite any consensus role uses.
pub const SUITE_MLDSA65_FALCON1024: u16 = 0x0001;
const SUITE_MAGIC: [u8; 2] = [0xB1, 0x0C];

/// `MLDSA_PUBKEY_LEN` 1952 + `FALCON1024_PK_BYTES` 1793 = `HYBRID_PK_BYTES`.
pub const HYBRID_PK_BYTES: usize = 3_745;
/// The enveloped public key: the only pubkey encoding this precompile accepts.
pub const ENVELOPED_PK_BYTES: usize = SUITE_HEADER_LEN + HYBRID_PK_BYTES; // 3_749

/// `MLDSA65_SIG_BYTES` — the fixed split point of the hybrid signature.
pub const MLDSA_SIG_LEN: usize = 3_309;
/// `falcon1024::signature_bytes()` (pqcrypto-falcon 0.4.1, PQClean non-padded).
pub const FALCON1024_MAX_SIG_BYTES: usize = 1_462;
/// Shortest legal enveloped hybrid signature: header + ML-DSA half + >=1 Falcon byte.
pub const MIN_ENVELOPED_SIG_BYTES: usize = SUITE_HEADER_LEN + MLDSA_SIG_LEN + 1; // 3_314
/// Longest: header + ML-DSA half + the Falcon worst case.
pub const MAX_ENVELOPED_SIG_BYTES: usize =
    SUITE_HEADER_LEN + MLDSA_SIG_LEN + FALCON1024_MAX_SIG_BYTES; // 4_775

// ── ABI ──────────────────────────────────────────────────────────────────────
/// `msg32 ‖ u256(pk_len) ‖ u256(sig_len)`, EVM word order (big-endian).
pub const HEADER_BYTES: usize = 32 * 3; // 96
/// Largest legal input. The pubkey length is FIXED, so this bound is tight and
/// the per-word gas term cannot be farmed by padding.
pub const MAX_INPUT_BYTES: usize = HEADER_BYTES + ENVELOPED_PK_BYTES + MAX_ENVELOPED_SIG_BYTES; // 8_620

/// Reserved Bloch precompile block: 16 zero bytes, then the envelope magic
/// `B1 0C`, then a u16 BE index. `pq_verify` is index 1. Far above Ethereum's
/// 0x01..0xff, so upstream can add precompiles forever without colliding.
pub const PQ_VERIFY_ADDRESS: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xB1, 0x0C, 0x00, 0x01,
];

// ── Gas ──────────────────────────────────────────────────────────────────────
/// Measured: one hybrid verification = 7,274,849 RV32IM instructions
/// (`spikes/prover-cost/RESULTS.md`, marginal count). Mirrors
/// `fee_market::HYBRID_VERIFY_INSTRUCTIONS`.
pub const HYBRID_VERIFY_INSTRUCTIONS: u64 = 7_274_849;
/// The one calibration ratio of the whole native schedule
/// (`fee_market::INSTRUCTIONS_PER_GAS`). Not re-decided here.
pub const INSTRUCTIONS_PER_GAS: u64 = 100;
/// Base charge = the same measured verification the eUTXO and §6.1 paths pay.
/// `fee_market::HYBRID_VERIFY_GAS` = 72,748.
pub const PQ_VERIFY_BASE_GAS: u64 = HYBRID_VERIFY_INSTRUCTIONS / INSTRUCTIONS_PER_GAS;
/// Per 32-byte input word: copy + the SHA3-256 address derivation.
/// 16,300 instructions per Keccak-f permutation (prover-cost cross-check:
/// 16,386 / 16,270) over the 136-byte SHA3-256 rate = 119.9 instr/byte =
/// 3,836 instr/word = 38.4 gas/word at the anchor. Rounded up.
pub const PQ_VERIFY_PER_WORD_GAS: u64 = 39;

/// Gas for an input of `len` bytes. A pure function of LENGTH ONLY — never of
/// content, never of validity. Charged in full before any parsing, so a
/// malformed input costs exactly what a valid one of the same length costs and
/// no attacker gets a cheap probe. Deterministic by construction.
pub const fn pq_verify_gas(len: usize) -> u64 {
    let words = (len as u64 + 31) / 32;
    PQ_VERIFY_BASE_GAS + words * PQ_VERIFY_PER_WORD_GAS
}

/// The result word. `Valid(addr)` encodes as 12 zero bytes ‖ addr20 — the exact
/// shape `ecrecover` returns, so `abi.decode(ret, (address))` works unchanged.
/// Invalid encodes as 32 zero bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Valid([u8; 20]),
    Invalid,
}

impl Outcome {
    pub fn to_word(self) -> [u8; 32] {
        let mut w = [0u8; 32];
        if let Outcome::Valid(a) = self {
            w[12..].copy_from_slice(&a);
        }
        w
    }
    pub fn is_valid(self) -> bool {
        matches!(self, Outcome::Valid(_))
    }
}

/// The precompile. TOTAL: every input maps to a 32-byte word. It never reverts,
/// never panics, and never reads state (staticcall-safe, hence `pure` on the
/// Solidity side).
///
/// Input framing:
/// ```text
///   [  0.. 32)  msg32     — the message digest, OPAQUE to this precompile
///   [ 32.. 64)  pk_len    — u256 BE, MUST equal ENVELOPED_PK_BYTES
///   [ 64.. 96)  sig_len   — u256 BE, MIN_ENVELOPED_SIG_BYTES ..= MAX
///   [ 96..  ..)  pk_envelope ‖ sig_envelope, and NOTHING after
/// ```
/// Returns `Valid(SHA3-256(pk_envelope)[..20])` — the caller's Bloch account
/// address — or `Invalid`. Returning the ADDRESS rather than a bare bool is
/// deliberate: Solidity has `keccak256`, not FIPS `SHA3-256`, so a contract
/// cannot derive a Bloch address on-chain. A bool would force every caller to
/// trust an address supplied alongside the signature, which is the classic
/// "any valid signature by anyone" hole. See spec §4.2.
pub fn pq_verify(input: &[u8]) -> Outcome {
    if input.len() < HEADER_BYTES || input.len() > MAX_INPUT_BYTES {
        return Outcome::Invalid;
    }
    let pk_len = match word_as_len(&input[32..64]) {
        Some(v) => v,
        None => return Outcome::Invalid,
    };
    let sig_len = match word_as_len(&input[64..96]) {
        Some(v) => v,
        None => return Outcome::Invalid,
    };
    if pk_len != ENVELOPED_PK_BYTES {
        return Outcome::Invalid;
    }
    if sig_len < MIN_ENVELOPED_SIG_BYTES || sig_len > MAX_ENVELOPED_SIG_BYTES {
        return Outcome::Invalid;
    }
    // Exact framing: one call has exactly one encoding. No trailing bytes.
    if input.len() != HEADER_BYTES + pk_len + sig_len {
        return Outcome::Invalid;
    }

    let msg = &input[0..32];
    let pk = &input[HEADER_BYTES..HEADER_BYTES + pk_len];
    let sig = &input[HEADER_BYTES + pk_len..];

    // Rule 1 + 2: strict envelope, single suite, on BOTH objects.
    if !is_enveloped_hybrid(pk) || !is_enveloped_hybrid(sig) {
        return Outcome::Invalid;
    }

    // Rule 3: the cryptography itself is the frozen crate's, unchanged. Suite
    // dispatch and AND-composition of the two halves stay where they are
    // audited (crypto/mod.rs, staking.rs::verify_hybrid).
    if !bloch_crypto::crypto::verify(pk, msg, sig) {
        return Outcome::Invalid;
    }

    Outcome::Valid(address_from_enveloped_pubkey(pk))
}

/// `address_from_pubkey` (crypto/mod.rs:274) without the string formatting:
/// SHA3-256 over the ENVELOPED public key, first 20 bytes. The envelope is
/// inside the hash, which is what makes the address suite-committing.
pub fn address_from_enveloped_pubkey(enveloped_pk: &[u8]) -> [u8; 20] {
    let h = Sha3_256::digest(enveloped_pk);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[..20]);
    a
}

fn is_enveloped_hybrid(b: &[u8]) -> bool {
    b.len() > SUITE_HEADER_LEN
        && b[0] == SUITE_MAGIC[0]
        && b[1] == SUITE_MAGIC[1]
        && u16::from_le_bytes([b[2], b[3]]) == SUITE_MLDSA65_FALCON1024
}

/// A u256 word read as a length. Any value that does not fit `usize` is not a
/// length; reject rather than truncate (silent truncation is how a 2^64+96
/// length becomes 96).
fn word_as_len(w: &[u8]) -> Option<usize> {
    if w[..24].iter().any(|&b| b != 0) {
        return None;
    }
    let mut n = [0u8; 8];
    n.copy_from_slice(&w[24..32]);
    usize::try_from(u64::from_be_bytes(n)).ok()
}

/// Build a well-formed input. Wallet/tooling helper; also the test fixture.
pub fn encode_input(msg32: &[u8; 32], pk: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(HEADER_BYTES + pk.len() + sig.len());
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

// ── Compile-time consistency with the fee market ─────────────────────────────
// The invariant the whole DoS argument rests on: the precompile never sells a
// verification below the instruction count that verification was MEASURED at.
// If this ever fails, the gas schedule is subsidising validator CPU.
const _: () = assert!(PQ_VERIFY_BASE_GAS * INSTRUCTIONS_PER_GAS >= HYBRID_VERIFY_INSTRUCTIONS - 99);
const _: () = assert!(PQ_VERIFY_BASE_GAS == 72_748, "must equal fee_market::HYBRID_VERIFY_GAS");
const _: () = assert!(MAX_INPUT_BYTES == 8_620);
