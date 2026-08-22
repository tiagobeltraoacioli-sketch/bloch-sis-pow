// SPDX-License-Identifier: AGPL-3.0-or-later
//! The hybrid-verify precompile (§8) — pure logic, no revm.
//!
//! Without it, option 2's contract ecosystem has no way to verify its own
//! chain's signatures: PQ permit, PQ meta-transactions, contract wallets,
//! PQ-validator bridges, Ustav/Kirpich charter checks. It ships with the first
//! EVM block, whenever that is.

use crate::root::call_message;
use crate::{
    parse_envelope_strict, HybridKeyVerifier, GAS_PER_BYTE, HYBRID_PK_BYTES, HYBRID_VERIFY_GAS,
    MLDSA65_PK_BYTES, MLDSA65_SIG_BYTES, SUITE_MLDSA65_FALCON1024,
};

/// Precompile address `0x00000000000000000000000000000000000000ff` — high
/// enough in the precompile space that upstream Ethereum's continued
/// allocation from `0x01` upward will not collide with it for the foreseeable
/// future.
pub const PQ_VERIFY_ADDRESS: [u8; 20] = {
    let mut a = [0u8; 20];
    a[19] = 0xff;
    a
};

/// Base charge, from `fee_market::HYBRID_VERIFY_GAS`. There is one
/// calibration and one place to edit it; `tests/gas_alignment.rs` asserts this
/// restatement has not drifted from the original.
pub const PQ_VERIFY_BASE_GAS: u64 = HYBRID_VERIFY_GAS;

/// What the precompile returns: a gas charge and 32 bytes of output.
///
/// **It never reverts and never panics.** Malformed input returns `false`. A
/// precompile that reverts on some inputs and not others is a divergence
/// surface between implementations; a total function is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrecompileOutput {
    /// Gas charged. Always the full charge — see [`pq_verify`].
    pub gas: u64,
    /// 32 bytes: `0x..01` for true, `0x..00` for false.
    pub output: [u8; 32],
}

/// `pq_verify(pk_envelope, msg32, sig_envelope) → bool`.
///
/// Input is standard Solidity ABI encoding of `(bytes pk, bytes32 msg, bytes
/// sig)`, so a contract calls it with `abi.encode(...)` and a `staticcall`.
/// Strict decode: non-canonical offsets, oversized lengths, non-zero padding
/// and trailing bytes are all failures.
///
/// **Gas is computed from the input length, before verification, and charged
/// in full on malformed input.** A cheap failure path is a DoS invitation: an
/// attacker who can make an invalid input cost less than a valid one has found
/// a free way to make every node work. Malformed costs exactly what
/// well-formed costs.
///
/// The message actually verified is `SHA3-256(DS_EVM_CALL ‖ chain_id ‖
/// msg32)`, never `msg32` itself — see [`crate::root::call_message`] for the
/// hole that closes. The wallet rule that goes with it, which belongs in the
/// wallet docs: **never sign a 32-byte blob the wallet did not construct
/// itself.**
pub fn pq_verify(input: &[u8], chain_id: u64, verifier: &dyn HybridKeyVerifier) -> PrecompileOutput {
    let gas = PQ_VERIFY_BASE_GAS.saturating_add((input.len() as u64).saturating_mul(GAS_PER_BYTE));
    let ok = decode_and_verify(input, chain_id, verifier).unwrap_or(false);
    let mut output = [0u8; 32];
    if ok {
        output[31] = 1;
    }
    PrecompileOutput { gas, output }
}

/// `None` on any malformed input, which the caller maps to `false`. Split out
/// so the `?` operator can carry "malformed" without a single early `return`
/// being able to skip the gas charge.
fn decode_and_verify(
    input: &[u8],
    chain_id: u64,
    verifier: &dyn HybridKeyVerifier,
) -> Option<bool> {
    // Head: offset(pk) ‖ msg32 ‖ offset(sig).
    if input.len() < 96 {
        return None;
    }
    let off_pk = word_as_usize(&input[0..32])?;
    let mut msg32 = [0u8; 32];
    msg32.copy_from_slice(&input[32..64]);
    let off_sig = word_as_usize(&input[64..96])?;

    // Canonical layout: the first dynamic tail starts immediately after the
    // three head words, and the second immediately after the first. Anything
    // else is a non-canonical encoding of the same arguments.
    if off_pk != 96 {
        return None;
    }
    let (pk, after_pk) = read_bytes_tail(input, off_pk)?;
    if off_sig != after_pk {
        return None;
    }
    let (sig, after_sig) = read_bytes_tail(input, off_sig)?;
    // Trailing padding is a rejection, exactly as it is in the transaction
    // decoder and for the same reason.
    if after_sig != input.len() {
        return None;
    }

    // Suite rules identical to the transaction's (§5.4), from the same code
    // path: envelope required, 0x0001 only, legacy blob rejected.
    let (pk_suite, pk_body) = parse_envelope_strict(&pk)?;
    let (sig_suite, sig_body) = parse_envelope_strict(&sig)?;
    if pk_suite != SUITE_MLDSA65_FALCON1024 || sig_suite != SUITE_MLDSA65_FALCON1024 {
        return None;
    }
    if pk_body.len() != HYBRID_PK_BYTES || sig_body.len() <= MLDSA65_SIG_BYTES {
        return None;
    }

    let message = call_message(chain_id, &msg32);
    let (mldsa_pk, falcon_pk) = pk_body.split_at(MLDSA65_PK_BYTES);
    let (mldsa_sig, falcon_sig) = sig_body.split_at(MLDSA65_SIG_BYTES);
    // AND, never OR — the same rule as the transaction path.
    Some(
        verifier.verify_mldsa65(mldsa_pk, &message, mldsa_sig)
            && verifier.verify_falcon1024(falcon_pk, &message, falcon_sig),
    )
}

/// A 32-byte ABI word as a `usize`. The high 24 bytes MUST be zero: a length
/// or offset that does not fit is malformed, not saturated.
fn word_as_usize(word: &[u8]) -> Option<usize> {
    if word.len() != 32 || word[..24].iter().any(|b| *b != 0) {
        return None;
    }
    let mut tail = [0u8; 8];
    tail.copy_from_slice(&word[24..32]);
    usize::try_from(u64::from_be_bytes(tail)).ok()
}

/// Read a `bytes` tail at `off`: a 32-byte length, the data, then zero padding
/// to the next 32-byte boundary. Returns the data and the offset just past the
/// padding. Non-zero padding is a rejection — it is a second encoding of the
/// same argument.
fn read_bytes_tail(input: &[u8], off: usize) -> Option<(Vec<u8>, usize)> {
    let len_end = off.checked_add(32)?;
    let len = word_as_usize(input.get(off..len_end)?)?;
    let data_end = len_end.checked_add(len)?;
    let data = input.get(len_end..data_end)?.to_vec();
    let padded = len.checked_add(31)? / 32 * 32;
    let pad_end = len_end.checked_add(padded)?;
    if input.get(data_end..pad_end)?.iter().any(|b| *b != 0) {
        return None;
    }
    Some((data, pad_end))
}
