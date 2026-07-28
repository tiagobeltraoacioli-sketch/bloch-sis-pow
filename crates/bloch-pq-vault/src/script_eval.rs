//! # script_eval — a NARROW, test-oriented evaluator for the vault's witnessScripts
//!
//! **This is NOT a Bitcoin consensus engine and makes no claim to be one.** It is a
//! deliberately tiny script interpreter that understands exactly the opcodes the vault's
//! two P2WSH witnessScripts use (`OP_IF/ELSE/ENDIF`, `OP_SHA256`, `OP_EQUALVERIFY`,
//! `OP_CHECKSIG`, `OP_CSV`, `OP_DROP`, minimal pushes). Its purpose is to let the tests
//! *prove* the load-bearing behaviour with real inputs:
//!
//! - the clawback (branch B) spends **only** with the correct PQ-derived preimage `r`
//!   (`OP_SHA256 r == H(r)` via `OP_EQUALVERIFY`) **and** a valid recovery-key signature;
//! - a wrong preimage aborts at `OP_EQUALVERIFY`;
//! - the normal path (branch A) requires the CSV relative-timelock Δ: it is *immature*
//!   (rejected) before Δ confirmations and valid at/after Δ, and it rejects a spend whose
//!   `nSequence` does not encode the delay (BIP-68/BIP-112).
//!
//! Signature checks use **real secp256k1 ECDSA** verification over the real BIP-143
//! P2WSH sighash the caller computes — so `OP_CHECKSIG` here is genuine, not a stub. The
//! parts we model rather than fully replicate (relative-timelock *maturity*, which stock
//! Bitcoin enforces at tx-acceptance, not inside the script interpreter) are called out
//! below. For production-grade verification, run the same transactions through
//! `bitcoinconsensus` / a full node; this module exists so the crate's tests are
//! self-contained and offline.

use bitcoin::opcodes::all as op;
use bitcoin::script::Instruction;
use bitcoin::secp256k1::{ecdsa, Message, PublicKey as SecpPubkey, Secp256k1, Verification};
use bitcoin::{ScriptBuf, Sequence};

/// The transaction-level facts the evaluator needs (what a node would know when checking
/// the spend). `sighash` is the precomputed BIP-143 P2WSH sighash for this input.
pub struct EvalCtx {
    /// The spending input's `nSequence` (carries the BIP-68 relative timelock, if any).
    pub input_sequence: Sequence,
    /// Confirmations elapsed on the spent output (used to model BIP-68 maturity).
    pub confirmations: u32,
    /// The spending transaction's version (CSV requires v2).
    pub tx_version: i32,
    /// The BIP-143 P2WSH sighash this input's signatures sign.
    pub sighash: [u8; 32],
}

/// Why a spend evaluation failed (fail-closed; distinct causes so tests can assert the
/// exact reason).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvalError {
    /// `OP_EQUALVERIFY` failed — e.g. a wrong preimage (`SHA256(r) != H(r)`).
    EqualVerifyFailed,
    /// `OP_CSV` disabled or the input's `nSequence` does not encode a ≥ Δ relative lock.
    CsvUnsatisfied,
    /// CSV present and encoded, but not yet matured (confirmations < Δ) — BIP-68.
    Immature,
    /// An opcode this narrow evaluator does not implement appeared.
    Unsupported(u8),
    /// Malformed script / stack underflow / bad push.
    ScriptError,
}

/// Evaluate `witness_script` with `initial_stack` (bottom→top, i.e. the P2WSH witness
/// items minus the script itself) under `ctx`. Returns `Ok(true)` iff the script leaves a
/// truthy value on top and every gate (hash-lock, CHECKSIG, CSV+maturity) passed.
pub fn eval<C: Verification>(
    secp: &Secp256k1<C>,
    witness_script: &ScriptBuf,
    initial_stack: Vec<Vec<u8>>,
    ctx: &EvalCtx,
) -> Result<bool, EvalError> {
    let mut stack: Vec<Vec<u8>> = initial_stack;
    // Conditional-execution stack (OP_IF/ELSE/ENDIF). `exec()` is the AND of all frames.
    let mut cond: Vec<bool> = Vec::new();
    let executing = |cond: &[bool]| cond.iter().all(|&b| b);

    for ins in witness_script.instructions() {
        let ins = ins.map_err(|_| EvalError::ScriptError)?;
        match ins {
            Instruction::PushBytes(pb) => {
                if executing(&cond) {
                    stack.push(pb.as_bytes().to_vec());
                }
            }
            Instruction::Op(o) => {
                let code = o.to_u8();
                // Flow-control opcodes must run even inside a non-executing branch.
                if o == op::OP_IF {
                    let take = if executing(&cond) {
                        cast_bool(&stack.pop().ok_or(EvalError::ScriptError)?)
                    } else {
                        false
                    };
                    cond.push(take);
                    continue;
                }
                if o == op::OP_ELSE {
                    let last = cond.last_mut().ok_or(EvalError::ScriptError)?;
                    *last = !*last;
                    continue;
                }
                if o == op::OP_ENDIF {
                    cond.pop().ok_or(EvalError::ScriptError)?;
                    continue;
                }
                if !executing(&cond) {
                    continue;
                }
                // Executing, non-flow opcodes:
                if o == op::OP_DROP {
                    stack.pop().ok_or(EvalError::ScriptError)?;
                } else if o == op::OP_SHA256 {
                    use sha2::{Digest, Sha256};
                    let top = stack.pop().ok_or(EvalError::ScriptError)?;
                    stack.push(Sha256::digest(&top).to_vec());
                } else if o == op::OP_EQUALVERIFY {
                    let a = stack.pop().ok_or(EvalError::ScriptError)?;
                    let b = stack.pop().ok_or(EvalError::ScriptError)?;
                    if a != b {
                        return Err(EvalError::EqualVerifyFailed);
                    }
                } else if o == op::OP_EQUAL {
                    let a = stack.pop().ok_or(EvalError::ScriptError)?;
                    let b = stack.pop().ok_or(EvalError::ScriptError)?;
                    stack.push(if a == b { vec![1] } else { vec![] });
                } else if o == op::OP_CHECKSIG {
                    let pk = stack.pop().ok_or(EvalError::ScriptError)?;
                    let sig = stack.pop().ok_or(EvalError::ScriptError)?;
                    stack.push(if check_ecdsa(secp, &ctx.sighash, &pk, &sig) {
                        vec![1]
                    } else {
                        vec![]
                    });
                } else if o == op::OP_CSV {
                    // BIP-112: read (do NOT pop) the required relative locktime, check it
                    // against the input's nSequence, then (BIP-68 maturity) confirmations.
                    let required = decode_scriptnum(stack.last().ok_or(EvalError::ScriptError)?);
                    check_csv(required, ctx)?;
                } else if (0x51..=0x60).contains(&code) {
                    // OP_PUSHNUM_1 ..= OP_PUSHNUM_16 → push scriptnum N.
                    stack.push(vec![code - 0x50]);
                } else if code == 0x00 {
                    // OP_0 / OP_PUSHBYTES_0 → push empty.
                    stack.push(vec![]);
                } else {
                    return Err(EvalError::Unsupported(code));
                }
            }
        }
    }
    Ok(stack.last().map(|v| cast_bool(v)).unwrap_or(false))
}

/// BIP-112 (in-script) + BIP-68 (maturity) check for a block-based relative timelock.
fn check_csv(required: i64, ctx: &EvalCtx) -> Result<(), EvalError> {
    if required < 0 {
        return Err(EvalError::CsvUnsatisfied);
    }
    // CSV requires tx version >= 2.
    if ctx.tx_version < 2 {
        return Err(EvalError::CsvUnsatisfied);
    }
    let seq = ctx.input_sequence.to_consensus_u32();
    // Disable bit (1<<31) set ⇒ relative locktime not enforced ⇒ CSV fails.
    if seq & 0x8000_0000 != 0 {
        return Err(EvalError::CsvUnsatisfied);
    }
    // Type bit (1<<22): must be BLOCK-based (clear) to match a block-based `required`.
    if seq & 0x0040_0000 != 0 {
        return Err(EvalError::CsvUnsatisfied);
    }
    let seq_blocks = (seq & 0x0000_ffff) as i64;
    if seq_blocks < required {
        return Err(EvalError::CsvUnsatisfied);
    }
    // BIP-68 maturity — enforced by the network at tx acceptance, modelled here so a
    // pre-Δ spend is rejected and a post-Δ one accepted.
    if (ctx.confirmations as i64) < required {
        return Err(EvalError::Immature);
    }
    Ok(())
}

/// Real secp256k1 ECDSA verification of a Bitcoin `<DER-sig ‖ sighash_type>` push against
/// a 33-byte compressed pubkey, over the given sighash.
fn check_ecdsa<C: Verification>(
    secp: &Secp256k1<C>,
    sighash: &[u8; 32],
    pk_bytes: &[u8],
    sig_bytes: &[u8],
) -> bool {
    if sig_bytes.is_empty() {
        return false;
    }
    // strip the trailing sighash-type byte
    let der = &sig_bytes[..sig_bytes.len() - 1];
    let sig = match ecdsa::Signature::from_der(der) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let pk = match SecpPubkey::from_slice(pk_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let msg = Message::from_digest(*sighash);
    secp.verify_ecdsa(&msg, &sig, &pk).is_ok()
}

/// Minimal Bitcoin `CScriptNum` (little-endian, sign-magnitude) decode — enough for the
/// small non-negative Δ values the vault uses.
fn decode_scriptnum(b: &[u8]) -> i64 {
    if b.is_empty() {
        return 0;
    }
    let mut acc: i64 = 0;
    for (i, &byte) in b.iter().enumerate() {
        acc |= (byte as i64) << (8 * i);
    }
    if b[b.len() - 1] & 0x80 != 0 {
        let neg = acc & !(0x80i64 << (8 * (b.len() - 1)));
        -neg
    } else {
        acc
    }
}

/// Bitcoin truthiness: empty or all-zero (allowing a single 0x80 sign byte) is false.
fn cast_bool(b: &[u8]) -> bool {
    for (i, &byte) in b.iter().enumerate() {
        if byte != 0 {
            if i == b.len() - 1 && byte == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}
