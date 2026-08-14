//! # bloch-euvm — deterministic eUTXO validator VM (FOUNDATION, step 1)
//!
//! > **Genesis-3-era crate.** This was designed and built for the
//! > proof-of-work chain, which stopped permanently at height 39,918 on
//! > 2026-08-13. The live chain is **Genesis-4, proof of stake** (30 s slots,
//! > 32-slot epochs, finality by epoch; consensus in
//! > `crates/bloch-pos-committee`), and this VM is **not wired into it**. The
//! > direction for contracts at L1 has since moved to an EVM
//! > (`docs/adr/ADR-040-evm-and-ustav-at-l1.md`), for which no code exists
//! > yet. Kept buildable for audit. Read every present-tense sentence below
//! > about "the chain" as describing Genesis-3.
//!
//! This is the first, self-contained increment of the native contract VM designed
//! in the validators/BaaS study (§5-quater). It is a **deterministic, gas-metered
//! stack machine** that runs a *validator* program to decide whether an extended
//! UTXO (an output carrying a `validator_hash` + `datum`) may be spent.
//!
//! Scope of this increment — and its honest limits:
//! - **NOT wired into node consensus.** It is a standalone library with tests only.
//!   Nothing here validates or produces real Bloch blocks yet.
//! - **Deterministic by construction:** `i128` checked arithmetic (no float, no
//!   overflow-wraps), no I/O, no clock, no allocation-dependent behaviour. Every
//!   node running the same program on the same inputs gets the same result — the
//!   property a consensus VM must have.
//! - **Gas-metered:** every op costs gas from a caller-set budget; a runaway program
//!   aborts at the ceiling (DoS bound).
//! - **Post-quantum signature verification is a HOST callback** ([`SigVerifier`]),
//!   so the VM stays pure and testable; the real ML-DSA-65‖Falcon-1024 verifier
//!   (from `bloch-crypto`) plugs in later without changing the VM.
//!
//! What it already demonstrates (see tests): a P2PKH validator (the current fixed
//! script as a trivial contract), an n-of-m multisig validator (the bridge custody
//! gap, §5-ter), and a hash-lock validator (the HTLC/atomic-swap primitive).

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// A value on the VM stack. Integers are bounded `i128` (checked); byte strings
/// are opaque blobs (pubkeys, hashes, signatures, preimages).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Val {
    Int(i128),
    Bytes(Vec<u8>),
}

impl Val {
    fn truthy(&self) -> Result<bool, VmError> {
        match self {
            Val::Int(n) => Ok(*n != 0),
            Val::Bytes(_) => Err(VmError::TypeError("expected Int for truthiness")),
        }
    }
}

/// A native-asset identifier (step 4). The base coin BLCH is the all-zero id;
/// every other token is its own 32-byte id (e.g. the hash of its minting policy).
pub type AssetId = [u8; 32];
/// The base coin BLCH.
pub const BLCH: AssetId = [0u8; 32];

/// A **multi-asset value** (step 4) — a deterministic bundle `asset_id -> amount`,
/// exactly like the eUTXO native-asset model. `BTreeMap` keeps ordering canonical.
pub type Value = std::collections::BTreeMap<AssetId, u64>;

/// Convenience: a value of `n` BLCH and nothing else.
pub fn blch(n: u64) -> Value {
    let mut v = Value::new();
    if n > 0 {
        v.insert(BLCH, n);
    }
    v
}
/// Amount of `asset` in `v` (0 if absent).
pub fn value_get(v: &Value, asset: &AssetId) -> u64 {
    *v.get(asset).unwrap_or(&0)
}

/// An **extended UTXO** output (step 2, multi-asset in step 4): a multi-asset
/// `value`, the hash of the validator that guards it, and its `datum` (local
/// contract state). Spending it requires revealing a validator program that hashes
/// to `validator_hash` and returns true.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtOutput {
    pub value: Value,
    pub validator_hash: [u8; 32],
    pub datum: Val,
}

/// The transaction context a validator may read (a minimal, deterministic view).
/// `fields` is generic scratch (sighash, totals...); `tx_outputs` lets a validator
/// inspect what the spending transaction creates — the mechanism behind stateful
/// contracts (a pool that must recreate itself, §5-quater). `self_validator_hash`
/// is the hash of the output being spent, so a contract can require continuation.
#[derive(Clone, Debug, Default)]
pub struct Ctx {
    pub fields: Vec<Val>,
    pub tx_outputs: Vec<ExtOutput>,
    pub self_validator_hash: [u8; 32],
    /// The multi-asset value of the output being spent (its own reserves).
    pub self_value: Value,
}

/// Host-provided signature verification. Kept outside the VM so the machine stays
/// pure/deterministic and unit-testable; production plugs the real verifiers in.
pub trait SigVerifier {
    /// Verify a post-quantum `sig` (hybrid ML-DSA-65 ‖ Falcon-1024) over `msg` under
    /// `pubkey`. MUST be deterministic.
    fn verify(&self, msg: &[u8], pubkey: &[u8], sig: &[u8]) -> bool;
    /// Verify a **secp256k1 ECDSA** `sig` (the Bitcoin curve) over `msg` under
    /// `pubkey`. Enables hybrid BTC-key + PQ-key validators (wBTC-PQ, §5-sexies).
    /// Default returns false so verifiers that only do PQ are unaffected.
    fn verify_ecdsa(&self, _msg: &[u8], _pubkey: &[u8], _sig: &[u8]) -> bool {
        false
    }
}

/// The instruction set (minimal but real: arithmetic, comparison, hashing, context,
/// signatures, and assertion — enough for P2PKH, multisig, and hash-locks).
#[derive(Clone, Debug)]
pub enum Op {
    PushInt(i128),
    PushBytes(Vec<u8>),
    Dup,
    Drop,
    Swap,
    /// **Assert the stack is exactly `n` deep**, without consuming anything.
    ///
    /// This exists because every fixed-offset [`Op::Pick`] in a compiled program is
    /// *top-relative*, while the values it means to read (the datum, a specific
    /// redeemer slot) sit at fixed positions from the **bottom**. `spend()` seeds the
    /// stack `[datum] ++ redeemer` and imposes no length check, so a spender who pads
    /// the redeemer with one extra leading value shifts every `Pick` offset by one and
    /// the program silently reads an attacker-controlled slot instead of the one it
    /// was compiled to read. That is not a bug in one module: it is a property of
    /// top-relative addressing with an unconstrained seed, and it defeated the
    /// TransferPolicy freeze gate (proven by `tests/audit_modules.rs`).
    ///
    /// Pinning the depth turns the assumption into a checked precondition. Emitted as
    /// the first op of every compiled module, so a padded redeemer aborts before any
    /// `Pick` runs, fail-closed. Because the assertion is *inside the program*, it is
    /// part of [`validator_hash`] — the arity a validator was compiled for is part of
    /// its identity and cannot be renegotiated by the spender.
    ExpectDepth(u8),
    /// Copy the element `n` positions below the top to the top (`Pick(0)` == `Dup`).
    /// Like Bitcoin's `OP_PICK` — lets a validator reach redeemer values that sit
    /// under the datum (e.g. a pubkey/signature pair) without consuming them.
    Pick(u8),
    Add,
    Sub,
    Mul,
    Eq,
    Lt,
    Not,
    /// SHA-256d (double SHA-256) of top bytes -> 32 bytes.
    Sha256d,
    /// SHAKE-256 XOF, 32-byte read, of top bytes -> 32 bytes.
    Shake256,
    /// len of top bytes -> Int.
    Size,
    /// push `ctx.fields[i]`.
    CtxField(u8),
    /// pop sig, pop pubkey, pop msg; push Int(1) if the host verifier accepts, else 0.
    VerifySig,
    /// Like [`Op::VerifySig`] but verifies a **secp256k1 ECDSA** (Bitcoin) signature
    /// via `SigVerifier::verify_ecdsa`. Enables hybrid BTC-key + PQ-key validators.
    VerifyEcdsa,
    /// pop top; if not truthy, abort with [`VmError::Assert`].
    Verify,
    /// push `ctx.tx_outputs[i].datum` (the state of the i-th created output).
    TxOutDatum(u8),
    /// push `ctx.tx_outputs[i].validator_hash` as Bytes.
    TxOutValidator(u8),
    /// push `ctx.tx_outputs[i].value[BLCH]` as Int (the output's BLCH amount).
    TxOutValue(u8),
    /// push the hash of the output being spent (for continuation checks).
    SelfValidator,
    /// pop an asset id (Bytes); push the amount of that asset in the SPENT output's
    /// value (the contract's own reserves) — step 4.
    SelfAsset,
    /// pop an asset id (Bytes); push the amount of that asset in `tx_outputs[i]`.
    TxOutAsset(u8),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VmError {
    OutOfGas,
    StackUnderflow,
    StackTooDeep,
    TypeError(&'static str),
    Overflow,
    BadCtxField(u8),
    BadTxOut(u8),
    ValidatorHashMismatch,
    Assert,
    EmptyResult,
    /// The live stack's total byte size exceeded [`MAX_TOTAL_BYTES`] (F2 memory ceiling).
    /// Fail-closed: a program that amplifies memory (e.g. `Dup` on a large blob) aborts
    /// deterministically instead of letting per-node RAM limits decide acceptance.
    MemoryLimitExceeded,
    /// A single `Bytes` operand exceeded [`MAX_OPERAND_BYTES`] (F2 per-operand ceiling).
    OperandTooLarge,
    /// The program had more ops than [`MAX_PROGRAM_OPS`] (F2 per-program ceiling).
    ProgramTooLarge,
}

/// **Static base cost of an op** — the length-INDEPENDENT part of its gas price.
/// Signature checks dominate real cost; hashing is mid; stack ops are cheap.
///
/// F2: this is only the *base*. The real charge in [`run`] is
/// [`op_gas`]`(op, stack)` = this base **plus** a term proportional to the operand's
/// byte length for every op that copies or hashes bytes (`PushBytes`, `Dup`, `Pick`,
/// `Sha256d`, `Shake256`, `Size`). A flat schedule let a 1-byte and an 8-MB hash both
/// cost 60 gas — gas then bounded neither CPU nor memory (machine-dependent block
/// acceptance = consensus split). Charging ∝ bytes restores that bound deterministically.
pub fn gas_cost(op: &Op) -> u64 {
    match op {
        Op::VerifySig | Op::VerifyEcdsa => 1000,
        Op::Sha256d | Op::Shake256 => 60,
        Op::Mul | Op::Add | Op::Sub => 4,
        _ => 1,
    }
}

/// Number of 32-byte words spanning `len` bytes (ceiling division). The unit the
/// byte-proportional gas term is charged in — deterministic, overflow-free for any
/// `len <= MAX_OPERAND_BYTES`.
#[inline]
fn words(len: u64) -> u64 {
    len / 32 + if len % 32 != 0 { 1 } else { 0 }
}

/// **The real, length-proportional gas cost of `op` given the current `stack`** (F2).
/// Base [`gas_cost`] plus one gas per 32-byte word of the operand the op copies or
/// hashes. Deterministic function of byte length only; never panics; saturating so an
/// (already ceiling-bounded) operand can never overflow the charge.
fn op_gas(op: &Op, stack: &[Val]) -> u64 {
    let top_len = || -> u64 {
        match stack.last() {
            Some(Val::Bytes(b)) => b.len() as u64,
            _ => 0,
        }
    };
    match op {
        Op::PushBytes(b) => 1u64.saturating_add(words(b.len() as u64)),
        Op::Dup => 1u64.saturating_add(words(top_len())),
        Op::Pick(n) => {
            let l = stack
                .len()
                .checked_sub(1 + *n as usize)
                .and_then(|i| stack.get(i))
                .map(|v| match v {
                    Val::Bytes(b) => b.len() as u64,
                    _ => 0,
                })
                .unwrap_or(0);
            1u64.saturating_add(words(l))
        }
        Op::Sha256d | Op::Shake256 => 60u64.saturating_add(words(top_len())),
        Op::Size => 1u64.saturating_add(words(top_len())),
        _ => gas_cost(op),
    }
}

const MAX_STACK: usize = 1024;

/// **F2 hard ceilings — memory/size bounds enforced fail-closed inside [`run`].**
///
/// Max byte length of any single `Bytes` operand. Bigger operands → [`VmError::OperandTooLarge`].
pub const MAX_OPERAND_BYTES: usize = 16 * 1024 * 1024; // 16 MiB
/// Max number of ops in a validator program. Bigger → [`VmError::ProgramTooLarge`].
pub const MAX_PROGRAM_OPS: usize = 100_000;
/// Max total live-stack byte size at any point during execution — the memory ceiling.
/// Exceeding it (e.g. via `Dup`-amplification) → [`VmError::MemoryLimitExceeded`].
pub const MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024; // 32 MiB

/// **F2 tx-level structural ceilings** (enforced by [`check_tx_resource_limits`],
/// BEFORE the unmetered conservation scan and the per-input `ctx.clone`).
pub const MAX_TX_INPUTS: usize = 1024;
/// Max outputs per transaction.
pub const MAX_TX_OUTPUTS: usize = 1024;
/// Max distinct assets referenced across a transaction's inputs + outputs (and the max
/// entries in any single multi-asset `Value`).
pub const MAX_TX_DISTINCT_ASSETS: usize = 4096;
/// Max total operand bytes carried by a transaction (datums + value maps + programs +
/// redeemers) — bounds the O(#in · #out · output_size) `ctx.clone` work.
pub const MAX_TX_BYTES: usize = 1024 * 1024; // 1 MiB

/// Sum of the live-stack's `Bytes` byte lengths (saturating). O(stack depth), and
/// `MAX_STACK` bounds the depth, so this is a bounded, deterministic scan.
#[inline]
fn stack_heap_bytes(stack: &[Val]) -> usize {
    let mut total: usize = 0;
    for v in stack {
        if let Val::Bytes(b) = v {
            total = total.saturating_add(b.len());
        }
    }
    total
}

/// Run a validator `program`. The stack is seeded with `initial` (bottom → top),
/// typically `[datum, redeemer...]`. Returns `true` iff execution finishes with a
/// truthy `Int` on top of a non-empty stack. Consumes gas from `gas`.
pub fn run(
    program: &[Op],
    initial: Vec<Val>,
    ctx: &Ctx,
    verifier: &dyn SigVerifier,
    gas: &mut u64,
) -> Result<bool, VmError> {
    let mut st: Vec<Val> = initial;
    if st.len() > MAX_STACK {
        return Err(VmError::StackTooDeep);
    }

    // ── F2 ceilings, enforced fail-closed BEFORE any execution ──
    // Per-program op count.
    if program.len() > MAX_PROGRAM_OPS {
        return Err(VmError::ProgramTooLarge);
    }
    // Per-operand byte cap: every literal in the program and every seeded stack value.
    for op in program {
        if let Op::PushBytes(b) = op {
            if b.len() > MAX_OPERAND_BYTES {
                return Err(VmError::OperandTooLarge);
            }
        }
    }
    for v in &st {
        if let Val::Bytes(b) = v {
            if b.len() > MAX_OPERAND_BYTES {
                return Err(VmError::OperandTooLarge);
            }
        }
    }
    // Total-allocated-bytes (memory) ceiling on the seeded stack.
    if stack_heap_bytes(&st) > MAX_TOTAL_BYTES {
        return Err(VmError::MemoryLimitExceeded);
    }

    macro_rules! pop {
        () => {
            st.pop().ok_or(VmError::StackUnderflow)?
        };
    }
    fn as_int(v: Val) -> Result<i128, VmError> {
        match v {
            Val::Int(n) => Ok(n),
            Val::Bytes(_) => Err(VmError::TypeError("expected Int")),
        }
    }
    fn as_bytes(v: Val) -> Result<Vec<u8>, VmError> {
        match v {
            Val::Bytes(b) => Ok(b),
            Val::Int(_) => Err(VmError::TypeError("expected Bytes")),
        }
    }
    fn as_asset(b: Vec<u8>) -> Result<AssetId, VmError> {
        b.as_slice()
            .try_into()
            .map_err(|_| VmError::TypeError("asset id must be 32 bytes"))
    }

    for op in program {
        // F2: gas is a deterministic function of OPERAND BYTE LENGTH, not a flat per-op
        // constant. Charged up-front (before the op runs) from the current stack.
        let cost = op_gas(op, &st);
        *gas = gas.checked_sub(cost).ok_or(VmError::OutOfGas)?;

        match op {
            Op::PushInt(n) => st.push(Val::Int(*n)),
            Op::PushBytes(b) => st.push(Val::Bytes(b.clone())),
            Op::Dup => {
                let top = st.last().ok_or(VmError::StackUnderflow)?.clone();
                st.push(top);
            }
            Op::Drop => {
                pop!();
            }
            Op::Swap => {
                let a = pop!();
                let b = pop!();
                st.push(a);
                st.push(b);
            }
            Op::ExpectDepth(n) => {
                if st.len() != *n as usize {
                    return Err(VmError::Assert);
                }
            }
            Op::Pick(n) => {
                let idx = st.len().checked_sub(1 + *n as usize).ok_or(VmError::StackUnderflow)?;
                let v = st[idx].clone();
                st.push(v);
            }
            Op::Add => {
                let b = as_int(pop!())?;
                let a = as_int(pop!())?;
                st.push(Val::Int(a.checked_add(b).ok_or(VmError::Overflow)?));
            }
            Op::Sub => {
                let b = as_int(pop!())?;
                let a = as_int(pop!())?;
                st.push(Val::Int(a.checked_sub(b).ok_or(VmError::Overflow)?));
            }
            Op::Mul => {
                let b = as_int(pop!())?;
                let a = as_int(pop!())?;
                st.push(Val::Int(a.checked_mul(b).ok_or(VmError::Overflow)?));
            }
            Op::Eq => {
                let b = pop!();
                let a = pop!();
                st.push(Val::Int((a == b) as i128));
            }
            Op::Lt => {
                let b = as_int(pop!())?;
                let a = as_int(pop!())?;
                st.push(Val::Int((a < b) as i128));
            }
            Op::Not => {
                let a = as_int(pop!())?;
                st.push(Val::Int((a == 0) as i128));
            }
            Op::Sha256d => {
                let b = as_bytes(pop!())?;
                let once = Sha256::digest(&b);
                let twice = Sha256::digest(once);
                st.push(Val::Bytes(twice.to_vec()));
            }
            Op::Shake256 => {
                let b = as_bytes(pop!())?;
                let mut h = Shake256::default();
                h.update(&b);
                let mut r = h.finalize_xof();
                let mut out = [0u8; 32];
                r.read(&mut out);
                st.push(Val::Bytes(out.to_vec()));
            }
            Op::Size => {
                let b = as_bytes(pop!())?;
                st.push(Val::Int(b.len() as i128));
            }
            Op::CtxField(i) => {
                let v = ctx
                    .fields
                    .get(*i as usize)
                    .ok_or(VmError::BadCtxField(*i))?
                    .clone();
                st.push(v);
            }
            Op::VerifySig => {
                let sig = as_bytes(pop!())?;
                let pk = as_bytes(pop!())?;
                let msg = as_bytes(pop!())?;
                st.push(Val::Int(verifier.verify(&msg, &pk, &sig) as i128));
            }
            Op::VerifyEcdsa => {
                let sig = as_bytes(pop!())?;
                let pk = as_bytes(pop!())?;
                let msg = as_bytes(pop!())?;
                st.push(Val::Int(verifier.verify_ecdsa(&msg, &pk, &sig) as i128));
            }
            Op::Verify => {
                let top = pop!();
                if !top.truthy()? {
                    return Err(VmError::Assert);
                }
            }
            Op::TxOutDatum(i) => {
                let o = ctx.tx_outputs.get(*i as usize).ok_or(VmError::BadTxOut(*i))?;
                st.push(o.datum.clone());
            }
            Op::TxOutValidator(i) => {
                let o = ctx.tx_outputs.get(*i as usize).ok_or(VmError::BadTxOut(*i))?;
                st.push(Val::Bytes(o.validator_hash.to_vec()));
            }
            Op::TxOutValue(i) => {
                let o = ctx.tx_outputs.get(*i as usize).ok_or(VmError::BadTxOut(*i))?;
                st.push(Val::Int(value_get(&o.value, &BLCH) as i128));
            }
            Op::SelfValidator => {
                st.push(Val::Bytes(ctx.self_validator_hash.to_vec()));
            }
            Op::SelfAsset => {
                let asset = as_asset(as_bytes(pop!())?)?;
                st.push(Val::Int(value_get(&ctx.self_value, &asset) as i128));
            }
            Op::TxOutAsset(i) => {
                let asset = as_asset(as_bytes(pop!())?)?;
                let o = ctx.tx_outputs.get(*i as usize).ok_or(VmError::BadTxOut(*i))?;
                st.push(Val::Int(value_get(&o.value, &asset) as i128));
            }
        }
        if st.len() > MAX_STACK {
            return Err(VmError::StackTooDeep);
        }
        // F2 memory ceiling: catch operand-size amplification (e.g. `Dup` cloning a
        // large blob) the instant it crosses the bound — fail-closed, deterministic.
        if stack_heap_bytes(&st) > MAX_TOTAL_BYTES {
            return Err(VmError::MemoryLimitExceeded);
        }
    }

    st.last().ok_or(VmError::EmptyResult)?.truthy()
}

/// Canonical, deterministic byte encoding of a validator program — the preimage of
/// its [`validator_hash`]. Tag byte per op + length-prefixed operands; two programs
/// encode equal iff they are the same instruction sequence.
pub fn encode_program(program: &[Op]) -> Vec<u8> {
    let mut o = Vec::new();
    fn put_bytes(o: &mut Vec<u8>, b: &[u8]) {
        o.extend_from_slice(&(b.len() as u32).to_le_bytes());
        o.extend_from_slice(b);
    }
    for op in program {
        match op {
            Op::PushInt(n) => { o.push(0x01); o.extend_from_slice(&n.to_le_bytes()); }
            Op::PushBytes(b) => { o.push(0x02); put_bytes(&mut o, b); }
            Op::Dup => o.push(0x10),
            Op::Drop => o.push(0x11),
            Op::Swap => o.push(0x12),
            Op::Pick(n) => { o.push(0x13); o.push(*n); }
            Op::ExpectDepth(n) => { o.push(0x14); o.push(*n); }
            Op::Add => o.push(0x20),
            Op::Sub => o.push(0x21),
            Op::Mul => o.push(0x22),
            Op::Eq => o.push(0x30),
            Op::Lt => o.push(0x31),
            Op::Not => o.push(0x32),
            Op::Sha256d => o.push(0x40),
            Op::Shake256 => o.push(0x41),
            Op::Size => o.push(0x42),
            Op::CtxField(i) => { o.push(0x50); o.push(*i); }
            Op::VerifySig => o.push(0x60),
            Op::VerifyEcdsa => o.push(0x62),
            Op::Verify => o.push(0x61),
            Op::TxOutDatum(i) => { o.push(0x70); o.push(*i); }
            Op::TxOutValidator(i) => { o.push(0x71); o.push(*i); }
            Op::TxOutValue(i) => { o.push(0x72); o.push(*i); }
            Op::SelfValidator => o.push(0x73),
            Op::SelfAsset => o.push(0x74),
            Op::TxOutAsset(i) => { o.push(0x75); o.push(*i); }
        }
    }
    o
}

/// The validator's identity: `SHA-256d(encode_program(program))`. This is what an
/// [`ExtOutput::validator_hash`] commits to; the spender must reveal a program that
/// reproduces it.
pub fn validator_hash(program: &[Op]) -> [u8; 32] {
    let d = Sha256::digest(Sha256::digest(encode_program(program)));
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// **The spend model (step 2).** To spend `output`, the spender reveals `program`
/// (which MUST hash to `output.validator_hash`) and supplies `redeemer` values. The
/// VM runs with the stack seeded `[datum, redeemer...]` and `ctx.self_validator_hash`
/// set to this output's hash; the spend is authorized iff the validator returns
/// true. This binds the program to the output and lets the contract inspect what the
/// spending transaction creates (`ctx.tx_outputs`) — the basis for stateful contracts.
pub fn spend(
    output: &ExtOutput,
    program: &[Op],
    redeemer: Vec<Val>,
    ctx: &Ctx,
    verifier: &dyn SigVerifier,
    gas: &mut u64,
) -> Result<bool, VmError> {
    if validator_hash(program) != output.validator_hash {
        return Err(VmError::ValidatorHashMismatch);
    }
    let mut ctx = ctx.clone();
    ctx.self_validator_hash = output.validator_hash;
    ctx.self_value = output.value.clone();
    let mut initial = Vec::with_capacity(1 + redeemer.len());
    initial.push(output.datum.clone());
    initial.extend(redeemer);
    run(program, initial, &ctx, verifier, gas)
}

// ── Step 3: transaction-level validation (the shape of the block-acceptance hook) ──
//
// This is the layer that WOULD plug into the node's `accept_block` — but it lives
// here, isolated and tested, and is NOT wired into live consensus. It enforces:
//   (1) native-value conservation (no inflation/loss),
//   (2) every input's validator authorizes the spend (seeing the whole tx),
//   (3) a gas budget shared across the tx (and a block-level ceiling) — the DoS bound.

/// One spent eUTXO in a transaction: the output being consumed, the revealed
/// validator program (must hash to `prev_output.validator_hash`), and its redeemer.
#[derive(Clone, Debug)]
pub struct EuTxInput {
    pub prev_output: ExtOutput,
    pub validator: Vec<Op>,
    pub redeemer: Vec<Val>,
}

/// A minimal eUTXO transaction: inputs consumed, outputs created, a fee, and the
/// sighash message signature-validators check (exposed as `ctx.fields[0]`).
#[derive(Clone, Debug)]
pub struct EuTx {
    pub inputs: Vec<EuTxInput>,
    pub outputs: Vec<ExtOutput>,
    pub fee: u64,
    pub sighash: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxError {
    ValueNotConserved { asset: AssetId, in_sum: u128, out_plus_fee: u128 },
    ValidatorRejected(usize),
    Vm(usize, VmError),
    OutOfBlockGas,
    /// The transaction exceeded a hard structural resource ceiling (F2): too many
    /// inputs/outputs, too many distinct assets, or too large a total operand size.
    /// The pre-VM conservation scan and the per-input `ctx.clone` are O(#assets ·
    /// (#in+#out)) and O(#in · #out · output_size) respectively and run BEFORE any gas
    /// is charged; without a ceiling that work is unbounded and unmetered (machine-
    /// dependent = consensus split). `what` names the ceiling that fired. Fail-closed.
    ResourceLimit { what: &'static str },
}

/// Bytes of operand data a single [`ExtOutput`] carries (value map + datum) — the
/// quantity `ctx.clone` copies per input. Saturating; deterministic.
fn ext_output_bytes(o: &ExtOutput) -> usize {
    let mut n = o.value.len().saturating_mul(40); // (32-byte id + 8-byte amount) per asset
    n = n.saturating_add(match &o.datum {
        Val::Int(_) => 16,
        Val::Bytes(b) => b.len(),
    });
    n
}

/// **F2 structural resource ceilings for a transaction — enforced BEFORE the unmetered
/// conservation scan and the per-input `ctx.clone`.** Caps input/output counts, the
/// number of distinct assets (and any single `Value`'s entry count), and the total
/// operand bytes the tx carries. Returns [`TxError::ResourceLimit`] fail-closed on any
/// breach. Bounded work: every check is O(1) per input/output plus a single early-
/// bailing asset-set scan, so this checker cannot itself be a DoS.
///
/// Shared choke point: the mint-aware mirror ([`crate::minting::validate_tx_with_mint`])
/// must call this too, wrapping the error as `MintTxError::Tx(..)`, so both validation
/// paths share one deterministic bound.
pub fn check_tx_resource_limits(tx: &EuTx) -> Result<(), TxError> {
    if tx.inputs.len() > MAX_TX_INPUTS {
        return Err(TxError::ResourceLimit { what: "too many inputs" });
    }
    if tx.outputs.len() > MAX_TX_OUTPUTS {
        return Err(TxError::ResourceLimit { what: "too many outputs" });
    }

    let mut assets: std::collections::BTreeSet<AssetId> = std::collections::BTreeSet::new();
    let mut total_bytes: usize = 0;

    // Inputs: prev_output + revealed validator program + redeemer.
    for i in &tx.inputs {
        if i.prev_output.value.len() > MAX_TX_DISTINCT_ASSETS {
            return Err(TxError::ResourceLimit { what: "value has too many assets" });
        }
        for k in i.prev_output.value.keys() {
            assets.insert(*k);
            if assets.len() > MAX_TX_DISTINCT_ASSETS {
                return Err(TxError::ResourceLimit { what: "too many distinct assets" });
            }
        }
        total_bytes = total_bytes.saturating_add(ext_output_bytes(&i.prev_output));
        if i.validator.len() > MAX_PROGRAM_OPS {
            return Err(TxError::ResourceLimit { what: "validator program too large" });
        }
        for op in &i.validator {
            if let Op::PushBytes(b) = op {
                total_bytes = total_bytes.saturating_add(b.len());
            }
        }
        for r in &i.redeemer {
            if let Val::Bytes(b) = r {
                total_bytes = total_bytes.saturating_add(b.len());
            }
        }
        if total_bytes > MAX_TX_BYTES {
            return Err(TxError::ResourceLimit { what: "transaction operand bytes exceed ceiling" });
        }
    }

    // Outputs: value + datum.
    for o in &tx.outputs {
        if o.value.len() > MAX_TX_DISTINCT_ASSETS {
            return Err(TxError::ResourceLimit { what: "value has too many assets" });
        }
        for k in o.value.keys() {
            assets.insert(*k);
            if assets.len() > MAX_TX_DISTINCT_ASSETS {
                return Err(TxError::ResourceLimit { what: "too many distinct assets" });
            }
        }
        total_bytes = total_bytes.saturating_add(ext_output_bytes(o));
        if total_bytes > MAX_TX_BYTES {
            return Err(TxError::ResourceLimit { what: "transaction operand bytes exceed ceiling" });
        }
    }

    Ok(())
}

/// Validate one eUTXO transaction against a per-tx `gas_limit`. Returns gas used.
pub fn validate_tx(tx: &EuTx, verifier: &dyn SigVerifier, gas_limit: u64) -> Result<u64, TxError> {
    // (0) F2: fail-closed structural ceilings BEFORE the unmetered per-asset scan and
    // the per-input ctx.clone — those are O(#assets·(#in+#out)) / O(#in·#out·size) and
    // run off the gas meter; without this bound the work is machine-dependent.
    check_tx_resource_limits(tx)?;
    // (1) per-asset native-value conservation. The fee is charged in BLCH only;
    // every other asset must balance exactly (no mint/burn without a policy).
    let mut assets: std::collections::BTreeSet<AssetId> = std::collections::BTreeSet::new();
    for i in &tx.inputs {
        assets.extend(i.prev_output.value.keys().copied());
    }
    for o in &tx.outputs {
        assets.extend(o.value.keys().copied());
    }
    assets.insert(BLCH);
    for asset in &assets {
        let in_sum: u128 = tx.inputs.iter().map(|i| value_get(&i.prev_output.value, asset) as u128).sum();
        let out_sum: u128 = tx.outputs.iter().map(|o| value_get(&o.value, asset) as u128).sum();
        let fee = if *asset == BLCH { tx.fee as u128 } else { 0 };
        let out_plus_fee = out_sum + fee;
        if in_sum != out_plus_fee {
            return Err(TxError::ValueNotConserved { asset: *asset, in_sum, out_plus_fee });
        }
    }
    // (2)+(3) run every validator with the whole tx visible, sharing one gas budget
    let ctx = Ctx {
        fields: vec![Val::Bytes(tx.sighash.clone())],
        tx_outputs: tx.outputs.clone(),
        self_validator_hash: [0u8; 32],
        self_value: Value::new(), // spend() sets this per-input
    };
    let mut gas = gas_limit;
    for (i, inp) in tx.inputs.iter().enumerate() {
        match spend(&inp.prev_output, &inp.validator, inp.redeemer.clone(), &ctx, verifier, &mut gas) {
            Ok(true) => {}
            Ok(false) => return Err(TxError::ValidatorRejected(i)),
            Err(e) => return Err(TxError::Vm(i, e)),
        }
    }
    Ok(gas_limit - gas)
}

/// Validate a block's eUTXO transactions under a per-tx and a block-wide gas ceiling.
/// Returns total gas used. This is the block-level DoS bound.
pub fn validate_block(
    txs: &[EuTx],
    verifier: &dyn SigVerifier,
    per_tx_gas: u64,
    block_gas: u64,
) -> Result<u64, (usize, TxError)> {
    let mut total: u64 = 0;
    for (i, tx) in txs.iter().enumerate() {
        let used = validate_tx(tx, verifier, per_tx_gas).map_err(|e| (i, e))?;
        total = total.checked_add(used).ok_or((i, TxError::OutOfBlockGas))?;
        if total > block_gas {
            return Err((i, TxError::OutOfBlockGas));
        }
    }
    Ok(total)
}

/// Fee → burn split (§5-bis, EIP-1559-style): `burn_bps` of the fee is burned
/// (removed from supply), the rest goes to the miner. Returns `(burned, to_miner)`.
pub fn fee_burn(fee: u64, burn_bps: u16) -> (u64, u64) {
    let burned = (fee as u128 * burn_bps.min(10_000) as u128 / 10_000) as u64;
    (burned, fee - burned)
}

// ─────────────────────────────────────────────────────────────────────────────
// Reference/foundation modules (standalone, tests-only, NOT consensus-wired).
pub mod batcher;
pub mod harness;
pub mod kirpich;
pub mod minting;
pub mod modules;
pub mod state;

// Kirpich — the deterministic, fail-closed internal-audit gate over the Ustav charter
// compile path (see [`modules::compile_charter_audited`]). Re-exported for ergonomic use.
pub use kirpich::{kirpich_audit, AuditReport, Finding, Severity};

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    /// A mock verifier that accepts exactly the (msg, pk, sig) triples it was told.
    struct MockVerifier {
        good: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    }
    impl SigVerifier for MockVerifier {
        fn verify(&self, msg: &[u8], pk: &[u8], sig: &[u8]) -> bool {
            self.good.iter().any(|(m, p, s)| m == msg && p == pk && s == sig)
        }
        // ECDSA mock: accept if the sig equals b"ECDSA:" ‖ pk (distinct from PQ path).
        fn verify_ecdsa(&self, _msg: &[u8], pk: &[u8], sig: &[u8]) -> bool {
            let mut e = b"ECDSA:".to_vec();
            e.extend_from_slice(pk);
            sig == e.as_slice()
        }
    }

    /// Hybrid BTC(ECDSA) + Bloch(PQ) 2-of-2 validator: BOTH must verify to spend.
    /// This is the wBTC-PQ guard — a BTC key and a post-quantum key together (§5-sexies).
    #[test]
    fn hybrid_ecdsa_and_pq_validator() {
        let msg = b"sighash".to_vec();
        let btc_pk = b"btc-pubkey".to_vec();
        let pq_pk = b"pq-pubkey".to_vec();
        let pq_sig = b"pq-sig".to_vec();
        let mut btc_sig = b"ECDSA:".to_vec();
        btc_sig.extend_from_slice(&btc_pk);

        // validator: VerifyEcdsa(msg, btc_pk, btc_sig) AND VerifySig(msg, pq_pk, pq_sig)
        let program = vec![
            Op::CtxField(0), Op::PushBytes(btc_pk.clone()), Op::PushBytes(btc_sig.clone()), Op::VerifyEcdsa, Op::Verify,
            Op::CtxField(0), Op::PushBytes(pq_pk.clone()), Op::PushBytes(pq_sig.clone()), Op::VerifySig,
        ];
        let ctx = Ctx { fields: vec![Val::Bytes(msg.clone())], ..Default::default() };
        let v = MockVerifier { good: vec![(msg.clone(), pq_pk.clone(), pq_sig.clone())] };
        let mut g = 5000;
        assert_eq!(run(&program, vec![], &ctx, &v, &mut g), Ok(true)); // both good → spend

        // PQ sig missing → the AND fails
        let v_no_pq = MockVerifier { good: vec![] };
        let mut g2 = 5000;
        assert_eq!(run(&program, vec![], &ctx, &v_no_pq, &mut g2), Ok(false));

        // BTC sig wrong → VerifyEcdsa's assertion fails
        let bad_btc = {
            let mut p = program.clone();
            p[2] = Op::PushBytes(b"wrong".to_vec());
            p
        };
        let mut g3 = 5000;
        assert_eq!(run(&bad_btc, vec![], &ctx, &v, &mut g3), Err(VmError::Assert));
    }

    fn sha256d(b: &[u8]) -> Vec<u8> {
        Sha256::digest(Sha256::digest(b)).to_vec()
    }

    /// P2PKH-as-contract: hash-check the pubkey against the datum, then verify the sig.
    #[test]
    fn p2pkh_validator() {
        let pubkey = b"pubkey-bytes".to_vec();
        let sig = b"sig-bytes".to_vec();
        let msg = b"sighash".to_vec();
        let pkh = sha256d(&pubkey);

        let ctx = Ctx { fields: vec![Val::Bytes(msg.clone())], ..Default::default() };
        let verifier = MockVerifier { good: vec![(msg.clone(), pubkey.clone(), sig.clone())] };

        let program = vec![
            // hash-check: sha256d(pubkey) == datum_pkh
            Op::PushBytes(pubkey.clone()),
            Op::Sha256d,
            Op::PushBytes(pkh.clone()),
            Op::Eq,
            Op::Verify,
            // sig-check: VerifySig(ctx.msg, pubkey, sig)
            Op::CtxField(0),
            Op::PushBytes(pubkey.clone()),
            Op::PushBytes(sig.clone()),
            Op::VerifySig,
        ];
        let mut gas = 10_000;
        assert_eq!(run(&program, vec![], &ctx, &verifier, &mut gas), Ok(true));

        // wrong signature → false result (not an error; the validator just returns 0)
        let bad = MockVerifier { good: vec![] };
        let mut gas2 = 10_000;
        assert_eq!(run(&program, vec![], &ctx, &bad, &mut gas2), Ok(false));

        // tampered pubkey → hash-check assertion fails
        let program_bad = {
            let mut p = program.clone();
            p[0] = Op::PushBytes(b"other-pubkey".to_vec());
            p
        };
        let mut gas3 = 10_000;
        assert_eq!(run(&program_bad, vec![], &ctx, &verifier, &mut gas3), Err(VmError::Assert));
    }

    /// 2-of-3 multisig — the bridge-custody primitive (§5-ter) the fixed script lacks.
    #[test]
    fn multisig_2_of_3() {
        let msg = b"sighash".to_vec();
        let ctx = Ctx { fields: vec![Val::Bytes(msg.clone())], ..Default::default() };
        let (pk1, s1) = (b"pk1".to_vec(), b"s1".to_vec());
        let (pk2, s2) = (b"pk2".to_vec(), b"s2".to_vec());
        let (pk3, s3) = (b"pk3".to_vec(), b"s3".to_vec());

        // program: count = verify1 + verify2 + verify3; require count >= 2  (i.e. not(count < 2))
        let check = |pk: &Vec<u8>, s: &Vec<u8>| {
            vec![Op::CtxField(0), Op::PushBytes(pk.clone()), Op::PushBytes(s.clone()), Op::VerifySig]
        };
        let mut program = vec![Op::PushInt(0)];
        for (pk, s) in [(&pk1, &s1), (&pk2, &s2), (&pk3, &s3)] {
            program.extend(check(pk, s));
            program.push(Op::Add);
        }
        program.push(Op::PushInt(2));
        program.push(Op::Lt); // (count < 2)
        program.push(Op::Not); // (count >= 2)

        // 2 of 3 valid → true
        let v2 = MockVerifier { good: vec![(msg.clone(), pk1.clone(), s1.clone()), (msg.clone(), pk3.clone(), s3.clone())] };
        let mut g = 20_000;
        assert_eq!(run(&program, vec![], &ctx, &v2, &mut g), Ok(true));

        // only 1 valid → false
        let v1 = MockVerifier { good: vec![(msg.clone(), pk2.clone(), s2.clone())] };
        let mut g2 = 20_000;
        assert_eq!(run(&program, vec![], &ctx, &v1, &mut g2), Ok(false));

        // all 3 valid → still true (>=2)
        let v3 = MockVerifier {
            good: vec![
                (msg.clone(), pk1.clone(), s1.clone()),
                (msg.clone(), pk2.clone(), s2.clone()),
                (msg.clone(), pk3.clone(), s3.clone()),
            ],
        };
        let mut g3 = 20_000;
        assert_eq!(run(&program, vec![], &ctx, &v3, &mut g3), Ok(true));
    }

    /// Hash-lock — the HTLC / atomic-swap primitive (§5-quater / §5-quinquies interop).
    #[test]
    fn hashlock_validator() {
        let preimage = b"the-secret-preimage".to_vec();
        let lock = sha256d(&preimage);
        // redeemer supplies the preimage on the stack; datum is the lock hash.
        let program = vec![
            Op::Sha256d,              // hash the preimage on top
            Op::PushBytes(lock.clone()),
            Op::Eq,
        ];
        let noop = MockVerifier { good: vec![] };
        let ctx = Ctx::default();

        let mut g = 1000;
        assert_eq!(run(&program, vec![Val::Bytes(preimage.clone())], &ctx, &noop, &mut g), Ok(true));

        let mut g2 = 1000;
        assert_eq!(run(&program, vec![Val::Bytes(b"wrong".to_vec())], &ctx, &noop, &mut g2), Ok(false));
    }

    /// Gas metering aborts a program that exceeds its budget.
    #[test]
    fn gas_exhaustion() {
        let program = vec![Op::PushBytes(b"x".to_vec()), Op::Sha256d, Op::Sha256d, Op::Sha256d];
        let noop = MockVerifier { good: vec![] };
        let ctx = Ctx::default();
        let mut tiny = 61; // enough for push(1) + one Sha256d(60), not the second
        assert_eq!(run(&program, vec![], &ctx, &noop, &mut tiny), Err(VmError::OutOfGas));
    }

    /// Determinism: same inputs → same result, repeatedly.
    #[test]
    fn deterministic() {
        let program = vec![Op::PushInt(7), Op::PushInt(6), Op::Mul, Op::PushInt(42), Op::Eq];
        let noop = MockVerifier { good: vec![] };
        let ctx = Ctx::default();
        for _ in 0..100 {
            let mut g = 100;
            assert_eq!(run(&program, vec![], &ctx, &noop, &mut g), Ok(true));
        }
    }

    /// Step 2: the spend model binds the revealed program to the output's hash — you
    /// cannot run a different program than the one the output commits to.
    #[test]
    fn spend_binds_program_to_output() {
        let program = vec![Op::PushInt(1)]; // trivial "always true"
        let vh = validator_hash(&program);
        let out = ExtOutput { value: blch(100), validator_hash: vh, datum: Val::Int(0) };
        let noop = MockVerifier { good: vec![] };
        let ctx = Ctx::default();

        let mut g = 100;
        assert_eq!(spend(&out, &program, vec![], &ctx, &noop, &mut g), Ok(true));

        // a DIFFERENT program (even one returning true) is rejected: hash mismatch.
        let other = vec![Op::PushInt(1), Op::PushInt(1), Op::Eq];
        let mut g2 = 100;
        assert_eq!(spend(&out, &other, vec![], &ctx, &noop, &mut g2), Err(VmError::ValidatorHashMismatch));
    }

    /// Step 2: a stateful CONTINUATION contract — a counter spendable only if the
    /// transaction re-creates it (same validator) with `datum + 1`. This is the
    /// exact pattern an AMM pool uses to recreate itself with updated reserves.
    #[test]
    fn continuation_counter_contract() {
        let program = vec![
            Op::TxOutValidator(0),   // [datum, outVH]
            Op::SelfValidator,       // [datum, outVH, selfVH]
            Op::Eq, Op::Verify,      // [datum]   assert continuation (same contract)
            Op::PushInt(1), Op::Add, // [datum+1]
            Op::TxOutDatum(0),       // [datum+1, outDatum]
            Op::Eq,                  // [(datum+1 == outDatum)]
        ];
        let vh = validator_hash(&program);
        let input = ExtOutput { value: blch(10), validator_hash: vh, datum: Val::Int(41) };
        let noop = MockVerifier { good: vec![] };

        // valid continuation: output[0] = same contract, datum 42
        let good = Ctx {
            tx_outputs: vec![ExtOutput { value: blch(10), validator_hash: vh, datum: Val::Int(42) }],
            ..Default::default()
        };
        let mut g = 1000;
        assert_eq!(spend(&input, &program, vec![], &good, &noop, &mut g), Ok(true));

        // wrong increment (43) → false
        let bad = Ctx {
            tx_outputs: vec![ExtOutput { value: blch(10), validator_hash: vh, datum: Val::Int(43) }],
            ..Default::default()
        };
        let mut g2 = 1000;
        assert_eq!(spend(&input, &program, vec![], &bad, &noop, &mut g2), Ok(false));

        // continuation to a DIFFERENT contract → assertion fails (cannot escape)
        let escape = Ctx {
            tx_outputs: vec![ExtOutput { value: blch(10), validator_hash: [9u8; 32], datum: Val::Int(42) }],
            ..Default::default()
        };
        let mut g3 = 1000;
        assert_eq!(spend(&input, &program, vec![], &escape, &noop, &mut g3), Err(VmError::Assert));
    }

    /// `Pick(n)` copies the n-th element below the top (Pick(0)==Dup) — lets a
    /// validator reach redeemer values that sit under the datum.
    #[test]
    fn pick_reaches_under_top() {
        let noop = MockVerifier { good: vec![] };
        let ctx = Ctx::default();
        // seed [10, 20, 30] (top=30); Pick(2) copies 10 → top; check == 10
        let program = vec![Op::Pick(2), Op::PushInt(10), Op::Eq];
        let mut g = 100;
        assert_eq!(
            run(&program, vec![Val::Int(10), Val::Int(20), Val::Int(30)], &ctx, &noop, &mut g),
            Ok(true)
        );
        // Pick(0) == Dup
        let mut g2 = 100;
        assert_eq!(run(&vec![Op::Pick(0), Op::Eq], vec![Val::Int(7)], &ctx, &noop, &mut g2), Ok(true));
        // Pick beyond the stack → underflow
        let mut g3 = 100;
        assert_eq!(run(&vec![Op::Pick(5)], vec![Val::Int(1)], &ctx, &noop, &mut g3), Err(VmError::StackUnderflow));
    }

    /// `validator_hash` is deterministic and distinguishes distinct programs.
    #[test]
    fn validator_hash_stable() {
        let a = vec![Op::PushInt(1), Op::PushInt(2), Op::Add];
        let b = vec![Op::PushInt(1), Op::PushInt(2), Op::Add];
        let c = vec![Op::PushInt(1), Op::PushInt(3), Op::Add];
        assert_eq!(validator_hash(&a), validator_hash(&b));
        assert_ne!(validator_hash(&a), validator_hash(&c));
    }

    // ── Step 3: transaction / block validation ──
    fn anyone_out(value: u64, vh: [u8; 32]) -> ExtOutput {
        ExtOutput { value: blch(value), validator_hash: vh, datum: Val::Int(0) }
    }

    #[test]
    fn tx_conserves_value_and_runs_validators() {
        let anyone = vec![Op::PushInt(1)];
        let vh = validator_hash(&anyone);
        let tx = EuTx {
            inputs: vec![EuTxInput { prev_output: anyone_out(100, vh), validator: anyone.clone(), redeemer: vec![] }],
            outputs: vec![anyone_out(90, vh)],
            fee: 10,
            sighash: b"sh".to_vec(),
        };
        let noop = MockVerifier { good: vec![] };
        assert!(validate_tx(&tx, &noop, 1_000).unwrap() >= 1);
    }

    #[test]
    fn tx_value_not_conserved_rejected() {
        let anyone = vec![Op::PushInt(1)];
        let vh = validator_hash(&anyone);
        let tx = EuTx {
            inputs: vec![EuTxInput { prev_output: anyone_out(100, vh), validator: anyone.clone(), redeemer: vec![] }],
            outputs: vec![anyone_out(90, vh)],
            fee: 5, // 90 + 5 = 95 != 100
            sighash: vec![],
        };
        let noop = MockVerifier { good: vec![] };
        assert_eq!(
            validate_tx(&tx, &noop, 1000),
            Err(TxError::ValueNotConserved { asset: BLCH, in_sum: 100, out_plus_fee: 95 })
        );
    }

    #[test]
    fn tx_validator_rejection() {
        let deny = vec![Op::PushInt(0)];
        let vh = validator_hash(&deny);
        let tx = EuTx {
            inputs: vec![EuTxInput { prev_output: anyone_out(100, vh), validator: deny.clone(), redeemer: vec![] }],
            outputs: vec![anyone_out(100, vh)],
            fee: 0,
            sighash: vec![],
        };
        let noop = MockVerifier { good: vec![] };
        assert_eq!(validate_tx(&tx, &noop, 1000), Err(TxError::ValidatorRejected(0)));
    }

    /// A whole AMM-style transaction: consume the pool eUTXO, re-create it (same
    /// validator) with its datum advanced, value conserved. The tx-level layer runs
    /// the pool validator against the full tx and accepts iff the continuation holds.
    #[test]
    fn amm_style_continuation_tx() {
        let pool = vec![
            Op::TxOutValidator(0), Op::SelfValidator, Op::Eq, Op::Verify,
            Op::PushInt(1), Op::Add, Op::TxOutDatum(0), Op::Eq,
        ];
        let vh = validator_hash(&pool);
        let noop = MockVerifier { good: vec![] };

        let ok_tx = EuTx {
            inputs: vec![EuTxInput { prev_output: ExtOutput { value: blch(1000), validator_hash: vh, datum: Val::Int(41) }, validator: pool.clone(), redeemer: vec![] }],
            outputs: vec![ExtOutput { value: blch(1000), validator_hash: vh, datum: Val::Int(42) }],
            fee: 0,
            sighash: vec![],
        };
        assert!(validate_tx(&ok_tx, &noop, 5000).is_ok());

        let bad_tx = EuTx {
            inputs: ok_tx.inputs.clone(),
            outputs: vec![ExtOutput { value: blch(1000), validator_hash: vh, datum: Val::Int(99) }],
            fee: 0,
            sighash: vec![],
        };
        assert_eq!(validate_tx(&bad_tx, &noop, 5000), Err(TxError::ValidatorRejected(0)));
    }

    #[test]
    fn block_gas_ceiling() {
        let anyone = vec![Op::PushInt(1)];
        let vh = validator_hash(&anyone);
        let mk = || EuTx {
            inputs: vec![EuTxInput { prev_output: anyone_out(10, vh), validator: anyone.clone(), redeemer: vec![] }],
            outputs: vec![anyone_out(10, vh)],
            fee: 0,
            sighash: vec![],
        };
        let noop = MockVerifier { good: vec![] };
        let txs = vec![mk(), mk(), mk()];
        assert!(validate_block(&txs, &noop, 100, 2).is_err());   // 3 txs > block ceiling of 2 gas
        assert!(validate_block(&txs, &noop, 100, 100).is_ok());  // ample ceiling
    }

    #[test]
    fn fee_burn_split() {
        assert_eq!(fee_burn(1000, 5000), (500, 500));  // 50% burned
        assert_eq!(fee_burn(1000, 10_000), (1000, 0)); // all burned
        assert_eq!(fee_burn(1000, 0), (0, 1000));      // none burned
    }

    /// Step 4: a real constant-product AMM. A pool eUTXO holds two native assets
    /// (its reserves). A swap consumes it and re-creates the same contract with new
    /// reserves; the pool validator enforces continuation AND `new_a·new_b ≥
    /// old_a·old_b` — so no transaction may drain the pool. This is Uniswap's core
    /// invariant, native, no bridge, on real assets.
    #[test]
    fn constant_product_amm() {
        const A: AssetId = [1u8; 32];
        const B: AssetId = [2u8; 32];
        let mkval = |pairs: &[(AssetId, u64)]| -> Value { pairs.iter().cloned().collect() };

        let pool = vec![
            Op::TxOutValidator(0), Op::SelfValidator, Op::Eq, Op::Verify, // same contract continues
            Op::PushBytes(A.to_vec()), Op::SelfAsset,                     // old_a
            Op::PushBytes(B.to_vec()), Op::SelfAsset, Op::Mul,            // old_k = old_a*old_b
            Op::PushBytes(A.to_vec()), Op::TxOutAsset(0),                 // new_a
            Op::PushBytes(B.to_vec()), Op::TxOutAsset(0), Op::Mul,        // new_k = new_a*new_b
            Op::Swap, Op::Lt, Op::Not,                                    // new_k >= old_k
        ];
        let pvh = validator_hash(&pool);
        let anyone = vec![Op::PushInt(1)];
        let avh = validator_hash(&anyone);
        let noop = MockVerifier { good: vec![] };

        // valid swap: +100 A in, 90 B out; product grows (1100·910 ≥ 1000·1000).
        let good = EuTx {
            inputs: vec![
                EuTxInput { prev_output: ExtOutput { value: mkval(&[(A, 1000), (B, 1000)]), validator_hash: pvh, datum: Val::Int(0) }, validator: pool.clone(), redeemer: vec![] },
                EuTxInput { prev_output: ExtOutput { value: mkval(&[(A, 100)]), validator_hash: avh, datum: Val::Int(0) }, validator: anyone.clone(), redeemer: vec![] },
            ],
            outputs: vec![
                ExtOutput { value: mkval(&[(A, 1100), (B, 910)]), validator_hash: pvh, datum: Val::Int(0) },
                ExtOutput { value: mkval(&[(B, 90)]), validator_hash: avh, datum: Val::Int(0) },
            ],
            fee: 0,
            sighash: vec![],
        };
        assert!(validate_tx(&good, &noop, 50_000).is_ok());

        // draining swap: takes 200 B for only 100 A; product shrinks → pool rejects it.
        let bad = EuTx {
            inputs: good.inputs.clone(),
            outputs: vec![
                ExtOutput { value: mkval(&[(A, 1100), (B, 800)]), validator_hash: pvh, datum: Val::Int(0) },
                ExtOutput { value: mkval(&[(B, 200)]), validator_hash: avh, datum: Val::Int(0) },
            ],
            fee: 0,
            sighash: vec![],
        };
        assert_eq!(validate_tx(&bad, &noop, 50_000), Err(TxError::ValidatorRejected(0)));
    }
}
