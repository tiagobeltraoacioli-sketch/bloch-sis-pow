//! asm — an ergonomic assembler / DSL for building `Vec<bloch_euvm::Op>` validator
//! programs by hand, so callers don't hand-write raw `Op` vectors everywhere.
//!
//! The centerpiece is [`Asm`], a small builder with one chainable method per
//! [`euvm::Op`] variant. Because every method returns `&mut Self`, programs read
//! top-to-bottom like assembly:
//!
//! ```
//! use euvm_tooling::asm::Asm;
//! let program = Asm::new()
//!     .push_int(1)
//!     .push_int(2)
//!     .add()
//!     .push_int(3)
//!     .eq()
//!     .verify()
//!     .build();
//! assert_eq!(program.len(), 6);
//! ```
//!
//! `build()` yields a plain `Vec<euvm::Op>` that drops straight into
//! `EuTxInput.validator`, `MintRequest.policy`, batcher validators, etc. The
//! matching [`Asm::hash`] returns the program's [`euvm::validator_hash`], which is
//! the on-chain identity of the output the program locks.
//!
//! The [`prog!`] macro is sugar for one-shot programs whose ops are known up front.

use crate::euvm;

/// A chainable builder that accumulates [`euvm::Op`]s into a validator program.
///
/// Construct with [`Asm::new`], append ops with the per-variant methods, then call
/// [`Asm::build`] to obtain the `Vec<euvm::Op>`. The builder never mutates or
/// inspects VM state — it is a pure syntactic convenience over `Vec<Op>`.
#[derive(Clone, Debug, Default)]
pub struct Asm {
    ops: Vec<euvm::Op>,
}

impl Asm {
    /// Start an empty program.
    pub fn new() -> Self {
        Asm { ops: Vec::new() }
    }

    /// Start from an existing op vector (e.g. to extend a template program).
    pub fn from_ops(ops: Vec<euvm::Op>) -> Self {
        Asm { ops }
    }

    /// Append an already-constructed [`euvm::Op`] (escape hatch for any variant).
    pub fn op(&mut self, op: euvm::Op) -> &mut Self {
        self.ops.push(op);
        self
    }

    /// Append every op from `other`, consuming its buffer. Useful for composing
    /// reusable fragments (e.g. a shared sighash-loading prologue).
    pub fn extend(&mut self, other: Asm) -> &mut Self {
        self.ops.extend(other.ops);
        self
    }

    // --- push / literals ----------------------------------------------------

    /// `PushInt(n)` — push the integer literal `Int(n)`.
    pub fn push_int(&mut self, n: i128) -> &mut Self {
        self.op(euvm::Op::PushInt(n))
    }

    /// `PushBytes(b)` — push the byte-string literal `Bytes(b)`.
    pub fn push_bytes(&mut self, b: impl Into<Vec<u8>>) -> &mut Self {
        self.op(euvm::Op::PushBytes(b.into()))
    }

    // --- stack shuffling ----------------------------------------------------

    /// `Dup` — duplicate the top item.
    pub fn dup(&mut self) -> &mut Self {
        self.op(euvm::Op::Dup)
    }

    /// `Drop` — pop and discard the top item. (Named `drop_` because `drop` is a
    /// prelude name.)
    pub fn drop_(&mut self) -> &mut Self {
        self.op(euvm::Op::Drop)
    }

    /// `Swap` — swap the top two items.
    pub fn swap(&mut self) -> &mut Self {
        self.op(euvm::Op::Swap)
    }

    /// `Pick(n)` — copy the element `n` positions below the top to the top
    /// (`Pick(0)` == [`Asm::dup`]).
    pub fn pick(&mut self, n: u8) -> &mut Self {
        self.op(euvm::Op::Pick(n))
    }

    // --- arithmetic / logic -------------------------------------------------

    /// `Add` — checked `i128` addition of the top two `Int`s.
    pub fn add(&mut self) -> &mut Self {
        self.op(euvm::Op::Add)
    }

    /// `Sub` — checked `i128` subtraction of the top two `Int`s.
    pub fn sub(&mut self) -> &mut Self {
        self.op(euvm::Op::Sub)
    }

    /// `Mul` — checked `i128` multiplication of the top two `Int`s.
    pub fn mul(&mut self) -> &mut Self {
        self.op(euvm::Op::Mul)
    }

    /// `Eq` — push `Int((a == b) as i128)`; works on `Int` or `Bytes`.
    pub fn eq(&mut self) -> &mut Self {
        self.op(euvm::Op::Eq)
    }

    /// `Lt` — push `Int((a < b) as i128)`; `Int`s only.
    pub fn lt(&mut self) -> &mut Self {
        self.op(euvm::Op::Lt)
    }

    /// `Not` — push `Int((a == 0) as i128)`; `Int` only.
    pub fn not(&mut self) -> &mut Self {
        self.op(euvm::Op::Not)
    }

    // --- hashing / size -----------------------------------------------------

    /// `Sha256d` — double-SHA256 of the top `Bytes` → 32 `Bytes`.
    pub fn sha256d(&mut self) -> &mut Self {
        self.op(euvm::Op::Sha256d)
    }

    /// `Shake256` — SHAKE-256 XOF 32-byte read of the top `Bytes` → 32 `Bytes`.
    pub fn shake256(&mut self) -> &mut Self {
        self.op(euvm::Op::Shake256)
    }

    /// `Size` — length of the top `Bytes` → `Int`.
    pub fn size(&mut self) -> &mut Self {
        self.op(euvm::Op::Size)
    }

    // --- context access -----------------------------------------------------

    /// `CtxField(i)` — push `ctx.fields[i]` (VM errors `BadCtxField` if OOB).
    pub fn ctx_field(&mut self, i: u8) -> &mut Self {
        self.op(euvm::Op::CtxField(i))
    }

    // --- signatures / assertions -------------------------------------------

    /// `VerifySig` — pop sig, pubkey, msg; push `Int(1)` if the PQ verifier
    /// accepts, else `Int(0)`.
    pub fn verify_sig(&mut self) -> &mut Self {
        self.op(euvm::Op::VerifySig)
    }

    /// `VerifyEcdsa` — like [`Asm::verify_sig`] but a secp256k1 ECDSA check.
    pub fn verify_ecdsa(&mut self) -> &mut Self {
        self.op(euvm::Op::VerifyEcdsa)
    }

    /// `Verify` — pop the top; abort with `Assert` if it is not truthy.
    pub fn verify(&mut self) -> &mut Self {
        self.op(euvm::Op::Verify)
    }

    // --- transaction-output introspection ----------------------------------

    /// `TxOutDatum(i)` — push `ctx.tx_outputs[i].datum`.
    pub fn tx_out_datum(&mut self, i: u8) -> &mut Self {
        self.op(euvm::Op::TxOutDatum(i))
    }

    /// `TxOutValidator(i)` — push `ctx.tx_outputs[i].validator_hash` as `Bytes`.
    pub fn tx_out_validator(&mut self, i: u8) -> &mut Self {
        self.op(euvm::Op::TxOutValidator(i))
    }

    /// `TxOutValue(i)` — push `ctx.tx_outputs[i].value[BLCH]` as `Int`.
    pub fn tx_out_value(&mut self, i: u8) -> &mut Self {
        self.op(euvm::Op::TxOutValue(i))
    }

    /// `SelfValidator` — push `ctx.self_validator_hash` as `Bytes`.
    pub fn self_validator(&mut self) -> &mut Self {
        self.op(euvm::Op::SelfValidator)
    }

    /// `SelfAsset` — pop an asset id (`Bytes`, 32) → push its amount in the spent
    /// output's reserves.
    pub fn self_asset(&mut self) -> &mut Self {
        self.op(euvm::Op::SelfAsset)
    }

    /// `TxOutAsset(i)` — pop an asset id (`Bytes`, 32) → push its amount in
    /// `ctx.tx_outputs[i].value`.
    pub fn tx_out_asset(&mut self, i: u8) -> &mut Self {
        self.op(euvm::Op::TxOutAsset(i))
    }

    // --- terminals ----------------------------------------------------------

    /// Number of ops accumulated so far.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Whether no ops have been accumulated.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Whether the program fits under the VM's [`euvm::MAX_PROGRAM_OPS`] ceiling.
    /// (`build`/`hash` do not enforce this — the VM does at spend time — but this
    /// lets a caller fail early.)
    pub fn within_op_limit(&self) -> bool {
        self.ops.len() <= euvm::MAX_PROGRAM_OPS
    }

    /// Borrow the accumulated ops without consuming the builder.
    pub fn ops(&self) -> &[euvm::Op] {
        &self.ops
    }

    /// The program's [`euvm::validator_hash`] (SHA-256d of its canonical encoding).
    /// This is the on-chain identity an `ExtOutput.validator_hash` must match for a
    /// spend to be authorized.
    pub fn hash(&self) -> [u8; 32] {
        euvm::validator_hash(&self.ops)
    }

    /// The program's canonical byte encoding ([`euvm::encode_program`]).
    pub fn encode(&self) -> Vec<u8> {
        euvm::encode_program(&self.ops)
    }

    /// Return the finished `Vec<euvm::Op>`.
    ///
    /// Takes `&self` (cloning the accumulated ops) so it can terminate a chain that
    /// began from a temporary — `Asm::new().push_int(1).add().build()` — where the
    /// per-op mutators returned `&mut Self`; a `self`-by-value terminal cannot be
    /// called on the `&mut Self` such a chain yields. `Asm: Clone`, so the clone is
    /// cheap and the builder stays reusable after `build`.
    pub fn build(&self) -> Vec<euvm::Op> {
        self.ops.clone()
    }

    /// Consume the builder and return the finished `Vec<euvm::Op>` without cloning.
    /// Use when you hold an owned `Asm` and want to move its buffer out.
    pub fn into_ops(self) -> Vec<euvm::Op> {
        self.ops
    }
}

/// Passthrough convenience: identity over a `Vec<Op>` so call sites reading
/// `asm::program(vec![...])` document intent ("this is a validator program").
pub fn program(ops: Vec<euvm::Op>) -> Vec<euvm::Op> {
    ops
}

/// Build a `Vec<euvm::Op>` from a comma-separated list of [`Asm`] method calls.
///
/// Each element is a method name (minus the receiver) with its arguments; the
/// macro threads a fresh [`Asm`] through them and calls [`Asm::build`].
///
/// ```
/// use euvm_tooling::prog;
/// let p = prog![push_int(2), push_int(2), add(), push_int(4), eq(), verify()];
/// assert_eq!(p.len(), 6);
/// ```
#[macro_export]
macro_rules! prog {
    ($($method:ident ( $($arg:expr),* $(,)? )),* $(,)?) => {{
        let mut __asm = $crate::asm::Asm::new();
        $( __asm.$method( $($arg),* ); )*
        __asm.build()
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_chains_in_order() {
        let program = Asm::new()
            .push_int(1)
            .push_int(2)
            .add()
            .push_int(3)
            .eq()
            .verify()
            .build();
        assert_eq!(program.len(), 6);
        // Spot-check ordering / operand wiring.
        match &program[0] {
            euvm::Op::PushInt(n) => assert_eq!(*n, 1),
            other => panic!("expected PushInt(1), got {other:?}"),
        }
        match &program[2] {
            euvm::Op::Add => {}
            other => panic!("expected Add, got {other:?}"),
        }
    }

    #[test]
    fn hash_matches_direct_validator_hash() {
        let mut asm = Asm::new();
        asm.push_bytes(vec![0xde, 0xad, 0xbe, 0xef]).sha256d();
        let ops = asm.ops().to_vec();
        assert_eq!(asm.hash(), euvm::validator_hash(&ops));
        assert_eq!(asm.encode(), euvm::encode_program(&ops));
    }

    #[test]
    fn every_family_appends_one_op() {
        let mut asm = Asm::new();
        asm.push_int(0)
            .push_bytes([0u8; 32])
            .dup()
            .drop_()
            .swap()
            .pick(1)
            .add()
            .sub()
            .mul()
            .eq()
            .lt()
            .not()
            .sha256d()
            .shake256()
            .size()
            .ctx_field(0)
            .verify_sig()
            .verify_ecdsa()
            .verify()
            .tx_out_datum(0)
            .tx_out_validator(0)
            .tx_out_value(0)
            .self_validator()
            .self_asset()
            .tx_out_asset(0);
        // 25 distinct builder calls → 25 ops.
        assert_eq!(asm.len(), 25);
        assert!(asm.within_op_limit());
    }

    #[test]
    fn prog_macro_matches_builder() {
        let via_macro = prog![push_int(2), push_int(2), add(), push_int(4), eq(), verify()];
        let via_builder = Asm::new()
            .push_int(2)
            .push_int(2)
            .add()
            .push_int(4)
            .eq()
            .verify()
            .build();
        assert_eq!(
            euvm::encode_program(&via_macro),
            euvm::encode_program(&via_builder)
        );
    }

    #[test]
    fn program_passthrough_is_identity() {
        let ops = Asm::new().self_validator().build();
        let same = program(ops.clone());
        assert_eq!(euvm::encode_program(&ops), euvm::encode_program(&same));
    }
}
