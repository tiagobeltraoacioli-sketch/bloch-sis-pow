//! tx — a fluent builder for [`bloch_euvm::EuTx`] (inputs, outputs, fee, sighash) that
//! wires revealed validator programs to their redeemers and produces a tx ready for
//! [`bloch_euvm::validate_tx`].
//!
//! # Two shapes of transaction
//!
//! - **DEPLOY** — a tx whose *output* carries a validator program: the output's
//!   `validator_hash` is `validator_hash(program)`, locking future spenders into that
//!   contract. Build outputs with [`ext_output`] so the hash can never desync from the
//!   program it commits to.
//! - **SPEND** — a tx that *consumes* a locked output: it reveals the validator program
//!   (which must hash back to `prev_output.validator_hash`) plus the witness/redeemer
//!   [`Val`](euvm::Val)s that satisfy it. Add inputs with [`TxBuilder::spend_input`].
//!
//! This module is pure construction + encoding — no network, no signing. The resulting
//! [`EuTx`](euvm::EuTx) is the exact struct the VM's `validate_tx` / `spend` entrypoints
//! accept, so callers can hand it straight to the harness / RPC layer later.
//!
//! ```no_run
//! use euvm_tooling::euvm;
//! use euvm_tooling::tx::{TxBuilder, ext_output};
//!
//! // A trivial "always true" program for illustration.
//! let program = vec![euvm::Op::PushInt(1)];
//!
//! // DEPLOY: create an output locked by `program`, carrying 100 BLCH.
//! let locked = ext_output(euvm::blch(100), &program, euvm::Val::Int(0));
//!
//! // SPEND: consume `locked`, revealing the program + an (empty) redeemer, and
//! // recreate 99 BLCH to a fresh output (1 BLCH goes to fee).
//! let tx = TxBuilder::new()
//!     .sighash(b"msg".to_vec())
//!     .fee(1)
//!     .spend_input(locked, program.clone(), vec![])
//!     .output(ext_output(euvm::blch(99), &program, euvm::Val::Int(0)))
//!     .build();
//! assert_eq!(tx.inputs.len(), 1);
//! ```

use crate::euvm;

/// Build an [`ExtOutput`](euvm::ExtOutput) whose `validator_hash` is derived from
/// `program`, guaranteeing the committed hash matches the program that must later be
/// revealed to spend it.
///
/// This is the single choke point that keeps a program and its `validator_hash` in
/// lock-step: a spender's revealed `validator` must hash to `prev_output.validator_hash`
/// or [`spend`](euvm::spend) rejects it with `ValidatorHashMismatch`. Always mint outputs
/// through here rather than setting `validator_hash` by hand.
///
/// `value` is the multi-asset bundle the output carries, `datum` is the on-chain state
/// the output pins to its validator (readable inside the VM as the seeded stack bottom).
pub fn ext_output(value: euvm::Value, program: &[euvm::Op], datum: euvm::Val) -> euvm::ExtOutput {
    euvm::ExtOutput {
        value,
        validator_hash: euvm::validator_hash(program),
        datum,
    }
}

/// Convenience: a single-asset BLCH output of `amount` locked by `program`, with an
/// integer `datum` of 0. Shorthand for the common "recreate N coins under this
/// contract" continuation output.
pub fn ext_output_blch(amount: u64, program: &[euvm::Op]) -> euvm::ExtOutput {
    ext_output(euvm::blch(amount), program, euvm::Val::Int(0))
}

/// A fluent builder for [`EuTx`](euvm::EuTx).
///
/// Accumulates inputs (each an `EuTxInput` = consumed output + revealed validator +
/// redeemer), outputs, a fee, and the sighash message signature-validators read from
/// `ctx.fields[0]`. Every mutating method takes `self` by value and returns it, so calls
/// chain; finish with [`build`](TxBuilder::build) or [`build_checked`](TxBuilder::build_checked).
#[derive(Clone, Debug, Default)]
pub struct TxBuilder {
    inputs: Vec<euvm::EuTxInput>,
    outputs: Vec<euvm::ExtOutput>,
    fee: u64,
    sighash: Vec<u8>,
}

impl TxBuilder {
    /// A fresh builder with no inputs/outputs, zero fee, and an empty sighash.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the transaction sighash — the message signature-checking validators read from
    /// `ctx.fields[0]`. Overwrites any previously set value.
    pub fn sighash(mut self, s: Vec<u8>) -> Self {
        self.sighash = s;
        self
    }

    /// Set the transaction fee (in base BLCH units). Overwrites any previous value.
    pub fn fee(mut self, f: u64) -> Self {
        self.fee = f;
        self
    }

    /// Add a SPEND input: consume `prev_output`, revealing the `validator` program that
    /// must hash to `prev_output.validator_hash`, plus the `redeemer` witness
    /// [`Val`](euvm::Val)s that satisfy it.
    ///
    /// This does not check the hash binding itself (validation does, at spend time) —
    /// but when `prev_output` was produced by [`ext_output`] with the same `validator`,
    /// the binding holds by construction.
    pub fn spend_input(
        mut self,
        prev_output: euvm::ExtOutput,
        validator: Vec<euvm::Op>,
        redeemer: Vec<euvm::Val>,
    ) -> Self {
        self.inputs.push(euvm::EuTxInput {
            prev_output,
            validator,
            redeemer,
        });
        self
    }

    /// Append an already-built output. Pair with [`ext_output`] to keep the output's
    /// `validator_hash` bound to the program that locks it.
    pub fn output(mut self, out: euvm::ExtOutput) -> Self {
        self.outputs.push(out);
        self
    }

    /// Append a DEPLOY output: `amount` BLCH locked directly by `validator_hash`, with a
    /// zero integer datum. Use when you already hold the target hash (e.g. a pubkey-hash
    /// or a precomputed validator hash) and do not have the program on hand.
    ///
    /// When you *do* have the program, prefer [`output`](TxBuilder::output) +
    /// [`ext_output`] so the hash is derived, not trusted.
    pub fn output_blch(mut self, amount: u64, validator_hash: [u8; 32]) -> Self {
        self.outputs.push(euvm::ExtOutput {
            value: euvm::blch(amount),
            validator_hash,
            datum: euvm::Val::Int(0),
        });
        self
    }

    /// Number of inputs accumulated so far.
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Number of outputs accumulated so far.
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    /// Finish and produce the [`EuTx`](euvm::EuTx). Never fails — no validation is run;
    /// hand the result to [`validate_tx`](euvm::validate_tx) (or
    /// [`build_checked`](TxBuilder::build_checked)) to enforce consensus rules.
    pub fn build(self) -> euvm::EuTx {
        euvm::EuTx {
            inputs: self.inputs,
            outputs: self.outputs,
            fee: self.fee,
            sighash: self.sighash,
        }
    }

    /// Finish and produce the [`EuTx`](euvm::EuTx), first checking it against the VM's
    /// structural resource ceilings (input/output counts, distinct assets, operand
    /// bytes) via [`check_tx_resource_limits`](euvm::check_tx_resource_limits).
    ///
    /// Returns [`TxError::ResourceLimit`](euvm::TxError) if any ceiling is breached. This
    /// only checks *structure* — it does NOT run validators or check value conservation;
    /// use [`validate_tx`](euvm::validate_tx) for the full spend-time check.
    pub fn build_checked(self) -> Result<euvm::EuTx, euvm::TxError> {
        let tx = self.build();
        euvm::check_tx_resource_limits(&tx)?;
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The program used to lock a spend and the one revealed to unlock it must hash
    /// identically — `ext_output` guarantees the output's `validator_hash` is exactly
    /// `validator_hash(program)`.
    #[test]
    fn ext_output_binds_hash_to_program() {
        let program = vec![euvm::Op::PushInt(1)];
        let out = ext_output(euvm::blch(50), &program, euvm::Val::Int(7));
        assert_eq!(out.validator_hash, euvm::validator_hash(&program));
        assert_eq!(euvm::value_get(&out.value, &euvm::BLCH), 50);
        assert_eq!(out.datum, euvm::Val::Int(7));
    }

    /// A minimal spend tx: consume one locked output, reveal its program + redeemer,
    /// recreate a smaller continuation output, and pay a fee. Confirms every field of the
    /// built `EuTx` wires through, and that the revealed input validator hashes back to
    /// the consumed output's committed hash.
    #[test]
    fn builds_spend_tx_end_to_end() {
        let program = vec![euvm::Op::PushInt(1)];
        let locked = ext_output(euvm::blch(100), &program, euvm::Val::Int(0));

        let tx = TxBuilder::new()
            .sighash(b"sighash-msg".to_vec())
            .fee(1)
            .spend_input(locked.clone(), program.clone(), vec![euvm::Val::Int(42)])
            .output(ext_output_blch(99, &program))
            .build();

        assert_eq!(tx.fee, 1);
        assert_eq!(tx.sighash, b"sighash-msg".to_vec());
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);

        let input = &tx.inputs[0];
        assert_eq!(input.redeemer, vec![euvm::Val::Int(42)]);
        // The revealed validator must hash to the consumed output's committed hash.
        assert_eq!(
            euvm::validator_hash(&input.validator),
            input.prev_output.validator_hash
        );
        assert_eq!(euvm::value_get(&tx.outputs[0].value, &euvm::BLCH), 99);
    }

    /// `output_blch` sets the raw hash and a zero datum without needing the program.
    #[test]
    fn output_blch_sets_raw_hash() {
        let h = [7u8; 32];
        let tx = TxBuilder::new().output_blch(25, h).build();
        assert_eq!(tx.outputs[0].validator_hash, h);
        assert_eq!(euvm::value_get(&tx.outputs[0].value, &euvm::BLCH), 25);
        assert_eq!(tx.outputs[0].datum, euvm::Val::Int(0));
    }

    /// A well-formed small tx passes the structural resource-ceiling check.
    #[test]
    fn build_checked_accepts_small_tx() {
        let program = vec![euvm::Op::PushInt(1)];
        let locked = ext_output(euvm::blch(10), &program, euvm::Val::Int(0));
        let res = TxBuilder::new()
            .spend_input(locked, program.clone(), vec![])
            .output(ext_output_blch(9, &program))
            .fee(1)
            .build_checked();
        assert!(res.is_ok());
    }

    /// Chained counts reflect what was added.
    #[test]
    fn counts_track_additions() {
        let program = vec![euvm::Op::PushInt(1)];
        let out = ext_output_blch(1, &program);
        let b = TxBuilder::new()
            .spend_input(out.clone(), program.clone(), vec![])
            .spend_input(out.clone(), program.clone(), vec![])
            .output(out.clone());
        assert_eq!(b.input_count(), 2);
        assert_eq!(b.output_count(), 1);
    }
}
