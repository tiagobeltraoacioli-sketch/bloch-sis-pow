//! sim — an instrumented off-chain runner around [`euvm::run`] / [`euvm::spend`].
//!
//! This module is the crate's test harness: it lets a developer take a validator
//! program (a `Vec<euvm::Op>`) plus a candidate spend (an [`euvm::ExtOutput`]
//! prevout, witness [`euvm::Val`] redeemer values, and a [`euvm::Ctx`]) and run it
//! through the *real* VM execution API, reporting the outcome (accept / reject /
//! error) together with the exact gas consumed. No node, no block, no deploy — the
//! fastest possible edit-run loop for contract authors.
//!
//! It also owns the crate's shared, reusable [`MockVerifier`]: `bloch-euvm`'s own
//! mock signature verifier is `#[cfg(test)]`-private and not importable, so every
//! other module (`examples`, `tx` doctests, …) reaches for the one defined here.
//!
//! ## Gas accounting
//!
//! The VM entrypoints take `gas: &mut u64` and *decrement* it as they execute. The
//! simulator seeds that counter with a caller-supplied `gas_limit`, runs, and reports
//! `gas_used = gas_limit - remaining`. On `Err(VmError::OutOfGas)` the counter is at
//! (or near) zero, so `gas_used` reflects effectively the whole budget.

use crate::euvm;

use euvm::{validate_tx, EuTx, TxError};
use euvm::{Ctx, ExtOutput, Op, SigVerifier, Val, VmError};

/// A reusable, deterministic [`SigVerifier`] for simulation and tests.
///
/// `bloch-euvm`'s built-in mock is test-private, so this is the crate-wide shared
/// verifier that `examples`, `tx`, and downstream tests all use.
///
/// Construction modes:
/// - [`MockVerifier::accepting`] — accept exactly the `(msg, pubkey, sig)` triples
///   supplied (PQ path). Anything not in the set is rejected.
/// - [`MockVerifier::always`] — accept *every* PQ signature (and ECDSA too).
/// - [`MockVerifier::never`] — reject everything (also the default via [`Default`]).
///
/// The `ecdsa_ok` flag independently controls the secp256k1 `verify_ecdsa` path;
/// [`MockVerifier::always`] sets it, the others leave it `false`.
#[derive(Clone, Debug, Default)]
pub struct MockVerifier {
    /// If `true`, `verify` returns `true` for every input regardless of `good`.
    all_ok: bool,
    /// If `true`, `verify_ecdsa` returns `true` for every input.
    ecdsa_ok: bool,
    /// Whitelisted `(msg, pubkey, sig)` triples accepted by the PQ `verify` path.
    good: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
}

impl MockVerifier {
    /// Accept exactly the given `(msg, pubkey, sig)` triples on the PQ `verify`
    /// path; reject anything else. ECDSA stays off.
    pub fn accepting(triples: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>) -> Self {
        MockVerifier {
            all_ok: false,
            ecdsa_ok: false,
            good: triples,
        }
    }

    /// Accept every signature — both the PQ `verify` and the ECDSA
    /// `verify_ecdsa` paths return `true`. Handy for exercising a validator's
    /// non-signature logic without wiring real keys.
    pub fn always() -> Self {
        MockVerifier {
            all_ok: true,
            ecdsa_ok: true,
            good: Vec::new(),
        }
    }

    /// Reject every signature on both paths (same as [`Default::default`]).
    pub fn never() -> Self {
        MockVerifier::default()
    }

    /// Add one accepted `(msg, pubkey, sig)` triple to the PQ whitelist, chainable.
    pub fn with_triple(
        mut self,
        msg: impl Into<Vec<u8>>,
        pubkey: impl Into<Vec<u8>>,
        sig: impl Into<Vec<u8>>,
    ) -> Self {
        self.good.push((msg.into(), pubkey.into(), sig.into()));
        self
    }
}

impl SigVerifier for MockVerifier {
    fn verify(&self, msg: &[u8], pubkey: &[u8], sig: &[u8]) -> bool {
        if self.all_ok {
            return true;
        }
        self.good
            .iter()
            .any(|(m, p, s)| m.as_slice() == msg && p.as_slice() == pubkey && s.as_slice() == sig)
    }

    fn verify_ecdsa(&self, _msg: &[u8], _pubkey: &[u8], _sig: &[u8]) -> bool {
        self.ecdsa_ok
    }
}

/// Outcome of a single simulated program/spend run.
///
/// `result` is the raw VM verdict: `Ok(true)` accept, `Ok(false)` reject (finished
/// with a falsy / non-truthy result), or `Err(VmError)` for an execution fault
/// (out-of-gas, type error, assertion abort, `ValidatorHashMismatch`, …). `gas_used`
/// is always meaningful — even on error — because the VM decrements as it runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimResult {
    /// The VM's verdict: accept (`Ok(true)`), reject (`Ok(false)`), or fault.
    pub result: Result<bool, VmError>,
    /// Gas consumed = `gas_limit - remaining`.
    pub gas_used: u64,
    /// The budget the run started with.
    pub gas_limit: u64,
}

impl SimResult {
    /// `true` iff the VM finished with `Ok(true)` (an accepted spend).
    pub fn accepted(&self) -> bool {
        matches!(self.result, Ok(true))
    }

    /// `true` iff the VM finished cleanly but non-truthy (`Ok(false)`).
    pub fn rejected(&self) -> bool {
        matches!(self.result, Ok(false))
    }

    /// `true` iff the run faulted (`Err(_)`).
    pub fn errored(&self) -> bool {
        self.result.is_err()
    }

    /// Gas remaining in the budget after the run.
    pub fn gas_remaining(&self) -> u64 {
        self.gas_limit.saturating_sub(self.gas_used)
    }
}

/// Run a bare program against a caller-supplied initial stack and context.
///
/// The stack is seeded bottom→top with `initial`. Returns a [`SimResult`] carrying
/// the VM verdict and the gas consumed. This is the lowest-level entrypoint — for
/// spending a specific UTXO (which binds `self_validator_hash`/`self_value` and
/// checks the program hash) use [`run_spend`] instead.
pub fn run_program(
    program: &[Op],
    initial: Vec<Val>,
    ctx: &Ctx,
    v: &dyn SigVerifier,
    gas_limit: u64,
) -> SimResult {
    let mut gas = gas_limit;
    let result = euvm::run(program, initial, ctx, v, &mut gas);
    SimResult {
        result,
        gas_used: gas_limit.saturating_sub(gas),
        gas_limit,
    }
}

/// Simulate spending a specific [`ExtOutput`] with a revealed validator program.
///
/// Mirrors [`euvm::spend`]: it checks `validator_hash(program) ==
/// output.validator_hash` (yielding `Err(VmError::ValidatorHashMismatch)` on
/// mismatch), binds `ctx.self_validator_hash` / `ctx.self_value` from the output,
/// seeds the stack `[datum, redeemer…]`, and runs — reporting gas alongside.
pub fn run_spend(
    output: &ExtOutput,
    program: &[Op],
    redeemer: Vec<Val>,
    ctx: &Ctx,
    v: &dyn SigVerifier,
    gas_limit: u64,
) -> SimResult {
    let mut gas = gas_limit;
    let result = euvm::spend(output, program, redeemer, ctx, v, &mut gas);
    SimResult {
        result,
        gas_used: gas_limit.saturating_sub(gas),
        gas_limit,
    }
}

/// Simulate full-transaction validation via [`euvm::validate_tx`].
///
/// Runs native-value conservation, every input's validator, and the shared gas
/// budget. Returns the gas used on success, or the structured [`TxError`] on the
/// first failure (a rejected validator, non-conservation, out-of-gas, …).
pub fn simulate_tx(tx: &EuTx, v: &dyn SigVerifier, gas_limit: u64) -> Result<u64, TxError> {
    validate_tx(tx, v, gas_limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::euvm::{blch, validator_hash};

    /// `PushInt(1)` finishes truthy on a non-empty stack → accept, tiny gas.
    #[test]
    fn run_program_accepts_truthy() {
        let prog = vec![Op::PushInt(1)];
        let ctx = Ctx::default();
        let v = MockVerifier::never();
        let r = run_program(&prog, vec![], &ctx, &v, 1_000);
        assert!(r.accepted());
        assert!(r.gas_used > 0);
        assert_eq!(r.gas_limit, 1_000);
        assert_eq!(r.gas_remaining(), 1_000 - r.gas_used);
    }

    /// `PushInt(0)` finishes falsy → clean reject, not an error.
    #[test]
    fn run_program_rejects_falsy() {
        let prog = vec![Op::PushInt(0)];
        let ctx = Ctx::default();
        let v = MockVerifier::never();
        let r = run_program(&prog, vec![], &ctx, &v, 1_000);
        assert!(r.rejected());
        assert!(!r.errored());
    }

    /// A tiny gas budget forces `OutOfGas`, still reporting a verdict.
    #[test]
    fn run_program_out_of_gas() {
        let prog = vec![Op::PushInt(1), Op::PushInt(2), Op::Add];
        let ctx = Ctx::default();
        let v = MockVerifier::never();
        let r = run_program(&prog, vec![], &ctx, &v, 1);
        assert!(r.errored());
        assert_eq!(r.result, Err(VmError::OutOfGas));
    }

    /// A program whose hash matches the output spends cleanly; datum dropped, 1+2==3.
    #[test]
    fn run_spend_happy_path() {
        // spend seeds the stack `[datum, redeemer...]`; datum is Int(0), so Drop it
        // then compute a truthy result.
        let prog = vec![Op::Drop, Op::PushInt(1), Op::PushInt(2), Op::Add];
        let out = ExtOutput {
            value: blch(100),
            validator_hash: validator_hash(&prog),
            datum: Val::Int(0),
        };
        let ctx = Ctx::default();
        let v = MockVerifier::never();
        let r = run_spend(&out, &prog, vec![], &ctx, &v, 10_000);
        assert!(r.accepted());
    }

    /// Wrong program → `ValidatorHashMismatch` before any execution.
    #[test]
    fn run_spend_hash_mismatch() {
        let real = vec![Op::PushInt(1)];
        let wrong = vec![Op::PushInt(2)];
        let out = ExtOutput {
            value: blch(1),
            validator_hash: validator_hash(&real),
            datum: Val::Int(0),
        };
        let ctx = Ctx::default();
        let v = MockVerifier::never();
        let r = run_spend(&out, &wrong, vec![], &ctx, &v, 10_000);
        assert_eq!(r.result, Err(VmError::ValidatorHashMismatch));
    }

    /// `always()` accepts an arbitrary triple; `accepting` matches only listed ones.
    #[test]
    fn mock_verifier_modes() {
        let always = MockVerifier::always();
        assert!(always.verify(b"m", b"pk", b"sig"));
        assert!(always.verify_ecdsa(b"m", b"pk", b"sig"));

        let never = MockVerifier::never();
        assert!(!never.verify(b"m", b"pk", b"sig"));
        assert!(!never.verify_ecdsa(b"m", b"pk", b"sig"));

        let sel = MockVerifier::accepting(vec![(b"m".to_vec(), b"pk".to_vec(), b"sig".to_vec())]);
        assert!(sel.verify(b"m", b"pk", b"sig"));
        assert!(!sel.verify(b"m", b"pk", b"other"));
        assert!(!sel.verify_ecdsa(b"m", b"pk", b"sig"));

        let chained =
            MockVerifier::never().with_triple(b"a".to_vec(), b"b".to_vec(), b"c".to_vec());
        assert!(chained.verify(b"a", b"b", b"c"));
    }
}
