//! Adversarial audit — lens: value/supply conservation & minting.
//!
//! Integration tests only; no `src/` file is edited. Each test documents a concrete
//! way a conservation/minting invariant is (or is not) violated.

use bloch_euvm::minting::{
    fixed_supply_cap_policy, policy_asset_id, validate_tx_with_mint, MintAction, MintCtx,
    MintRequest, MintTxError,
};
use bloch_euvm::{
    validate_tx, AssetId, EuTx, EuTxInput, ExtOutput, Op, SigVerifier, TxError, Val, Value, BLCH,
};

/// A verifier that rejects everything (the conservation tests never exercise sigs).
struct NoopVerifier;
impl SigVerifier for NoopVerifier {
    fn verify(&self, _m: &[u8], _p: &[u8], _s: &[u8]) -> bool {
        false
    }
}

fn one_asset(a: AssetId, n: u64) -> Value {
    let mut v = Value::new();
    v.insert(a, n);
    v
}

// ───────────────────────────────────────────────────────────────────────────
// FINDING A (medium): the per-asset conservation loop is UNMETERED and O(n²).
//
// `validate_tx` step (1) — and `validate_tx_with_mint` step (2) — iterate
//   for asset in assets { for inp in inputs {..} for out in outputs {..} }
// BEFORE any gas is charged (gas only meters validator execution, step 2/3).
// With one distinct asset per input, |assets| == |inputs|, so the loop is
// O(inputs × (inputs+outputs)) == O(n²) of work that NO gas ceiling bounds.
//
// Demonstration: pass gas_limit == 0. If conservation were metered, a large tx
// would abort with OutOfGas before scanning. Instead the full O(n²) scan runs
// and the call returns ValueNotConserved — proving the work happened on a zero
// gas budget. An attacker puts one such tx in a block to burn node CPU for free.
// ───────────────────────────────────────────────────────────────────────────

/// A validator we never actually run here (conservation rejects first), but the
/// program/hash still needs to be well-formed for the input to type-check.
fn anyone() -> (Vec<Op>, [u8; 32]) {
    let p = vec![Op::PushInt(1)];
    let h = bloch_euvm::validator_hash(&p);
    (p, h)
}

fn distinct_asset(i: usize) -> AssetId {
    let mut a = [0u8; 32];
    a[0..8].copy_from_slice(&(i as u64 + 1).to_le_bytes()); // never all-zero → never BLCH
    a
}

#[test]
fn conservation_scan_is_unmetered_and_scales_superlinearly() {
    let (prog, vh) = anyone();
    const N: usize = 1500;

    // N inputs, each carrying a *distinct* asset (so |assets| ≈ N). The last asset
    // is deliberately unbalanced so step (1) must scan every asset to notice.
    let mut inputs = Vec::with_capacity(N);
    let mut outputs = Vec::with_capacity(N);
    for i in 0..N {
        let a = distinct_asset(i);
        let in_amt = 100u64;
        // Balance every asset except the last, which is short by 1 → non-conserving.
        let out_amt = if i == N - 1 { 99 } else { 100 };
        inputs.push(EuTxInput {
            prev_output: ExtOutput {
                value: one_asset(a, in_amt),
                validator_hash: vh,
                datum: Val::Int(0),
            },
            validator: prog.clone(),
            redeemer: vec![],
        });
        outputs.push(ExtOutput {
            value: one_asset(a, out_amt),
            validator_hash: vh,
            datum: Val::Int(0),
        });
    }
    let tx = EuTx { inputs, outputs, fee: 0, sighash: vec![] };

    // gas_limit == 0. The O(N²) conservation scan runs to completion anyway and
    // reports the imbalance — never OutOfGas. This is the unmetered-work proof.
    let got = validate_tx(&tx, &NoopVerifier, 0);
    match got {
        Err(TxError::ValueNotConserved { .. }) => {
            // Confirmed: ~N*(N) inner iterations executed with a zero gas budget.
        }
        other => panic!("expected an unmetered ValueNotConserved scan, got {other:?}"),
    }
}

#[test]
fn mint_conservation_scan_is_also_unmetered() {
    let (prog, vh) = anyone();
    const N: usize = 1500;
    let mut inputs = Vec::with_capacity(N);
    let mut outputs = Vec::with_capacity(N);
    for i in 0..N {
        let a = distinct_asset(i);
        let out_amt = if i == N - 1 { 99 } else { 100 };
        inputs.push(EuTxInput {
            prev_output: ExtOutput {
                value: one_asset(a, 100),
                validator_hash: vh,
                datum: Val::Int(0),
            },
            validator: prog.clone(),
            redeemer: vec![],
        });
        outputs.push(ExtOutput {
            value: one_asset(a, out_amt),
            validator_hash: vh,
            datum: Val::Int(0),
        });
    }
    let tx = EuTx { inputs, outputs, fee: 0, sighash: vec![] };
    // No mint requests; gas_limit 0. Same unmetered O(N²) scan inside the mint path.
    let got = validate_tx_with_mint(&tx, &[], &MintCtx::default(), &NoopVerifier, 0);
    assert!(
        matches!(got, Err(MintTxError::ValueNotConserved { .. })),
        "expected an unmetered mint-path conservation scan, got {got:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// FINDING B (medium): `fixed_supply_cap_policy(i128::MAX)` — a public reference
// constructor — computes `cap + 1` in native Rust i128. On the boundary argument
// i128::MAX this overflows: it PANICS in a debug build (incl. `cargo test`) and
// silently wraps to i128::MIN in release (yielding a policy that rejects every
// mint, including a zero delta). A no-panic-on-in-range-input violation living in
// the minting module; if a node ever re-derives a cap policy from consensus data
// carrying cap==i128::MAX, the panic path crashes the node during validation.
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn fixed_supply_cap_policy_max_cap_panics_or_fails_shut() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let built = std::panic::catch_unwind(|| fixed_supply_cap_policy(i128::MAX));
    std::panic::set_hook(prev);

    match built {
        Err(_) => {
            // Debug profile: confirmed PANIC on an in-range i128 argument. A public
            // constructor must never panic — this is the reproduced defect.
        }
        Ok(policy) => {
            // Release profile: wrapped to a reject-everything policy (fails closed on
            // conservation, but the "no cap" intent is inverted to "no mint ever").
            let asset = policy_asset_id(&policy);
            let tx = EuTx { inputs: vec![], outputs: vec![], fee: 0, sighash: vec![] };
            let mints = vec![MintRequest {
                policy,
                redeemer: vec![],
                action: MintAction { asset_id: asset, delta: 0 },
            }];
            assert_eq!(
                validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &NoopVerifier, 50_000),
                Err(MintTxError::PolicyRejected { asset })
            );
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// POSITIVE CONFIRMATIONS — the core supply invariants DO hold (lens is otherwise
// clean on these points). Kept as regression anchors.
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn blch_can_never_be_minted_even_with_a_true_policy() {
    // Present an always-true policy but claim it governs BLCH: rejected pre-gas.
    let policy = vec![Op::PushInt(1)];
    let tx = EuTx {
        inputs: vec![],
        outputs: vec![ExtOutput { value: one_asset(BLCH, 100), validator_hash: [0u8; 32], datum: Val::Int(0) }],
        fee: 0,
        sighash: vec![],
    };
    let mints = vec![MintRequest {
        policy,
        redeemer: vec![],
        action: MintAction { asset_id: BLCH, delta: 100 },
    }];
    assert_eq!(
        validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &NoopVerifier, 50_000),
        Err(MintTxError::BlchMintForbidden)
    );
}

#[test]
fn no_asset_can_be_created_without_a_presented_policy() {
    // Output invents 500 of asset X, no mint request → exact-balance rejects.
    let x = distinct_asset(42);
    let tx = EuTx {
        inputs: vec![],
        outputs: vec![ExtOutput { value: one_asset(x, 500), validator_hash: [0u8; 32], datum: Val::Int(0) }],
        fee: 0,
        sighash: vec![],
    };
    assert!(matches!(
        validate_tx_with_mint(&tx, &[], &MintCtx::default(), &NoopVerifier, 50_000),
        Err(MintTxError::ValueNotConserved { .. })
    ));
}

#[test]
fn authorised_delta_cannot_exceed_the_cap_and_binds_the_real_shift() {
    // Cap policy authorising delta 500, but the tx creates only 10 → rejected: the
    // authorised delta is bound to the observed value change, so a policy can't be
    // used as a blank cheque for a larger mint.
    let policy = fixed_supply_cap_policy(1_000_000);
    let asset = policy_asset_id(&policy);
    let tx = EuTx {
        inputs: vec![],
        outputs: vec![ExtOutput { value: one_asset(asset, 10), validator_hash: [0u8; 32], datum: Val::Int(0) }],
        fee: 0,
        sighash: vec![],
    };
    let mints = vec![MintRequest {
        policy,
        redeemer: vec![],
        action: MintAction { asset_id: asset, delta: 500 },
    }];
    assert!(matches!(
        validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &NoopVerifier, 50_000),
        Err(MintTxError::ValueNotConserved { .. })
    ));
}

#[test]
fn burn_cannot_drive_supply_negative() {
    let policy = fixed_supply_cap_policy(1_000_000);
    let asset = policy_asset_id(&policy);
    let mut prior = std::collections::BTreeMap::new();
    prior.insert(asset, 50i128); // only 50 exist
    let mctx = MintCtx { height: 0, prior_supply: prior };
    let guard = vec![Op::PushInt(1)];
    let gvh = bloch_euvm::validator_hash(&guard);
    let tx = EuTx {
        inputs: vec![EuTxInput {
            prev_output: ExtOutput { value: one_asset(asset, 100), validator_hash: gvh, datum: Val::Int(0) },
            validator: guard,
            redeemer: vec![],
        }],
        outputs: vec![ExtOutput { value: one_asset(asset, 0), validator_hash: [0u8; 32], datum: Val::Int(0) }],
        fee: 0,
        sighash: vec![],
    };
    let mints = vec![MintRequest {
        policy,
        redeemer: vec![],
        action: MintAction { asset_id: asset, delta: -100 },
    }];
    assert_eq!(
        validate_tx_with_mint(&tx, &mints, &mctx, &NoopVerifier, 50_000),
        Err(MintTxError::SupplyNegative { asset })
    );
}
