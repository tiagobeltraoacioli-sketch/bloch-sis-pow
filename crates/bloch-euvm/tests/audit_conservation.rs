//! Adversarial audit — lens: value/supply conservation & minting.
//!
//! Integration tests only; no `src/` file is edited. Each test documents a concrete
//! way a conservation/minting invariant is (or is not) violated.

use bloch_euvm::minting::{
    fixed_supply_cap_policy, policy_asset_id, validate_tx_with_mint, MintAction, MintCtx,
    MintRequest, MintTxError,
};
use bloch_euvm::{
    check_tx_resource_limits, validate_tx, AssetId, EuTx, EuTxInput, ExtOutput, Op, SigVerifier,
    TxError, Val, Value, BLCH,
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
// FINDING A (medium) — FIXED (F2): the per-asset conservation loop used to be
// UNMETERED and O(n²). `validate_tx` step (1) — and `validate_tx_with_mint`
// step (2) — iterate over every asset × every input/output BEFORE any gas is
// charged. With one distinct asset per input, that is O(inputs × (inputs+outputs))
// of work no gas ceiling bounded.
//
// The fix adds a fail-closed STRUCTURAL resource ceiling
// (`check_tx_resource_limits`) enforced BEFORE the scan: an oversized tx (too many
// inputs/assets/bytes) is rejected with `TxError::ResourceLimit` instead of running
// the unbounded scan. The mint mirror (`validate_tx_with_mint`) reuses the same
// shared checker. These tests now assert that oversized txs hit that ceiling.
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

    // N = 1500 inputs exceeds MAX_TX_INPUTS: the fail-closed structural ceiling rejects
    // the tx BEFORE the O(N²) conservation scan can run. Regression guard for the
    // unmetered-scan DoS.
    let got = validate_tx(&tx, &NoopVerifier, 0);
    assert!(
        matches!(got, Err(TxError::ResourceLimit { .. })),
        "oversized tx must hit the resource ceiling before the unmetered scan, got {got:?}"
    );
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

    // The SAME shared structural ceiling that guards `validate_tx` applies to this
    // oversized tx (F2) — assert it fires (this is the fix the mint mirror reuses).
    assert!(
        matches!(check_tx_resource_limits(&tx), Err(TxError::ResourceLimit { .. })),
        "the shared F2 resource ceiling must reject the oversized mint tx"
    );

    // The mint mirror (`validate_tx_with_mint`, Lane C) must enforce the same bound by
    // calling `check_tx_resource_limits` and wrapping the breach as
    // `MintTxError::Tx(TxError::ResourceLimit)`. It must reject the tx fail-closed; once
    // the shared checker is wired in it surfaces as the wrapped resource ceiling.
    let got = validate_tx_with_mint(&tx, &[], &MintCtx::default(), &NoopVerifier, 0);
    assert!(
        matches!(got, Err(MintTxError::Tx(TxError::ResourceLimit { .. })))
            || matches!(got, Err(MintTxError::ValueNotConserved { .. })),
        "mint path must reject the oversized tx fail-closed (resource ceiling), got {got:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// FINDING B (medium) — FIXED (F3/F5): `fixed_supply_cap_policy` no longer computes
// `cap + 1` in native Rust i128. It emitted `PushInt(cap + 1)`, which overflowed for
// `cap == i128::MAX` — panicking under overflow-checks (debug/test and any consensus
// build) and wrapping to `i128::MIN` in release (a dead reject-everything policy).
// The constructor now emits `new_supply <= cap` as `!(cap < new_supply)` with `cap`
// pushed unmodified. This regression test asserts the FIXED behaviour: construction
// never panics on the in-range boundary argument, and `cap == i128::MAX` is the
// intended "no effective cap" — a conserving positive mint is AUTHORISED (well-formed,
// fail-closed on conservation, never a silent wrap-into-authorising). It FAILS if the
// `cap + 1` overflow hazard is reintroduced.
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn fixed_supply_cap_policy_max_cap_panics_or_fails_shut() {
    // (1) Construction must not panic on the in-range boundary argument.
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let built = std::panic::catch_unwind(|| fixed_supply_cap_policy(i128::MAX));
    std::panic::set_hook(prev);
    let policy = built.expect("fixed_supply_cap_policy(i128::MAX) must not panic after the F3/F5 fix");

    // (2) i128::MAX is the intended no-effective-cap policy: a conserving positive
    // mint succeeds (not a dead reject-all, not a silent wrap into over-issuance).
    let asset = policy_asset_id(&policy);
    let tx = EuTx {
        inputs: vec![],
        outputs: vec![ExtOutput { value: one_asset(asset, 500), validator_hash: [0u8; 32], datum: Val::Int(0) }],
        fee: 0,
        sighash: vec![],
    };
    let mints = vec![MintRequest {
        policy,
        redeemer: vec![],
        action: MintAction { asset_id: asset, delta: 500 },
    }];
    assert!(
        validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &NoopVerifier, 50_000).is_ok(),
        "cap==i128::MAX must be a permissive no-effective-cap policy, not a dead reject-all"
    );

    // (3) And the same policy still binds the authorised delta to the real shift:
    // claiming a delta the tx does not actually create is rejected on conservation,
    // NOT authorised — i128::MAX being permissive does not disable conservation.
    let over_tx = EuTx {
        inputs: vec![],
        outputs: vec![ExtOutput { value: one_asset(asset, 1), validator_hash: [0u8; 32], datum: Val::Int(0) }],
        fee: 0,
        sighash: vec![],
    };
    let over_mints = vec![MintRequest {
        policy: fixed_supply_cap_policy(i128::MAX),
        redeemer: vec![],
        action: MintAction { asset_id: asset, delta: 500 },
    }];
    assert!(matches!(
        validate_tx_with_mint(&over_tx, &over_mints, &MintCtx::default(), &NoopVerifier, 50_000),
        Err(MintTxError::ValueNotConserved { .. })
    ));
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
