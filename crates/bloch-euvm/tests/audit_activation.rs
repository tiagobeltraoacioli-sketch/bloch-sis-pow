//! Adversarial audit — lens: Activation / feature-off / crypto wiring.
//! Integration tests (do NOT edit src/ or other tests). Each test demonstrates one
//! concrete way to violate (or confirm) an invariant of harness.rs / lib.rs.

use bloch_euvm::harness::{
    accept_block_model, is_feature_active, AcceptOutcome, BlockModel, GasCeilings,
    DEFAULT_GAS_CEILINGS, EUVM_ACTIVATION_HEIGHT,
};
use bloch_euvm::{
    blch, validate_tx, validator_hash, ExtOutput, EuTx, EuTxInput, Op, SigVerifier, TxError, Val,
};

// ── verifiers ────────────────────────────────────────────────────────────────

/// Fail-closed PQ verifier that accepts exactly one (msg, pk, sig) triple. It does
/// NOT override `verify_ecdsa`, so ECDSA checks fall through to the trait default.
struct PqOnlyVerifier {
    good: (Vec<u8>, Vec<u8>, Vec<u8>),
}
impl SigVerifier for PqOnlyVerifier {
    fn verify(&self, msg: &[u8], pk: &[u8], sig: &[u8]) -> bool {
        (msg, pk, sig) == (self.good.0.as_slice(), self.good.1.as_slice(), self.good.2.as_slice())
    }
    // verify_ecdsa intentionally NOT implemented — uses the default (returns false).
}

// ─────────────────────────────────────────────────────────────────────────────
// FINDING A — active-path `committed_bytes` does not bind the eUTXO state.
// Two blocks with DIFFERENT outputs (different committed value distribution) but the
// same (tx count, gas used, fee split) produce BYTE-IDENTICAL committed_bytes.
// A commitment that does not bind the transactions/state it commits is not a sound
// consensus commitment: nodes that disagree on eUTXO state would not diverge here,
// and an adversary can swap the block's real effect while preserving the summary.
// ─────────────────────────────────────────────────────────────────────────────

fn anyone_tx(value: u64, fee: u64) -> EuTx {
    let prog = vec![Op::PushInt(1)];
    let vh = validator_hash(&prog);
    EuTx {
        inputs: vec![EuTxInput {
            prev_output: ExtOutput { value: blch(value), validator_hash: vh, datum: Val::Int(0) },
            validator: prog,
            redeemer: vec![],
        }],
        outputs: vec![ExtOutput { value: blch(value - fee), validator_hash: vh, datum: Val::Int(0) }],
        fee,
        sighash: vec![],
    }
}

#[test]
fn finding_a_committed_bytes_do_not_bind_eutxo_state() {
    struct Noop;
    impl SigVerifier for Noop {
        fn verify(&self, _m: &[u8], _p: &[u8], _s: &[u8]) -> bool { false }
    }
    let v = Noop;
    let legacy = b"LEGACY".to_vec();

    // Two DIFFERENT blocks: same tx count (1), same validator program (=> same gas),
    // same fee (=> same burn split), but WILDLY different committed value/outputs.
    let block_small = BlockModel { height: EUVM_ACTIVATION_HEIGHT, legacy_bytes: legacy.clone(), eu_txs: vec![anyone_tx(100, 10)] };
    let block_huge  = BlockModel { height: EUVM_ACTIVATION_HEIGHT, legacy_bytes: legacy.clone(), eu_txs: vec![anyone_tx(1_000_000, 10)] };

    let out_small: AcceptOutcome = accept_block_model(&block_small, &v, DEFAULT_GAS_CEILINGS).unwrap();
    let out_huge:  AcceptOutcome = accept_block_model(&block_huge, &v, DEFAULT_GAS_CEILINGS).unwrap();

    // The two blocks move very different amounts of value (90 vs 999_990 BLCH out)...
    assert_ne!(block_small.eu_txs[0].outputs, block_huge.eu_txs[0].outputs);
    // ...yet the node's committed bytes are byte-for-byte identical. The commitment
    // binds only the 36-byte summary (count/gas/burn/miner), not the eUTXO state root.
    assert_eq!(
        out_small.committed_bytes, out_huge.committed_bytes,
        "committed_bytes MUST differ when the committed eUTXO state differs"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// FINDING B — sighash is taken verbatim from the tx and never bound to tx contents.
// `validate_tx` sets ctx.fields[0] = tx.sighash directly. A signature that verifies
// over a sighash S therefore authorizes ANY transaction that merely DECLARES
// sighash == S, regardless of that tx's actual outputs. One valid signature can be
// replayed into a different tx with different outputs. The reference model omits the
// sighash-over-tx-contents computation the node must perform.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn finding_b_signature_not_bound_to_tx_outputs() {
    let msg = b"SIGHASH-S".to_vec(); // attacker declares this; unrelated to outputs
    let pk = b"victim-pubkey".to_vec();
    let sig = b"victim-sig".to_vec();

    // Validator: verify a signature over ctx.fields[0] (the declared sighash).
    let prog = vec![
        Op::CtxField(0),
        Op::PushBytes(pk.clone()),
        Op::PushBytes(sig.clone()),
        Op::VerifySig,
    ];
    let vh = validator_hash(&prog);
    let v = PqOnlyVerifier { good: (msg.clone(), pk.clone(), sig.clone()) };

    let mk = |out_value: u64| EuTx {
        inputs: vec![EuTxInput {
            prev_output: ExtOutput { value: blch(100), validator_hash: vh, datum: Val::Int(0) },
            validator: prog.clone(),
            redeemer: vec![],
        }],
        // Same sighash S declared, but the recipient/amount split differs per tx.
        outputs: vec![ExtOutput { value: blch(out_value), validator_hash: vh, datum: Val::Int(0) }],
        fee: 100 - out_value,
        sighash: msg.clone(),
    };

    // The SAME signature authorizes two DIFFERENT transactions (different fee/output
    // split) because nothing binds the signed sighash to the tx it authorizes.
    let tx_a = mk(90); // pays 10 fee, 90 to output
    let tx_b = mk(0);  // pays 100 fee, 0 to output — a completely different effect
    assert_ne!(tx_a.outputs, tx_b.outputs);
    assert!(validate_tx(&tx_a, &v, 10_000).is_ok(), "tx_a authorized");
    assert!(validate_tx(&tx_b, &v, 10_000).is_ok(), "tx_b authorized by the SAME sig — replay");
}

// ─────────────────────────────────────────────────────────────────────────────
// FINDING C — `verify_ecdsa` default-false silently locks ECDSA-only validators.
// A host verifier that implements only the PQ `verify` (forgetting verify_ecdsa)
// makes every VerifyEcdsa return false, so a wBTC/BTC-custody output guarded by an
// ECDSA check is permanently unspendable even with a correct signature. Fail-closed,
// but there is no compile-time signal the real verifier MUST override it.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn finding_c_ecdsa_only_validator_unspendable_under_pq_only_verifier() {
    let msg = b"sighash".to_vec();
    let pk = b"btc-pubkey".to_vec();
    let sig = b"btc-sig".to_vec();

    // ECDSA-only validator: assert an ECDSA signature verifies.
    let prog = vec![
        Op::CtxField(0),
        Op::PushBytes(pk.clone()),
        Op::PushBytes(sig.clone()),
        Op::VerifyEcdsa,
    ];
    let vh = validator_hash(&prog);

    let tx = EuTx {
        inputs: vec![EuTxInput {
            prev_output: ExtOutput { value: blch(100), validator_hash: vh, datum: Val::Int(0) },
            validator: prog,
            redeemer: vec![],
        }],
        outputs: vec![ExtOutput { value: blch(100), validator_hash: vh, datum: Val::Int(0) }],
        fee: 0,
        sighash: msg.clone(),
    };

    // A PQ-only verifier does not override verify_ecdsa -> default false -> the
    // validator returns 0 -> the spend is rejected though the sig is "correct".
    let pq_only = PqOnlyVerifier { good: (msg.clone(), pk.clone(), sig.clone()) };
    assert_eq!(
        validate_tx(&tx, &pq_only, 10_000),
        Err(TxError::ValidatorRejected(0)),
        "ECDSA-only output is unspendable because verify_ecdsa fell through to default-false"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// CONTROL — height gate & feature-off are CLEAN (confirming, not attacking).
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn control_height_gate_and_feature_off_are_clean() {
    // Sentinel inert: no realistic height activates.
    assert_eq!(EUVM_ACTIVATION_HEIGHT, u64::MAX);
    for h in [0u64, 1, 2_400, 3_000, 21_000_000, u64::MAX - 1] {
        assert!(!is_feature_active(h));
    }
    // Exact, off-by-one-clean flip.
    assert!(!is_feature_active(u64::MAX - 1));
    assert!(is_feature_active(u64::MAX));

    // Feature-off byte identity, even with (malformed) eu_txs present.
    struct Noop;
    impl SigVerifier for Noop {
        fn verify(&self, _m: &[u8], _p: &[u8], _s: &[u8]) -> bool { false }
    }
    let legacy = b"CANONICAL".to_vec();
    let b = BlockModel {
        height: EUVM_ACTIVATION_HEIGHT - 1,
        legacy_bytes: legacy.clone(),
        eu_txs: vec![anyone_tx(100, 10)],
    };
    let out = accept_block_model(&b, &Noop, GasCeilings { per_tx: 0, block: 0 }).unwrap();
    assert!(!out.feature_active);
    assert_eq!(out.committed_bytes, legacy);
    assert_eq!((out.eu_gas_used, out.total_fee, out.fee_burned, out.fee_to_miner), (0, 0, 0, 0));
}
