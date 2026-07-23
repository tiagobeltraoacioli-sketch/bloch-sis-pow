//! Audit lens: DETERMINISM / consensus-split hunt — commitment-binding repro.
//!
//! Separate file so the existing tests/audit_determinism.rs is left untouched.
//!
//! Positive confirmations (encode_program / SMT root are byte-stable and order-
//! independent) plus the F1 regression guard: accept_block_model now commits a real
//! SparseMerkleTree root over the resulting eUTXO state (carrying n_txs/gas/burned/
//! to_miner as bound side-data), so two blocks carrying DIFFERENT eUTXO transactions
//! commit DIFFERENT bytes. Determinism holds AND state-binding holds; if the harness
//! ever reverts to a scalar summary these tests fail (the blocks collide again).

use bloch_euvm::harness::{
    accept_block_model, BlockModel, DEFAULT_GAS_CEILINGS, EUVM_ACTIVATION_HEIGHT,
};
use bloch_euvm::state::SparseMerkleTree;
use bloch_euvm::{blch, encode_program, validator_hash, EuTx, EuTxInput, ExtOutput, Op, SigVerifier, Val};

struct NoSig;
impl SigVerifier for NoSig {
    fn verify(&self, _m: &[u8], _p: &[u8], _s: &[u8]) -> bool {
        false
    }
}

fn anyone_tx(value: u64, datum: i128) -> EuTx {
    let prog = vec![Op::PushInt(1)];
    let vh = validator_hash(&prog);
    EuTx {
        inputs: vec![EuTxInput {
            prev_output: ExtOutput { value: blch(value), validator_hash: vh, datum: Val::Int(0) },
            validator: prog.clone(),
            redeemer: vec![],
        }],
        outputs: vec![ExtOutput { value: blch(value), validator_hash: vh, datum: Val::Int(datum) }],
        fee: 0,
        sighash: vec![],
    }
}

// ── positive determinism confirmations (must PASS) ──

#[test]
fn encode_program_and_hash_are_byte_stable() {
    let p = vec![
        Op::PushInt(-1),
        Op::PushBytes(vec![0xde, 0xad, 0xbe, 0xef]),
        Op::Pick(3),
        Op::Sha256d,
        Op::TxOutAsset(2),
        Op::VerifyEcdsa,
    ];
    let a = encode_program(&p);
    for _ in 0..1000 {
        assert_eq!(encode_program(&p), a);
        assert_eq!(validator_hash(&p), validator_hash(&p));
    }
}

#[test]
fn smt_root_is_insertion_order_independent() {
    let mut a = SparseMerkleTree::new();
    for (k, v) in [(&b"z"[..], &b"1"[..]), (b"a", b"2"), (b"m", b"3"), (b"", b"4")] {
        a.insert(k, v);
    }
    let mut b = SparseMerkleTree::new();
    b.insert(b"", b"4");
    b.insert(b"m", b"3");
    b.insert(b"z", b"WRONG");
    b.insert(b"a", b"2");
    b.insert(b"z", b"1"); // corrected
    assert_eq!(a.root(), b.root());
}

// ── FINDING repro: committed bytes do not bind the eUTXO state ──

#[test]
fn committed_bytes_do_not_bind_eutxo_state_two_distinct_blocks_collide() {
    let v = NoSig;
    let legacy = b"CANONICAL-LEGACY-PREFIX".to_vec();

    let block_a = BlockModel {
        height: EUVM_ACTIVATION_HEIGHT,
        legacy_bytes: legacy.clone(),
        eu_txs: vec![anyone_tx(100, 0)],
    };
    let block_b = BlockModel {
        height: EUVM_ACTIVATION_HEIGHT,
        legacy_bytes: legacy.clone(),
        eu_txs: vec![anyone_tx(999, 0)], // different BLCH moved
    };

    let out_a = accept_block_model(&block_a, &v, DEFAULT_GAS_CEILINGS).unwrap();
    let out_b = accept_block_model(&block_b, &v, DEFAULT_GAS_CEILINGS).unwrap();

    assert_ne!(
        block_a.eu_txs[0].inputs[0].prev_output.value,
        block_b.eu_txs[0].inputs[0].prev_output.value,
        "the two blocks must carry genuinely different eUTXO state"
    );
    assert!(out_a.feature_active && out_b.feature_active);

    // F1 FIXED: the commitment now binds the resulting eUTXO state (a SparseMerkleTree
    // root), so two blocks moving different BLCH produce DIFFERENT committed bytes.
    // (Regression guard: if the harness ever reverts to a scalar summary, these two
    // blocks collide again and this assertion fails.)
    assert_ne!(
        out_a.committed_bytes, out_b.committed_bytes,
        "committed bytes must diverge for two DIFFERENT eUTXO states — \
         the commitment binds a state root, not just a summary"
    );
}

#[test]
fn distinct_output_datums_produce_the_same_commitment() {
    let v = NoSig;
    let legacy = b"L".to_vec();
    let mk = |datum: i128| BlockModel {
        height: EUVM_ACTIVATION_HEIGHT,
        legacy_bytes: legacy.clone(),
        eu_txs: vec![anyone_tx(50, datum)],
    };
    let a = accept_block_model(&mk(0), &v, DEFAULT_GAS_CEILINGS).unwrap();
    let b = accept_block_model(&mk(7), &v, DEFAULT_GAS_CEILINGS).unwrap();
    // F1 FIXED: the output datum is part of the committed leaf, so distinct datums
    // (0 vs 7) now produce distinct commitments — the state is bound.
    assert_ne!(
        a.committed_bytes, b.committed_bytes,
        "distinct output datums must produce distinct commitments — state is bound"
    );
}
