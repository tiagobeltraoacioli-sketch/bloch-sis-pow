//! Guards the security properties of `Transaction::sighash` (SIGHASH_ALL):
//! it must commit to every output, every input outpoint, and the signed input's
//! index — so signatures can't be replayed across txs or have outputs redirected.

use bloch::core::{Transaction, TxInput, TxOutput};

fn base() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![
            TxInput { prev_txid: [1u8; 32], prev_index: 0, script_sig: vec![], sequence: 0xffff_ffff },
            TxInput { prev_txid: [2u8; 32], prev_index: 1, script_sig: vec![], sequence: 0xffff_ffff },
        ],
        outputs: vec![TxOutput { value: 100, script_pubkey: vec![9u8; 20] }],
        locktime: 0,
    }
}

#[test]
fn sighash_binds_index_outputs_and_inputs_but_not_script_sig() {
    let tx = base();
    let h0 = tx.sighash(0);

    // Distinct per signed input.
    assert_ne!(h0, tx.sighash(1), "each input must sign a distinct hash");

    // Commits to outputs — no value or recipient can be changed post-signing.
    let mut v = base(); v.outputs[0].value = 101;
    assert_ne!(h0, v.sighash(0), "output value must be committed");
    let mut a = base(); a.outputs[0].script_pubkey = vec![8u8; 20];
    assert_ne!(h0, a.sighash(0), "output recipient must be committed");

    // Commits to input outpoints — no cross-tx replay onto different UTXOs.
    let mut i = base(); i.inputs[1].prev_txid = [7u8; 32];
    assert_ne!(h0, i.sighash(0), "input outpoints must be committed");

    // Does NOT commit to script_sig (you cannot sign your own signature) —
    // the sighash strips it, so a different script_sig yields the same hash.
    let mut s = base(); s.inputs[0].script_sig = vec![5, 5, 5];
    assert_eq!(h0, s.sighash(0), "script_sig must not affect the sighash");
}

#[test]
fn regular_txid_is_not_malleable_via_script_sig() {
    // A regular (non-coinbase) tx's txid must exclude script_sig, so a third
    // party can't malleate the signature to change the txid (the Mt.Gox class).
    let tx = base();
    assert!(!tx.is_coinbase(), "base() must be a regular tx for this test");
    let id = tx.txid();
    let mut m = base();
    m.inputs[0].script_sig = vec![1, 2, 3, 4, 5];
    assert_eq!(id, m.txid(), "regular txid must not depend on script_sig (no malleability)");
}
