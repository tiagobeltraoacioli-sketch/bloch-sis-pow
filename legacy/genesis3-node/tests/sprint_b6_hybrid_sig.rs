//! Sprint B6b-2 — hybrid Falcon-1024 ‖ ML-DSA-65 signatures, end-to-end
//! through the real transaction path (sighash → build_script_sig →
//! parse_script_sig → crypto::verify), and the both-halves-required property.

use bloch::core::{Transaction, TxInput, TxOutput};
use bloch::crypto;

fn one_input_tx() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [7u8; 32],
            prev_index: 0,
            script_sig: vec![],
            sequence:   u32::MAX,
        }],
        outputs: vec![TxOutput { value: 1_000, script_pubkey: vec![0u8; 20] }],
        locktime: 0,
    }
}

#[test]
fn hybrid_signed_input_verifies_end_to_end() {
    let (pk, sk) = crypto::generate_keypair();
    let mut tx = one_input_tx();

    // Sign the input's sighash with the hybrid key, attach via the wire format.
    let sighash = tx.sighash(0, bloch::core::ChainId::Mainnet);
    let sig = crypto::sign(&sk, &sighash).expect("hybrid sign");
    tx.inputs[0].script_sig = Transaction::build_script_sig(&sig, &pk);

    // Consensus path: parse (sig, pubkey) back out, verify against the sighash.
    let (psig, ppk) = Transaction::parse_script_sig(&tx.inputs[0].script_sig)
        .expect("script_sig must parse");
    assert_eq!(ppk, pk, "recovered pubkey must match");
    assert!(crypto::verify(&ppk, &sighash, &psig), "hybrid-signed input must verify");

    // Tampering the Falcon half (last byte) must break verification.
    let mut bad = psig.clone();
    let n = bad.len();
    bad[n - 1] ^= 0x01;
    assert!(!crypto::verify(&ppk, &sighash, &bad), "tampered Falcon half must fail");
}

#[test]
fn hybrid_requires_both_halves() {
    let (pk, sk) = crypto::generate_keypair();
    let msg = b"both-halves-required";
    let full = crypto::sign(&sk, msg).unwrap();

    // ML-DSA half alone (Falcon dropped) must NOT verify — both are required.
    let mldsa_only = &full[..crypto::MLDSA_SIG_LEN];
    assert!(!crypto::verify(&pk, msg, mldsa_only), "ML-DSA half alone must not verify");

    // A random Falcon half with a valid ML-DSA half must also fail.
    let mut wrong_falcon = full.clone();
    for b in wrong_falcon[crypto::MLDSA_SIG_LEN..].iter_mut() { *b ^= 0xFF; }
    assert!(!crypto::verify(&pk, msg, &wrong_falcon), "corrupt Falcon half must fail");
}
