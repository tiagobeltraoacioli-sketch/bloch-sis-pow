//! Coherence C2: shielded transactions survive the block wire format
//! (to_bitcoin_bytes ↔ from_bitcoin_bytes), and empty-shielded blocks still
//! round-trip (genesis-preserving).

use bloch::coherence::{
    NoteCiphertext, ShieldedTx,
    NOTE_AEAD_NONCE_LEN, NOTE_AEAD_TAG_LEN, NOTE_KEM_CT_LEN, NOTE_PLAINTEXT_LEN,
};
use bloch::core::{Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};

/// A wire-length-exact note ciphertext with recognizable filler bytes.
fn note_ct(fill: u8) -> NoteCiphertext {
    NoteCiphertext {
        kem_ct: vec![fill; NOTE_KEM_CT_LEN],
        nonce: [fill ^ 0x0F; NOTE_AEAD_NONCE_LEN],
        payload: vec![fill ^ 0xF0; NOTE_PLAINTEXT_LEN + NOTE_AEAD_TAG_LEN],
    }
}

fn coinbase() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: [0u8; 32], prev_index: u32::MAX,
            script_sig: b"coherence-serde".to_vec(), sequence: u32::MAX,
        }],
        outputs: vec![TxOutput { value: 100, script_pubkey: vec![1u8; 20] }],
        locktime: 0,
    }
}

fn block_with(shielded: Vec<ShieldedTx>) -> Block {
    let cb = coinbase();
    Block {
        header: BlockHeader {
            version: 1, parents: vec![],
            merkle_root: Transaction::merkle_root(&[cb.clone()]),
            timestamp: 1, bits: 0x2100ffff, nonce: 0,
        },
        transactions: vec![cb],
        blue_score: 0,
        height: 1,
        pow_solution: vec![],
        shielded_transactions: shielded,
        auxpow: None,
    }
}

#[test]
fn shielded_txs_survive_the_block_wire_format() {
    let stx = ShieldedTx {
        anchor: [7u8; 32],
        nullifiers: vec![[1u8; 32], [2u8; 32]],
        outputs: vec![[3u8; 32]],
        output_ciphertexts: vec![note_ct(0xAB)],
        fee: 5,
        proof: vec![9, 9, 9, 9],
        binding_sig: vec![8, 8],
    };
    let block = block_with(vec![stx.clone()]);
    let parsed = Block::from_bitcoin_bytes(&block.to_bitcoin_bytes()).expect("round-trip");

    assert_eq!(parsed.shielded_transactions.len(), 1);
    let p = &parsed.shielded_transactions[0];
    assert_eq!(p.anchor, stx.anchor);
    assert_eq!(p.nullifiers, stx.nullifiers);
    assert_eq!(p.outputs, stx.outputs);
    // Note ciphertext survives the wire byte-for-byte (kem_ct, nonce, payload).
    assert_eq!(p.output_ciphertexts, stx.output_ciphertexts);
    assert_eq!(p.fee, stx.fee);
    assert_eq!(p.proof, stx.proof);
    assert_eq!(p.binding_sig, stx.binding_sig);
}

#[test]
fn parser_rejects_wrong_length_note_ciphertext_components() {
    // A kem_ct that is not exactly NOTE_KEM_CT_LEN (ML-KEM-1024: 1568) bytes
    // must be rejected at parse time (mirrors the "implausible proof length"
    // guards), not only at apply-time well-formedness checks.
    let mut bad_kem = note_ct(0x11);
    bad_kem.kem_ct.pop();
    let stx = ShieldedTx {
        anchor: [7u8; 32], nullifiers: vec![[1u8; 32]], outputs: vec![[3u8; 32]],
        output_ciphertexts: vec![bad_kem],
        fee: 5, proof: vec![9], binding_sig: vec![8],
    };
    let block = block_with(vec![stx]);
    assert!(Block::from_bitcoin_bytes(&block.to_bitcoin_bytes()).is_err(),
        "short kem_ct must fail to parse");

    // Same for a payload that is not NOTE_PLAINTEXT_LEN + NOTE_AEAD_TAG_LEN.
    let mut bad_payload = note_ct(0x22);
    bad_payload.payload.push(0);
    let stx = ShieldedTx {
        anchor: [7u8; 32], nullifiers: vec![[1u8; 32]], outputs: vec![[3u8; 32]],
        output_ciphertexts: vec![bad_payload],
        fee: 5, proof: vec![9], binding_sig: vec![8],
    };
    let block = block_with(vec![stx]);
    assert!(Block::from_bitcoin_bytes(&block.to_bitcoin_bytes()).is_err(),
        "oversized note payload must fail to parse");
}

#[test]
fn merkle_binds_shielded_txs_genesis_preserving() {
    // Empty shielded: body_merkle_root == transparent merkle (genesis-preserving).
    let b0 = block_with(vec![]);
    assert_eq!(b0.body_merkle_root(), Transaction::merkle_root(&b0.transactions));

    // With shielded: set the header to the body root → validate_merkle passes.
    let stx = ShieldedTx {
        anchor: [7u8; 32], nullifiers: vec![[1u8; 32]], outputs: vec![[3u8; 32]],
        output_ciphertexts: vec![note_ct(0xCD)],
        fee: 5, proof: vec![9, 9], binding_sig: vec![8],
    };
    let mut b = block_with(vec![stx.clone()]);
    // header still has the transparent-only root → mismatch now (shielded bound in)
    assert!(!b.validate_merkle(), "shielded present but header not updated → reject");
    b.header.merkle_root = b.body_merkle_root();
    assert!(b.validate_merkle(), "header = body root → accept");

    // Tampering a shielded tx breaks the commitment.
    b.shielded_transactions[0].fee = 999;
    assert!(!b.validate_merkle(), "tampered shielded tx must fail merkle");
}

#[test]
fn empty_shielded_block_round_trips() {
    let block = block_with(vec![]);
    let parsed = Block::from_bitcoin_bytes(&block.to_bitcoin_bytes()).expect("round-trip");
    assert!(parsed.shielded_transactions.is_empty());
    // transparent parts intact
    assert_eq!(parsed.transactions.len(), 1);
    assert_eq!(parsed.height, 1);
}
