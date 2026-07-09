//! Sprint AA.1 pt 2a — stratum-format transaction serialization.
//!
//! Locks in the Bitcoin-format byte layout of Transaction so that
//! external miners (who generate coinbase bytes client-side during
//! stratum submission) and the node (which parses those bytes into
//! Transaction objects) agree on every byte position.
//!
//! If any of these tests fail, the coinbase reconstruction path in
//! src/stratum/submit.rs will silently produce a Transaction whose
//! txid differs from what the miner used when walking their merkle
//! branch. Every share then gets rejected as merkle-mismatch.

use bloch::core::{Transaction, TxInput, TxOutput};

fn mk_coinbase() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [0u8; 32],
            prev_index: u32::MAX,
            script_sig: b"height:42|\xde\xad\xbe\xef\xca\xfe\xba\xbestratum-test".to_vec(),
            sequence:   u32::MAX,
        }],
        outputs: vec![
            TxOutput { value: 500_000_000, script_pubkey: vec![0x11; 20] },
            TxOutput { value: 10_000_000,  script_pubkey: vec![0x22; 20] },
        ],
        locktime: 0,
    }
}

fn mk_standard_tx() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [0xAA; 32],
            prev_index: 3,
            script_sig: vec![0x42; 96], // realistic signed input
            sequence:   u32::MAX,
        }],
        outputs: vec![
            TxOutput { value: 123_456_789, script_pubkey: vec![0x33; 20] },
        ],
        locktime: 0,
    }
}

#[test]
fn stratum_bytes_round_trip_with_script_sig() {
    let tx = mk_standard_tx();
    let bytes = tx.to_stratum_bytes(true);
    let reparsed = Transaction::from_stratum_bytes(&bytes).expect("round-trip");

    assert_eq!(reparsed.version, tx.version);
    assert_eq!(reparsed.inputs.len(), tx.inputs.len());
    assert_eq!(reparsed.inputs[0].prev_txid, tx.inputs[0].prev_txid);
    assert_eq!(reparsed.inputs[0].prev_index, tx.inputs[0].prev_index);
    assert_eq!(reparsed.inputs[0].script_sig, tx.inputs[0].script_sig);
    assert_eq!(reparsed.inputs[0].sequence, tx.inputs[0].sequence);
    assert_eq!(reparsed.outputs.len(), tx.outputs.len());
    assert_eq!(reparsed.outputs[0].value, tx.outputs[0].value);
    assert_eq!(reparsed.outputs[0].script_pubkey, tx.outputs[0].script_pubkey);
    assert_eq!(reparsed.locktime, tx.locktime);
}

#[test]
fn stratum_bytes_without_script_sig_omits_it_entirely() {
    // include_script_sig=false means the script_sig is NOT written
    // at all (not zero-length) — this matches Bitcoin's wtxid.
    let tx = mk_standard_tx();
    let with_sig = tx.to_stratum_bytes(true);
    let without_sig = tx.to_stratum_bytes(false);

    // "without" must be shorter by exactly the sig bytes plus the varint.
    let sig_len = tx.inputs[0].script_sig.len();
    let varint_len = if sig_len < 0xFD { 1 } else if sig_len <= 0xFFFF { 3 } else { 5 };
    assert_eq!(with_sig.len() - without_sig.len(), sig_len + varint_len);
}

#[test]
fn coinbase_txid_uses_script_sig_non_coinbase_does_not() {
    // Two tx with same fields except script_sig content.
    // Coinbase: txid depends on script_sig.
    // Non-coinbase: txid ignores script_sig (malleability fix).

    let base_coinbase = mk_coinbase();
    let mut modified_coinbase = base_coinbase.clone();
    modified_coinbase.inputs[0].script_sig.extend_from_slice(b"X");
    assert_ne!(base_coinbase.txid(), modified_coinbase.txid(),
        "coinbase txid MUST change when script_sig changes (extranonce effect)");

    let base_std = mk_standard_tx();
    let mut modified_std = base_std.clone();
    modified_std.inputs[0].script_sig.push(0x99);
    assert_eq!(base_std.txid(), modified_std.txid(),
        "non-coinbase txid must NOT change with script_sig (VULN-06 fix)");
}

#[test]
fn version_field_is_4_bytes_little_endian_at_offset_zero() {
    let mut tx = mk_standard_tx();
    tx.version = 0x04030201;
    let bytes = tx.to_stratum_bytes(true);
    assert_eq!(&bytes[0..4], &[0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn locktime_is_last_4_bytes_little_endian() {
    let mut tx = mk_standard_tx();
    tx.locktime = 0xAABBCCDD;
    let bytes = tx.to_stratum_bytes(true);
    let n = bytes.len();
    assert_eq!(&bytes[n - 4..], &[0xDD, 0xCC, 0xBB, 0xAA]);
}

#[test]
fn from_stratum_bytes_rejects_trailing_garbage_gracefully() {
    // Not strictly required — cursor-based parsing stops at locktime.
    // But trailing bytes are evidence of a bug upstream; document
    // current behavior so a future change is deliberate.
    let tx = mk_standard_tx();
    let mut bytes = tx.to_stratum_bytes(true);
    bytes.push(0xFF); // extra byte
    // Currently: parse succeeds and ignores trailing byte.
    let parsed = Transaction::from_stratum_bytes(&bytes);
    assert!(parsed.is_ok(), "current behavior: trailing bytes tolerated");
}

#[test]
fn from_stratum_bytes_rejects_truncated_input() {
    let tx = mk_standard_tx();
    let bytes = tx.to_stratum_bytes(true);
    let truncated = &bytes[..bytes.len() - 2]; // missing 2 bytes of locktime
    let parsed = Transaction::from_stratum_bytes(truncated);
    assert!(parsed.is_err(), "truncated input must error");
}

#[test]
fn txid_changes_when_output_value_changes() {
    let base = mk_standard_tx();
    let mut modified = base.clone();
    modified.outputs[0].value = base.outputs[0].value + 1;
    assert_ne!(base.txid(), modified.txid());
}

#[test]
fn coinbase_with_extranonce_round_trips() {
    // The actual stratum scenario: a coinbase whose script_sig contains
    // height prefix + extranonce + tag. Serializing and reparsing must
    // preserve every byte.
    let coinbase = mk_coinbase();
    let bytes = coinbase.to_stratum_bytes(true);
    let parsed = Transaction::from_stratum_bytes(&bytes).expect("coinbase round-trip");

    assert!(parsed.is_coinbase());
    assert_eq!(parsed.inputs[0].script_sig, coinbase.inputs[0].script_sig);
    assert_eq!(parsed.txid(), coinbase.txid());
}
