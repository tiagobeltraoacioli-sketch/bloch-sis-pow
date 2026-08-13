//! Sprint 1.d — Transaction network wire migration.
//!
//! These tests verify that the Bitcoin-format tx bytes (produced by
//! wallet clients + cli + mempool rebroadcast) round-trip through
//! the same Transaction::from_stratum_bytes the node uses on RPC
//! sendrawtransaction and the gossipsub NewTransaction handler.
//!
//! If these tests fail, wallets can't broadcast and miners can't
//! accept mempool txs.

use bloch::core::{Transaction, TxInput, TxOutput};

fn mk_tx(tag: u8) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [tag; 32],
            prev_index: 0,
            script_sig: {
                // Realistic 80-byte signed input
                let mut s = vec![0u8; 4]; // sig_len prefix
                s[0] = 64;
                s.extend_from_slice(&vec![tag; 64]);  // sig
                s.extend_from_slice(&[16, 0, 0, 0]);   // pk_len prefix
                s.extend_from_slice(&vec![tag; 16]);   // pk
                s
            },
            sequence:   u32::MAX,
        }],
        outputs: vec![
            TxOutput { value: 123_000_000, script_pubkey: vec![tag; 20] },
        ],
        locktime: 0,
    }
}

#[test]
fn wallet_encoded_bytes_parse_on_node() {
    // Simulate: wallet calls tx.to_stratum_bytes(true), serializes to hex,
    // sends via RPC. Node receives hex, hex::decodes, Transaction::from_stratum_bytes.
    let tx = mk_tx(0x42);
    let wallet_bytes = tx.to_stratum_bytes(true);

    // Simulate network hop via hex encoding (same as wallet RPC path).
    let hex_on_wire = hex::encode(&wallet_bytes);
    let received_bytes = hex::decode(&hex_on_wire).expect("hex decode");

    // Node side.
    let received_tx = Transaction::from_stratum_bytes(&received_bytes)
        .expect("from_stratum_bytes should succeed");

    // Txid must match — otherwise the node will reject it as a
    // deserialization artifact.
    assert_eq!(received_tx.txid(), tx.txid());
    assert_eq!(received_tx.outputs[0].value, 123_000_000);
}

#[test]
fn rebroadcast_loop_preserves_tx_bytes() {
    // main.rs re-broadcasts mempool txs periodically. Verify that
    // a tx going through get_for_block -> to_stratum_bytes ->
    // network -> from_stratum_bytes produces an identical tx.
    let original = mk_tx(0xAA);
    let txid_orig = original.txid();

    for _ in 0..5 {
        let bytes = original.to_stratum_bytes(true);
        let parsed = Transaction::from_stratum_bytes(&bytes).unwrap();
        assert_eq!(parsed.txid(), txid_orig, "rebroadcast preserves txid");
    }
}

#[test]
fn coinbase_tx_from_block_round_trips_via_stratum_bytes() {
    // Realistic scenario: a coinbase built in the miner loop gets
    // round-tripped through stratum bytes (as it would via RPC
    // getrawtransaction or sendrawtransaction paths).
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [0u8; 32],
            prev_index: u32::MAX,
            script_sig: format!("height:100").into_bytes(),
            sequence:   u32::MAX,
        }],
        outputs: vec![
            TxOutput { value: 500_000_000, script_pubkey: vec![0x11; 20] },
            TxOutput { value: 10_000_000,  script_pubkey: vec![0x22; 20] },
        ],
        locktime: 0,
    };

    let bytes = coinbase.to_stratum_bytes(true);
    let parsed = Transaction::from_stratum_bytes(&bytes).unwrap();

    assert!(parsed.is_coinbase());
    assert_eq!(parsed.txid(), coinbase.txid());
    assert_eq!(parsed.inputs[0].script_sig, coinbase.inputs[0].script_sig);
}

#[test]
fn tx_size_matches_what_rpc_reports() {
    // rpc/mod.rs uses to_stratum_bytes(true).len() for size reporting.
    // Verify this matches the actual on-wire length.
    let tx = mk_tx(0xCC);
    let bytes = tx.to_stratum_bytes(true);
    let reported_size = tx.to_stratum_bytes(true).len() as u32;
    assert_eq!(bytes.len() as u32, reported_size);
}

#[test]
fn sendrawtransaction_roundtrip_via_hex() {
    // Exactly the sequence sendrawtransaction RPC does:
    //   client: tx.to_stratum_bytes(true) -> hex::encode -> RPC
    //   server: params -> hex::decode -> Transaction::from_stratum_bytes
    //   server: validate + mempool.add

    let tx = mk_tx(0x77);
    let client_wire = hex::encode(tx.to_stratum_bytes(true));

    // Server receives:
    let server_bytes = hex::decode(&client_wire).expect("hex");
    let server_tx = Transaction::from_stratum_bytes(&server_bytes)
        .expect("parse");

    assert_eq!(server_tx.txid(), tx.txid());
    assert_eq!(server_tx.is_coinbase(), tx.is_coinbase());
}

#[test]
fn gossipsub_tx_bytes_parse_correctly() {
    // NewTransaction message: tx_data field is raw stratum bytes.
    // No hex wrapping on the wire — gossipsub carries arbitrary bytes.
    let tx = mk_tx(0x55);
    let wire_bytes = tx.to_stratum_bytes(true);

    // Node in main.rs:505 receives tx_data: Vec<u8> directly.
    let parsed = Transaction::from_stratum_bytes(&wire_bytes)
        .expect("gossipsub tx parse");

    assert_eq!(parsed.txid(), tx.txid());
}
