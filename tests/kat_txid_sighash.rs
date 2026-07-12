// ─────────────────────────────────────────────────────────────────────────────
// Self-referential regression vectors generated from this repository's own
// implementation — NOT independent/external test vectors, and NOT an audit.
// They detect drift, not correctness.
// ─────────────────────────────────────────────────────────────────────────────
//
// KAT: Transaction txid + sighash (external-style, public-API only).
//
// Exercises `bloch::core::{Transaction, TxInput, TxOutput}` through its public
// surface: txid(), sighash(), to_stratum_bytes(), from_stratum_bytes().
//
// The transaction inputs/outputs are fully specified in
// tests/vectors/kat_txid_sighash.json. All pinned outputs are pure functions of
// the tx bytes (SHA-256d for txid, SHA3-256 over a bincode encoding for sighash),
// so these are platform-stable regression anchors.
//
// Pins:
//   - txid (SHA-256d over stratum-format bytes, script_sig omitted for a
//     non-coinbase tx — the malleability-resistant form),
//   - sighash for input 0 (SIGHASH_ALL, as the CURRENT code computes it),
//   - the stratum wire bytes (include_script_sig = true),
//   - a from_stratum_bytes(to_stratum_bytes(true)) round-trip that reproduces
//     the same txid.
//
// NOTE ON SIGHASH SIGNATURE: this calls whatever `Transaction::sighash(index)`
// this worktree exposes. If a different developer changes the sighash algorithm
// or signature, that change is NOT in this worktree, so this vector pins the
// behaviour as it currently stands here.
//
// Unaudited software; the coin has no value. These are regression vectors,
// not proofs of correctness or security.

use bloch::core::{Transaction, TxInput, TxOutput};
use serde_json::Value;

fn load() -> Value {
    let path = format!("{}/tests/vectors/kat_txid_sighash.json", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    serde_json::from_str(&raw).expect("kat_txid_sighash.json must be valid JSON")
}

fn hexbytes(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex {s:?}: {e}"))
}

fn arr32(s: &str) -> [u8; 32] {
    let b = hexbytes(s);
    <[u8; 32]>::try_from(b.as_slice()).expect("expected 32-byte hex")
}

fn build_tx(v: &Value) -> Transaction {
    let t = &v["tx"];
    let inputs = t["inputs"].as_array().unwrap().iter().map(|i| TxInput {
        prev_txid: arr32(i["prev_txid"].as_str().unwrap()),
        prev_index: i["prev_index"].as_u64().unwrap() as u32,
        script_sig: hexbytes(i["script_sig"].as_str().unwrap()),
        sequence: i["sequence"].as_u64().unwrap() as u32,
    }).collect();
    let outputs = t["outputs"].as_array().unwrap().iter().map(|o| TxOutput {
        value: o["value"].as_u64().unwrap(),
        script_pubkey: hexbytes(o["script_pubkey"].as_str().unwrap()),
    }).collect();
    Transaction {
        version: t["version"].as_u64().unwrap() as u32,
        inputs,
        outputs,
        locktime: t["locktime"].as_u64().unwrap() as u32,
    }
}

#[test]
fn txid_and_sighash_are_stable() {
    let v = load();
    let tx = build_tx(&v);
    let expected = &v["expected"];

    assert!(!tx.is_coinbase(), "fixture is a non-coinbase tx");

    assert_eq!(
        hex::encode(tx.txid()),
        expected["txid"].as_str().unwrap(),
        "txid drifted from the pinned vector"
    );

    assert_eq!(
        hex::encode(tx.sighash(0)),
        expected["sighash_input_0"].as_str().unwrap(),
        "sighash(0) drifted from the pinned vector"
    );

    assert_eq!(
        hex::encode(tx.to_stratum_bytes(true)),
        expected["stratum_bytes_with_scriptsig"].as_str().unwrap(),
        "stratum wire bytes (with script_sig) drifted"
    );
}

#[test]
fn stratum_bytes_round_trip_preserves_txid() {
    let v = load();
    let tx = build_tx(&v);

    let wire = tx.to_stratum_bytes(true);
    let parsed = Transaction::from_stratum_bytes(&wire).expect("round-trip parse");

    assert_eq!(parsed.txid(), tx.txid(), "round-trip must preserve txid");
    assert_eq!(parsed.sighash(0), tx.sighash(0), "round-trip must preserve sighash");
    assert_eq!(parsed.inputs[0].script_sig, tx.inputs[0].script_sig, "script_sig preserved");
    assert_eq!(parsed.outputs[0].value, tx.outputs[0].value, "output value preserved");
}
