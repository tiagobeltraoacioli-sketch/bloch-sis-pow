// ─────────────────────────────────────────────────────────────────────────────
// Self-referential regression vectors generated from this repository's own
// implementation — NOT independent/external test vectors, and NOT an audit.
// They detect drift, not correctness.
// ─────────────────────────────────────────────────────────────────────────────
//
// KAT: Address derivation (external-style, public-API only).
//
// Exercises `bloch::address::{Address, Network}` through its public surface.
// Input: a FIXED, fully specified public-key byte string (see tests/vectors/
// kat_address.json — `pubkey_hex`). Address derivation is a pure hash
// (`SHA3-256(pubkey)[..20]` + a doubled-SHA3 4-byte checksum), so these vectors
// are platform-stable regression anchors.
//
// Pins, for the same fixed pubkey:
//   - the 20-byte on-chain address hash (hex),
//   - the human-readable Mainnet string (bloch1q…),
//   - the human-readable Testnet string (bloch1t…),
//   - and a parse round-trip (string → Address → same 20-byte hash).
//
// Unaudited software; the coin has no value. These are regression vectors,
// not proofs of correctness or security.

use bloch::address::{Address, Network};
use serde_json::Value;

fn load() -> Value {
    let path = format!("{}/tests/vectors/kat_address.json", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    serde_json::from_str(&raw).expect("kat_address.json must be valid JSON")
}

fn hexval(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap_or_else(|| panic!("missing string field {key}")))
        .unwrap_or_else(|e| panic!("field {key} is not valid hex: {e}"))
}

#[test]
fn address_hash_and_strings_are_stable() {
    let v = load();
    let pubkey = hexval(&v, "pubkey_hex");
    assert_eq!(pubkey.len(), v["pubkey_len"].as_u64().unwrap() as usize, "pubkey length");

    let expected = &v["expected"];

    // Both networks share the same 20-byte hash (only the string prefix differs).
    let addr_m = Address::from_pubkey(&pubkey, Network::Mainnet);
    let addr_t = Address::from_pubkey(&pubkey, Network::Testnet);

    assert_eq!(
        hex::encode(addr_m.hash_bytes()),
        expected["address_hash_hex"].as_str().unwrap(),
        "20-byte mainnet address hash drifted"
    );
    assert_eq!(
        hex::encode(addr_t.hash_bytes()),
        expected["address_hash_hex"].as_str().unwrap(),
        "20-byte testnet address hash drifted (must equal mainnet hash)"
    );

    assert_eq!(
        addr_m.to_string(),
        expected["mainnet_string"].as_str().unwrap(),
        "mainnet address string drifted"
    );
    assert_eq!(
        addr_t.to_string(),
        expected["testnet_string"].as_str().unwrap(),
        "testnet address string drifted"
    );

    // Structural sanity on the human-readable form.
    assert!(addr_m.to_string().starts_with("bloch1q"), "mainnet must start bloch1q");
    assert!(addr_t.to_string().starts_with("bloch1t"), "testnet must start bloch1t");
}

#[test]
fn address_string_round_trips_through_parse() {
    let v = load();
    let expected = &v["expected"];

    for (net_str, is_mainnet) in [("mainnet_string", true), ("testnet_string", false)] {
        let s = expected[net_str].as_str().unwrap();
        let parsed = Address::parse(s).expect("pinned address string must parse (checksum valid)");
        assert_eq!(parsed.is_mainnet(), is_mainnet, "network flag round-trip for {net_str}");
        assert_eq!(
            hex::encode(parsed.hash_bytes()),
            expected["address_hash_hex"].as_str().unwrap(),
            "parsed hash must equal pinned hash for {net_str}"
        );
        // Re-serialize must reproduce the exact pinned string.
        assert_eq!(parsed.to_string(), s, "re-serialization must be identical for {net_str}");
    }
}
