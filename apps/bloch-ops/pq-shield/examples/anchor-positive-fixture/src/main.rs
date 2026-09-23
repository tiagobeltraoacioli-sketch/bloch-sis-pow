//! Disposable, publicly reproducible test signer. Never use this seed for funds.
use bloch_pq_vault::anchor::{sign_anchor, PqShieldAnchor, TargetChain, ANCHOR_VERSION};
use serde_json::json;

fn main() {
    // Public fixture seed. The derived private key is intentionally NOT secure.
    let (pubkey, secret) = bloch_crypto::crypto::generate_keypair_from_seed(&[0x42; 32])
        .expect("test key generation");
    let anchor = PqShieldAnchor {
        version: ANCHOR_VERSION,
        target_chain: TargetChain::Bitcoin,
        btc_vault_address: b"bcrt1qtestvaultonly".to_vec(),
        recovery_hash: [0x5a; 32],
        pq_recovery_pubkey: pubkey.clone(),
        designated_safe_dest: b"bcrt1qtestsafedestinationonly".to_vec(),
        csv_delay: 144,
        policy: b"disposable-local-integration-test".to_vec(),
    };
    let signed = sign_anchor(&anchor, &secret).expect("test signature");
    println!("{}", json!({
        "fields": {
            "target_chain": "bitcoin",
            "btc_vault_address": "bcrt1qtestvaultonly",
            "recovery_hash": hex::encode(anchor.recovery_hash),
            "pq_recovery_pubkey": hex::encode(&pubkey),
            "designated_safe_dest": "bcrt1qtestsafedestinationonly",
            "csv_delay": 144,
            "policy": "disposable-local-integration-test"
        },
        "commitment_bytes_hex": hex::encode(anchor.commitment_bytes()),
        "signature": hex::encode(&signed.signature),
        "signed_anchor_hex": hex::encode(signed.serialize())
    }));
}
