//! # bloch-btc-wallet — a quantum-ready hybrid wallet identity (FOUNDATION)
//!
//! From ONE seed the Postern wallet derives BOTH:
//! - **standard Bitcoin addresses** (BIP-84 native SegWit `bc1q…` and BIP-86 Taproot
//!   `bc1p…`), via the audited `bitcoin` (rust-bitcoin) crate — usable for real BTC
//!   *today*; and
//! - a **companion post-quantum keypair** (hybrid ML-DSA-65 ‖ Falcon-1024), from the
//!   same seed, via `bloch-crypto`.
//!
//! So one backup phrase controls a classical BTC identity AND a PQ identity. The PQ
//! key is what guards value once it moves to a chain that verifies PQ (wBTC-PQ on
//! Bloch, via the `bloch-euvm` hybrid ECDSA+PQ validator) — and is ready for a future
//! Bitcoin PQ soft fork (BIP-360).
//!
//! ## Honest scope
//! - The **BTC address is classical secp256k1** — the companion PQ key does **not**
//!   make a native BTC coin quantum-safe (Bitcoin has no PQ opcode). The value is:
//!   one seed manages both, and the PQ key is ready for wBTC-PQ / a future soft fork.
//! - Standalone + tested; not wired into the node. Unaudited.

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::key::{CompressedPublicKey, TapTweak};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, KnownHrp, NetworkKind};
use std::str::FromStr;

/// A quantum-ready wallet identity derived from one seed.
#[derive(Clone, Debug)]
pub struct HybridIdentity {
    /// BIP-84 native SegWit v0 address (`bc1q…` on mainnet).
    pub btc_p2wpkh: String,
    /// BIP-86 Taproot address (`bc1p…` on mainnet).
    pub btc_p2tr: String,
    /// Compressed secp256k1 public key (33 bytes) for the BTC receive key.
    pub btc_pubkey: Vec<u8>,
    /// Hybrid ML-DSA-65 ‖ Falcon-1024 public key (enveloped) for the PQ identity.
    pub pq_pubkey: Vec<u8>,
    /// The Bloch address derived from the PQ public key (`bloch1q…`).
    pub bloch_address: String,
}

/// Derive the BTC receive key at the given BIP path and return (compressed pubkey,
/// p2wpkh address, p2tr address). `mainnet` selects the address HRP.
fn derive_btc(seed: &[u8], path: &str, mainnet: bool) -> (Vec<u8>, String, String) {
    let secp = Secp256k1::new();
    let net = if mainnet { NetworkKind::Main } else { NetworkKind::Test };
    let hrp = if mainnet { KnownHrp::Mainnet } else { KnownHrp::Testnets };
    let master = Xpriv::new_master(net, seed).expect("valid master");
    let dp = DerivationPath::from_str(path).expect("valid path");
    let xpriv = master.derive_priv(&secp, &dp).expect("derive");
    let kp = xpriv.to_keypair(&secp);
    let compressed = CompressedPublicKey(kp.public_key());
    let p2wpkh = Address::p2wpkh(&compressed, hrp).to_string();
    // BIP-86 key-path Taproot: tweak the internal key with no script.
    let (xonly, _parity) = kp.x_only_public_key();
    let p2tr = Address::p2tr(&secp, xonly, None, hrp).to_string();
    (compressed.to_bytes().to_vec(), p2wpkh, p2tr)
}

/// Derive the full quantum-ready identity from a seed. Uses account 0, first receive
/// index (BIP-84 `m/84'/0'/0'/0/0`, BIP-86 `m/86'/0'/0'/0/0`) for the BTC keys, and
/// the same seed for the hybrid PQ keypair.
pub fn derive_identity(seed: &[u8], mainnet: bool) -> HybridIdentity {
    let coin = if mainnet { "0'" } else { "1'" };
    let (btc_pubkey, btc_p2wpkh, _) = derive_btc(seed, &format!("m/84'/{coin}/0'/0/0"), mainnet);
    let (_, _, btc_p2tr) = derive_btc(seed, &format!("m/86'/{coin}/0'/0/0"), mainnet);

    let (pq_pubkey, _pq_secret) =
        bloch_crypto::crypto::generate_keypair_from_seed(seed).expect("pq keygen from seed");
    let net = if mainnet {
        bloch_crypto::address::Network::Mainnet
    } else {
        bloch_crypto::address::Network::Testnet
    };
    let bloch_address = bloch_crypto::address::Address::from_pubkey(&pq_pubkey, net).to_string();

    HybridIdentity { btc_p2wpkh, btc_p2tr, btc_pubkey, pq_pubkey, bloch_address }
}

/// Build the Bloch-side hybrid guard for wBTC-PQ: a 2-of-2 eUTXO validator requiring
/// BOTH this identity's BTC key (ECDSA) AND its PQ key (ML-DSA‖Falcon) to spend.
/// Returns the validator program; its `validator_hash` addresses the guarded output.
pub fn hybrid_wbtc_validator(btc_pubkey: &[u8], pq_pubkey: &[u8]) -> Vec<bloch_euvm::Op> {
    use bloch_euvm::Op;
    vec![
        // BTC leg: VerifyEcdsa(sighash, btc_pubkey, btc_sig) must hold
        Op::CtxField(0),
        Op::PushBytes(btc_pubkey.to_vec()),
        Op::Pick(3), // redeemer btc_sig (below datum+pq_sig — arranged by the spender)
        Op::VerifyEcdsa,
        Op::Verify,
        // PQ leg: VerifySig(sighash, pq_pubkey, pq_sig) must hold
        Op::CtxField(0),
        Op::PushBytes(pq_pubkey.to_vec()),
        Op::Pick(2), // redeemer pq_sig
        Op::VerifySig,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP-39 test seed for the canonical "abandon abandon … about" mnemonic.
    // (64-byte seed; BIP-84 vector: first mainnet receive addr is a known bc1q value.)
    fn abandon_seed() -> Vec<u8> {
        // seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic") for the all-"abandon"+"about" phrase
        hex(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        )
    }
    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn bip84_known_vector() {
        // Official BIP-84 test vector, account 0, first receiving address.
        let (_, p2wpkh, _) = derive_btc(&abandon_seed(), "m/84'/0'/0'/0/0", true);
        assert_eq!(p2wpkh, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    }

    #[test]
    fn bip86_known_vector() {
        // Official BIP-86 test vector, account 0, first receiving Taproot address.
        let (_, _, p2tr) = derive_btc(&abandon_seed(), "m/86'/0'/0'/0/0", true);
        assert_eq!(p2tr, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
    }

    #[test]
    fn hybrid_identity_from_one_seed() {
        let seed = abandon_seed();
        let id = derive_identity(&seed, true);
        // one seed → a real BTC address AND a Bloch PQ address
        assert!(id.btc_p2wpkh.starts_with("bc1q"));
        assert!(id.btc_p2tr.starts_with("bc1p"));
        assert!(id.bloch_address.starts_with("bloch1"));
        assert_eq!(id.btc_pubkey.len(), 33); // compressed secp256k1
        assert!(!id.pq_pubkey.is_empty());
        // deterministic: same seed → same identity
        let id2 = derive_identity(&seed, true);
        assert_eq!(id.btc_p2wpkh, id2.btc_p2wpkh);
        assert_eq!(id.bloch_address, id2.bloch_address);
        assert_eq!(id.pq_pubkey, id2.pq_pubkey);
    }

    #[test]
    fn hybrid_validator_hash_is_stable() {
        let seed = abandon_seed();
        let id = derive_identity(&seed, true);
        let v1 = hybrid_wbtc_validator(&id.btc_pubkey, &id.pq_pubkey);
        let v2 = hybrid_wbtc_validator(&id.btc_pubkey, &id.pq_pubkey);
        assert_eq!(bloch_euvm::validator_hash(&v1), bloch_euvm::validator_hash(&v2));
        // a different BTC key → a different guard
        let other = hybrid_wbtc_validator(&[2u8; 33], &id.pq_pubkey);
        assert_ne!(bloch_euvm::validator_hash(&v1), bloch_euvm::validator_hash(&other));
    }
}
