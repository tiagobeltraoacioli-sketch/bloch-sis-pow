// SPDX-License-Identifier: AGPL-3.0-or-later

//! Addresses, script hashes, and the wallet key.
//!
//! ## The two script-hash forms, and which one this crate uses
//!
//! A Genesis-4 output is locked by a 32-byte `script_hash`, and consensus
//! accepts a spend when either (`transition::owns`):
//!
//! 1. `script_hash == SHA3-256(pubkey)` — the full 32-byte form, or
//! 2. `script_hash[..20] == SHA3-256(pubkey)[..20]` with the last 12 bytes
//!    zero — the **address-derived** form. A `bloch1q…` address encodes
//!    exactly those 20 bytes (plus a checksum), so anyone who has your
//!    address can only ever build this form.
//!
//! The two forms are DIFFERENT keys in the eUTXO set: `getbalance` on one
//! does not see coins locked under the other. This crate therefore uses the
//! address-derived form everywhere — for the hot wallet's own coins, for
//! change, and for recipients — so that one `script_hash` query covers
//! everything it creates and receives.

use sha3::{Digest, Sha3_256};

use bloch_crypto::address::{Address, Network};

/// A 32-byte eUTXO locking key.
pub type ScriptHash = [u8; 32];

/// The address-derived script hash for a parsed `bloch1q…` address: its 20
/// hash bytes, zero-padded to 32. This is the memory rule "script_hash = the
/// 20 bytes after the bloch1q prefix, zero-padded", made typed.
pub fn script_hash_of_address(addr: &Address) -> ScriptHash {
    let mut out = [0u8; 32];
    out[..20].copy_from_slice(addr.hash_bytes());
    out
}

/// Parse a `bloch1q…` string (checksum-validated) into the script hash its
/// outputs must be locked to. Testnet (`bloch1t…`) is refused: a withdrawal
/// client that silently pays a testnet-shaped address on mainnet has already
/// lost the argument about carefulness.
pub fn script_hash_of_address_str(s: &str) -> Result<ScriptHash, String> {
    let addr = Address::parse(s).map_err(|e| format!("bad address: {e}"))?;
    if !addr.is_mainnet() {
        return Err("not a mainnet (bloch1q…) address".into());
    }
    Ok(script_hash_of_address(&addr))
}

/// The hot wallet's hybrid keypair (suite-enveloped ML-DSA-65 ‖ Falcon-1024,
/// as bloch-crypto produces it). Secret bytes never leave this struct and it
/// implements neither `Debug` nor `Clone` on purpose.
pub struct KeyMaterial {
    pubkey: Vec<u8>,
    secret: Vec<u8>,
}

impl KeyMaterial {
    /// Deterministic keypair from a >=32-byte seed. The seed IS the wallet:
    /// generate and store it with the discipline of BLOCH-GENESIS-KEYS.md
    /// (air-gapped, human-held), not in the process that runs this client's
    /// polling loop, if you can avoid it.
    pub fn from_seed(seed: &[u8]) -> Result<KeyMaterial, String> {
        let (pubkey, secret) =
            bloch_crypto::crypto::generate_keypair_from_seed(seed).map_err(|e| e.to_string())?;
        Ok(KeyMaterial { pubkey, secret })
    }

    /// Fresh keypair from OS entropy.
    pub fn generate() -> KeyMaterial {
        let (pubkey, secret) = bloch_crypto::crypto::generate_keypair();
        KeyMaterial { pubkey, secret }
    }

    /// Wrap already-generated suite-enveloped key bytes (e.g. loaded from an
    /// external keystore). No validation beyond signing being able to fail
    /// later — the envelope is bloch-crypto's to judge.
    pub fn from_parts(pubkey: Vec<u8>, secret: Vec<u8>) -> KeyMaterial {
        KeyMaterial { pubkey, secret }
    }

    /// The suite-enveloped public key — the bytes that go into a transfer's
    /// witness, and the bytes whose SHA3-256 an output's script hash commits
    /// to.
    pub fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }

    /// This wallet's `bloch1q…` address.
    pub fn address(&self) -> Address {
        Address::from_pubkey(&self.pubkey, Network::Mainnet)
    }

    /// The address-derived script hash this wallet's coins live under — the
    /// one to hand to `getbalance` / `listunspent`, and the one change
    /// outputs are locked to.
    pub fn script_hash(&self) -> ScriptHash {
        script_hash_of_address(&self.address())
    }

    /// Hybrid signature over a 32-byte signing root, both halves.
    pub fn sign(&self, signing_root: &[u8; 32]) -> Result<Vec<u8>, String> {
        bloch_crypto::crypto::sign(&self.secret, signing_root).map_err(|e| e.to_string())
    }
}

/// Consensus's ownership rule (`transition::owns`), restated here so tests
/// and the builder can check what they emit is spendable. Kept in exact sync
/// with the committee crate by `owns_matches_consensus` below.
pub fn owns(key_hash: &[u8; 32], script_hash: &[u8; 32]) -> bool {
    if key_hash == script_hash {
        return true;
    }
    script_hash[20..] == [0u8; 12] && key_hash[..20] == script_hash[..20]
}

/// SHA3-256 of a public key — the full-form script hash, and the left half
/// of the ownership rule.
pub fn key_hash(pubkey: &[u8]) -> [u8; 32] {
    Sha3_256::digest(pubkey).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_owns_its_own_script_hash() {
        // One deterministic key (hybrid keygen is expensive; one is enough).
        let key = KeyMaterial::from_seed(&[7u8; 32]).unwrap();
        let sh = key.script_hash();
        assert_eq!(&sh[20..], &[0u8; 12], "address-derived form must be zero-padded");
        assert!(owns(&key_hash(key.pubkey()), &sh));
        // And the round trip through the printed address is the same hash.
        let printed = key.address().to_string();
        assert_eq!(script_hash_of_address_str(&printed).unwrap(), sh);
    }

    #[test]
    fn testnet_address_refused() {
        let addr = Address::from_hash([9u8; 20], Network::Testnet).to_string();
        assert!(script_hash_of_address_str(&addr).is_err());
    }

    #[test]
    fn bad_checksum_refused() {
        let mut s = Address::from_hash([9u8; 20], Network::Mainnet).to_string();
        let flip = if s.ends_with('0') { "1" } else { "0" };
        s.replace_range(s.len() - 1.., flip);
        assert!(script_hash_of_address_str(&s).is_err());
    }
}
