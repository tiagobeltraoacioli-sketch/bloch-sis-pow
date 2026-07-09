//! Bloch-SIS Protocol — HD Wallet (BIP39 mnemonic + ML-DSA-65 keys)
//!
//! Uses BIP39 24-word mnemonic as the master key for an encrypted wallet
//! containing multiple ML-DSA-65 keypairs. Optional passphrase supported
//! (Ledger/Trezor style).
//!
//! Backup requires BOTH: the mnemonic phrase AND the wallet file.
//! The mnemonic alone cannot reconstruct ML-DSA-65 keys (no lattice-based
//! deterministic derivation standard exists yet). When such a standard
//! emerges, this module will be upgraded.

use crate::crypto;
use crate::wallet::{Keypair, KdfParams, KeystoreCrypto};
use crate::core::TESTNET_PREFIX;
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use argon2::{Argon2, Algorithm, Version, Params};
use base64::{Engine as _, engine::general_purpose as b64};
use rand::RngCore;
use std::path::Path;
use bip39::Mnemonic;

// ── Encrypted HD Wallet file format ──────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct HdWalletFile {
    pub version:     u32,
    pub format:      String,            // "hd-wallet-v1"
    pub network:     String,
    pub mnemonic_crypto: KeystoreCrypto, // encrypted mnemonic (locked with passphrase+password)
    pub addresses:   Vec<HdAddress>,     // list of (index, address, encrypted_keypair)
    pub created_at:  String,
    pub description: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct HdAddress {
    pub index:   u32,
    pub address: String,
    pub label:   String,
    pub keypair_crypto: KeystoreCrypto,   // encrypted keypair for this index
}

// ── Internal encrypted payload structures ───────────────────────────────────

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct MnemonicPayload { mnemonic: String }

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct KeypairPayload { private_key_hex: String, public_key_hex: String }

// ── HD Wallet type ───────────────────────────────────────────────────────────

pub struct HdWallet {
    pub mnemonic: Mnemonic,
    pub master_key: Vec<u8>,      // derived from mnemonic + passphrase + password
    pub addresses: Vec<(u32, Keypair, String)>, // (index, keypair, label)
    pub network:  String,
}

impl Drop for HdWallet {
    fn drop(&mut self) { self.master_key.zeroize(); }
}

impl HdWallet {

    /// Create a new HD wallet: generates a 24-word mnemonic and the first keypair.
    pub fn create(
        password: &str,
        passphrase: Option<&str>,
        testnet: bool,
    ) -> Result<Self, String> {
        // Generate 256-bit entropy (24 words)
        let mut entropy = [0u8; 32];
        rand::rng().fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|e| format!("mnemonic generation failed: {}", e))?;

        // New wallets use the v2 per-wallet salt.
        let master_key = derive_master_key(&mnemonic.to_string(), passphrase.unwrap_or(""), password, 2)?;

        let kp = crate::wallet::generate_keypair(testnet);
        let network = if testnet { "testnet" } else { "mainnet" }.to_string();

        Ok(HdWallet {
            mnemonic,
            master_key,
            addresses: vec![(0, kp, "primary".to_string())],
            network,
        })
    }

    /// Add a new address to the wallet (generates a new keypair).
    pub fn new_address(&mut self, label: &str) -> &Keypair {
        let next_index = self.addresses.iter().map(|(i, _, _)| *i).max().unwrap_or(0) + 1;
        let testnet = self.network == "testnet";
        let kp = crate::wallet::generate_keypair(testnet);
        self.addresses.push((next_index, kp, label.to_string()));
        &self.addresses.last().unwrap().1
    }

    /// Import an existing keypair (e.g., from founder.json) into the HD wallet.
    pub fn import_keypair(&mut self, keypair: Keypair, label: &str) {
        let next_index = self.addresses.iter().map(|(i, _, _)| *i).max().unwrap_or(0) + 1;
        self.addresses.push((next_index, keypair, label.to_string()));
    }

    /// Get keypair at a given index.
    pub fn get(&self, index: u32) -> Option<&Keypair> {
        self.addresses.iter().find(|(i, _, _)| *i == index).map(|(_, kp, _)| kp)
    }

    /// Get keypair by address string.
    pub fn get_by_address(&self, address: &str) -> Option<&Keypair> {
        self.addresses.iter().find(|(_, kp, _)| kp.address == address).map(|(_, kp, _)| kp)
    }

    /// Save encrypted wallet file.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        // Encrypt mnemonic with master_key
        let mnemonic_crypto = encrypt_with_key(
            &self.master_key,
            &serde_json::to_vec(&MnemonicPayload { mnemonic: self.mnemonic.to_string() })
                .map_err(|e| e.to_string())?,
        )?;

        // Encrypt each keypair with master_key
        let mut addresses = Vec::new();
        for (idx, kp, label) in &self.addresses {
            let payload = KeypairPayload {
                private_key_hex: hex::encode(&kp.private_key),
                public_key_hex:  hex::encode(&kp.public_key),
            };
            let bytes = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
            let crypto = encrypt_with_key(&self.master_key, &bytes)?;
            addresses.push(HdAddress {
                index: *idx,
                address: kp.address.clone(),
                label: String::from(label),
                keypair_crypto: crypto,
            });
        }

        let wallet = HdWalletFile {
            version: 2, // v2: per-wallet Argon2 salt (v1 files still load via the legacy path)
            format: "hd-wallet-v1".into(),
            network: self.network.clone(),
            mnemonic_crypto,
            addresses,
            created_at: chrono::Utc::now().to_rfc3339(),
            description: "Bloch-SIS Protocol HD Wallet (BIP39 + ML-DSA-65)".into(),
        };

        let json = serde_json::to_string_pretty(&wallet).map_err(|e| e.to_string())?;
        // Sprint T.5 — Audit L-4: atomic write (temp + fsync + rename).
        crate::util::atomic_write(path, json.as_bytes()).map_err(|e| e.to_string())
    }

    /// Load and decrypt HD wallet file with mnemonic + passphrase + password.
    pub fn load(path: &Path, mnemonic_str: &str, passphrase: Option<&str>, password: &str) -> Result<Self, String> {
        let json = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let wallet: HdWalletFile = serde_json::from_str(&json).map_err(|e| e.to_string())?;
        if wallet.format != "hd-wallet-v1" { return Err("unsupported wallet format".into()); }

        // Parse mnemonic
        let mnemonic = Mnemonic::parse(mnemonic_str)
            .map_err(|e| format!("invalid mnemonic: {}", e))?;

        // Derive master key — route the salt by the file's version (v1 legacy
        // constant salt, v2+ per-wallet), so existing wallets still decrypt.
        let master_key = derive_master_key(&mnemonic.to_string(), passphrase.unwrap_or(""), password, wallet.version)?;

        // Verify mnemonic matches (by decrypting and comparing)
        let mnemonic_bytes = decrypt_with_key(&master_key, &wallet.mnemonic_crypto)?;
        let payload: MnemonicPayload = serde_json::from_slice(&mnemonic_bytes)
            .map_err(|e| format!("mnemonic decrypt failed — wrong password/passphrase/mnemonic ({})", e))?;
        if payload.mnemonic != mnemonic.to_string() {
            return Err("mnemonic mismatch — tampered file?".into());
        }

        // Decrypt each keypair
        let mut addresses = Vec::new();
        for addr in &wallet.addresses {
            let bytes = decrypt_with_key(&master_key, &addr.keypair_crypto)?;
            let mut kpp: KeypairPayload = serde_json::from_slice(&bytes)
                .map_err(|e| format!("keypair {} decrypt failed: {}", addr.index, e))?;
            let priv_key = hex::decode(&kpp.private_key_hex).map_err(|e| e.to_string())?;
            let pub_key  = hex::decode(&kpp.public_key_hex).map_err(|e| e.to_string())?;
            kpp.zeroize();

            let testnet = addr.address.starts_with(TESTNET_PREFIX);
            let derived = crypto::address_from_pubkey(&pub_key, testnet);
            if derived != addr.address {
                return Err(format!("address {} mismatch — tampered", addr.index));
            }

            let kp = Keypair {
                private_key: priv_key,
                public_key:  pub_key,
                address:     addr.address.clone(),
            };
            addresses.push((addr.index, kp, addr.label.clone()));
        }

        Ok(HdWallet { mnemonic, master_key, addresses, network: wallet.network })
    }

    /// List all addresses (for display).
    pub fn list(&self) -> Vec<(u32, String, String)> {
        self.addresses.iter().map(|(i, kp, label): &(u32, Keypair, String)| (*i, kp.address.clone(), label.clone())).collect()
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Derive the master encryption key from mnemonic + passphrase + password.
/// This is what locks/unlocks the wallet file.
fn derive_master_key(mnemonic: &str, passphrase: &str, password: &str, version: u32) -> Result<Vec<u8>, String> {
    // Combine mnemonic + passphrase + password into the KDF input
    let mut combined = Vec::with_capacity(mnemonic.len() + passphrase.len() + password.len() + 2);
    combined.extend_from_slice(mnemonic.as_bytes());
    combined.push(0);
    combined.extend_from_slice(passphrase.as_bytes());
    combined.push(0);
    combined.extend_from_slice(password.as_bytes());

    // Salt. v1 used ONE constant salt for every wallet — a real weakness (a
    // precomputation against one wallet transfers to all). Kept only so existing
    // v1 files still decrypt. v2+ binds the salt to the mnemonic, so it is unique
    // per wallet + deterministic (no stored salt, no format change).
    use sha3::{Sha3_256, Digest};
    let salt = if version >= 2 {
        let mut h = Sha3_256::new();
        h.update(b"bloch-sis/hd-wallet/salt/v2");
        h.update(mnemonic.as_bytes());
        h.finalize().to_vec()
    } else {
        Sha3_256::digest(b"bloch-layer-hd-wallet-v1").to_vec()
    };

    let params = Params::new(262144, 4, 4, Some(32)).map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = vec![0u8; 32];
    argon2.hash_password_into(&combined, &salt, &mut key).map_err(|e| e.to_string())?;
    Ok(key)
}

fn encrypt_with_key(key: &[u8], plaintext: &[u8]) -> Result<KeystoreCrypto, String> {
    let mut nonce_b = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_b);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let ct = cipher.encrypt(Nonce::from_slice(&nonce_b), plaintext)
        .map_err(|e| format!("encrypt failed: {}", e))?;
    Ok(KeystoreCrypto {
        cipher:     "aes-256-gcm".into(),
        ciphertext: b64::STANDARD.encode(&ct),
        nonce:      b64::STANDARD.encode(nonce_b),
        kdf:        "argon2id-master".into(),
        kdf_params: KdfParams {
            memory_cost: 262144, time_cost: 4, parallelism: 4,
            salt: b64::STANDARD.encode(b"derived-from-mnemonic"),
            output_len: 32,
        },
    })
}

fn decrypt_with_key(key: &[u8], crypto: &KeystoreCrypto) -> Result<Vec<u8>, String> {
    let nonce_b = b64::STANDARD.decode(&crypto.nonce).map_err(|e| e.to_string())?;
    let ct = b64::STANDARD.decode(&crypto.ciphertext).map_err(|e| e.to_string())?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher.decrypt(Nonce::from_slice(&nonce_b), ct.as_ref())
        .map_err(|_| "decrypt failed — wrong credentials".to_string())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_save_load_roundtrip() {
        let tmp = std::env::temp_dir().join("bloch-hd-test.json");
        let _ = std::fs::remove_file(&tmp);

        let w = HdWallet::create("test-password-12345!", Some("my-passphrase"), true).unwrap();
        let mnemonic = w.mnemonic.to_string();
        let addr0 = w.addresses[0].1.address.clone();
        w.save(&tmp).unwrap();

        let loaded = HdWallet::load(&tmp, &mnemonic, Some("my-passphrase"), "test-password-12345!").unwrap();
        assert_eq!(loaded.addresses[0].1.address, addr0);
        assert_eq!(loaded.mnemonic.to_string(), mnemonic);

        // Wrong password fails
        let bad = HdWallet::load(&tmp, &mnemonic, Some("my-passphrase"), "wrong-password!");
        assert!(bad.is_err());

        // Wrong passphrase fails
        let bad = HdWallet::load(&tmp, &mnemonic, Some("wrong-passphrase"), "test-password-12345!");
        assert!(bad.is_err());

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn new_address_increments_index() {
        let mut w = HdWallet::create("test-password-12345!", None, true).unwrap();
        assert_eq!(w.addresses.len(), 1);
        w.new_address("savings");
        w.new_address("business");
        assert_eq!(w.addresses.len(), 3);
        assert_eq!(w.addresses[2].0, 2);
    }
}
