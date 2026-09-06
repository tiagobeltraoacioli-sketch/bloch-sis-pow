//! Bloch-SIS Protocol — HD Wallet (BIP39 mnemonic + ML-DSA-65 keys)
//!
//! Uses BIP39 24-word mnemonic as the master key for an encrypted wallet
//! containing multiple ML-DSA-65 keypairs. Optional passphrase supported
//! (Ledger/Trezor style).
//!
//! Keys are DERIVED from the mnemonic, not sampled from the OS RNG: the BIP39
//! seed (`mnemonic` + optional passphrase, PBKDF2 per BIP39) is the master
//! seed, and address `i` is `crypto::diversified_keypair(seed, i)` — the same
//! domain-separated, deterministic derivation the diversified-address path
//! uses. So the mnemonic (+ passphrase) alone recovers every derived address:
//! see [`HdWallet::recover`], which needs no wallet file. The file password is
//! deliberately NOT part of the seed; it only locks the file.
//!
//! Wallets written before v3 stored OS-random keys that no seed reproduces.
//! Those files still load unchanged — each address carries a `derived` flag
//! (absent = false = legacy random key), and `load` always uses the keypair
//! stored in the file, never a re-derivation.

use crate::crypto;
use crate::wallet::{Keypair, KdfParams, KeystoreCrypto};
use crate::core::TESTNET_PREFIX;
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use argon2::{Argon2, Algorithm, Version, Params};
use base64::{Engine as _, engine::general_purpose as b64};
use rand::RngCore;
use std::path::Path;
use std::collections::BTreeSet;
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
    /// True when this key was derived from the BIP39 seed at `index`, i.e. the
    /// mnemonic alone reproduces it. False (and absent in pre-v3 files) for
    /// imported keys and for legacy OS-random keys.
    #[serde(default)]
    pub derived: bool,
}

// ── Internal encrypted payload structures ───────────────────────────────────

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct MnemonicPayload { mnemonic: String }

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct KeypairPayload { private_key_hex: String, public_key_hex: String }

// ── HD Wallet type ───────────────────────────────────────────────────────────

pub struct HdWallet {
    pub mnemonic: Mnemonic,
    // SECURITY (A4 lows): never read outside this module — no legitimate
    // external consumer needs the raw derived encryption key (unlike
    // `mnemonic`, which `bloch-cli` displays to the user for backup).
    master_key: Vec<u8>,      // derived from mnemonic + passphrase + password
    /// BIP39 seed (mnemonic + passphrase). Master seed for key DERIVATION —
    /// no password in it, so the mnemonic alone recovers the keys.
    seed: Vec<u8>,
    pub addresses: Vec<(u32, Keypair, String)>, // (index, keypair, label)
    /// Indices whose key is NOT reproducible from `seed` (imported keys, and
    /// every address of a pre-v3 random-key wallet).
    imported: BTreeSet<u32>,
    pub network:  String,
    /// A4 H-1: the wallet-FILE version this instance was created or loaded
    /// under (1 = constant salt, 2/3 = per-wallet salt — see
    /// `derive_master_key`). `save()` re-encrypts with `master_key`, which was
    /// derived using THIS version's salt; writing a DIFFERENT version number
    /// while keeping the same key would make the file permanently
    /// undecryptable (`load` would derive the salt for the wrong version).
    /// `create`/`recover` always start a brand-new file at the CURRENT
    /// `WALLET_VERSION`; `load` preserves whatever version the file already
    /// had, so re-saving a v1/v2 file never breaks it.
    file_version: u32,
}

impl Drop for HdWallet {
    fn drop(&mut self) { self.master_key.zeroize(); self.seed.zeroize(); }
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

        // New wallets use the v2 per-wallet salt (v3 files keep it).
        let master_key = derive_master_key(&mnemonic.to_string(), passphrase.unwrap_or(""), password, WALLET_VERSION)?;

        // Address 0 is DERIVED from the seed, so the mnemonic recovers it.
        let seed = mnemonic.to_seed(passphrase.unwrap_or("")).to_vec();
        let kp = derive_at(&seed, 0, testnet)?;
        let network = if testnet { "testnet" } else { "mainnet" }.to_string();

        Ok(HdWallet {
            mnemonic,
            master_key,
            seed,
            addresses: vec![(0, kp, "primary".to_string())],
            imported: BTreeSet::new(),
            network,
            file_version: WALLET_VERSION,
        })
    }

    /// Recover a wallet from the mnemonic ALONE — no wallet file needed.
    ///
    /// Derives addresses `0..count` from the BIP39 seed; `password` only sets
    /// the key that a subsequent [`save`](Self::save) locks the file with.
    /// Imported keys (and pre-v3 random keys) are NOT recoverable this way —
    /// they never came from the seed.
    pub fn recover(
        mnemonic_str: &str,
        passphrase: Option<&str>,
        password: &str,
        testnet: bool,
        count: u32,
    ) -> Result<Self, String> {
        let mnemonic = Mnemonic::parse(mnemonic_str)
            .map_err(|e| format!("invalid mnemonic: {}", e))?;
        let master_key = derive_master_key(&mnemonic.to_string(), passphrase.unwrap_or(""), password, WALLET_VERSION)?;
        let seed = mnemonic.to_seed(passphrase.unwrap_or("")).to_vec();

        let mut addresses = Vec::with_capacity(count.max(1) as usize);
        for index in 0..count.max(1) {
            let label = if index == 0 { "primary".to_string() } else { format!("address-{}", index) };
            addresses.push((index, derive_at(&seed, index, testnet)?, label));
        }

        Ok(HdWallet {
            mnemonic,
            master_key,
            seed,
            addresses,
            imported: BTreeSet::new(),
            network: if testnet { "testnet" } else { "mainnet" }.to_string(),
            file_version: WALLET_VERSION,
        })
    }

    /// Add a new address to the wallet, DERIVED from the seed at the next index.
    pub fn new_address(&mut self, label: &str) -> Result<&Keypair, String> {
        let next_index = self.addresses.iter().map(|(i, _, _)| *i).max().unwrap_or(0) + 1;
        let testnet = self.network == "testnet";
        let kp = derive_at(&self.seed, next_index, testnet)?;
        self.addresses.push((next_index, kp, label.to_string()));
        Ok(&self.addresses.last().unwrap().1)
    }

    /// Import an existing keypair (e.g., from founder.json) into the HD wallet.
    /// An imported key does not come from the seed, so the mnemonic alone will
    /// never bring it back — the wallet file stays part of that key's backup.
    pub fn import_keypair(&mut self, keypair: Keypair, label: &str) {
        let next_index = self.addresses.iter().map(|(i, _, _)| *i).max().unwrap_or(0) + 1;
        self.addresses.push((next_index, keypair, label.to_string()));
        self.imported.insert(next_index);
    }

    /// True when address `index` is reproducible from the mnemonic alone.
    pub fn is_derived(&self, index: u32) -> bool {
        !self.imported.contains(&index) && self.addresses.iter().any(|(i, _, _)| *i == index)
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
                derived: !self.imported.contains(idx),
            });
        }

        let wallet = HdWalletFile {
            // A4 H-1 FIX: write the version THIS instance's `master_key` was
            // actually derived under (`self.file_version`), never the
            // hardcoded current `WALLET_VERSION`. `create`/`recover` set
            // `file_version = WALLET_VERSION` for a brand-new file, so new
            // wallets are unaffected; `load` preserves whatever version an
            // existing v1/v2 file already carried, so re-saving it keeps the
            // SAME salt on the NEXT load instead of silently becoming
            // undecryptable (the exact bug this replaces: the old code always
            // wrote `WALLET_VERSION` here while still encrypting with the
            // key derived under the file's ORIGINAL version/salt).
            version: self.file_version,
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

        // Verify mnemonic matches (by decrypting and comparing). Wrapped in
        // Zeroizing (A4 lows): this plaintext carries the full mnemonic in
        // JSON form and must not linger in memory after the comparison below.
        let mnemonic_bytes = Zeroizing::new(decrypt_with_key(&master_key, &wallet.mnemonic_crypto)?);
        let payload: MnemonicPayload = serde_json::from_slice(&mnemonic_bytes)
            .map_err(|e| format!("mnemonic decrypt failed — wrong password/passphrase/mnemonic ({})", e))?;
        if payload.mnemonic != mnemonic.to_string() {
            return Err("mnemonic mismatch — tampered file?".into());
        }

        // Decrypt each keypair. The stored key always wins — a pre-v3 wallet's
        // OS-random keys are not reproducible from the seed, so re-deriving here
        // would silently hand back the wrong (empty) addresses.
        let mut addresses = Vec::new();
        let mut imported = BTreeSet::new();
        for addr in &wallet.addresses {
            // Zeroizing (A4 lows): plaintext JSON containing the hex-encoded
            // private key — must not survive past the parse below.
            let bytes = Zeroizing::new(decrypt_with_key(&master_key, &addr.keypair_crypto)?);
            let mut kpp: KeypairPayload = serde_json::from_slice(&bytes)
                .map_err(|e| format!("keypair {} decrypt failed: {}", addr.index, e))?;
            let priv_key = hex::decode(&kpp.private_key_hex).map_err(|e| e.to_string())?;
            let pub_key  = hex::decode(&kpp.public_key_hex).map_err(|e| e.to_string())?;
            kpp.zeroize();

            let testnet = addr.address.starts_with(TESTNET_PREFIX);
            // NB: local, not `addr.derived` — this is the recomputed address string.
            let derived_address = crypto::address_from_pubkey(&pub_key, testnet);
            if derived_address != addr.address {
                return Err(format!("address {} mismatch — tampered", addr.index));
            }

            let kp = Keypair {
                private_key: priv_key,
                public_key:  pub_key,
                address:     addr.address.clone(),
            };
            addresses.push((addr.index, kp, addr.label.clone()));
            if !addr.derived { imported.insert(addr.index); }
        }

        let seed = mnemonic.to_seed(passphrase.unwrap_or("")).to_vec();
        // A4 H-1 FIX: preserve the file's OWN version — `master_key` above
        // was derived under `wallet.version`'s salt, so `save()` must write
        // that SAME version back, not the current `WALLET_VERSION`.
        Ok(HdWallet {
            mnemonic, master_key, seed, addresses, imported,
            network: wallet.network,
            file_version: wallet.version,
        })
    }

    /// List all addresses (for display).
    pub fn list(&self) -> Vec<(u32, String, String)> {
        self.addresses.iter().map(|(i, kp, label): &(u32, Keypair, String)| (*i, kp.address.clone(), label.clone())).collect()
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Current wallet-file version. v3 = keys derived from the BIP39 seed.
const WALLET_VERSION: u32 = 3;

/// Derive the keypair for `index` from the BIP39 seed.
///
/// Deterministic and domain-separated (`crypto::diversified_seed`), so the same
/// mnemonic + passphrase yields the same address at the same index on every
/// machine — which is what makes the mnemonic a real backup.
fn derive_at(seed: &[u8], index: u32, testnet: bool) -> Result<Keypair, String> {
    let (public_key, private_key) = crypto::diversified_keypair(seed, index)
        .map_err(|e| format!("key derivation failed at index {}: {}", index, e))?;
    let address = crypto::address_from_pubkey(&public_key, testnet);
    Ok(Keypair { private_key, public_key, address })
}

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
    // SECURITY (A4 lows): `Nonce::from_slice` PANICS on any length other than
    // 12 bytes. `nonce_b` comes from an untrusted wallet file — guard the
    // length BEFORE it reaches the fixed-size AES-GCM nonce so a truncated or
    // corrupt file returns an error instead of crashing the process.
    const NONCE_LEN: usize = 12;
    const GCM_TAG_LEN: usize = 16;
    if nonce_b.len() != NONCE_LEN {
        return Err(format!(
            "wallet-file nonce has invalid length: expected {} bytes, got {}",
            NONCE_LEN, nonce_b.len()
        ));
    }
    if ct.len() < GCM_TAG_LEN {
        return Err(format!(
            "wallet-file ciphertext too short: {} bytes, need at least the {}-byte GCM tag",
            ct.len(), GCM_TAG_LEN
        ));
    }
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
        w.new_address("savings").unwrap();
        w.new_address("business").unwrap();
        assert_eq!(w.addresses.len(), 3);
        assert_eq!(w.addresses[2].0, 2);
    }

    /// K-M2: the mnemonic must actually recover the wallet. Same mnemonic (+
    /// passphrase) → byte-identical addresses, with NO wallet file involved.
    /// Before the fix every address came from `generate_keypair()` (OS random)
    /// and this could only pass by a 2^-256 accident.
    #[test]
    fn same_mnemonic_reproduces_same_addresses() {
        let mut w = HdWallet::create("test-password-12345!", Some("pp"), true).unwrap();
        w.new_address("savings").unwrap();
        w.new_address("business").unwrap();
        let mnemonic = w.mnemonic.to_string();
        let originals: Vec<String> = w.addresses.iter().map(|(_, kp, _)| kp.address.clone()).collect();
        assert_eq!(originals.len(), 3);

        // Recover from the mnemonic alone — different password on purpose: the
        // file password locks the file, it must not enter key derivation.
        let r = HdWallet::recover(&mnemonic, Some("pp"), "another-password-9!", true, 3).unwrap();
        let recovered: Vec<String> = r.addresses.iter().map(|(_, kp, _)| kp.address.clone()).collect();
        assert_eq!(recovered, originals, "mnemonic must reproduce the same addresses");

        // Derivation is a pure function of (seed, index): recover twice, same keys.
        let r2 = HdWallet::recover(&mnemonic, Some("pp"), "another-password-9!", true, 3).unwrap();
        assert_eq!(r2.addresses[2].1.private_key, r.addresses[2].1.private_key);

        // A different BIP39 passphrase is a different wallet.
        let other = HdWallet::recover(&mnemonic, Some("other-pp"), "another-password-9!", true, 1).unwrap();
        assert_ne!(other.addresses[0].1.address, originals[0]);

        // Indices are independent of each other.
        assert_ne!(originals[0], originals[1]);
        assert_ne!(originals[1], originals[2]);
    }

    /// Backward compat: a pre-v3 file (no `derived` field, OS-random keys) must
    /// still load, and `load` must hand back the STORED key, never a
    /// re-derivation that would point at an empty address.
    #[test]
    fn loads_legacy_random_key_wallet() {
        let tmp = std::env::temp_dir().join("bloch-hd-legacy-test.json");
        let _ = std::fs::remove_file(&tmp);

        // Build a wallet whose key is OS-random, exactly like a pre-v3 file.
        let mut w = HdWallet::create("test-password-12345!", None, true).unwrap();
        let random_kp = crate::wallet::generate_keypair(true);
        let random_addr = random_kp.address.clone();
        w.import_keypair(random_kp, "legacy");
        assert!(w.is_derived(0));
        assert!(!w.is_derived(1), "an imported key is not seed-derived");
        w.save(&tmp).unwrap();
        let mnemonic = w.mnemonic.to_string();

        // Strip the v3-only fields to make it a genuine v2-shaped file.
        let json = std::fs::read_to_string(&tmp).unwrap();
        let mut file: serde_json::Value = serde_json::from_str(&json).unwrap();
        file["version"] = serde_json::json!(2);
        for a in file["addresses"].as_array_mut().unwrap() {
            a.as_object_mut().unwrap().remove("derived");
        }
        std::fs::write(&tmp, serde_json::to_string_pretty(&file).unwrap()).unwrap();

        let loaded = HdWallet::load(&tmp, &mnemonic, None, "test-password-12345!").unwrap();
        assert_eq!(loaded.addresses.len(), 2);
        assert_eq!(loaded.addresses[1].1.address, random_addr, "stored key must survive the load");
        // No `derived` flag → treat every address as unreproducible, which is true.
        assert!(!loaded.is_derived(0));
        assert!(!loaded.is_derived(1));

        let _ = std::fs::remove_file(&tmp);
    }

    /// A4 H-1 regression: a genuine v1-shaped file (constant Argon2 salt)
    /// must remain decryptable through `load → new_address → save → load`.
    ///
    /// Before the fix, `save()` unconditionally stamped `version:
    /// WALLET_VERSION` (3) into the file while still encrypting with
    /// `self.master_key` — which for a v1-loaded wallet was derived under the
    /// v1 CONSTANT salt. The next `load()` would then read `version: 3`,
    /// derive the v2+ per-wallet salt for this mnemonic, and decryption would
    /// fail PERMANENTLY (wrong key). This test fails on the pre-fix code at
    /// the second `load()` with a "wrong password/passphrase/mnemonic" error
    /// — reverting the `file_version` field / `save()`'s `self.file_version`
    /// write turns this red again.
    #[test]
    fn v1_file_survives_load_new_address_save_load_roundtrip() {
        let tmp = std::env::temp_dir().join("bloch-hd-v1-roundtrip-test.json");
        let _ = std::fs::remove_file(&tmp);

        let password = "test-password-12345!";
        let mnemonic = Mnemonic::from_entropy(&[0x11u8; 32]).unwrap();
        let mnemonic_str = mnemonic.to_string();

        let v1_file = build_raw_file(&mnemonic, &mnemonic_str, password, 1);
        std::fs::write(&tmp, serde_json::to_string_pretty(&v1_file).unwrap()).unwrap();

        let mut w = HdWallet::load(&tmp, &mnemonic_str, None, password).unwrap();
        assert_eq!(w.file_version, 1, "loaded instance must remember it came from a v1 file");
        w.new_address("second").unwrap();
        w.save(&tmp).unwrap();

        let w2 = HdWallet::load(&tmp, &mnemonic_str, None, password)
            .expect("v1 file must remain decryptable after a save — A4 H-1 regression");
        assert_eq!(w2.addresses.len(), 2);
        assert_eq!(w2.file_version, 1, "re-saved file must still be recorded/read back as v1");

        // A second round trip (save → load → save → load) must also hold.
        w2.save(&tmp).unwrap();
        let w3 = HdWallet::load(&tmp, &mnemonic_str, None, password).unwrap();
        assert_eq!(w3.addresses.len(), 2);

        let _ = std::fs::remove_file(&tmp);
    }

    /// Same regression, for a v2-shaped file (per-wallet salt, no `derived`
    /// flags) — the version-persistence fix must not be special-cased to v1.
    #[test]
    fn v2_file_survives_load_new_address_save_load_roundtrip() {
        let tmp = std::env::temp_dir().join("bloch-hd-v2-roundtrip-test.json");
        let _ = std::fs::remove_file(&tmp);

        let password = "test-password-12345!";
        let mnemonic = Mnemonic::from_entropy(&[0x22u8; 32]).unwrap();
        let mnemonic_str = mnemonic.to_string();

        let v2_file = build_raw_file(&mnemonic, &mnemonic_str, password, 2);
        std::fs::write(&tmp, serde_json::to_string_pretty(&v2_file).unwrap()).unwrap();

        let mut w = HdWallet::load(&tmp, &mnemonic_str, None, password).unwrap();
        assert_eq!(w.file_version, 2);
        w.new_address("second").unwrap();
        w.save(&tmp).unwrap();

        let w2 = HdWallet::load(&tmp, &mnemonic_str, None, password)
            .expect("v2 file must remain decryptable after a save");
        assert_eq!(w2.addresses.len(), 2);
        assert_eq!(w2.file_version, 2);

        let _ = std::fs::remove_file(&tmp);
    }

    /// Hand-build a genuine `HdWalletFile` at an explicit `version`, with its
    /// single address's `keypair_crypto` encrypted under the master key THAT
    /// version's salt scheme produces — exactly what a real pre-v3 file looks
    /// like on disk, without going through `HdWallet::save` (which always
    /// writes the CURRENT `WALLET_VERSION`).
    fn build_raw_file(mnemonic: &Mnemonic, mnemonic_str: &str, password: &str, version: u32) -> HdWalletFile {
        let master_key = derive_master_key(mnemonic_str, "", password, version).unwrap();
        let seed = mnemonic.to_seed("").to_vec();
        let kp0 = derive_at(&seed, 0, true).unwrap();

        let mnemonic_crypto = encrypt_with_key(
            &master_key,
            &serde_json::to_vec(&MnemonicPayload { mnemonic: mnemonic_str.to_string() }).unwrap(),
        ).unwrap();
        let keypair_crypto = encrypt_with_key(
            &master_key,
            &serde_json::to_vec(&KeypairPayload {
                private_key_hex: hex::encode(&kp0.private_key),
                public_key_hex: hex::encode(&kp0.public_key),
            }).unwrap(),
        ).unwrap();

        HdWalletFile {
            version,
            format: "hd-wallet-v1".into(),
            network: "testnet".into(),
            mnemonic_crypto,
            addresses: vec![HdAddress {
                index: 0, address: kp0.address.clone(), label: "primary".into(),
                keypair_crypto, derived: true,
            }],
            created_at: chrono::Utc::now().to_rfc3339(),
            description: "test fixture".into(),
        }
    }
}
