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
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use argon2::{Argon2, Algorithm, Version, Params};
use base64::{Engine as _, engine::general_purpose as b64};
use rand::RngCore;
use std::borrow::Cow;
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

impl HdWalletFile {
    /// Read public wallet metadata under the conservative interactive budget.
    ///
    /// This does not decrypt keys, but it still bounds both the input bytes and
    /// the number of address records allocated/returned to callers. Use
    /// [`Self::read_public_with_limits`] only for an explicit trusted-backup
    /// workflow that needs different limits.
    pub fn read_public_bounded(path: &Path) -> Result<Self, String> {
        let wallet = Self::read_public_with_limits(
            path,
            DEFAULT_HD_WALLET_LOAD_LIMITS.max_file_bytes,
            DEFAULT_HD_WALLET_LOAD_LIMITS.max_addresses,
        )?;
        validate_wallet_encrypted_payload_limits(&wallet)?;
        Ok(wallet)
    }

    /// Read public wallet metadata with explicit byte and address limits.
    ///
    /// The byte budget is enforced while reading. A non-retaining JSON
    /// preflight rejects excess address records before they are allocated by
    /// the full wallet deserializer. Exact-limit inputs are accepted.
    pub fn read_public_with_limits(
        path: &Path,
        max_file_bytes: usize,
        max_addresses: usize,
    ) -> Result<Self, String> {
        let bytes = crate::util::read_wallet_file(path, max_file_bytes)
            .map_err(|error| error.to_string())?;
        preflight_wallet_record_limits(&bytes, max_addresses, None)?;
        let wallet: Self = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        validate_wallet_structure(&wallet)?;
        validate_wallet_address_limit(&wallet, max_addresses)?;
        Ok(wallet)
    }
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

/// Borrow ordinary unescaped secrets directly from their zeroizing decrypted
/// plaintext buffers. `Cow` retains compatibility with equivalent JSON that
/// uses escapes; owned secret fallbacks are wiped on drop.
#[derive(Deserialize)]
struct BorrowedMnemonicPayload<'a> {
    #[serde(borrow)]
    mnemonic: Cow<'a, str>,
}

impl Drop for BorrowedMnemonicPayload<'_> {
    fn drop(&mut self) {
        if let Cow::Owned(mnemonic) = &mut self.mnemonic {
            mnemonic.zeroize();
        }
    }
}

#[derive(Deserialize)]
struct BorrowedKeypairPayload<'a> {
    #[serde(borrow)]
    private_key_hex: Cow<'a, str>,
    #[serde(borrow)]
    public_key_hex: Cow<'a, str>,
}

impl Drop for BorrowedKeypairPayload<'_> {
    fn drop(&mut self) {
        if let Cow::Owned(private_key_hex) = &mut self.private_key_hex {
            private_key_hex.zeroize();
        }
    }
}

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

/// Resource policy for loading an HD-wallet backup.
///
/// The historical [`HdWallet::load`] and [`HdWallet::load_with_file_limit`]
/// entry points intentionally keep accepting every wallet that fits their
/// existing byte budget. Callers handling untrusted or unusually large
/// backups can opt into this stricter policy without changing the on-disk
/// format or making old backups unrecoverable through the compatibility APIs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HdWalletLoadLimits {
    /// Maximum bytes read from the wallet file.
    pub max_file_bytes: usize,
    /// Maximum total address records decrypted and retained in memory.
    pub max_addresses: usize,
    /// Maximum `derived: true` records rederived from the mnemonic and checked.
    /// This separately accounts for the expensive diversified-key derivation
    /// performed after decryption; imported/legacy records do not consume it.
    pub max_derived_key_checks: usize,
}

/// Conservative policy for interactive wallet consumers.
///
/// A thousand imported/legacy records remain available, while the more
/// expensive mnemonic rederivation work is capped separately. Applications
/// should use [`HdWallet::load_bounded`] for ordinary unlocks and expose an
/// explicit, trusted-backup recovery workflow when these limits are too low.
pub const DEFAULT_HD_WALLET_LOAD_LIMITS: HdWalletLoadLimits = HdWalletLoadLimits {
    max_file_bytes: crate::util::DEFAULT_WALLET_FILE_LIMIT,
    max_addresses: 1_024,
    max_derived_key_checks: 256,
};

impl Default for HdWalletLoadLimits {
    fn default() -> Self { DEFAULT_HD_WALLET_LOAD_LIMITS }
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
        if count > 4096 { return Err("recovery count exceeds 4096 addresses per request".into()); }
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
        let current_index = self.addresses.iter().map(|(i, _, _)| *i).max()
            .ok_or_else(|| "HD wallet contains no addresses".to_string())?;
        let next_index = current_index
            .checked_add(1).ok_or_else(|| "HD address index exhausted".to_string())?;
        let testnet = self.network == "testnet";
        let kp = derive_at(&self.seed, next_index, testnet)?;
        self.addresses.push((next_index, kp, label.to_string()));
        Ok(&self.addresses.last().unwrap().1)
    }

    /// Import an existing keypair (e.g., from founder.json) into the HD wallet.
    /// An imported key does not come from the seed, so the mnemonic alone will
    /// never bring it back — the wallet file stays part of that key's backup.
    /// Returns an error if the address index is exhausted. This method now
    /// returns `Result` instead of `()`; callers must handle import failure.
    pub fn import_keypair(&mut self, keypair: Keypair, label: &str) -> Result<(), String> {
        self.try_import_keypair(keypair, label)
    }

    /// Fallible import for untrusted or exhausted wallet files. On failure the
    /// wallet is unchanged; this consumes the supplied keypair. Keep its backup.
    /// Both import entry points report exhaustion or inconsistent key material
    /// without panicking or wrapping.
    pub fn try_import_keypair(&mut self, keypair: Keypair, label: &str) -> Result<(), String> {
        let current_index = self.addresses.iter().map(|(i, _, _)| *i).max()
            .ok_or_else(|| "HD wallet contains no addresses".to_string())?;
        let next_index = current_index
            .checked_add(1).ok_or_else(|| "HD address index exhausted".to_string())?;

        let testnet = keypair.address.starts_with(TESTNET_PREFIX);
        if crypto::address_from_pubkey(&keypair.public_key, testnet) != keypair.address {
            return Err("imported keypair public key does not match address".into());
        }
        let proof = keypair.sign_message(IMPORT_KEY_AUTH_CHALLENGE)
            .map_err(|_| "imported keypair private key is invalid".to_string())?;
        if !Keypair::verify_message(&keypair.public_key, IMPORT_KEY_AUTH_CHALLENGE, &proof) {
            return Err("imported keypair private/public keys do not match".into());
        }

        self.addresses.push((next_index, keypair, label.to_string()));
        self.imported.insert(next_index);
        Ok(())
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
        let mnemonic_bytes = Zeroizing::new(serde_json::to_vec(
            &MnemonicPayload { mnemonic: self.mnemonic.to_string() }).map_err(|e| e.to_string())?);
        let mnemonic_crypto = encrypt_with_key(&self.master_key, &mnemonic_bytes)?;

        // Encrypt each keypair with master_key
        let mut addresses = Vec::new();
        for (idx, kp, label) in &self.addresses {
            let payload = KeypairPayload {
                private_key_hex: hex::encode(&kp.private_key),
                public_key_hex:  hex::encode(&kp.public_key),
            };
            let bytes = Zeroizing::new(serde_json::to_vec(&payload).map_err(|e| e.to_string())?);
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
        Self::load_with_file_limit(path, mnemonic_str, passphrase, password, crate::util::DEFAULT_WALLET_FILE_LIMIT)
    }

    /// Load using the conservative policy intended for normal interactive use.
    ///
    /// This is deliberately distinct from [`Self::load`], whose historical
    /// compatibility contract does not cap address or rederivation counts.
    pub fn load_bounded(path: &Path, mnemonic_str: &str, passphrase: Option<&str>, password: &str) -> Result<Self, String> {
        Self::load_with_limits(path, mnemonic_str, passphrase, password, HdWalletLoadLimits::default())
    }

    /// Explicit bounded recovery override for large authentic backups (maximum 512 MiB).
    /// The budget covers input bytes; parsed allocations and KDF work are additional.
    pub fn load_with_file_limit(path: &Path, mnemonic_str: &str, passphrase: Option<&str>, password: &str, max_bytes: usize) -> Result<Self, String> {
        Self::load_internal(path, mnemonic_str, passphrase, password, max_bytes, None)
    }

    /// Load with explicit aggregate address and derived-key work limits.
    ///
    /// Both counters are checked by a non-retaining JSON preflight before the
    /// full wallet value is allocated, and before the master-key KDF or any
    /// ciphertext/key derivation work. Exact-limit files are accepted;
    /// exceeding either counter fails closed without trying the credentials.
    pub fn load_with_limits(
        path: &Path,
        mnemonic_str: &str,
        passphrase: Option<&str>,
        password: &str,
        limits: HdWalletLoadLimits,
    ) -> Result<Self, String> {
        Self::load_internal(
            path,
            mnemonic_str,
            passphrase,
            password,
            limits.max_file_bytes,
            Some(limits),
        )
    }

    fn load_internal(
        path: &Path,
        mnemonic_str: &str,
        passphrase: Option<&str>,
        password: &str,
        max_bytes: usize,
        limits: Option<HdWalletLoadLimits>,
    ) -> Result<Self, String> {
        let bytes = crate::util::read_wallet_file(path, max_bytes).map_err(|e| e.to_string())?;
        if let Some(limits) = limits {
            preflight_wallet_record_limits(
                &bytes,
                limits.max_addresses,
                Some(limits.max_derived_key_checks),
            )?;
        }
        let wallet: HdWalletFile = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        validate_wallet_structure(&wallet)?;
        if let Some(limits) = limits {
            validate_wallet_load_limits(&wallet, limits)?;
        }

        // Parse mnemonic
        let mnemonic = Mnemonic::parse(mnemonic_str)
            .map_err(|e| format!("invalid mnemonic: {}", e))?;
        let canonical_mnemonic = Zeroizing::new(mnemonic.to_string());

        // Derive master key — route the salt by the file's version (v1 legacy
        // constant salt, v2+ per-wallet), so existing wallets still decrypt.
        let mut master_key = Zeroizing::new(derive_master_key(&canonical_mnemonic, passphrase.unwrap_or(""), password, wallet.version)?);

        // Verify mnemonic matches (by decrypting and comparing). Wrapped in
        // Zeroizing (A4 lows): this plaintext carries the full mnemonic in
        // JSON form and must not linger in memory after the comparison below.
        let mnemonic_bytes = Zeroizing::new(decrypt_with_key(&master_key, &wallet.mnemonic_crypto)?);
        let payload: BorrowedMnemonicPayload<'_> = serde_json::from_slice(&mnemonic_bytes)
            .map_err(|e| format!("mnemonic decrypt failed — wrong password/passphrase/mnemonic ({})", e))?;
        if payload.mnemonic.as_ref() != canonical_mnemonic.as_str() {
            return Err("mnemonic mismatch — tampered file?".into());
        }

        // Decrypt each keypair. The stored key always wins — a pre-v3 wallet's
        // OS-random keys are not reproducible from the seed, so re-deriving here
        // would silently hand back the wrong (empty) addresses.
        let mut addresses = Vec::with_capacity(wallet.addresses.len());
        let mut imported = BTreeSet::new();
        let mut seed = Zeroizing::new(mnemonic.to_seed(passphrase.unwrap_or("")).to_vec());
        for addr in wallet.addresses {
            // Zeroizing (A4 lows): plaintext JSON containing the hex-encoded
            // private key — must not survive past the parse below.
            let bytes = Zeroizing::new(decrypt_with_key(&master_key, &addr.keypair_crypto)?);
            let kpp: BorrowedKeypairPayload<'_> = serde_json::from_slice(&bytes)
                .map_err(|e| format!("keypair {} decrypt failed: {}", addr.index, e))?;
            let mut priv_key = Zeroizing::new(hex::decode(kpp.private_key_hex.as_ref()).map_err(|e| e.to_string())?);
            let pub_key  = hex::decode(kpp.public_key_hex.as_ref()).map_err(|e| e.to_string())?;

            let testnet = addr.address.starts_with(TESTNET_PREFIX);
            // NB: local, not `addr.derived` — this is the recomputed address string.
            let derived_address = crypto::address_from_pubkey(&pub_key, testnet);
            if derived_address != addr.address {
                return Err(format!("address {} mismatch — tampered", addr.index));
            }

            if addr.derived {
                let expected = derive_at(&seed, addr.index, testnet)?;
                if expected.public_key != pub_key || expected.private_key.as_slice() != priv_key.as_slice() {
                    return Err(format!("derived keypair {} does not match mnemonic and index", addr.index));
                }
            }
            let (loaded, is_imported) = into_loaded_address(
                addr,
                std::mem::take(&mut *priv_key),
                pub_key,
            );
            if is_imported { imported.insert(loaded.0); }
            addresses.push(loaded);
        }

        // A4 H-1 FIX: preserve the file's OWN version — `master_key` above
        // was derived under `wallet.version`'s salt, so `save()` must write
        // that SAME version back, not the current `WALLET_VERSION`.
        Ok(HdWallet {
            mnemonic, master_key: std::mem::take(&mut *master_key),
            seed: std::mem::take(&mut *seed), addresses, imported,
            network: wallet.network,
            file_version: wallet.version,
        })
    }

    /// List all addresses (for display).
    pub fn list(&self) -> Vec<(u32, String, String)> {
        self.addresses.iter().map(|(i, kp, label): &(u32, Keypair, String)| (*i, kp.address.clone(), label.clone())).collect()
    }
}

// Reject ambiguous metadata before expensive KDF/decryption. No funded key is
// re-derived, renumbered or silently repaired during restore.
fn validate_wallet_structure(wallet: &HdWalletFile) -> Result<(), String> {
    if wallet.format != "hd-wallet-v1" { return Err("unsupported wallet format".into()); }
    if !(1..=WALLET_VERSION).contains(&wallet.version) { return Err("unsupported wallet version".into()); }
    let prefix = match wallet.network.as_str() {
        "testnet" => TESTNET_PREFIX,
        "mainnet" => crate::core::MAINNET_PREFIX,
        _ => return Err("unsupported wallet network".into()),
    };
    if wallet.addresses.is_empty() { return Err("HD wallet contains no addresses".into()); }
    let mut indices = BTreeSet::new();
    for address in &wallet.addresses {
        if !indices.insert(address.index) { return Err("duplicate HD address index".into()); }
        // Imported/pre-v3 keys may legitimately belong to another network;
        // preserve those backups. The network promises only future derivations.
        if address.derived && !address.address.starts_with(prefix) {
            return Err("derived address and wallet network differ".into());
        }
    }
    Ok(())
}

/// Transfer authenticated record ownership into the live wallet without
/// cloning attacker-controlled address/label strings. Authentication and
/// mnemonic/index checks happen before this helper is called.
fn into_loaded_address(
    address: HdAddress,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
) -> ((u32, Keypair, String), bool) {
    let is_imported = !address.derived;
    let keypair = Keypair {
        private_key,
        public_key,
        address: address.address,
    };
    ((address.index, keypair, address.label), is_imported)
}

fn validate_wallet_load_limits(
    wallet: &HdWalletFile,
    limits: HdWalletLoadLimits,
) -> Result<(), String> {
    validate_wallet_address_limit(wallet, limits.max_addresses)?;
    let derived_key_checks = wallet.addresses.iter().filter(|address| address.derived).count();
    if derived_key_checks > limits.max_derived_key_checks {
        return Err(format!(
            "HD wallet derived-key check count {} exceeds configured limit {}",
            derived_key_checks, limits.max_derived_key_checks
        ));
    }
    validate_wallet_encrypted_payload_limits(wallet)
}

fn validate_wallet_address_limit(wallet: &HdWalletFile, max_addresses: usize) -> Result<(), String> {
    if wallet.addresses.len() > max_addresses {
        return Err(format!(
            "HD wallet address count {} exceeds configured limit {}",
            wallet.addresses.len(), max_addresses
        ));
    }
    Ok(())
}

// These are encoded-string ceilings, checked before Base64 decoding or the
// master-key KDF. Genuine HD-wallet payloads are much smaller (a mnemonic JSON
// object and one fixed-suite hybrid keypair JSON object respectively). The
// generous headroom preserves every repository-produced and historical key
// shape while preventing a bounded 64 MiB file from creating another
// file-sized nonce/ciphertext allocation during each decrypt. Explicit legacy
// recovery loaders intentionally bypass this ordinary interactive policy.
const MAX_HD_WALLET_NONCE_B64_BYTES: usize = 64;
const MAX_HD_WALLET_MNEMONIC_CIPHERTEXT_B64_BYTES: usize = 4 * 1024;
const MAX_HD_WALLET_KEYPAIR_CIPHERTEXT_B64_BYTES: usize = 64 * 1024;

fn validate_wallet_encrypted_payload_limits(wallet: &HdWalletFile) -> Result<(), String> {
    validate_encrypted_payload_limit(
        "mnemonic",
        &wallet.mnemonic_crypto,
        MAX_HD_WALLET_MNEMONIC_CIPHERTEXT_B64_BYTES,
    )?;
    for address in &wallet.addresses {
        validate_encrypted_payload_limit(
            &format!("keypair {}", address.index),
            &address.keypair_crypto,
            MAX_HD_WALLET_KEYPAIR_CIPHERTEXT_B64_BYTES,
        )?;
    }
    Ok(())
}

fn validate_encrypted_payload_limit(
    field: &str,
    crypto: &KeystoreCrypto,
    max_ciphertext_b64_bytes: usize,
) -> Result<(), String> {
    if crypto.nonce.len() > MAX_HD_WALLET_NONCE_B64_BYTES {
        return Err(format!(
            "HD wallet {} nonce encoding length {} exceeds bounded limit {}",
            field,
            crypto.nonce.len(),
            MAX_HD_WALLET_NONCE_B64_BYTES
        ));
    }
    if crypto.ciphertext.len() > max_ciphertext_b64_bytes {
        return Err(format!(
            "HD wallet {} ciphertext encoding length {} exceeds bounded limit {}",
            field,
            crypto.ciphertext.len(),
            max_ciphertext_b64_bytes
        ));
    }
    Ok(())
}

/// Scan only the JSON shape needed for resource accounting. `IgnoredAny`
/// consumes all payload fields without retaining their strings or encrypted
/// blobs. The address counter is charged as soon as an array element begins,
/// so an excess record is rejected before any of its fields are visited.
fn preflight_wallet_record_limits(
    bytes: &[u8],
    max_addresses: usize,
    max_derived_key_checks: Option<usize>,
) -> Result<(), String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    WalletRecordLimitSeed { max_addresses, max_derived_key_checks }
        .deserialize(&mut deserializer)
        .map_err(normalize_preflight_error)?;
    deserializer.end().map_err(|error| error.to_string())
}

fn normalize_preflight_error(error: serde_json::Error) -> String {
    let rendered = error.to_string();
    if rendered.starts_with("HD wallet address count ")
        || rendered.starts_with("HD wallet derived-key check count ")
    {
        rendered.split(" at line ").next().unwrap_or(&rendered).to_string()
    } else {
        rendered
    }
}

struct WalletRecordLimitSeed {
    max_addresses: usize,
    max_derived_key_checks: Option<usize>,
}

const HD_WALLET_FIELDS: &[&str] = &[
    "version",
    "format",
    "network",
    "mnemonic_crypto",
    "addresses",
    "created_at",
    "description",
];

const HD_ADDRESS_FIELDS: &[&str] = &[
    "index",
    "address",
    "label",
    "keypair_crypto",
    "derived",
];

impl<'de> DeserializeSeed<'de> for WalletRecordLimitSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Match HdWalletFile's derived Deserialize entry point exactly.
        // serde_json accepts a struct as either a keyed object or a positional
        // sequence; the preflight must account both shapes before the real
        // deserializer is allowed to allocate either one.
        deserializer.deserialize_struct(
            "HdWalletFile",
            HD_WALLET_FIELDS,
            WalletRecordLimitVisitor {
                max_addresses: self.max_addresses,
                max_derived_key_checks: self.max_derived_key_checks,
            },
        )
    }
}

struct WalletRecordLimitVisitor {
    max_addresses: usize,
    max_derived_key_checks: Option<usize>,
}

impl<'de> Visitor<'de> for WalletRecordLimitVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an HD-wallet JSON object")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut saw_addresses = false;
        while let Some(field) = map.next_key::<String>()? {
            if field == "addresses" {
                if saw_addresses {
                    return Err(de::Error::duplicate_field("addresses"));
                }
                saw_addresses = true;
                map.next_value_seed(AddressSequenceLimitSeed {
                    max_addresses: self.max_addresses,
                    max_derived_key_checks: self.max_derived_key_checks,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }

    fn visit_seq<S>(self, mut sequence: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        // Derived HdWalletFile order: version, format, network,
        // mnemonic_crypto, addresses, created_at, description. Missing or
        // ill-typed non-accounting fields are left for the real deserializer;
        // this pass only needs to reach and bound `addresses` without
        // retaining the preceding values.
        for _ in 0..4 {
            if sequence.next_element::<IgnoredAny>()?.is_none() {
                return Ok(());
            }
        }
        if sequence
            .next_element_seed(AddressSequenceLimitSeed {
                max_addresses: self.max_addresses,
                max_derived_key_checks: self.max_derived_key_checks,
            })?
            .is_none()
        {
            return Ok(());
        }
        for _ in 0..2 {
            if sequence.next_element::<IgnoredAny>()?.is_none() {
                return Ok(());
            }
        }
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(de::Error::invalid_length(8, &self));
        }
        Ok(())
    }
}

struct AddressSequenceLimitSeed {
    max_addresses: usize,
    max_derived_key_checks: Option<usize>,
}

impl<'de> DeserializeSeed<'de> for AddressSequenceLimitSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(AddressSequenceLimitVisitor {
            max_addresses: self.max_addresses,
            max_derived_key_checks: self.max_derived_key_checks,
        })
    }
}

struct AddressSequenceLimitVisitor {
    max_addresses: usize,
    max_derived_key_checks: Option<usize>,
}

impl<'de> Visitor<'de> for AddressSequenceLimitVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an array of HD-wallet address records")
    }

    fn visit_seq<S>(self, mut sequence: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        let mut addresses = 0usize;
        let mut derived_key_checks = 0usize;
        while sequence.next_element_seed(AddressRecordLimitSeed {
            addresses: &mut addresses,
            derived_key_checks: &mut derived_key_checks,
            max_addresses: self.max_addresses,
            max_derived_key_checks: self.max_derived_key_checks,
        })?.is_some() {}
        Ok(())
    }
}

struct AddressRecordLimitSeed<'a> {
    addresses: &'a mut usize,
    derived_key_checks: &'a mut usize,
    max_addresses: usize,
    max_derived_key_checks: Option<usize>,
}

impl<'de> DeserializeSeed<'de> for AddressRecordLimitSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        *self.addresses += 1;
        if *self.addresses > self.max_addresses {
            return Err(de::Error::custom(format_args!(
                "HD wallet address count {} exceeds configured limit {}",
                *self.addresses, self.max_addresses
            )));
        }
        deserializer.deserialize_struct(
            "HdAddress",
            HD_ADDRESS_FIELDS,
            AddressRecordLimitVisitor {
                derived_key_checks: self.derived_key_checks,
                max_derived_key_checks: self.max_derived_key_checks,
            },
        )
    }
}

struct AddressRecordLimitVisitor<'a> {
    derived_key_checks: &'a mut usize,
    max_derived_key_checks: Option<usize>,
}

impl<'de> Visitor<'de> for AddressRecordLimitVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an HD-wallet address object")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut saw_derived = false;
        while let Some(field) = map.next_key::<String>()? {
            if field == "derived" {
                if saw_derived {
                    return Err(de::Error::duplicate_field("derived"));
                }
                saw_derived = true;
                if map.next_value::<bool>()? {
                    *self.derived_key_checks += 1;
                    if let Some(limit) = self.max_derived_key_checks {
                        if *self.derived_key_checks > limit {
                            return Err(de::Error::custom(format_args!(
                                "HD wallet derived-key check count {} exceeds configured limit {}",
                                *self.derived_key_checks, limit
                            )));
                        }
                    }
                }
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }

    fn visit_seq<S>(self, mut sequence: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        // Derived HdAddress order: index, address, label, keypair_crypto,
        // derived. The outer seed has already charged this record before any
        // of these payload fields are visited.
        for _ in 0..4 {
            if sequence.next_element::<IgnoredAny>()?.is_none() {
                return Ok(());
            }
        }
        if sequence.next_element::<bool>()?.unwrap_or(false) {
            *self.derived_key_checks += 1;
            if let Some(limit) = self.max_derived_key_checks {
                if *self.derived_key_checks > limit {
                    return Err(de::Error::custom(format_args!(
                        "HD wallet derived-key check count {} exceeds configured limit {}",
                        *self.derived_key_checks, limit
                    )));
                }
            }
        }
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(de::Error::invalid_length(6, &self));
        }
        Ok(())
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Current wallet-file version. v3 = keys derived from the BIP39 seed.
const WALLET_VERSION: u32 = 3;

/// Non-exported proof-of-possession challenge used only while admitting a new
/// imported keypair. The signature is immediately discarded.
const IMPORT_KEY_AUTH_CHALLENGE: &[u8] = b"BLOCH-HD-WALLET-IMPORT-AUTH-v1";

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
    let mut combined = Zeroizing::new(Vec::with_capacity(mnemonic.len() + passphrase.len() + password.len() + 2));
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
    if key.len() != 32 { return Err("AES-256 key must contain 32 bytes".into()); }
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
    if key.len() != 32 { return Err("AES-256 key must contain 32 bytes".into()); }
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

        let file_len = std::fs::metadata(&tmp).unwrap().len() as usize;
        assert!(HdWallet::load_with_file_limit(&tmp, "invalid mnemonic", None, "wrong", file_len - 1)
            .err().unwrap().contains("byte limit"));
        let exact = HdWallet::load_with_file_limit(&tmp, &mnemonic, Some("my-passphrase"), "test-password-12345!", file_len).unwrap();
        assert_eq!(exact.addresses[0].1.address, addr0);
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
        w.import_keypair(random_kp, "legacy").unwrap();
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

    #[test]
    fn load_authenticates_derived_index_and_private_key_but_preserves_imports() {
        let path = std::env::temp_dir().join(format!("bloch-derived-auth-{}.json", std::process::id()));
        let mnemonic = Mnemonic::from_entropy(&[0x43; 32]).unwrap();
        let phrase = mnemonic.to_string();
        let password = "fixture-password";
        let mut file = build_raw_file(&mnemonic, &phrase, password, 3);
        file.addresses[0].index = 1; // metadata is outside the encrypted payload
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert!(HdWallet::load(&path, &phrase, None, password).err().unwrap().contains("does not match"));
        file.addresses[0].derived = false;
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        let imported = HdWallet::load(&path, &phrase, None, password).unwrap();
        assert!(!imported.is_derived(1));
        assert_eq!(imported.get(1).unwrap().address, file.addresses[0].address);

        file.addresses[0].index = 0;
        file.addresses[0].derived = true;
        let key = derive_master_key(&phrase, "", password, 3).unwrap();
        let seed = mnemonic.to_seed("");
        let correct = derive_at(&seed, 0, true).unwrap();
        let unrelated = derive_at(&seed, 1, true).unwrap();
        file.addresses[0].keypair_crypto = encrypt_with_key(&key,
            &serde_json::to_vec(&KeypairPayload {
                public_key_hex: hex::encode(&correct.public_key),
                private_key_hex: hex::encode(&unrelated.private_key),
            }).unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert!(HdWallet::load(&path, &phrase, None, password).err().unwrap().contains("does not match"));
        std::fs::remove_file(&path).unwrap();
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

#[cfg(test)]
mod audit_wallet_boundaries {
    use super::*;
    use crate::wallet::disclosure::{DisclosureBundle, DisclosureKeyConvention, keypair_at, keypair_at_with_convention};
    use crate::address::Network;

    #[test]
    fn disclosure_explicit_hd_convention_matches_existing_funded_keys() {
        let seed = [42;64];
        for index in [0, 1, 7] {
            let existing = derive_at(&seed, index, true).unwrap();
            let (public, secret) = keypair_at_with_convention(&seed, index, DisclosureKeyConvention::HdWalletV3).unwrap();
            let _secret = Zeroizing::new(secret);
            assert_eq!(public, existing.public_key);
            let (legacy, secret) = keypair_at(&seed, index).unwrap();
            let _secret = Zeroizing::new(secret);
            if index == 0 { assert_ne!(legacy, public); } else { assert_eq!(legacy, public); }
        }
        let bundle = DisclosureBundle::create_with_convention(&seed, &[0,1], Network::Testnet,
            "audit", "auditor", DisclosureKeyConvention::HdWalletV3).unwrap();
        assert!(bundle.verify().is_ok());
        assert_eq!(bundle.entries[0].address, derive_at(&seed, 0, true).unwrap().address);
        let legacy = DisclosureBundle::create(&seed, &[0], Network::Testnet, "audit", "auditor").unwrap();
        assert_ne!(legacy.entries[0].address, bundle.entries[0].address);
    }

    #[test]
    fn hostile_wallet_metadata_is_refused_without_changing_legacy_versions() {
        let crypto = encrypt_with_key(&[0; 32], b"fixture").unwrap();
        let mut file = HdWalletFile {
            version: 1, format: "hd-wallet-v1".into(), network: "testnet".into(),
            mnemonic_crypto: crypto.clone(), addresses: vec![HdAddress {
                index: u32::MAX, address: format!("{}fixture", TESTNET_PREFIX),
                label: "last".into(), keypair_crypto: crypto, derived: false,
            }], created_at: String::new(), description: String::new(),
        };
        for version in [1, 2, 3] {
            file.version = version;
            assert!(validate_wallet_structure(&file).is_ok());
        }
        for version in [0, 4, u32::MAX] {
            file.version = version;
            assert_eq!(validate_wallet_structure(&file).unwrap_err(), "unsupported wallet version");
        }
        file.version = 3;
        file.addresses.push(file.addresses[0].clone());
        assert_eq!(validate_wallet_structure(&file).unwrap_err(), "duplicate HD address index");
        file.addresses.pop();
        file.network = "mainnet".into();
        assert!(validate_wallet_structure(&file).is_ok(), "preserve cross-network imported backups");
        file.addresses[0].derived = true;
        assert_eq!(validate_wallet_structure(&file).unwrap_err(), "derived address and wallet network differ");
        file.network = "unrecognized".into();
        assert_eq!(validate_wallet_structure(&file).unwrap_err(), "unsupported wallet network");
        file.network = "testnet".into();
        file.addresses.clear();
        assert_eq!(validate_wallet_structure(&file).unwrap_err(), "HD wallet contains no addresses");
    }

    #[test]
    fn malformed_aes_keys_and_excessive_recovery_counts_are_refused() {
        assert!(HdWallet::recover("not even a mnemonic", None, "password", true, u32::MAX)
            .err().unwrap().contains("4096"));
        let encrypted = encrypt_with_key(&[42;32], b"test").unwrap();
        for length in [0, 1, 31, 33, 100] {
            assert!(encrypt_with_key(&vec![42;length], b"test").is_err());
            assert!(decrypt_with_key(&vec![42;length], &encrypted).is_err());
        }
        for index in [0,1] {
            assert!(keypair_at_with_convention(&[1;31], index, DisclosureKeyConvention::HdWalletV3).is_err());
        }
    }

    #[test]
    fn exhausted_address_index_returns_error_without_rotating_keys() {
        let mnemonic = Mnemonic::from_entropy(&[42;32]).unwrap();
        let seed = mnemonic.to_seed("").to_vec();
        let key = derive_at(&seed, u32::MAX, true).unwrap();
        let address = key.address.clone();
        let mut wallet = HdWallet { mnemonic, master_key:vec![0;32], seed,
            addresses:vec![(u32::MAX,key,"last".into())], imported:BTreeSet::new(),
            network:"testnet".into(), file_version:WALLET_VERSION };
        assert!(wallet.new_address("overflow").err().unwrap().contains("exhausted"));
        assert_eq!(wallet.addresses.len(), 1);
        assert_eq!(wallet.addresses[0].1.address, address);
        let imported_key = derive_at(&wallet.seed, 1, true).unwrap();
        assert!(wallet.try_import_keypair(imported_key, "overflow").unwrap_err().contains("exhausted"));
        let another_key = derive_at(&wallet.seed, 2, true).unwrap();
        assert!(wallet.import_keypair(another_key, "overflow").unwrap_err().contains("exhausted"));
        assert_eq!(wallet.addresses.len(), 1);
        assert!(wallet.imported.is_empty());
        assert_eq!(wallet.addresses[0].0, u32::MAX);
        assert_eq!(wallet.addresses[0].1.address, address);
    }

    #[test]
    fn empty_wallet_state_is_refused_without_synthesizing_index_one() {
        let mnemonic = Mnemonic::from_entropy(&[42;32]).unwrap();
        let seed = mnemonic.to_seed("").to_vec();
        let mut wallet = HdWallet { mnemonic, master_key:vec![0;32], seed,
            addresses:Vec::new(), imported:BTreeSet::new(),
            network:"testnet".into(), file_version:WALLET_VERSION };

        assert_eq!(wallet.new_address("unexpected").unwrap_err(), "HD wallet contains no addresses");
        let imported_key = derive_at(&wallet.seed, 0, true).unwrap();
        assert_eq!(wallet.try_import_keypair(imported_key, "unexpected").unwrap_err(),
            "HD wallet contains no addresses");
        assert!(wallet.addresses.is_empty());
        assert!(wallet.imported.is_empty());
    }

    #[test]
    fn opt_in_load_limits_accept_exact_bounds_and_reject_excess_before_credentials() {
        let crypto = encrypt_with_key(&[0; 32], b"fixture").unwrap();
        let address = |index, derived| HdAddress {
            index,
            address: format!("{}fixture-{index}", TESTNET_PREFIX),
            label: format!("address-{index}"),
            keypair_crypto: crypto.clone(),
            derived,
        };
        let mut file = HdWalletFile {
            version: 3,
            format: "hd-wallet-v1".into(),
            network: "testnet".into(),
            mnemonic_crypto: crypto.clone(),
            addresses: vec![address(0, true), address(1, false), address(2, true)],
            created_at: String::new(),
            description: String::new(),
        };

        let exact = HdWalletLoadLimits {
            max_file_bytes: crate::util::DEFAULT_WALLET_FILE_LIMIT,
            max_addresses: 3,
            max_derived_key_checks: 2,
        };
        assert!(validate_wallet_load_limits(&file, exact).is_ok());

        let address_excess = HdWalletLoadLimits { max_addresses: 2, ..exact };
        assert_eq!(
            validate_wallet_load_limits(&file, address_excess).unwrap_err(),
            "HD wallet address count 3 exceeds configured limit 2"
        );
        let derivation_excess = HdWalletLoadLimits { max_derived_key_checks: 1, ..exact };
        assert_eq!(
            validate_wallet_load_limits(&file, derivation_excess).unwrap_err(),
            "HD wallet derived-key check count 2 exceeds configured limit 1"
        );

        // Exercise the public path with deliberately invalid credentials. The
        // resource error must win, proving it is returned before mnemonic
        // parsing, Argon2 and per-address decryption.
        file.addresses.truncate(1);
        file.addresses[0].derived = false;
        let bytes = serde_json::to_vec(&file).unwrap();
        let path = std::env::temp_dir().join(format!(
            "bloch-hd-load-limits-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, &bytes).unwrap();
        let rejected = HdWallet::load_with_limits(
            &path,
            "not a mnemonic",
            None,
            "wrong",
            HdWalletLoadLimits {
                max_file_bytes: bytes.len(),
                max_addresses: 0,
                max_derived_key_checks: 0,
            },
        )
        .err()
        .unwrap();
        assert!(rejected.contains("address count 1 exceeds configured limit 0"));
        let admitted = HdWallet::load_with_limits(
            &path,
            "not a mnemonic",
            None,
            "wrong",
            HdWalletLoadLimits {
                max_file_bytes: bytes.len(),
                max_addresses: 1,
                max_derived_key_checks: 0,
            },
        )
        .err()
        .unwrap();
        assert!(admitted.contains("invalid mnemonic"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn bounded_default_accepts_exact_work_limits_and_rejects_each_excess() {
        let crypto = encrypt_with_key(&[0; 32], b"fixture").unwrap();
        let address = |index, derived| HdAddress {
            index,
            address: format!("{}fixture-{index}", TESTNET_PREFIX),
            label: String::new(),
            keypair_crypto: crypto.clone(),
            derived,
        };
        let limits = HdWalletLoadLimits::default();
        assert_eq!(limits, DEFAULT_HD_WALLET_LOAD_LIMITS);

        let mut file = HdWalletFile {
            version: 3,
            format: "hd-wallet-v1".into(),
            network: "testnet".into(),
            mnemonic_crypto: crypto.clone(),
            addresses: (0..limits.max_addresses)
                .map(|index| address(index as u32, index < limits.max_derived_key_checks))
                .collect(),
            created_at: String::new(),
            description: String::new(),
        };
        assert!(validate_wallet_load_limits(&file, limits).is_ok());

        file.addresses.push(address(limits.max_addresses as u32, false));
        assert_eq!(
            validate_wallet_load_limits(&file, limits).unwrap_err(),
            "HD wallet address count 1025 exceeds configured limit 1024"
        );

        file.addresses.truncate(limits.max_derived_key_checks + 1);
        for address in &mut file.addresses { address.derived = true; }
        assert_eq!(
            validate_wallet_load_limits(&file, limits).unwrap_err(),
            "HD wallet derived-key check count 257 exceeds configured limit 256"
        );
    }

    #[test]
    fn bounded_payload_caps_accept_exact_limits_and_reject_before_credentials() {
        let mut mnemonic_crypto = encrypt_with_key(&[0; 32], b"fixture").unwrap();
        mnemonic_crypto.ciphertext = "A".repeat(MAX_HD_WALLET_MNEMONIC_CIPHERTEXT_B64_BYTES);
        mnemonic_crypto.nonce = "A".repeat(MAX_HD_WALLET_NONCE_B64_BYTES);
        let mut keypair_crypto = mnemonic_crypto.clone();
        keypair_crypto.ciphertext = "A".repeat(MAX_HD_WALLET_KEYPAIR_CIPHERTEXT_B64_BYTES);
        let mut file = HdWalletFile {
            version: 3,
            format: "hd-wallet-v1".into(),
            network: "testnet".into(),
            mnemonic_crypto,
            addresses: vec![HdAddress {
                index: 0,
                address: format!("{}payload-cap", TESTNET_PREFIX),
                label: String::new(),
                keypair_crypto,
                derived: false,
            }],
            created_at: String::new(),
            description: String::new(),
        };
        let limits = HdWalletLoadLimits {
            max_file_bytes: crate::util::DEFAULT_WALLET_FILE_LIMIT,
            max_addresses: 1,
            max_derived_key_checks: 0,
        };
        assert!(validate_wallet_load_limits(&file, limits).is_ok());

        file.mnemonic_crypto.ciphertext.push('A');
        assert_eq!(
            validate_wallet_load_limits(&file, limits).unwrap_err(),
            "HD wallet mnemonic ciphertext encoding length 4097 exceeds bounded limit 4096"
        );
        file.mnemonic_crypto.ciphertext.pop();
        file.addresses[0].keypair_crypto.ciphertext.push('A');
        assert_eq!(
            validate_wallet_load_limits(&file, limits).unwrap_err(),
            "HD wallet keypair 0 ciphertext encoding length 65537 exceeds bounded limit 65536"
        );
        file.addresses[0].keypair_crypto.ciphertext.pop();
        file.addresses[0].keypair_crypto.nonce.push('A');
        assert_eq!(
            validate_wallet_load_limits(&file, limits).unwrap_err(),
            "HD wallet keypair 0 nonce encoding length 65 exceeds bounded limit 64"
        );

        // Exercise both production bounded readers with an excess ciphertext.
        // The resource error must win over invalid credentials, proving that
        // no Argon2, Base64 decode or AES plaintext allocation was attempted.
        file.addresses[0].keypair_crypto.nonce.pop();
        file.addresses[0].keypair_crypto.ciphertext.push('A');
        let bytes = serde_json::to_vec(&file).unwrap();
        let path = std::env::temp_dir().join(format!(
            "bloch-hd-payload-caps-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, &bytes).unwrap();
        let expected =
            "HD wallet keypair 0 ciphertext encoding length 65537 exceeds bounded limit 65536";
        assert_eq!(HdWalletFile::read_public_bounded(&path).err().unwrap(), expected);
        assert_eq!(
            HdWallet::load_with_limits(&path, "not a mnemonic", None, "wrong", limits)
                .err().unwrap(),
            expected
        );

        // Explicit trusted public recovery retains its historical policy.
        assert!(HdWalletFile::read_public_with_limits(&path, bytes.len(), 1).is_ok());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn authenticated_address_metadata_moves_without_duplicate_buffers() {
        let crypto = encrypt_with_key(&[0; 32], b"fixture").unwrap();
        let address_text = format!("{}move-owned-address", TESTNET_PREFIX);
        let label = "L".repeat(32 * 1024);
        let address_pointer = address_text.as_ptr();
        let label_pointer = label.as_ptr();
        let record = HdAddress {
            index: 7,
            address: address_text,
            label,
            keypair_crypto: crypto,
            derived: false,
        };

        let (loaded, is_imported) = into_loaded_address(record, vec![1, 2], vec![3, 4]);
        assert_eq!(loaded.0, 7);
        assert!(is_imported);
        assert_eq!(loaded.1.address.as_ptr(), address_pointer);
        assert_eq!(loaded.2.as_ptr(), label_pointer);
        assert_eq!(loaded.1.private_key, vec![1, 2]);
        assert_eq!(loaded.1.public_key, vec![3, 4]);
    }

    #[test]
    fn decrypted_secret_strings_borrow_plaintext_and_preserve_escaped_json() {
        let mnemonic_plaintext = Zeroizing::new(serde_json::to_vec(&MnemonicPayload {
            mnemonic: "alpha beta gamma".into(),
        }).unwrap());
        let mnemonic: BorrowedMnemonicPayload<'_> =
            serde_json::from_slice(&mnemonic_plaintext).unwrap();
        assert!(matches!(&mnemonic.mnemonic, Cow::Borrowed(_)));
        let mnemonic_pointer = mnemonic.mnemonic.as_ptr() as usize;
        let mnemonic_start = mnemonic_plaintext.as_ptr() as usize;
        assert!(mnemonic_pointer >= mnemonic_start);
        assert!(mnemonic_pointer < mnemonic_start + mnemonic_plaintext.len());
        drop(mnemonic);

        let plaintext = Zeroizing::new(serde_json::to_vec(&KeypairPayload {
            private_key_hex: "a1b2c3d4".into(),
            public_key_hex: "01020304".into(),
        }).unwrap());
        let parsed: BorrowedKeypairPayload<'_> = serde_json::from_slice(&plaintext).unwrap();
        assert!(matches!(&parsed.private_key_hex, Cow::Borrowed(_)));
        assert!(matches!(&parsed.public_key_hex, Cow::Borrowed(_)));
        let private_pointer = parsed.private_key_hex.as_ptr() as usize;
        let plaintext_start = plaintext.as_ptr() as usize;
        assert!(private_pointer >= plaintext_start);
        assert!(private_pointer < plaintext_start + plaintext.len());
        assert_eq!(hex::decode(parsed.private_key_hex.as_ref()).unwrap(), [0xa1, 0xb2, 0xc3, 0xd4]);
        drop(parsed);

        // Serde must allocate to unescape this equivalent historical shape.
        // Keeping Cow's owned path preserves it, while Drop wipes the owned
        // private string instead of leaving the compatibility copy behind.
        let escaped = br#"{
            "private_key_hex":"\u0061\u0062",
            "public_key_hex":"\u0063\u0064"
        }"#;
        let escaped_parsed: BorrowedKeypairPayload<'_> =
            serde_json::from_slice(escaped).unwrap();
        assert!(matches!(&escaped_parsed.private_key_hex, Cow::Owned(_)));
        assert!(matches!(&escaped_parsed.public_key_hex, Cow::Owned(_)));
        assert_eq!(hex::decode(escaped_parsed.private_key_hex.as_ref()).unwrap(), [0xab]);
        assert_eq!(hex::decode(escaped_parsed.public_key_hex.as_ref()).unwrap(), [0xcd]);

        let escaped_mnemonic: BorrowedMnemonicPayload<'_> = serde_json::from_slice(
            br#"{"mnemonic":"alpha\u0020beta"}"#,
        ).unwrap();
        assert!(matches!(&escaped_mnemonic.mnemonic, Cow::Owned(_)));
        assert_eq!(escaped_mnemonic.mnemonic.as_ref(), "alpha beta");
    }

    #[test]
    fn json_preflight_enforces_exact_record_limits_before_full_allocation() {
        let exact = br#"{
            "ignored": {"large-shaped-payload": [1, 2, 3]},
            "addresses": [
                {"derived": true, "label": "first"},
                {"label": "legacy", "derived": false}
            ]
        }"#;
        assert!(preflight_wallet_record_limits(exact, 2, Some(1)).is_ok());
        assert_eq!(
            preflight_wallet_record_limits(exact, 1, Some(1)).unwrap_err(),
            "HD wallet address count 2 exceeds configured limit 1"
        );
        assert_eq!(
            preflight_wallet_record_limits(exact, 2, Some(0)).unwrap_err(),
            "HD wallet derived-key check count 1 exceeds configured limit 0"
        );

        // The third record is deliberately truncated. Charging the record as
        // soon as it begins must return the resource-limit error before either
        // parsing or allocating any of that excess record's fields.
        let hostile_overflow = br#"{"addresses":[{}, {}, {"huge": "#;
        assert_eq!(
            preflight_wallet_record_limits(hostile_overflow, 2, None).unwrap_err(),
            "HD wallet address count 3 exceeds configured limit 2"
        );
    }

    #[test]
    fn json_preflight_matches_serde_struct_sequence_semantics_and_limits() {
        fn positional_struct(
            value: serde_json::Value,
            fields: &[&str],
        ) -> serde_json::Value {
            let mut object = value.as_object().cloned().expect("serialized struct object");
            serde_json::Value::Array(
                fields
                    .iter()
                    .map(|field| object.remove(*field).expect("serialized struct field"))
                    .collect(),
            )
        }

        let crypto = encrypt_with_key(&[0; 32], b"fixture").unwrap();
        let file = HdWalletFile {
            version: 3,
            format: "hd-wallet-v1".into(),
            network: "testnet".into(),
            mnemonic_crypto: crypto.clone(),
            addresses: vec![
                HdAddress {
                    index: 0,
                    address: format!("{}derived", TESTNET_PREFIX),
                    label: "derived".into(),
                    keypair_crypto: crypto.clone(),
                    derived: true,
                },
                HdAddress {
                    index: 1,
                    address: format!("{}imported", TESTNET_PREFIX),
                    label: "imported".into(),
                    keypair_crypto: crypto,
                    derived: false,
                },
            ],
            created_at: String::new(),
            description: String::new(),
        };

        let map_bytes = serde_json::to_vec(&file).unwrap();
        let mut top = serde_json::to_value(&file)
            .unwrap()
            .as_object()
            .cloned()
            .unwrap();
        let positional_addresses = top
            .remove("addresses")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .cloned()
            .map(|address| positional_struct(address, HD_ADDRESS_FIELDS))
            .collect();
        top.insert(
            "addresses".into(),
            serde_json::Value::Array(positional_addresses),
        );
        let sequence_bytes = serde_json::to_vec(&positional_struct(
            serde_json::Value::Object(top),
            HD_WALLET_FIELDS,
        ))
        .unwrap();

        // Both representations are accepted by HdWalletFile's actual Serde
        // implementation and must receive identical preflight accounting.
        assert_eq!(
            serde_json::from_slice::<HdWalletFile>(&sequence_bytes)
                .unwrap()
                .addresses
                .len(),
            2
        );
        let path = std::env::temp_dir().join(format!(
            "bloch-hd-positional-preflight-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, &sequence_bytes).unwrap();
        assert_eq!(
            HdWalletFile::read_public_with_limits(&path, sequence_bytes.len(), 2)
                .unwrap()
                .addresses
                .len(),
            2
        );
        std::fs::remove_file(path).unwrap();
        for bytes in [&map_bytes[..], &sequence_bytes[..]] {
            assert!(preflight_wallet_record_limits(bytes, 2, Some(1)).is_ok());
            assert_eq!(
                preflight_wallet_record_limits(bytes, 1, Some(1)).unwrap_err(),
                "HD wallet address count 2 exceeds configured limit 1"
            );
            assert_eq!(
                preflight_wallet_record_limits(bytes, 2, Some(0)).unwrap_err(),
                "HD wallet derived-key check count 1 exceeds configured limit 0"
            );
        }

        // Sequence form keeps the same early-charge guarantee: the third
        // record is counted before its truncated payload is parsed.
        let hostile_sequence = br#"[null,null,null,null,[[],[],["#;
        assert_eq!(
            preflight_wallet_record_limits(hostile_sequence, 2, None).unwrap_err(),
            "HD wallet address count 3 exceeds configured limit 2"
        );
    }

    #[test]
    fn public_metadata_reader_accepts_exact_bounds_and_rejects_each_excess() {
        let crypto = encrypt_with_key(&[0; 32], b"fixture").unwrap();
        let address = |index| HdAddress {
            index,
            address: format!("{}public-{index}", TESTNET_PREFIX),
            label: format!("label-{index}"),
            keypair_crypto: crypto.clone(),
            // Public listing performs no mnemonic rederivation. Marking these
            // imports also proves that only the aggregate record cap applies.
            derived: false,
        };
        let limit = DEFAULT_HD_WALLET_LOAD_LIMITS.max_addresses;
        let mut file = HdWalletFile {
            version: 3,
            format: "hd-wallet-v1".into(),
            network: "testnet".into(),
            mnemonic_crypto: crypto.clone(),
            addresses: (0..limit).map(|index| address(index as u32)).collect(),
            created_at: String::new(),
            description: String::new(),
        };
        let path = std::env::temp_dir().join(format!(
            "bloch-hd-public-limits-{}.json",
            std::process::id()
        ));

        let exact_bytes = serde_json::to_vec(&file).unwrap();
        std::fs::write(&path, &exact_bytes).unwrap();
        let exact = HdWalletFile::read_public_with_limits(&path, exact_bytes.len(), limit)
            .expect("exact byte and record limits must be accepted");
        assert_eq!(exact.addresses.len(), limit);
        assert!(HdWalletFile::read_public_bounded(&path).is_ok());
        assert!(HdWalletFile::read_public_with_limits(&path, exact_bytes.len() - 1, limit)
            .err().unwrap().contains("byte limit"));

        file.addresses.push(address(limit as u32));
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert_eq!(
            HdWalletFile::read_public_bounded(&path).err().unwrap(),
            "HD wallet address count 1025 exceeds configured limit 1024"
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn import_rejects_inconsistent_key_material_without_mutating_wallet() {
        let mut wallet = HdWallet::recover(
            &Mnemonic::from_entropy(&[43;32]).unwrap().to_string(),
            None, "fixture-password", true, 1,
        ).unwrap();
        let original_address = wallet.addresses[0].1.address.clone();
        let first = derive_at(&wallet.seed, 7, true).unwrap();
        let second = derive_at(&wallet.seed, 8, true).unwrap();

        let wrong_address = Keypair {
            private_key: first.private_key.clone(),
            public_key: first.public_key.clone(),
            address: second.address.clone(),
        };
        assert_eq!(wallet.try_import_keypair(wrong_address, "wrong-address").unwrap_err(),
            "imported keypair public key does not match address");

        let mismatched_keys = Keypair {
            private_key: first.private_key.clone(),
            public_key: second.public_key.clone(),
            address: second.address.clone(),
        };
        assert_eq!(wallet.try_import_keypair(mismatched_keys, "mismatched").unwrap_err(),
            "imported keypair private/public keys do not match");
        assert_eq!(wallet.addresses.len(), 1);
        assert_eq!(wallet.addresses[0].1.address, original_address);
        assert!(wallet.imported.is_empty());

        wallet.try_import_keypair(first, "valid").unwrap();
        assert_eq!(wallet.addresses.len(), 2);
        assert!(wallet.imported.contains(&1));

        let third = derive_at(&wallet.seed, 9, true).unwrap();
        let raw_public = third.public_key[crypto::SUITE_HEADER_LEN..].to_vec();
        let raw_legacy = Keypair {
            private_key: third.private_key[crypto::SUITE_HEADER_LEN..].to_vec(),
            address: crypto::address_from_pubkey(&raw_public, true),
            public_key: raw_public,
        };
        wallet.try_import_keypair(raw_legacy, "valid-legacy-raw").unwrap();
        assert_eq!(wallet.addresses.len(), 3);
        assert!(wallet.imported.contains(&2));
    }
}
