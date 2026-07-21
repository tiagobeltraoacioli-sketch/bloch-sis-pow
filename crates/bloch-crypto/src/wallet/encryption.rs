//! Encrypted wallet keyfile format.
//!
//! Keyfile is a JSON document with this structure:
//!
//! ```json
//! {
//!   "version": 1,
//!   "network": "mainnet",
//!   "kdf": {
//!     "algo": "argon2id",
//!     "salt_b64": "...",
//!     "m_cost": 65536,
//!     "t_cost": 3,
//!     "p_cost": 4
//!   },
//!   "cipher": {
//!     "algo": "aes-256-gcm",
//!     "nonce_b64": "...",
//!     "ciphertext_b64": "..."
//!   },
//!   "meta": {
//!     "public_key_b64": "...",
//!     "address": "bloch1q..."
//!   }
//! }
//! ```
//!
//! Security properties:
//!
//!   - AES-256-GCM: authenticated encryption — MAC catches tampering
//!   - Argon2id: memory-hard KDF resists GPU/ASIC brute-force
//!   - Random salt per keyfile: rainbow tables useless
//!   - Random nonce per encrypt: same password encrypts to different ciphertext
//!   - Public key stored in metadata: wallet address visible without unlocking
//!
//! Threat model:
//!   - Attacker with keyfile + weak password → recovers keys via brute-force
//!     Mitigation: warn users, require ≥12 chars + complexity
//!   - Attacker with keyfile + strong password → computationally infeasible
//!     Argon2id with 64MB memory cost = ~1 second per attempt on modern CPU
//!   - Attacker with keyfile + correct password → can use wallet (intended)

use super::errors::WalletError;
use crate::address::Network;
use serde::{Serialize, Deserialize};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit, Payload}};
use sha3::{Sha3_256, Digest};
use argon2::{Argon2, Algorithm, Version, Params};
use rand::RngCore;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use zeroize::{Zeroize, Zeroizing};

/// Current keyfile version.
/// v1 = Argon2id + AES-256-GCM (this implementation).
const KEYFILE_VERSION: u32 = 1;

/// v2 keyfile (P4 — diversified-address wallets): same Argon2id + AES-256-GCM
/// construction, but the ciphertext protects the wallet MASTER SEED alongside
/// the base secret key, so index-N receive addresses (`crypto::diversified_*`)
/// and selective-disclosure bundles (`wallet::disclosure`) can be produced from
/// an encrypted-at-rest store instead of forcing the user to re-type the seed
/// phrase for every derivation. v2 uses its OWN AAD domain ("bloch-kf2" + the
/// version number, see `keyfile_aad_v2`), so a v2 ciphertext can never be
/// re-labelled and decrypted under v1 semantics or vice versa — the GCM tag
/// fails on any cross-version replay.
pub const KEYFILE_VERSION_V2: u32 = 2;

/// Bounds for the v2 plaintext layout (`[4B seed_len LE][seed][secret]`).
/// The BIP39 PBKDF2 seed is 64 bytes; 32 is the floor `generate_keypair_from_seed`
/// accepts; 128 leaves headroom without letting a corrupt field run away.
const V2_SEED_MIN: usize = 32;
const V2_SEED_MAX: usize = 128;

/// KDF parameters. Tuned for ~4 seconds on modern CPU (2026).
///
/// Sprint T.2 — Audit M-4 fix: bumped from 64MiB/m_cost=65536 to 256MiB/m_cost=262144
/// to quadruple attacker GPU/ASIC cost on brute force of weak passwords.
/// Existing keystore files carry their own KdfParams in the KdfDesc struct —
/// old files continue to decrypt with their original 64MiB cost; only NEW
/// encryptions use the higher default.
#[derive(Clone, Copy)]
pub struct KdfParams {
    pub m_cost: u32,    // Memory cost in KiB. 262144 = 256 MiB (Sprint T.2)
    pub t_cost: u32,    // Time cost (iterations). 4 = balanced at 256MiB
    pub p_cost: u32,    // Parallelism. 4 threads
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 262_144,  // 256 MiB — Sprint T.2 bump (was 65_536)
            t_cost: 4,
            p_cost: 4,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedKeyfile {
    pub version: u32,
    pub network: NetworkStr,
    pub kdf: KdfDesc,
    pub cipher: CipherDesc,
    pub meta: Meta,
}

#[derive(Serialize, Deserialize)]
pub struct KdfDesc {
    pub algo: String,      // "argon2id"
    pub salt_b64: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

#[derive(Serialize, Deserialize)]
pub struct CipherDesc {
    pub algo: String,      // "aes-256-gcm"
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Serialize, Deserialize)]
pub struct Meta {
    pub public_key_b64: String,
    pub address: String,
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub enum NetworkStr {
    #[serde(rename = "mainnet")]
    Mainnet,
    #[serde(rename = "testnet")]
    Testnet,
}

impl From<Network> for NetworkStr {
    fn from(n: Network) -> Self {
        match n {
            Network::Mainnet => NetworkStr::Mainnet,
            Network::Testnet => NetworkStr::Testnet,
        }
    }
}

impl From<NetworkStr> for Network {
    fn from(s: NetworkStr) -> Self {
        match s {
            NetworkStr::Mainnet => Network::Mainnet,
            NetworkStr::Testnet => Network::Testnet,
        }
    }
}

impl EncryptedKeyfile {
    /// Encrypt a secret key with the given password and default KDF params.
    pub fn encrypt(
        secret: &[u8],
        public: &[u8],
        network: Network,
        password: &str,
    ) -> Result<Self, WalletError> {
        Self::encrypt_with_params(secret, public, network, password, KdfParams::default())
    }

    /// Encrypt with custom KDF parameters (for tuning or low-resource devices).
    pub fn encrypt_with_params(
        secret: &[u8],
        public: &[u8],
        network: Network,
        password: &str,
        params: KdfParams,
    ) -> Result<Self, WalletError> {
        // Sprint T.3 — Audit M-5 fix: stricter password policy.
        // Previous policy (8 char min) allowed trivially crackable passwords
        // like "password" or "12345678". New policy: 12 char minimum plus a
        // denylist of the most commonly breached passwords. This is intentionally
        // a BLOCKING check, not a warning — a weak password renders all the
        // Argon2 hardening moot.
        validate_password_strength(password)?;

        // Generate random salt + nonce
        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut nonce_bytes);

        // Derive encryption key via Argon2id
        let mut key = [0u8; 32];
        derive_key(password, &salt, params, &mut key)?;

        // Encrypt with AES-256-GCM
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let nonce = Nonce::from_slice(&nonce_bytes);
        // SECURITY (audit M2): bind the public key + network into the AEAD as
        // AAD so they cannot be swapped without breaking the GCM tag. Otherwise
        // an attacker with write access swaps meta.public_key for their own and
        // deposits route to an address they control, while decrypt still reports
        // "integrity OK" (the tag only covered the secret).
        let aad = keyfile_aad(public, network);
        let ciphertext = cipher.encrypt(nonce, Payload { msg: secret, aad: &aad })
            .map_err(|e| WalletError::Crypto(format!("AES-GCM encrypt: {}", e)))?;

        // Zero the key immediately after use
        key.zeroize();

        // Build address string for metadata
        let hash_full = Sha3_256::digest(public);
        let mut addr_hash = [0u8; 20];
        addr_hash.copy_from_slice(&hash_full[..20]);
        let is_testnet = matches!(network, Network::Testnet);
        let address = crate::crypto::address_from_hash(&addr_hash, is_testnet);

        Ok(EncryptedKeyfile {
            version: KEYFILE_VERSION,
            network: network.into(),
            kdf: KdfDesc {
                algo: "argon2id".to_string(),
                salt_b64: B64.encode(&salt),
                m_cost: params.m_cost,
                t_cost: params.t_cost,
                p_cost: params.p_cost,
            },
            cipher: CipherDesc {
                algo: "aes-256-gcm".to_string(),
                nonce_b64: B64.encode(&nonce_bytes),
                ciphertext_b64: B64.encode(&ciphertext),
            },
            meta: Meta {
                public_key_b64: B64.encode(public),
                address,
            },
        })
    }

    /// Decrypt with password. Returns (secret, public, network).
    pub fn decrypt(&self, password: &str) -> Result<(Vec<u8>, Vec<u8>, Network), WalletError> {
        // Version check
        if self.version != KEYFILE_VERSION {
            return Err(WalletError::UnsupportedVersion(self.version));
        }

        // Algorithm checks
        if self.kdf.algo != "argon2id" {
            return Err(WalletError::Parse(format!("unknown KDF: {}", self.kdf.algo)));
        }
        if self.cipher.algo != "aes-256-gcm" {
            return Err(WalletError::Parse(format!("unknown cipher: {}", self.cipher.algo)));
        }

        // Decode base64
        let salt = B64.decode(&self.kdf.salt_b64).map_err(|e| WalletError::Parse(e.to_string()))?;
        let nonce_bytes = B64.decode(&self.cipher.nonce_b64).map_err(|e| WalletError::Parse(e.to_string()))?;
        let ciphertext = B64.decode(&self.cipher.ciphertext_b64).map_err(|e| WalletError::Parse(e.to_string()))?;
        let public = B64.decode(&self.meta.public_key_b64).map_err(|e| WalletError::Parse(e.to_string()))?;

        // SECURITY (audit M): length-guard fields decoded from the untrusted
        // keyfile BEFORE they reach fixed-size consumers. `Nonce::from_slice`
        // PANICS on any length other than 12 bytes, so a truncated or corrupt
        // keyfile would crash the process instead of returning an error. The
        // salt and ciphertext are guarded too: v1 keyfiles always carry a
        // 16-byte salt, and an AES-256-GCM ciphertext shorter than the 16-byte
        // tag cannot possibly be valid.
        const SALT_LEN: usize = 16;
        const NONCE_LEN: usize = 12;
        const GCM_TAG_LEN: usize = 16;
        if salt.len() != SALT_LEN {
            return Err(WalletError::Parse(format!(
                "keyfile salt has invalid length: expected {} bytes, got {}",
                SALT_LEN, salt.len()
            )));
        }
        if nonce_bytes.len() != NONCE_LEN {
            return Err(WalletError::Parse(format!(
                "keyfile nonce has invalid length: expected {} bytes, got {}",
                NONCE_LEN, nonce_bytes.len()
            )));
        }
        if ciphertext.len() < GCM_TAG_LEN {
            return Err(WalletError::Parse(format!(
                "keyfile ciphertext too short: {} bytes, need at least the {}-byte GCM tag",
                ciphertext.len(), GCM_TAG_LEN
            )));
        }

        // SECURITY (audit L1): reject absurd KDF params from the untrusted
        // keyfile BEFORE handing them to Argon2. m_cost near u32::MAX (KiB)
        // forces a multi-terabyte allocation that OOM-kills the process on any
        // unlock attempt; large t_cost is a CPU slow-loris.
        const MAX_M_COST_KIB: u32 = 1024 * 1024; // 1 GiB
        const MAX_T_COST: u32 = 16;
        const MAX_P_COST: u32 = 16;
        if self.kdf.m_cost > MAX_M_COST_KIB
            || self.kdf.t_cost > MAX_T_COST
            || self.kdf.p_cost > MAX_P_COST
        {
            return Err(WalletError::Parse(format!(
                "KDF params out of bounds (m_cost={} KiB, t_cost={}, p_cost={})",
                self.kdf.m_cost, self.kdf.t_cost, self.kdf.p_cost
            )));
        }

        // Derive key
        let params = KdfParams {
            m_cost: self.kdf.m_cost,
            t_cost: self.kdf.t_cost,
            p_cost: self.kdf.p_cost,
        };
        let mut key = [0u8; 32];
        derive_key(password, &salt, params, &mut key)?;

        // Decrypt
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let nonce = Nonce::from_slice(&nonce_bytes);
        // SECURITY (audit M2): verify against the same public+network AAD used
        // at encrypt time. A tampered public key or flipped network breaks the
        // GCM tag → WrongPassword, so a swapped receive address cannot pass as
        // "integrity OK".
        let net: Network = self.network.into();
        let aad = keyfile_aad(&public, net);
        let secret = cipher.decrypt(nonce, Payload { msg: ciphertext.as_ref(), aad: &aad })
            .map_err(|_| WalletError::WrongPassword)?;

        key.zeroize();

        Ok((secret, public, net))
    }

    // ── v2: master seed encrypted at rest (P4) ────────────────────────────────

    /// Encrypt a v2 keyfile protecting `(master_seed, secret)` under `password`
    /// with default KDF params. `master_seed` is the 64-byte BIP39 seed
    /// (`SeedPhrase::to_seed_bytes()`); `secret`/`public` are the base (index-0)
    /// keypair, so a v2 file is a strict superset of a v1 file: everything v1
    /// enabled still works, plus diversified derivation and disclosure.
    pub fn encrypt_seed_v2(
        master_seed: &[u8],
        secret: &[u8],
        public: &[u8],
        network: Network,
        password: &str,
    ) -> Result<Self, WalletError> {
        Self::encrypt_seed_v2_with_params(
            master_seed, secret, public, network, password, KdfParams::default())
    }

    /// v2 encrypt with custom KDF parameters (tuning / low-resource devices).
    pub fn encrypt_seed_v2_with_params(
        master_seed: &[u8],
        secret: &[u8],
        public: &[u8],
        network: Network,
        password: &str,
        params: KdfParams,
    ) -> Result<Self, WalletError> {
        if master_seed.len() < V2_SEED_MIN || master_seed.len() > V2_SEED_MAX {
            return Err(WalletError::Crypto(format!(
                "master seed length {} out of bounds ({}..={})",
                master_seed.len(), V2_SEED_MIN, V2_SEED_MAX)));
        }
        // Same blocking password policy as v1 (Sprint T.3 / Audit M-5).
        validate_password_strength(password)?;

        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut nonce_bytes);

        let mut key = [0u8; 32];
        derive_key(password, &salt, params, &mut key)?;

        // Plaintext: [4B seed_len LE][seed][secret]. Zeroizing so the buffer
        // wipes on every exit path.
        let mut plain = Zeroizing::new(Vec::with_capacity(4 + master_seed.len() + secret.len()));
        plain.extend_from_slice(&(master_seed.len() as u32).to_le_bytes());
        plain.extend_from_slice(master_seed);
        plain.extend_from_slice(secret);

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let nonce = Nonce::from_slice(&nonce_bytes);
        // v2 AAD domain: binds version + public key + network (audit M2 for v1,
        // extended with the version so cross-version replay breaks the tag).
        let aad = keyfile_aad_v2(public, network);
        let ciphertext = cipher.encrypt(nonce, Payload { msg: plain.as_slice(), aad: &aad })
            .map_err(|e| WalletError::Crypto(format!("AES-GCM encrypt: {}", e)))?;

        key.zeroize();

        let hash_full = Sha3_256::digest(public);
        let mut addr_hash = [0u8; 20];
        addr_hash.copy_from_slice(&hash_full[..20]);
        let is_testnet = matches!(network, Network::Testnet);
        let address = crate::crypto::address_from_hash(&addr_hash, is_testnet);

        Ok(EncryptedKeyfile {
            version: KEYFILE_VERSION_V2,
            network: network.into(),
            kdf: KdfDesc {
                algo: "argon2id".to_string(),
                salt_b64: B64.encode(&salt),
                m_cost: params.m_cost,
                t_cost: params.t_cost,
                p_cost: params.p_cost,
            },
            cipher: CipherDesc {
                algo: "aes-256-gcm".to_string(),
                nonce_b64: B64.encode(&nonce_bytes),
                ciphertext_b64: B64.encode(&ciphertext),
            },
            meta: Meta {
                public_key_b64: B64.encode(public),
                address,
            },
        })
    }

    /// Decrypt a v2 keyfile. Returns `(master_seed, secret, public, network)`
    /// with both secrets in `Zeroizing` wrappers so they wipe when the caller
    /// drops them.
    ///
    /// The guards below intentionally mirror `decrypt()` verbatim rather than
    /// share a helper: the v1 path is audited (M, M2, L1) and stays untouched.
    pub fn decrypt_v2(&self, password: &str)
        -> Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>, Vec<u8>, Network), WalletError>
    {
        if self.version != KEYFILE_VERSION_V2 {
            return Err(WalletError::UnsupportedVersion(self.version));
        }
        if self.kdf.algo != "argon2id" {
            return Err(WalletError::Parse(format!("unknown KDF: {}", self.kdf.algo)));
        }
        if self.cipher.algo != "aes-256-gcm" {
            return Err(WalletError::Parse(format!("unknown cipher: {}", self.cipher.algo)));
        }

        let salt = B64.decode(&self.kdf.salt_b64).map_err(|e| WalletError::Parse(e.to_string()))?;
        let nonce_bytes = B64.decode(&self.cipher.nonce_b64).map_err(|e| WalletError::Parse(e.to_string()))?;
        let ciphertext = B64.decode(&self.cipher.ciphertext_b64).map_err(|e| WalletError::Parse(e.to_string()))?;
        let public = B64.decode(&self.meta.public_key_b64).map_err(|e| WalletError::Parse(e.to_string()))?;

        // Length guards (audit M): Nonce::from_slice panics off-length; salt is
        // fixed 16B; a GCM ciphertext below tag size cannot be valid.
        const SALT_LEN: usize = 16;
        const NONCE_LEN: usize = 12;
        const GCM_TAG_LEN: usize = 16;
        if salt.len() != SALT_LEN {
            return Err(WalletError::Parse(format!(
                "keyfile salt has invalid length: expected {} bytes, got {}",
                SALT_LEN, salt.len())));
        }
        if nonce_bytes.len() != NONCE_LEN {
            return Err(WalletError::Parse(format!(
                "keyfile nonce has invalid length: expected {} bytes, got {}",
                NONCE_LEN, nonce_bytes.len())));
        }
        if ciphertext.len() < GCM_TAG_LEN {
            return Err(WalletError::Parse(format!(
                "keyfile ciphertext too short: {} bytes, need at least the {}-byte GCM tag",
                ciphertext.len(), GCM_TAG_LEN)));
        }

        // KDF-parameter bounds (audit L1): reject OOM/slow-loris params from
        // the untrusted file before Argon2 sees them.
        const MAX_M_COST_KIB: u32 = 1024 * 1024; // 1 GiB
        const MAX_T_COST: u32 = 16;
        const MAX_P_COST: u32 = 16;
        if self.kdf.m_cost > MAX_M_COST_KIB
            || self.kdf.t_cost > MAX_T_COST
            || self.kdf.p_cost > MAX_P_COST
        {
            return Err(WalletError::Parse(format!(
                "KDF params out of bounds (m_cost={} KiB, t_cost={}, p_cost={})",
                self.kdf.m_cost, self.kdf.t_cost, self.kdf.p_cost)));
        }

        let params = KdfParams {
            m_cost: self.kdf.m_cost,
            t_cost: self.kdf.t_cost,
            p_cost: self.kdf.p_cost,
        };
        let mut key = [0u8; 32];
        derive_key(password, &salt, params, &mut key)?;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let net: Network = self.network.into();
        let aad = keyfile_aad_v2(&public, net);
        let plain = Zeroizing::new(
            cipher.decrypt(nonce, Payload { msg: ciphertext.as_ref(), aad: &aad })
                .map_err(|_| WalletError::WrongPassword)?);
        key.zeroize();

        // Parse [4B seed_len LE][seed][secret] with bounds checks — the
        // plaintext is authenticated, so a failure here means an encoder bug,
        // but never index out of bounds.
        if plain.len() < 4 {
            return Err(WalletError::Parse("v2 payload truncated (missing seed length)".into()));
        }
        let seed_len = u32::from_le_bytes([plain[0], plain[1], plain[2], plain[3]]) as usize;
        if seed_len < V2_SEED_MIN || seed_len > V2_SEED_MAX || plain.len() < 4 + seed_len {
            return Err(WalletError::Parse(format!(
                "v2 payload seed length {} out of bounds", seed_len)));
        }
        let master_seed = Zeroizing::new(plain[4..4 + seed_len].to_vec());
        let secret = Zeroizing::new(plain[4 + seed_len..].to_vec());

        Ok((master_seed, secret, public, net))
    }
}

/// AAD that binds the public key + network into the keyfile AEAD (audit M2),
/// so neither can be altered without invalidating the GCM tag. Domain-tagged
/// to avoid any cross-context collision.
fn keyfile_aad(public: &[u8], network: Network) -> Vec<u8> {
    let mut aad = Vec::with_capacity(public.len() + 9);
    aad.extend_from_slice(b"bloch-kf");
    aad.push(match network { Network::Testnet => 1u8, _ => 0u8 });
    aad.extend_from_slice(public);
    aad
}

/// v2 AAD: a DISTINCT domain tag plus the format version, then the same
/// network + public-key binding as v1. Because the v1 tag ("bloch-kf") and the
/// v2 tag ("bloch-kf2" + version bytes) never collide, flipping the `version`
/// field on a keyfile re-routes decryption to the other AAD and the GCM tag
/// fails closed (`WrongPassword`) — a v2 seed ciphertext can never be
/// mis-decrypted as a v1 "secret key only" blob or vice versa.
fn keyfile_aad_v2(public: &[u8], network: Network) -> Vec<u8> {
    let mut aad = Vec::with_capacity(public.len() + 14);
    aad.extend_from_slice(b"bloch-kf2");
    aad.extend_from_slice(&KEYFILE_VERSION_V2.to_le_bytes());
    aad.push(match network { Network::Testnet => 1u8, _ => 0u8 });
    aad.extend_from_slice(public);
    aad
}

/// Argon2id KDF wrapper.
fn derive_key(
    password: &str,
    salt: &[u8],
    params: KdfParams,
    output: &mut [u8],
) -> Result<(), WalletError> {
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, None)
        .map_err(|e| WalletError::Crypto(format!("argon2 params: {}", e)))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    argon.hash_password_into(password.as_bytes(), salt, output)
        .map_err(|e| WalletError::Crypto(format!("argon2: {}", e)))?;
    Ok(())
}

/// Reject passwords that would defeat the Argon2id hardening anyway.
///
/// Sprint T.3 — Audit M-5 fix. Two checks:
///
/// 1. Length >= 12 characters. NIST SP 800-63B recommends 8 as an absolute
///    minimum for human-memorized secrets but allows implementations to require
///    more. 12 is the widely-used threshold for "strong enough that brute force
///    needs real compute". We measure in bytes, not graphemes — a 12-byte ASCII
///    password and a 4-emoji password (each emoji is ~4 bytes) both pass, and
///    both have enough entropy if the emojis are chosen randomly.
///
/// 2. Not on the denylist of most-breached passwords. This is a tiny hardcoded
///    list — not a replacement for haveibeenpwned-style services, but catches
///    the "password123"-tier obvious picks that Argon2id cannot rescue.
///
/// The denylist is checked after lowercasing and trimming surrounding whitespace
/// to catch "PASSWORD123" and "  password123  " as equivalents.
fn validate_password_strength(password: &str) -> Result<(), WalletError> {
    const MIN_LEN: usize = 12;

    // Denylist: top ~50 most-breached passwords per public leak corpora.
    // ALL entries must be >= 12 chars to be actually hit by this check after
    // the length gate — shorter ones are already caught by `len() < MIN_LEN`.
    // Kept short intentionally — this is a sanity filter, not a WAF.
    const DENYLIST: &[&str] = &[
        // Very common patterns that meet length but are worthless entropy
        "password1234",
        "password12345",
        "passwordpassword",
        "123456789012",
        "1234567890123",
        "12345678901234",
        "qwertyuiopas",
        "qwertyuiop12",
        "qwerty1234567",
        "letmeinplease",
        "welcomewelcome",
        "administrator",
        "qwerty12345",
        "iloveyoumost",
        "monkeymonkey123",
        "dragonballz12",
        "testtesttest",
        "ababababab12",
    ];

    if password.len() < MIN_LEN {
        return Err(WalletError::WeakPassword(
            format!("password must be at least {} characters (got {})", MIN_LEN, password.len())
        ));
    }

    let normalized = password.trim().to_lowercase();
    if DENYLIST.iter().any(|banned| *banned == normalized.as_str()) {
        return Err(WalletError::WeakPassword(
            "password appears on the list of commonly breached passwords; \
             pick something unique. Consider a diceware phrase: 4-5 random \
             words from a word list produce ~60+ bits of entropy and are \
             memorable.".into()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let secret = b"very secret ml-dsa private key bytes";
        let public = b"public key bytes";
        let password = "correct horse battery staple";

        // Use low KDF params for test speed
        let fast_params = KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1 };

        let keyfile = EncryptedKeyfile::encrypt_with_params(
            secret, public, Network::Mainnet, password, fast_params
        ).unwrap();

        let (decrypted_secret, decrypted_public, decrypted_network) =
            keyfile.decrypt(password).unwrap();

        assert_eq!(decrypted_secret, secret);
        assert_eq!(decrypted_public, public);
        assert!(matches!(decrypted_network, Network::Mainnet));
    }

    #[test]
    fn wrong_password_fails() {
        let fast_params = KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1 };
        let keyfile = EncryptedKeyfile::encrypt_with_params(
            b"secret", b"public", Network::Mainnet, "right_pass_123", fast_params
        ).unwrap();

        let result = keyfile.decrypt("wrong_password");
        assert!(matches!(result, Err(WalletError::WrongPassword)));
    }

    #[test]
    fn weak_password_rejected_too_short() {
        // "short" = 5 chars; the Sprint T.3 minimum is 12.
        let result = EncryptedKeyfile::encrypt(
            b"secret", b"public", Network::Mainnet, "short"
        );
        assert!(matches!(result, Err(WalletError::WeakPassword(_))));
    }

    /// Sprint T.3 — Audit M-5: any password in the denylist must be rejected
    /// even if it meets the length requirement.
    #[test]
    fn weak_password_rejected_denylist() {
        // 16 chars — meets length requirement, but on the denylist.
        let result = EncryptedKeyfile::encrypt(
            b"secret", b"public", Network::Mainnet, "passwordpassword"
        );
        match result {
            Err(WalletError::WeakPassword(msg)) => {
                assert!(
                    msg.to_lowercase().contains("breach") ||
                    msg.to_lowercase().contains("common"),
                    "error message should explain the denylist reason, got: {}",
                    msg
                );
            }
            Err(other) => panic!("expected WeakPassword error, got different error: {}", other),
            Ok(_)      => panic!("expected WeakPassword error, got Ok(_)"),
        }
    }

    /// Sprint T.3: length-boundary check — exactly 11 chars must be rejected,
    /// exactly 12 chars must be accepted (given it's not on the denylist).
    #[test]
    fn weak_password_length_boundary() {
        let fast_params = KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1 };

        // 11 chars → rejected
        let r11 = EncryptedKeyfile::encrypt_with_params(
            b"secret", b"public", Network::Mainnet, "elevenchars", fast_params
        );
        assert!(matches!(r11, Err(WalletError::WeakPassword(_))),
            "11-char password must be rejected");

        // 12 chars (not on denylist) → accepted
        let r12 = EncryptedKeyfile::encrypt_with_params(
            b"secret", b"public", Network::Mainnet, "twelvechars!", fast_params
        );
        assert!(r12.is_ok(), "12-char password must be accepted");
    }

    /// Audit REGRESSION: a keyfile with a truncated/corrupt nonce must return
    /// a parse error, not panic. `Nonce::from_slice` panics on any length
    /// other than 12 bytes, so before the length guard this test crashed the
    /// process on decrypt.
    #[test]
    fn corrupt_nonce_returns_error_not_panic() {
        let fast_params = KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1 };
        let mut keyfile = EncryptedKeyfile::encrypt_with_params(
            b"secret", b"public", Network::Mainnet, "password-abcd-12", fast_params
        ).unwrap();

        // Truncated 4-byte nonce (valid base64, wrong decoded length).
        keyfile.cipher.nonce_b64 = B64.encode([0u8; 4]);
        let result = keyfile.decrypt("password-abcd-12");
        assert!(matches!(result, Err(WalletError::Parse(_))),
            "short nonce must be a Parse error");

        // Oversized 32-byte nonce is equally invalid.
        keyfile.cipher.nonce_b64 = B64.encode([0u8; 32]);
        let result = keyfile.decrypt("password-abcd-12");
        assert!(matches!(result, Err(WalletError::Parse(_))),
            "long nonce must be a Parse error");
    }

    /// Audit: truncated salt and tag-less ciphertext must also be clean
    /// parse errors on decrypt of a corrupt keyfile.
    #[test]
    fn corrupt_salt_or_short_ciphertext_returns_error() {
        let fast_params = KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1 };
        let keyfile = EncryptedKeyfile::encrypt_with_params(
            b"secret", b"public", Network::Mainnet, "password-abcd-12", fast_params
        ).unwrap();

        // Truncated 4-byte salt.
        let mut kf_salt = EncryptedKeyfile {
            version: keyfile.version,
            network: keyfile.network,
            kdf: KdfDesc { salt_b64: B64.encode([0u8; 4]), algo: keyfile.kdf.algo.clone(),
                m_cost: keyfile.kdf.m_cost, t_cost: keyfile.kdf.t_cost, p_cost: keyfile.kdf.p_cost },
            cipher: CipherDesc { algo: keyfile.cipher.algo.clone(),
                nonce_b64: keyfile.cipher.nonce_b64.clone(),
                ciphertext_b64: keyfile.cipher.ciphertext_b64.clone() },
            meta: Meta { public_key_b64: keyfile.meta.public_key_b64.clone(),
                address: keyfile.meta.address.clone() },
        };
        assert!(matches!(kf_salt.decrypt("password-abcd-12"), Err(WalletError::Parse(_))),
            "short salt must be a Parse error");

        // Ciphertext shorter than the 16-byte GCM tag.
        kf_salt.kdf.salt_b64 = keyfile.kdf.salt_b64.clone();
        kf_salt.cipher.ciphertext_b64 = B64.encode([0u8; 8]);
        assert!(matches!(kf_salt.decrypt("password-abcd-12"), Err(WalletError::Parse(_))),
            "tag-less ciphertext must be a Parse error");
    }

    #[test]
    fn different_encrypts_produce_different_ciphertext() {
        let fast_params = KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1 };
        let k1 = EncryptedKeyfile::encrypt_with_params(
            b"secret", b"public", Network::Mainnet, "password-abcd-12", fast_params
        ).unwrap();
        let k2 = EncryptedKeyfile::encrypt_with_params(
            b"secret", b"public", Network::Mainnet, "password-abcd-12", fast_params
        ).unwrap();

        // Same secret, same password, but different salt → different output
        assert_ne!(k1.cipher.ciphertext_b64, k2.cipher.ciphertext_b64);
        assert_ne!(k1.kdf.salt_b64, k2.kdf.salt_b64);
    }

    // ── v2 (master seed at rest) ─────────────────────────────────────────────

    fn v2_fixture() -> (EncryptedKeyfile, Vec<u8>, Vec<u8>, Vec<u8>) {
        let fast_params = KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1 };
        let seed = vec![0x42u8; 64];       // 64-byte BIP39-style seed
        let secret = b"base secret key bytes".to_vec();
        let public = b"base public key bytes".to_vec();
        let kf = EncryptedKeyfile::encrypt_seed_v2_with_params(
            &seed, &secret, &public, Network::Testnet, "password-abcd-12", fast_params
        ).unwrap();
        (kf, seed, secret, public)
    }

    #[test]
    fn v2_roundtrip_recovers_seed_secret_public_network() {
        let (kf, seed, secret, public) = v2_fixture();
        assert_eq!(kf.version, KEYFILE_VERSION_V2);

        let (d_seed, d_secret, d_public, d_net) = kf.decrypt_v2("password-abcd-12").unwrap();
        assert_eq!(d_seed.as_slice(), seed.as_slice());
        assert_eq!(d_secret.as_slice(), secret.as_slice());
        assert_eq!(d_public, public);
        assert!(matches!(d_net, Network::Testnet));
    }

    #[test]
    fn v2_wrong_password_fails() {
        let (kf, ..) = v2_fixture();
        assert!(matches!(kf.decrypt_v2("wrong-password-x"), Err(WalletError::WrongPassword)));
    }

    #[test]
    fn v2_rejects_out_of_bounds_seed_lengths() {
        let fast_params = KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1 };
        for bad_len in [0usize, 16, 31, 129] {
            let r = EncryptedKeyfile::encrypt_seed_v2_with_params(
                &vec![1u8; bad_len], b"sk", b"pk", Network::Mainnet,
                "password-abcd-12", fast_params);
            assert!(matches!(r, Err(WalletError::Crypto(_))),
                "seed length {} must be rejected", bad_len);
        }
    }

    /// Cross-version replay must fail CLOSED in both directions: the version
    /// field routes to a different AAD domain, so the GCM tag cannot verify.
    #[test]
    fn v2_version_field_tamper_fails_both_directions() {
        // v2 file re-labelled as v1 → v1 decrypt path → v1 AAD → tag failure.
        let (mut kf, ..) = v2_fixture();
        kf.version = KEYFILE_VERSION;
        assert!(matches!(kf.decrypt("password-abcd-12"), Err(WalletError::WrongPassword)),
            "v2 ciphertext must not decrypt under v1 semantics");

        // v1 file re-labelled as v2 → v2 decrypt path → v2 AAD → tag failure.
        let fast_params = KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1 };
        let mut kf1 = EncryptedKeyfile::encrypt_with_params(
            b"secret", b"public", Network::Mainnet, "password-abcd-12", fast_params
        ).unwrap();
        kf1.version = KEYFILE_VERSION_V2;
        assert!(matches!(kf1.decrypt_v2("password-abcd-12"), Err(WalletError::WrongPassword)),
            "v1 ciphertext must not decrypt under v2 semantics");
    }

    /// Version guards: each decrypt path refuses the other version OUTRIGHT
    /// (before any KDF work) when the label is honest.
    #[test]
    fn v2_and_v1_version_guards() {
        let (kf2, ..) = v2_fixture();
        assert!(matches!(kf2.decrypt("password-abcd-12"),
            Err(WalletError::UnsupportedVersion(2))));

        let fast_params = KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1 };
        let kf1 = EncryptedKeyfile::encrypt_with_params(
            b"secret", b"public", Network::Mainnet, "password-abcd-12", fast_params
        ).unwrap();
        assert!(matches!(kf1.decrypt_v2("password-abcd-12"),
            Err(WalletError::UnsupportedVersion(1))));
    }

    /// Audit M2 carried into v2: a swapped public key breaks the AAD binding.
    #[test]
    fn v2_tampered_public_key_fails_tag() {
        let (mut kf, ..) = v2_fixture();
        kf.meta.public_key_b64 = B64.encode(b"attacker public key");
        assert!(matches!(kf.decrypt_v2("password-abcd-12"), Err(WalletError::WrongPassword)));
    }

    /// The decrypted v2 seed must drive diversified derivation end-to-end:
    /// encrypted-at-rest store → unlock → same addresses as the live seed.
    #[test]
    fn v2_seed_supports_diversified_derivation_after_unlock() {
        let fast_params = KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1 };
        let seed = vec![7u8; 64];
        let kf = EncryptedKeyfile::encrypt_seed_v2_with_params(
            &seed, b"sk-bytes", b"pk-bytes", Network::Testnet,
            "password-abcd-12", fast_params
        ).unwrap();
        let (d_seed, ..) = kf.decrypt_v2("password-abcd-12").unwrap();
        let live = crate::crypto::diversified_address(&seed, 3, true).unwrap();
        let stored = crate::crypto::diversified_address(&d_seed, 3, true).unwrap();
        assert_eq!(live, stored,
            "address derived from the at-rest seed must match the live seed");
    }

    #[test]
    fn unsupported_version_fails() {
        let fast_params = KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1 };
        let mut keyfile = EncryptedKeyfile::encrypt_with_params(
            b"secret", b"public", Network::Mainnet, "password-abcd-12", fast_params
        ).unwrap();

        keyfile.version = 999;  // simulate future version we don't know
        let result = keyfile.decrypt("password-abcd-12");
        assert!(matches!(result, Err(WalletError::UnsupportedVersion(999))));
    }
}
