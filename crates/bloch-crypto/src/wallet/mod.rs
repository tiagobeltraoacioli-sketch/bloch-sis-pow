//! Bloch-SIS Protocol Wallet Library (v0.5.4 — Sprint C)
//!
//! This module unifies the wallet functionality that was previously scattered
//! across `main.rs` (CLI commands), `hd_wallet/`, and ad-hoc scripts.
//!
//! Primary consumer: the Tauri desktop wallet in `bloch-layer-wallet-desktop/`.
//! Secondary consumer: the `bloch` CLI binary.
//!
//! Architecture:
//!
//!   Wallet — holds keypair + network + optional encrypted keyfile state
//!     │
//!     ├─ generate()            — new wallet with random seed
//!     ├─ from_seed()           — deterministic from BIP39 seed phrase
//!     ├─ load_encrypted()      — unlock keyfile with password
//!     ├─ save_encrypted()      — write AES-GCM encrypted keyfile
//!     ├─ address()             — derive and cache address
//!     ├─ public_key()          — raw pk bytes
//!     ├─ sign_tx(tx)           — detached, pure function
//!     └─ build_tx(...)         — pure tx construction (no network)
//!
//!   WalletClient (separate struct) — talks to a Bloch-SIS Protocol node
//!     │
//!     ├─ balance(addr)         — via getbalance RPC
//!     ├─ history(addr)         — via getaddresshistory / listtransactions
//!     ├─ utxos(addr)           — via getutxos RPC
//!     ├─ broadcast(tx)         — via sendrawtransaction RPC
//!     └─ estimate_fee()        — via estimatefeeadvanced RPC (Sprint B)
//!
//! Rationale for separation: Wallet holds keys (secret), WalletClient holds
//! network connection (not secret). They compose for convenience but can be
//! used independently — e.g. cold-signing, airgapped tx construction.

use crate::address::{Address, Network};
use crate::core::{Transaction, TxInput, TxOutput, TESTNET_PREFIX};
use crate::crypto;
use sha3::{Sha3_256, Digest};
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};

pub mod seed;
pub mod encryption;
#[cfg(feature = "node")]
pub mod client;
pub mod errors;

pub use seed::SeedPhrase;
pub use errors::WalletError;

/// Local UTXO representation for wallet operations.
#[derive(Debug, Clone)]
pub struct Utxo {
    pub txid:   [u8; 32],
    pub index:  u32,
    pub output: TxOutput,
}


// ─────────────────────────────────────────────────────────────────────────────
// Wallet — primary user-facing struct
// ─────────────────────────────────────────────────────────────────────────────

/// A single-key wallet (no HD derivation in this version).
///
/// v0.6+ roadmap: BIP-32 style HD derivation for multi-address wallets.
pub struct Wallet {
    /// Raw keypair material. Zeroed on drop.
    keypair: KeyMaterial,
    /// Cached address (derived from pubkey).
    address: Address,
    /// Mainnet or testnet — affects address encoding, NOT signing.
    network: Network,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct KeyMaterial {
    /// ML-DSA-65 private key.
    secret: Vec<u8>,
    /// ML-DSA-65 public key.
    public: Vec<u8>,
}

impl Wallet {
    /// Generate a new wallet with a fresh random seed phrase.
    ///
    /// Returns `(wallet, seed_phrase)`. The caller MUST display the seed
    /// phrase to the user for backup and MUST NOT persist it unencrypted.
    pub fn generate(network: Network) -> Result<(Self, SeedPhrase), WalletError> {
        let seed = SeedPhrase::generate()?;
        let wallet = Self::from_seed(&seed, network)?;
        Ok((wallet, seed))
    }

    /// Deterministically derive a wallet from a seed phrase.
    ///
    /// This is pure — same seed always produces same wallet.
    pub fn from_seed(seed: &SeedPhrase, network: Network) -> Result<Self, WalletError> {
        let seed_bytes = seed.to_seed_bytes();
        // ML-DSA-65 keygen from 32-byte seed
        let (public, secret) = crypto::generate_keypair_from_seed(&seed_bytes[..32])
            .map_err(|e| WalletError::Crypto(e.to_string()))?;

        let hash_full = Sha3_256::digest(&public);
        let mut addr_hash = [0u8; 20];
        addr_hash.copy_from_slice(&hash_full[..20]);
        let addr = Address::from_hash(addr_hash, network);

        Ok(Wallet {
            keypair: KeyMaterial { secret, public },
            address: addr,
            network,
        })
    }

    /// Load an encrypted keyfile from disk and unlock with password.
    pub fn load_encrypted(path: &std::path::Path, password: &str) -> Result<Self, WalletError> {
        let bytes = std::fs::read(path).map_err(|e| WalletError::Io(e.to_string()))?;
        let ef: encryption::EncryptedKeyfile = serde_json::from_slice(&bytes)
            .map_err(|e| WalletError::Parse(e.to_string()))?;

        let (secret, public, network) = ef.decrypt(password)?;
        let hash_full = Sha3_256::digest(&public);
        let mut addr_hash = [0u8; 20];
        addr_hash.copy_from_slice(&hash_full[..20]);
        let addr = Address::from_hash(addr_hash, network);

        Ok(Wallet {
            keypair: KeyMaterial { secret, public },
            address: addr,
            network,
        })
    }

    /// Save wallet to an encrypted keyfile.
    ///
    /// Uses AES-GCM with Argon2id KDF (configurable params in `encryption::KdfParams`).
    /// Sprint T.5 — Audit L-4: writes are atomic (temp + fsync + rename) so a
    /// crash during save cannot corrupt the existing keystore.
    pub fn save_encrypted(&self, path: &std::path::Path, password: &str) -> Result<(), WalletError> {
        let ef = encryption::EncryptedKeyfile::encrypt(
            &self.keypair.secret,
            &self.keypair.public,
            self.network,
            password,
        )?;
        let bytes = serde_json::to_vec_pretty(&ef)
            .map_err(|e| WalletError::Parse(e.to_string()))?;
        crate::util::atomic_write(path, &bytes)
            .map_err(|e| WalletError::Io(e.to_string()))?;
        Ok(())
    }

    /// Returns the wallet's address (cached, cheap to call).
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the wallet's network (mainnet or testnet).
    pub fn network(&self) -> Network {
        self.network
    }

    /// Returns the raw public key bytes (for inspection or signing verification).
    pub fn public_key(&self) -> &[u8] {
        &self.keypair.public
    }

    /// Sign a transaction in-place.
    ///
    /// Each input gets a signature derived from the tx sighash. The wallet
    /// MUST own the UTXOs referenced by the inputs (i.e., their script_pubkey
    /// equals this wallet's address hash) — otherwise signing produces an
    /// invalid tx that the network will reject.
    pub fn sign_tx(&self, mut tx: Transaction) -> Result<Transaction, WalletError> {
        // Each input gets its own sighash. script_sig = signature || pubkey.
        let pubkey = &self.keypair.public;
        let mut signatures = Vec::with_capacity(tx.inputs.len());

        for i in 0..tx.inputs.len() {
            let sighash = tx.sighash(i);
            let sig = crypto::sign(&self.keypair.secret, &sighash)
                .map_err(|e| WalletError::Crypto(e.to_string()))?;
            // FIX: consensus verification parses script_sig with
            // `parse_script_sig` (length-prefixed [4B sig_len][sig][4B pk_len]
            // [pk]). This previously wrote a RAW `sig||pubkey`, which
            // parse_script_sig mis-parses → the signature fails to verify and the
            // tx is rejected. Use the canonical builder (matches build_tx +
            // the RPC/consensus verifiers).
            signatures.push(Transaction::build_script_sig(&sig, pubkey));
        }

        for (input, script_sig) in tx.inputs.iter_mut().zip(signatures) {
            input.script_sig = script_sig;
        }

        Ok(tx)
    }

    /// Build an unsigned transaction spending the given UTXOs to `recipient`.
    ///
    /// This is pure — no network call required. Caller must provide UTXOs
    /// (typically from `WalletClient::utxos()`).
    ///
    /// Logic:
    ///   - Sum UTXO values, verify >= `amount + fee`
    ///   - Create output to `recipient` with `amount`
    ///   - Create change output to self with `(total - amount - fee)` if > dust
    ///   - Return unsigned tx ready for `sign_tx()`
    pub fn build_tx(
        &self,
        utxos: Vec<Utxo>,
        recipient: &Address,
        amount: u64,
        fee: u64,
    ) -> Result<Transaction, WalletError> {
        if utxos.is_empty() {
            return Err(WalletError::InsufficientFunds { needed: amount + fee, have: 0 });
        }

        let total_in: u64 = utxos.iter().map(|u| u.output.value).sum();
        let needed = amount.checked_add(fee).ok_or(WalletError::Overflow)?;

        if total_in < needed {
            return Err(WalletError::InsufficientFunds { needed, have: total_in });
        }

        let change = total_in - needed;

        let inputs: Vec<TxInput> = utxos.iter().map(|u| TxInput {
            prev_txid: u.txid,
            prev_index: u.index,
            script_sig: Vec::new(), // filled by sign_tx
            sequence: 0xffffffff,
        }).collect();

        let mut outputs = vec![
            TxOutput {
                value: amount,
                script_pubkey: recipient.hash().to_vec(),
            },
        ];

        // Add change output if above dust threshold
        const DUST_THRESHOLD_SATS: u64 = 546;
        if change >= DUST_THRESHOLD_SATS {
            outputs.push(TxOutput {
                value: change,
                script_pubkey: self.address.hash().to_vec(),
            });
        }
        // If change < dust, it becomes additional fee (implicit)

        Ok(Transaction {
            version: 1,
            inputs,
            outputs,
            locktime: 0,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_tx_script_sig_is_length_prefixed_and_verifies() {
        // Regression: Wallet::sign_tx must emit the canonical length-prefixed
        // script_sig that consensus parses with parse_script_sig — a raw
        // sig||pubkey (the old bug) fails verification and the tx is rejected.
        let (wallet, _seed) = Wallet::generate(Network::Testnet).unwrap();
        let tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [1u8; 32], prev_index: 0, script_sig: vec![], sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOutput { value: 100, script_pubkey: vec![2u8; 20] }],
            locktime: 0,
        };
        let signed = wallet.sign_tx(tx).unwrap();
        let (sig, pk) = Transaction::parse_script_sig(&signed.inputs[0].script_sig)
            .expect("script_sig must be parseable (length-prefixed)");
        assert!(
            crypto::verify(&pk, &signed.sighash(0), &sig),
            "the signature the consensus verifier extracts must verify"
        );
    }

    #[test]
    fn generate_produces_valid_address() {
        let (wallet, _seed) = Wallet::generate(Network::Mainnet).unwrap();
        assert!(wallet.address().to_string().starts_with("bloch1q"));
        assert_eq!(wallet.network(), Network::Mainnet);
        assert!(!wallet.public_key().is_empty());
    }

    #[test]
    fn from_seed_is_deterministic() {
        let (_, seed) = Wallet::generate(Network::Mainnet).unwrap();
        let w1 = Wallet::from_seed(&seed, Network::Mainnet).unwrap();
        let w2 = Wallet::from_seed(&seed, Network::Mainnet).unwrap();
        assert_eq!(w1.address().to_string(), w2.address().to_string());
        assert_eq!(w1.public_key(), w2.public_key());
    }

    #[test]
    fn same_seed_different_network_different_prefix() {
        let (_, seed) = Wallet::generate(Network::Mainnet).unwrap();
        let main = Wallet::from_seed(&seed, Network::Mainnet).unwrap();
        let test = Wallet::from_seed(&seed, Network::Testnet).unwrap();
        assert!(main.address().to_string().starts_with("bloch1q"));
        assert!(test.address().to_string().starts_with("bloch1t"));
        // Same underlying hash, different encoding
        assert_eq!(main.public_key(), test.public_key());
    }

    #[test]
    fn build_tx_rejects_insufficient_funds() {
        let (wallet, _) = Wallet::generate(Network::Mainnet).unwrap();
        let (other_wallet, _) = Wallet::generate(Network::Mainnet).unwrap();

        let utxos = vec![Utxo {
            txid: [0u8; 32],
            index: 0,
            output: TxOutput { value: 1000, script_pubkey: wallet.address().hash().to_vec() },
        }];

        // Try to send 2000 with 1000 UTXO
        let result = wallet.build_tx(utxos, other_wallet.address(), 2000, 100);
        assert!(matches!(result, Err(WalletError::InsufficientFunds { .. })));
    }

    #[test]
    fn build_tx_creates_change_output() {
        let (wallet, _) = Wallet::generate(Network::Mainnet).unwrap();
        let (other_wallet, _) = Wallet::generate(Network::Mainnet).unwrap();

        let utxos = vec![Utxo {
            txid: [0u8; 32],
            index: 0,
            output: TxOutput { value: 100_000, script_pubkey: wallet.address().hash().to_vec() },
        }];

        let tx = wallet.build_tx(utxos, other_wallet.address(), 50_000, 1000).unwrap();

        // 2 outputs: recipient + change
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.outputs[0].value, 50_000);
        assert_eq!(tx.outputs[1].value, 49_000); // 100k - 50k - 1k fee
    }

    #[test]
    fn build_tx_no_change_when_exact() {
        let (wallet, _) = Wallet::generate(Network::Mainnet).unwrap();
        let (other, _) = Wallet::generate(Network::Mainnet).unwrap();

        let utxos = vec![Utxo {
            txid: [0u8; 32],
            index: 0,
            output: TxOutput { value: 51_000, script_pubkey: wallet.address().hash().to_vec() },
        }];

        // Send exactly (utxo - fee) — no change
        let tx = wallet.build_tx(utxos, other.address(), 50_000, 1_000).unwrap();
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, 50_000);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Legacy Compatibility Layer (Sprint C transitional)
// ───────────────────────────────────────────────────────────────────────────
// The following code is preserved from the pre-Sprint-C wallet/mod.rs to
// keep existing consumers compiling: hd_wallet, bloch-cli, bloch-wallet.
//
// Planned removal: Sprint C.1 migrates these consumers to the new `Wallet`
// API defined above. Until then, both APIs coexist.
//
// Do NOT write new code against the types below — use `Wallet` instead.
// ═══════════════════════════════════════════════════════════════════════════


use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use argon2::{Argon2, Algorithm, Version, Params};
use base64::{Engine as _, engine::general_purpose as b64};
use rand::RngCore;
use std::path::Path;

// ── Encrypted keystore ────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedKeystore {
    pub version:     u32,
    pub address:     String,
    pub network:     String,
    pub crypto:      KeystoreCrypto,
    pub created_at:  String,
    pub description: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeystoreCrypto {
    pub cipher: String, pub ciphertext: String, pub nonce: String,
    pub kdf: String,    pub kdf_params: KdfParams,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_cost: u32, pub time_cost: u32, pub parallelism: u32,
    pub salt: String,     pub output_len: u32,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct KeystorePayload { private_key_hex: String, public_key_hex: String }

// ── Keypair ───────────────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct Keypair {
    pub private_key: Vec<u8>,
    pub public_key:  Vec<u8>,
    pub address:     String,
}

impl Drop for Keypair {
    fn drop(&mut self) { self.private_key.zeroize(); }
}

impl Keypair {
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        crypto::sign(&self.private_key, msg).map_err(|e| e.to_string())
    }

    pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        crypto::verify(pk, msg, sig)
    }

    pub fn address_bytes(&self) -> Vec<u8> {
        use sha3::{Sha3_256, Digest};
        Sha3_256::digest(&self.public_key)[..20].to_vec()
    }

    // ── Keystore ──────────────────────────────────────────────────────────────

    pub fn save_encrypted(&self, path: &Path, password: &str) -> Result<(), String> {
        let mut salt = vec![0u8; 32];
        rand::rng().fill_bytes(&mut salt);
        let mut enc_key = derive_key(password, &salt)?;
        let mut nonce_b = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_b);

        let payload = KeystorePayload {
            private_key_hex: hex::encode(&self.private_key),
            public_key_hex:  hex::encode(&self.public_key),
        };
        let mut plain = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
        let cipher  = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&enc_key));
        let ct      = cipher.encrypt(Nonce::from_slice(&nonce_b), plain.as_ref())
            .map_err(|e| e.to_string())?;
        plain.zeroize(); enc_key.zeroize();

        let ks = EncryptedKeystore {
            version: 2,
            address: self.address.clone(),
            network: if self.address.starts_with(TESTNET_PREFIX) { "testnet" } else { "mainnet" }.into(),
            crypto: KeystoreCrypto {
                cipher:     "aes-256-gcm".into(),
                ciphertext: b64::STANDARD.encode(&ct),
                nonce:      b64::STANDARD.encode(nonce_b),
                kdf:        "argon2id".into(),
                kdf_params: KdfParams { memory_cost: 262144, time_cost: 4, parallelism: 4,
                    salt: b64::STANDARD.encode(&salt), output_len: 32 },
            },
            created_at:  chrono::Utc::now().to_rfc3339(),
            description: "Bloch-SIS Protocol ML-DSA-65 Keystore v2".into(),
        };
        let json = serde_json::to_string_pretty(&ks).map_err(|e| e.to_string())?;
        // Sprint T.5 — Audit L-4: atomic write (temp + fsync + rename).
        crate::util::atomic_write(path, json.as_bytes()).map_err(|e| e.to_string())
    }

    pub fn load_encrypted(path: &Path, password: &str) -> Result<Self, String> {
        let json = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let ks: EncryptedKeystore = serde_json::from_str(&json).map_err(|e| e.to_string())?;
        if ks.version != 2 { return Err("unsupported keystore version".into()); }

        let salt      = b64::STANDARD.decode(&ks.crypto.kdf_params.salt).map_err(|e| e.to_string())?;
        let mut enc_k = derive_key(password, &salt)?;
        let nonce_b   = b64::STANDARD.decode(&ks.crypto.nonce).map_err(|e| e.to_string())?;
        let ct        = b64::STANDARD.decode(&ks.crypto.ciphertext).map_err(|e| e.to_string())?;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&enc_k));
        let plain  = cipher.decrypt(Nonce::from_slice(&nonce_b), ct.as_ref())
            .map_err(|_| "decryption failed — wrong password or corrupted file".to_string())?;
        enc_k.zeroize();

        let mut payload: KeystorePayload = serde_json::from_slice(&plain).map_err(|e| e.to_string())?;
        let private_key = hex::decode(&payload.private_key_hex).map_err(|e| e.to_string())?;
        let public_key  = hex::decode(&payload.public_key_hex).map_err(|e| e.to_string())?;
        payload.zeroize();

        let testnet = ks.address.starts_with(TESTNET_PREFIX);
        let derived = crypto::address_from_pubkey(&public_key, testnet);
        if derived != ks.address { return Err("address mismatch — keystore may be tampered".into()); }
        Ok(Keypair { private_key, public_key, address: ks.address })
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keypair")
            .field("address", &self.address)
            .field("pubkey_len", &self.public_key.len())
            .field("privkey", &"[REDACTED]")
            .finish()
    }
}

// ── TX builder ────────────────────────────────────────────────────────────────

pub struct TxBuilder;

impl TxBuilder {
    /// Build and sign a transaction.
    /// Selects UTXOs from `available_utxos`, signs each input with `keypair`.
    /// Returns the fully signed Transaction ready to broadcast.
    pub fn build(
        keypair:         &Keypair,
        available_utxos: &[(Vec<u8>, u32, TxOutput)],  // (txid, index, output)
        to_address_hex:  &str,                           // 20-byte hex address
        amount_sats:     u64,
        fee_sats:        u64,
    ) -> Result<Transaction, String> {
        let total_needed = amount_sats.checked_add(fee_sats)
            .ok_or("amount + fee overflow")?;

        // Coin selection: greedy, smallest-first
        let mut selected: Vec<&(Vec<u8>, u32, TxOutput)> = vec![];
        let mut selected_total = 0u64;
        let mut sorted = available_utxos.iter().collect::<Vec<_>>();
        sorted.sort_by_key(|(_, _, o)| o.value);

        for utxo in &sorted {
            selected.push(utxo);
            selected_total += utxo.2.value;
            if selected_total >= total_needed { break; }
        }

        if selected_total < total_needed {
            return Err(format!(
                "insufficient funds: have {} sats, need {} sats",
                selected_total, total_needed
            ));
        }

        // Build inputs (script_sig empty for now — filled after sighash)
        let inputs: Vec<TxInput> = selected.iter().map(|(txid, idx, _)| {
            let mut prev_txid = [0u8; 32];
            prev_txid.copy_from_slice(&txid[..32.min(txid.len())]);
            TxInput { prev_txid, prev_index: *idx, script_sig: vec![], sequence: u32::MAX }
        }).collect();

        // Build outputs
        let to_bytes = hex::decode(to_address_hex)
            .map_err(|_| "invalid destination address hex")?;
        let mut outputs = vec![TxOutput { value: amount_sats, script_pubkey: to_bytes }];

        // Change output
        let change = selected_total - total_needed;
        if change > 546 { // dust threshold
            outputs.push(TxOutput {
                value:         change,
                script_pubkey: keypair.address_bytes(),
            });
        }

        let mut tx = Transaction { version: 1, inputs, outputs, locktime: 0 };

        // Sign each input
        for i in 0..tx.inputs.len() {
            let sighash = tx.sighash(i);
            let sig     = keypair.sign(&sighash)?;
            tx.inputs[i].script_sig = Transaction::build_script_sig(&sig, &keypair.public_key);
        }

        Ok(tx)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn generate_keypair(testnet: bool) -> Keypair {
    let (public_key, private_key) = crypto::generate_keypair();
    let address = crypto::address_from_pubkey(&public_key, testnet);
    Keypair { private_key, public_key, address }
}

pub fn validate_password(pw: &str) -> Result<(), String> {
    if pw.len() < 12 { return Err("at least 12 characters".into()); }
    let c = [
        pw.chars().any(|c| c.is_uppercase()),
        pw.chars().any(|c| c.is_lowercase()),
        pw.chars().any(|c| c.is_ascii_digit()),
        pw.chars().any(|c| !c.is_alphanumeric()),
    ];
    if c.iter().filter(|&&x| x).count() < 3 {
        return Err("need 3 of: uppercase, lowercase, digit, special".into());
    }
    Ok(())
}

fn derive_key(pw: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
    let params = Params::new(262144, 4, 4, Some(32)).map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = vec![0u8; 32];
    argon2.hash_password_into(pw.as_bytes(), salt, &mut key).map_err(|e| e.to_string())?;
    Ok(key)
}

pub mod cli;

