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
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use serde::{Serialize, Deserialize};

pub mod seed;
pub mod encryption;
#[cfg(feature = "node")]
pub mod client;
pub mod errors;
pub mod http_rpc;
pub mod disclosure;

pub use seed::{SeedPhrase, SeedVersion};
pub use errors::WalletError;
pub use disclosure::{DisclosureBundle, DisclosureEntry, VerifiedDisclosure, DisclosureError};

/// Read a satoshi-denominated field out of a node JSON-RPC response.
///
/// V4 rule R3 (docs/specs/BLOCH-RPC-V4.md) puts every satoshi amount on the
/// wire as a decimal STRING — the V4 supply exceeds `i64::MAX` and is far past
/// JavaScript's `Number.MAX_SAFE_INTEGER`, so a JSON number cannot carry it.
/// Live Genesis-3 nodes still send JSON numbers, so wallet code accepts BOTH
/// and one binary talks to either wire. Returns `None` for anything else
/// (float, null, non-numeric string) so callers keep their existing
/// missing-field handling.
pub fn sat_u64(v: &serde_json::Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    v.as_str().and_then(|s| s.trim().parse::<u64>().ok())
}

/// Parse an exact BLOCH decimal amount into satoshis without floating point.
/// Accepts unsigned decimal notation with at most eight fractional digits.
/// Exponents, signs, sub-satoshi precision and u64 overflow are rejected.
pub fn parse_bloch_satoshis(amount: &str) -> Result<u64, &'static str> {
    let amount = amount.trim();
    let (whole, fraction) = amount.split_once('.').unwrap_or((amount, ""));
    if (whole.is_empty() && fraction.is_empty()) || fraction.len() > 8
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("amount must use unsigned decimal notation with at most 8 fractional digits");
    }
    let whole = if whole.is_empty() { 0 } else {
        whole.parse::<u64>().map_err(|_| "amount exceeds u64 satoshis")?
    };
    let mut fractional = if fraction.is_empty() { 0 } else {
        fraction.parse::<u64>().map_err(|_| "invalid fractional amount")?
    };
    for _ in fraction.len()..8 {
        fractional = fractional.checked_mul(10).ok_or("amount exceeds u64 satoshis")?;
    }
    whole.checked_mul(100_000_000).and_then(|value| value.checked_add(fractional))
        .ok_or("amount exceeds u64 satoshis")
}

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

/// Take ownership of a repository-produced wallet secret immediately, without
/// cloning its allocation, until it can be transferred into `KeyMaterial`.
fn wallet_secret_owner(secret: Vec<u8>) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(secret)
}

impl Wallet {
    /// Generate a new wallet with a fresh random seed phrase.
    ///
    /// Returns `(wallet, seed_phrase)`. The caller MUST display the seed
    /// phrase to the user for backup and MUST NOT persist it unencrypted.
    /// Always derives under the CURRENT default seed version
    /// ([`SeedVersion::V2Bip39Sha512`]) — a brand-new mnemonic has no prior
    /// version to preserve.
    pub fn generate(network: Network) -> Result<(Self, SeedPhrase), WalletError> {
        let seed = SeedPhrase::generate()?;
        let wallet = Self::from_seed_versioned(&seed, "", SeedVersion::V2Bip39Sha512, network)?;
        Ok((wallet, seed))
    }

    /// Deterministically derive a wallet from a seed phrase under the CURRENT
    /// default seed version ([`SeedVersion::V2Bip39Sha512`]) and no BIP39
    /// passphrase.
    ///
    /// K-M3: kept for source compatibility with callers written before the
    /// versioned API existed. This can only reopen a wallet created under
    /// V2 (every wallet created after the K-M3 fix). To reopen a wallet that
    /// might predate the fix, use [`Self::from_seed_versioned`] with an
    /// explicit version, or [`Self::recover_ambiguous`] /
    /// [`Self::recover_resolved`] when the version is not known.
    pub fn from_seed(seed: &SeedPhrase, network: Network) -> Result<Self, WalletError> {
        Self::from_seed_versioned(seed, "", SeedVersion::V2Bip39Sha512, network)
    }

    /// Deterministically derive a wallet from a seed phrase under an
    /// EXPLICIT [`SeedVersion`] and BIP39 passphrase (`""` for none).
    ///
    /// This is pure — same (seed, passphrase, version) always produces the
    /// same wallet. It is the only path that can reopen a PRE-K-M3 (V1)
    /// wallet: the caller must know (or resolve, see
    /// [`Self::recover_resolved`]) which version created it.
    pub fn from_seed_versioned(
        seed: &SeedPhrase,
        passphrase: &str,
        version: SeedVersion,
        network: Network,
    ) -> Result<Self, WalletError> {
        // Own the returned master-seed copy under zeroizing drop for the
        // complete (potentially slow) hybrid key-generation call.
        let seed_bytes = Zeroizing::new(
            seed.to_seed_bytes_versioned(version, passphrase)?,
        );
        // ML-DSA-65 keygen from 32-byte seed
        let (public, secret) = crypto::generate_keypair_from_seed(&seed_bytes[..32])
            .map_err(|e| WalletError::Crypto(e.to_string()))?;
        let mut secret = wallet_secret_owner(secret);

        let hash_full = Sha3_256::digest(&public);
        let mut addr_hash = [0u8; 20];
        addr_hash.copy_from_slice(&hash_full[..20]);
        let addr = Address::from_hash(addr_hash, network);

        Ok(Wallet {
            keypair: KeyMaterial {
                secret: std::mem::take(&mut *secret),
                public,
            },
            address: addr,
            network,
        })
    }

    /// K-M3: recover every candidate wallet a mnemonic COULD produce when the
    /// seed version that created it is NOT known (e.g. restoring from a paper
    /// backup with no other record). Derives under every [`SeedVersion`] and
    /// returns all of them, tagged by version, instead of silently picking
    /// one — picking wrong derives the WRONG keys with no error at all.
    pub fn recover_ambiguous(
        seed: &SeedPhrase,
        passphrase: &str,
        network: Network,
    ) -> Result<Vec<(SeedVersion, Self)>, WalletError> {
        let mut out = Vec::with_capacity(2);
        for version in [SeedVersion::V2Bip39Sha512, SeedVersion::V1LegacyPbkdf2Sha256] {
            out.push((version, Self::from_seed_versioned(seed, passphrase, version, network)?));
        }
        Ok(out)
    }

    /// K-M3: resolve the seed-version ambiguity from a hint instead of
    /// guessing. Tries, in order:
    ///   1. `expected_address` — a string the caller already trusts (typed by
    ///      the user, read from an old keyfile's `meta.address`, etc.).
    ///   2. `has_history` — a caller-supplied SEAM for an on-chain-history
    ///      lookup (e.g. `WalletClient::balance`/`history`), so this
    ///      network-free module never dials out itself; pass `|_| false`
    ///      when no such lookup is available.
    ///
    /// Returns [`WalletError::AmbiguousSeedVersion`] if neither resolves it —
    /// never silently returns one of the two candidates.
    pub fn recover_resolved(
        seed: &SeedPhrase,
        passphrase: &str,
        network: Network,
        expected_address: Option<&str>,
        mut has_history: impl FnMut(&Address) -> bool,
    ) -> Result<(SeedVersion, Self), WalletError> {
        let mut candidates = Self::recover_ambiguous(seed, passphrase, network)?;

        // Cheapest check first: a string comparison against a caller-supplied
        // hint, before ever calling into `has_history` (which may dial a
        // node). `position` (not `into_iter().find`) so `candidates` is not
        // consumed — falling through to the history seam below must not
        // re-derive (expensive PQ keygen) every candidate a second time.
        if let Some(addr) = expected_address {
            if let Some(idx) = candidates.iter().position(|(_, w)| w.address().to_string() == addr) {
                return Ok(candidates.remove(idx));
            }
        }

        for (v, w) in candidates {
            if has_history(w.address()) {
                return Ok((v, w));
            }
        }
        Err(WalletError::AmbiguousSeedVersion)
    }

    /// Load an encrypted keyfile from disk and unlock with password.
    pub fn load_encrypted(path: &std::path::Path, password: &str) -> Result<Self, WalletError> {
        Self::load_encrypted_with_file_limit(path, password, crate::util::DEFAULT_WALLET_FILE_LIMIT)
    }

    /// Explicit bounded recovery override; byte budget does not bound KDF or parsed memory.
    pub fn load_encrypted_with_file_limit(path: &std::path::Path, password: &str, max_bytes: usize) -> Result<Self, WalletError> {
        let bytes = crate::util::read_wallet_file(path, max_bytes).map_err(|e| WalletError::Io(e.to_string()))?;
        let ef: encryption::EncryptedKeyfile = serde_json::from_slice(&bytes)
            .map_err(|e| WalletError::Parse(e.to_string()))?;

        let (mut secret, public, network) = ef.decrypt_zeroizing(password)?;
        let hash_full = Sha3_256::digest(&public);
        let mut addr_hash = [0u8; 20];
        addr_hash.copy_from_slice(&hash_full[..20]);
        let addr = Address::from_hash(addr_hash, network);

        Ok(Wallet {
            keypair: KeyMaterial {
                secret: std::mem::take(&mut *secret),
                public,
            },
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

        // Chain-id (Roadmap #8) derived from the wallet's own network — the
        // signer and the node validator must fold the SAME domain into the sighash.
        let chain_id = crate::core::ChainId::for_network(self.network);
        for i in 0..tx.inputs.len() {
            let sighash = tx.sighash(i, chain_id);
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
        if recipient.network() != self.network {
            return Err(WalletError::NetworkMismatch);
        }
        let needed = amount.checked_add(fee).ok_or(WalletError::Overflow)?;
        if utxos.is_empty() {
            return Err(WalletError::InsufficientFunds { needed, have: 0 });
        }
        let mut outpoints = std::collections::BTreeSet::new();
        for utxo in &utxos {
            if !outpoints.insert((utxo.txid, utxo.index)) {
                return Err(WalletError::Parse("duplicate UTXO outpoint".into()));
            }
        }
        let total_in = utxos.iter().try_fold(0u64, |total, utxo| {
            total.checked_add(utxo.output.value).ok_or(WalletError::Overflow)
        })?;

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
    fn wallet_secret_owner_preserves_allocation_and_wipes_while_live() {
        let _: fn(Vec<u8>) -> Zeroizing<Vec<u8>> = wallet_secret_owner;
        assert!(std::mem::needs_drop::<Zeroizing<Vec<u8>>>());

        let secret = Vec::from([0x19, 0x27, 0x43, 0x61, 0x7f]);
        let pointer = secret.as_ptr();
        let capacity = secret.capacity();
        let expected = secret.clone();
        let mut owner = wallet_secret_owner(secret);

        assert_eq!(owner.as_ptr(), pointer);
        assert_eq!(owner.capacity(), capacity);
        assert_eq!(owner.as_slice(), expected.as_slice());
        owner.zeroize();
        assert!(owner.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn current_wallet_custom_file_budget_preserves_authenticated_roundtrip() {
        let (wallet, _) = Wallet::generate(Network::Testnet).unwrap();
        let password = "synthetic-backup-password-19!";
        let encrypted = encryption::EncryptedKeyfile::encrypt_with_params(
            &wallet.keypair.secret, &wallet.keypair.public, wallet.network, password,
            encryption::KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1 }).unwrap();
        let bytes = serde_json::to_vec(&encrypted).unwrap();
        let path = std::env::temp_dir().join(format!("bloch-current-wallet-budget-{}.json", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();
        let loaded = Wallet::load_encrypted_with_file_limit(&path, password, bytes.len()).unwrap();
        assert_eq!(loaded.address, wallet.address);
        assert_eq!(loaded.keypair.secret, wallet.keypair.secret);
        assert_eq!(loaded.network, Network::Testnet);
        assert!(matches!(Wallet::load_encrypted_with_file_limit(&path, "wrong", bytes.len() - 1),
            Err(WalletError::Io(message)) if message.contains("byte limit")));
        assert!(matches!(Wallet::load_encrypted_with_file_limit(&path, "wrong", bytes.len()),
            Err(WalletError::WrongPassword)));
        std::fs::remove_file(path).unwrap();
    }

    /// V4 rule R3: satoshi amounts arrive as decimal strings; live G3 nodes
    /// still send numbers. Wallet parsing must accept BOTH, exactly — including
    /// values past 2^53, which is the whole reason the wire changed.
    #[test]
    fn sat_u64_reads_both_wires_exactly() {
        assert_eq!(sat_u64(&serde_json::json!(8_400_000_000u64)), Some(8_400_000_000));
        assert_eq!(sat_u64(&serde_json::json!("8400000000")), Some(8_400_000_000));
        assert_eq!(sat_u64(&serde_json::json!(u64::MAX.to_string())), Some(u64::MAX));
        assert_eq!(sat_u64(&serde_json::json!(" 42 ")), Some(42));

        // Anything that is not an exact non-negative integer is None, so
        // callers keep their missing-field handling instead of silently
        // reading a corrupted amount.
        assert_eq!(sat_u64(&serde_json::json!(1.5f64)), None);
        assert_eq!(sat_u64(&serde_json::json!("-1")), None);
        assert_eq!(sat_u64(&serde_json::json!("not-a-number")), None);
        assert_eq!(sat_u64(&serde_json::Value::Null), None);
    }

    // ── K-M3: versioned seed derivation ──────────────────────────────────────

    /// `from_seed_versioned` under the two versions must produce DIFFERENT
    /// wallets for the identical mnemonic — this is the exact bug K-M3
    /// reported (the PRF changed with no way to ask for the old one back).
    #[test]
    fn from_seed_versioned_v1_and_v2_diverge() {
        let (_, seed) = Wallet::generate(Network::Mainnet).unwrap();
        let v1 = Wallet::from_seed_versioned(
            &seed, "", SeedVersion::V1LegacyPbkdf2Sha256, Network::Mainnet).unwrap();
        let v2 = Wallet::from_seed_versioned(
            &seed, "", SeedVersion::V2Bip39Sha512, Network::Mainnet).unwrap();
        assert_ne!(v1.address().to_string(), v2.address().to_string());
        // from_seed()/generate() must be the V2 default, never silently V1.
        let default = Wallet::from_seed(&seed, Network::Mainnet).unwrap();
        assert_eq!(default.address().to_string(), v2.address().to_string());
    }

    #[test]
    fn wallet_master_seed_consumer_uses_exact_zeroizing_array() {
        let seed = SeedPhrase::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ).unwrap();
        let mut seed_bytes = Zeroizing::new(
            seed.to_seed_bytes_versioned(SeedVersion::V2Bip39Sha512, "TREZOR")
                .unwrap(),
        );
        assert!(std::mem::needs_drop::<Zeroizing<[u8; 64]>>());
        let (expected_public, expected_secret) =
            crypto::generate_keypair_from_seed(&seed_bytes[..32]).unwrap();
        let expected_secret = Zeroizing::new(expected_secret);
        let wallet = Wallet::from_seed_versioned(
            &seed,
            "TREZOR",
            SeedVersion::V2Bip39Sha512,
            Network::Mainnet,
        ).unwrap();
        assert_eq!(wallet.keypair.public, expected_public);
        assert_eq!(wallet.keypair.secret.as_slice(), expected_secret.as_slice());

        // Structural evidence only: this proves the production owner type and
        // its array implement Zeroize, not the contents of storage after Drop.
        seed_bytes.zeroize();
        assert!(seed_bytes.iter().all(|byte| *byte == 0));
    }

    /// K-M3: `recover_ambiguous` must return BOTH candidates, never guess.
    #[test]
    fn recover_ambiguous_returns_both_versions() {
        let (_, seed) = Wallet::generate(Network::Mainnet).unwrap();
        let candidates = Wallet::recover_ambiguous(&seed, "", Network::Mainnet).unwrap();
        assert_eq!(candidates.len(), 2);
        let versions: Vec<SeedVersion> = candidates.iter().map(|(v, _)| *v).collect();
        assert!(versions.contains(&SeedVersion::V1LegacyPbkdf2Sha256));
        assert!(versions.contains(&SeedVersion::V2Bip39Sha512));
        assert_ne!(candidates[0].1.address().to_string(), candidates[1].1.address().to_string());
    }

    /// K-M3: `recover_resolved` must pick the candidate matching a supplied
    /// address — this is the "never silently choosing" contract: given a
    /// hint, resolve it; given none, fail rather than guess.
    #[test]
    fn recover_resolved_matches_expected_address() {
        let (_, seed) = Wallet::generate(Network::Mainnet).unwrap();
        let v1 = Wallet::from_seed_versioned(
            &seed, "", SeedVersion::V1LegacyPbkdf2Sha256, Network::Mainnet).unwrap();
        let v1_addr = v1.address().to_string();

        let (resolved_version, resolved_wallet) = Wallet::recover_resolved(
            &seed, "", Network::Mainnet, Some(&v1_addr), |_| false,
        ).unwrap();
        assert_eq!(resolved_version, SeedVersion::V1LegacyPbkdf2Sha256);
        assert_eq!(resolved_wallet.address().to_string(), v1_addr);
    }

    /// K-M3: the on-chain-history seam resolves the ambiguity when no
    /// address hint is given.
    #[test]
    fn recover_resolved_uses_history_seam() {
        let (_, seed) = Wallet::generate(Network::Mainnet).unwrap();
        let v1 = Wallet::from_seed_versioned(
            &seed, "", SeedVersion::V1LegacyPbkdf2Sha256, Network::Mainnet).unwrap();
        let v1_hash = *v1.address().hash();

        let (resolved_version, _) = Wallet::recover_resolved(
            &seed, "", Network::Mainnet, None,
            |addr| *addr.hash() == v1_hash,
        ).unwrap();
        assert_eq!(resolved_version, SeedVersion::V1LegacyPbkdf2Sha256);
    }

    /// K-M3: with NO matching hint at all, resolution must fail closed
    /// rather than default to either version.
    #[test]
    fn recover_resolved_fails_closed_with_no_match() {
        let (_, seed) = Wallet::generate(Network::Mainnet).unwrap();
        let result = Wallet::recover_resolved(&seed, "", Network::Mainnet, None, |_| false);
        assert!(matches!(result, Err(WalletError::AmbiguousSeedVersion)));
    }

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
            crypto::verify(&pk, &signed.sighash(0, crate::core::ChainId::Testnet), &sig),
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


use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, AeadInPlace, KeyInit}};
use argon2::{Argon2, Algorithm, Version, Params};
use base64::{Engine as _, engine::general_purpose as b64};
use rand::RngCore;
use std::borrow::Cow;
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

/// Borrow ordinary unescaped key strings from the zeroizing decrypted JSON.
/// Historical escaped JSON still works through `Cow::Owned`; the fallback is
/// explicitly wiped instead of leaving a second secret string allocation.
#[derive(Deserialize)]
struct BorrowedKeystorePayload<'a> {
    #[serde(borrow)]
    private_key_hex: Cow<'a, str>,
    #[serde(borrow)]
    public_key_hex: Cow<'a, str>,
}

impl Drop for BorrowedKeystorePayload<'_> {
    fn drop(&mut self) {
        if let Cow::Owned(private_key_hex) = &mut self.private_key_hex {
            private_key_hex.zeroize();
        }
        if let Cow::Owned(public_key_hex) = &mut self.public_key_hex {
            public_key_hex.zeroize();
        }
    }
}

// ── Keypair ───────────────────────────────────────────────────────────────────

#[derive(Clone, Deserialize)]
pub struct Keypair {
    pub private_key: Vec<u8>,
    pub public_key:  Vec<u8>,
    pub address:     String,
}

/// SECURITY (A4 lows): hand-written so the private key can NEVER reach a
/// `serde_json::to_*`/`to_vec`/etc. call on `Keypair` — a careless log line,
/// debug endpoint, or accidental persist that serializes a `Keypair` must not
/// be able to leak the secret key. Only the address and public key travel;
/// encrypted persistence goes through `KeystorePayload`/`EncryptedKeyfile`,
/// which are separate types with their own AEAD, not this impl.
impl Serialize for Keypair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("Keypair", 2)?;
        s.serialize_field("public_key", &hex::encode(&self.public_key))?;
        s.serialize_field("address", &self.address)?;
        s.end()
    }
}

impl Drop for Keypair {
    fn drop(&mut self) { self.private_key.zeroize(); }
}

impl Keypair {
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        // Legacy v2 keystores stored the RAW private key (no 4-byte suite envelope),
        // while newer keys and crypto::sign use the enveloped form. If this key is
        // un-enveloped, wrap it under the SAME suite the (enveloped) public key
        // declares, so the signature matches the address's suite. Never mutates
        // the stored key. The temporary owned wrapper contains the entire secret,
        // so keep it in zeroizing storage instead of a plain `Cow::Owned` buffer.
        if crypto::parse_envelope(&self.private_key).is_some() {
            crypto::sign(&self.private_key, msg).map_err(|e| e.to_string())
        } else {
            let suite = crypto::parse_envelope(&self.public_key)
                .map(|(s, _)| s)
                .unwrap_or(crypto::SUITE_MLDSA65_FALCON1024);
            let sk = Zeroizing::new(crypto::wrap_envelope(suite, &self.private_key));
            crypto::sign(&sk, msg).map_err(|e| e.to_string())
        }
    }

    /// Verify arbitrary wallet data while preserving legacy format compatibility.
    ///
    /// Matching enveloped and raw-hybrid pairs are attempted explicitly before
    /// the historical autodetecting verifier. The final fallback preserves mixed
    /// raw/enveloped inputs previously accepted by this broad compatibility API.
    pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        crypto::verify_enveloped(pk, msg, sig)
            || crypto::verify_legacy_hybrid_raw(pk, msg, sig)
            || crypto::verify(pk, msg, sig)
    }

    /// A4-M-4: sign an arbitrary user-supplied MESSAGE (never a raw digest).
    /// Signs `crypto::signed_message_digest(message)`, not `message` itself —
    /// the caller must pass the message's raw bytes, never hex-decoded text,
    /// so a 64-hex-character message can never be reinterpreted as a raw
    /// 32-byte tx sighash / disclosure digest / PoS signing root. Pair with
    /// [`Self::verify_message`].
    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let digest = crypto::signed_message_digest(message);
        self.sign(&digest)
    }

    /// Verify a signature produced by [`Self::sign_message`] over `message`
    /// under public key `pk` while preserving historical wallet compatibility.
    ///
    /// Known enveloped and raw-hybrid pairs are tried through their explicit
    /// format APIs first. The generic verifier remains a final fallback for
    /// older mixed envelope/raw records whose storage metadata was not retained.
    pub fn verify_message(pk: &[u8], message: &[u8], sig: &[u8]) -> bool {
        let digest = crypto::signed_message_digest(message);
        crypto::verify_enveloped(pk, &digest, sig)
            || crypto::verify_legacy_hybrid_raw(pk, &digest, sig)
            || crypto::verify(pk, &digest, sig)
    }

    /// Verify a newly-issued wallet message using the strict modern policy.
    /// Both objects must carry suite envelopes and the signature encoding must
    /// be canonical; legacy raw and mixed-format records are rejected.
    pub fn verify_message_canonical(pk: &[u8], message: &[u8], sig: &[u8]) -> bool {
        let digest = crypto::signed_message_digest(message);
        crypto::verify_enveloped_canonical(pk, &digest, sig)
    }

    pub fn address_bytes(&self) -> Vec<u8> {
        use sha3::{Sha3_256, Digest};
        Sha3_256::digest(&self.public_key)[..20].to_vec()
    }

    // ── Keystore ──────────────────────────────────────────────────────────────

    pub fn save_encrypted(&self, path: &Path, password: &str) -> Result<(), String> {
        // SECURITY (A4 lows): enforce the SAME blocking password policy as
        // the new-style `EncryptedKeyfile` (length + breach denylist) here
        // too — this legacy path is reachable directly (e.g. the CLI's `New`
        // command), and Argon2 hardening is moot behind a weak password.
        encryption::validate_password_strength(password).map_err(|e| e.to_string())?;

        let mut salt = vec![0u8; 32];
        rand::rng().fill_bytes(&mut salt);
        let enc_key = derive_key(password, &salt)?;
        let mut nonce_b = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_b);

        let ct = encrypt_legacy_keystore_payload(
            &enc_key,
            &nonce_b,
            &self.private_key,
            &self.public_key,
        )?;
        // The derived key is no longer needed once the private helper has
        // returned the ciphertext. Wipe it before public metadata assembly,
        // final JSON serialization and atomic write/fsync below.
        drop(enc_key);

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
        Self::load_encrypted_with_file_limit(path, password, crate::util::DEFAULT_WALLET_FILE_LIMIT)
    }

    /// Explicit bounded recovery override for authentic large keystores (maximum 512 MiB).
    pub fn load_encrypted_with_file_limit(path: &Path, password: &str, max_bytes: usize) -> Result<Self, String> {
        let bytes = crate::util::read_wallet_file(path, max_bytes).map_err(|e| e.to_string())?;
        let ks: EncryptedKeystore = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if ks.version != 2 { return Err("unsupported keystore version".into()); }

        // Reject attacker-controlled Argon2 work before any Base64 decoder can
        // allocate output for the remaining untrusted fields.
        validate_kdf_params(&ks.crypto.kdf_params)?;
        validate_legacy_nonce_base64_length(&ks.crypto.nonce)?;

        let salt      = b64::STANDARD.decode(&ks.crypto.kdf_params.salt).map_err(|e| e.to_string())?;
        let nonce_b   = b64::STANDARD.decode(&ks.crypto.nonce).map_err(|e| e.to_string())?;
        // Reuse the decoded ciphertext allocation for authenticated plaintext.
        // The wrapper wipes it if validation, KDF setup or authentication fails.
        let mut plain = Zeroizing::new(
            b64::STANDARD.decode(&ks.crypto.ciphertext).map_err(|e| e.to_string())?,
        );

        // SECURITY (A4 lows): `Nonce::from_slice` PANICS on any length other
        // than 12 bytes. `nonce_b` comes from an untrusted keystore file, so
        // guard the length BEFORE it reaches the fixed-size AES-GCM nonce —
        // a truncated/corrupt file must return an error, never crash the
        // process.
        const NONCE_LEN: usize = 12;
        const GCM_TAG_LEN: usize = 16;
        if nonce_b.len() != NONCE_LEN {
            return Err(format!(
                "keystore nonce has invalid length: expected {} bytes, got {}",
                NONCE_LEN, nonce_b.len()
            ));
        }
        if plain.len() < GCM_TAG_LEN {
            return Err(format!(
                "keystore ciphertext too short: {} bytes, need at least the {}-byte GCM tag",
                plain.len(), GCM_TAG_LEN
            ));
        }

        // SECURITY (A4 lows): honour the KDF params the keystore file
        // actually carries (a change to the default cost in `save_encrypted`
        // must not break decrypting an older file) but BOUND them first — an
        // untrusted file with e.g. `memory_cost` near `u32::MAX` (KiB) would
        // otherwise force a multi-terabyte Argon2 allocation (OOM) on unlock,
        // and `output_len != 32` would panic the AES-256 key conversion below.
        let enc_k = derive_key_with_params(password, &salt, &ks.crypto.kdf_params)?;

        decrypt_legacy_keystore_in_place(&enc_k, &nonce_b, &mut plain)?;
        drop(enc_k);

        let payload: BorrowedKeystorePayload<'_> =
            serde_json::from_slice(&plain).map_err(|e| e.to_string())?;
        let mut private_key = Zeroizing::new(
            hex::decode(payload.private_key_hex.as_ref()).map_err(|e| e.to_string())?,
        );
        let public_key = hex::decode(payload.public_key_hex.as_ref()).map_err(|e| e.to_string())?;
        drop(payload);

        let testnet = ks.address.starts_with(TESTNET_PREFIX);
        let derived = crypto::address_from_pubkey(&public_key, testnet);
        if derived != ks.address { return Err("address mismatch — keystore may be tampered".into()); }
        Ok(Keypair { private_key: std::mem::take(&mut *private_key), public_key, address: ks.address })
    }
}

/// Serialize and encrypt the legacy keypair while keeping repository-owned
/// secret copies inside this short-lived boundary. The structured hex payload
/// is wiped as soon as serialization succeeds; the zeroizing JSON plaintext
/// is wiped when this helper returns, before public metadata is assembled or
/// the final keystore is written.
fn encrypt_legacy_keystore_payload(
    key: &[u8],
    nonce: &[u8; 12],
    private_key: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>, String> {
    let payload = KeystorePayload {
        private_key_hex: hex::encode(private_key),
        public_key_hex: hex::encode(public_key),
    };
    let plain = Zeroizing::new(
        serde_json::to_vec(&payload).map_err(|e| e.to_string())?,
    );
    drop(payload);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher.encrypt(Nonce::from_slice(nonce), plain.as_ref())
        .map_err(|e| e.to_string())
}

fn decrypt_legacy_keystore_in_place(
    key: &[u8],
    nonce_b: &[u8],
    ciphertext: &mut Vec<u8>,
) -> Result<(), String> {
    const NONCE_LEN: usize = 12;
    const GCM_TAG_LEN: usize = 16;
    if key.len() != 32 {
        return Err("AES-256 key must contain 32 bytes".into());
    }
    if nonce_b.len() != NONCE_LEN {
        return Err(format!(
            "keystore nonce has invalid length: expected {} bytes, got {}",
            NONCE_LEN, nonce_b.len()
        ));
    }
    if ciphertext.len() < GCM_TAG_LEN {
        return Err(format!(
            "keystore ciphertext too short: {} bytes, need at least the {}-byte GCM tag",
            ciphertext.len(), GCM_TAG_LEN
        ));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher.decrypt_in_place(Nonce::from_slice(nonce_b), b"", ciphertext)
        .map_err(|_| "decryption failed — wrong password or corrupted file".to_string())
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

        let to_bytes = hex::decode(to_address_hex)
            .map_err(|_| "invalid destination address hex")?;
        if to_bytes.len() != 20 {
            return Err("destination address hash must contain exactly 20 bytes".into());
        }
        let mut outpoints = std::collections::BTreeSet::new();
        for (txid, index, _) in available_utxos {
            if txid.len() != 32 {
                return Err("UTXO transaction ID must contain exactly 32 bytes".into());
            }
            if !outpoints.insert((txid.as_slice(), *index)) {
                return Err("duplicate UTXO outpoint".into());
            }
        }

        // Coin selection: greedy, smallest-first
        let mut selected: Vec<&(Vec<u8>, u32, TxOutput)> = vec![];
        let mut selected_total = 0u64;
        let mut sorted = available_utxos.iter().collect::<Vec<_>>();
        sorted.sort_by_key(|(_, _, o)| o.value);

        for utxo in &sorted {
            selected.push(utxo);
            selected_total = selected_total.checked_add(utxo.2.value)
                .ok_or("selected UTXO value overflow")?;
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
            prev_txid.copy_from_slice(txid);
            TxInput { prev_txid, prev_index: *idx, script_sig: vec![], sequence: u32::MAX }
        }).collect();

        // Build outputs (destination was validated before coin selection/signing).
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

        // Chain-id (Roadmap #8) — folded into every input's sighash, so it MUST
        // match the node validator's node_chain_id() or the signature is rejected.
        // Derived from the address prefix (mainnet/testnet) by default; override
        // via BLOCH_GENESIS3=1 (Genesis-3 mainnet) or BLOCH_GENESIS2=1
        // (Genesis-2 devnet) when signing for a SHA-256d carry-over chain
        // (whose addresses keep the mainnet prefix but whose chain-id differs).
        // BLOCH_GENESIS3 wins if both are set (explicit and newest chain).
        let chain_id = if std::env::var("BLOCH_GENESIS3").is_ok() {
            crate::core::ChainId::Genesis3Mainnet
        } else if std::env::var("BLOCH_GENESIS2").is_ok() {
            crate::core::ChainId::Genesis2Devnet
        } else if keypair.address.starts_with(TESTNET_PREFIX) {
            crate::core::ChainId::Testnet
        } else {
            crate::core::ChainId::Mainnet
        };
        // Sign each input
        for i in 0..tx.inputs.len() {
            let sighash = tx.sighash(i, chain_id);
            let sig     = keypair.sign(&sighash)?;
            tx.inputs[i].script_sig = Transaction::build_script_sig(&sig, &keypair.public_key);
        }

        Ok(tx)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn generate_keypair(testnet: bool) -> Keypair {
    let (public_key, private_key) = crypto::generate_keypair();
    let mut private_key = wallet_secret_owner(private_key);
    let address = crypto::address_from_pubkey(&public_key, testnet);
    Keypair {
        private_key: std::mem::take(&mut *private_key),
        public_key,
        address,
    }
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

fn derive_key(pw: &str, salt: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let params = Params::new(262144, 4, 4, Some(32)).map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new(vec![0u8; 32]);
    argon2.hash_password_into(pw.as_bytes(), salt, &mut key).map_err(|e| e.to_string())?;
    Ok(key)
}

/// Bounds mirrored from `encryption::EncryptedKeyfile::decrypt` (audit L1):
/// an untrusted keystore file's `kdf_params` must be sanity-checked BEFORE
/// they drive an Argon2 allocation. `memory_cost` near `u32::MAX` (KiB) forces
/// a multi-terabyte allocation (OOM-kills the process on unlock); a huge
/// `time_cost` is a CPU slow-loris. `output_len` is pinned to exactly 32 —
/// this keystore format always feeds the result straight into AES-256-GCM,
/// whose `Key::from_slice` panics on anything but 32 bytes.
const MAX_M_COST_KIB: u32 = 1024 * 1024; // 1 GiB
const MAX_T_COST: u32 = 16;
const MAX_P_COST: u32 = 16;
const LEGACY_NONCE_B64_LEN: usize = 16; // 12 decoded bytes

fn validate_legacy_nonce_base64_length(nonce_b64: &str) -> Result<(), String> {
    if nonce_b64.len() != LEGACY_NONCE_B64_LEN {
        return Err(format!(
            "keystore nonce Base64 has invalid encoded length: expected {} bytes, got {}",
            LEGACY_NONCE_B64_LEN,
            nonce_b64.len()
        ));
    }
    Ok(())
}

fn validate_kdf_params(p: &KdfParams) -> Result<(), String> {
    if p.memory_cost > MAX_M_COST_KIB || p.time_cost > MAX_T_COST || p.parallelism > MAX_P_COST {
        return Err(format!(
            "KDF params out of bounds (memory_cost={} KiB, time_cost={}, parallelism={})",
            p.memory_cost, p.time_cost, p.parallelism
        ));
    }
    if p.output_len != 32 {
        return Err(format!(
            "KDF output_len must be 32 (AES-256 key), got {}", p.output_len
        ));
    }
    Ok(())
}

fn derive_key_with_params(
    pw: &str,
    salt: &[u8],
    p: &KdfParams,
) -> Result<Zeroizing<Vec<u8>>, String> {
    // Keep validation here as a defense for any future non-file caller.
    validate_kdf_params(p)?;
    let params = Params::new(p.memory_cost, p.time_cost, p.parallelism, Some(32))
        .map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new(vec![0u8; 32]);
    argon2.hash_password_into(pw.as_bytes(), salt, &mut key).map_err(|e| e.to_string())?;
    Ok(key)
}

// Terminal CLI (clap + rpassword) — gated so the pure wallet/crypto subset
// cross-compiles to wasm32 for the mobile WASM wallet. Native CLI builds enable
// `wallet-cli` (the `postern-wallet` bin already requires it).
#[cfg(feature = "wallet-cli")]
pub mod cli;


#[cfg(test)]
mod legacy_keystore_tests {
    use super::*;

    #[test]
    fn legacy_keygen_preserves_address_and_signing_on_both_networks() {
        assert!(std::mem::needs_drop::<Keypair>());

        for testnet in [false, true] {
            let keypair = generate_keypair(testnet);
            assert_eq!(
                keypair.address,
                crypto::address_from_pubkey(&keypair.public_key, testnet),
            );
            let signature = keypair.sign(b"wave-136-keygen-parity").unwrap();
            assert!(Keypair::verify(
                &keypair.public_key,
                b"wave-136-keygen-parity",
                &signature,
            ));
        }
    }

    #[test]
    fn legacy_save_temporaries_have_zeroizing_ownership_and_exact_json() {
        let _: fn(&str, &[u8]) -> Result<Zeroizing<Vec<u8>>, String> = derive_key;
        let _: fn(&[u8], &[u8; 12], &[u8], &[u8]) -> Result<Vec<u8>, String> =
            encrypt_legacy_keystore_payload;
        assert!(std::mem::needs_drop::<Zeroizing<Vec<u8>>>());
        assert!(std::mem::needs_drop::<KeystorePayload>());

        let payload = KeystorePayload {
            private_key_hex: "a1b2c3d4".into(),
            public_key_hex: "01020304".into(),
        };
        let expected = serde_json::to_vec(&payload).unwrap();
        let key = [0x52; 32];
        let nonce = [0x73; 12];
        let historical_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let expected_ciphertext = historical_cipher
            .encrypt(Nonce::from_slice(&nonce), expected.as_slice())
            .unwrap();
        let mut ciphertext = Zeroizing::new(
            encrypt_legacy_keystore_payload(
                &key,
                &nonce,
                &[0xa1, 0xb2, 0xc3, 0xd4],
                &[0x01, 0x02, 0x03, 0x04],
            ).unwrap(),
        );
        assert_eq!(&ciphertext[..], &expected_ciphertext);
        decrypt_legacy_keystore_in_place(&key, &nonce, &mut ciphertext).unwrap();
        assert_eq!(&ciphertext[..], &expected);
        ciphertext.zeroize();
        assert!(ciphertext.is_empty() || ciphertext.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn legacy_load_kdf_returns_exact_zeroizing_owner() {
        let _: fn(
            &str,
            &[u8],
            &KdfParams,
        ) -> Result<Zeroizing<Vec<u8>>, String> = derive_key_with_params;

        let kdf = KdfParams {
            memory_cost: 8,
            time_cost: 1,
            parallelism: 1,
            salt: String::new(),
            output_len: 32,
        };
        let salt = [0x39; 16];
        let mut expected = vec![0u8; 32];
        let params = Params::new(8, 1, 1, Some(32)).unwrap();
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(b"synthetic-test-password", &salt, &mut expected)
            .unwrap();

        let mut actual =
            derive_key_with_params("synthetic-test-password", &salt, &kdf).unwrap();
        assert!(std::mem::needs_drop::<Zeroizing<Vec<u8>>>());
        assert_eq!(&actual[..], &expected);
        actual.zeroize();
        assert!(actual.is_empty() || actual.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn legacy_loader_checks_every_kdf_bound_before_base64() {
        let password = "synthetic-test-password";
        let path = std::env::temp_dir().join(format!(
            "bloch-wave176-legacy-kdf-order-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let baseline = KdfParams {
            memory_cost: 8,
            time_cost: 1,
            parallelism: 1,
            salt: b64::STANDARD.encode([0x19; 32]),
            output_len: 32,
        };
        let cases = [
            (
                KdfParams { memory_cost: MAX_M_COST_KIB + 1, ..baseline.clone() },
                format!(
                    "KDF params out of bounds (memory_cost={} KiB, time_cost=1, parallelism=1)",
                    MAX_M_COST_KIB + 1
                ),
            ),
            (
                KdfParams { time_cost: MAX_T_COST + 1, ..baseline.clone() },
                format!(
                    "KDF params out of bounds (memory_cost=8 KiB, time_cost={}, parallelism=1)",
                    MAX_T_COST + 1
                ),
            ),
            (
                KdfParams { parallelism: MAX_P_COST + 1, ..baseline.clone() },
                format!(
                    "KDF params out of bounds (memory_cost=8 KiB, time_cost=1, parallelism={})",
                    MAX_P_COST + 1
                ),
            ),
            (
                KdfParams { output_len: 31, ..baseline.clone() },
                "KDF output_len must be 32 (AES-256 key), got 31".to_string(),
            ),
        ];

        for (kdf_params, expected) in cases {
            let keystore = EncryptedKeystore {
                version: 2,
                address: "unused".into(),
                network: "mainnet".into(),
                crypto: KeystoreCrypto {
                    cipher: "aes-256-gcm".into(),
                    // If policy ordering regresses, this deliberately invalid
                    // large sentinel produces a Base64 error instead.
                    ciphertext: "!".repeat(64 * 1024),
                    nonce: b64::STANDARD.encode([0x28; 12]),
                    kdf: "argon2id".into(),
                    kdf_params,
                },
                created_at: String::new(),
                description: String::new(),
            };
            let bytes = serde_json::to_vec(&keystore).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            assert_eq!(
                Keypair::load_encrypted_with_file_limit(&path, password, bytes.len())
                    .unwrap_err(),
                expected
            );
        }

        // A valid, inexpensive parameter set still reaches the unchanged
        // Argon2/AES path and round-trips an authentic legacy keystore.
        let keypair = generate_keypair(false);
        let salt = [0x19; 32];
        let nonce = [0x28; 12];
        let kdf_params = baseline;
        let key = derive_key_with_params(password, &salt, &kdf_params).unwrap();
        let payload = Zeroizing::new(serde_json::to_vec(&KeystorePayload {
            private_key_hex: hex::encode(&keypair.private_key),
            public_key_hex: hex::encode(&keypair.public_key),
        }).unwrap());
        let ciphertext = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key))
            .encrypt(Nonce::from_slice(&nonce), payload.as_ref())
            .unwrap();
        let keystore = EncryptedKeystore {
            version: 2,
            address: keypair.address.clone(),
            network: "mainnet".into(),
            crypto: KeystoreCrypto {
                cipher: "aes-256-gcm".into(),
                ciphertext: b64::STANDARD.encode(ciphertext),
                nonce: b64::STANDARD.encode(nonce),
                kdf: "argon2id".into(),
                kdf_params,
            },
            created_at: String::new(),
            description: String::new(),
        };
        let bytes = serde_json::to_vec(&keystore).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let loaded = Keypair::load_encrypted_with_file_limit(&path, password, bytes.len())
            .unwrap();
        assert_eq!(loaded.private_key, keypair.private_key);
        assert_eq!(loaded.public_key, keypair.public_key);
        assert_eq!(loaded.address, keypair.address);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn legacy_nonce_base64_length_precedes_decode_without_restricting_salt() {
        let path = std::env::temp_dir().join(format!(
            "bloch-wave181-legacy-nonce-shape-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let password = "synthetic-test-password";
        let keypair = generate_keypair(false);
        let salt = [0x19; 8];
        let nonce = [0x28; 12];
        let kdf_params = KdfParams {
            memory_cost: 8,
            time_cost: 1,
            parallelism: 1,
            salt: b64::STANDARD.encode(salt),
            output_len: 32,
        };
        let key = derive_key_with_params(password, &salt, &kdf_params).unwrap();
        let payload = Zeroizing::new(serde_json::to_vec(&KeystorePayload {
            private_key_hex: hex::encode(&keypair.private_key),
            public_key_hex: hex::encode(&keypair.public_key),
        }).unwrap());
        let ciphertext = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key))
            .encrypt(Nonce::from_slice(&nonce), payload.as_ref())
            .unwrap();
        let baseline = EncryptedKeystore {
            version: 2,
            address: keypair.address.clone(),
            network: "mainnet".into(),
            crypto: KeystoreCrypto {
                cipher: "aes-256-gcm".into(),
                ciphertext: b64::STANDARD.encode(ciphertext),
                nonce: b64::STANDARD.encode(nonce),
                kdf: "argon2id".into(),
                // Legacy load historically accepts any Argon2-valid salt
                // length; this non-save-produced salt pins that compatibility.
                kdf_params,
            },
            created_at: String::new(),
            description: String::new(),
        };
        let load = |keystore: &EncryptedKeystore| {
            let bytes = serde_json::to_vec(keystore).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            Keypair::load_encrypted_with_file_limit(
                &path,
                password,
                bytes.len(),
            )
        };

        assert_eq!(baseline.crypto.nonce.len(), LEGACY_NONCE_B64_LEN);
        let loaded = load(&baseline).unwrap();
        assert_eq!(loaded.private_key, keypair.private_key);
        assert_eq!(loaded.public_key, keypair.public_key);
        assert_eq!(loaded.address, keypair.address);

        let mut exact_sentinel = baseline.clone();
        exact_sentinel.crypto.nonce = "!".repeat(LEGACY_NONCE_B64_LEN);
        assert!(
            !load(&exact_sentinel).unwrap_err().contains("invalid encoded length"),
            "an exact-length nonce sentinel must reach the Base64 decoder",
        );

        let mut one_over = baseline;
        one_over.crypto.nonce = "!".repeat(LEGACY_NONCE_B64_LEN + 1);
        assert_eq!(
            load(&one_over).unwrap_err(),
            format!(
                "keystore nonce Base64 has invalid encoded length: expected {} bytes, got {}",
                LEGACY_NONCE_B64_LEN,
                LEGACY_NONCE_B64_LEN + 1
            ),
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn legacy_decrypted_key_strings_borrow_plaintext_and_preserve_escaped_json() {
        let plain = Zeroizing::new(
            serde_json::to_vec(&KeystorePayload {
                private_key_hex: "a1b2c3d4".into(),
                public_key_hex: "01020304".into(),
            }).unwrap(),
        );
        let parsed: BorrowedKeystorePayload<'_> = serde_json::from_slice(&plain).unwrap();
        assert!(matches!(&parsed.private_key_hex, Cow::Borrowed(_)));
        assert!(matches!(&parsed.public_key_hex, Cow::Borrowed(_)));
        let start = plain.as_ptr() as usize;
        let end = start + plain.len();
        for pointer in [
            parsed.private_key_hex.as_ptr() as usize,
            parsed.public_key_hex.as_ptr() as usize,
        ] {
            assert!(pointer >= start && pointer < end);
        }
        assert_eq!(
            hex::decode(parsed.private_key_hex.as_ref()).unwrap(),
            [0xa1, 0xb2, 0xc3, 0xd4]
        );
        drop(parsed);

        let escaped = br#"{
            "private_key_hex":"\u0061\u0062",
            "public_key_hex":"\u0063\u0064"
        }"#;
        let escaped_parsed: BorrowedKeystorePayload<'_> =
            serde_json::from_slice(escaped).unwrap();
        assert!(matches!(&escaped_parsed.private_key_hex, Cow::Owned(_)));
        assert!(matches!(&escaped_parsed.public_key_hex, Cow::Owned(_)));
        assert_eq!(hex::decode(escaped_parsed.private_key_hex.as_ref()).unwrap(), [0xab]);
        assert_eq!(hex::decode(escaped_parsed.public_key_hex.as_ref()).unwrap(), [0xcd]);
        assert!(std::mem::needs_drop::<BorrowedKeystorePayload<'_>>());
    }

    #[test]
    fn legacy_keystore_decryption_reuses_ciphertext_allocation_at_tag_boundary() {
        let key = [0x82; 32];
        let nonce = [0x28; 12];
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

        for plaintext in [b"".as_slice(), b"legacy wallet secret".as_slice()] {
            let mut buffer = cipher.encrypt(Nonce::from_slice(&nonce), plaintext).unwrap();
            let allocation = buffer.as_ptr();
            let encrypted_len = buffer.len();

            decrypt_legacy_keystore_in_place(&key, &nonce, &mut buffer).unwrap();

            assert_eq!(
                buffer.as_ptr(), allocation,
                "legacy decrypt must reuse the Base64-decoded allocation"
            );
            assert_eq!(buffer, plaintext);
            assert_eq!(encrypted_len, plaintext.len() + 16);
        }

        let mut below_tag = vec![0u8; 15];
        assert_eq!(
            decrypt_legacy_keystore_in_place(&key, &nonce, &mut below_tag).unwrap_err(),
            "keystore ciphertext too short: 15 bytes, need at least the 16-byte GCM tag"
        );

        let mut tampered = Zeroizing::new(
            cipher.encrypt(
                Nonce::from_slice(&nonce),
                b"authenticated legacy secret".as_slice(),
            ).unwrap(),
        );
        tampered[0] ^= 1;
        let allocation = tampered.as_ptr();
        assert_eq!(
            decrypt_legacy_keystore_in_place(&key, &nonce, &mut tampered).unwrap_err(),
            "decryption failed — wrong password or corrupted file"
        );
        assert_eq!(tampered.as_ptr(), allocation);
        assert!(std::mem::needs_drop::<Zeroizing<Vec<u8>>>());
    }

    #[test]
    fn keypair_verify_accepts_genuine_magic_prefixed_raw_signature_explicitly() {
        const MESSAGE: &[u8] = b"BLOCH-CR10-MAGIC-PREFIX-FIXTURE-v1";
        const SEARCH_COUNTER: u64 = 23_156;
        const SIGNING_SEED_HEX: &str =
            "5d051b8c445a2f169a9a0104877500c39332cb493ec6de2723cb37dfbb233042";

        let (enveloped_public_key, enveloped_secret_key) =
            crypto::generate_keypair_from_seed(&[0x64; 32]).unwrap();
        let mut h = Sha3_256::new();
        h.update(b"bloch/cr10/signing-rng/v1");
        h.update(SEARCH_COUNTER.to_le_bytes());
        let signing_seed: [u8; 32] = h.finalize().into();
        assert_eq!(hex::encode(signing_seed), SIGNING_SEED_HEX);
        let enveloped_signature =
            pqcrypto_internals::with_seeded_rng_scope(&signing_seed, || {
                crypto::sign(&enveloped_secret_key, MESSAGE).unwrap()
            });

        assert!(Keypair::verify(
            &enveloped_public_key,
            MESSAGE,
            &enveloped_signature,
        ));
        assert!(crypto::verify_enveloped_canonical(
            &enveloped_public_key,
            MESSAGE,
            &enveloped_signature,
        ));

        let raw_public_key = &enveloped_public_key[crypto::SUITE_HEADER_LEN..];
        let raw_signature = &enveloped_signature[crypto::SUITE_HEADER_LEN..];
        assert_eq!(&raw_signature[..2], &[0xb1, 0x0c]);
        assert!(
            !crypto::verify(raw_public_key, MESSAGE, raw_signature),
            "generic autodetection must misclassify this genuine raw signature"
        );
        assert!(Keypair::verify(raw_public_key, MESSAGE, raw_signature));
    }

    /// A4 lows: `Keypair::save_encrypted` must enforce the same blocking
    /// password policy as the new-style keyfile — a weak password must never
    /// produce a keystore file at all.
    #[test]
    fn save_encrypted_rejects_weak_password() {
        let kp = generate_keypair(false);
        let tmp = std::env::temp_dir().join("bloch-kp-weak-pw-test.json");
        let _ = std::fs::remove_file(&tmp);
        let result = kp.save_encrypted(&tmp, "short");
        assert!(result.is_err(), "a short password must be rejected");
        assert!(!tmp.exists(), "no keystore file must be written on a rejected password");
    }

    /// A4 lows: a keystore with a corrupt/truncated nonce must return an
    /// error, not panic. `Nonce::from_slice` panics on any length other than
    /// 12 bytes; before the length guard this crashed the process.
    #[test]
    fn load_encrypted_corrupt_nonce_returns_error_not_panic() {
        let kp = generate_keypair(false);
        let tmp = std::env::temp_dir().join("bloch-kp-corrupt-nonce-test.json");
        let _ = std::fs::remove_file(&tmp);
        kp.save_encrypted(&tmp, "correct-horse-battery-9!").unwrap();

        let json = std::fs::read_to_string(&tmp).unwrap();
        let mut ks: serde_json::Value = serde_json::from_str(&json).unwrap();
        ks["crypto"]["nonce"] = serde_json::json!(b64::STANDARD.encode([0u8; 4]));
        std::fs::write(&tmp, serde_json::to_string(&ks).unwrap()).unwrap();

        let result = Keypair::load_encrypted(&tmp, "correct-horse-battery-9!");
        assert!(result.is_err(), "a truncated nonce must be a clean error");

        let _ = std::fs::remove_file(&tmp);
    }

    /// A4 lows: an out-of-bounds `kdf_params.memory_cost` in an untrusted
    /// keystore file must be rejected BEFORE it reaches Argon2 (which would
    /// otherwise attempt a multi-terabyte allocation).
    #[test]
    fn load_encrypted_rejects_out_of_bounds_kdf_params() {
        let kp = generate_keypair(false);
        let tmp = std::env::temp_dir().join("bloch-kp-bad-kdf-test.json");
        let _ = std::fs::remove_file(&tmp);
        kp.save_encrypted(&tmp, "correct-horse-battery-9!").unwrap();

        let json = std::fs::read_to_string(&tmp).unwrap();
        let mut ks: serde_json::Value = serde_json::from_str(&json).unwrap();
        ks["crypto"]["kdf_params"]["memory_cost"] = serde_json::json!(u32::MAX - 1);
        std::fs::write(&tmp, serde_json::to_string(&ks).unwrap()).unwrap();

        let result = Keypair::load_encrypted(&tmp, "correct-horse-battery-9!");
        assert!(result.is_err(), "an absurd memory_cost must be rejected, not attempted");

        let _ = std::fs::remove_file(&tmp);
    }

    /// A4 lows: `Keypair`'s hand-written `Serialize` must never emit the
    /// private key, however the type is serialized.
    #[test]
    fn keypair_serialize_never_emits_private_key() {
        let kp = generate_keypair(false);
        let json = serde_json::to_string(&kp).unwrap();
        let hex_priv = hex::encode(&kp.private_key);
        assert!(!json.contains(&hex_priv), "serialized Keypair must not contain the private key hex");
        assert!(json.contains(&kp.address), "serialized Keypair must still carry the address");
    }

    /// A4-M-4 regression: signing a 64-hex-character MESSAGE must NOT produce
    /// a signature valid over the raw 32 bytes that hex decodes to — the
    /// exact phishing shape the finding reported ("sign this challenge",
    /// where the challenge is secretly a tx sighash / disclosure digest
    /// preimage). Before the fix, the CLI auto-hex-decoded the message and
    /// signed those raw bytes directly, so this assertion would have failed
    /// (the signature over the digest string via the OLD path IS a valid
    /// signature over the raw bytes).
    #[test]
    fn sign_message_of_64_hex_chars_does_not_forge_a_raw_digest_signature() {
        let kp = generate_keypair(false);

        // A 64-hex-char "message" a phishing flow could ask the user to sign
        // — it decodes to exactly 32 bytes, the same shape as a tx sighash.
        let hex_message = "ab".repeat(32);
        assert_eq!(hex_message.len(), 64);
        let raw_digest = hex::decode(&hex_message).unwrap();
        assert_eq!(raw_digest.len(), 32);

        let sig = kp.sign_message(hex_message.as_bytes()).unwrap();

        // The new signed-message API verifies over the message bytes.
        assert!(Keypair::verify_message(&kp.public_key, hex_message.as_bytes(), &sig));

        // But the OLD vulnerable path — treat `sig` as a signature over the
        // raw hex-decoded 32 bytes (e.g. a tx sighash preimage) — must fail.
        assert!(
            !crypto::verify(&kp.public_key, &raw_digest, &sig),
            "a signed MESSAGE must never verify as a signature over the raw \
             hex-decoded digest — that would let a signed challenge double as \
             a transaction/disclosure signature"
        );

        // And a genuine raw-digest signature (the tx-sighash-style path) must
        // NOT verify as a signed message over the hex string either — the two
        // domains are symmetric-safe, not just one-directional.
        let raw_sig = crypto::sign(&kp.private_key, &raw_digest).unwrap();
        assert!(!Keypair::verify_message(&kp.public_key, hex_message.as_bytes(), &raw_sig));
    }

    /// Sanity: normal save/load with a strong password still round-trips —
    /// the new guards must not break the legitimate path.
    #[test]
    fn save_load_roundtrip_still_works() {
        let kp = generate_keypair(false);
        let tmp = std::env::temp_dir().join("bloch-kp-roundtrip-test.json");
        let _ = std::fs::remove_file(&tmp);
        kp.save_encrypted(&tmp, "correct-horse-battery-9!").unwrap();
        let file_len = std::fs::metadata(&tmp).unwrap().len() as usize;
        assert!(Keypair::load_encrypted_with_file_limit(&tmp, "wrong", file_len - 1)
            .err().unwrap().contains("byte limit"));
        assert!(matches!(Wallet::load_encrypted_with_file_limit(&tmp, "wrong", file_len - 1), Err(WalletError::Io(message)) if message.contains("byte limit")));
        let exact = Keypair::load_encrypted_with_file_limit(&tmp, "correct-horse-battery-9!", file_len).unwrap();
        assert_eq!(exact.private_key, kp.private_key);
        let loaded = Keypair::load_encrypted(&tmp, "correct-horse-battery-9!").unwrap();
        assert_eq!(loaded.address, kp.address);
        assert_eq!(loaded.private_key, kp.private_key);
        let _ = std::fs::remove_file(&tmp);
    }
}

#[cfg(test)]
mod legacy_sign_tests {
    use super::*;
    // A legacy-format key (raw sk, enveloped pk — the founder v2 shape) must sign and
    // the signature must verify under the enveloped pubkey (the exact consensus check).
    #[test]
    fn legacy_raw_sk_signs_and_verifies() {
        let (pk_env, sk_env) = crypto::generate_keypair(); // both enveloped
        // strip the 4-byte envelope from the sk to simulate the legacy v2 keystore
        let raw_sk = sk_env[4..].to_vec();
        assert!(crypto::parse_envelope(&raw_sk).map(|(s,_)| s) != Some(0xB10C_u16) , "raw sk must look un-enveloped");
        let kp = Keypair {
            private_key: raw_sk,
            public_key: pk_env.clone(),
            address: crypto::address_from_pubkey(&pk_env, false),
        };
        let msg = b"experimental-tx-sighash";
        let sig = kp.sign(msg).expect("legacy sign must succeed");
        assert!(crypto::verify(&pk_env, msg, &sig), "signature must verify under enveloped pubkey");
    }

    /// The zeroizing legacy-wrapper path must remain fail-closed when hostile
    /// wallet material has the expected raw shape but does not belong to the
    /// stored public key. Some backends accept any correctly-sized secret
    /// byte string and emit an unusable signature; others reject it. Neither
    /// outcome may authenticate the corrupted wallet record.
    #[test]
    fn corrupted_legacy_raw_secret_never_authenticates() {
        let (pk_env, _) = crypto::generate_keypair();
        // Use a different, structurally valid secret of the exact legacy raw
        // length. Flipping an arbitrary byte is not a reliable corruption:
        // Falcon's encoded secret can contain representation bits that do not
        // change the effective key, making this regression probabilistic.
        let (_, unrelated_sk_env) = crypto::generate_keypair();
        let raw_sk = unrelated_sk_env[crypto::SUITE_HEADER_LEN..].to_vec();
        let kp = Keypair {
            private_key: raw_sk,
            public_key: pk_env.clone(),
            address: crypto::address_from_pubkey(&pk_env, false),
        };
        let message = b"wallet-legacy-secret-authentication-regression";
        if let Ok(signature) = kp.sign(message) {
            assert!(
                !Keypair::verify(&pk_env, message, &signature),
                "a signature from corrupted legacy secret bytes must not authenticate"
            );
        }
    }

    /// THE founder case: a fully PRE-ENVELOPE wallet — RAW pubkey AND RAW privkey,
    /// address = SHA3-256(raw pubkey) — must produce a spend that passes the node's
    /// EXACT acceptance path (main.rs: pk_hash==script_pubkey AND crypto::verify).
    #[test]
    fn pre_envelope_founder_style_spend_verifies() {
        use sha3::{Sha3_256, Digest};
        let (pk_env, sk_env) = crypto::generate_keypair();
        let raw_pk = pk_env[4..].to_vec();   // 3745 — like the founder pubkey
        let raw_sk = sk_env[4..].to_vec();   // 6337 — like the founder privkey
        // address the OLD chain stored: SHA3-256(RAW pubkey)[..20]
        let script_pubkey = Sha3_256::digest(&raw_pk)[..20].to_vec();

        let kp = Keypair {
            private_key: raw_sk,
            public_key: raw_pk.clone(),      // the CLI puts THIS raw pk in script_sig
            address: crypto::address_from_pubkey(&raw_pk, false),
        };
        let sighash = b"genesis2-input-sighash";
        let sig = kp.sign(sighash).expect("founder-style sign must succeed");

        // Replicate the node's two consensus checks (src/main.rs:2764-2778):
        // 1) pubkey hash matches the UTXO's script_pubkey
        let pk_hash = Sha3_256::digest(&raw_pk)[..20].to_vec();
        assert_eq!(pk_hash, script_pubkey, "raw pubkey must hash to the carry-over address");
        // 2) crypto::verify accepts the raw pubkey + signature (the legacy fix)
        assert!(crypto::verify(&raw_pk, sighash, &sig), "node verify must accept the pre-envelope spend");

        // And a wrong key must still be rejected (no weakening).
        let (other_env, _) = crypto::generate_keypair();
        assert!(!crypto::verify(&other_env[4..], sighash, &sig), "a different pubkey must NOT verify");
    }
}

#[cfg(test)]
mod audit_transaction_boundaries {
    use super::*;
    #[test]
    fn cross_network_addresses_with_identical_hashes_are_refused() {
        for network in [Network::Mainnet, Network::Testnet] {
            let (wallet, _) = Wallet::generate(network).unwrap();
            let other = if network == Network::Mainnet { Network::Testnet } else { Network::Mainnet };
            let wrong = Address::from_hash([42;20], other);
            let right = Address::from_hash([42;20], network);
            let utxos = || vec![Utxo { txid:[1;32], index:0,
                output: TxOutput { value:1000, script_pubkey:wallet.address().hash().to_vec() } }];
            assert!(matches!(wallet.build_tx(utxos(), &wrong, 900, 100), Err(WalletError::NetworkMismatch)));
            assert!(wallet.build_tx(utxos(), &right, 900, 100).is_ok());
        }
    }
    #[test]
    fn empty_and_aggregate_input_overflows_return_errors() {
        let (wallet, _) = Wallet::generate(Network::Testnet).unwrap();
        assert!(matches!(wallet.build_tx(vec![], wallet.address(), u64::MAX, 1), Err(WalletError::Overflow)));
        let inputs = [u64::MAX, 1].into_iter().enumerate().map(|(index, value)| Utxo {
            txid:[1;32], index:index as u32, output:TxOutput { value, script_pubkey:wallet.address().hash().to_vec() }
        }).collect();
        assert!(matches!(wallet.build_tx(inputs, wallet.address(), 1, 0), Err(WalletError::Overflow)));
    }
}

#[cfg(test)]
mod audit_coin_selection_inputs {
    use super::*;

    #[test]
    fn legacy_builder_refuses_malformed_outpoints_destinations_duplicates_and_overflow() {
        let keypair = generate_keypair(true);
        let output = |value| TxOutput { value, script_pubkey: keypair.address_bytes() };
        let destination = "ab".repeat(20);
        for length in [0, 1, 31, 33, 64] {
            let inputs = vec![(vec![1; length], 0, output(1000))];
            assert!(TxBuilder::build(&keypair, &inputs, &destination, 900, 100)
                .err().unwrap().contains("exactly 32 bytes"));
        }
        let valid = vec![(vec![1; 32], 0, output(1000))];
        for destination in [String::new(), "ab".repeat(19), "ab".repeat(21), "zz".repeat(20)] {
            assert!(TxBuilder::build(&keypair, &valid, &destination, 900, 100).is_err());
        }
        let repeated = vec![(vec![1; 32], 0, output(500)), (vec![1; 32], 0, output(500))];
        assert!(TxBuilder::build(&keypair, &repeated, &destination, 900, 100)
            .err().unwrap().contains("duplicate"));
        let overflow = vec![(vec![1; 32], 0, output(1)), (vec![2; 32], 0, output(u64::MAX))];
        assert!(TxBuilder::build(&keypair, &overflow, &destination, u64::MAX, 0)
            .err().unwrap().contains("overflow"));
        // Distinct output indices from the same transaction are legitimate.
        let distinct = vec![(vec![1; 32], 0, output(500)), (vec![1; 32], 1, output(500))];
        let tx = TxBuilder::build(&keypair, &distinct, &destination, 900, 100).unwrap();
        assert_eq!(tx.inputs.len(), 2);
        assert_eq!(tx.outputs[0].value, 900);
        assert_eq!(tx.outputs[0].script_pubkey, vec![0xab; 20]);
    }

    #[test]
    fn current_builder_refuses_repeated_outpoint_without_rejecting_other_indices() {
        let (wallet, _) = Wallet::generate(Network::Testnet).unwrap();
        let utxo = |index| Utxo { txid: [3; 32], index,
            output: TxOutput { value: 500, script_pubkey: wallet.address().hash().to_vec() } };
        assert!(matches!(wallet.build_tx(vec![utxo(0), utxo(0)], wallet.address(), 900, 100),
            Err(WalletError::Parse(message)) if message.contains("duplicate")));
        let tx = wallet.build_tx(vec![utxo(0), utxo(1)], wallet.address(), 900, 100).unwrap();
        assert_eq!(tx.inputs.len(), 2);
    }
}

#[cfg(test)]
mod audit_exact_decimal_amounts {
    use super::parse_bloch_satoshis;
    #[test]
    fn exact_values_cover_float_precision_and_u64_boundaries() {
        for (input, expected) in [("0", 0), (".5", 50_000_000), ("1.", 100_000_000),
            ("0.00000001", 1), ("90071992.54740993", 9_007_199_254_740_993),
            ("184467440737.09551615", u64::MAX), (" 0001.2500 ", 125_000_000)] {
            assert_eq!(parse_bloch_satoshis(input), Ok(expected));
        }
        for invalid in ["", ".", "-1", "+1", "NaN", "inf", "1e3", "1.2.3",
            "0.000000001", "1.000000000", "184467440737.09551616", "184467440738",
            "999999999999999999999999999", "１", "1,000"] {
            assert!(parse_bloch_satoshis(invalid).is_err());
        }
    }
}
