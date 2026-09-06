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

#![forbid(unsafe_code)]

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::key::{CompressedPublicKey, TapTweak};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, KnownHrp, NetworkKind};
use std::str::FromStr;

/// I-13: this crate's public entry points must fail CLOSED on malformed
/// input rather than panic — a caller that mishandles an untrusted or
/// truncated seed must get an `Err`, never a crashed process.
#[derive(Debug, Clone, thiserror::Error)]
pub enum IdentityError {
    #[error("seed too short: {0} bytes (need at least 32)")]
    SeedTooShort(usize),
    #[error("BIP-32 master key derivation failed: {0}")]
    Bip32Master(String),
    #[error("BIP-32 derivation path is invalid: {0}")]
    Bip32Path(String),
    #[error("BIP-32 child-key derivation failed: {0}")]
    Bip32Derive(String),
    #[error("PQ keygen failed: {0}")]
    PqKeygen(String),
}

/// Minimum seed length this crate accepts anywhere (I-13). BIP32 itself
/// tolerates shorter seeds, but `generate_keypair_from_seed` requires 32, and
/// a seed below that has less entropy than any BIP39 phrase this wallet ever
/// produces — reject it up front instead of half-deriving the BTC keys and
/// panicking on the PQ leg.
const MIN_SEED_LEN: usize = 32;

/// Which KDF derives the companion PQ keygen seed from the wallet's BIP39
/// seed (I-13). `derive_identity`'s PQ half and `bloch_pq_vault::derive_vault_keys`'s
/// PQ half are documented to be "the exact companion key" for the SAME
/// wallet, so this choice is shared across both crates and must stay in
/// lock-step — see `bloch_pq_vault::VaultKeyDerivation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqSeedKdf {
    /// Pre-I-13 (default, for compatibility with existing callers/tests):
    /// `seed[..32]` reused VERBATIM as the ML-DSA/Falcon keygen seed — the
    /// same root bytes that also derive the BTC master key. A keygen-side
    /// weakness in one primitive family could in principle leak information
    /// about the other's key, since they share literal seed material.
    V1RawSeedReuse,
    /// I-13 fix: SHA3-256("bloch-btc-wallet/pq-seed/v2" ‖ seed) — the PQ
    /// keygen seed is independent of the raw BTC master-seed bytes, so the
    /// two primitive families no longer share literal key material.
    V2DomainSeparated,
}

/// Derive the PQ keygen SEED bytes for a wallet's BIP39 `seed` under the
/// given [`PqSeedKdf`] — exposed (not just used internally by
/// `derive_identity*`) so a caller that needs the FULL PQ keypair, not just
/// `derive_identity`'s public half (e.g. `bloch_pq_vault::derive_vault_keys_v2`,
/// which also needs the secret key), reproduces the EXACT same seed without
/// re-implementing the domain tag in a second place where it could drift.
///
/// Returns `None` if `seed` is shorter than [`MIN_SEED_LEN`] (I-13: fail
/// closed on this public entry point too — `V1RawSeedReuse`'s fixed-size
/// slice below would otherwise panic on a caller-supplied short seed).
pub fn pq_seed_for(seed: &[u8], kdf: PqSeedKdf) -> Option<[u8; 32]> {
    if seed.len() < MIN_SEED_LEN {
        return None;
    }
    Some(pq_seed(seed, kdf))
}

/// Precondition: `seed.len() >= MIN_SEED_LEN` — enforced by every caller
/// (`derive_identity_versioned` and the public `pq_seed_for` wrapper) before
/// this is reached; not re-checked here to keep the hot path a single match.
fn pq_seed(seed: &[u8], kdf: PqSeedKdf) -> [u8; 32] {
    match kdf {
        PqSeedKdf::V1RawSeedReuse => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&seed[..32]);
            out
        }
        PqSeedKdf::V2DomainSeparated => {
            use sha3::{Sha3_256, Digest};
            let mut h = Sha3_256::new();
            h.update(b"bloch-btc-wallet/pq-seed/v2");
            h.update(seed);
            h.finalize().into()
        }
    }
}

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
///
/// I-13: every fallible step now returns `Err` instead of panicking — `path`
/// is always a hardcoded, crate-internal constant (never attacker input), but
/// failing closed uniformly is cheap and keeps this function honest about
/// what it actually asserts.
fn derive_btc(seed: &[u8], path: &str, mainnet: bool) -> Result<(Vec<u8>, String, String), IdentityError> {
    let secp = Secp256k1::new();
    let net = if mainnet { NetworkKind::Main } else { NetworkKind::Test };
    let hrp = if mainnet { KnownHrp::Mainnet } else { KnownHrp::Testnets };
    let master = Xpriv::new_master(net, seed).map_err(|e| IdentityError::Bip32Master(e.to_string()))?;
    let dp = DerivationPath::from_str(path).map_err(|e| IdentityError::Bip32Path(e.to_string()))?;
    let xpriv = master.derive_priv(&secp, &dp).map_err(|e| IdentityError::Bip32Derive(e.to_string()))?;
    let kp = xpriv.to_keypair(&secp);
    let compressed = CompressedPublicKey(kp.public_key());
    let p2wpkh = Address::p2wpkh(&compressed, hrp).to_string();
    // BIP-86 key-path Taproot: tweak the internal key with no script.
    let (xonly, _parity) = kp.x_only_public_key();
    let p2tr = Address::p2tr(&secp, xonly, None, hrp).to_string();
    Ok((compressed.to_bytes().to_vec(), p2wpkh, p2tr))
}

/// Derive the full quantum-ready identity from a seed. Uses account 0, first receive
/// index (BIP-84 `m/84'/0'/0'/0/0`, BIP-86 `m/86'/0'/0'/0/0`) for the BTC keys, and
/// [`PqSeedKdf::V1RawSeedReuse`] (the historical, documented "exact companion key"
/// of `bloch_pq_vault::derive_vault_keys`) for the PQ keypair.
///
/// I-13: fails closed (`Err`) on a too-short seed instead of panicking through
/// `generate_keypair_from_seed`'s `.expect(..)`. Kept as the default entry
/// point for source compatibility; see [`derive_identity_versioned`] for the
/// domain-separated PQ-seed KDF.
pub fn derive_identity(seed: &[u8], mainnet: bool) -> Result<HybridIdentity, IdentityError> {
    derive_identity_versioned(seed, mainnet, PqSeedKdf::V1RawSeedReuse)
}

/// Derive the full quantum-ready identity from a seed under an EXPLICIT
/// [`PqSeedKdf`] for the companion PQ keypair. The BTC (secp256k1) derivation
/// is unaffected by this choice — only which bytes seed the ML-DSA/Falcon
/// keygen changes.
pub fn derive_identity_versioned(
    seed: &[u8],
    mainnet: bool,
    pq_kdf: PqSeedKdf,
) -> Result<HybridIdentity, IdentityError> {
    if seed.len() < MIN_SEED_LEN {
        return Err(IdentityError::SeedTooShort(seed.len()));
    }

    let coin = if mainnet { "0'" } else { "1'" };
    let (btc_pubkey, btc_p2wpkh, _) = derive_btc(seed, &format!("m/84'/{coin}/0'/0/0"), mainnet)?;
    let (_, _, btc_p2tr) = derive_btc(seed, &format!("m/86'/{coin}/0'/0/0"), mainnet)?;

    let pq_seed_bytes = pq_seed(seed, pq_kdf);
    let (pq_pubkey, _pq_secret) = bloch_crypto::crypto::generate_keypair_from_seed(&pq_seed_bytes)
        .map_err(|e| IdentityError::PqKeygen(e.to_string()))?;
    let net = if mainnet {
        bloch_crypto::address::Network::Mainnet
    } else {
        bloch_crypto::address::Network::Testnet
    };
    let bloch_address = bloch_crypto::address::Address::from_pubkey(&pq_pubkey, net).to_string();

    Ok(HybridIdentity { btc_p2wpkh, btc_p2tr, btc_pubkey, pq_pubkey, bloch_address })
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
        let (_, p2wpkh, _) = derive_btc(&abandon_seed(), "m/84'/0'/0'/0/0", true).unwrap();
        assert_eq!(p2wpkh, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    }

    #[test]
    fn bip86_known_vector() {
        // Official BIP-86 test vector, account 0, first receiving Taproot address.
        let (_, _, p2tr) = derive_btc(&abandon_seed(), "m/86'/0'/0'/0/0", true).unwrap();
        assert_eq!(p2tr, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
    }

    #[test]
    fn hybrid_identity_from_one_seed() {
        let seed = abandon_seed();
        let id = derive_identity(&seed, true).unwrap();
        // one seed → a real BTC address AND a Bloch PQ address
        assert!(id.btc_p2wpkh.starts_with("bc1q"));
        assert!(id.btc_p2tr.starts_with("bc1p"));
        assert!(id.bloch_address.starts_with("bloch1"));
        assert_eq!(id.btc_pubkey.len(), 33); // compressed secp256k1
        assert!(!id.pq_pubkey.is_empty());
        // deterministic: same seed → same identity
        let id2 = derive_identity(&seed, true).unwrap();
        assert_eq!(id.btc_p2wpkh, id2.btc_p2wpkh);
        assert_eq!(id.bloch_address, id2.bloch_address);
        assert_eq!(id.pq_pubkey, id2.pq_pubkey);
    }

    #[test]
    fn hybrid_validator_hash_is_stable() {
        let seed = abandon_seed();
        let id = derive_identity(&seed, true).unwrap();
        let v1 = hybrid_wbtc_validator(&id.btc_pubkey, &id.pq_pubkey);
        let v2 = hybrid_wbtc_validator(&id.btc_pubkey, &id.pq_pubkey);
        assert_eq!(bloch_euvm::validator_hash(&v1), bloch_euvm::validator_hash(&v2));
        // a different BTC key → a different guard
        let other = hybrid_wbtc_validator(&[2u8; 33], &id.pq_pubkey);
        assert_ne!(bloch_euvm::validator_hash(&v1), bloch_euvm::validator_hash(&other));
    }

    // ── I-13 regression tests ────────────────────────────────────────────────

    /// I-13: a seed shorter than 32 bytes must return `Err`, never panic.
    /// Before the fix, `Xpriv::new_master`/`generate_keypair_from_seed` were
    /// driven with `.expect(..)`, so a short seed crashed the process instead
    /// of failing closed.
    #[test]
    fn short_seed_fails_closed_instead_of_panicking() {
        for len in [0usize, 1, 16, 31] {
            let short_seed = vec![0x42u8; len];
            let result = derive_identity(&short_seed, true);
            assert!(
                matches!(result, Err(IdentityError::SeedTooShort(l)) if l == len),
                "seed of {} bytes must be rejected with SeedTooShort, got {:?}", len, result
            );
        }
        // The boundary itself must still succeed.
        assert!(derive_identity(&[0x42u8; 32], true).is_ok());
    }

    /// I-13: the two `PqSeedKdf` variants must derive DIFFERENT PQ keypairs
    /// for the identical seed — this is the point of domain-separating the
    /// PQ leg from the raw BTC master-seed bytes.
    #[test]
    fn pq_seed_kdf_v1_and_v2_diverge() {
        let seed = abandon_seed();
        let v1 = derive_identity_versioned(&seed, true, PqSeedKdf::V1RawSeedReuse).unwrap();
        let v2 = derive_identity_versioned(&seed, true, PqSeedKdf::V2DomainSeparated).unwrap();
        assert_ne!(v1.pq_pubkey, v2.pq_pubkey, "V1 and V2 PQ keys must never collide");
        // The BTC halves are UNAFFECTED by the PQ-seed KDF choice.
        assert_eq!(v1.btc_p2wpkh, v2.btc_p2wpkh);
        assert_eq!(v1.btc_p2tr, v2.btc_p2tr);
        // `derive_identity`'s default must be V1 (documented "exact companion
        // key" invariant with `bloch_pq_vault::derive_vault_keys`, unversioned).
        let default = derive_identity(&seed, true).unwrap();
        assert_eq!(default.pq_pubkey, v1.pq_pubkey);
    }

    /// I-13 KAT: V1 (raw seed reuse) must remain byte-for-byte what it always
    /// was — the SAME pq_pubkey the pre-fix code produced for this seed —
    /// so nothing that already depends on the "exact companion key" invariant
    /// with `bloch_pq_vault::derive_vault_keys` silently changes underfoot.
    #[test]
    fn pq_seed_kdf_v1_matches_raw_seed_pq_keygen() {
        let seed = abandon_seed();
        let (expected_pk, _) = bloch_crypto::crypto::generate_keypair_from_seed(&seed[..32]).unwrap();
        let id = derive_identity_versioned(&seed, true, PqSeedKdf::V1RawSeedReuse).unwrap();
        assert_eq!(id.pq_pubkey, expected_pk);
    }
}
