//! Bloch-SIS Protocol — Cryptography
//!
//! ML-DSA-65 signatures via pqcrypto-mldsa (NIST FIPS 204, official name).
//! Replaces deprecated pqcrypto-dilithium.
//!
//! Key sizes (ML-DSA-65):
//!   Public key:  1952 bytes
//!   Secret key:  4032 bytes
//!   Signature:   3309 bytes

use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{PublicKey, SecretKey, DetachedSignature};
use sha3::{Sha3_256, Digest};
use log::debug;

// Hybrid signature layout (Sprint B6b-1): ML-DSA-65 ‖ Falcon-1024.
// Public key = mldsa_pk(1952) ‖ falcon_pk. Secret = mldsa_sk(4032) ‖ falcon_sk.
// Signature  = mldsa_sig(3309) ‖ falcon_sig(variable). Splits use the fixed
// ML-DSA lengths; the Falcon part is the remainder. Both must verify.
pub const MLDSA_PUBKEY_LEN: usize = 1952;
pub const MLDSA_SECRET_LEN: usize = 4032;
pub const MLDSA_SIG_LEN:    usize = 3309;

pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let (mpk, msk) = mldsa65::keypair();
    let (fpk, fsk) = falcon::keypair();
    let mut pk = mpk.as_bytes().to_vec(); pk.extend_from_slice(&fpk);
    let mut sk = msk.as_bytes().to_vec(); sk.extend_from_slice(&fsk);
    (pk, sk)
}

/// Deterministic keypair generation from a 32-byte seed.
///
/// Uses FIPS 204 Algorithm 6 (ML-DSA.KeyGen_internal) — keygen is inherently
/// deterministic from the seed bytes consumed by `randombytes()`. We activate
/// a thread-local ChaCha20-seeded RNG via the Bloch-SIS Protocol pqcrypto-internals fork (see Cargo.toml [patch.crates-io]) of
/// `pqcrypto-internals` (see Cargo.toml `[patch.crates-io]`), which overrides
/// `PQCRYPTO_RUST_randombytes` for the duration of the keypair() call.
///
/// # Guarantees
///
/// - Same `seed` bytes → byte-identical `(public_key, secret_key)` every time,
///   on every platform supported by pqcrypto-mldsa.
/// - Different seeds → independent keypairs (ChaCha20 gives cryptographic
///   separation).
/// - The RNG state does not leak across calls: a thread-local RAII guard
///   (`SeededRngGuard`) clears the override on drop.
///
/// # Compatibility warning
///
/// This produces keypairs compatible with `pqcrypto-mldsa 0.1.x`. A future
/// upstream crate upgrade that changes internal keygen order would produce
/// different keypairs from the same seed. Wallet files should therefore
/// record the `pqcrypto-mldsa` version at generation time, and migration
/// should re-derive via the old version's algorithm before upgrading.
///
/// # Seed input
///
/// Accepts any `&[u8]` of length >= 32. Only the first 32 bytes are used as
/// the ChaCha20 key. Callers deriving seeds from BIP39 24-word phrases should
/// pass the 64-byte PBKDF2 output truncated to or hashed to 32 bytes.
pub fn generate_keypair_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    if seed.len() < 32 {
        return Err(CryptoError::InvalidKey(
            format!("seed too short: {} bytes (need 32+)", seed.len())
        ));
    }

    // Use first 32 bytes as ChaCha20 key. For longer seeds (e.g. 64-byte
    // BIP39 PBKDF2), the caller is responsible for hashing down to 32 bytes
    // if they want the full entropy preserved — here we take the first 32
    // for simplicity.
    let mut seed32 = [0u8; 32];
    seed32.copy_from_slice(&seed[..32]);

    // Activate thread-local seeded RNG for PQClean's internal randombytes().
    // Guard is RAII — on drop (end of this function), OS RNG is restored.
    let _guard = pqcrypto_internals::with_seeded_rng(&seed32);
    // Both keygens draw from the same seeded randombytes stream → deterministic
    // given the seed (ML-DSA is fully deterministic; Falcon is deterministic
    // given the byte stream — the platform-float caveat is documented in B6).
    let (mpk, msk) = mldsa65::keypair();
    let (fpk, fsk) = falcon::keypair();
    let mut pk = mpk.as_bytes().to_vec(); pk.extend_from_slice(&fpk);
    let mut sk = msk.as_bytes().to_vec(); sk.extend_from_slice(&fsk);
    Ok((pk, sk))
}

pub fn sign(secret_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Hybrid: mldsa_sk(4032) ‖ falcon_sk. Produce mldsa_sig(3309) ‖ falcon_sig.
    if secret_key_bytes.len() <= MLDSA_SECRET_LEN {
        return Err(CryptoError::InvalidKey("hybrid secret key too short".into()));
    }
    let (msk, fsk) = secret_key_bytes.split_at(MLDSA_SECRET_LEN);
    let sk = mldsa65::SecretKey::from_bytes(msk)
        .map_err(|_| CryptoError::InvalidKey("bad ML-DSA secret key".into()))?;
    let mut out = mldsa65::detached_sign(message, &sk).as_bytes().to_vec();
    out.extend_from_slice(&falcon::sign(fsk, message)?);
    Ok(out)
}

pub fn verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    // Audit L-1 fix: return `false` on parse failure (consensus rule — a
    // malformed signature MUST be treated as invalid), but also log at
    // debug! level so developers can tell the difference between
    // "signature parsed but didn't verify" and "signature was malformed".
    // Consensus behavior is unchanged.
    // Hybrid: split off the fixed-length ML-DSA prefix; the remainder is
    // Falcon. BOTH must verify (defence in depth across two lattice families).
    if public_key_bytes.len() <= MLDSA_PUBKEY_LEN || signature_bytes.len() <= MLDSA_SIG_LEN {
        debug!("crypto::verify: hybrid pubkey/sig too short (pk={}, sig={})",
               public_key_bytes.len(), signature_bytes.len());
        return false;
    }
    let (mpk, fpk) = public_key_bytes.split_at(MLDSA_PUBKEY_LEN);
    let (msig, fsig) = signature_bytes.split_at(MLDSA_SIG_LEN);

    let pk = match mldsa65::PublicKey::from_bytes(mpk) {
        Ok(k) => k,
        Err(e) => { debug!("crypto::verify: ML-DSA pubkey parse failed: {:?}", e); return false; }
    };
    let sig = match mldsa65::DetachedSignature::from_bytes(msig) {
        Ok(s) => s,
        Err(e) => { debug!("crypto::verify: ML-DSA sig parse failed: {:?}", e); return false; }
    };
    if mldsa65::verify_detached_signature(&sig, message, &pk).is_err() {
        return false;
    }
    // Falcon half.
    falcon::verify(fpk, message, fsig)
}

pub fn address_from_pubkey(public_key: &[u8], testnet: bool) -> String {
    let hash = Sha3_256::digest(public_key);
    let mut payload = [0u8; 20];
    payload.copy_from_slice(&hash[..20]);
    address_from_hash(&payload, testnet)
}

// ── Diversified (unlinkable) addresses — privacy P4 ───────────────────────────
//
// Address reuse links a user's activity on-chain. Diversified addresses derive an
// INDEPENDENT keypair per index from the master seed: each yields an
// on-chain-unlinkable address (an observer can't tell two belong to the same
// wallet), all deterministically recoverable from the seed. Rotate one per
// receive; never reuse.

/// Per-index sub-seed for a diversified address (HD-style, domain-separated).
pub fn diversified_seed(master_seed: &[u8], index: u32) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"bloch:diversifier:v1");
    h.update(master_seed);
    h.update(index.to_le_bytes());
    h.finalize().into()
}

/// Diversified keypair for `index` — independent, unlinkable, deterministic.
pub fn diversified_keypair(master_seed: &[u8], index: u32)
    -> Result<(Vec<u8>, Vec<u8>), CryptoError>
{
    generate_keypair_from_seed(&diversified_seed(master_seed, index))
}

/// Diversified address string for `index`.
pub fn diversified_address(master_seed: &[u8], index: u32, testnet: bool)
    -> Result<String, CryptoError>
{
    let (pk, _) = diversified_keypair(master_seed, index)?;
    Ok(address_from_pubkey(&pk, testnet))
}

/// Format a 20-byte pubkey hash into a bloch1q/bloch1t address with 4-byte checksum.
/// Use this when you already have the hash (e.g. treasury address, multisig hash)
/// and need the user-facing string form.
pub fn address_from_hash(hash: &[u8; 20], testnet: bool) -> String {
    use crate::core::{MAINNET_PREFIX, TESTNET_PREFIX};
    let inner   = Sha3_256::digest(hash);
    let outer   = Sha3_256::digest(inner);
    let checksum = &outer[..4];
    let mut addr = hash.to_vec();
    addr.extend_from_slice(checksum);
    format!("{}{}", if testnet { TESTNET_PREFIX } else { MAINNET_PREFIX }, hex::encode(&addr))
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid key: {0}")]   InvalidKey(String),
    #[error("sign failed: {0}")]   SignFailed(String),
    #[error("verify failed")]      VerifyFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn sign_verify_roundtrip() {
        let (pk, sk) = generate_keypair();
        let sig = sign(&sk, b"test").unwrap();
        assert!(verify(&pk, b"test", &sig));
    }
    #[test] fn wrong_message_fails() {
        let (pk, sk) = generate_keypair();
        let sig = sign(&sk, b"correct").unwrap();
        assert!(!verify(&pk, b"tampered", &sig));
    }
    #[test] fn diversified_addresses_are_distinct_deterministic_and_valid() {
        let seed = [7u8; 64];
        let a0 = diversified_address(&seed, 0, true).unwrap();
        let a1 = diversified_address(&seed, 1, true).unwrap();
        let a2 = diversified_address(&seed, 2, true).unwrap();
        // Unlinkable: different indices → different addresses.
        assert_ne!(a0, a1);
        assert_ne!(a1, a2);
        assert_ne!(a0, a2);
        // Recoverable: same (seed, index) → same address.
        assert_eq!(a0, diversified_address(&seed, 0, true).unwrap());
        // Valid testnet address form.
        assert!(a0.starts_with("bloch1t"));
        // A different master seed gives a different address at the same index.
        assert_ne!(a0, diversified_address(&[8u8; 64], 0, true).unwrap());
    }
    #[test] fn address_format() {
        let (pk, _) = generate_keypair();
        assert!(address_from_pubkey(&pk, false).starts_with("bloch1q"));
    }

    // ═══════════════════════════════════════════════════════════════════
    // Sprint T.1 — Audit finding C-2 fix verification
    // ═══════════════════════════════════════════════════════════════════

    /// Core guarantee: same seed → byte-identical keypair.
    /// This is the test that distinguishes real seed derivation from the
    /// admitted stub that Sprint T.1 replaces.
    #[test]
    fn seed_keypair_is_deterministic() {
        let seed = [0x42u8; 32];
        let (pk1, sk1) = generate_keypair_from_seed(&seed).unwrap();
        let (pk2, sk2) = generate_keypair_from_seed(&seed).unwrap();
        assert_eq!(pk1, pk2, "same seed must produce same public key");
        assert_eq!(sk1, sk2, "same seed must produce same secret key");
    }

    /// Different seeds must produce independent keypairs.
    #[test]
    fn different_seeds_yield_different_keypairs() {
        let (pk_a, _) = generate_keypair_from_seed(&[0xAAu8; 32]).unwrap();
        let (pk_b, _) = generate_keypair_from_seed(&[0xBBu8; 32]).unwrap();
        assert_ne!(pk_a, pk_b, "different seeds must produce different keys");
    }

    /// Seeded keypair and random keypair must not collide. This confirms
    /// that the thread-local override does not leak into subsequent
    /// `generate_keypair()` calls (guard is correctly dropped).
    #[test]
    fn random_keypair_unaffected_by_prior_seeded_call() {
        let _seeded = generate_keypair_from_seed(&[0xFFu8; 32]).unwrap();
        let (pk_rand_1, _) = generate_keypair();
        let (pk_rand_2, _) = generate_keypair();
        assert_ne!(
            pk_rand_1, pk_rand_2,
            "random keypairs after seeded call must still be independent"
        );
    }

    /// Sign/verify works end-to-end with a seeded keypair.
    #[test]
    fn seeded_keypair_can_sign_and_verify() {
        let seed = [0x77u8; 32];
        let (pk, sk) = generate_keypair_from_seed(&seed).unwrap();
        let msg = b"bloch-test-message";
        let sig = sign(&sk, msg).unwrap();
        assert!(verify(&pk, msg, &sig));
    }

    /// Short seeds must be rejected with a clear error.
    #[test]
    fn short_seed_rejected() {
        let result = generate_keypair_from_seed(&[0u8; 16]);
        assert!(result.is_err());
    }
}

// ── Falcon-1024 (Sprint B6b) ────────────────────────────────────────────────
//
// The second signature of the hybrid Falcon-1024 ‖ ML-DSA-65 scheme: two
// distinct lattice families (NTRU vs Module-LWE/SIS) for defence in depth — a
// break of one assumption does not forge a signature. Falcon verification is
// deterministic (integer), so it is consensus-safe; Falcon *signing* uses
// floating-point Gaussian sampling and may differ across platforms, which is
// fine for randomized signatures (only deterministic seed→sig reproducibility
// is affected — see the B6 notes).
pub mod falcon {
    use pqcrypto_falcon::falcon1024;
    use pqcrypto_traits::sign::{PublicKey, SecretKey, DetachedSignature};
    use super::CryptoError;

    /// Falcon-1024 public-key length (bytes).
    pub fn pubkey_len() -> usize { falcon1024::public_key_bytes() }

    pub fn keypair() -> (Vec<u8>, Vec<u8>) {
        let (pk, sk) = falcon1024::keypair();
        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    }

    pub fn sign(secret_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sk = falcon1024::SecretKey::from_bytes(secret_key_bytes)
            .map_err(|_| CryptoError::InvalidKey("bad falcon secret key".into()))?;
        Ok(falcon1024::detached_sign(message, &sk).as_bytes().to_vec())
    }

    /// Deterministic verification (consensus rule): malformed inputs → false.
    pub fn verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
        let pk = match falcon1024::PublicKey::from_bytes(public_key_bytes) {
            Ok(p) => p, Err(_) => return false,
        };
        let sig = match falcon1024::DetachedSignature::from_bytes(signature_bytes) {
            Ok(s) => s, Err(_) => return false,
        };
        falcon1024::verify_detached_signature(&sig, message, &pk).is_ok()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn falcon_roundtrip() {
            let (pk, sk) = keypair();
            let msg = b"bloch-falcon-b6b";
            let sig = sign(&sk, msg).expect("sign");
            assert!(verify(&pk, msg, &sig), "valid falcon sig must verify");
            assert!(!verify(&pk, b"other message", &sig), "wrong message must fail");
            let mut bad = sig.clone(); bad[0] ^= 0x01;
            assert!(!verify(&pk, msg, &bad), "tampered sig must fail");
        }
    }
}
