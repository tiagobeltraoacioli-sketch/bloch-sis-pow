//! Bloch cryptographic host for the Ustav v2 reference transition kernel.
//!
//! No permissive crypto defaults and no node activation. Only suite 0x0001
//! (ML-DSA-65 AND Falcon-1024) is admitted. Custody uses compressed secp256k1
//! public keys and compact, low-S ECDSA signatures over the 32-byte signing hash.
//! This does not validate a Bitcoin deposit or constitute a BTC bridge.
pub use bloch_euvm::ustav::*;

use bloch_crypto::crypto;
use bloch_euvm::SigVerifier;
use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

/// Concrete verifier; signature generation remains in bloch-crypto / the wallet.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlochVerifier;

// Encoding pinned by bloch-crypto's pqcrypto-falcon =0.4.1 dependency and KATs.
const FALCON_PUBLIC_KEY_BYTES: usize = 1793;

impl Verifier for BlochVerifier {
    fn valid_pq_key(&self, key: &[u8]) -> bool {
        let Some((suite, body)) = crypto::split_envelope(key) else {
            return false;
        };
        if suite != crypto::SUITE_MLDSA65_FALCON1024
            || body.len() != crypto::MLDSA_PUBKEY_LEN + FALCON_PUBLIC_KEY_BYTES
        {
            return false;
        }
        // ML-DSA-65's rho + packed 10-bit t1 has no invalid bit patterns. Falcon
        // public keys do: logn header 10 and 1024 big-endian 14-bit coefficients
        // strictly below q=12289 (PQClean falcon-1024/clean/codec.c modq_decode).
        // Length-only PQClean Rust wrappers do not perform this admission check.
        let falcon = &body[crypto::MLDSA_PUBKEY_LEN..];
        if falcon[0] != 10 {
            return false;
        }
        falcon[1..].chunks_exact(7).all(|chunk| {
            let mut bytes = [0u8; 8];
            bytes[1..].copy_from_slice(chunk);
            let packed = u64::from_be_bytes(bytes);
            [42, 28, 14, 0]
                .into_iter()
                .all(|shift| ((packed >> shift) & 0x3fff) < 12_289)
        })
    }

    fn valid_ecdsa_key(&self, key: &[u8]) -> bool {
        key.len() == 33 && matches!(key[0], 2 | 3) && VerifyingKey::from_sec1_bytes(key).is_ok()
    }
}

impl SigVerifier for BlochVerifier {
    fn verify(&self, message: &[u8], key: &[u8], signature: &[u8]) -> bool {
        message.len() == 32
            && signature.len() <= MAX_SIGNATURE_BYTES
            && self.valid_pq_key(key)
            && crypto::split_envelope(signature)
                .is_some_and(|(suite, _)| suite == crypto::SUITE_MLDSA65_FALCON1024)
            && crypto::verify(key, message, signature)
    }

    fn verify_ecdsa(&self, message: &[u8], key: &[u8], signature: &[u8]) -> bool {
        if message.len() != 32 || signature.len() != 64 || !self.valid_ecdsa_key(key) {
            return false;
        }
        let Ok(key) = VerifyingKey::from_sec1_bytes(key) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(signature) else {
            return false;
        };
        // Canonical signatures: accepting both s and -s admits a second encoding.
        signature.normalize_s().is_none() && key.verify_prehash(message, &signature).is_ok()
    }
}
