//! PQ-only cryptographic host for the Ustav v3 reference transition kernel.
//!
//! No permissive crypto defaults and no node activation. Only suite 0x0001
//! (ML-DSA-65 AND Falcon-1024) is admitted. Native custody uses PQ Governance
//! quorums. Classical wallet compatibility belongs to the separate bloch-l2-evm
//! repository; it supplies no native L1 Verifier implementation.
#![forbid(unsafe_code)]
pub use bloch_euvm::ustav::*;

use bloch_crypto::crypto;

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

    fn verify_pq(&self, message: &[u8], key: &[u8], signature: &[u8]) -> bool {
        message.len() == 32
            && signature.len() <= MAX_SIGNATURE_BYTES
            && self.valid_pq_key(key)
            && crypto::split_envelope(signature)
                .is_some_and(|(suite, _)| suite == crypto::SUITE_MLDSA65_FALCON1024)
            && crypto::verify(key, message, signature)
    }
}
