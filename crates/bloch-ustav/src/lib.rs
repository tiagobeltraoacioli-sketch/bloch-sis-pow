//! PQ-only cryptographic host for the Ustav v3 reference transition kernel.
//!
//! No permissive crypto defaults and no node activation. Only suite 0x0001
//! (ML-DSA-65 AND Falcon-1024) is admitted. Native custody uses PQ Governance
//! quorums. Classical wallet compatibility belongs to the separate bloch-l2-evm
//! repository; it supplies no native L1 Verifier implementation.
#![forbid(unsafe_code)]
pub use bloch_euvm::ustav::*;

#[cfg(feature = "native-dex-host")]
pub mod dex_admission;
#[cfg(feature = "native-dex-host")]
pub mod dex_journal;

use bloch_crypto::crypto;

/// Concrete verifier; signature generation remains in bloch-crypto / the wallet.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlochVerifier;

impl Verifier for BlochVerifier {
    fn valid_pq_key(&self, key: &[u8]) -> bool {
        crypto::valid_native_hybrid_key(key)
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
