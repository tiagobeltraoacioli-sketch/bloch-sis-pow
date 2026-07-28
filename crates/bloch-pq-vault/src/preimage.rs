//! # preimage — the PQ-derived recovery secret `r` and its hash-lock `H(r)`
//!
//! The clawback branch of the vault (spec §2.1 branch B, and the deposit hash-gate
//! §2.1 `V`) is locked with `OP_SHA256 <H(r)> OP_EQUALVERIFY`. Bitcoin can only check
//! `SHA256(r) == H(r)`; it cannot verify a post-quantum signature. So the "PQ
//! authorization" of a clawback is made concrete by **deriving `r` from the owner's
//! post-quantum secret key**:
//!
//! ```text
//!   r    = HKDF-SHA256(ikm = pq_sk, salt = DOMAIN, info = "pq-shield/v1" ‖ vault_id)   (32 bytes)
//!   H(r) = SHA256(r)                                                                    (single SHA-256, == Bitcoin OP_SHA256)
//! ```
//!
//! Only the holder of `pq_sk` (the ML-DSA-65 ‖ Falcon-1024 secret from `bloch-crypto`)
//! can produce `r`. Its commitment `H(r)` is what the on-chain script and the Bloch
//! anchor share. *Ability to reveal `r` ⇒ possession of `pq_sk` at setup time* — that is
//! the "preimage bound to the PQ key" (spec §2.3).
//!
//! ## Honest limit (repeated from the spec §2.2)
//! Once `r` is revealed on-chain (in the unvault or clawback witness), it is public;
//! from that point the safety of branch B rests on `recovery_pubkey` not being
//! CRQC-derivable in time and on the watchtower winning the fee race — NOT on `r`
//! staying secret. `r` is single-use.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// HKDF `info` prefix — domain separation for this construction / version.
pub const INFO_PREFIX: &[u8] = b"pq-shield/v1";
/// HKDF `salt` — a fixed domain tag (non-secret; HKDF is secure with a fixed salt).
pub const HKDF_SALT: &[u8] = b"bloch-pq-shield-vault/HKDF-salt/v1";
/// Length of the derived recovery secret `r`, in bytes (spec §7: ≥ 32).
pub const RECOVERY_SECRET_LEN: usize = 32;

/// Derive the recovery secret `r = HKDF-SHA256(pq_sk, "pq-shield/v1" ‖ vault_id)`.
///
/// Deterministic: the same `pq_sk` and `vault_id` always yield the same `r`, and only
/// the holder of `pq_sk` can compute it. `vault_id` is any per-vault domain separator
/// (e.g. the deposit outpoint, a UUID, or a monotonically increasing index) so one PQ
/// key can guard many independent vaults with independent preimages.
pub fn derive_recovery_secret(pq_sk: &[u8], vault_id: &[u8]) -> [u8; RECOVERY_SECRET_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), pq_sk);
    let mut info = Vec::with_capacity(INFO_PREFIX.len() + vault_id.len());
    info.extend_from_slice(INFO_PREFIX);
    info.extend_from_slice(vault_id);
    let mut r = [0u8; RECOVERY_SECRET_LEN];
    // HKDF-Expand of 32 bytes never exceeds the 255*HashLen ceiling, so this cannot fail.
    hk.expand(&info, &mut r).expect("HKDF expand of 32 bytes is always within bounds");
    r
}

/// `H(r) = SHA256(r)` — a **single** SHA-256, matching Bitcoin's `OP_SHA256` (NOT the
/// double-SHA256 `Sha256d` the eUTXO VM / validator hashing uses). This is the value
/// embedded in the vault's hash-lock and the Bloch anchor's `recovery_hash`.
pub fn recovery_hash(r: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(r));
    out
}

/// Convenience: derive `r` and return `(r, H(r))` in one call.
pub fn derive_recovery(pq_sk: &[u8], vault_id: &[u8]) -> ([u8; RECOVERY_SECRET_LEN], [u8; 32]) {
    let r = derive_recovery_secret(pq_sk, vault_id);
    let h = recovery_hash(&r);
    (r, h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_key_bound() {
        let sk = b"a-fake-pq-secret-key-material-32b!!";
        let (r1, h1) = derive_recovery(sk, b"vault-1");
        let (r2, h2) = derive_recovery(sk, b"vault-1");
        assert_eq!(r1, r2, "same key+id must give same r");
        assert_eq!(h1, h2);
        assert_eq!(r1.len(), 32);
        // H(r) is single SHA-256 of r
        assert_eq!(h1, recovery_hash(&r1));

        // different vault_id → different r (independent per-vault preimages)
        let (r3, _) = derive_recovery(sk, b"vault-2");
        assert_ne!(r1, r3);

        // different key → different r (only the pq_sk holder can produce r)
        let (r4, _) = derive_recovery(b"a-DIFFERENT-pq-secret-key-material", b"vault-1");
        assert_ne!(r1, r4);
    }
}
