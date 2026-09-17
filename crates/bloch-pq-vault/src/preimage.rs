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
//! A client holding `pq_sk` can deterministically derive `r`. Its commitment
//! `H(r)` is shared by the script and anchor. Possession of `r` is NOT proof of
//! possessing the PQ key: it can be copied, delegated or revealed on-chain.
//! Bitcoin checks a hash preimage and classical signature, not PQ-key ownership.
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
/// Deterministic: the same `pq_sk` and `vault_id` always yield the same `r`.
/// Anyone given that preimage can reuse it; this function tracks no lifecycle. `vault_id` is any per-vault domain separator
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

/// Restore the EXISTING V1 preimage and check it against the funded vault's
/// independently retained recovery hash before returning it. This preserves
/// the original HKDF bytes exactly; the `_v1` suffix selects that existing
/// derivation explicitly. A wrong key, vault ID or expected hash returns an
/// error rather than a different apparently usable recovery secret.
///
/// Store the original vault ID, V1 derivation label and recovery hash in the
/// backup. This check establishes a matching hash preimage, not freshness,
/// single-use, key erasure, PQ-key ownership or authenticity of backup metadata.
/// Legacy weak/empty input material is not silently re-derived under a new rule.
pub fn restore_recovery_secret_v1(
    pq_sk: &[u8], vault_id: &[u8], expected_recovery_hash: &[u8; 32],
) -> Result<zeroize::Zeroizing<[u8; RECOVERY_SECRET_LEN]>, &'static str> {
    let secret = zeroize::Zeroizing::new(derive_recovery_secret(pq_sk, vault_id));
    if &recovery_hash(secret.as_ref()) != expected_recovery_hash {
        return Err("recovery hash mismatch: check the original key, vault ID and derivation version");
    }
    Ok(secret)
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
    fn checked_restore_preserves_v1_and_refuses_context_mismatch() {
        let key = b"synthetic recovery material for regression only";
        let id = b"original-vault-id";
        let (old_secret, expected) = derive_recovery(key, id);
        assert_eq!(*restore_recovery_secret_v1(key, id, &expected).unwrap(), old_secret);
        assert!(restore_recovery_secret_v1(b"wrong-key", id, &expected).is_err());
        assert!(restore_recovery_secret_v1(key, b"reused-or-wrong-id", &expected).is_err());
        assert!(restore_recovery_secret_v1(key, id, &[0;32]).is_err());
        // Restoration never substitutes a new derivation for historical inputs.
        let (old_secret, expected) = derive_recovery(&[], &[]);
        assert_eq!(*restore_recovery_secret_v1(&[], &[], &expected).unwrap(), old_secret);
    }

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
