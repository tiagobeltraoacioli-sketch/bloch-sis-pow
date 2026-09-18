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

use crate::{derive_vault_keys_versioned, VaultKeyDerivation};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// HKDF `info` prefix — domain separation for this construction / version.
pub const INFO_PREFIX: &[u8] = b"pq-shield/v1";
/// HKDF `salt` — a fixed domain tag (non-secret; HKDF is secure with a fixed salt).
pub const HKDF_SALT: &[u8] = b"bloch-pq-shield-vault/HKDF-salt/v1";
/// Length of the derived recovery secret `r`, in bytes (spec §7: ≥ 32).
pub const RECOVERY_SECRET_LEN: usize = 32;
/// Maximum caller context retained in a recovery record. This easily fits an
/// outpoint, UUID or application salt while bounding untrusted backup input.
pub const MAX_VAULT_ID_LEN: usize = 1024;

const RECOVERY_CONTEXT_MAGIC: &[u8; 8] = b"BPQRCTX\0";
const RECOVERY_CONTEXT_VERSION: u8 = 1;
const RECOVERY_CONTEXT_FIXED_LEN: usize = 8 + 1 + 1 + 1 + 1 + 2 + 32;
const SIGNED_RECOVERY_CONTEXT_MAGIC: &[u8; 8] = b"BPQRSGN\0";
const SIGNED_RECOVERY_CONTEXT_VERSION: u8 = 1;
const SIGNED_RECOVERY_CONTEXT_HEADER_LEN: usize = 8 + 1 + 1 + 2 + 2;
const SIGNED_RECOVERY_CONTEXT_DOMAIN: &[u8] = b"BLOCH-PQ-RECOVERY-CONTEXT-SIGNATURE-v1";
/// Defensive wire limit for an enveloped hybrid recovery-context signature.
pub const MAX_RECOVERY_CONTEXT_SIGNATURE_LEN: usize = 8192;

/// Refusals for the strict, public recovery-context record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryContextError {
    Malformed,
    UnsupportedVersion,
    UnknownKeyDerivation,
    UnknownNetwork,
    NonCanonicalReservedByte,
    EmptyVaultId,
    VaultIdTooLong,
    ZeroRecoveryHash,
    NetworkMismatch,
    RecoveryHashMismatch,
    KeyDerivationFailed,
    EmptySignature,
    SignatureTooLong,
    BadSignature,
}

impl std::fmt::Display for RecoveryContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed or trailing recovery-context bytes",
            Self::UnsupportedVersion => "unsupported recovery-context version",
            Self::UnknownKeyDerivation => "unknown vault key-derivation tag",
            Self::UnknownNetwork => "unknown recovery-context network tag",
            Self::NonCanonicalReservedByte => "recovery-context reserved byte must be zero",
            Self::EmptyVaultId => "vault ID must not be empty",
            Self::VaultIdTooLong => "vault ID exceeds the recovery-context limit",
            Self::ZeroRecoveryHash => "recovery hash must not be all zero",
            Self::NetworkMismatch => "recovery-context network does not match the funded vault",
            Self::RecoveryHashMismatch => "recovery context does not match the funded vault hash",
            Self::KeyDerivationFailed => "vault keys could not be derived from the supplied seed",
            Self::EmptySignature => "signed recovery context has an empty signature",
            Self::SignatureTooLong => "signed recovery-context signature exceeds the format limit",
            Self::BadSignature => "recovery-context signature is invalid for the trusted PQ key",
        })
    }
}

impl std::error::Error for RecoveryContextError {}

#[derive(Debug)]
pub enum RecoveryContextSignError {
    Crypto(bloch_crypto::crypto::CryptoError),
    EmptySignature,
    SignatureTooLong,
}

impl std::fmt::Display for RecoveryContextSignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Crypto(err) => write!(f, "could not sign recovery context: {err}"),
            Self::EmptySignature => f.write_str("recovery-context signer returned no bytes"),
            Self::SignatureTooLong => {
                f.write_str("recovery-context signer exceeded the format limit")
            }
        }
    }
}

impl std::error::Error for RecoveryContextSignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(err) => Some(err),
            _ => None,
        }
    }
}

/// Versioned public metadata needed to reproduce an existing V1 recovery
/// preimage without guessing its key family or free-form vault ID.
///
/// The record contains no secret. Its `recovery_hash` must still be compared
/// with an independently retained/funded vault commitment during restoration;
/// the record is not self-authenticating and is not a uniqueness registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryContextV1 {
    key_derivation: VaultKeyDerivation,
    mainnet: bool,
    vault_id: Vec<u8>,
    recovery_hash: [u8; 32],
}

/// Canonically framed, PQ-authenticated recovery metadata.
///
/// The trusted public key is deliberately absent from this object: accepting a
/// key carried by the backup would make the signature self-certifying. The
/// restoring party must obtain the vault owner's PQ public key independently
/// and pass it to [`Self::verify`]. This authenticates the metadata bytes; it
/// does not prove freshness, uniqueness, non-reuse or on-chain PQ possession.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRecoveryContextV1 {
    context: RecoveryContextV1,
    signature: Vec<u8>,
}

impl SignedRecoveryContextV1 {
    pub fn context(&self) -> &RecoveryContextV1 {
        &self.context
    }
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    fn signing_bytes(context: &RecoveryContextV1) -> Vec<u8> {
        let encoded = context.encode();
        let mut out = Vec::with_capacity(SIGNED_RECOVERY_CONTEXT_DOMAIN.len() + 8 + encoded.len());
        out.extend_from_slice(SIGNED_RECOVERY_CONTEXT_DOMAIN);
        out.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
        out.extend_from_slice(&encoded);
        out
    }

    /// Sign the exact canonical recovery-context bytes under a distinct domain.
    pub fn sign(
        context: &RecoveryContextV1,
        pq_secret: &[u8],
    ) -> Result<Self, RecoveryContextSignError> {
        let signature = bloch_crypto::crypto::sign(pq_secret, &Self::signing_bytes(context))
            .map_err(RecoveryContextSignError::Crypto)?;
        if signature.is_empty() {
            return Err(RecoveryContextSignError::EmptySignature);
        }
        if signature.len() > MAX_RECOVERY_CONTEXT_SIGNATURE_LEN {
            return Err(RecoveryContextSignError::SignatureTooLong);
        }
        Ok(Self {
            context: context.clone(),
            signature,
        })
    }

    /// Verify under a public key supplied independently of the backup record.
    pub fn verify(&self, trusted_pq_pubkey: &[u8]) -> Result<(), RecoveryContextError> {
        if bloch_crypto::crypto::verify(
            trusted_pq_pubkey,
            &Self::signing_bytes(&self.context),
            &self.signature,
        ) {
            Ok(())
        } else {
            Err(RecoveryContextError::BadSignature)
        }
    }

    /// Fail-closed restoration path: authenticate the metadata before using
    /// any of its derivation selectors, then apply the funded hash/network
    /// checks performed by [`RecoveryContextV1::restore`].
    pub fn verify_and_restore(
        &self,
        trusted_pq_pubkey: &[u8],
        seed: &[u8],
        expected_mainnet: bool,
        funded_recovery_hash: &[u8; 32],
    ) -> Result<zeroize::Zeroizing<[u8; RECOVERY_SECRET_LEN]>, RecoveryContextError> {
        self.verify(trusted_pq_pubkey)?;
        self.context
            .restore(seed, expected_mainnet, funded_recovery_hash)
    }

    /// Strict bounded framing for the canonical context and its signature.
    pub fn encode(&self) -> Vec<u8> {
        let context = self.context.encode();
        let mut out = Vec::with_capacity(
            SIGNED_RECOVERY_CONTEXT_HEADER_LEN + context.len() + self.signature.len(),
        );
        out.extend_from_slice(SIGNED_RECOVERY_CONTEXT_MAGIC);
        out.push(SIGNED_RECOVERY_CONTEXT_VERSION);
        out.push(0); // reserved
        out.extend_from_slice(&(context.len() as u16).to_le_bytes());
        out.extend_from_slice(&(self.signature.len() as u16).to_le_bytes());
        out.extend_from_slice(&context);
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecoveryContextError> {
        if bytes.len() < SIGNED_RECOVERY_CONTEXT_HEADER_LEN
            || &bytes[..8] != SIGNED_RECOVERY_CONTEXT_MAGIC
        {
            return Err(RecoveryContextError::Malformed);
        }
        if bytes[8] != SIGNED_RECOVERY_CONTEXT_VERSION {
            return Err(RecoveryContextError::UnsupportedVersion);
        }
        if bytes[9] != 0 {
            return Err(RecoveryContextError::NonCanonicalReservedByte);
        }
        let context_len = u16::from_le_bytes([bytes[10], bytes[11]]) as usize;
        let signature_len = u16::from_le_bytes([bytes[12], bytes[13]]) as usize;
        if signature_len == 0 {
            return Err(RecoveryContextError::EmptySignature);
        }
        if signature_len > MAX_RECOVERY_CONTEXT_SIGNATURE_LEN {
            return Err(RecoveryContextError::SignatureTooLong);
        }
        let context_end = SIGNED_RECOVERY_CONTEXT_HEADER_LEN
            .checked_add(context_len)
            .ok_or(RecoveryContextError::Malformed)?;
        let expected_len = context_end
            .checked_add(signature_len)
            .ok_or(RecoveryContextError::Malformed)?;
        if bytes.len() != expected_len {
            return Err(RecoveryContextError::Malformed);
        }
        let context =
            RecoveryContextV1::decode(&bytes[SIGNED_RECOVERY_CONTEXT_HEADER_LEN..context_end])?;
        Ok(Self {
            context,
            signature: bytes[context_end..].to_vec(),
        })
    }
}

impl RecoveryContextV1 {
    pub fn new(
        key_derivation: VaultKeyDerivation,
        mainnet: bool,
        vault_id: &[u8],
        recovery_hash: [u8; 32],
    ) -> Result<Self, RecoveryContextError> {
        if vault_id.is_empty() {
            return Err(RecoveryContextError::EmptyVaultId);
        }
        if vault_id.len() > MAX_VAULT_ID_LEN {
            return Err(RecoveryContextError::VaultIdTooLong);
        }
        if recovery_hash == [0; 32] {
            return Err(RecoveryContextError::ZeroRecoveryHash);
        }
        Ok(Self {
            key_derivation,
            mainnet,
            vault_id: vault_id.to_vec(),
            recovery_hash,
        })
    }

    pub fn key_derivation(&self) -> VaultKeyDerivation {
        self.key_derivation
    }
    pub fn mainnet(&self) -> bool {
        self.mainnet
    }
    pub fn vault_id(&self) -> &[u8] {
        &self.vault_id
    }
    pub fn recovery_hash(&self) -> [u8; 32] {
        self.recovery_hash
    }

    /// Canonical public backup bytes. Unknown versions/tags, nonzero reserved
    /// fields, truncation and trailing data are rejected by [`Self::decode`].
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECOVERY_CONTEXT_FIXED_LEN + self.vault_id.len());
        out.extend_from_slice(RECOVERY_CONTEXT_MAGIC);
        out.push(RECOVERY_CONTEXT_VERSION);
        out.push(match self.key_derivation {
            VaultKeyDerivation::V1SharedReceiveChain => 1,
            VaultKeyDerivation::V2DedicatedHardenedBranch => 2,
            VaultKeyDerivation::V3HardenedRoles => 3,
        });
        out.push(u8::from(self.mainnet));
        out.push(0); // reserved for a future fail-closed format revision
        out.extend_from_slice(&(self.vault_id.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.recovery_hash);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecoveryContextError> {
        if bytes.len() < RECOVERY_CONTEXT_FIXED_LEN || &bytes[..8] != RECOVERY_CONTEXT_MAGIC {
            return Err(RecoveryContextError::Malformed);
        }
        if bytes[8] != RECOVERY_CONTEXT_VERSION {
            return Err(RecoveryContextError::UnsupportedVersion);
        }
        let key_derivation = match bytes[9] {
            1 => VaultKeyDerivation::V1SharedReceiveChain,
            2 => VaultKeyDerivation::V2DedicatedHardenedBranch,
            3 => VaultKeyDerivation::V3HardenedRoles,
            _ => return Err(RecoveryContextError::UnknownKeyDerivation),
        };
        let mainnet = match bytes[10] {
            0 => false,
            1 => true,
            _ => return Err(RecoveryContextError::UnknownNetwork),
        };
        if bytes[11] != 0 {
            return Err(RecoveryContextError::NonCanonicalReservedByte);
        }
        let vault_id_len = u16::from_le_bytes([bytes[12], bytes[13]]) as usize;
        if vault_id_len == 0 {
            return Err(RecoveryContextError::EmptyVaultId);
        }
        if vault_id_len > MAX_VAULT_ID_LEN {
            return Err(RecoveryContextError::VaultIdTooLong);
        }
        let expected_len = RECOVERY_CONTEXT_FIXED_LEN
            .checked_add(vault_id_len)
            .ok_or(RecoveryContextError::Malformed)?;
        if bytes.len() != expected_len {
            return Err(RecoveryContextError::Malformed);
        }
        let hash_start = 14 + vault_id_len;
        let mut recovery_hash = [0; 32];
        recovery_hash.copy_from_slice(&bytes[hash_start..hash_start + 32]);
        Self::new(
            key_derivation,
            mainnet,
            &bytes[14..hash_start],
            recovery_hash,
        )
    }

    /// Restore using the recorded V1/V2/V3 key family, then bind the result to
    /// the independently supplied network and funded `H(r)`. No version is
    /// guessed or tried in sequence.
    pub fn restore(
        &self,
        seed: &[u8],
        expected_mainnet: bool,
        funded_recovery_hash: &[u8; 32],
    ) -> Result<zeroize::Zeroizing<[u8; RECOVERY_SECRET_LEN]>, RecoveryContextError> {
        if self.mainnet != expected_mainnet {
            return Err(RecoveryContextError::NetworkMismatch);
        }
        if &self.recovery_hash != funded_recovery_hash {
            return Err(RecoveryContextError::RecoveryHashMismatch);
        }
        let keys = derive_vault_keys_versioned(seed, self.mainnet, self.key_derivation)
            .map_err(|_| RecoveryContextError::KeyDerivationFailed)?;
        restore_recovery_secret_v1(keys.pq_secret_key(), &self.vault_id, funded_recovery_hash)
            .map_err(|_| RecoveryContextError::RecoveryHashMismatch)
    }
}

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
    hk.expand(&info, &mut r)
        .expect("HKDF expand of 32 bytes is always within bounds");
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
    pq_sk: &[u8],
    vault_id: &[u8],
    expected_recovery_hash: &[u8; 32],
) -> Result<zeroize::Zeroizing<[u8; RECOVERY_SECRET_LEN]>, &'static str> {
    let secret = zeroize::Zeroizing::new(derive_recovery_secret(pq_sk, vault_id));
    if &recovery_hash(secret.as_ref()) != expected_recovery_hash {
        return Err(
            "recovery hash mismatch: check the original key, vault ID and derivation version",
        );
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
        assert_eq!(
            *restore_recovery_secret_v1(key, id, &expected).unwrap(),
            old_secret
        );
        assert!(restore_recovery_secret_v1(b"wrong-key", id, &expected).is_err());
        assert!(restore_recovery_secret_v1(key, b"reused-or-wrong-id", &expected).is_err());
        assert!(restore_recovery_secret_v1(key, id, &[0; 32]).is_err());
        // Restoration never substitutes a new derivation for historical inputs.
        let (old_secret, expected) = derive_recovery(&[], &[]);
        assert_eq!(
            *restore_recovery_secret_v1(&[], &[], &expected).unwrap(),
            old_secret
        );
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

    #[test]
    fn versioned_context_restores_all_existing_key_families_without_guessing() {
        let seed = [42u8; 32];
        let vault_id = b"vault-backup-context-17";
        for version in [
            VaultKeyDerivation::V1SharedReceiveChain,
            VaultKeyDerivation::V2DedicatedHardenedBranch,
            VaultKeyDerivation::V3HardenedRoles,
        ] {
            let keys = derive_vault_keys_versioned(&seed, false, version).unwrap();
            let (expected_secret, expected_hash) = derive_recovery(keys.pq_secret_key(), vault_id);
            let context = RecoveryContextV1::new(version, false, vault_id, expected_hash).unwrap();
            let decoded = RecoveryContextV1::decode(&context.encode()).unwrap();
            assert_eq!(decoded, context);
            assert_eq!(
                *decoded.restore(&seed, false, &expected_hash).unwrap(),
                expected_secret
            );
        }
    }

    #[test]
    fn context_restore_refuses_network_hash_and_metadata_substitution() {
        let seed = [43u8; 32];
        let vault_id = b"funded-vault-9";
        let keys =
            derive_vault_keys_versioned(&seed, false, VaultKeyDerivation::V1SharedReceiveChain)
                .unwrap();
        let (_, expected_hash) = derive_recovery(keys.pq_secret_key(), vault_id);
        let context = RecoveryContextV1::new(
            VaultKeyDerivation::V1SharedReceiveChain,
            false,
            vault_id,
            expected_hash,
        )
        .unwrap();

        assert_eq!(
            context.restore(&seed, true, &expected_hash).unwrap_err(),
            RecoveryContextError::NetworkMismatch,
        );
        assert_eq!(
            context.restore(&seed, false, &[7; 32]).unwrap_err(),
            RecoveryContextError::RecoveryHashMismatch,
        );
        assert_eq!(
            context.restore(&[1; 3], false, &expected_hash).unwrap_err(),
            RecoveryContextError::KeyDerivationFailed,
        );
        assert_eq!(
            context
                .restore(&[44; 32], false, &expected_hash)
                .unwrap_err(),
            RecoveryContextError::RecoveryHashMismatch,
        );

        let mut changed_id = context.encode();
        changed_id[14] ^= 1;
        let changed_id = RecoveryContextV1::decode(&changed_id).unwrap();
        assert_eq!(
            changed_id
                .restore(&seed, false, &expected_hash)
                .unwrap_err(),
            RecoveryContextError::RecoveryHashMismatch,
        );

        let mut changed_version = context.encode();
        changed_version[9] = 2;
        let changed_version = RecoveryContextV1::decode(&changed_version).unwrap();
        assert_eq!(
            changed_version
                .restore(&seed, false, &expected_hash)
                .unwrap_err(),
            RecoveryContextError::RecoveryHashMismatch,
        );
    }

    #[test]
    fn recovery_context_codec_is_bounded_strict_and_canonical() {
        let context = RecoveryContextV1::new(
            VaultKeyDerivation::V3HardenedRoles,
            true,
            b"unique-vault-salt",
            [9; 32],
        )
        .unwrap();
        let encoded = context.encode();
        for end in 0..encoded.len() {
            assert!(RecoveryContextV1::decode(&encoded[..end]).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            RecoveryContextV1::decode(&trailing),
            Err(RecoveryContextError::Malformed)
        );

        for (offset, value, expected) in [
            (8, 2, RecoveryContextError::UnsupportedVersion),
            (9, 0, RecoveryContextError::UnknownKeyDerivation),
            (10, 2, RecoveryContextError::UnknownNetwork),
            (11, 1, RecoveryContextError::NonCanonicalReservedByte),
        ] {
            let mut malformed = encoded.clone();
            malformed[offset] = value;
            assert_eq!(RecoveryContextV1::decode(&malformed), Err(expected));
        }
        let mut empty = encoded.clone();
        empty[12..14].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            RecoveryContextV1::decode(&empty),
            Err(RecoveryContextError::EmptyVaultId)
        );
        let mut oversized = encoded.clone();
        oversized[12..14].copy_from_slice(&((MAX_VAULT_ID_LEN + 1) as u16).to_le_bytes());
        assert_eq!(
            RecoveryContextV1::decode(&oversized),
            Err(RecoveryContextError::VaultIdTooLong)
        );
        assert_eq!(
            RecoveryContextV1::new(VaultKeyDerivation::V3HardenedRoles, false, b"", [1; 32],),
            Err(RecoveryContextError::EmptyVaultId),
        );
        assert_eq!(
            RecoveryContextV1::new(
                VaultKeyDerivation::V3HardenedRoles,
                false,
                &vec![1; MAX_VAULT_ID_LEN + 1],
                [1; 32],
            ),
            Err(RecoveryContextError::VaultIdTooLong),
        );
        assert_eq!(
            RecoveryContextV1::new(
                VaultKeyDerivation::V3HardenedRoles,
                false,
                b"vault",
                [0; 32],
            ),
            Err(RecoveryContextError::ZeroRecoveryHash),
        );
    }

    #[test]
    fn recovery_context_encoding_has_stable_golden_bytes() {
        let context = RecoveryContextV1::new(
            VaultKeyDerivation::V2DedicatedHardenedBranch,
            true,
            b"gold",
            [0xab; 32],
        )
        .unwrap();
        let expected = [
            0x42, 0x50, 0x51, 0x52, 0x43, 0x54, 0x58, 0x00, // BPQRCTX\0
            0x01, // recovery-context version
            0x02, // V2DedicatedHardenedBranch
            0x01, // mainnet
            0x00, // reserved
            0x04, 0x00, // little-endian vault-id length
            0x67, 0x6f, 0x6c, 0x64, // "gold"
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab,
        ];
        assert_eq!(context.encode(), expected);
        assert_eq!(RecoveryContextV1::decode(&expected).unwrap(), context);
    }

    #[test]
    fn recovery_context_round_trips_maximum_vault_id_on_mainnet() {
        let vault_id = vec![0x5a; MAX_VAULT_ID_LEN];
        let context = RecoveryContextV1::new(
            VaultKeyDerivation::V3HardenedRoles,
            true,
            &vault_id,
            [0x7c; 32],
        )
        .unwrap();
        let encoded = context.encode();
        assert_eq!(encoded.len(), RECOVERY_CONTEXT_FIXED_LEN + MAX_VAULT_ID_LEN);
        assert_eq!(RecoveryContextV1::decode(&encoded).unwrap(), context);
    }

    #[test]
    fn signed_context_authenticates_metadata_under_an_external_key() {
        let seed = [51u8; 32];
        let keys =
            derive_vault_keys_versioned(&seed, false, VaultKeyDerivation::V3HardenedRoles).unwrap();
        let (expected_secret, expected_hash) =
            derive_recovery(keys.pq_secret_key(), b"wave-51-vault");
        let context = RecoveryContextV1::new(
            VaultKeyDerivation::V3HardenedRoles,
            false,
            b"wave-51-vault",
            expected_hash,
        )
        .unwrap();
        let signed = SignedRecoveryContextV1::sign(&context, keys.pq_secret_key()).unwrap();
        let decoded = SignedRecoveryContextV1::decode(&signed.encode()).unwrap();
        assert_eq!(decoded, signed);
        assert_eq!(decoded.verify(&keys.pq_pubkey), Ok(()));
        assert_eq!(
            *decoded
                .verify_and_restore(&keys.pq_pubkey, &seed, false, &expected_hash)
                .unwrap(),
            expected_secret,
        );

        let other =
            derive_vault_keys_versioned(&[52u8; 32], false, VaultKeyDerivation::V3HardenedRoles)
                .unwrap();
        assert_eq!(
            decoded.verify(&other.pq_pubkey),
            Err(RecoveryContextError::BadSignature)
        );

        let mut bad_signature = decoded.clone();
        let last = bad_signature.signature.len() - 1;
        bad_signature.signature[last] ^= 1;
        assert_eq!(
            bad_signature.verify(&keys.pq_pubkey),
            Err(RecoveryContextError::BadSignature),
        );

        let substituted_context = RecoveryContextV1::new(
            VaultKeyDerivation::V2DedicatedHardenedBranch,
            false,
            b"wave-51-vault",
            expected_hash,
        )
        .unwrap();
        let substituted = SignedRecoveryContextV1 {
            context: substituted_context,
            signature: decoded.signature.clone(),
        };
        assert_eq!(
            substituted.verify(&keys.pq_pubkey),
            Err(RecoveryContextError::BadSignature),
        );
    }

    #[test]
    fn signed_context_codec_is_strict_bounded_and_canonical() {
        let context = RecoveryContextV1::new(
            VaultKeyDerivation::V1SharedReceiveChain,
            true,
            b"codec",
            [0x71; 32],
        )
        .unwrap();
        let signed = SignedRecoveryContextV1 {
            context,
            signature: vec![0xa5; 17],
        };
        let encoded = signed.encode();
        for end in 0..encoded.len() {
            assert!(SignedRecoveryContextV1::decode(&encoded[..end]).is_err());
        }
        assert_eq!(SignedRecoveryContextV1::decode(&encoded).unwrap(), signed);

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            SignedRecoveryContextV1::decode(&trailing),
            Err(RecoveryContextError::Malformed),
        );
        let mut wrong_version = encoded.clone();
        wrong_version[8] = 2;
        assert_eq!(
            SignedRecoveryContextV1::decode(&wrong_version),
            Err(RecoveryContextError::UnsupportedVersion),
        );
        let mut reserved = encoded.clone();
        reserved[9] = 1;
        assert_eq!(
            SignedRecoveryContextV1::decode(&reserved),
            Err(RecoveryContextError::NonCanonicalReservedByte),
        );
        let mut empty_signature = encoded.clone();
        empty_signature[12..14].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            SignedRecoveryContextV1::decode(&empty_signature),
            Err(RecoveryContextError::EmptySignature),
        );
        let mut oversized = encoded;
        oversized[12..14]
            .copy_from_slice(&((MAX_RECOVERY_CONTEXT_SIGNATURE_LEN + 1) as u16).to_le_bytes());
        assert_eq!(
            SignedRecoveryContextV1::decode(&oversized),
            Err(RecoveryContextError::SignatureTooLong),
        );
    }
}
