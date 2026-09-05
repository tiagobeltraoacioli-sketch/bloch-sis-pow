//! # anchor — the Bloch PQ registry record (`PqShieldAnchor`) and its guard
//!
//! The part Bitcoin structurally cannot do (spec §3): a publicly-auditable record,
//! **signed with the owner's post-quantum key** (ML-DSA-65 ‖ Falcon-1024 via
//! `bloch-crypto`), binding
//! `{btc_vault_address, H(r), pq_recovery_pubkey, designated_safe_destination, policy}`.
//!
//! **Division of labour (spec §2.3):** Bitcoin enforces the hash + timelock half; Bloch
//! enforces the PQ half; the shared `recovery_hash = H(r)` and `designated_safe_dest`
//! are the hinge. Bitcoin never sees a PQ signature — so revealing `r` on Bitcoin is not
//! by itself a proof of PQ authorization. This anchor is what makes the *legitimate*
//! recovery flow PQ-authorized and auditable; a compliant watchtower fee-bumps a
//! clawback **only** to the anchored `designated_safe_dest`.
//!
//! ## Mapping onto `bloch-euvm` (spec §3.2)
//! The anchor is an ordinary Bloch eUTXO whose *datum* carries these fields and whose
//! *guard program* is the existing, audited-compiler custody/governance validator — no
//! new opcode, no new module kind. [`anchor_guard_governance`] emits a `Governance`
//! 1-of-1 over the PQ key (minimum); [`anchor_guard_custody`] emits the `Custody` 2-of-2
//! (BTC key AND PQ key — the same hybrid identity that owns the BTC vault owns its
//! anchor), reusing `bloch_btc_wallet::hybrid_wbtc_validator`.
//!
//! ## Honest limit (inherited, spec §3 note)
//! `bloch-euvm`'s `modules.rs` is itself FOUNDATION / unaudited / NOT consensus-wired.
//! The anchor design assumes a real PQ verifier and datum serialization are wired in the
//! Integrate phase. Designed ≠ built ≠ booted.

use bloch_euvm::modules::{
    compile_charter, GovernanceConfig, ModuleKind, TokenCharter,
};
use bloch_euvm::Op;

/// Domain tag for the anchor commitment preimage (domain separation).
const ANCHOR_DOMAIN: &[u8] = b"BLOCH-PQ-SHIELD-ANCHOR-v1";
/// Current anchor format version.
pub const ANCHOR_VERSION: u16 = 1;

/// Which native chain the guarded coin lives on (spec §3.1 `target_chain`). The anchor
/// is chain-agnostic; only this tag and the address bytes change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetChain {
    Bitcoin,
    Litecoin,
    BitcoinCash,
    Dogecoin,
    EthereumL1,
}

impl TargetChain {
    /// A stable 1-byte tag folded into the signed commitment.
    fn tag(self) -> u8 {
        match self {
            TargetChain::Bitcoin => 0x01,
            TargetChain::Litecoin => 0x02,
            TargetChain::BitcoinCash => 0x03,
            TargetChain::Dogecoin => 0x04,
            TargetChain::EthereumL1 => 0x05,
        }
    }
}

/// The `PqShieldAnchor` datum (spec §3.1) — the committed, PQ-signed vault record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqShieldAnchor {
    /// Format version (= [`ANCHOR_VERSION`]).
    pub version: u16,
    /// The native chain the vault protects.
    pub target_chain: TargetChain,
    /// The vault deposit address `V` (bytes of its string form, e.g. `bc1q…`).
    pub btc_vault_address: Vec<u8>,
    /// `H(r) = SHA256(HKDF(pq_sk, …))` — the shared hash-lock.
    pub recovery_hash: [u8; 32],
    /// The owner's enveloped ML-DSA-65 ‖ Falcon-1024 public key (the PQ recovery key).
    pub pq_recovery_pubkey: Vec<u8>,
    /// The ONLY address the anchored clawback flow may target (a fresh, hidden-pubkey
    /// address — spec §9.4).
    pub designated_safe_dest: Vec<u8>,
    /// Δ in blocks — MUST equal the on-chain branch-A CSV delay (spec §3.1). `u16`
    /// because that is the width Bitcoin's `Sequence::from_height` (and therefore
    /// [`crate::vault::VaultParams::csv_delay`]) actually enforces: keeping this wider
    /// than the chain let an anchor advertise a Δ that silently truncated to a
    /// *different* on-chain Δ under `as u16`. The wire encoding stays 4 bytes LE (see
    /// [`PqShieldAnchor::commitment_bytes`]) so the signed format is unchanged.
    pub csv_delay: u16,
    /// Opaque watchtower policy id / rotation rules / expiry.
    pub policy: Vec<u8>,
}

impl PqShieldAnchor {
    /// Deterministic serialization of the **committed fields** (everything the PQ
    /// signature covers). Length-prefixed (`u32` LE) byte fields; scalars LE. A change in
    /// any field changes these bytes and therefore invalidates the signature.
    pub fn commitment_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(ANCHOR_DOMAIN);
        b.extend_from_slice(&self.version.to_le_bytes());
        b.push(self.target_chain.tag());
        put_bytes(&mut b, &self.btc_vault_address);
        b.extend_from_slice(&self.recovery_hash);
        put_bytes(&mut b, &self.pq_recovery_pubkey);
        put_bytes(&mut b, &self.designated_safe_dest);
        b.extend_from_slice(&(self.csv_delay as u32).to_le_bytes());
        put_bytes(&mut b, &self.policy);
        b
    }

    /// Full deterministic serialization of a SIGNED anchor: the committed bytes followed
    /// by the length-prefixed signature. Round-trips with [`SignedAnchor::deserialize`].
    fn serialize_with_sig(&self, signature: &[u8]) -> Vec<u8> {
        let mut b = self.commitment_bytes();
        put_bytes(&mut b, signature);
        b
    }
}

/// A `PqShieldAnchor` together with the owner's PQ signature over its committed fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAnchor {
    pub anchor: PqShieldAnchor,
    /// ML-DSA-65 ‖ Falcon-1024 signature (enveloped) over [`PqShieldAnchor::commitment_bytes`].
    pub signature: Vec<u8>,
}

/// Errors from anchor (de)serialization / verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorError {
    /// The PQ signature did not verify under the caller's trusted key.
    BadSignature,
    /// The anchor names a `pq_recovery_pubkey` that is NOT the key the relying party
    /// trusts. This is the check that stops a self-certifying forgery: an attacker can
    /// always mint a syntactically perfect anchor signed by their *own* PQ key.
    UntrustedKey,
    /// `version` is not a format this build understands.
    UnsupportedVersion(u16),
    /// `csv_delay` does not fit the on-chain (`u16`) CSV width, so it could never equal
    /// the branch-A delay it claims to mirror.
    CsvDelayOutOfRange(u32),
    /// Truncated / malformed serialized anchor.
    Malformed,
    /// Unknown `target_chain` tag on deserialize.
    UnknownChain(u8),
}

/// Sign a `PqShieldAnchor` with the owner's PQ secret key (ML-DSA-65 ‖ Falcon-1024).
/// The `pq_secret` MUST correspond to `anchor.pq_recovery_pubkey`; [`verify_anchor`]
/// enforces that binding — against an *externally trusted* key — at verification time.
pub fn sign_anchor(
    anchor: &PqShieldAnchor,
    pq_secret: &[u8],
) -> Result<SignedAnchor, bloch_crypto::crypto::CryptoError> {
    let sig = bloch_crypto::crypto::sign(pq_secret, &anchor.commitment_bytes())?;
    Ok(SignedAnchor { anchor: anchor.clone(), signature: sig })
}

/// Verify a signed anchor **against a PQ key the relying party already trusts**.
///
/// `trusted_pq_pubkey` is the enveloped ML-DSA-65 ‖ Falcon-1024 public key the caller
/// obtained out-of-band — from the vault registration, the anchor guard hash
/// ([`anchor_guard_governance`] / [`anchor_guard_custody`], which commit to it), or a
/// previously-trusted anchor. It is NOT read out of the blob under inspection.
///
/// ## Why the key must come from outside (spec §3, and the reason this exists)
/// Verifying under `signed.anchor.pq_recovery_pubkey` is *self-certifying* and decides
/// nothing: anyone can generate a PQ keypair, write their own `designated_safe_dest`
/// into an anchor, sign it with their own secret, and publish a blob that "verifies".
/// A watchtower that fee-bumps a clawback to that destination would be paying an
/// attacker. Authenticity here means "signed by **the** owner", so the owner's identity
/// has to be an input, not a self-declaration.
///
/// Returns `Ok(())` iff the anchor is a supported version, names exactly
/// `trusted_pq_pubkey`, and carries a valid PQ signature over its committed fields.
/// Tampering with ANY committed field (address, `H(r)`, safe destination, Δ, policy, …)
/// changes [`PqShieldAnchor::commitment_bytes`] and makes this fail closed.
pub fn verify_anchor(
    signed: &SignedAnchor,
    trusted_pq_pubkey: &[u8],
) -> Result<(), AnchorError> {
    if signed.anchor.version != ANCHOR_VERSION {
        return Err(AnchorError::UnsupportedVersion(signed.anchor.version));
    }
    // The hinge: identity is supplied by the verifier, never by the blob.
    if signed.anchor.pq_recovery_pubkey.as_slice() != trusted_pq_pubkey {
        return Err(AnchorError::UntrustedKey);
    }
    // Verify under the caller's copy, so the anchor's own bytes cannot steer the check.
    let ok = bloch_crypto::crypto::verify(
        trusted_pq_pubkey,
        &signed.anchor.commitment_bytes(),
        &signed.signature,
    );
    if ok {
        Ok(())
    } else {
        Err(AnchorError::BadSignature)
    }
}

impl SignedAnchor {
    /// Deterministic full serialization (committed fields ‖ signature).
    pub fn serialize(&self) -> Vec<u8> {
        self.anchor.serialize_with_sig(&self.signature)
    }

    /// Inverse of [`SignedAnchor::serialize`]. Validates the *format* only — version,
    /// chain tag, Δ width, framing — and does NOT verify the signature or decide who
    /// owns the anchor; call [`verify_anchor`] with a trusted key after.
    pub fn deserialize(bytes: &[u8]) -> Result<SignedAnchor, AnchorError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.expect_tag(ANCHOR_DOMAIN)?;
        let version = c.get_u16()?;
        if version != ANCHOR_VERSION {
            return Err(AnchorError::UnsupportedVersion(version));
        }
        let chain_tag = c.get_u8()?;
        let target_chain = match chain_tag {
            0x01 => TargetChain::Bitcoin,
            0x02 => TargetChain::Litecoin,
            0x03 => TargetChain::BitcoinCash,
            0x04 => TargetChain::Dogecoin,
            0x05 => TargetChain::EthereumL1,
            other => return Err(AnchorError::UnknownChain(other)),
        };
        let btc_vault_address = c.get_bytes()?;
        let recovery_hash = c.get_array32()?;
        let pq_recovery_pubkey = c.get_bytes()?;
        let designated_safe_dest = c.get_bytes()?;
        // 4 bytes on the wire (format-stable), but only a value the chain could actually
        // enforce is accepted — a wider Δ is rejected, not silently truncated.
        let wide_delay = c.get_u32()?;
        let csv_delay = u16::try_from(wide_delay)
            .map_err(|_| AnchorError::CsvDelayOutOfRange(wide_delay))?;
        let policy = c.get_bytes()?;
        let signature = c.get_bytes()?;
        Ok(SignedAnchor {
            anchor: PqShieldAnchor {
                version,
                target_chain,
                btc_vault_address,
                recovery_hash,
                pq_recovery_pubkey,
                designated_safe_dest,
                csv_delay,
                policy,
            },
            signature,
        })
    }
}

// ── euvm guard programs (spec §3.2) ──────────────────────────────────────────────────

/// The anchor guard as a `Governance` 1-of-1 over the PQ recovery key (spec §3.2
/// minimum): only a valid ML-DSA‖Falcon signature updates/rotates the anchor. Returns
/// the concrete eUTXO validator program (its `bloch_euvm::validator_hash` addresses the
/// guarded output).
pub fn anchor_guard_governance(pq_recovery_pubkey: &[u8]) -> Vec<Op> {
    let ct = compile_charter(&TokenCharter {
        token_name: b"PQ-SHIELD-ANCHOR".to_vec(),
        modules: vec![ModuleKind::Governance(GovernanceConfig {
            signers: vec![pq_recovery_pubkey.to_vec()],
            threshold: 1,
        })],
    });
    ct.validators[0].program.clone()
}

/// The anchor guard as the `Custody` 2-of-2 (BTC key AND PQ key), recommended for high
/// value (spec §3.2 / §7): the same hybrid identity that owns the BTC vault owns its
/// anchor. Reuses `bloch_btc_wallet::hybrid_wbtc_validator`.
pub fn anchor_guard_custody(btc_pubkey: &[u8], pq_recovery_pubkey: &[u8]) -> Vec<Op> {
    bloch_btc_wallet::hybrid_wbtc_validator(btc_pubkey, pq_recovery_pubkey)
}

// ── tiny deterministic codec helpers ─────────────────────────────────────────────────

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}
impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], AnchorError> {
        let end = self.i.checked_add(n).ok_or(AnchorError::Malformed)?;
        if end > self.b.len() {
            return Err(AnchorError::Malformed);
        }
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }
    fn expect_tag(&mut self, tag: &[u8]) -> Result<(), AnchorError> {
        let s = self.take(tag.len())?;
        if s == tag {
            Ok(())
        } else {
            Err(AnchorError::Malformed)
        }
    }
    fn get_u8(&mut self) -> Result<u8, AnchorError> {
        Ok(self.take(1)?[0])
    }
    fn get_u16(&mut self) -> Result<u16, AnchorError> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    fn get_u32(&mut self) -> Result<u32, AnchorError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn get_array32(&mut self) -> Result<[u8; 32], AnchorError> {
        let s = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        Ok(a)
    }
    fn get_bytes(&mut self) -> Result<Vec<u8>, AnchorError> {
        let n = self.get_u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(pq_pubkey: Vec<u8>) -> PqShieldAnchor {
        PqShieldAnchor {
            version: ANCHOR_VERSION,
            target_chain: TargetChain::Bitcoin,
            btc_vault_address: b"bcrt1qexampledepositaddress".to_vec(),
            recovery_hash: [0x5a; 32],
            pq_recovery_pubkey: pq_pubkey,
            designated_safe_dest: b"bcrt1qsafecolddestination".to_vec(),
            csv_delay: 144,
            policy: b"watchtower-policy-01".to_vec(),
        }
    }

    #[test]
    fn sign_verify_roundtrip_and_tamper_fails() {
        let seed = [7u8; 32];
        let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&seed).unwrap();
        let anchor = sample(pk.clone());

        let signed = sign_anchor(&anchor, &sk).unwrap();
        assert!(verify_anchor(&signed, &pk).is_ok(), "honest anchor must verify");

        // tamper the safe destination → verify fails closed
        let mut t1 = signed.clone();
        t1.anchor.designated_safe_dest = b"bcrt1qATTACKERdestination".to_vec();
        assert_eq!(verify_anchor(&t1, &pk), Err(AnchorError::BadSignature));

        // tamper H(r) → fails
        let mut t2 = signed.clone();
        t2.anchor.recovery_hash = [0xff; 32];
        assert_eq!(verify_anchor(&t2, &pk), Err(AnchorError::BadSignature));

        // tamper Δ → fails
        let mut t3 = signed.clone();
        t3.anchor.csv_delay = 6;
        assert_eq!(verify_anchor(&t3, &pk), Err(AnchorError::BadSignature));
    }

    /// REGRESSION (K-M6-anchor-selfcert). The attacker holds no part of the owner's PQ
    /// key. They mint a *perfectly signed* anchor under their own key, naming their own
    /// `designated_safe_dest` — the address a compliant watchtower would fee-bump a
    /// clawback to. Under the old self-certifying `verify_anchor(&signed)` this returned
    /// `Ok(())`, because the blob supplied both the claim and the key that judged it.
    #[test]
    fn forged_anchor_signed_by_attacker_key_is_rejected() {
        let (owner_pk, owner_sk) =
            bloch_crypto::crypto::generate_keypair_from_seed(&[11u8; 32]).unwrap();
        let (attacker_pk, attacker_sk) =
            bloch_crypto::crypto::generate_keypair_from_seed(&[66u8; 32]).unwrap();
        assert_ne!(owner_pk, attacker_pk);

        // The honest anchor the world trusts, and the key it is trusted by.
        let honest = sign_anchor(&sample(owner_pk.clone()), &owner_sk).unwrap();
        assert!(verify_anchor(&honest, &owner_pk).is_ok());

        // The forgery: same vault, same H(r) — but the attacker's payout address and the
        // attacker's PQ key. It is internally consistent and self-verifies perfectly.
        let mut forged_anchor = sample(attacker_pk.clone());
        forged_anchor.designated_safe_dest = b"bcrt1qATTACKERpayoutaddress".to_vec();
        let forged = sign_anchor(&forged_anchor, &attacker_sk).unwrap();
        assert!(
            bloch_crypto::crypto::verify(
                &forged.anchor.pq_recovery_pubkey,
                &forged.anchor.commitment_bytes(),
                &forged.signature,
            ),
            "the forgery IS self-consistent — that is exactly why self-certification fails"
        );

        // Against the key the relying party actually trusts, it fails closed.
        assert_eq!(verify_anchor(&forged, &owner_pk), Err(AnchorError::UntrustedKey));

        // …and it survives a serialize round-trip as a forgery, not as an anchor.
        let back = SignedAnchor::deserialize(&forged.serialize()).unwrap();
        assert_eq!(verify_anchor(&back, &owner_pk), Err(AnchorError::UntrustedKey));

        // The owner's real anchor is not verifiable under the attacker's key either.
        assert_eq!(verify_anchor(&honest, &attacker_pk), Err(AnchorError::UntrustedKey));
    }

    /// A signature lifted from the owner's honest anchor cannot be replayed onto a
    /// different anchor that still names the owner's key.
    #[test]
    fn owner_key_with_transplanted_signature_is_rejected() {
        let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&[12u8; 32]).unwrap();
        let honest = sign_anchor(&sample(pk.clone()), &sk).unwrap();

        let mut swapped = sample(pk.clone());
        swapped.designated_safe_dest = b"bcrt1qATTACKERpayoutaddress".to_vec();
        let replay = SignedAnchor { anchor: swapped, signature: honest.signature.clone() };
        assert_eq!(verify_anchor(&replay, &pk), Err(AnchorError::BadSignature));
    }

    #[test]
    fn unsupported_version_is_rejected_on_verify_and_deserialize() {
        let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&[13u8; 32]).unwrap();
        let mut a = sample(pk.clone());
        a.version = ANCHOR_VERSION + 1;
        // Signed honestly under a future version this build cannot interpret.
        let signed = sign_anchor(&a, &sk).unwrap();
        assert_eq!(
            verify_anchor(&signed, &pk),
            Err(AnchorError::UnsupportedVersion(ANCHOR_VERSION + 1)),
            "version must be honored, not merely carried"
        );
        assert_eq!(
            SignedAnchor::deserialize(&signed.serialize()),
            Err(AnchorError::UnsupportedVersion(ANCHOR_VERSION + 1))
        );
    }

    /// Δ is `u16` on the wire-decode path because that is what Bitcoin's CSV enforces.
    /// A wider value must be REJECTED, never truncated into a different on-chain delay.
    #[test]
    fn oversized_csv_delay_is_rejected_not_truncated() {
        let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&[14u8; 32]).unwrap();
        let signed = sign_anchor(&sample(pk), &sk).unwrap();
        let mut bytes = signed.serialize();

        // The Δ field sits immediately before the length-prefixed `policy`, which ends
        // the commitment — compute the offset instead of scanning for the bytes (the PQ
        // pubkey blob can contain the same 4-byte pattern).
        let commitment_len = signed.anchor.commitment_bytes().len();
        let delta_at = commitment_len - 4 - (4 + signed.anchor.policy.len());
        assert_eq!(&bytes[delta_at..delta_at + 4], &144u32.to_le_bytes());

        // Overwrite with 0x0001_0090 = 65_680, which truncates to 144 — the honest Δ.
        bytes[delta_at..delta_at + 4].copy_from_slice(&65_680u32.to_le_bytes());
        assert_eq!(65_680u32 as u16, 144, "the truncation this rejection prevents");

        assert_eq!(
            SignedAnchor::deserialize(&bytes),
            Err(AnchorError::CsvDelayOutOfRange(65_680))
        );
    }

    #[test]
    fn serialize_roundtrips() {
        let seed = [9u8; 32];
        let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&seed).unwrap();
        let signed = sign_anchor(&sample(pk.clone()), &sk).unwrap();
        let bytes = signed.serialize();
        let back = SignedAnchor::deserialize(&bytes).unwrap();
        assert_eq!(back, signed);
        assert!(verify_anchor(&back, &pk).is_ok());
        // deterministic
        assert_eq!(signed.serialize(), back.serialize());
    }

    #[test]
    fn guard_programs_are_stable_and_key_bound() {
        let (pk, _sk) = bloch_crypto::crypto::generate_keypair_from_seed(&[3u8; 32]).unwrap();
        let g1 = anchor_guard_governance(&pk);
        let g2 = anchor_guard_governance(&pk);
        assert_eq!(bloch_euvm::validator_hash(&g1), bloch_euvm::validator_hash(&g2));
        // different PQ key → different guard hash
        let (pk2, _) = bloch_crypto::crypto::generate_keypair_from_seed(&[4u8; 32]).unwrap();
        assert_ne!(
            bloch_euvm::validator_hash(&g1),
            bloch_euvm::validator_hash(&anchor_guard_governance(&pk2))
        );
        // custody guard also stable
        let c1 = anchor_guard_custody(b"btc-pk", &pk);
        assert_eq!(
            bloch_euvm::validator_hash(&c1),
            bloch_euvm::validator_hash(&anchor_guard_custody(b"btc-pk", &pk))
        );
    }
}
