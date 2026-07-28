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
    /// Δ in blocks — MUST equal the on-chain branch-A CSV delay (spec §3.1).
    pub csv_delay: u32,
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
        b.extend_from_slice(&self.csv_delay.to_le_bytes());
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
    /// The PQ signature did not verify under `pq_recovery_pubkey`.
    BadSignature,
    /// Truncated / malformed serialized anchor.
    Malformed,
    /// Unknown `target_chain` tag on deserialize.
    UnknownChain(u8),
}

/// Sign a `PqShieldAnchor` with the owner's PQ secret key (ML-DSA-65 ‖ Falcon-1024).
/// The `pq_secret` MUST correspond to `anchor.pq_recovery_pubkey`; [`verify_anchor`]
/// enforces that binding at verification time.
pub fn sign_anchor(
    anchor: &PqShieldAnchor,
    pq_secret: &[u8],
) -> Result<SignedAnchor, bloch_crypto::crypto::CryptoError> {
    let sig = bloch_crypto::crypto::sign(pq_secret, &anchor.commitment_bytes())?;
    Ok(SignedAnchor { anchor: anchor.clone(), signature: sig })
}

/// Verify a signed anchor: the PQ signature must verify over the committed fields under
/// the anchor's own `pq_recovery_pubkey`. Returns `Ok(())` iff authentic. Tampering with
/// ANY committed field (address, `H(r)`, safe destination, Δ, policy, …) changes
/// [`PqShieldAnchor::commitment_bytes`] and makes this fail closed.
pub fn verify_anchor(signed: &SignedAnchor) -> Result<(), AnchorError> {
    let ok = bloch_crypto::crypto::verify(
        &signed.anchor.pq_recovery_pubkey,
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

    /// Inverse of [`SignedAnchor::serialize`]. Does NOT verify the signature — call
    /// [`verify_anchor`] after.
    pub fn deserialize(bytes: &[u8]) -> Result<SignedAnchor, AnchorError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.expect_tag(ANCHOR_DOMAIN)?;
        let version = c.get_u16()?;
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
        let csv_delay = c.get_u32()?;
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
        let anchor = sample(pk);

        let signed = sign_anchor(&anchor, &sk).unwrap();
        assert!(verify_anchor(&signed).is_ok(), "honest anchor must verify");

        // tamper the safe destination → verify fails closed
        let mut t1 = signed.clone();
        t1.anchor.designated_safe_dest = b"bcrt1qATTACKERdestination".to_vec();
        assert_eq!(verify_anchor(&t1), Err(AnchorError::BadSignature));

        // tamper H(r) → fails
        let mut t2 = signed.clone();
        t2.anchor.recovery_hash = [0xff; 32];
        assert_eq!(verify_anchor(&t2), Err(AnchorError::BadSignature));

        // tamper Δ → fails
        let mut t3 = signed.clone();
        t3.anchor.csv_delay = 6;
        assert_eq!(verify_anchor(&t3), Err(AnchorError::BadSignature));
    }

    #[test]
    fn serialize_roundtrips() {
        let seed = [9u8; 32];
        let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&seed).unwrap();
        let signed = sign_anchor(&sample(pk), &sk).unwrap();
        let bytes = signed.serialize();
        let back = SignedAnchor::deserialize(&bytes).unwrap();
        assert_eq!(back, signed);
        assert!(verify_anchor(&back).is_ok());
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
