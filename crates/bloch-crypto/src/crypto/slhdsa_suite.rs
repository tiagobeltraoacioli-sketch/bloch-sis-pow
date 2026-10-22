//! HF3 optional signature suite `0x0003`: SLH-DSA-SHAKE-128s ‖ Falcon-1024.
//!
//! Hash-based (FIPS 205, stateless; security reduces to SHAKE256 properties
//! only) paired with the NTRU-lattice Falcon-1024. BOTH halves must verify.
//! The point is assumption diversity: suite 0x0001 (ML-DSA-65 ‖ Falcon-1024,
//! the default and the only suite live spends use) is two lattice families;
//! this suite survives a break of every lattice scheme while SHAKE256 holds,
//! and survives an SLH-DSA implementation bug while Falcon holds.
//!
//! ## Gate
//!
//! This crate holds NO activation constant. The one HF3 constant is
//! `bloch_pos_committee::params::HF3_SLH_SUITE_EPOCH` (`u64::MAX` = never);
//! consensus decides `params::hf3_slh_suite_active(epoch)` and passes the
//! verdict in as `slh_suite_enabled`. With it `false`, [`super::verify_spend`]
//! is literally [`super::verify`], and every context-free entry point
//! (`verify`, `verify_enveloped*`) treats suite 0x0003 through the unchanged
//! unknown/reserved-suite arm. Keygen and signing are available so wallets and
//! tests can exercise the suite off-chain; no consensus verifier accepts the
//! result until a reviewed release lowers that one constant.
//!
//! ## Wire format (after the 4-byte `B1 0C ‖ 03 00` envelope header)
//!
//! ```text
//!   pk  = slh_pk(32)    ‖ falcon_pk(1793)                  = 1825 B body
//!   sk  = slh_sk(64)    ‖ falcon_sk(2305)                  = 2369 B body
//!   sig = slh_sig(7856) ‖ falcon_sig(compact, 42..=1462)   ≤ 9318 B body
//! ```
//!
//! Cross-suite / downgrade binding, in addition to the envelope suite id and
//! the address = SHA3-256(enveloped pk) commitment shared with every suite:
//!   * the SLH-DSA half is FIPS 205 *pure* signing with the suite context
//!     string [`SLHDSA_SUITE_CONTEXT`] (M' = 0x00 ‖ |ctx| ‖ ctx ‖ M);
//!   * the Falcon half signs [`FALCON_BIND_TAG`] ‖ M, never the bare message,
//!     so it can never be lifted into (or out of) suite 0x0001, whose Falcon
//!     half signs the bare message;
//!   * the Falcon half must use the canonical compact encoding (no padded
//!     variant, no malleable re-encodings);
//!   * seeded keygen derives both halves from a suite-domain-separated
//!     SHAKE256 expansion, so a wallet seed never yields a Falcon key shared
//!     with suite 0x0001.
//!
//! ## Verify cost (DoS bound)
//!
//! Verification work is bounded by a constant independent of the input:
//!   * lengths are checked before any hashing — the pk body must be exactly
//!     1825 B and the signature body in `(7856, 7856 + 1462]`; anything else
//!     is rejected for the price of two comparisons;
//!   * the Falcon half (≈0.1 ms) is verified FIRST, so random or replayed
//!     garbage never reaches the SLH-DSA half (≈2.2 ms; a fixed 4,378
//!     Keccak-f1600 permutations for SHAKE-128s, with the message hashed
//!     once — every consensus caller signs a 32-byte root);
//!   * consensus prices a 0x0003 witness at `SLHDSA_FALCON_VERIFY_GAS`
//!     (1,067,610 gas, ~14.7× the hybrid) and gossip budgets weight it
//!     15 hybrid units, both from the same gate (bloch-pos-committee
//!     `fee_market`, bloch-pos-node `engine::verification`).
//!
//! ## Implementation
//!
//! `fips205` 0.4.1 (IntegrityChain), vendored byte-identically and hash-pinned
//! at crates/fips205: pure Rust, `#![deny(unsafe_code)]`, FIPS 205 final
//! (Aug 2024), MIT OR Apache-2.0, constant-time at source level
//! (dudect-checked upstream), NOT independently audited. Checked against the
//! NIST ACVP-Server SLH-DSA-SHAKE-128s keyGen/sigGen/sigVer vectors
//! (tests/acvp_slhdsa.rs). NO security is claimed.

use fips205::slh_dsa_shake_128s as slh;
use fips205::traits::{KeyGen, SerDes, Signer, Verifier};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use zeroize::Zeroizing;

use super::{falcon, wrap_envelope, CryptoError};

/// Suite id: SLH-DSA-SHAKE-128s ‖ Falcon-1024 (HF3, optional).
pub const SUITE_SLHDSA128S_FALCON1024: u16 = 0x0003;

/// SLH-DSA-SHAKE-128s public key (PK.seed ‖ PK.root).
pub const SLHDSA128S_PUBKEY_LEN: usize = slh::PK_LEN;
/// SLH-DSA-SHAKE-128s secret key (SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root).
pub const SLHDSA128S_SECRET_LEN: usize = slh::SK_LEN;
/// SLH-DSA-SHAKE-128s signature (fixed length).
pub const SLHDSA128S_SIG_LEN: usize = slh::SIG_LEN;

const _: () = assert!(SLHDSA128S_PUBKEY_LEN == 32);
const _: () = assert!(SLHDSA128S_SECRET_LEN == 64);
const _: () = assert!(SLHDSA128S_SIG_LEN == 7856);

/// FIPS 205 context string bound into every suite-0x0003 SLH-DSA signature.
pub const SLHDSA_SUITE_CONTEXT: &[u8] = b"BLOCH/SUITE/0x0003/SLH-DSA-SHAKE-128s+Falcon-1024/v1";
/// Fixed-length prefix the Falcon half signs ahead of the message.
pub const FALCON_BIND_TAG: &[u8] = b"BLOCH/SUITE/0x0003/FALCON-1024/v1\0";
/// Domain for deterministic (seeded) keygen expansion.
const KEYGEN_DOMAIN: &[u8] = b"BLOCH/SUITE/0x0003/KEYGEN/v1";

// FIPS 205 caps the context string at 255 bytes; fips205 returns `false` /
// an error above it, which would make the suite unusable rather than unsafe.
const _: () = assert!(SLHDSA_SUITE_CONTEXT.len() <= 255);

/// Upper bound on a compact Falcon-1024 signature (PQClean `CRYPTO_BYTES`).
fn falcon_max_sig_len() -> usize { pqcrypto_falcon::falcon1024::signature_bytes() }

/// Whether suite 0x0003 is accepted at `epoch` under an explicit
/// `activation` (wallet / rehearsal helper; `u64::MAX` means "never",
/// including at epoch `u64::MAX`). Consensus does not use this: it decides
/// with `bloch_pos_committee::params::hf3_slh_suite_active`.
pub const fn active_under(epoch: u64, activation: u64) -> bool {
    activation != u64::MAX && epoch >= activation
}

/// Exact suite-0x0003 public-key body length (SLH pk ‖ Falcon pk).
pub fn slhdsa_suite_pubkey_body_len() -> usize {
    SLHDSA128S_PUBKEY_LEN.saturating_add(falcon::pubkey_len())
}

/// Maximum suite-0x0003 signature BODY length (SLH sig ‖ max Falcon sig).
pub fn max_slhdsa_suite_signature_body_len() -> usize {
    SLHDSA128S_SIG_LEN.saturating_add(falcon_max_sig_len())
}

/// Maximum enveloped suite-0x0003 signature length (header + body).
pub fn max_slhdsa_suite_signature_len() -> usize {
    super::SUITE_HEADER_LEN.saturating_add(max_slhdsa_suite_signature_body_len())
}

fn falcon_bound_message(message: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(FALCON_BIND_TAG.len().saturating_add(message.len()));
    m.extend_from_slice(FALCON_BIND_TAG);
    m.extend_from_slice(message);
    m
}

/// rand_core 0.6 adapter that hands out pre-drawn bytes once. Feeds FIPS 205
/// `opt_rand` drawn from the workspace RNG (rand 0.9) without pulling a second
/// OS-RNG stack (`getrandom` 0.2) into the wasm wallet.
struct PreDrawnRng<'a> { bytes: &'a [u8], used: bool }

impl rand_core::RngCore for PreDrawnRng<'_> {
    fn next_u32(&mut self) -> u32 { 0 }
    fn next_u64(&mut self) -> u64 { 0 }
    fn fill_bytes(&mut self, out: &mut [u8]) { let _ = self.try_fill_bytes(out); }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        if self.used || out.len() != self.bytes.len() {
            // Fail closed: fips205 maps this to a sign error.
            let code = core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START)
                .unwrap_or(core::num::NonZeroU32::MIN);
            return Err(rand_core::Error::from(code));
        }
        out.copy_from_slice(self.bytes);
        self.used = true;
        Ok(())
    }
}
impl rand_core::CryptoRng for PreDrawnRng<'_> {}

fn assemble(slh_part: &[u8], falcon_part: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut v = Zeroizing::new(Vec::with_capacity(slh_part.len().saturating_add(falcon_part.len())));
    v.extend_from_slice(slh_part);
    v.extend_from_slice(falcon_part);
    v
}

fn envelope_pair(slh_pk: &[u8], slh_sk: &[u8], fpk: &[u8], fsk: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let pk = assemble(slh_pk, fpk);
    let sk = assemble(slh_sk, fsk);
    (wrap_envelope(SUITE_SLHDSA128S_FALCON1024, &pk),
     wrap_envelope(SUITE_SLHDSA128S_FALCON1024, &sk))
}

/// Fresh random suite-0x0003 keypair `(enveloped pk, enveloped sk)`.
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    use rand::RngCore as _;
    let mut seeds = Zeroizing::new([0u8; 3 * slh::N]);
    rand::rng().fill_bytes(&mut seeds[..]);
    let (spk, ssk) = keygen_from_slh_seeds(&seeds);
    let (fpk, fsk) = falcon::keypair();
    let fsk = Zeroizing::new(fsk);
    envelope_pair(&spk, &ssk[..], &fpk, &fsk)
}

fn keygen_from_slh_seeds(seeds: &[u8; 3 * slh::N]) -> ([u8; slh::PK_LEN], Zeroizing<[u8; slh::SK_LEN]>) {
    let mut sk_seed = Zeroizing::new([0u8; slh::N]);
    let mut sk_prf = Zeroizing::new([0u8; slh::N]);
    let mut pk_seed = [0u8; slh::N];
    sk_seed.copy_from_slice(&seeds[..slh::N]);
    sk_prf.copy_from_slice(&seeds[slh::N..2 * slh::N]);
    pk_seed.copy_from_slice(&seeds[2 * slh::N..]);
    let (pk, sk) = slh::KG::keygen_with_seeds(&sk_seed, &sk_prf, &pk_seed);
    (pk.into_bytes(), Zeroizing::new(sk.into_bytes()))
}

/// Deterministic suite-0x0003 keypair from a ≥32-byte seed (first 32 used,
/// matching [`super::generate_keypair_from_seed`]). Both halves come from a
/// SHAKE256 expansion under a suite-specific domain, so the result shares no
/// key material with the suite-0x0001 keypair of the same seed.
pub fn generate_keypair_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    if seed.len() < 32 {
        return Err(CryptoError::InvalidKey(format!("seed too short: {} bytes (need 32+)", seed.len())));
    }
    let mut xof = Shake256::default();
    xof.update(KEYGEN_DOMAIN);
    xof.update(&seed[..32]);
    let mut rdr = xof.finalize_xof();
    let mut slh_seeds = Zeroizing::new([0u8; 3 * slh::N]);
    let mut falcon_seed = Zeroizing::new([0u8; 32]);
    rdr.read(&mut slh_seeds[..]);
    rdr.read(&mut falcon_seed[..]);
    let (spk, ssk) = keygen_from_slh_seeds(&slh_seeds);
    let (fpk, fsk) = pqcrypto_internals::with_seeded_rng_scope(&falcon_seed, falcon::keypair);
    let fsk = Zeroizing::new(fsk);
    Ok(envelope_pair(&spk, &ssk[..], &fpk, &fsk))
}

/// Sign `message` with a suite-0x0003 secret-key BODY (header already
/// stripped). Hedged FIPS 205 signing (fresh 16-byte `opt_rand`).
pub(crate) fn sign_body(sk_body: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use rand::RngCore as _;
    let mut opt_rand = Zeroizing::new([0u8; slh::N]);
    rand::rng().fill_bytes(&mut opt_rand[..]);
    sign_body_with_opt_rand(sk_body, message, Some(&opt_rand[..]))
}

/// `opt_rand = None` ⇒ FIPS 205 deterministic variant (opt_rand = PK.seed).
pub(crate) fn sign_body_with_opt_rand(
    sk_body: &[u8],
    message: &[u8],
    opt_rand: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    if sk_body.len() <= SLHDSA128S_SECRET_LEN {
        return Err(CryptoError::InvalidKey("SLH-DSA hybrid secret key too short".into()));
    }
    let (ssk, fsk) = sk_body.split_at(SLHDSA128S_SECRET_LEN);
    let mut ssk_arr = Zeroizing::new([0u8; slh::SK_LEN]);
    ssk_arr.copy_from_slice(ssk);
    // try_from_bytes recomputes PK.root from the seeds: a corrupted key fails here.
    let sk = slh::PrivateKey::try_from_bytes(&ssk_arr)
        .map_err(|e| CryptoError::InvalidKey(format!("bad SLH-DSA secret key: {e}")))?;
    let (hedged, bytes): (bool, &[u8]) = match opt_rand {
        Some(r) => (true, r),
        None => (false, &[]),
    };
    let mut rng = PreDrawnRng { bytes, used: false };
    let slh_sig = sk.try_sign_with_rng(&mut rng, message, SLHDSA_SUITE_CONTEXT, hedged)
        .map_err(|e| CryptoError::SignFailed(format!("SLH-DSA: {e}")))?;
    let fsig = falcon::sign(fsk, &falcon_bound_message(message))?;
    let mut out = Vec::with_capacity(slh_sig.len().saturating_add(fsig.len()));
    out.extend_from_slice(&slh_sig);
    out.extend_from_slice(&fsig);
    Ok(wrap_envelope(SUITE_SLHDSA128S_FALCON1024, &out))
}

/// Suite-0x0003 BODY verifier, ungated. Exact pk length, fixed SLH-DSA
/// signature length, canonical (compact) Falcon remainder; BOTH must verify.
/// Malformed input ⇒ `false`, never a panic. Consensus callers MUST go
/// through the HF3 gate ([`super::verify_spend`]).
///
/// Order is a cost decision, not a semantic one: the result is the AND of
/// both halves either way, but checking the ~20× cheaper Falcon half first
/// means a forged or replayed signature is refused before the SLH-DSA half's
/// fixed ~4.4 k Keccak permutations are spent on it.
pub(crate) fn verify_body(pk_body: &[u8], message: &[u8], sig_body: &[u8]) -> bool {
    if pk_body.len() != slhdsa_suite_pubkey_body_len() {
        return false;
    }
    if sig_body.len() <= SLHDSA128S_SIG_LEN || sig_body.len() > max_slhdsa_suite_signature_body_len() {
        return false;
    }
    let (spk, fpk) = pk_body.split_at(SLHDSA128S_PUBKEY_LEN);
    let (ssig, fsig) = sig_body.split_at(SLHDSA128S_SIG_LEN);
    let (Ok(spk), Ok(ssig)) = (<&[u8; slh::PK_LEN]>::try_from(spk), <&[u8; slh::SIG_LEN]>::try_from(ssig)) else {
        return false;
    };
    if !falcon::verify_canonical(fpk, &falcon_bound_message(message), fsig) {
        return false;
    }
    let Ok(pk) = slh::PublicKey::try_from_bytes(spk) else { return false };
    pk.verify(message, ssig, SLHDSA_SUITE_CONTEXT)
}

/// Whether `public_key_bytes` is a well-formed suite-0x0003 envelope.
/// Format predicate only — it says nothing about activation.
pub fn is_slhdsa_hybrid_public_key(public_key_bytes: &[u8]) -> bool {
    matches!(super::parse_envelope(public_key_bytes), Some((SUITE_SLHDSA128S_FALCON1024, body))
        if body.len() == slhdsa_suite_pubkey_body_len())
}

/// Node-local spend-admission policy: the live hybrid
/// ([`super::is_hybrid_public_key`], unchanged) and, when the caller's HF3
/// gate is open (`slh_suite_enabled`), a well-formed suite-0x0003 key. With
/// the gate closed this is exactly `is_hybrid_public_key`.
pub fn is_spend_public_key_admissible(public_key_bytes: &[u8], slh_suite_enabled: bool) -> bool {
    super::is_hybrid_public_key(public_key_bytes)
        || (slh_suite_enabled && is_slhdsa_hybrid_public_key(public_key_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        address_from_pubkey, generate_keypair_from_seed as hybrid_from_seed, is_hybrid_public_key,
        sign, verify, verify_enveloped, verify_enveloped_canonical, verify_spend,
        verify_with_slhdsa_activation, SUITE_HEADER_LEN, SUITE_MLDSA65_FALCON1024, SUITE_MLDSA65_ONLY,
    };
    use sha3::{Digest, Sha3_256};

    const SEED: [u8; 32] = [0x5a; 32];
    const MSG: &[u8] = b"bloch hf3 slh-dsa suite";
    const ACT: u64 = 10;

    fn kp() -> (Vec<u8>, Vec<u8>) { generate_keypair_from_seed(&SEED).unwrap() }
    fn ok(p: &[u8], s: &[u8]) -> bool { verify_with_slhdsa_activation(p, MSG, s, ACT, ACT) }
    fn relabel(b: &[u8], suite: u16) -> Vec<u8> {
        let mut t = b.to_vec();
        t[2..4].copy_from_slice(&suite.to_le_bytes());
        t
    }

    #[test]
    fn sizes_and_envelope() {
        let (pk, sk) = kp();
        assert_eq!(pk.len(), SUITE_HEADER_LEN + 32 + 1793);
        assert_eq!(sk.len(), SUITE_HEADER_LEN + 64 + 2305);
        assert_eq!(u16::from_le_bytes([pk[2], pk[3]]), SUITE_SLHDSA128S_FALCON1024);
        let sig = sign(&sk, MSG).unwrap();
        assert!(sig.len() > SUITE_HEADER_LEN + SLHDSA128S_SIG_LEN);
        assert!(sig.len() <= max_slhdsa_suite_signature_len());
        assert_eq!(max_slhdsa_suite_signature_len(), 4 + 7856 + 1462);
        assert!(is_slhdsa_hybrid_public_key(&pk));
        assert!(!is_hybrid_public_key(&pk), "the live hybrid predicate must refuse 0x0003");
    }

    #[test]
    fn closed_gate_and_context_free_entry_points_refuse_0x0003() {
        let (pk, sk) = kp();
        let sig = sign(&sk, MSG).unwrap();
        assert!(verify_body(&pk[4..], MSG, &sig[4..]), "sanity: body verifies ungated");
        assert!(!verify_spend(&pk, MSG, &sig, false));
        assert!(!is_spend_public_key_admissible(&pk, false));
        assert!(verify_spend(&pk, MSG, &sig, true));
        assert!(is_spend_public_key_admissible(&pk, true));
        for e in [0, 1, 5_850, 1 << 40, u64::MAX - 1, u64::MAX] {
            assert!(!active_under(e, u64::MAX), "u64::MAX activation is never");
        }
        assert!(!verify(&pk, MSG, &sig));
        assert!(!verify_enveloped(&pk, MSG, &sig));
        assert!(!verify_enveloped_canonical(&pk, MSG, &sig));
    }

    /// With the gate off, the epoch verifier is the context-free verifier on
    /// every input class — including valid 0x0003 objects, which therefore
    /// take today's unknown/reserved-suite arm.
    #[test]
    fn pre_activation_epoch_verifier_equals_context_free_verifier() {
        let (spk, ssk) = kp();
        let ssig = sign(&ssk, MSG).unwrap();
        let (hpk, hsk) = hybrid_from_seed(&SEED).unwrap();
        let hsig = sign(&hsk, MSG).unwrap();
        let (mpk, msk) = {
            use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
            let (p, s) = pqcrypto_mldsa::mldsa65::keypair();
            (crate::crypto::wrap_envelope(SUITE_MLDSA65_ONLY, p.as_bytes()),
             crate::crypto::wrap_envelope(SUITE_MLDSA65_ONLY, s.as_bytes()))
        };
        let msig = sign(&msk, MSG).unwrap();
        let mut bad = hsig.clone();
        bad[100] ^= 1;
        let pks: [&[u8]; 6] = [&spk, &hpk, &hpk[4..], &mpk, &relabel(&spk, 0xFFFF), b"junk"];
        let sigs: [&[u8]; 7] = [&ssig, &hsig, &hsig[4..], &msig, &bad, &relabel(&ssig, 0x0001), b""];
        for p in pks {
            for s in sigs {
                let want = verify(p, MSG, s);
                assert_eq!(verify_spend(p, MSG, s, false), want);
                // Under a rehearsal activation, every epoch below it agrees too.
                assert_eq!(verify_with_slhdsa_activation(p, MSG, s, ACT - 1, ACT), want);
            }
            assert_eq!(is_spend_public_key_admissible(p, false), is_hybrid_public_key(p));
        }
        // Sanity of the corpus: the hybrid ones really do verify.
        assert!(verify(&hpk, MSG, &hsig) && verify(&mpk, MSG, &msig));
    }

    /// Owner decision (HF3 is strictly opt-in): every verdict on an object
    /// whose PUBLIC KEY is not suite 0x0003 — 0x0001, 0x0002, legacy raw,
    /// malformed — is identical with the gate open and closed, including
    /// 0x0001 keys paired with 0x0003-labelled signatures.
    #[test]
    fn non_0x0003_key_verdicts_are_identical_across_the_gate() {
        let (spk, ssk) = kp();
        let ssig = sign(&ssk, MSG).unwrap();
        let (hpk, hsk) = hybrid_from_seed(&SEED).unwrap();
        let hsig = sign(&hsk, MSG).unwrap();
        let (mpk, msk) = {
            use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
            let (p, s) = pqcrypto_mldsa::mldsa65::keypair();
            (crate::crypto::wrap_envelope(SUITE_MLDSA65_ONLY, p.as_bytes()),
             crate::crypto::wrap_envelope(SUITE_MLDSA65_ONLY, s.as_bytes()))
        };
        let msig = sign(&msk, MSG).unwrap();
        let mut bad = hsig.clone();
        bad[100] ^= 1;
        let mut legacy_sig_with_0x0003_magic = hsig[4..].to_vec();
        legacy_sig_with_0x0003_magic[..4].copy_from_slice(&[0xB1, 0x0C, 0x03, 0x00]);
        let pks: [&[u8]; 5] = [&hpk, &hpk[4..], &mpk, &relabel(&spk, 0xFFFF), b"junk"];
        let sigs: [&[u8]; 9] = [&ssig, &hsig, &hsig[4..], &msig, &bad,
            &relabel(&ssig, 0x0001), &relabel(&hsig, SUITE_SLHDSA128S_FALCON1024),
            &legacy_sig_with_0x0003_magic, b""];
        for p in pks {
            for s in sigs {
                assert_eq!(verify_spend(p, MSG, s, true), verify(p, MSG, s));
                assert_eq!(verify_spend(p, MSG, s, false), verify(p, MSG, s));
            }
            assert_eq!(is_spend_public_key_admissible(p, true), is_hybrid_public_key(p));
        }
        assert!(verify_spend(&hpk, MSG, &hsig, true) && verify_spend(&hpk[4..], MSG, &hsig[4..], true));
        assert!(verify_spend(&mpk, MSG, &msig, true));
        // Address format is untouched: same pk, same address, either way.
        assert_eq!(address_from_pubkey(&hpk, false), address_from_pubkey(&hpk, false));
    }

    #[test]
    fn rehearsal_activation_accepts_only_at_or_after_epoch() {
        let (pk, sk) = kp();
        let sig = sign(&sk, MSG).unwrap();
        assert!(!verify_with_slhdsa_activation(&pk, MSG, &sig, ACT - 1, ACT));
        assert!(verify_with_slhdsa_activation(&pk, MSG, &sig, ACT, ACT));
        assert!(verify_with_slhdsa_activation(&pk, MSG, &sig, u64::MAX, ACT));
        assert!(!verify_with_slhdsa_activation(&pk, b"other", &sig, ACT, ACT));
        assert!(is_spend_public_key_admissible(&pk, true));
        assert!(!is_spend_public_key_admissible(&pk[..pk.len() - 1], true));
    }

    #[test]
    fn existing_suites_unchanged_through_epoch_verifier_after_activation() {
        let (pk, sk) = hybrid_from_seed(&SEED).unwrap();
        let sig = sign(&sk, MSG).unwrap();
        for enabled in [false, true] {
            assert!(verify_spend(&pk, MSG, &sig, enabled));
        }
        for e in [0, ACT, u64::MAX] {
            assert!(verify_with_slhdsa_activation(&pk, MSG, &sig, e, ACT));
        }
        assert!(!verify_with_slhdsa_activation(&pk, b"x", &sig, ACT, ACT));
        // Legacy raw hybrid still verifies via the epoch path after activation.
        assert!(verify_with_slhdsa_activation(&pk[4..], MSG, &sig[4..], ACT, ACT));
    }

    // ── Hybrid AND: either half invalid ⇒ reject ────────────────────────────

    #[test]
    fn and_combiner_rejects_when_either_half_is_invalid() {
        let (pk, sk) = kp();
        let (pk_b, sk_b) = generate_keypair_from_seed(&[0x5b; 32]).unwrap();
        let sig = sign(&sk, MSG).unwrap();
        let other_msg = sign(&sk, b"a different message").unwrap();
        let other_key = sign(&sk_b, MSG).unwrap();
        assert!(ok(&pk, &sig) && ok(&pk_b, &other_key));
        let split = 4 + SLHDSA128S_SIG_LEN;
        let splice = |slh_from: &[u8], falcon_from: &[u8]| {
            let mut s = slh_from[..split].to_vec();
            s.extend_from_slice(&falcon_from[split..]);
            s
        };
        // Valid SLH half + Falcon half over another message / from another key.
        assert!(!ok(&pk, &splice(&sig, &other_msg)), "valid SLH + wrong-message Falcon");
        assert!(!ok(&pk, &splice(&sig, &other_key)), "valid SLH + foreign-key Falcon");
        // Valid Falcon half + SLH half over another message / from another key.
        assert!(!ok(&pk, &splice(&other_msg, &sig)), "wrong-message SLH + valid Falcon");
        assert!(!ok(&pk, &splice(&other_key, &sig)), "foreign-key SLH + valid Falcon");
        // A pk mixing the two keys' halves accepts neither key's signature.
        let mut mixed = pk[..4 + SLHDSA128S_PUBKEY_LEN].to_vec();
        mixed.extend_from_slice(&pk_b[4 + SLHDSA128S_PUBKEY_LEN..]);
        assert!(!ok(&mixed, &sig) && !ok(&mixed, &other_key));
        // ...but accepts the spliced signature matching it, proving the splice
        // itself is well-formed and the rejections above are the AND at work.
        assert!(ok(&mixed, &splice(&sig, &other_key)));
        // Zeroed halves.
        let mut z = sig.clone();
        z[4..split].fill(0);
        assert!(!ok(&pk, &z), "zeroed SLH half");
        let mut z = sig.clone();
        z[split + 41..].fill(0);
        assert!(!ok(&pk, &z), "zeroed Falcon half");
    }

    #[test]
    fn every_tamper_truncation_and_extension_fails() {
        let (pk, sk) = kp();
        let sig = sign(&sk, MSG).unwrap();
        assert!(ok(&pk, &sig));
        for i in [4, 4 + 16, 4 + SLHDSA128S_SIG_LEN / 2, 4 + SLHDSA128S_SIG_LEN - 1,
                  4 + SLHDSA128S_SIG_LEN, 4 + SLHDSA128S_SIG_LEN + 50, sig.len() - 1] {
            let mut t = sig.clone(); t[i] ^= 1; assert!(!ok(&pk, &t), "sig byte {i}");
        }
        for i in [4, 4 + 31, 4 + 32 + 1, pk.len() - 1] {
            let mut t = pk.clone(); t[i] ^= 1; assert!(!ok(&t, &sig), "pk byte {i}");
        }
        assert!(!ok(&pk, &sig[..sig.len() - 1]));
        let mut ext = sig.clone(); ext.push(0); assert!(!ok(&pk, &ext));
        assert!(!ok(&pk, &sig[..4 + SLHDSA128S_SIG_LEN]), "SLH half alone (Falcon stripped)");
        assert!(!ok(&pk, &sig[..4]));
        assert!(!ok(&pk[..pk.len() - 1], &sig));
        let mut pk_ext = pk.clone(); pk_ext.push(0); assert!(!ok(&pk_ext, &sig));
        // Oversized body (beyond the Falcon cap) is refused on length alone.
        let mut huge = sig[..4 + SLHDSA128S_SIG_LEN].to_vec();
        huge.resize(max_slhdsa_suite_signature_len() + 1, 0);
        assert!(!verify_body(&pk[4..], MSG, &huge[4..]));
    }

    // ── Suite mismatch / downgrade ──────────────────────────────────────────

    #[test]
    fn suite_mismatch_and_downgrade_are_rejected() {
        let (pk, sk) = kp();
        let sig = sign(&sk, MSG).unwrap();
        let (hpk, hsk) = hybrid_from_seed(&SEED).unwrap();
        let hsig = sign(&hsk, MSG).unwrap();
        for e in [ACT, u64::MAX] {
            let v = |p: &[u8], s: &[u8]| verify_with_slhdsa_activation(p, MSG, s, e, ACT);
            assert!(v(&pk, &sig) && v(&hpk, &hsig));
            // 0x0003 pk with a signature of any other label, and vice versa.
            for other in [SUITE_MLDSA65_FALCON1024, SUITE_MLDSA65_ONLY, 0x0000, 0x0004, 0xFFFF] {
                assert!(!v(&pk, &relabel(&sig, other)), "0x0003 pk, sig as {other:#06x}");
                assert!(!v(&relabel(&pk, other), &sig), "pk as {other:#06x}, 0x0003 sig");
                assert!(!v(&relabel(&pk, other), &relabel(&sig, other)), "both as {other:#06x}");
            }
            // Raw (header-less) 0x0003 bodies fall to the legacy hybrid path.
            assert!(!v(&pk[4..], &sig[4..]) && !v(&pk, &sig[4..]) && !v(&pk[4..], &sig));
            // Real objects of the other suite never cross.
            assert!(!v(&hpk, &sig) && !v(&pk, &hsig) && !v(&hpk[4..], &sig));
            // A 0x0001 signature relabelled 0x0003 against the 0x0001 key.
            assert!(!v(&hpk, &relabel(&hsig, SUITE_SLHDSA128S_FALCON1024)));
            assert!(!v(&relabel(&hpk, SUITE_SLHDSA128S_FALCON1024), &relabel(&hsig, SUITE_SLHDSA128S_FALCON1024)));
        }
    }

    #[test]
    fn falcon_half_is_suite_bound_and_not_liftable_into_0x0001() {
        let (pk, sk) = kp();
        let sig = sign(&sk, MSG).unwrap();
        let fpk = &pk[4 + SLHDSA128S_PUBKEY_LEN..];
        let fsig = &sig[4 + SLHDSA128S_SIG_LEN..];
        assert!(!falcon::verify(fpk, MSG, fsig), "Falcon half must not sign the bare message");
        assert!(falcon::verify(fpk, &falcon_bound_message(MSG), fsig));
        // SLH half is bound to the suite context, not the empty context.
        let spk = slh::PublicKey::try_from_bytes(pk[4..36].try_into().unwrap()).unwrap();
        let ssig: &[u8; slh::SIG_LEN] = sig[4..4 + SLHDSA128S_SIG_LEN].try_into().unwrap();
        assert!(spk.verify(MSG, ssig, SLHDSA_SUITE_CONTEXT));
        assert!(!spk.verify(MSG, ssig, b""));
    }

    #[test]
    fn padded_falcon_encoding_is_refused() {
        let (pk, sk) = kp();
        let sig = sign(&sk, MSG).unwrap();
        // Zero-pad the compact Falcon half to the padded length: the plain
        // Falcon verifier tolerates trailing zeros, the canonical one must not.
        let mut padded = sig.clone();
        padded.resize(4 + SLHDSA128S_SIG_LEN + falcon::padded_signature_len().min(falcon_max_sig_len()), 0);
        if padded.len() > sig.len() {
            assert!(!ok(&pk, &padded));
        }
    }

    // ── Determinism / golden vectors (wallet recovery depends on these) ─────

    #[test]
    fn seeded_keygen_is_deterministic_disjoint_and_pinned() {
        let (a, _) = kp();
        let (b, _) = kp();
        assert_eq!(a, b);
        let (c, _) = generate_keypair_from_seed(&[0x5b; 32]).unwrap();
        assert_ne!(a, c);
        let (h, _) = hybrid_from_seed(&SEED).unwrap();
        let hybrid_falcon = &h[4 + super::super::MLDSA_PUBKEY_LEN..];
        assert_ne!(&a[4 + SLHDSA128S_PUBKEY_LEN..], hybrid_falcon, "no Falcon key reuse across suites");
        assert_ne!(address_from_pubkey(&a, false), address_from_pubkey(&h, false));
        let relabelled = relabel(&a, SUITE_MLDSA65_ONLY);
        assert_ne!(address_from_pubkey(&a, false), address_from_pubkey(&relabelled, false));
        assert!(generate_keypair_from_seed(&[0u8; 31]).is_err());
        // Golden: the SLH half of the seeded key and the whole enveloped pk.
        assert_eq!(hex::encode(&a[4..36]), GOLDEN_SLH_PK_HEX);
        assert_eq!(hex::encode(Sha3_256::digest(&a)), GOLDEN_PK_SHA3_HEX);
    }

    #[test]
    fn deterministic_variant_is_stable_and_pinned_and_hedged_is_not() {
        let (pk, sk) = kp();
        let d1 = sign_body_with_opt_rand(&sk[4..], MSG, None).unwrap();
        let d2 = sign_body_with_opt_rand(&sk[4..], MSG, None).unwrap();
        assert_eq!(&d1[..4 + SLHDSA128S_SIG_LEN], &d2[..4 + SLHDSA128S_SIG_LEN]);
        assert_eq!(hex::encode(Sha3_256::digest(&d1[4..4 + SLHDSA128S_SIG_LEN])), GOLDEN_DET_SLH_SIG_SHA3_HEX);
        let h1 = sign(&sk, MSG).unwrap();
        let h2 = sign(&sk, MSG).unwrap();
        assert_ne!(&h1[..4 + SLHDSA128S_SIG_LEN], &h2[..4 + SLHDSA128S_SIG_LEN]);
        for s in [&d1, &h1, &h2] {
            assert!(ok(&pk, s));
        }
        assert!(sign_body_with_opt_rand(&sk[4..], MSG, Some(&[0u8; 15])).is_err());
    }

    const GOLDEN_SLH_PK_HEX: &str = "53b0515008039bfa40b6fa08e95c57822b3ee14104371253199e498ed83a761b";
    const GOLDEN_PK_SHA3_HEX: &str = "fce94a4222ea13929d710cacdc927b778128b5375341d1f321187ff49aa31ef2";
    const GOLDEN_DET_SLH_SIG_SHA3_HEX: &str = "b52b3e95b12420374fba72a9590fb429cadcf409c1f7ac12961d307bfa1236c2";

    #[test]
    fn corrupted_secret_key_is_rejected() {
        let (_, sk) = kp();
        let mut bad = sk.clone(); bad[4 + 63] ^= 1; // PK.root byte
        assert!(sign(&bad, MSG).is_err());
        assert!(sign(&sk[..4 + SLHDSA128S_SECRET_LEN], MSG).is_err());
    }

    #[test]
    fn random_keygen_roundtrips() {
        let (pk, sk) = generate_keypair();
        let sig = sign(&sk, MSG).unwrap();
        assert!(ok(&pk, &sig));
    }

    // ── Robustness: no input panics, including ones that reach SLH-DSA ─────

    fn xorshift(seed: u64) -> impl FnMut() -> u64 {
        let mut x = seed;
        move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x }
    }

    #[test]
    fn fuzz_malformed_0x0003_never_panics() {
        let mut next = xorshift(0x9e37_79b9_7f4a_7c15);
        for _ in 0..200 {
            let pl = (next() % 2000) as usize;
            let sl = (next() % 9500) as usize;
            let mut pk = vec![0xB1, 0x0C, 0x03, 0x00];
            pk.extend((0..pl).map(|_| next() as u8));
            let mut sig = vec![0xB1, 0x0C, 0x03, 0x00];
            sig.extend((0..sl).map(|_| next() as u8));
            assert!(!ok(&pk, &sig));
            assert!(!verify(&pk, MSG, &sig));
        }
    }

    /// Random SLH-DSA halves of exactly the right length, behind a VALID
    /// Falcon half, so every iteration runs the full SLH-DSA verifier on
    /// attacker-chosen bytes (random FORS/hypertree indices and paths).
    /// Release builds keep `overflow-checks = true`; a panic here would be a
    /// consensus crash.
    #[test]
    fn fuzz_random_slh_half_behind_valid_falcon_never_panics() {
        let (pk, sk) = kp();
        let sig = sign(&sk, MSG).unwrap();
        let mut next = xorshift(0xD1B5_4A32_D192_ED03);
        for round in 0..24 {
            let mut t = sig.clone();
            for b in &mut t[4..4 + SLHDSA128S_SIG_LEN] {
                *b = next() as u8;
            }
            if round % 3 == 0 {
                // Keep R and most of FORS, randomise only the hypertree tail.
                t[4..4 + 4000].copy_from_slice(&sig[4..4 + 4000]);
            }
            assert!(!ok(&pk, &t));
            // Random 32-byte SLH public keys with the real signature.
            let mut p = pk.clone();
            for b in &mut p[4..36] {
                *b = next() as u8;
            }
            assert!(!ok(&p, &sig));
        }
    }
}

/// HF3 benchmark — `cargo test --release -p bloch-crypto --lib
/// slhdsa_suite::bench -- --ignored --nocapture --test-threads=1`.
#[cfg(test)]
mod bench {
    use super::*;
    use crate::crypto::{generate_keypair as hybrid_keygen, sign, verify, verify_with_slhdsa_activation};
    use std::time::Instant;

    const MSG: &[u8; 32] = &[0x42; 32]; // every live caller signs a 32-byte digest

    fn time<T>(n: u32, mut f: impl FnMut() -> T) -> (f64, T) {
        let t = Instant::now();
        let mut last = None;
        for _ in 0..n { last = Some(std::hint::black_box(f())); }
        (t.elapsed().as_secs_f64() * 1e3 / f64::from(n), last.unwrap())
    }

    fn row(name: &str, pk: usize, sig: usize, kg: f64, sg: f64, vf: f64) {
        println!("BENCH | {name:<34} | pk {pk:>5} B | sig {sig:>5} B | keygen {kg:>9.3} ms | sign {sg:>9.3} ms | verify {vf:>7.3} ms");
    }

    #[test]
    #[ignore = "benchmark; run with --release --ignored --nocapture"]
    fn suites() {
        println!("BENCH | message = 32-byte digest; times are per-op means, single thread");
        let (kg, (pk, sk)) = time(20, hybrid_keygen);
        let (sg, sig) = time(50, || sign(&sk, MSG).unwrap());
        let (vf, ok) = time(200, || verify(&pk, MSG, &sig));
        assert!(ok);
        row("0x0001 ML-DSA-65+Falcon-1024 (env)", pk.len(), sig.len(), kg, sg, vf);
        let (kg, (pk, sk)) = time(5, generate_keypair);
        let (sg, sig) = time(10, || sign(&sk, MSG).unwrap());
        let (vf, ok) = time(100, || verify_with_slhdsa_activation(&pk, MSG, &sig, 1, 1));
        assert!(ok);
        row("0x0003 SLH-128s+Falcon-1024 (env)", pk.len(), sig.len(), kg, sg, vf);
        // Rejection cost of a forged signature (garbage Falcon half): the
        // SLH-DSA half is never reached.
        let mut forged = sig.clone();
        let n = forged.len();
        forged[n - 1] ^= 1;
        let (vf_bad, ok) = time(200, || verify_with_slhdsa_activation(&pk, MSG, &forged, 1, 1));
        assert!(!ok);
        println!("BENCH | 0x0003 reject (bad Falcon half): {vf_bad:.3} ms");
        println!("BENCH | 0x0003 max enveloped sig = {} B", max_slhdsa_suite_signature_len());
    }
}
