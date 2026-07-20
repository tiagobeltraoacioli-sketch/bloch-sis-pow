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

// ── Crypto-agility suite-ID envelope (Roadmap #1) ────────────────────────────
//
// Every public key AND signature (and, for symmetry, the secret key) now carries
// a 4-byte header so the verifier dispatches on an IN-BAND algorithm identifier
// instead of assuming fixed offsets. This makes suites swappable (e.g. drop
// Falcon → SUITE_MLDSA65_ONLY) without a further format break.
//
//   byte 0     : 0xB1  ┐ 2-byte magic "B1 0C" — an enveloped object vs. a legacy
//   byte 1     : 0x0C  ┘ raw ML-DSA blob; a mismatch ⇒ verify returns false.
//   bytes 2..4 : suite_id : u16 LE
//
// Parse failure (len<4 / bad magic / unknown suite) ⇒ verify returns false and
// NEVER panics (consensus rule). NOT a security claim: this is unaudited.
pub const SUITE_HEADER_LEN: usize = 4;
const SUITE_MAGIC: [u8; 2] = [0xB1, 0x0C];
/// Today's hybrid: ML-DSA-65 ‖ Falcon-1024.
pub const SUITE_MLDSA65_FALCON1024: u16 = 0x0001;
/// ML-DSA-65 only — the "Falcon removed" suite (proof that Falcon is removable).
pub const SUITE_MLDSA65_ONLY: u16 = 0x0002;
// 0x0000 and 0xFFFF are reserved and never valid ⇒ verify returns false.

/// Parse the 4-byte suite envelope header. `None` on any malformation
/// (len < 4 or bad magic) — the caller MUST treat `None` as invalid (`false`),
/// never a panic. The returned body is everything after the header.
pub(crate) fn parse_envelope(b: &[u8]) -> Option<(u16, &[u8])> {
    if b.len() < SUITE_HEADER_LEN { return None; }
    if b[0] != SUITE_MAGIC[0] || b[1] != SUITE_MAGIC[1] { return None; }
    let suite = u16::from_le_bytes([b[2], b[3]]);
    Some((suite, &b[SUITE_HEADER_LEN..]))
}

/// Prepend the 4-byte suite header (`magic ‖ suite_id LE`) to a body.
pub(crate) fn wrap_envelope(suite: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SUITE_HEADER_LEN + body.len());
    out.extend_from_slice(&SUITE_MAGIC);
    out.extend_from_slice(&suite.to_le_bytes());
    out.extend_from_slice(body);
    out
}

pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let (mpk, msk) = mldsa65::keypair();
    let (fpk, fsk) = falcon::keypair();
    let mut pk = mpk.as_bytes().to_vec(); pk.extend_from_slice(&fpk);
    let mut sk = msk.as_bytes().to_vec(); sk.extend_from_slice(&fsk);
    // Enveloped under suite 0x0001 (magic ‖ 01 00 ‖ body). The enveloped pk is
    // THE public key everywhere (keygen, address hashing, script_sig) so
    // addresses become suite-committing (design §2.4).
    (wrap_envelope(SUITE_MLDSA65_FALCON1024, &pk),
     wrap_envelope(SUITE_MLDSA65_FALCON1024, &sk))
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
    Ok((wrap_envelope(SUITE_MLDSA65_FALCON1024, &pk),
        wrap_envelope(SUITE_MLDSA65_FALCON1024, &sk)))
}

pub fn sign(secret_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Parse the suite envelope on the secret key, then produce a signature
    // enveloped under the SAME suite. Parse failure ⇒ Err (never a panic).
    let (suite, sk_body) = parse_envelope(secret_key_bytes)
        .ok_or_else(|| CryptoError::InvalidKey("secret-key envelope: too short or bad magic".into()))?;
    match suite {
        SUITE_MLDSA65_FALCON1024 => {
            // Hybrid body: mldsa_sk(4032) ‖ falcon_sk. Produce mldsa_sig(3309) ‖ falcon_sig.
            if sk_body.len() <= MLDSA_SECRET_LEN {
                return Err(CryptoError::InvalidKey("hybrid secret key too short".into()));
            }
            let (msk, fsk) = sk_body.split_at(MLDSA_SECRET_LEN);
            let sk = mldsa65::SecretKey::from_bytes(msk)
                .map_err(|_| CryptoError::InvalidKey("bad ML-DSA secret key".into()))?;
            let mut out = mldsa65::detached_sign(message, &sk).as_bytes().to_vec();
            out.extend_from_slice(&falcon::sign(fsk, message)?);
            Ok(wrap_envelope(suite, &out))
        }
        SUITE_MLDSA65_ONLY => {
            if sk_body.len() != MLDSA_SECRET_LEN {
                return Err(CryptoError::InvalidKey("ML-DSA-only secret key wrong length".into()));
            }
            let sk = mldsa65::SecretKey::from_bytes(sk_body)
                .map_err(|_| CryptoError::InvalidKey("bad ML-DSA secret key".into()))?;
            let out = mldsa65::detached_sign(message, &sk).as_bytes().to_vec();
            Ok(wrap_envelope(suite, &out))
        }
        _ => Err(CryptoError::InvalidKey(format!("unknown/reserved suite {:#06x}", suite))),
    }
}

/// Parse a suite envelope, or fall back to the LEGACY pre-envelope encoding:
/// carry-over wallets created before the 4-byte header (their address is
/// `SHA3-256(raw hybrid pubkey)`) present a bare `mldsa ‖ falcon` body with no
/// magic. Treat a no-magic object as suite 0x0001 (hybrid), the only suite the
/// old chain produced. A genuine hybrid pubkey/sig never starts with `B1 0C`
/// (those are ML-DSA bytes), so this is unambiguous; a mismatch still ⇒ verify
/// false via the body checks. This restores spendability of pre-envelope
/// carry-over funds without weakening enveloped verification. CONSENSUS-CRITICAL.
fn parse_envelope_or_legacy(b: &[u8]) -> (u16, &[u8]) {
    match parse_envelope(b) {
        Some((suite, body)) => (suite, body),
        None => (SUITE_MLDSA65_FALCON1024, b),
    }
}

pub fn verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    // Suite-ID dispatch (design §2.3). Accepts enveloped objects AND legacy
    // pre-envelope (raw hybrid) objects from the carry-over. A pk of one suite
    // must not verify a sig of another. Any body parse failure ⇒ false, never a
    // panic (consensus rule). NO security is claimed.
    let (pk_suite, pk_body) = parse_envelope_or_legacy(public_key_bytes);
    let (sig_suite, sig_body) = parse_envelope_or_legacy(signature_bytes);
    if pk_suite != sig_suite {
        debug!("crypto::verify: suite mismatch (pk={:#06x}, sig={:#06x})", pk_suite, sig_suite);
        return false;
    }
    match pk_suite {
        SUITE_MLDSA65_FALCON1024 => verify_hybrid_mldsa_falcon(pk_body, message, sig_body),
        SUITE_MLDSA65_ONLY       => verify_mldsa65_only(pk_body, message, sig_body),
        other => { debug!("crypto::verify: unknown/reserved suite {:#06x}", other); false }
    }
}

/// Suite 0x0001 verifier — the pre-envelope `verify` body verbatim, now
/// operating on the post-header BODY slices. The `<=` length guards, the
/// `from_bytes` parse-fail⇒false, and the ML-DSA-AND-Falcon combiner are all
/// preserved: BOTH halves must verify (defence in depth across two lattice
/// families). Behaviour on 0x0001 objects is byte-for-byte identical to the
/// legacy path except for the 4-byte header strip.
fn verify_hybrid_mldsa_falcon(pk_body: &[u8], message: &[u8], sig_body: &[u8]) -> bool {
    if pk_body.len() <= MLDSA_PUBKEY_LEN || sig_body.len() <= MLDSA_SIG_LEN {
        debug!("crypto::verify: hybrid pubkey/sig body too short (pk={}, sig={})",
               pk_body.len(), sig_body.len());
        return false;
    }
    let (mpk, fpk) = pk_body.split_at(MLDSA_PUBKEY_LEN);
    let (msig, fsig) = sig_body.split_at(MLDSA_SIG_LEN);

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

/// Suite 0x0002 verifier — ML-DSA-65 only (Falcon removed). Exact-length bodies
/// required. Provided so `SUITE_MLDSA65_ONLY` objects verify; no live output
/// uses this suite yet (gating new 0x0002 acceptance behind a height activation
/// is future work, design §2.5).
fn verify_mldsa65_only(pk_body: &[u8], message: &[u8], sig_body: &[u8]) -> bool {
    if pk_body.len() != MLDSA_PUBKEY_LEN || sig_body.len() != MLDSA_SIG_LEN {
        debug!("crypto::verify: mldsa-only pk/sig body wrong length (pk={}, sig={})",
               pk_body.len(), sig_body.len());
        return false;
    }
    let pk = match mldsa65::PublicKey::from_bytes(pk_body) {
        Ok(k) => k, Err(_) => return false,
    };
    let sig = match mldsa65::DetachedSignature::from_bytes(sig_body) {
        Ok(s) => s, Err(_) => return false,
    };
    mldsa65::verify_detached_signature(&sig, message, &pk).is_ok()
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
// The second signature of the hybrid ML-DSA-65 ‖ Falcon-1024 scheme: two
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

// ═════════════════════════════════════════════════════════════════════════════
// Roadmap #5 — KATs + reference-equivalence + no-panic fuzz (audit-prep).
//
// Scope (see docs/../roadmap-crypto-core §3.1 items 2–3, §4 items 1–3):
//   (A) Reference-equivalence for the borrowed primitives — prove the hybrid
//       wrapper preserves the upstream ML-DSA-65 / Falcon-1024 byte layout
//       (catches offset/endianness/split bugs). The upstream `pqcrypto-*`
//       crates are used as the reference ORACLE; no vectors are fabricated.
//   (B) Golden regression vector for deterministic keygen-from-seed.
//   (C) No-panic fuzz of the signature parse+verify path.
//
// KAT SOURCE / HONESTY: the official NIST FIPS-204 ML-DSA-65 `.rsp` KAT files
// and the Falcon-1024 NIST KATs are NOT vendored in-tree — only PQClean's
// `nistkat.c` C harness ships in the `pqcrypto-*` crates, which is not callable
// from Rust and, crucially, reproduces its keypair from a NIST AES-256-CTR DRBG
// while Bloch's `generate_keypair_from_seed` uses a ChaCha20 stream. A signed
// NIST `.rsp` vector therefore does NOT reproduce a Bloch seeded keypair. What
// IS provable here without fabrication is that Bloch's wrapper does not corrupt
// the underlying scheme: a signature produced with the upstream primitive at
// the documented offsets verifies through Bloch's hybrid `verify`, and vice
// versa. Full NIST-KAT wiring still needs: (1) the official `.rsp` files
// vendored, and (2) an AES-256-CTR NIST DRBG to drive keygen — see the
// `#[ignore]`d `full_nist_kat_wiring_todo` below.
// ═════════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod kat {
    use super::*;
    use pqcrypto_falcon::falcon1024;
    use pqcrypto_mldsa::mldsa65;
    // NOTE: the `pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey}`
    // trait imports were removed here: the suite-envelope refactor replaced the
    // kat module's direct trait-method slicing with `parse_envelope(..)` body
    // access, so those traits are no longer referenced in this module.

    // Falcon-1024 public-key length (used for the reverse-split oracle test).
    const FALCON_PUBKEY_LEN: usize = 1793;

    // ─── (A) Reference-equivalence: primitive length KATs ─────────────────────
    // The hybrid wrapper hard-codes the ML-DSA split offsets. If the upstream
    // crate ever changed a length, the fixed 1952/4032/3309 splits would slice
    // the wrong bytes — assert they still match the primitive.
    #[test]
    fn primitive_lengths_match_hybrid_split_offsets() {
        assert_eq!(mldsa65::public_key_bytes(), MLDSA_PUBKEY_LEN, "ML-DSA-65 pk len");
        assert_eq!(mldsa65::secret_key_bytes(), MLDSA_SECRET_LEN, "ML-DSA-65 sk len");
        assert_eq!(mldsa65::signature_bytes(), MLDSA_SIG_LEN, "ML-DSA-65 sig len");
        assert_eq!(falcon1024::public_key_bytes(), FALCON_PUBKEY_LEN, "Falcon-1024 pk len");

        // Enveloped objects = 4-byte suite header + the raw primitive lengths.
        let (pk, sk) = generate_keypair();
        let sig = sign(&sk, b"envelope-len-check").unwrap();
        assert_eq!(pk.len(), SUITE_HEADER_LEN + MLDSA_PUBKEY_LEN + FALCON_PUBKEY_LEN,
                   "enveloped hybrid pk = header + mldsa_pk + falcon_pk");
        assert_eq!(sk.len(), SUITE_HEADER_LEN + MLDSA_SECRET_LEN + falcon1024::secret_key_bytes(),
                   "enveloped hybrid sk = header + mldsa_sk + falcon_sk");
        // Falcon signature is variable-length, so the enveloped sig is bounded
        // above by header + mldsa_sig + Falcon MAX, and strictly larger than the
        // header + mldsa_sig (a non-empty Falcon tail is present).
        assert!(sig.len() > SUITE_HEADER_LEN + MLDSA_SIG_LEN,
                   "enveloped hybrid sig must carry a Falcon tail");
        assert!(sig.len() <= SUITE_HEADER_LEN + MLDSA_SIG_LEN + falcon1024::signature_bytes(),
                   "enveloped hybrid sig <= header + mldsa_sig + falcon_sig(max)");
        // The header carries the magic + suite 0x0001.
        assert_eq!(&pk[..2], &SUITE_MAGIC, "pk magic");
        assert_eq!(u16::from_le_bytes([pk[2], pk[3]]), SUITE_MLDSA65_FALCON1024, "pk suite id");
    }

    // ─── (A) Reference-equivalence: upstream-built artifact verifies via Bloch ─
    // Build a hybrid keypair + signature by hand from the UPSTREAM primitives in
    // the documented ML-DSA-first order, then feed it to Bloch's `verify`.
    // Acceptance proves Bloch splits `pk`/`sig` at exactly the upstream byte
    // boundaries (offset/endianness bug catcher).
    #[test]
    fn upstream_built_hybrid_verifies_through_bloch() {
        let msg = b"reference-equivalence-forward";
        let (mpk, msk) = mldsa65::keypair();
        let (fpk, fsk) = falcon1024::keypair();

        // pk = mldsa_pk(1952) ‖ falcon_pk ; sig = mldsa_sig(3309) ‖ falcon_sig,
        // each wrapped in the suite-0x0001 envelope Bloch's verify now expects.
        let mut pk_body = mpk.as_bytes().to_vec();
        pk_body.extend_from_slice(fpk.as_bytes());
        let mut sig_body = mldsa65::detached_sign(msg, &msk).as_bytes().to_vec();
        sig_body.extend_from_slice(falcon1024::detached_sign(msg, &fsk).as_bytes());
        let pk = wrap_envelope(SUITE_MLDSA65_FALCON1024, &pk_body);
        let sig = wrap_envelope(SUITE_MLDSA65_FALCON1024, &sig_body);

        assert!(
            verify(&pk, msg, &sig),
            "hybrid assembled from upstream primitives at documented offsets must verify"
        );
        // Sanity: a different message must fail (the wrapper really checks it).
        assert!(!verify(&pk, b"other", &sig));
    }

    // ─── (A) Reference-equivalence: Bloch-built halves parse as upstream prims ─
    // The reverse direction: take a Bloch hybrid keypair/signature, split at the
    // documented offsets, and verify each half DIRECTLY with the upstream crate.
    // Proves Bloch's concatenation emits valid, correctly-ordered upstream bytes.
    #[test]
    fn bloch_built_halves_verify_as_upstream_primitives() {
        let msg = b"reference-equivalence-reverse";
        let (pk, sk) = generate_keypair();
        let sig = sign(&sk, msg).unwrap();

        // Strip the 4-byte suite header before splitting at the primitive offsets.
        let (_pk_suite, pk_body)  = parse_envelope(&pk).expect("pk envelope");
        let (_sig_suite, sig_body) = parse_envelope(&sig).expect("sig envelope");
        let (mpk_b, fpk_b) = pk_body.split_at(MLDSA_PUBKEY_LEN);
        let (msig_b, fsig_b) = sig_body.split_at(MLDSA_SIG_LEN);

        // ML-DSA half through the upstream primitive directly.
        let mpk = mldsa65::PublicKey::from_bytes(mpk_b).expect("ML-DSA pk half must parse upstream");
        let msig = mldsa65::DetachedSignature::from_bytes(msig_b)
            .expect("ML-DSA sig half must parse upstream");
        assert!(
            mldsa65::verify_detached_signature(&msig, msg, &mpk).is_ok(),
            "Bloch ML-DSA half must verify under the upstream primitive"
        );

        // Falcon half through the upstream primitive directly.
        let fpk = falcon1024::PublicKey::from_bytes(fpk_b).expect("Falcon pk half must parse upstream");
        let fsig = falcon1024::DetachedSignature::from_bytes(fsig_b)
            .expect("Falcon sig half must parse upstream");
        assert!(
            falcon1024::verify_detached_signature(&fsig, msg, &fpk).is_ok(),
            "Bloch Falcon half must verify under the upstream primitive"
        );
    }

    // ─── (B) Golden regression vector: deterministic keygen-from-seed ─────────
    // Fixed seed → byte-stable keypair. We pin the ML-DSA-65 halves only: FIPS
    // 204 keygen (Alg. 6) is deterministic AND platform-stable given the byte
    // stream, so these hashes are portable regression anchors. The Falcon-1024
    // half is deterministic on a fixed platform but carries the documented
    // floating-point-platform caveat (see `generate_keypair_from_seed` docs), so
    // its bytes are NOT pinned here — only asserted reproducible within a run and
    // length-checked. If pqcrypto-mldsa's internal keygen order ever changes,
    // these hashes change and wallet recovery breaks — that is exactly what this
    // vector guards (cf. the crate's own compatibility warning).
    const GOLDEN_SEED: [u8; 32] = [0x11u8; 32];
    const GOLDEN_MLDSA_PK_HASH: &str =
        "bb34618ab597cc394fcfa9c9c5791d4767baacce3648285e8069742a55e2de37";
    const GOLDEN_MLDSA_SK_HASH: &str =
        "4ea56265a543928d9c4cf073fe8a6a85b9f7444b2012f2603b26b6a24f1255aa";
    // Deterministic ML-DSA signature over GOLDEN_MSG produced under the seeded
    // RNG (regression-only path; production signing is HEDGED — see below).
    const GOLDEN_MSG: &[u8] = b"BLOCH-HYBRID-GOLDEN-VECTOR-V1";
    const GOLDEN_MLDSA_SIG_HASH: &str =
        "196127fe6b978be23ad4828405f60a7d49839abf4cbba77ead02394e291a59fb";

    #[test]
    fn golden_seed_to_keypair_is_byte_stable() {
        let (pk, sk) = generate_keypair_from_seed(&GOLDEN_SEED).unwrap();
        // Full ENVELOPED hybrid lengths (4-byte suite header + hybrid body).
        assert_eq!(pk.len(), SUITE_HEADER_LEN + MLDSA_PUBKEY_LEN + FALCON_PUBKEY_LEN, "hybrid pk len");
        assert_eq!(sk.len(), SUITE_HEADER_LEN + MLDSA_SECRET_LEN + falcon1024::secret_key_bytes(), "hybrid sk len");
        // Pinned ML-DSA halves — the hash VALUES are unchanged from the pre-envelope
        // goldens: the ML-DSA body bytes are identical, only shifted by the 4-byte
        // header, so we slice pk[4..4+1952] / sk[4..4+4032] instead of pk[..1952].
        assert_eq!(
            hex::encode(Sha3_256::digest(&pk[SUITE_HEADER_LEN..SUITE_HEADER_LEN + MLDSA_PUBKEY_LEN])),
            GOLDEN_MLDSA_PK_HASH,
            "ML-DSA-65 public-key half drifted from the golden vector"
        );
        assert_eq!(
            hex::encode(Sha3_256::digest(&sk[SUITE_HEADER_LEN..SUITE_HEADER_LEN + MLDSA_SECRET_LEN])),
            GOLDEN_MLDSA_SK_HASH,
            "ML-DSA-65 secret-key half drifted from the golden vector"
        );
    }

    #[test]
    fn golden_deterministic_mldsa_signature_half_is_byte_stable() {
        // Drive PQClean's randombytes from the same seed so the (normally
        // hedged) ML-DSA signature becomes deterministic for a byte-stable
        // golden vector. This exercises the deterministic-signing path used
        // ONLY for regression pinning — NOT the production signer.
        let (_pk, sk) = generate_keypair_from_seed(&GOLDEN_SEED).unwrap();
        let _guard = pqcrypto_internals::with_seeded_rng(&GOLDEN_SEED);
        let sig = sign(&sk, GOLDEN_MSG).unwrap();
        drop(_guard);
        // Hash VALUE unchanged; slice shifts by the 4-byte header: sig[4..4+3309].
        assert_eq!(
            hex::encode(Sha3_256::digest(&sig[SUITE_HEADER_LEN..SUITE_HEADER_LEN + MLDSA_SIG_LEN])),
            GOLDEN_MLDSA_SIG_HASH,
            "deterministic ML-DSA-65 signature half drifted from the golden vector"
        );
    }

    #[test]
    fn golden_vector_verifies_and_rejects_tampering() {
        let (pk, sk) = generate_keypair_from_seed(&GOLDEN_SEED).unwrap();
        let sig = sign(&sk, GOLDEN_MSG).unwrap();
        assert!(verify(&pk, GOLDEN_MSG, &sig), "fresh hybrid signature must verify");

        // Flip the FIRST ML-DSA-body byte (offset shifted past the 4-byte header,
        // sig[0]→sig[4]) → must fail (AND-combiner).
        let mut t1 = sig.clone();
        t1[SUITE_HEADER_LEN] ^= 0x01;
        assert!(!verify(&pk, GOLDEN_MSG, &t1), "tampered ML-DSA half must fail");

        // Flip a byte in the Falcon half (MLDSA_SIG_LEN+1 → 4+MLDSA_SIG_LEN+1) →
        // must fail (AND-combiner).
        let mut t2 = sig.clone();
        let flip = SUITE_HEADER_LEN + MLDSA_SIG_LEN + 1;
        t2[flip] ^= 0x01;
        assert!(!verify(&pk, GOLDEN_MSG, &t2), "tampered Falcon half must fail");

        // Truncated signature → parse failure ⇒ false.
        assert!(!verify(&pk, GOLDEN_MSG, &sig[..sig.len() - 1]), "truncated sig must fail");
        assert!(!verify(&pk, GOLDEN_MSG, &sig[..MLDSA_SIG_LEN]), "falcon-less sig must fail");

        // Oversized signature (trailing garbage) → false.
        let mut over = sig.clone();
        over.push(0x00);
        assert!(!verify(&pk, GOLDEN_MSG, &over), "oversized sig must fail");

        // Tampered public key: ML-DSA body byte (pk[4]) and Falcon body byte
        // (pk[4+1952+1]) → false.
        let mut pk_m = pk.clone();
        pk_m[SUITE_HEADER_LEN] ^= 0x01;
        assert!(!verify(&pk_m, GOLDEN_MSG, &sig), "tampered ML-DSA pubkey must fail");
        let mut pk_f = pk.clone();
        pk_f[SUITE_HEADER_LEN + MLDSA_PUBKEY_LEN + 1] ^= 0x01;
        assert!(!verify(&pk_f, GOLDEN_MSG, &sig), "tampered Falcon pubkey must fail");

        // ── NEW envelope negative cases (design §4.2) ─────────────────────────
        // Bad magic on the signature → parse fail ⇒ false.
        let mut bad_magic = sig.clone();
        bad_magic[0] ^= 0x01;
        assert!(!verify(&pk, GOLDEN_MSG, &bad_magic), "bad-magic sig must fail");
        // Bad magic on the pubkey → false.
        let mut bad_magic_pk = pk.clone();
        bad_magic_pk[1] ^= 0x01;
        assert!(!verify(&bad_magic_pk, GOLDEN_MSG, &sig), "bad-magic pk must fail");
        // Unknown suite (0xFFFF) on BOTH pk and sig so the suites match but the
        // dispatch arm is `_ => false`.
        let mut us_pk = pk.clone();  us_pk[2] = 0xFF;  us_pk[3] = 0xFF;
        let mut us_sig = sig.clone(); us_sig[2] = 0xFF; us_sig[3] = 0xFF;
        assert!(!verify(&us_pk, GOLDEN_MSG, &us_sig), "unknown-suite must fail");
        // Reserved suite 0x0000 on both → false.
        let mut z_pk = pk.clone();  z_pk[2] = 0x00;  z_pk[3] = 0x00;
        let mut z_sig = sig.clone(); z_sig[2] = 0x00; z_sig[3] = 0x00;
        assert!(!verify(&z_pk, GOLDEN_MSG, &z_sig), "reserved suite 0x0000 must fail");
        // Suite mismatch: valid 0x0001 pk vs a sig relabelled 0x0002 → false.
        let mut mism_sig = sig.clone(); mism_sig[2] = 0x02; mism_sig[3] = 0x00;
        assert!(!verify(&pk, GOLDEN_MSG, &mism_sig), "pk/sig suite mismatch must fail");
        // Header-only (len == 4, empty body) on sig and on pk → false.
        assert!(!verify(&pk, GOLDEN_MSG, &sig[..SUITE_HEADER_LEN]), "header-only sig must fail");
        assert!(!verify(&pk[..SUITE_HEADER_LEN], GOLDEN_MSG, &sig), "header-only pk must fail");
        // Shorter-than-header (len < 4) on both → false (parse_envelope None).
        assert!(!verify(&pk[..2], GOLDEN_MSG, &sig), "len-2 pk must fail");
        assert!(!verify(&pk, GOLDEN_MSG, &sig[..3]), "len-3 sig must fail");
    }

    // ─── (B') Hedged-signing regression (roadmap §2.2) ────────────────────────
    // Production signing must stay HEDGED (randomized): two signatures over the
    // same message under the same key must differ. A regression to deterministic
    // signing would be a silent fault-attack exposure.
    #[test]
    fn production_signing_is_hedged_nondeterministic() {
        let (pk, sk) = generate_keypair_from_seed(&GOLDEN_SEED).unwrap();
        let s1 = sign(&sk, GOLDEN_MSG).unwrap();
        let s2 = sign(&sk, GOLDEN_MSG).unwrap();
        assert_ne!(s1, s2, "hybrid signing must be hedged (randomized), not deterministic");
        assert!(verify(&pk, GOLDEN_MSG, &s1));
        assert!(verify(&pk, GOLDEN_MSG, &s2));
    }

    // ─── Suite 0x0002 (ML-DSA-65 only) round-trip + suite isolation ───────────
    // Concrete proof that Falcon is removable in principle (design §2.5): build a
    // SUITE_MLDSA65_ONLY keypair from the upstream ML-DSA primitive, sign+verify
    // through the enveloped path, and confirm suite isolation.
    #[test]
    fn suite_mldsa65_only_roundtrips_and_is_suite_isolated() {
        let (mpk, msk) = mldsa65::keypair();
        let pk_env = wrap_envelope(SUITE_MLDSA65_ONLY, mpk.as_bytes());
        let sk_env = wrap_envelope(SUITE_MLDSA65_ONLY, msk.as_bytes());
        assert_eq!(pk_env.len(), SUITE_HEADER_LEN + MLDSA_PUBKEY_LEN, "0x0002 pk len");

        let msg = b"mldsa-only-suite";
        let sig = sign(&sk_env, msg).expect("mldsa-only sign");
        assert_eq!(sig.len(), SUITE_HEADER_LEN + MLDSA_SIG_LEN, "0x0002 sig len");
        assert!(verify(&pk_env, msg, &sig), "mldsa-only sig must verify");
        assert!(!verify(&pk_env, b"other", &sig), "wrong message must fail");

        // A 0x0001 (hybrid) pk cannot verify a 0x0002 sig — suite mismatch ⇒ false.
        let (hpk, _hsk) = generate_keypair();
        assert!(!verify(&hpk, msg, &sig), "hybrid pk must reject mldsa-only sig (suite mismatch)");
    }

    // ─── Addresses commit to the suite (design §2.4) ──────────────────────────
    // The address hashes the ENVELOPED pk, so a 0x0001 key and a 0x0002 key over
    // the SAME ML-DSA body hash to different addresses.
    #[test]
    fn addresses_commit_to_suite() {
        let (mpk, _msk) = mldsa65::keypair();
        let (fpk, _fsk) = falcon1024::keypair();
        let mut hybrid_body = mpk.as_bytes().to_vec();
        hybrid_body.extend_from_slice(fpk.as_bytes());
        let pk_0001 = wrap_envelope(SUITE_MLDSA65_FALCON1024, &hybrid_body);
        let pk_0002 = wrap_envelope(SUITE_MLDSA65_ONLY, mpk.as_bytes());
        let a1 = address_from_pubkey(&pk_0001, false);
        let a2 = address_from_pubkey(&pk_0002, false);
        assert_ne!(a1, a2, "different suites over the same ML-DSA key must hash to different addresses");
    }

    // ─── (C) No-panic fuzz: signature parse+verify path ───────────────────────
    // Adversarial/random bytes into `verify` must ALWAYS return a bool (the
    // consensus "parse-failure ⇒ false" rule), never panic. Uses a deterministic
    // SplitMix64 stream so failures are reproducible; cargo-fuzz `pow_verify`
    // provides coverage-guided fuzzing on nightly (see fuzz/).
    struct SplitMix64(u64);
    impl SplitMix64 {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn bytes(&mut self, len: usize) -> Vec<u8> {
            (0..len).map(|_| (self.next() & 0xFF) as u8).collect()
        }
    }

    #[test]
    fn fuzz_verify_never_panics() {
        // A real keypair/sig so some structured inputs land near the valid path.
        let (good_pk, sk) = generate_keypair();
        let good_sig = sign(&sk, b"m").unwrap();

        // Structured seed cases (boundary lengths around the split offsets AND
        // the 4-byte envelope header — design §4.3 invariant 2).
        let hdr = |suite: u16, body_len: usize| {
            let mut v = vec![0xB1u8, 0x0C];
            v.extend_from_slice(&suite.to_le_bytes());
            v.extend(std::iter::repeat(0u8).take(body_len));
            v
        };
        let structured: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (vec![], vec![]),
            // Envelope-length boundaries: len 0,1,2,3,4.
            (vec![], vec![0xB1]),
            (vec![0xB1], vec![0xB1, 0x0C]),
            (vec![0xB1, 0x0C], vec![0xB1, 0x0C, 0x01]),
            (vec![0xB1, 0x0C, 0x01], vec![0xB1, 0x0C, 0x01, 0x00]), // len 4 header-only
            // Good header + garbage body, various suites incl. reserved 0x0000/0xFFFF.
            (hdr(SUITE_MLDSA65_FALCON1024, MLDSA_PUBKEY_LEN), hdr(SUITE_MLDSA65_FALCON1024, MLDSA_SIG_LEN)),
            (hdr(SUITE_MLDSA65_ONLY, MLDSA_PUBKEY_LEN), hdr(SUITE_MLDSA65_ONLY, MLDSA_SIG_LEN)),
            (hdr(0x0000, MLDSA_PUBKEY_LEN), hdr(0x0000, MLDSA_SIG_LEN)),
            (hdr(0xFFFF, MLDSA_PUBKEY_LEN), hdr(0xFFFF, MLDSA_SIG_LEN)),
            // Legacy raw (no header) blobs — must now parse-fail ⇒ false, not panic.
            (vec![0u8; MLDSA_PUBKEY_LEN], vec![0u8; MLDSA_SIG_LEN]),
            (vec![0u8; MLDSA_PUBKEY_LEN + 1], vec![0u8; MLDSA_SIG_LEN + 1]),
            (good_pk.clone(), good_sig.clone()),
            (good_pk.clone(), vec![0xFFu8; good_sig.len()]),
            (vec![0u8; good_pk.len()], good_sig.clone()),
        ];
        for (pk, sig) in &structured {
            let r = std::panic::catch_unwind(|| verify(pk, b"m", sig));
            assert!(r.is_ok(), "verify panicked on a structured case");
        }

        // Random fuzz: pk/sig of varied lengths, random messages.
        let mut rng = SplitMix64(0xB10C_C0DE_1234_5678);
        for _ in 0..4000 {
            let pk_len = (rng.next() % 4000) as usize;
            let sig_len = (rng.next() % 4700) as usize;
            let msg_len = (rng.next() % 64) as usize;
            let pk = rng.bytes(pk_len);
            let sig = rng.bytes(sig_len);
            let msg = rng.bytes(msg_len);
            let r = std::panic::catch_unwind(|| verify(&pk, &msg, &sig));
            assert!(r.is_ok(), "verify panicked on random input (pk={pk_len}, sig={sig_len})");
        }

        // Mutate a valid sig one byte at a time — never panics, always false.
        for i in 0..good_sig.len().min(512) {
            let mut s = good_sig.clone();
            s[i] ^= 0xFF;
            let r = std::panic::catch_unwind(|| verify(&good_pk, b"m", &s));
            assert!(r.is_ok(), "verify panicked on single-byte mutation at {i}");
        }
    }

    #[test]
    fn fuzz_sign_never_panics_on_bad_secret_key() {
        // `sign` must return Ok/Err on any secret-key bytes, never panic.
        let mut rng = SplitMix64(0xDEAD_BEEF_F00D_0001);
        for _ in 0..2000 {
            let len = (rng.next() % 6500) as usize;
            let sk = rng.bytes(len);
            let r = std::panic::catch_unwind(|| {
                let _ = sign(&sk, b"fuzz-message");
            });
            assert!(r.is_ok(), "sign panicked on bad secret key (len={len})");
        }
    }

    // ─── Honest gap marker: full NIST-KAT wiring ──────────────────────────────
    #[test]
    #[ignore = "needs vendored NIST FIPS-204/Falcon .rsp KAT files + an AES-256-CTR \
                NIST DRBG to reproduce keygen; not sourceable in-tree today (only \
                PQClean nistkat.c ships, which is C-only and DRBG-seeded). The tests \
                above prove wrapper equivalence against the upstream crate oracle."]
    fn full_nist_kat_wiring_todo() {
        // TODO(audit P0.3): vendor the official ML-DSA-65 and Falcon-1024 NIST
        // KAT response files, implement the AES-256-CTR DRBG the KATs seed from,
        // reproduce (pk, sk, sig) for each seed, and assert byte-equality through
        // the pqcrypto primitives. This gives standards-traceable KATs on top of
        // the crate-oracle equivalence already proven here.
    }
}
