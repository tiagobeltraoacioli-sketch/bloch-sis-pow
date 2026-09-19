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

/// Maximum encoded signature length emitted by the currently supported signers.
/// Producers may reserve this before signing; this does not change wire rules.
pub fn max_signature_len() -> usize {
    SUITE_HEADER_LEN.saturating_add(MLDSA_SIG_LEN)
        .saturating_add(pqcrypto_falcon::falcon1024::signature_bytes())
}

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
    // Capacity hint only: saturating is exact for every real body and merely
    // a smaller-than-ideal hint in the impossible overflow case.
    let mut out = Vec::with_capacity(SUITE_HEADER_LEN.saturating_add(body.len()));
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
///   owns cleanup and clears the override on return or unwind.
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
    let mut seed32 = zeroize::Zeroizing::new([0u8; 32]);
    seed32.copy_from_slice(&seed[..32]);

    // Both keygens consume the unchanged stream within a non-escaping scope.
    // Cleanup also removes any accidentally forgotten nested legacy guards.
    let ((mpk, msk), (fpk, fsk)) = pqcrypto_internals::with_seeded_rng_scope(&seed32, || {
        (mldsa65::keypair(), falcon::keypair())
    });
    let mut pk = mpk.as_bytes().to_vec(); pk.extend_from_slice(&fpk);
    let mut sk = msk.as_bytes().to_vec(); sk.extend_from_slice(&fsk);
    Ok((wrap_envelope(SUITE_MLDSA65_FALCON1024, &pk),
        wrap_envelope(SUITE_MLDSA65_FALCON1024, &sk)))
}

// ── Signed-message domain (A4-M-4) ──────────────────────────────────────────
//
// `crypto::sign` signs its `message` argument verbatim. Every OTHER caller in
// the codebase signs a 32-byte digest whose PREIMAGE is domain-tagged (tx
// sighash, disclosure digest, PoS signing root, transport handshake). A
// "sign arbitrary user-supplied text" CLI/API flow that fed raw text straight
// into `crypto::sign` had no such tag: a 64-hex-character "message" is a raw
// 32-byte digest, indistinguishable at the signature layer from an attacker-
// chosen tx sighash preimage — a "prove you own this address by signing this
// challenge" flow could silently produce a valid transaction/disclosure
// signature. `signed_message_digest` closes that: length-prefixed AND
// domain-tagged, so no choice of `message` bytes (hex-looking or otherwise)
// can ever collide with another domain's preimage.

/// Domain tag for the "sign an arbitrary message" flow. Distinct from every
/// other signing domain in the codebase; not a prefix of any of them and none
/// of them are a prefix of this one.
pub const SIGNED_MESSAGE_DOMAIN: &[u8] = b"BLOCH-SIGNED-MESSAGE-v1";

/// The digest a "sign this message" flow actually signs: SHA3-256(
/// `SIGNED_MESSAGE_DOMAIN` ‖ `message.len() as u64 LE` ‖ `message`).
///
/// Callers MUST pass the message's raw bytes as the user typed/supplied them
/// — NEVER hex-decode user-supplied text first. Hex-decoding a 64-character
/// message before this point is exactly the bug this function exists to
/// close: it would turn a "sign this challenge" phishing prompt back into
/// "sign this raw 32-byte digest", regardless of what digest gets computed
/// afterwards.
pub fn signed_message_digest(message: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(SIGNED_MESSAGE_DOMAIN);
    h.update((message.len() as u64).to_le_bytes());
    h.update(message);
    h.finalize().into()
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
/// old chain produced. A mismatch still ⇒ verify false via the body checks.
/// This restores spendability of pre-envelope carry-over funds without
/// weakening enveloped verification. CONSENSUS-CRITICAL.
fn parse_envelope_or_legacy(b: &[u8]) -> (u16, &[u8]) {
    match parse_envelope(b) {
        Some((suite, body)) => (suite, body),
        None => (SUITE_MLDSA65_FALCON1024, b),
    }
}

/// Exact byte length of a raw (non-enveloped) legacy hybrid ML-DSA-65 ‖
/// Falcon-1024 PUBLIC key — `MLDSA_PUBKEY_LEN` plus the Falcon-1024 public-key
/// length, both fixed. An ENVELOPED pubkey of the same suite is always
/// exactly `SUITE_HEADER_LEN` bytes LONGER, so length alone disambiguates
/// legacy-vs-enveloped with no ambiguity — see [`parse_pubkey_envelope_or_legacy`].
fn legacy_hybrid_pubkey_len() -> usize {
    MLDSA_PUBKEY_LEN + falcon::pubkey_len()
}

/// Public-key-specific version of [`parse_envelope_or_legacy`] (audit A4
/// lows / legacy pubkey fallback).
///
/// A raw legacy pubkey has a `1/65536` chance of happening to start with the
/// two-byte magic `[0xB1, 0x0C]` — plain hybrid key material, not a crafted
/// attack. `parse_envelope_or_legacy` would then misclassify it as enveloped
/// (treating its bytes 2..4 as a bogus suite id), corrupting the suite
/// dispatch in `verify` and permanently locking those funds even though the
/// key and signature are both genuine.
///
/// Length resolves this with no heuristics: an ENVELOPED hybrid pubkey is
/// *exactly* `SUITE_HEADER_LEN` (4) bytes longer than the raw legacy
/// encoding, so the two encodings can never collide on length. Checking the
/// exact legacy length FIRST — before the magic-byte heuristic — means a
/// legacy pubkey is classified correctly regardless of its leading bytes.
fn parse_pubkey_envelope_or_legacy(b: &[u8]) -> (u16, &[u8]) {
    if b.len() == legacy_hybrid_pubkey_len() {
        return (SUITE_MLDSA65_FALCON1024, b);
    }
    parse_envelope_or_legacy(b)
}

/// Whether a public-key encoding names the live hybrid suite.
///
/// This is a format/policy predicate, not a cryptographic verification: it
/// accepts the exact legacy raw `ML-DSA-65 || Falcon-1024` key shape and the
/// exact suite-0x0001 envelope shape.  In particular it refuses suite 0x0002
/// even though [`verify`] deliberately retains support for that crypto-agility
/// suite.  Admission callers use this distinction to keep new ML-DSA-only
/// transfers out of the live network without changing historical consensus.
pub fn is_hybrid_public_key(public_key_bytes: &[u8]) -> bool {
    let (suite, body) = parse_pubkey_envelope_or_legacy(public_key_bytes);
    suite == SUITE_MLDSA65_FALCON1024 && body.len() == legacy_hybrid_pubkey_len()
}

pub fn verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    // Suite-ID dispatch (design §2.3). Accepts enveloped objects AND legacy
    // pre-envelope (raw hybrid) objects from the carry-over. A pk of one suite
    // must not verify a sig of another. Any body parse failure ⇒ false, never a
    // panic (consensus rule). NO security is claimed.
    let (pk_suite, pk_body) = parse_pubkey_envelope_or_legacy(public_key_bytes);
    let (sig_suite, sig_body) = parse_envelope_or_legacy(signature_bytes);
    verify_parsed(pk_suite, pk_body, message, sig_suite, sig_body)
}

/// Verify objects whose trusted format contract requires an explicit suite envelope.
///
/// Unlike [`verify`], this entry point never falls back to the legacy raw hybrid
/// encoding and therefore never guesses whether signature bytes beginning with
/// the envelope magic are raw material or a header. Use it only for versioned
/// formats that already require both their key and signature to be enveloped.
/// Historical consensus and carry-over wallet verification must keep using
/// [`verify`] or [`verify_legacy_hybrid_raw`] according to their trusted format
/// metadata.
pub fn verify_enveloped(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> bool {
    let Some((pk_suite, pk_body)) = parse_envelope(public_key_bytes) else {
        return false;
    };
    let Some((sig_suite, sig_body)) = parse_envelope(signature_bytes) else {
        return false;
    };
    verify_parsed(pk_suite, pk_body, message, sig_suite, sig_body)
}

/// Verify explicitly enveloped objects and require canonical primitive encodings.
///
/// This opt-in entry point has the same strict envelope and suite dispatch as
/// [`verify_enveloped`]. For hybrid suite `0x0001`, it additionally rejects
/// Falcon's alternate 1,280-byte zero-padded representation. Existing
/// consensus and compatibility callers are intentionally not migrated here.
pub fn verify_enveloped_canonical(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> bool {
    let Some((pk_suite, pk_body)) = parse_envelope(public_key_bytes) else {
        return false;
    };
    let Some((sig_suite, sig_body)) = parse_envelope(signature_bytes) else {
        return false;
    };
    verify_parsed_with_falcon(
        pk_suite,
        pk_body,
        message,
        sig_suite,
        sig_body,
        falcon::verify_canonical,
    )
}

fn verify_parsed(
    pk_suite: u16,
    pk_body: &[u8],
    message: &[u8],
    sig_suite: u16,
    sig_body: &[u8],
) -> bool {
    verify_parsed_with_falcon(
        pk_suite,
        pk_body,
        message,
        sig_suite,
        sig_body,
        falcon::verify,
    )
}

fn verify_parsed_with_falcon(
    pk_suite: u16,
    pk_body: &[u8],
    message: &[u8],
    sig_suite: u16,
    sig_body: &[u8],
    verify_falcon: fn(&[u8], &[u8], &[u8]) -> bool,
) -> bool {
    if pk_suite != sig_suite {
        debug!("crypto::verify: suite mismatch (pk={:#06x}, sig={:#06x})", pk_suite, sig_suite);
        return false;
    }
    match pk_suite {
        SUITE_MLDSA65_FALCON1024 => {
            verify_hybrid_mldsa_falcon_with(pk_body, message, sig_body, verify_falcon)
        }
        SUITE_MLDSA65_ONLY       => verify_mldsa65_only(pk_body, message, sig_body),
        other => { debug!("crypto::verify: unknown/reserved suite {:#06x}", other); false }
    }
}

/// Explicit verification of legacy raw ML-DSA-65 || Falcon-1024 objects.
///
/// Use only when trusted format metadata says BOTH the key and signature are
/// raw legacy hybrid bytes. No magic-byte classification is performed, so a
/// raw signature beginning with `B1 0C` is not mistaken for an envelope.
/// Enveloped keys are rejected by their different length; do not strip an
/// untrusted envelope and retry here after another verification policy fails.
/// This opt-in API does not change [`verify`] or any historical consensus
/// caller. The legacy heuristic's ambiguous signatures remain a separate
/// consensus compatibility/activation issue.
pub fn verify_legacy_hybrid_raw(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    public_key_bytes.len() == legacy_hybrid_pubkey_len()
        && verify_hybrid_mldsa_falcon(public_key_bytes, message, signature_bytes)
}

/// Verify explicitly raw legacy hybrid objects with canonical Falcon encoding.
///
/// This is the canonical-policy counterpart of [`verify_legacy_hybrid_raw`].
/// It is only appropriate when trusted format metadata already requires BOTH
/// objects to use the raw legacy hybrid layout. It performs no envelope
/// detection or fallback and rejects Falcon's alternate zero-padded encoding.
/// Existing consensus and compatibility callers are intentionally unchanged.
pub fn verify_legacy_hybrid_raw_canonical(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> bool {
    public_key_bytes.len() == legacy_hybrid_pubkey_len()
        && verify_hybrid_mldsa_falcon_with(
            public_key_bytes,
            message,
            signature_bytes,
            falcon::verify_canonical,
        )
}

/// Suite 0x0001 verifier — the pre-envelope `verify` body verbatim, now
/// operating on the post-header BODY slices. The `<=` length guards, the
/// `from_bytes` parse-fail⇒false, and the ML-DSA-AND-Falcon combiner are all
/// preserved: BOTH halves must verify (defence in depth across two lattice
/// families). Behaviour on 0x0001 objects is byte-for-byte identical to the
/// legacy path except for the 4-byte header strip.
fn verify_hybrid_mldsa_falcon(pk_body: &[u8], message: &[u8], sig_body: &[u8]) -> bool {
    verify_hybrid_mldsa_falcon_with(pk_body, message, sig_body, falcon::verify)
}

fn verify_hybrid_mldsa_falcon_with(
    pk_body: &[u8],
    message: &[u8],
    sig_body: &[u8],
    verify_falcon: fn(&[u8], &[u8], &[u8]) -> bool,
) -> bool {
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
    verify_falcon(fpk, message, fsig)
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

/// Verify a raw (non-enveloped) ML-DSA-65 detached signature — the public
/// counterpart of [`falcon::verify`] for the other half of the hybrid.
///
/// The Genesis-4 weak-subjectivity envelope verifier
/// (`bloch-pos-committee::ws` via the node's `HybridKeyVerifier`
/// implementation) receives the two hybrid halves already split at the fixed
/// points and must verify each under its own primitive. Exported so that
/// caller does not have to counterfeit a suite envelope to reach the ML-DSA
/// body verifier — one primitive, one entry point per half. Exact-length
/// bodies required; malformed input ⇒ `false`, never a panic (consensus
/// rule).
pub fn verify_mldsa65_raw(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    verify_mldsa65_only(public_key_bytes, message, signature_bytes)
}

/// Split a suite-enveloped object (public key, secret key, or signature) into
/// `(suite_id, body)`, or `None` if the bytes carry no valid envelope header.
///
/// Public for Genesis-4 node tooling that must re-frame enveloped objects
/// into the raw halves the PoS committee crate consumes (weak-subjectivity
/// checkpoint envelopes carry raw `mldsa ‖ falcon` bodies, not suite
/// envelopes). Read-only view; exposing it here keeps the 4-byte header
/// format defined in exactly one place.
pub fn split_envelope(bytes: &[u8]) -> Option<(u16, &[u8])> {
    parse_envelope(bytes)
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

/// Repository-owned per-index seed used for key generation. The public
/// `diversified_seed` return remains caller-owned for API compatibility; this
/// wrapper keeps the internal copy under wiping ownership for its full use.
fn zeroizing_diversified_seed(master_seed: &[u8], index: u32) -> zeroize::Zeroizing<[u8; 32]> {
    zeroize::Zeroizing::new(diversified_seed(master_seed, index))
}

/// Diversified keypair for `index` — independent, unlinkable, deterministic.
pub fn diversified_keypair(master_seed: &[u8], index: u32)
    -> Result<(Vec<u8>, Vec<u8>), CryptoError>
{
    let seed = zeroizing_diversified_seed(master_seed, index);
    generate_keypair_from_seed(&seed[..])
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
    #[test]
    fn diversified_keypair_owns_exact_subseed_under_zeroizing_drop() {
        use zeroize::Zeroize;

        let master_seed = [0x5au8; 64];
        let index = 0x1020_3040;
        let public_seed = diversified_seed(&master_seed, index);
        let mut owned_seed = zeroizing_diversified_seed(&master_seed, index);

        assert!(std::mem::needs_drop::<zeroize::Zeroizing<[u8; 32]>>());
        assert_eq!(&owned_seed[..], &public_seed);

        let expected = generate_keypair_from_seed(&public_seed).unwrap();
        let actual = diversified_keypair(&master_seed, index).unwrap();
        assert_eq!(actual, expected, "zeroizing ownership must not change key bytes");

        // Structural evidence for the live owner; no post-Drop memory claim.
        owned_seed.zeroize();
        assert!(owned_seed.iter().all(|byte| *byte == 0));
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
// deterministic (integer), so it is consensus-safe. Falcon *signing* is pinned
// to PQClean's `clean` variant (PoS finding F1, BLOCH-FALCON-ONLINE-SIGNING.md
// §3.2): integer-only emulated IEEE-754 Gaussian sampling, constant-time by
// construction and bit-exact across platforms — the native floating-point
// variants (avx2/aarch64) are excluded via `default-features = false` and
// guarded by the tripwire test + KAT below and scripts/falcon-clean-guard.sh.
pub mod falcon {
    use pqcrypto_falcon::falcon1024;
    use pqcrypto_traits::sign::{PublicKey, SecretKey, DetachedSignature};
    use super::CryptoError;

    /// Falcon-1024 public-key length (bytes).
    pub fn pubkey_len() -> usize { falcon1024::public_key_bytes() }

    /// Length of Falcon-1024's alternate fixed-width padded signature.
    ///
    /// The compatibility verifier accepts this representation; canonical
    /// policies use the value to construct or identify migration fixtures.
    pub fn padded_signature_len() -> usize {
        pqcrypto_falcon::falconpadded1024::signature_bytes()
    }

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

    /// Verify only Falcon-1024's compact, non-padded detached encoding.
    ///
    /// The historical verifier deliberately accepts PQClean's alternate
    /// 1280-byte zero-padded representation. That is consensus compatibility,
    /// but it also gives one mathematical signature two byte encodings. New
    /// non-consensus formats can opt into this entry point to require the exact
    /// compact encoding emitted by [`sign`].
    pub fn verify_canonical(
        public_key_bytes: &[u8],
        message: &[u8],
        signature_bytes: &[u8],
    ) -> bool {
        is_compact_signature_encoding(signature_bytes)
            && verify(public_key_bytes, message, signature_bytes)
    }

    const FALCON1024_HEADER: u8 = 0x30 + 10;
    const FALCON_NONCE_LEN: usize = 40;
    const FALCON1024_COEFFICIENTS: usize = 1024;

    fn is_compact_signature_encoding(signature: &[u8]) -> bool {
        if signature.len() <= 1 + FALCON_NONCE_LEN || signature[0] != FALCON1024_HEADER {
            return false;
        }
        let encoded = &signature[1 + FALCON_NONCE_LEN..];
        compact_encoding_len(encoded) == Some(encoded.len())
    }

    /// Length-only mirror of PQClean's `comp_decode` framing. It validates the
    /// unique sign/magnitude+unary encoding without performing signature math.
    fn compact_encoding_len(encoded: &[u8]) -> Option<usize> {
        let mut accumulator = 0u32;
        let mut remaining_bits = 0u32;
        let mut consumed = 0usize;

        for _ in 0..FALCON1024_COEFFICIENTS {
            let next = *encoded.get(consumed)?;
            consumed += 1;
            accumulator = (accumulator << 8) | u32::from(next);
            let first = accumulator >> remaining_bits;
            let sign = first & 128;
            let mut magnitude = first & 127;

            loop {
                if remaining_bits == 0 {
                    let next = *encoded.get(consumed)?;
                    consumed += 1;
                    accumulator = (accumulator << 8) | u32::from(next);
                    remaining_bits = 8;
                }
                remaining_bits -= 1;
                if ((accumulator >> remaining_bits) & 1) != 0 {
                    break;
                }
                magnitude += 128;
                if magnitude > 2047 {
                    return None;
                }
            }
            if sign != 0 && magnitude == 0 {
                return None;
            }
        }

        let unused_mask = (1u32 << remaining_bits).wrapping_sub(1);
        if accumulator & unused_mask != 0 {
            return None;
        }
        Some(consumed)
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

        #[test]
        fn canonical_verifier_rejects_the_legacy_zero_padded_variant() {
            let (pk, sk) = keypair();
            let msg = b"falcon-canonical-encoding";
            let sig = sign(&sk, msg).unwrap();
            assert!(verify_canonical(&pk, msg, &sig));

            let mut padded = sig.clone();
            padded.resize(
                pqcrypto_falcon::falconpadded1024::signature_bytes(),
                0,
            );
            assert_ne!(
                padded, sig,
                "fresh compact signature must leave padding room"
            );
            assert!(
                verify(&pk, msg, &padded),
                "legacy verifier accepts PQClean padding"
            );
            assert!(!verify_canonical(&pk, msg, &padded));

            assert!(!verify_canonical(&pk, msg, &sig[..sig.len() - 1]));
            let mut tampered = sig;
            tampered[1] ^= 1;
            assert!(!verify_canonical(&pk, msg, &tampered));
        }

        // ── F1 guard: the constant-time `clean` path must be the ONLY Falcon ──
        // implementation in the binary (BLOCH-FALCON-ONLINE-SIGNING.md §3.2).
        //
        // `pqcrypto-falcon`'s DEFAULT features ("avx2", "neon") compile PQClean's
        // native floating-point variants and runtime-dispatch signing to them
        // (AVX2 doubles on x86_64, `typedef double fpr` on aarch64). A PoS
        // validator signs on a publicly known schedule, so Falcon signing must
        // run PQClean's `clean` variant: integer-emulated IEEE-754, constant-time
        // by construction. The workspace therefore declares the crate with
        // `default-features = false`.
        //
        // A Cargo.toml declaration alone is not proof — features are ADDITIVE,
        // so any workspace member (or a future dependency) re-enabling the
        // defaults silently restores native-FP dispatch for every build. This
        // test inspects the test executable itself: when the avx2/neon features
        // are off, the FP variants' C files are never compiled and their symbols
        // (`PQCLEAN_FALCON1024_AVX2_*`, `PQCLEAN_FALCON1024_AARCH64_*`) cannot
        // exist in the binary; when a feature is re-enabled, the dispatch code
        // references them and the linker must keep them. Symbol ABSENCE is
        // therefore a faithful tripwire, on every target, for "the constant-time
        // path is the only path".
        //
        // The needles are assembled at runtime from fragments so the test's own
        // string literals cannot produce a false positive in the scan.

        /// Plain forward byte-substring scan (no regex/memmem dependency).
        fn binary_contains(haystack: &[u8], needle: &[u8]) -> bool {
            if needle.is_empty() || haystack.len() < needle.len() {
                return false;
            }
            let first = needle[0];
            let mut i = 0;
            while i + needle.len() <= haystack.len() {
                if haystack[i] == first && &haystack[i..i + needle.len()] == needle {
                    return true;
                }
                i += 1;
            }
            false
        }

        #[test]
        fn falcon_native_fp_variants_are_not_linked() {
            let exe = std::env::current_exe().expect("current_exe");
            let bytes = std::fs::read(&exe).expect("read test executable");

            // Assembled at runtime — the concatenated needle never appears as a
            // contiguous literal in this test's own rodata.
            let sym = |variant: &str| format!("PQCLEAN_{}{}_{}_crypto_sign", "FALCON", "1024", variant);
            let clean = sym("CLEAN");
            let avx2 = sym("AVX2");
            let aarch64 = sym("AARCH64");

            // Control: the `clean` symbols MUST be visible. If this fails, the
            // binary's symbol names are not observable (e.g. stripped test
            // binary) and the absence checks below would be vacuous — fail
            // loudly instead of false-passing.
            assert!(
                binary_contains(&bytes, clean.as_bytes()),
                "control failed: `{clean}` not found in {} — symbol names are not \
                 observable in this binary, so this guard cannot run (is the test \
                 binary stripped?)",
                exe.display()
            );

            // Tripwire: no native floating-point Falcon variant may be linked.
            for fp in [&avx2, &aarch64] {
                assert!(
                    !binary_contains(&bytes, fp.as_bytes()),
                    "NATIVE FLOATING-POINT Falcon implementation `{fp}` is linked \
                     into the binary. Someone re-enabled pqcrypto-falcon's default \
                     features (avx2/neon) somewhere in the workspace. Under PoS the \
                     validator signs on a public schedule and must use PQClean's \
                     integer-only constant-time `clean` variant exclusively — see \
                     BLOCH-FALCON-ONLINE-SIGNING.md §3.2 and the pqcrypto-falcon \
                     entries in Cargo.toml (`default-features = false`)."
                );
            }
        }

        // ── F1 KAT: seeded Falcon-1024 keygen + sign pinned byte-for-byte ────
        //
        // Purpose: prove the switch to the `clean` variant did NOT change the
        // wire format or the produced bytes. PQClean requires all variants of a
        // scheme to be KAT-compatible (same randombytes stream → same key/sig
        // bytes), so these pins hold across `clean`/avx2/aarch64 AND across
        // platforms — `clean` is bit-exact integer emulation. A dependency bump
        // that changed the produced bytes (format break, sampler change, e.g. a
        // silent move to FN-DSA semantics) fails here before it can hit
        // consensus. NOTE: precisely because the variants are KAT-compatible,
        // this test does NOT prove which variant runs — that is
        // `falcon_native_fp_variants_are_not_linked`'s job. The two tests
        // together are the guard.
        //
        // Seeded signing is REGRESSION PINNING ONLY: production Falcon signing
        // must stay randomized (fresh salt per signature — the property that
        // neutralizes the "Sleeping Falcon" FP-divergence attack, eprint
        // 2024/1709). Never seed the RNG around a production signer.
        #[test]
        fn falcon_clean_seeded_kat_is_byte_stable_and_verifies() {
            use sha3::{Digest, Sha3_256};

            const KAT_SEED: [u8; 32] = [0xB1; 32];
            const KAT_MSG: &[u8] = b"bloch-pos-falcon-clean-kat-v1";

            // Pinned on pqcrypto-falcon 0.4.1, `clean` variant (aarch64 host;
            // bit-exact on every platform by construction).
            const KAT_PK_HASH: &str =
                "afc79ea102992a5081b8172b55fb7c14e01ff2a74501a8577d1fe4df094c2375";
            const KAT_SIG_HASH: &str =
                "645bf4db96650515c016aa1f615b78ad4dac5985363abdfbb8a3e0fc4a5d2e24";
            const KAT_SIG_LEN: usize = 1271;

            let (pk, sk, sig) = pqcrypto_internals::with_seeded_rng_scope(&KAT_SEED, || {
                let (pk, sk) = keypair();
                let sig = sign(&sk, KAT_MSG).expect("seeded falcon sign");
                (pk, sk, sig)
            });
            // Falcon signatures are variable-length in general; under a fixed
            // randomness stream the length is fixed too, so pin it as well.
            assert_eq!(sig.len(), KAT_SIG_LEN, "seeded Falcon signature length drifted");
            assert_eq!(
                hex::encode(Sha3_256::digest(&pk)),
                KAT_PK_HASH,
                "seeded Falcon-1024 public key drifted from the pinned KAT"
            );
            assert_eq!(
                hex::encode(Sha3_256::digest(&sig)),
                KAT_SIG_HASH,
                "seeded Falcon-1024 signature drifted from the pinned KAT"
            );

            // Compatibility both ways: the pinned signature verifies, and a
            // fresh (OS-randomness) signature under the same key verifies too —
            // the format change surface is zero.
            assert!(verify(&pk, KAT_MSG, &sig), "pinned KAT signature must verify");
            let fresh = sign(&sk, KAT_MSG).expect("randomized falcon sign");
            assert!(verify(&pk, KAT_MSG, &fresh), "randomized signature must verify");
            assert_ne!(fresh, sig, "production signing must remain randomized (fresh salt)");
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

    #[test]
    fn valid_magic_prefixed_raw_signature_requires_explicit_legacy_policy() {
        const MESSAGE: &[u8] = b"BLOCH-CR10-MAGIC-PREFIX-FIXTURE-v1";
        const SEARCH_COUNTER: u64 = 23_156;
        const SIGNING_SEED_HEX: &str =
            "5d051b8c445a2f169a9a0104877500c39332cb493ec6de2723cb37dfbb233042";

        let (enveloped_pk, enveloped_sk) =
            generate_keypair_from_seed(&[0x64; 32]).unwrap();
        let mut h = Sha3_256::new();
        h.update(b"bloch/cr10/signing-rng/v1");
        h.update(SEARCH_COUNTER.to_le_bytes());
        let signing_seed: [u8; 32] = h.finalize().into();
        assert_eq!(hex::encode(signing_seed), SIGNING_SEED_HEX);

        let enveloped_sig = pqcrypto_internals::with_seeded_rng_scope(
            &signing_seed,
            || sign(&enveloped_sk, MESSAGE).unwrap(),
        );
        let raw_pk = &enveloped_pk[SUITE_HEADER_LEN..];
        let raw_sig = &enveloped_sig[SUITE_HEADER_LEN..];

        assert_eq!(&raw_sig[..2], &SUITE_MAGIC, "fixture must hit the ambiguity");
        assert!(
            verify_legacy_hybrid_raw(raw_pk, MESSAGE, raw_sig),
            "the magic-prefixed raw signature is cryptographically genuine"
        );
        assert!(verify_legacy_hybrid_raw_canonical(raw_pk, MESSAGE, raw_sig));
        assert!(
            !verify(raw_pk, MESSAGE, raw_sig),
            "generic autodetection must misclassify the raw magic prefix"
        );

        let (misclassified_suite, _) = parse_envelope(raw_sig).unwrap();
        assert_ne!(
            misclassified_suite,
            SUITE_MLDSA65_FALCON1024,
            "bytes after the coincidental magic are not trusted format metadata"
        );
    }

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

    #[test]
    fn strict_enveloped_verifier_rejects_raw_and_mixed_encodings() {
        let msg = b"strict-enveloped-format";
        let (pk, sk) = generate_keypair();
        let sig = sign(&sk, msg).unwrap();
        let raw_pk = &pk[SUITE_HEADER_LEN..];
        let raw_sig = &sig[SUITE_HEADER_LEN..];

        assert!(verify_enveloped(&pk, msg, &sig));
        assert!(!verify_enveloped(raw_pk, msg, &sig));
        assert!(!verify_enveloped(&pk, msg, raw_sig));
        assert!(!verify_enveloped(raw_pk, msg, raw_sig));
        assert!(!verify_enveloped(&pk, b"other", &sig));
    }

    #[test]
    fn canonical_enveloped_verifier_rejects_padded_falcon_half() {
        let msg = b"canonical-enveloped-format";
        let (pk, sk) = generate_keypair_from_seed(&[0x58; 32]).unwrap();
        let sig = pqcrypto_internals::with_seeded_rng_scope(&[0xA5; 32], || {
            sign(&sk, msg).unwrap()
        });

        assert!(verify_enveloped(&pk, msg, &sig));
        assert!(verify_enveloped_canonical(&pk, msg, &sig));

        let falcon_offset = SUITE_HEADER_LEN + MLDSA_SIG_LEN;
        let padded_len = falcon_offset + pqcrypto_falcon::falconpadded1024::signature_bytes();
        assert!(
            sig.len() < padded_len,
            "pinned compact signature must fit padded form"
        );
        let mut padded = sig.clone();
        padded.resize(padded_len, 0);

        assert!(
            verify_enveloped(&pk, msg, &padded),
            "compatibility verifier must retain the accepted padded form"
        );
        assert!(!verify_enveloped_canonical(&pk, msg, &padded));
        assert!(!verify_enveloped_canonical(
            &pk[SUITE_HEADER_LEN..],
            msg,
            &sig
        ));

        let (mpk, msk) = mldsa65::keypair();
        let mldsa_pk = wrap_envelope(SUITE_MLDSA65_ONLY, mpk.as_bytes());
        let mldsa_sk = wrap_envelope(SUITE_MLDSA65_ONLY, msk.as_bytes());
        let mldsa_sig = sign(&mldsa_sk, msg).unwrap();
        assert!(verify_enveloped_canonical(&mldsa_pk, msg, &mldsa_sig));
    }

    #[test]
    fn canonical_raw_verifier_rejects_padded_falcon_half_without_sniffing() {
        let msg = b"canonical-raw-legacy-format";
        let (mpk, msk) = mldsa65::keypair();
        let (fpk, fsk) = falcon1024::keypair();

        let mut pk = mpk.as_bytes().to_vec();
        pk.extend_from_slice(fpk.as_bytes());
        let mut sig = mldsa65::detached_sign(msg, &msk).as_bytes().to_vec();
        sig.extend_from_slice(falcon1024::detached_sign(msg, &fsk).as_bytes());

        assert!(verify_legacy_hybrid_raw(&pk, msg, &sig));
        assert!(verify_legacy_hybrid_raw_canonical(&pk, msg, &sig));

        let padded_len = MLDSA_SIG_LEN
            + pqcrypto_falcon::falconpadded1024::signature_bytes();
        assert!(sig.len() < padded_len, "compact fixture must leave padding room");
        let mut padded = sig.clone();
        padded.resize(padded_len, 0);

        assert!(
            verify_legacy_hybrid_raw(&pk, msg, &padded),
            "compatibility raw verifier must retain padded acceptance"
        );
        assert!(!verify_legacy_hybrid_raw_canonical(&pk, msg, &padded));
        assert!(!verify_legacy_hybrid_raw_canonical(
            &wrap_envelope(SUITE_MLDSA65_FALCON1024, &pk),
            msg,
            &sig,
        ));
        assert!(!verify_legacy_hybrid_raw_canonical(
            &pk,
            msg,
            &wrap_envelope(SUITE_MLDSA65_FALCON1024, &sig),
        ));
        assert!(!verify_legacy_hybrid_raw_canonical(&pk, b"other", &sig));
    }

    /// A genuine LEGACY (non-enveloped) hybrid object — no magic, no header,
    /// exactly the carry-over encoding — must still verify through the public
    /// `verify()` entry point via the length-based classification.
    #[test]
    fn genuine_legacy_raw_hybrid_verifies_through_bloch() {
        let msg = b"legacy-carry-over-raw-hybrid";
        let (mpk, msk) = mldsa65::keypair();
        let (fpk, fsk) = falcon1024::keypair();

        let mut pk_raw = mpk.as_bytes().to_vec();
        pk_raw.extend_from_slice(fpk.as_bytes());
        let mut sig_raw = mldsa65::detached_sign(msg, &msk).as_bytes().to_vec();
        sig_raw.extend_from_slice(falcon1024::detached_sign(msg, &fsk).as_bytes());

        assert_eq!(pk_raw.len(), legacy_hybrid_pubkey_len());
        assert!(verify_legacy_hybrid_raw(&pk_raw, msg, &sig_raw));
        assert!(!verify_legacy_hybrid_raw(&pk_raw, b"other", &sig_raw));
        assert!(!verify_legacy_hybrid_raw(&wrap_envelope(SUITE_MLDSA65_FALCON1024, &pk_raw), msg, &sig_raw));
        assert!(!verify_legacy_hybrid_raw(&pk_raw, msg, &wrap_envelope(SUITE_MLDSA65_FALCON1024, &sig_raw)));
        // Historical auto-detection remains unchanged. Its rare raw-signature
        // collision is deliberately not promoted into an unversioned fallback.
        if !sig_raw.starts_with(&[0xb1, 0x0c]) {
            assert!(verify(&pk_raw, msg, &sig_raw), "unambiguous raw legacy hybrid must verify");
        }
        assert!(!verify(&pk_raw, b"other", &sig_raw));
    }

    /// A4 lows (legacy pubkey fallback): a raw legacy pubkey that happens to
    /// start with the 4-byte suite header's magic `[0xB1, 0x0C]` must NOT be
    /// misclassified as an enveloped object. A genuine collision is a
    /// 1-in-65536 event over real key material — far too rare to brute-force
    /// a real ML-DSA-65 keypair for in a test — so this constructs the
    /// SHAPE directly: a buffer of exactly `legacy_hybrid_pubkey_len()` bytes
    /// leading with the magic. Length alone must win the classification.
    #[test]
    fn legacy_pubkey_starting_with_envelope_magic_is_not_misclassified() {
        let len = legacy_hybrid_pubkey_len();
        let mut raw_pk = vec![0xABu8; len];
        raw_pk[0] = 0xB1;
        raw_pk[1] = 0x0C;

        let (suite, body) = parse_pubkey_envelope_or_legacy(&raw_pk);
        assert_eq!(suite, SUITE_MLDSA65_FALCON1024, "exact legacy length must win over the magic heuristic");
        assert_eq!(body.len(), len, "the WHOLE buffer is the body — no header may be stripped");

        // Contrast: the magic-only heuristic (`parse_envelope_or_legacy`, still
        // used for signatures, whose length is not fixed) DOES misread this
        // buffer as enveloped and strips 4 bytes — demonstrating the bug this
        // pubkey-specific fix closes.
        let (old_suite, old_body) = parse_envelope_or_legacy(&raw_pk);
        assert_eq!(old_body.len(), len - SUITE_HEADER_LEN, "sanity: the naive heuristic strips a header here");
        assert_ne!(old_suite, suite, "sanity: the naive heuristic derives a bogus suite id from key bytes");
    }

    #[test]
    fn hybrid_public_key_policy_distinguishes_live_and_crypto_agility_suites() {
        let raw_hybrid = vec![0xabu8; legacy_hybrid_pubkey_len()];
        let enveloped_hybrid = wrap_envelope(SUITE_MLDSA65_FALCON1024, &raw_hybrid);
        let mldsa_only = wrap_envelope(SUITE_MLDSA65_ONLY, &vec![0xcdu8; MLDSA_PUBKEY_LEN]);

        assert!(is_hybrid_public_key(&raw_hybrid));
        assert!(is_hybrid_public_key(&enveloped_hybrid));
        assert!(!is_hybrid_public_key(&mldsa_only));
        assert!(!is_hybrid_public_key(&enveloped_hybrid[..enveloped_hybrid.len() - 1]));

        // The exact legacy length wins over coincidental magic, just as it
        // does in verification; old funds are not stranded by this policy.
        let mut magic_collision = raw_hybrid;
        magic_collision[..2].copy_from_slice(&SUITE_MAGIC);
        magic_collision[2..4].copy_from_slice(&SUITE_MLDSA65_ONLY.to_le_bytes());
        assert!(is_hybrid_public_key(&magic_collision));
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
        let sig = pqcrypto_internals::with_seeded_rng_scope(&GOLDEN_SEED, || {
            sign(&sk, GOLDEN_MSG).unwrap()
        });
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
        assert!(s1.len() <= max_signature_len());
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
        assert!(sig.len() <= max_signature_len());
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
