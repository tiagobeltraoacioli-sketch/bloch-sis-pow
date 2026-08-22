// SPDX-License-Identifier: AGPL-3.0-or-later
//! Test matrix for the §6.2 precompile.
//!
//! House rules this file obeys:
//!   * every negative test carries its CONTROL half — the same assertion on the
//!     input that must pass, so a verifier stuck at `false` cannot pass the suite;
//!   * every load-bearing rule is proved BY MUTATION — the mutant is compiled
//!     right here, fed a witness input, and asserted to disagree with the
//!     reference. A rule with no mutant that can see it is a rule that is not
//!     being tested (a 489-test suite once survived reverting two consensus
//!     sites; that is what this section exists to prevent).

use bloch_crypto::crypto as bc;
use pq_precompile_spike::*;
use sha3::{Digest, Sha3_256};

const SUITE_MLDSA65_ONLY: u16 = 0x0002;
const MLDSA_PUBKEY_LEN: usize = 1_952;
const MLDSA_SECRET_LEN: usize = 4_032;

fn fixture() -> (Vec<u8>, Vec<u8>, [u8; 32], Vec<u8>) {
    let (pk, sk) = bc::generate_keypair();
    let msg = [0x11u8; 32];
    let sig = bc::sign(&sk, &msg).expect("sign");
    (pk, sk, msg, sig)
}

fn envelope(suite: u16, body: &[u8]) -> Vec<u8> {
    let mut v = vec![0xB1, 0x0C];
    v.extend_from_slice(&suite.to_le_bytes());
    v.extend_from_slice(body);
    v
}

// ── 1. The function itself ───────────────────────────────────────────────────

#[test]
fn valid_hybrid_signature_returns_the_signers_address() {
    let (pk, _sk, msg, sig) = fixture();
    let out = pq_verify(&encode_input(&msg, &pk, &sig));
    let addr = match out {
        Outcome::Valid(a) => a,
        Outcome::Invalid => panic!("valid signature must verify"),
    };
    // The returned 20 bytes ARE the account's Bloch address payload: the same
    // bytes `address_from_pubkey` puts in front of its checksum.
    let expect = &bc::address_from_pubkey(&pk, false)["bloch1q".len()..][..40];
    assert_eq!(hex::encode(addr), expect, "returned address must be the chain's");
    // ecrecover-shaped return word: 12 zero bytes then the address.
    let w = out.to_word();
    assert_eq!(&w[..12], &[0u8; 12]);
    assert_eq!(&w[12..], &addr);
}

#[test]
fn wrong_message_fails_and_the_right_one_passes() {
    let (pk, _sk, msg, sig) = fixture();
    assert!(pq_verify(&encode_input(&msg, &pk, &sig)).is_valid(), "CONTROL");
    let other = [0x22u8; 32];
    assert!(!pq_verify(&encode_input(&other, &pk, &sig)).is_valid());
}

#[test]
fn tampering_with_either_half_fails() {
    let (pk, _sk, msg, sig) = fixture();
    assert!(pq_verify(&encode_input(&msg, &pk, &sig)).is_valid(), "CONTROL");
    // ML-DSA half (bytes 4..3313 of the envelope).
    let mut a = sig.clone();
    a[10] ^= 0x01;
    assert!(!pq_verify(&encode_input(&msg, &pk, &a)).is_valid(), "ML-DSA half");
    // Falcon half (after the fixed split at MLDSA_SIG_LEN).
    let mut b = sig.clone();
    let n = b.len() - 1;
    b[n] ^= 0x01;
    assert!(!pq_verify(&encode_input(&msg, &pk, &b)).is_valid(), "Falcon half");
}

#[test]
fn another_keys_signature_does_not_verify_under_this_pubkey() {
    let (pk, _sk, msg, sig) = fixture();
    let (pk2, sk2) = bc::generate_keypair();
    let sig2 = bc::sign(&sk2, &msg).unwrap();
    assert!(pq_verify(&encode_input(&msg, &pk2, &sig2)).is_valid(), "CONTROL");
    assert!(!pq_verify(&encode_input(&msg, &pk, &sig2)).is_valid());
    // ...and the two addresses are different, so a contract comparing the
    // returned address to a stored owner rejects the substitution.
    let a = pq_verify(&encode_input(&msg, &pk, &sig)).to_word();
    let b = pq_verify(&encode_input(&msg, &pk2, &sig2)).to_word();
    assert_ne!(a, b);
}

// ── 2. Framing ───────────────────────────────────────────────────────────────

#[test]
fn framing_is_exact() {
    let (pk, _sk, msg, sig) = fixture();
    let good = encode_input(&msg, &pk, &sig);
    assert!(pq_verify(&good).is_valid(), "CONTROL");

    let mut trailing = good.clone();
    trailing.push(0x00);
    assert!(!pq_verify(&trailing).is_valid(), "trailing byte");

    assert!(!pq_verify(&good[..good.len() - 1]).is_valid(), "truncated");
    assert!(!pq_verify(&[]).is_valid(), "empty");
    assert!(!pq_verify(&good[..HEADER_BYTES]).is_valid(), "header only");

    // A length word that does not fit usize must be REJECTED, not truncated.
    let mut huge = good.clone();
    huge[32] = 0x01; // most-significant byte of pk_len
    assert!(!pq_verify(&huge).is_valid(), "oversized length word");

    // pk length is fixed: a shorter/longer pubkey is not a pubkey.
    let mut short_pk = pk.clone();
    short_pk.pop();
    assert!(!pq_verify(&encode_input(&msg, &short_pk, &sig)).is_valid());
}

#[test]
fn the_function_is_total_and_never_panics() {
    // Deterministic pseudo-random garbage across every interesting length.
    let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
    for len in [0usize, 1, 31, 32, 95, 96, 97, 3_000, 8_619, 8_620, 8_621, 20_000] {
        let mut v = vec![0u8; len];
        for b in v.iter_mut() {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (s >> 33) as u8;
        }
        let _ = pq_verify(&v); // must not panic
        assert!(pq_verify_gas(v.len()) >= PQ_VERIFY_BASE_GAS);
    }
}

// ── 3. Gas ───────────────────────────────────────────────────────────────────

#[test]
fn gas_is_a_function_of_length_only() {
    let (pk, _sk, msg, sig) = fixture();
    let good = encode_input(&msg, &pk, &sig);
    let garbage = vec![0xABu8; good.len()];
    assert!(pq_verify(&good).is_valid(), "CONTROL");
    assert!(!pq_verify(&garbage).is_valid());
    assert_eq!(
        pq_verify_gas(good.len()),
        pq_verify_gas(garbage.len()),
        "a rejected input must cost exactly what an accepted one of the same size costs"
    );
}

#[test]
fn gas_never_undersells_the_measured_verification() {
    // The whole DoS argument in one assertion.
    assert!(PQ_VERIFY_BASE_GAS * INSTRUCTIONS_PER_GAS + INSTRUCTIONS_PER_GAS > HYBRID_VERIFY_INSTRUCTIONS);
    assert_eq!(PQ_VERIFY_BASE_GAS, 72_748, "fee_market::HYBRID_VERIFY_GAS");
    // And the block-level consequence: a full block of precompile calls cannot
    // exceed the instruction budget the block gas limit already implies.
    const BLOCK_GAS_LIMIT: u64 = 60_000_000;
    let calls = BLOCK_GAS_LIMIT / pq_verify_gas(HEADER_BYTES);
    assert!(
        calls * HYBRID_VERIFY_INSTRUCTIONS <= BLOCK_GAS_LIMIT * INSTRUCTIONS_PER_GAS,
        "{calls} calls would exceed the block's own instruction budget"
    );
}

#[test]
fn gas_is_monotone_and_bounded() {
    assert!(pq_verify_gas(0) < pq_verify_gas(MAX_INPUT_BYTES));
    // The tight bound is what makes the per-word term unfarmable: the pubkey
    // length is fixed, so no caller can buy words without buying a verification.
    assert_eq!(pq_verify_gas(MAX_INPUT_BYTES), PQ_VERIFY_BASE_GAS + 270 * PQ_VERIFY_PER_WORD_GAS);
}

// ── 4. MUTATION PROOFS ───────────────────────────────────────────────────────
// Each mutant is the rule REMOVED. The test fails if the mutant and the
// reference agree — i.e. if the rule is not load-bearing on any input.

/// MUTANT A — the envelope check dropped, delegating straight to
/// `bloch_crypto::verify`, which falls back to the LEGACY pre-envelope encoding.
fn mutant_a_lenient_envelope(msg: &[u8; 32], pk: &[u8], sig: &[u8]) -> bool {
    bc::verify(pk, msg, sig)
}

#[test]
fn mutation_a_strict_envelope_is_load_bearing_on_the_SIGNATURE() {
    // WHERE THE WITNESS LIVES, and why the obvious one is not it.
    //
    // The pubkey side is already closed by framing: `pk_len` must be exactly
    // 3,749, and a legacy raw pubkey is 3,745, so it never reaches the
    // verifier. The SIGNATURE side is open, because `sig_len` must be a RANGE
    // (Falcon is variable) and a legacy raw signature — 4,586 bytes here —
    // sits comfortably inside it. `bloch_crypto::verify` computes suite 0x0001
    // for an enveloped pubkey and, via `parse_envelope_or_legacy`, ALSO 0x0001
    // for an un-enveloped signature; the suites match and it verifies.
    //
    // The damage is signature MALLEABILITY: one authorization, two distinct
    // valid byte encodings. Contracts that de-duplicate by `keccak256(sig)` —
    // Safe-style signature bookkeeping, bridge replay caches — would see two
    // different signatures for the same approval.
    //
    // This test was originally written with the pubkey ALSO stripped, and it
    // passed against a reference with the check deleted. That is the mutation
    // surviving; the witness below is the corrected one.
    let (pk, _sk, msg, sig) = fixture();
    let raw_sig = &sig[SUITE_HEADER_LEN..];

    // Control: the enveloped form is accepted by both.
    assert!(pq_verify(&encode_input(&msg, &pk, &sig)).is_valid());
    assert!(mutant_a_lenient_envelope(&msg, &pk, &sig));

    // Witness: enveloped pubkey, UN-enveloped signature.
    assert!(
        raw_sig.len() >= MIN_ENVELOPED_SIG_BYTES && raw_sig.len() <= MAX_ENVELOPED_SIG_BYTES,
        "the witness only exists because a raw signature fits the length range"
    );
    assert!(
        mutant_a_lenient_envelope(&msg, &pk, raw_sig),
        "mutant must accept the legacy signature encoding, else this is not the mutation"
    );
    assert!(
        !pq_verify(&encode_input(&msg, &pk, raw_sig)).is_valid(),
        "MUTATION SURVIVED: one authorization would have two valid encodings"
    );
}

#[test]
fn framing_alone_closes_the_pubkey_side() {
    // Stated as its own fact rather than hidden inside the mutation test: the
    // fixed pubkey length is what keeps a legacy pubkey out, and the two
    // encodings derive DIFFERENT addresses, which is why it matters.
    let (pk, _sk, msg, sig) = fixture();
    let raw_pk = &pk[SUITE_HEADER_LEN..];
    assert_eq!(raw_pk.len(), ENVELOPED_PK_BYTES - SUITE_HEADER_LEN);
    assert!(!pq_verify(&encode_input(&msg, raw_pk, &sig)).is_valid());
    assert_ne!(
        address_from_enveloped_pubkey(&pk),
        address_from_enveloped_pubkey(raw_pk),
        "two encodings, two addresses — that is what the fixed length prevents"
    );
}

/// MUTANT B — suite pinning dropped: any suite the crate knows is accepted.
fn mutant_b_any_suite(msg: &[u8; 32], pk: &[u8], sig: &[u8]) -> bool {
    match bc::split_envelope(pk) {
        Some(_) => bc::verify(pk, msg, sig),
        None => false,
    }
}

#[test]
fn mutation_b_a_falcon_less_suite_never_authorises() {
    // HONEST LABEL. This asserts the BEHAVIOUR (`0x0002` must not authorise),
    // not that the suite check is the line enforcing it: today the fixed
    // `pk_len` rejects a 1,956-byte ML-DSA-only pubkey first, so deleting the
    // suite check does not change any observable outcome and NO witness exists.
    // The check is kept as the guard that becomes load-bearing the moment a
    // second suite with a 3,745-byte public key is defined — at which point a
    // witness appears and this test must be strengthened to use it.
    // An ML-DSA-only (0x0002) key pair, re-enveloped from the hybrid halves.
    let (hpk, hsk) = bc::generate_keypair();
    let pk2 = envelope(SUITE_MLDSA65_ONLY, &hpk[SUITE_HEADER_LEN..][..MLDSA_PUBKEY_LEN]);
    let sk2 = envelope(SUITE_MLDSA65_ONLY, &hsk[SUITE_HEADER_LEN..][..MLDSA_SECRET_LEN]);
    let msg = [0x33u8; 32];
    let sig2 = bc::sign(&sk2, &msg).expect("ML-DSA-only sign");

    // Control: it is a genuinely valid signature under the crate's own verifier.
    assert!(bc::verify(&pk2, &msg, &sig2), "fixture must be a real 0x0002 signature");
    assert!(mutant_b_any_suite(&msg, &pk2, &sig2), "mutant must accept 0x0002");

    // Reference refuses it: half the suite, same price, same address space.
    assert!(
        !pq_verify(&encode_input(&msg, &pk2, &sig2)).is_valid(),
        "MUTATION SURVIVED: a Falcon-less authorization would be accepted at the hybrid price"
    );
    // Control half for the reference: the hybrid pair still passes.
    let hsig = bc::sign(&hsk, &msg).unwrap();
    assert!(pq_verify(&encode_input(&msg, &hpk, &hsig)).is_valid(), "CONTROL");
}

/// MUTANT C — the address derived over the pubkey BODY instead of the envelope
/// (the tempting "strip the header first" refactor).
fn mutant_c_address_over_body(enveloped_pk: &[u8]) -> [u8; 20] {
    let h = Sha3_256::digest(&enveloped_pk[SUITE_HEADER_LEN..]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[..20]);
    a
}

#[test]
fn mutation_c_address_covers_the_envelope() {
    let (pk, _sk, _msg, _sig) = fixture();
    let reference = address_from_enveloped_pubkey(&pk);
    assert_ne!(
        reference,
        mutant_c_address_over_body(&pk),
        "MUTATION SURVIVED: the address must commit to the suite, or a suite swap is invisible"
    );
    // Control: the reference agrees with the chain's own derivation.
    let chain = &bc::address_from_pubkey(&pk, false)["bloch1q".len()..][..40];
    assert_eq!(hex::encode(reference), chain);
}

/// MUTANT D — trailing bytes tolerated (`>=` instead of `==` on the framing).
fn mutant_d_tolerates_trailing(input: &[u8]) -> bool {
    if input.len() < HEADER_BYTES + ENVELOPED_PK_BYTES + MIN_ENVELOPED_SIG_BYTES {
        return false;
    }
    let sig_len = u64::from_be_bytes(input[88..96].try_into().unwrap()) as usize;
    let pk = &input[HEADER_BYTES..HEADER_BYTES + ENVELOPED_PK_BYTES];
    let sig = &input[HEADER_BYTES + ENVELOPED_PK_BYTES..][..sig_len];
    let msg: [u8; 32] = input[..32].try_into().unwrap();
    bc::verify(pk, &msg, sig)
}

#[test]
fn mutation_d_exact_framing_is_load_bearing() {
    let (pk, _sk, msg, sig) = fixture();
    let good = encode_input(&msg, &pk, &sig);
    let mut padded = good.clone();
    padded.extend_from_slice(&[0xEE; 64]);

    assert!(mutant_d_tolerates_trailing(&good), "CONTROL");
    assert!(
        mutant_d_tolerates_trailing(&padded),
        "mutant must accept padding, else this is not the mutation"
    );
    assert!(
        !pq_verify(&padded).is_valid(),
        "MUTATION SURVIVED: one call would have unboundedly many encodings"
    );
    // Why it is not cosmetic: padding changes the gas charged, so a tolerated
    // pad is a knob for making two identical authorizations cost differently.
    assert_ne!(pq_verify_gas(good.len()), pq_verify_gas(padded.len()));
}

// ── 5. The redundancy that is kept on purpose, stated rather than implied ────

#[test]
fn the_length_caps_are_implied_by_the_field_rules() {
    // Two reference mutations SURVIVED this suite, and the honest reading is
    // that they are unobservable rather than untested:
    //
    //   M5  `pk_len == 3,749`  relaxed to `pk_len >= 3,749`
    //   M6  the `input.len() > MAX_INPUT_BYTES` guard deleted
    //
    // Neither changes any outcome, because the exact-framing rule already
    // forces `len = 96 + pk_len + sig_len`, `sig_len` is range-bounded, and
    // `bloch_crypto`'s body checks reject any pubkey that is not exactly
    // 1,952 ‖ 1,793. Both checks are kept anyway: they make the maximum input
    // size a CONSTANT that a reader can see without following three checks
    // into another crate, and the gas bound of the spec's §5.4 is stated over
    // that constant. This test pins the property they exist to guarantee.
    let (pk, _sk, msg, sig) = fixture();
    let accepted = encode_input(&msg, &pk, &sig);
    assert!(pq_verify(&accepted).is_valid(), "CONTROL");
    assert!(
        accepted.len() <= MAX_INPUT_BYTES,
        "no accepted input may exceed the size the gas bound is stated over"
    );
    assert!(pq_verify_gas(accepted.len()) <= pq_verify_gas(MAX_INPUT_BYTES));

    // An over-long pubkey is not a pubkey, whichever check catches it.
    let mut long_pk = pk.clone();
    long_pk.push(0x00);
    assert!(!pq_verify(&encode_input(&msg, &long_pk, &sig)).is_valid());
}
