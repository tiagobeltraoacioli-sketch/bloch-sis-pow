// SPDX-License-Identifier: AGPL-3.0-or-later
//! P9e crypto audit: deterministic regression tests that pin the CURRENT
//! behaviour of the hybrid ML-DSA-65 || Falcon-1024 verifier at its split and
//! envelope boundaries. Some assertions document accepted-but-noteworthy
//! behaviour (marked "DOCUMENTS"); flipping them requires a consensus
//! decision, not a test edit.
use bloch_crypto::crypto::{self as c, falcon, MLDSA_PUBKEY_LEN, MLDSA_SIG_LEN, SUITE_HEADER_LEN as HDR};

fn key(seed: u8) -> (Vec<u8>, Vec<u8>) {
    c::generate_keypair_from_seed(&[seed; 32]).unwrap()
}
fn seeded_sign(sk: &[u8], msg: &[u8], s: u8) -> Vec<u8> {
    pqcrypto_internals::with_seeded_rng_scope(&[s; 32], || c::sign(sk, msg).unwrap())
}
fn env(suite: u16, body: &[u8]) -> Vec<u8> {
    let mut v = vec![0xB1, 0x0C];
    v.extend_from_slice(&suite.to_le_bytes());
    v.extend_from_slice(body);
    v
}

const MSG: &[u8] = b"p9e boundary message";

#[test]
fn shifting_the_split_point_never_verifies() {
    // The ML-DSA half is fixed-length (3309), so a "crafted split" can only
    // move bytes across the boundary; each shift must break one half.
    let (pk, sk) = key(0x21);
    let sig = seeded_sign(&sk, MSG, 1);
    assert!(c::verify(&pk, MSG, &sig));
    let b = HDR + MLDSA_SIG_LEN;
    for d in 1..=96usize {
        // Move d bytes of the Falcon half into the ML-DSA side (drop d bytes of
        // ML-DSA tail): body length shrinks by d, boundary content shifts.
        let mut left = sig.clone();
        left.drain(b - d..b);
        assert!(!c::verify(&pk, MSG, &left), "shift -{d}");
        // Pad the ML-DSA side with d bytes (pushes Falcon half right).
        let mut right = sig.clone();
        for _ in 0..d { right.insert(b, sig[b]); }
        assert!(!c::verify(&pk, MSG, &right), "shift +{d}");
    }
    // Same for the public key split at 1952.
    for d in 1..=32usize {
        let mut p = pk.clone();
        p.drain(HDR + MLDSA_PUBKEY_LEN - d..HDR + MLDSA_PUBKEY_LEN);
        assert!(!c::verify(&p, MSG, &sig));
    }
}

#[test]
fn halves_from_different_keys_or_messages_never_combine() {
    let (pk_a, sk_a) = key(0x31);
    let (pk_b, sk_b) = key(0x32);
    let sa = seeded_sign(&sk_a, MSG, 1);
    let sb = seeded_sign(&sk_b, MSG, 2);
    let sa2 = seeded_sign(&sk_a, b"other", 3);
    let b = HDR + MLDSA_SIG_LEN;
    let mix = |x: &[u8], y: &[u8]| [&x[..b], &y[b..]].concat();
    assert!(!c::verify(&pk_a, MSG, &mix(&sa, &sb)));
    assert!(!c::verify(&pk_b, MSG, &mix(&sa, &sb)));
    assert!(!c::verify(&pk_a, MSG, &mix(&sa, &sa2)));
    assert!(!c::verify(&pk_a, MSG, &mix(&sa2, &sa)));
    // Mixed public key (ML-DSA of A, Falcon of B) with mixed signature.
    let pk_mix = [&pk_a[..HDR + MLDSA_PUBKEY_LEN], &pk_b[HDR + MLDSA_PUBKEY_LEN..]].concat();
    assert!(c::verify(&pk_mix, MSG, &mix(&sa, &sb)),
        "DOCUMENTS: halves are independent; a hybrid identity is just the concatenation");
    assert_ne!(c::address_from_pubkey(&pk_mix, false), c::address_from_pubkey(&pk_a, false));
}

#[test]
fn documents_signature_encoding_multiplicity_accepted_by_consensus_verify() {
    // One signing event yields FOUR byte strings accepted by `crypto::verify`
    // (the consensus/tx path): {header, no header} x {compact, padded Falcon}.
    // Two signing events over the same (key, msg) additionally recombine
    // halves. txids are witness-free (transition.rs `txid`), so this is not
    // txid malleability, but it is witness/byte-size malleability.
    let (pk, sk) = key(0x41);
    let s1 = seeded_sign(&sk, MSG, 1);
    let s2 = seeded_sign(&sk, MSG, 2);
    let b = HDR + MLDSA_SIG_LEN;
    let mut padded = s1.clone();
    padded.resize(b + falcon::padded_signature_len(), 0);
    assert_ne!(padded, s1, "fixture must leave padding room");
    let raw = s1[HDR..].to_vec();
    let raw_padded = padded[HDR..].to_vec();
    let recombined = [&s1[..b], &s2[b..]].concat();
    for (name, s) in [("enveloped", &s1), ("padded", &padded), ("raw", &raw),
                      ("raw+padded", &raw_padded), ("recombined", &recombined)] {
        assert!(c::verify(&pk, MSG, s), "verify rejects {name}");
    }
    assert!(c::verify_enveloped(&pk, MSG, &padded));
    assert!(!c::verify_enveloped(&pk, MSG, &raw));
    assert!(c::verify_enveloped_canonical(&pk, MSG, &s1));
    assert!(!c::verify_enveloped_canonical(&pk, MSG, &padded));
    assert!(c::verify_enveloped_canonical(&pk, MSG, &recombined),
        "DOCUMENTS: canonical policy does not bind the two halves to one signing event");
    // Only the exact 1280-byte padded length is tolerated; other zero tails fail.
    for extra in [1usize, 2, 7] {
        let mut z = s1.clone();
        z.extend(std::iter::repeat(0u8).take(extra));
        if z.len() - b != falcon::padded_signature_len() {
            assert!(!c::verify(&pk, MSG, &z), "zero tail +{extra}");
        }
    }
}

#[test]
fn documents_suite_id_is_not_bound_into_the_signed_message() {
    // Suites 0x0001 and 0x0002 both sign the bare message with ML-DSA (empty
    // FIPS 204 context). Stripping the Falcon half of a 0x0001 signature and
    // re-heading it 0x0002 therefore verifies under a 0x0002 key that reuses
    // the SAME ML-DSA public key. Harmless today (addresses commit to the
    // enveloped pk and no flow re-envelopes keys), but a "drop Falcon"
    // migration that re-wraps existing ML-DSA halves as 0x0002 would make every
    // historical hybrid signature a valid ML-DSA-only signature. P9a's 0x0003
    // prototype binds a context/tag; 0x0001/0x0002 do not.
    let (pk, sk) = key(0x51);
    let s = seeded_sign(&sk, MSG, 1);
    let pk2 = env(0x0002, &pk[HDR..HDR + MLDSA_PUBKEY_LEN]);
    let s2 = env(0x0002, &s[HDR..HDR + MLDSA_SIG_LEN]);
    assert!(c::verify(&pk2, MSG, &s2));
    assert!(c::verify_enveloped_canonical(&pk2, MSG, &s2));
    // But the hybrid key never accepts it, and the header suite must match.
    assert!(!c::verify(&pk, MSG, &s2));
    assert!(!c::verify(&pk2, MSG, &s));
    assert!(!c::is_hybrid_public_key(&pk2));
}

#[test]
fn malformed_lengths_and_reserved_suites_fail_closed() {
    let (pk, sk) = key(0x61);
    let s = seeded_sign(&sk, MSG, 1);
    for suite in [0x0000u16, 0x0003, 0x00FF, 0x0100, 0xFFFF] {
        assert!(!c::verify(&env(suite, &pk[HDR..]), MSG, &env(suite, &s[HDR..])), "suite {suite:#06x}");
    }
    for n in [0usize, 1, 3, 4, 5, HDR + MLDSA_SIG_LEN - 1, HDR + MLDSA_SIG_LEN, HDR + MLDSA_SIG_LEN + 1, HDR + MLDSA_SIG_LEN + 41] {
        assert!(!c::verify(&pk, MSG, &s[..n.min(s.len())]), "truncated to {n}");
    }
    // Over-long Falcon half (> PQClean CRYPTO_BYTES 1462) is a length error.
    let mut long = s.clone();
    long.resize(HDR + MLDSA_SIG_LEN + 1463, 0);
    assert!(!c::verify(&pk, MSG, &long));
    // Trailing byte on the ML-DSA raw verifier.
    let mut m = s[HDR..HDR + MLDSA_SIG_LEN].to_vec();
    m.push(0);
    assert!(!c::verify_mldsa65_raw(&pk[HDR..HDR + MLDSA_PUBKEY_LEN], MSG, &m));
    // Falcon public key with wrong header byte / length.
    let fpk = &pk[HDR + MLDSA_PUBKEY_LEN..];
    let fs = &s[HDR + MLDSA_SIG_LEN..];
    assert!(falcon::verify(fpk, MSG, fs));
    let mut bad = fpk.to_vec();
    bad[0] ^= 1;
    assert!(!falcon::verify(&bad, MSG, fs));
    assert!(!falcon::verify(&fpk[..fpk.len() - 1], MSG, fs));
}
