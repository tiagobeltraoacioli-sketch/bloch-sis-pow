// SPDX-License-Identifier: AGPL-3.0-or-later
//! §6.2 precompile — behaviour, framing, gas.
//!
//! Every negative test carries its control half: the same call with the one
//! byte or one field put back, asserted to succeed. A negative test without a
//! control proves only that *something* was wrong.

mod common;
use common::{alice, mallory, rewrap, strip};

use bloch_crypto::crypto;
use bloch_evm_pq_precompile::*;
use bloch_pos_committee::fee_market::{
    BLOCK_GAS_LIMIT, HYBRID_VERIFY_GAS, HYBRID_VERIFY_INSTRUCTIONS, INSTRUCTIONS_PER_GAS,
};

const MSG: [u8; 32] = [0x5a; 32];

/// Mirrors `bloch_crypto::crypto::MLDSA_SIG_LEN`; named so the tests read as
/// rule statements rather than as a second import of a constant.
const MLDSA_SIG_LEN_FOR_TESTS: usize = 3309;

fn good_call() -> Vec<u8> {
    let a = alice();
    encode_input(&MSG, &a.pk, &a.sign(&MSG))
}

// ── The happy path, and what it returns ─────────────────────────────────────

#[test]
fn valid_hybrid_signature_returns_the_signer_address() {
    let a = alice();
    let out = pq_verify_raw(&good_call());
    assert_ne!(out, REJECTED, "a genuine hybrid signature must verify");
    assert_eq!(out, a.expected_word());
    assert_eq!(&out[..12], &[0u8; 12], "address must be left-padded into a word");
}

#[test]
fn the_returned_address_is_the_chains_address_derivation() {
    // The precompile is the only way a contract can learn a Bloch address:
    // Solidity's keccak256 is not FIPS-202 SHA3-256. If this drifts from
    // `address_from_pubkey`, the EVM and the base chain disagree about who
    // owns an account.
    let a = alice();
    let out = pq_verify_raw(&good_call());
    let from_precompile = crypto::address_from_hash(&out[12..].try_into().unwrap(), false);
    let from_chain = crypto::address_from_pubkey(&a.pk, false);
    assert_eq!(from_precompile, from_chain);
}

#[test]
fn a_different_key_gives_a_different_address() {
    // Control for the test above: the assertion would also pass if every
    // input produced one constant address.
    let m = mallory();
    let out = pq_verify_raw(&encode_input(&MSG, &m.pk, &m.sign(&MSG)));
    assert_eq!(out, m.expected_word());
    assert_ne!(out, alice().expected_word());
}

// ── Signature soundness ─────────────────────────────────────────────────────

#[test]
fn wrong_message_is_rejected() {
    let a = alice();
    let sig = a.sign(&MSG);
    let other = [0x5b; 32];
    assert_eq!(pq_verify_raw(&encode_input(&other, &a.pk, &sig)), REJECTED);
    // control
    assert_ne!(pq_verify_raw(&encode_input(&MSG, &a.pk, &sig)), REJECTED);
}

#[test]
fn tampered_signature_is_rejected_in_both_halves() {
    let a = alice();
    let sig = a.sign(&MSG);
    // ML-DSA half (body byte 0 is just past the 4-byte envelope).
    let mut mldsa_broken = sig.clone();
    mldsa_broken[4] ^= 0x01;
    assert_eq!(pq_verify_raw(&encode_input(&MSG, &a.pk, &mldsa_broken)), REJECTED);
    // Falcon half — this is the one an OR-degraded combiner would let through.
    let mut falcon_broken = sig.clone();
    let n = falcon_broken.len();
    falcon_broken[n - 1] ^= 0x01;
    assert_eq!(pq_verify_raw(&encode_input(&MSG, &a.pk, &falcon_broken)), REJECTED);
    // control
    assert_ne!(pq_verify_raw(&encode_input(&MSG, &a.pk, &sig)), REJECTED);
}

#[test]
fn another_partys_key_does_not_verify() {
    let a = alice();
    let m = mallory();
    assert_eq!(pq_verify_raw(&encode_input(&MSG, &m.pk, &a.sign(&MSG))), REJECTED);
    assert_ne!(pq_verify_raw(&encode_input(&MSG, &a.pk, &a.sign(&MSG))), REJECTED);
}

// ── Rule 1: strict envelope. THE malleability witness. ──────────────────────

#[test]
fn an_unenveloped_signature_is_refused_here_although_bloch_crypto_accepts_it() {
    // `crypto::verify` must keep accepting the legacy encoding — pre-envelope
    // carry-over wallets depend on it. Inside the EVM the same tolerance is
    // signature MALLEABILITY: one authorization with two valid byte strings,
    // which silently breaks any contract that de-duplicates by
    // `keccak256(sig)` (Safe-style bookkeeping, bridge and relayer replay
    // caches). The signature length is a RANGE, not a constant, so a stripped
    // signature lands inside the accepted band and no length check catches it.
    let a = alice();
    let sig = a.sign(&MSG);
    let raw = strip(&sig);

    assert!(
        crypto::verify(&a.pk, &MSG, &raw),
        "premise: the base verifier accepts the legacy encoding (if this ever \
         fails, the malleability is gone and this rule may be revisited)"
    );
    assert!(
        (MIN_ENVELOPED_SIG_LEN..=MAX_ENVELOPED_SIG_LEN).contains(&raw.len()),
        "premise: the stripped signature is inside the accepted length band, \
         so only the envelope check can reject it"
    );
    assert_eq!(
        pq_verify_raw(&encode_input(&MSG, &a.pk, &raw)),
        REJECTED,
        "the precompile must admit exactly one encoding"
    );
    // control: the same signature, envelope intact.
    assert_ne!(pq_verify_raw(&encode_input(&MSG, &a.pk, &sig)), REJECTED);
}

#[test]
fn a_corrupted_envelope_magic_is_refused() {
    let a = alice();
    let sig = a.sign(&MSG);
    let mut bad = sig.clone();
    bad[1] ^= 0xFF; // 0x0C -> not 0x0C
    assert_eq!(pq_verify_raw(&encode_input(&MSG, &a.pk, &bad)), REJECTED);
    let mut bad_pk = a.pk.clone();
    bad_pk[0] ^= 0xFF;
    assert_eq!(pq_verify_raw(&encode_input(&MSG, &bad_pk, &sig)), REJECTED);
    assert_ne!(pq_verify_raw(&encode_input(&MSG, &a.pk, &sig)), REJECTED);
}

// ── Rules 1 and 2 stated as rules ───────────────────────────────────────────
//
// These two tests exist because of a mutation result, not for coverage.
// Deleting the public-key envelope check (M2) and accepting any suite tag
// (M3) both SURVIVED the behavioural suite: `crypto::verify` dispatches on
// the suite itself and the geometry of a 3,749-byte object makes every other
// tag fail anyway, so the rules are today enforced twice and observable
// zero times. That is fine until it isn't — a new suite with same-sized
// bodies, or a loosened length rule, and the redundancy evaporates silently.
// So the rules are pinned directly.

#[test]
fn the_envelope_predicate_admits_only_suite_0x0001() {
    let a = alice();
    assert!(is_hybrid_envelope(&a.pk, a.pk.len() - 4), "the real key is admitted");
    for suite in [0x0000u16, crypto::SUITE_MLDSA65_ONLY, 0x0003, 0xFFFF] {
        assert!(
            !is_hybrid_envelope(&rewrap(&a.pk, suite), a.pk.len() - 4),
            "suite {suite:#06x} must not pass rule 2"
        );
    }
}

#[test]
fn the_envelope_predicate_requires_the_header_to_be_present() {
    let a = alice();
    let raw = strip(&a.pk);
    assert_eq!(raw.len(), a.pk.len() - 4);
    assert!(!is_hybrid_envelope(&raw, raw.len()), "no header, no admission");
    assert!(!is_hybrid_envelope(&raw, raw.len() - 4), "and not under any body length");
    // control
    assert!(is_hybrid_envelope(&a.pk, raw.len()));
}

#[test]
fn the_signature_predicate_admits_only_suite_0x0001_with_a_falcon_half() {
    let a = alice();
    let sig = a.sign(&MSG);
    assert!(is_hybrid_envelope_longer_than(&sig, MLDSA_SIG_LEN_FOR_TESTS));
    assert!(
        !is_hybrid_envelope_longer_than(&strip(&sig), MLDSA_SIG_LEN_FOR_TESTS),
        "the legacy encoding is not an envelope"
    );
    assert!(
        !is_hybrid_envelope_longer_than(&rewrap(&sig, crypto::SUITE_MLDSA65_ONLY), MLDSA_SIG_LEN_FOR_TESTS),
        "wrong suite"
    );
    // An ML-DSA half with nothing after it is not a hybrid signature.
    let mut no_falcon = vec![0xB1u8, 0x0C, 0x01, 0x00];
    no_falcon.resize(4 + MLDSA_SIG_LEN_FOR_TESTS, 0);
    assert!(!is_hybrid_envelope_longer_than(&no_falcon, MLDSA_SIG_LEN_FOR_TESTS));
}

// ── Rule 2: one suite ───────────────────────────────────────────────────────

#[test]
fn suite_0x0002_is_refused_on_both_objects() {
    // Same bodies, only the suite tag changed. `SUITE_MLDSA65_ONLY` is as
    // available and as unused here as it is in staking (staking.rs:52-56):
    // a single-family suite would drop the hybrid property.
    let a = alice();
    let sig = a.sign(&MSG);
    let pk2 = rewrap(&a.pk, crypto::SUITE_MLDSA65_ONLY);
    let sig2 = rewrap(&sig, crypto::SUITE_MLDSA65_ONLY);
    assert_eq!(pq_verify_raw(&encode_input(&MSG, &pk2, &sig2)), REJECTED);
    assert_eq!(pq_verify_raw(&encode_input(&MSG, &pk2, &sig)), REJECTED);
    assert_eq!(pq_verify_raw(&encode_input(&MSG, &a.pk, &sig2)), REJECTED);
    // control
    assert_ne!(pq_verify_raw(&encode_input(&MSG, &a.pk, &sig)), REJECTED);
}

#[test]
fn a_reserved_suite_tag_is_refused() {
    let a = alice();
    let sig = a.sign(&MSG);
    for suite in [0x0000u16, 0x0003, 0xFFFF] {
        assert_eq!(
            pq_verify_raw(&encode_input(&MSG, &rewrap(&a.pk, suite), &rewrap(&sig, suite))),
            REJECTED,
            "suite {suite:#06x} must not verify"
        );
    }
    assert_ne!(pq_verify_raw(&encode_input(&MSG, &a.pk, &sig)), REJECTED);
}

// ── Rule 3: exact framing ───────────────────────────────────────────────────

#[test]
fn a_trailing_byte_is_refused() {
    let mut input = good_call();
    input.push(0x00);
    assert_eq!(pq_verify_raw(&input), REJECTED, "trailing data is a second encoding");
    input.pop();
    assert_ne!(pq_verify_raw(&input), REJECTED);
}

#[test]
fn a_short_read_is_refused() {
    let mut input = good_call();
    let last = input.pop().unwrap();
    assert_eq!(pq_verify_raw(&input), REJECTED);
    input.push(last);
    assert_ne!(pq_verify_raw(&input), REJECTED);
}

#[test]
fn declared_lengths_that_do_not_sum_to_the_input_are_refused() {
    // The bytes are all present and the signature is genuine; only the
    // declared split moves. Two length words plus a body is exactly the shape
    // that admits many encodings of one call if the sum is not checked.
    let a = alice();
    let sig = a.sign(&MSG);
    let good = encode_input(&MSG, &a.pk, &sig);
    for (delta_pk, delta_sig) in [(1i64, -1i64), (-1, 1), (0, 1), (1, 0), (0, -1)] {
        let mut bad = good.clone();
        let pk_len = (ENVELOPED_PK_LEN as i64 + delta_pk) as u64;
        let sig_len = (sig.len() as i64 + delta_sig) as u64;
        bad[56..64].copy_from_slice(&pk_len.to_be_bytes());
        bad[88..96].copy_from_slice(&sig_len.to_be_bytes());
        assert_eq!(pq_verify_raw(&bad), REJECTED, "split {delta_pk}/{delta_sig}");
    }
    assert_ne!(pq_verify_raw(&good), REJECTED);
}

#[test]
fn a_non_canonical_length_word_is_refused() {
    // A length is not a place to accept 2^256 encodings of one number.
    let mut input = good_call();
    input[32] = 0x01; // high byte of pk_len
    assert_eq!(pq_verify_raw(&input), REJECTED);
    input[32] = 0x00;
    input[64] = 0x01; // high byte of sig_len
    assert_eq!(pq_verify_raw(&input), REJECTED);
    input[64] = 0x00;
    assert_ne!(pq_verify_raw(&input), REJECTED);
}

#[test]
fn the_public_key_length_is_exact() {
    let a = alice();
    let sig = a.sign(&MSG);
    let mut short_pk = a.pk.clone();
    short_pk.pop();
    assert_eq!(pq_verify_raw(&encode_input(&MSG, &short_pk, &sig)), REJECTED);
    let mut long_pk = a.pk.clone();
    long_pk.push(0);
    assert_eq!(pq_verify_raw(&encode_input(&MSG, &long_pk, &sig)), REJECTED);
    assert_ne!(pq_verify_raw(&encode_input(&MSG, &a.pk, &sig)), REJECTED);
}

#[test]
fn the_signature_length_band_is_enforced_at_both_ends() {
    let a = alice();
    let sig = a.sign(&MSG);
    // Below the band: a WELL-FORMED 0x0001 envelope carrying an ML-DSA half
    // with no Falcon byte after it. Enveloped on purpose — a buffer of zeros
    // would be rejected by the magic check and would prove nothing about the
    // band.
    let mut too_short = vec![0xB1u8, 0x0C, 0x01, 0x00];
    too_short.resize(MIN_ENVELOPED_SIG_LEN - 1, 0);
    assert_eq!(pq_verify_raw(&encode_input(&MSG, &a.pk, &too_short)), REJECTED);
    // Above the band: a well-formed envelope longer than Falcon-1024 can be.
    let mut too_long = vec![0xB1u8, 0x0C, 0x01, 0x00];
    too_long.resize(MAX_ENVELOPED_SIG_LEN + 1, 0);
    assert_eq!(pq_verify_raw(&encode_input(&MSG, &a.pk, &too_long)), REJECTED);
    assert_ne!(pq_verify_raw(&encode_input(&MSG, &a.pk, &sig)), REJECTED);
}

#[test]
fn a_real_signature_sits_inside_the_declared_band() {
    // Otherwise the band would be rejecting honest traffic, and every test
    // above would be passing for the wrong reason.
    assert_eq!(
        MIN_ENVELOPED_SIG_LEN,
        4 + MLDSA_SIG_LEN_FOR_TESTS + 1,
        "the rule tests above are only meaningful if this constant is right"
    );
    let sig = alice().sign(&MSG);
    assert!(sig.len() >= MIN_ENVELOPED_SIG_LEN, "{} too short", sig.len());
    assert!(sig.len() <= MAX_ENVELOPED_SIG_LEN, "{} too long", sig.len());
}

#[test]
fn max_falcon_sig_len_matches_the_linked_library() {
    // If `pqcrypto-falcon` ever changes its maximum, MAX_INPUT_BYTES and the
    // whole DoS arithmetic move with it.
    assert_eq!(
        MAX_FALCON_SIG_BYTES,
        pqcrypto_falcon::falcon1024::signature_bytes(),
        "the constant and the linked PQClean build must agree"
    );
}

// ── Totality ────────────────────────────────────────────────────────────────

#[test]
fn short_and_empty_inputs_are_refused_without_panicking() {
    for n in 0..HEADER_LEN + 4 {
        assert_eq!(pq_verify_raw(&vec![0xAB; n]), REJECTED, "len {n}");
    }
}

#[test]
fn oversized_input_is_refused_without_panicking() {
    assert_eq!(pq_verify_raw(&vec![0u8; MAX_INPUT_BYTES + 1]), REJECTED);
    assert_eq!(pq_verify_raw(&vec![0u8; 1_000_000]), REJECTED);
}

#[test]
fn arbitrary_bytes_never_panic_and_never_authorize() {
    // A cheap deterministic sweep: xorshift over lengths that bracket every
    // boundary the function has.
    let mut state: u64 = 0x0B10_C000_0000_0001u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for len in [0usize, 1, 31, 32, 95, 96, 97, 7158, 7159, 8619, 8620, 8621] {
        for _ in 0..8 {
            let buf: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
            assert_eq!(pq_verify_raw(&buf), REJECTED, "len {len}");
        }
    }
}

#[test]
fn the_result_is_deterministic() {
    // Consensus rule: same bytes, same 32 bytes, every node, every call.
    let input = good_call();
    let first = pq_verify_raw(&input);
    for _ in 0..3 {
        assert_eq!(pq_verify_raw(&input), first);
    }
}

// ── Gas ─────────────────────────────────────────────────────────────────────

#[test]
fn gas_is_the_documented_formula() {
    assert_eq!(PQ_VERIFY_BASE_GAS, HYBRID_VERIFY_GAS, "the anchor is the fee market's");
    assert_eq!(PQ_VERIFY_BASE_GAS, 72_748);
    assert_eq!(pq_verify_gas(0), 72_748);
    assert_eq!(pq_verify_gas(HEADER_LEN), 72_748 + 39 * 3); // 72,865
    assert_eq!(pq_verify_gas(MAX_INPUT_BYTES), 72_748 + 39 * 270); // 83,278
    assert_eq!(pq_verify_gas(MIN_VERIFYING_INPUT_BYTES), 72_748 + 39 * 224); // 81,484
    // partial word rounds up
    assert_eq!(pq_verify_gas(33), pq_verify_gas(64));
    assert!(pq_verify_gas(33) > pq_verify_gas(32));
}

#[test]
fn gas_is_monotone_in_length() {
    let mut prev = pq_verify_gas(0);
    for n in 1..=MAX_INPUT_BYTES {
        let g = pq_verify_gas(n);
        assert!(g >= prev, "gas fell at {n}");
        prev = g;
    }
}

#[test]
fn gas_never_undersells_the_measured_verification() {
    // The load-bearing DoS claim: at every input length that can reach the
    // verifier, the gas charged buys at least the instructions the
    // verification costs. `HYBRID_VERIFY_GAS` alone does NOT — the fee
    // market's constant truncates 7,274,849/100 to 72,748, 49 instructions
    // short — so this is a property of the per-word term, not of the anchor.
    for n in MIN_VERIFYING_INPUT_BYTES..=MAX_INPUT_BYTES {
        let instructions_bought = pq_verify_gas(n) as u128 * INSTRUCTIONS_PER_GAS as u128;
        assert!(
            instructions_bought >= HYBRID_VERIFY_INSTRUCTIONS as u128,
            "length {n} buys {instructions_bought} instructions, verification costs {HYBRID_VERIFY_INSTRUCTIONS}"
        );
    }
    assert!(
        (PQ_VERIFY_BASE_GAS as u128) * (INSTRUCTIONS_PER_GAS as u128)
            < (HYBRID_VERIFY_INSTRUCTIONS as u128),
        "if the base alone ever covers it, say so and simplify — but do not \
         assume it does"
    );
}

#[test]
fn a_block_of_this_precompile_fits_the_blocks_instruction_budget() {
    // Everything an attacker can buy with one block of gas, against what one
    // block of gas is calibrated to be worth.
    let cheapest_verifying = pq_verify_gas(MIN_VERIFYING_INPUT_BYTES);
    let calls = BLOCK_GAS_LIMIT / cheapest_verifying;
    let instructions = calls as u128 * HYBRID_VERIFY_INSTRUCTIONS as u128;
    let budget = BLOCK_GAS_LIMIT as u128 * INSTRUCTIONS_PER_GAS as u128;
    assert!(
        instructions <= budget,
        "{calls} verifications = {instructions} instructions vs budget {budget}"
    );
    assert_eq!(calls, 736, "the DoS write-up quotes this number");
}

#[test]
fn gas_does_not_depend_on_whether_the_signature_is_valid() {
    // A cheap early-out would hand an attacker a discounted probe and make
    // the price a function of the data. Same length ⇒ same price, always.
    let a = alice();
    let sig = a.sign(&MSG);
    let good = encode_input(&MSG, &a.pk, &sig);
    let mut bad = good.clone();
    let n = bad.len();
    bad[n - 1] ^= 0x01;

    let g = pq_verify(&good, u64::MAX).expect("gas").gas_used;
    let b = pq_verify(&bad, u64::MAX).expect("gas").gas_used;
    assert_eq!(g, b);
    assert_ne!(pq_verify(&good, u64::MAX).unwrap().output, REJECTED);
    assert_eq!(pq_verify(&bad, u64::MAX).unwrap().output, REJECTED);
}

#[test]
fn a_malformed_short_call_still_pays_in_full() {
    // 96 bytes of garbage costs 72,865 gas for no work. Deliberate.
    let r = pq_verify(&[0u8; 96], u64::MAX).expect("gas");
    assert_eq!(r.gas_used, 72_865);
    assert_eq!(r.output, REJECTED);
}

#[test]
fn insufficient_gas_is_out_of_gas_not_a_free_answer() {
    let input = good_call();
    let needed = pq_verify_gas(input.len());
    assert_eq!(pq_verify(&input, needed - 1), Err(OutOfGas));
    assert!(pq_verify(&input, needed).is_ok());
}

// ── Inertness ───────────────────────────────────────────────────────────────

#[test]
fn the_precompile_is_inert_at_every_epoch_the_chain_can_reach() {
    assert_eq!(PQ_PRECOMPILE_ACTIVATION_EPOCH, u64::MAX);
    for epoch in [0u64, 800, 27_000, 1 << 40, u64::MAX - 1] {
        assert!(!is_active(epoch), "epoch {epoch} must not activate this");
    }
}

#[test]
fn the_address_is_the_reserved_bloch_block() {
    assert_eq!(&PQ_VERIFY_ADDRESS[..16], &[0u8; 16]);
    assert_eq!(&PQ_VERIFY_ADDRESS[16..], &[0xB1, 0x0C, 0x00, 0x01]);
    assert_eq!(
        hex::encode(PQ_VERIFY_ADDRESS),
        "00000000000000000000000000000000b10c0001",
        "the Solidity constant in contracts/BlochPQ.sol must equal this"
    );
}
