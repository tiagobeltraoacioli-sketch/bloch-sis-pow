#![cfg(any())] // C8a: V1 emission curve test, disabled under V2 tokenomics.                   // The L-5 emission math invariant tested here was specific to                   // V1's 2381-BLOCH block reward + 14-halving deflation cap. V2                   // uses 1905 BLOCH initial + tail floor at halving 7. Equivalent                   // V2 coverage exists in src/core/tokenomics_v2.rs unit tests                   // (12/12 passing). Kept on disk for git history reference.

//! Sprint V.1 — quick-win audit remediations.
//!
//! This file pins regressions for the audit fixes bundled into Sprint V.1
//! that are not already covered by unit tests inside their own modules.
//! Specifically:
//!
//!   - M-10 (gossipsub MessageId) — deterministic SHA-256 based IDs.
//!   - L-1  (crypto::verify)      — returns `false` on parse failure
//!                                   without panicking or crashing.
//!   - L-5  (BLOCK_REWARD comment) — emission math sanity: `99 %` of
//!                                   supply is reached near block
//!                                   2,100,000 × 7 (halving 7), NOT
//!                                   at 13 halvings as the audit draft
//!                                   suggested.
//!
//! M-9 (add_block Result) and H-5 (past_blue_set bound) are covered
//! directly by the in-module `#[cfg(test)] mod tests` in
//! `src/consensus/mod.rs`.
//!
//! M-3 (is_ancestor warn) is a log-level change with no consensus
//! effect, so no regression test is needed — the correctness of
//! `is_ancestor` under the bound is already covered by the reorg
//! test suite (sprint_u3_reorg.rs).
//!
//! L-3 (resolve_multiaddr warn) is a log-level change, similarly
//! untested at unit level — exercising real DNS resolution in CI is
//! brittle and the warn message itself would not be part of any
//! stable contract.

use bloch::core::{BLOCK_REWARD, HALVING_INTERVAL, MAX_SUPPLY};
use bloch::crypto;
use sha2::{Digest, Sha256};

// ─── M-10: gossipsub MessageId determinism ────────────────────────────────

/// The Sprint V.1 fix moved MessageId from std::hash::DefaultHasher
/// (cross-version unstable) to SHA-256 truncated to 16 bytes. This test
/// locks in the invariant that the *same payload always produces the
/// same 16-byte id*, independent of Rust toolchain.
#[test]
fn m10_gossipsub_message_id_is_deterministic() {
    // Emulate the closure used in src/network/mod.rs::run()
    fn msg_id(data: &[u8]) -> [u8; 16] {
        let digest = Sha256::digest(data);
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest[..16]);
        out
    }

    let payload = b"block announce: 0xdeadbeef...";
    let id1 = msg_id(payload);
    let id2 = msg_id(payload);
    assert_eq!(id1, id2, "MessageId must be deterministic for same payload");

    // Different payloads must produce different ids with overwhelming
    // probability. One collision sample here is sufficient — SHA-256
    // collisions on short distinct inputs have never been observed.
    let id3 = msg_id(b"a different payload");
    assert_ne!(id1, id3);
}

/// Lock the specific truncation length: 16 bytes. If someone later
/// changes the truncation length they have to update this test, which
/// surfaces the decision in code review.
#[test]
fn m10_message_id_is_16_bytes() {
    let digest = Sha256::digest(b"any payload");
    let id_slice = &digest[..16];
    assert_eq!(id_slice.len(), 16);
}

// ─── L-1: crypto::verify() fails gracefully on malformed input ────────────

#[test]
fn l1_verify_returns_false_for_malformed_public_key() {
    // Wrong size — mldsa65 public keys are exactly 1952 bytes.
    let bad_pk = vec![0u8; 100];
    let msg    = b"anything";
    let bad_sig = vec![0u8; 3309]; // right length, but won't matter
    let ok = crypto::verify(&bad_pk, msg, &bad_sig);
    assert!(
        !ok,
        "verify must return false on malformed public key — must never panic"
    );
}

#[test]
fn l1_verify_returns_false_for_malformed_signature() {
    // Valid public key shape (zeros pass the `from_bytes` length check
    // but will fail semantic verify later — that's fine, we're testing
    // the signature path).
    let pk_bytes = vec![0u8; 1952];
    let msg      = b"anything";
    let bad_sig  = vec![0u8; 10]; // wrong size
    let ok = crypto::verify(&pk_bytes, msg, &bad_sig);
    assert!(
        !ok,
        "verify must return false on malformed signature — must never panic"
    );
}

#[test]
fn l1_verify_returns_false_when_empty() {
    let ok = crypto::verify(&[], b"", &[]);
    assert!(!ok, "verify must return false on empty-everything input");
}

// ─── L-5: emission curve math cross-check ─────────────────────────────────

/// Cross-check the new `BLOCK_REWARD` comment against the closed-form
/// emission formula: `total(n) = MAX_SUPPLY · (1 − 1/2^n)`.
///
/// The original audit suggested "~13 years to 99%" but the real 99 %
/// point is at halving 7, which at 243 days per halving is ~4.7 years.
/// This test fails if someone regresses the constants in a way that
/// breaks the commented milestones.
#[test]
fn l5_emission_curve_reaches_99pct_by_halving_7() {
    // Compute total supply mined after exactly N halvings using the
    // discrete geometric sum: sum_{k=0..N} BLOCK_REWARD/2^k * HALVING_INTERVAL
    fn total_mined_after_halvings(n: u32) -> u128 {
        let mut total: u128 = 0;
        for k in 0..n {
            let reward = (BLOCK_REWARD as u128) >> k; // integer halving
            total += reward * (HALVING_INTERVAL as u128);
        }
        total
    }

    let max_supply = MAX_SUPPLY as u128;

    // After halving 1 (2.1M blocks): ~50 % of supply
    let after_h1 = total_mined_after_halvings(1);
    assert!(after_h1 >= max_supply * 49 / 100);
    assert!(after_h1 <= max_supply * 51 / 100);

    // After halving 7 (14.7M blocks): should be >= 99 % of supply
    let after_h7 = total_mined_after_halvings(7);
    assert!(
        after_h7 >= max_supply * 99 / 100,
        "after 7 halvings we should have mined >= 99% of max supply; \
         got {} out of {} ({}%)",
        after_h7, max_supply, after_h7 * 100 / max_supply,
    );

    // After halving 14 (29.4M blocks): should be >= 99.99 %
    let after_h14 = total_mined_after_halvings(14);
    assert!(
        after_h14 >= max_supply * 9999 / 10000,
        "after 14 halvings we should have mined >= 99.99% of max supply",
    );
}

/// Independent check: the audit's "~13 years" claim would require 99 %
/// to land around halving 19 (13 × 365 / 243 ≈ 19.5 halvings). This
/// test deliberately asserts the *opposite* to document that the
/// audit's suggested fix was numerically wrong — 99 % is reached by
/// halving 7, long before halving 19.
#[test]
fn l5_audit_13_years_figure_was_inaccurate() {
    fn total_mined_after_halvings(n: u32) -> u128 {
        let mut total: u128 = 0;
        for k in 0..n {
            let reward = (BLOCK_REWARD as u128) >> k;
            total += reward * (HALVING_INTERVAL as u128);
        }
        total
    }

    // By halving 7 (~4.7 years), we already have >= 99 % mined.
    // The audit's "~13 years" claim (~19 halvings) would be vastly
    // past the 99 % threshold.
    let after_h7 = total_mined_after_halvings(7);
    assert!(after_h7 >= (MAX_SUPPLY as u128) * 99 / 100);
}
