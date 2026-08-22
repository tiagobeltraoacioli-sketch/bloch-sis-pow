// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cost harness for the §6.2 precompile. Prints the numbers that
//! `docs/specs/BLOCH-L1-EVM-PQ-PRECOMPILE.md` §5 quotes, measured on the
//! machine it runs on. Run: `cargo run --release --bin pq-precompile-cost`.
//!
//! Two questions only:
//!   1. What does one call cost in gas, at every input size that exists?
//!   2. If an attacker buys a whole block of gas and spends it all here, how
//!      much validator wall-clock does that buy, against a 30 s slot?

use pq_precompile_spike::*;
use std::time::Instant;

// fee_market.rs — quoted, not re-decided.
const BLOCK_GAS_LIMIT: u64 = 60_000_000;
const MAX_BLOCK_TX_BYTES_V2: u64 = 524_288;
const GAS_PER_BYTE: u64 = 16;
const TX_FLAT_GAS: u64 = 5_000;
const MIN_BASE_FEE_MILLISAT_PER_GAS: u128 = 10;
const SLOT_SECS: f64 = 30.0;
// The EVM's own warm STATICCALL floor (Cancun) — the cheapest possible wrapper
// around one precompile call.
const STATICCALL_WARM_GAS: u64 = 100;

fn main() {
    let (pk, sk) = bloch_crypto::crypto::generate_keypair();
    let msg = [0x5au8; 32];
    let sig = bloch_crypto::crypto::sign(&sk, &msg).expect("sign");
    let input = encode_input(&msg, &pk, &sig);

    println!("== sizes ==");
    println!("enveloped pk      : {} B (fixed)", pk.len());
    println!("enveloped sig     : {} B (Falcon is variable; max {})", sig.len(), MAX_ENVELOPED_SIG_BYTES);
    println!("precompile input  : {} B (max {})", input.len(), MAX_INPUT_BYTES);

    assert!(pq_verify(&input).is_valid(), "fixture must verify");

    // ── measure ──────────────────────────────────────────────────────────────
    let warm = 20;
    for _ in 0..warm {
        std::hint::black_box(pq_verify(&input));
    }
    let n = 300;
    let t0 = Instant::now();
    for _ in 0..n {
        std::hint::black_box(pq_verify(&input));
    }
    let per_call = t0.elapsed().as_secs_f64() / n as f64;

    // Control half: the same loop over an input the precompile REJECTS before
    // it reaches any lattice arithmetic. If this is not far cheaper, the
    // measurement above is not measuring verification.
    let mut bad = input.clone();
    bad[HEADER_BYTES] ^= 0xFF; // break the pubkey envelope magic
    assert!(!pq_verify(&bad).is_valid(), "control must be rejected");
    let t1 = Instant::now();
    for _ in 0..n {
        std::hint::black_box(pq_verify(&bad));
    }
    let per_reject = t1.elapsed().as_secs_f64() / n as f64;

    println!("\n== native cost, this machine ==");
    println!("valid  call : {:>9.1} us", per_call * 1e6);
    println!("reject call : {:>9.3} us  (control half: parse-only)", per_reject * 1e6);

    // ── gas ──────────────────────────────────────────────────────────────────
    let g_typ = pq_verify_gas(input.len());
    let g_max = pq_verify_gas(MAX_INPUT_BYTES);
    let g_min = pq_verify_gas(HEADER_BYTES);
    println!("\n== gas ==");
    println!("base            : {PQ_VERIFY_BASE_GAS}");
    println!("per 32-B word   : {PQ_VERIFY_PER_WORD_GAS}");
    println!("typical call    : {g_typ}  ({} B)", input.len());
    println!("max-size call   : {g_max}  ({} B)", MAX_INPUT_BYTES);
    println!("min-size call   : {g_min}  (96 B, rejected, charged in full)");

    // ── the DoS bound ────────────────────────────────────────────────────────
    // Two different ceilings, and they must not be conflated. The cheapest
    // possible CALL is a 96-byte input that is rejected before any lattice
    // arithmetic: it maximises the CALL COUNT and costs almost no CPU. The
    // cheapest real VERIFICATION must carry a full-size input. Validator
    // wall-clock is bounded by the second, not the first.
    let cheapest_call = g_min + STATICCALL_WARM_GAS;
    let calls = BLOCK_GAS_LIMIT / cheapest_call;
    let cheapest_verify = g_typ + STATICCALL_WARM_GAS;
    let verifies = BLOCK_GAS_LIMIT / cheapest_verify;
    let secs = verifies as f64 * per_call;
    println!("\n== worst-case block ==");
    println!("cheapest CALL      (96 B, rejected)   : {cheapest_call} gas -> {calls} calls, {:.3} ms of CPU",
        calls as f64 * per_reject * 1e3);
    println!("cheapest VERIFY    ({} B input)      : {cheapest_verify} gas -> {verifies} verifications", input.len());
    println!("anchor instructions those represent   : {:.2} G (block budget {:.2} G)",
        verifies as f64 * HYBRID_VERIFY_INSTRUCTIONS as f64 / 1e9,
        BLOCK_GAS_LIMIT as f64 * INSTRUCTIONS_PER_GAS as f64 / 1e9);
    println!("native wall-clock for that block      : {:.3} s ({:.2}% of a {:.0} s slot)",
        secs, 100.0 * secs / SLOT_SECS, SLOT_SECS);

    // What the same block buys through the BYTE-capped path that exists today.
    let bytes_bound = MAX_BLOCK_TX_BYTES_V2 / (sig.len() as u64 + 110);
    println!("\n== against the byte-capped path ==");
    println!("verifications a 512 KiB block can carry as tx signatures : {bytes_bound}");
    println!("the precompile raises the per-block verification ceiling : {:.1}x", verifies as f64 / bytes_bound as f64);

    let cost_sat = BLOCK_GAS_LIMIT as u128 * MIN_BASE_FEE_MILLISAT_PER_GAS / 1_000;
    println!("\nattacker cost for that block at the fee floor : {} sat ({:.6} BLCH)",
        cost_sat, cost_sat as f64 / 1e8);

    // ── the permit accounting the DEX question turns on (spec §7) ────────────
    let tx_overhead = 100u64; // §6.1 body fields, ex-signature
    let one_auth_tx = tx_overhead + sig.len() as u64;
    let permit_tx = tx_overhead + sig.len() as u64 + pk.len() as u64 + sig.len() as u64;
    println!("\n== approve+swap: two txs, one batch, or one permit ==");
    println!("two txs (approve, then swap) : {} B, {} gas intrinsic",
        2 * one_auth_tx, 2 * (TX_FLAT_GAS + one_auth_tx * GAS_PER_BYTE + PQ_VERIFY_BASE_GAS));
    println!("one 6.1 batch tx             : {} B, {} gas intrinsic",
        one_auth_tx, TX_FLAT_GAS + one_auth_tx * GAS_PER_BYTE + PQ_VERIFY_BASE_GAS);
    println!("one permit tx (self-permit)  : {} B, {} gas intrinsic + {} precompile",
        permit_tx, TX_FLAT_GAS + permit_tx * GAS_PER_BYTE + PQ_VERIFY_BASE_GAS, g_typ);
}
