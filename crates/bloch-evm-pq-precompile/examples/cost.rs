// SPDX-License-Identifier: AGPL-3.0-or-later
//! Native wall-clock harness for the §6.2 precompile.
//!
//!     cargo run --release --example cost -p bloch-evm-pq-precompile
//!
//! Not a test: it measures THIS machine. The activation gate is the same
//! measurement on the slowest box in the fleet, with the worst-case input.
//! The gas schedule is anchored to the RV32IM instruction count from
//! `spikes/prover-cost/RESULTS.md`, not to any wall clock — this harness
//! exists to answer a different question: does a block full of `pq_verify`
//! fit inside a 30-second slot?

use bloch_crypto::crypto;
use bloch_evm_pq_precompile::*;
use bloch_pos_committee::fee_market::BLOCK_GAS_LIMIT;
use std::time::Instant;

const RUNS: u32 = 25;

fn main() {
    let (pk, sk) = crypto::generate_keypair_from_seed(&[0x11; 32]).expect("keygen");
    let msg = [0x5a; 32];
    let sig = crypto::sign(&sk, &msg).expect("sign");
    let input = encode_input(&msg, &pk, &sig);

    println!("pk        {} B", pk.len());
    println!("sig       {} B  (band {}..={})", sig.len(), MIN_ENVELOPED_SIG_LEN, MAX_ENVELOPED_SIG_LEN);
    println!("input     {} B  (max {})", input.len(), MAX_INPUT_BYTES);
    println!("gas       {}", pq_verify_gas(input.len()));
    println!();

    assert_ne!(pq_verify_raw(&input), REJECTED, "harness must measure a REAL verification");

    let mut samples: Vec<u128> = Vec::with_capacity(RUNS as usize);
    for _ in 0..RUNS {
        let t = Instant::now();
        let out = pq_verify_raw(&input);
        let dt = t.elapsed().as_micros();
        assert_ne!(out, REJECTED);
        samples.push(dt);
    }
    samples.sort_unstable();
    let median = samples[samples.len() / 2];
    println!("verify    min {} us  median {} us  max {} us  (n={})",
             samples[0], median, samples[samples.len() - 1], RUNS);

    // A rejected call does no verification work — the two must not be confused
    // when quoting "calls per block".
    let junk = vec![0u8; HEADER_LEN];
    let t = Instant::now();
    for _ in 0..1000 {
        std::hint::black_box(pq_verify_raw(&junk));
    }
    println!("reject    {} us / 1000 calls", t.elapsed().as_micros());
    println!();

    let per_call_gas = pq_verify_gas(input.len());
    let calls = BLOCK_GAS_LIMIT / per_call_gas;
    let cheapest = pq_verify_gas(MIN_VERIFYING_INPUT_BYTES);
    let worst_calls = BLOCK_GAS_LIMIT / cheapest;
    println!("one block of gas buys {calls} calls at this size, {worst_calls} at the cheapest verifying size");
    println!("worst case wall clock  {:.3} s  = {:.2}% of a 30 s slot",
             worst_calls as f64 * median as f64 / 1e6,
             worst_calls as f64 * median as f64 / 1e6 / 30.0 * 100.0);
}
