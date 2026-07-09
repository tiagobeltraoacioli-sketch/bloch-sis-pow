// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Example: end-to-end mining + verification using a *test-only* relaxed
// parameter set. This demonstrates the algorithm working end-to-end,
// which the canonical-parameter brute-force example cannot.
//
// Run with:
//   cargo run --release --example mine_easy
//
// IMPORTANT: This example bypasses the canonical residual bound (β)
// to make brute-force search tractable. It is for *algorithm
// validation only* and DOES NOT represent the security level of
// real Bloch-SIS-PoW. Production miners use BKZ + Babai rounding
// to find solutions at canonical parameters.

use bloch_sis_pow::difficulty::{hash_meets_target, Target};
use bloch_sis_pow::encode::encode_s;
use bloch_sis_pow::expand::expand_matrix_and_target;
use bloch_sis_pow::field::infinity_norm;
use bloch_sis_pow::matrix::residual_centered;
use bloch_sis_pow::shake::shake256_dom;
use bloch_sis_pow::solver::derive_pow_seed;
use bloch_sis_pow::DOMAIN_LABEL_POW_AUX;

const N: usize = 256;
const B: i32 = 2;

// RELAXED demo: only check the FIRST k coefficients of the residual.
// k=4 → probability (1/8)^4 ≈ 1/4096 per candidate. With ~13K candidates/s
// CPU throughput, expected time ≈ 0.3 seconds. Demonstrates the full
// algorithm path end-to-end in a runnable example.
//
// Real β check applies to all 512 residual coefficients, requiring
// lattice reduction techniques (BKZ + Babai) that are out of scope
// for this reference implementation.
const DEMO_RESIDUAL_PREFIX: usize = 4;
const DEMO_BETA_I64: i64 = 8_380_417i64 / 16;  // canonical β, but only on first 4 coords

fn main() {
    println!("Bloch-SIS-PoW algorithm validation (prefix-residual demo)");
    println!("=========================================================");
    println!();
    println!("⚠ This example checks the residual bound β=q/16 on only");
    println!("  the FIRST 4 coefficients (instead of all 512), making");
    println!("  brute-force search tractable. Demonstrates end-to-end");
    println!("  flow; does NOT represent real Bloch-SIS-PoW security.");
    println!();

    let header = b"BLOCH-EASY-DEMO-1";
    let target = Target::MAX; // skip aux filter for this demo

    let mut total_attempts = 0u64;
    let max_attempts = 5_000_000u64;
    let start = std::time::Instant::now();
    let mut nonce = 0u64;

    'outer: loop {
        let seed = derive_pow_seed(header, nonce);
        let (a, t) = expand_matrix_and_target(&seed);

        let mut state = nonce.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        for _ in 0..2048 {
            total_attempts += 1;
            if total_attempts >= max_attempts {
                println!("✗ Did not find solution within {} attempts.", max_attempts);
                return;
            }

            // Sample candidate s
            let mut s = [0i32; N];
            for slot in s.iter_mut() {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                let v = ((state >> 33) % (2 * B as u64 + 1)) as i32;
                *slot = v - B;
            }

            // Residual check on first DEMO_RESIDUAL_PREFIX coefficients
            // (relaxed for tractability of brute-force demo).
            let r = residual_centered(&a, &s, &t);
            let prefix_norm = infinity_norm(&r[..DEMO_RESIDUAL_PREFIX]);
            if (prefix_norm as i64) >= DEMO_BETA_I64 {
                continue;
            }

            // Aux hash check (Target::MAX so any hash passes)
            let s_bytes = encode_s(&s).expect("valid s");
            let aux = shake256_dom(
                DOMAIN_LABEL_POW_AUX,
                &[&s_bytes, &nonce.to_le_bytes(), header],
                32,
            );
            let mut aux_arr = [0u8; 32];
            aux_arr.copy_from_slice(&aux);
            if hash_meets_target(&aux_arr, &target) {
                let elapsed = start.elapsed();
                println!("✔ Found valid (nonce, s) pair!");
                println!("  Nonce:        {}", nonce);
                println!("  Attempts:     {}", total_attempts);
                println!("  Elapsed:      {:.2}s", elapsed.as_secs_f64());
                println!("  Prefix residual norm: {} (canonical β={}, on first {} coords)",
                         prefix_norm, DEMO_BETA_I64, DEMO_RESIDUAL_PREFIX);
                println!("  Aux hash:     {}", hex::encode(&aux_arr[..16]));
                println!();
                println!("  s (first 16):  [");
                for (i, &c) in s[..16].iter().enumerate() {
                    if i > 0 { print!(", "); }
                    print!("{:>2}", c);
                }
                println!("  ]");
                break 'outer;
            }
        }

        nonce = nonce.wrapping_add(1);
    }

    println!();
    println!("Note: under canonical β = q/16, the same brute-force");
    println!("search would never terminate. Production mining requires");
    println!("lattice reduction techniques. See");
    println!("  Bloch_SIS_PoW_Academic_Foundations_v0.1.pdf, §6, §10");
    println!("for the algorithmic upgrade path.");
}
