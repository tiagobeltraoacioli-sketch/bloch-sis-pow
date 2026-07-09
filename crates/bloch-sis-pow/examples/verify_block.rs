// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Example: mine then verify, demonstrating the round-trip and timing.
//
// Run with:
//   cargo run --release --example verify_block

use bloch_sis_pow::difficulty::Target;
use bloch_sis_pow::solver::{mine, MineConfig};
use bloch_sis_pow::verify::verify;

fn main() {
    println!("Bloch-SIS-PoW mine + verify round-trip");
    println!("======================================");
    println!();

    let header = b"BLOCH-EXAMPLE-VERIFY-1";
    let mut target_bytes = [0xFFu8; 32];
    target_bytes[0] = 0x00;
    target_bytes[1] = 0xFF;
    let target = Target::from_be_bytes(target_bytes);

    let cfg = MineConfig {
        start_nonce: 0,
        candidates_per_nonce: 8192,
        max_total_attempts: 5_000_000,
        ..Default::default()
    };

    println!("Step 1: mining a valid PoW...");
    let mine_start = std::time::Instant::now();
    let r = match mine(header, &target, &cfg, None) {
        Ok(r)  => r,
        Err(e) => {
            println!("  ✗ Could not mine within budget: {}", e);
            return;
        }
    };
    let mine_elapsed = mine_start.elapsed();
    println!("  ✔ Found nonce={}, attempts={}, elapsed={:.2}s",
             r.nonce, r.attempts, mine_elapsed.as_secs_f64());

    println!();
    println!("Step 2: verifying...");
    let verify_start = std::time::Instant::now();
    let n_verifications = 100;
    for _ in 0..n_verifications {
        verify(header, r.nonce, &r.solution, &target)
            .expect("freshly mined PoW must verify");
    }
    let verify_elapsed = verify_start.elapsed();
    let avg_verify_us = verify_elapsed.as_micros() as f64 / n_verifications as f64;
    println!("  ✔ Verification successful");
    println!("  Avg verify time: {:.0} µs ({} verifications averaged)",
             avg_verify_us, n_verifications);

    println!();
    println!("Step 3: confirming corruption is rejected...");

    // Tamper with a coefficient and re-verify; must fail.
    let mut bad = r.solution;
    bad[0] = if bad[0] == 0 { 1 } else { 0 };
    match verify(header, r.nonce, &bad, &target) {
        Ok(())   => println!("  ⚠ Unexpectedly accepted; investigate."),
        Err(e)   => println!("  ✔ Correctly rejected: {}", e),
    }

    // Tamper with the nonce.
    match verify(header, r.nonce.wrapping_add(1), &r.solution, &target) {
        Ok(())   => println!("  ⚠ Tampered nonce accepted; investigate."),
        Err(e)   => println!("  ✔ Tampered nonce rejected: {}", e),
    }

    // Tamper with the header.
    let mut bad_header = header.to_vec();
    bad_header[0] ^= 0x01;
    match verify(&bad_header, r.nonce, &r.solution, &target) {
        Ok(())   => println!("  ⚠ Tampered header accepted; investigate."),
        Err(e)   => println!("  ✔ Tampered header rejected: {}", e),
    }

    println!();
    println!("Done.");
}
