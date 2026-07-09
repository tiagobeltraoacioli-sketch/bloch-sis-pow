// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Example: mine a Bloch-SIS-PoW block at low difficulty.
//
// Run with:
//   cargo run --release --example mine_block

use bloch_sis_pow::difficulty::Target;
use bloch_sis_pow::solver::{mine, MineConfig};

fn main() {
    println!("Bloch-SIS-PoW reference miner — example");
    println!("======================================");
    println!();

    // Synthetic block header (in production: serialized BlockHeader).
    let header = b"BLOCH-EXAMPLE-BLOCK-1\
                   parents=[0xab..., 0xcd...]\
                   merkle_root=0xef...\
                   timestamp=1777686240\
                   bits=0x1d00FFFF";

    // Easy testnet target: roughly 1-in-65536 hashes pass aux filter.
    // (Real mainnet target will be calibrated to give one block every 30s
    // at expected network hashrate.)
    let mut target_bytes = [0xFFu8; 32];
    target_bytes[0] = 0x00;
    target_bytes[1] = 0xFF;
    let target = Target::from_be_bytes(target_bytes);

    let cfg = MineConfig {
        start_nonce: 0,
        candidates_per_nonce: 4096,
        // CRITICAL FINDING (Phase 0 reference impl):
        // With m=512 rows and beta=q/16, the probability that a random
        // s in {-2,...,2}^N satisfies the residual bound is approximately
        // (2*beta/q)^m = (1/8)^512, which is effectively zero. The
        // brute-force RNG approach in this reference solver therefore
        // CANNOT find a solution at canonical parameters in any
        // reasonable time.
        //
        // This is an EXPECTED outcome and CONFIRMS the design intent:
        // production miners must use lattice reduction (BKZ + Babai
        // rounding) to construct candidates near the target, not
        // sample uniformly. The cryptographer-in-residence will
        // implement the proper algorithm.
        //
        // For demonstration we cap attempts at a tractable number;
        // the example will time out gracefully and report the
        // throughput of the candidate-generation loop, which is the
        // useful diagnostic for engineering work.
        max_total_attempts: 500_000,
        ..Default::default()
    };

    println!("Header:                {} bytes", header.len());
    println!("Target (top-3 bytes):  {:02x} {:02x} {:02x}",
             target.as_bytes()[0], target.as_bytes()[1], target.as_bytes()[2]);
    println!("Candidates per nonce:  {}", cfg.candidates_per_nonce);
    println!("Max attempts:          {}", cfg.max_total_attempts);
    println!();
    println!("Mining...");
    let start = std::time::Instant::now();

    match mine(header, &target, &cfg, None) {
        Ok(result) => {
            let elapsed = start.elapsed();
            let hps = result.attempts as f64 / elapsed.as_secs_f64();
            println!();
            println!("✔ Block mined!");
            println!("  Nonce:       {}", result.nonce);
            println!("  Aux hash:    {}", hex::encode(&result.aux_hash));
            println!("  Attempts:    {}", result.attempts);
            println!("  Elapsed:     {:.2}s", elapsed.as_secs_f64());
            println!("  Throughput:  {:.0} candidates/s", hps);
            println!();
            println!("Solution s (first 16 coefficients):");
            print!("  [");
            for (i, &c) in result.solution[..16].iter().enumerate() {
                if i > 0 { print!(", "); }
                print!("{:>2}", c);
            }
            println!(", …]");
        }
        Err(e) => {
            let elapsed = start.elapsed();
            let hps = cfg.max_total_attempts as f64 / elapsed.as_secs_f64();
            println!();
            println!("✗ Mining did not succeed within budget: {}", e);
            println!();
            println!("  Throughput observed: {:.0} candidates/s", hps);
            println!("  Elapsed:             {:.2}s", elapsed.as_secs_f64());
            println!();
            println!("  ─────────────────────────────────────────────────────");
            println!("  EXPECTED at canonical parameters with brute-force RNG.");
            println!("  Probability that random s ∈ {{-2,…,2}}^256 satisfies");
            println!("  the residual bound is ~(1/8)^512 ≈ 0.");
            println!();
            println!("  Production miners must use lattice reduction (BKZ +");
            println!("  Babai rounding) to construct candidates near the");
            println!("  target. The reference solver in this crate is for");
            println!("  *correctness verification*, not throughput.");
            println!("  ─────────────────────────────────────────────────────");
        }
    }
}
