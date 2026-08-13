//! LOCAL MINING DEMO — "Dual AND" hybrid PoW (design probe, NOT consensus).
//!
//! Actually MINES a block that satisfies BOTH proof-of-work schemes at once:
//!   valid(block) = sha256d_ok(header)  AND  sis_ok(header, pow_solution)
//!
//! The two schemes share ONE search variable — the 32-bit nonce — so grinding
//! it moves both PoWs together (the coupling that makes the AND non-cosmetic):
//!   * SHA-256d hashes the full 80-byte MiningHeader (nonce at bytes 76..80).
//!   * SIS seed = SHAKE256(DOMAIN || pow_preimage[0..76] || nonce_le).
//!
//! Mining loop (DoS-safe order): grind nonce -> cheap SHA-256d gate FIRST ->
//! only on a SHA hit, run the expensive SIS solve BOUND TO THAT SAME NONCE
//! (budget capped at one nonce's candidates so a witness can't be found for a
//! different nonce). First nonce that clears BOTH is a Dual AND block.
//!
//! Run:  cargo run --release --example mine_dual_and
//!       SHA_BITS=20 cargo run --release --example mine_dual_and   (harder SHA)

use std::time::Instant;

use bloch::core::{sha256d_pow_valid, BlockHeader, MerkleRoot};
use bloch::pow;

/// Number of leading zero BITS the SHA-256d hash must have (tunable via env).
/// 16 => ~65k hashes expected (sub-second in release). Raise for more grind.
fn sha_leading_zero_bits() -> u32 {
    std::env::var("SHA_BITS").ok().and_then(|s| s.parse().ok()).unwrap_or(16)
}

/// Big-endian target with `bits` leading zeros then all-ones: hash <= target
/// iff the hash has at least `bits` leading zero bits.
fn target_with_leading_zeros(bits: u32) -> [u8; 32] {
    let mut t = [0xFFu8; 32];
    let full = (bits / 8) as usize;
    for b in t.iter_mut().take(full) {
        *b = 0x00;
    }
    let rem = bits % 8;
    if full < 32 && rem > 0 {
        t[full] = 0xFFu8 >> rem;
    }
    t
}

fn header_at(nonce: u64) -> BlockHeader {
    BlockHeader {
        version: 1,
        parents: vec![],
        merkle_root: MerkleRoot::ZERO,
        timestamp: 1_777_000_000,
        // Easiest SIS AUX target: the real SIS work is the k=4 residual gate
        // (4096 candidate short-vectors per nonce), which keeps the demo fast.
        bits: pow::target_to_bits(&pow::Target::MAX),
        nonce,
    }
}

fn main() {
    let sha_bits = sha_leading_zero_bits();
    let sha_target = target_with_leading_zeros(sha_bits);
    let sis_bits = pow::target_to_bits(&pow::Target::MAX);
    // Post-activation height so the SIS co-requirement is enforced.
    let height: u64 = 5_000;
    // pow_preimage excludes the nonce (76 bytes) -> identical for every nonce.
    let preimage = header_at(0).pow_preimage();

    println!("=== Dual AND local mining demo ===");
    println!(
        "SHA-256d target: {} leading zero bits  |  SIS: k=4 testnet regime, 4096 candidates/nonce",
        sha_bits
    );
    println!("Rule (height {height} >= activation): block valid IFF SHA-256d hit AND SIS witness bound to the SAME nonce\n");

    let t0 = Instant::now();
    let mut hashes: u64 = 0;
    let mut sha_hits: u64 = 0;
    let mut sis_tries: u64 = 0;

    let mut nonce: u64 = 0;
    loop {
        let header = header_at(nonce);
        hashes += 1;

        // (1) cheap SHA-256d gate FIRST
        if sha256d_pow_valid(&header.pow_hash(), &sha_target, height) {
            sha_hits += 1;
            // (2) SIS solve BOUND TO THIS EXACT nonce (budget <= one nonce's
            //     candidates so it cannot wander to a different nonce).
            sis_tries += 1;
            if let Some((got_nonce, solution)) =
                pow::mine_sis_pow_testnet(&preimage, sis_bits, nonce, 4096)
            {
                assert_eq!(got_nonce, nonce, "coupling: SIS witness must bind the SHA nonce");
                let dt = t0.elapsed();

                // Independent verification of BOTH components.
                let sha_ok = sha256d_pow_valid(&header.pow_hash(), &sha_target, height);
                let mut s = [0i32; pow::SOLUTION_LEN];
                s.copy_from_slice(&solution);
                let sis_ok =
                    pow::verify_sis_pow_testnet(&header.pow_preimage(), header.nonce, &s, sis_bits)
                        .is_ok();

                let pow_hash = header.pow_hash();
                println!("*** DUAL AND BLOCK MINED ***");
                println!("  nonce            : {nonce}  (< 2^32: {})", nonce < (1u64 << 32));
                println!("  SHA-256d pow_hash: {}", hex::encode(pow_hash));
                println!(
                    "  leading zero bits: {}",
                    pow_hash.iter().map(|b| b.leading_zeros() as u32).take_while(|&z| z == 8).count() as u32 * 8
                        + pow_hash.iter().find(|&&b| b != 0).map(|&b| b.leading_zeros()).unwrap_or(0)
                );
                println!("  SIS witness      : 256-dim vector, first 8 coeffs = {:?}", &s[..8]);
                println!(
                    "  witness norm     : ||s||_inf = {}",
                    s.iter().map(|c| c.abs()).max().unwrap_or(0)
                );
                println!();
                println!("  VERIFY  SHA-256d : {}", if sha_ok { "PASS" } else { "FAIL" });
                println!("  VERIFY  SIS      : {}", if sis_ok { "PASS" } else { "FAIL" });
                println!(
                    "  VERIFY  Dual AND : {}",
                    if sha_ok && sis_ok { "PASS (both)" } else { "FAIL" }
                );
                println!();
                println!(
                    "  work: {hashes} SHA hashes, {sha_hits} SHA hits, {sis_tries} SIS solves, in {:.2?}",
                    dt
                );
                println!(
                    "  rate: {:.0} H/s (SHA gate)",
                    hashes as f64 / dt.as_secs_f64().max(1e-9)
                );
                assert!(sha_ok && sis_ok, "mined block must verify under BOTH schemes");
                println!("\nOK — a real Dual AND block was mined and re-verified locally.");
                return;
            }
            // SHA hit but no SIS witness at this nonce -> keep grinding.
        }

        nonce += 1;
        if nonce % 200_000 == 0 {
            println!(
                "  ...grinding: {hashes} hashes, {sha_hits} SHA hits, {sis_tries} SIS solves, {:.1?}",
                t0.elapsed()
            );
        }
        if nonce >= (1u64 << 32) {
            eprintln!("exhausted 32-bit nonce space without a Dual AND block; lower SHA_BITS");
            std::process::exit(1);
        }
    }
}
