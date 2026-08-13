//! Bloch-SIS Protocol hashrate + GENESIS_BITS calibration tool.
//!
//! Two modes of operation:
//!
//! 1. Benchmark: measure the local machine's SHA-256d hashrate for
//!    a fixed duration, then compute the compact `bits` value that
//!    would yield the desired average block time at that hashrate.
//!
//!    $ bloch-calibrate
//!    $ bloch-calibrate --duration 120 --threads 8 --target-time 10
//!
//! 2. Compute-only: skip the benchmark and compute bits for a hashrate
//!    you supply (useful for aggregating measurements across multiple
//!    machines — run bench locally on each, sum, then compute once).
//!
//!    $ bloch-calibrate --hashrate 23000000 --target-time 10
//!
//! Design
//! ======
//!
//! The benchmark hashes an 80-byte dummy header (Bitcoin-format,
//! matching Bloch-SIS Protocol's `MiningHeader::to_bytes` layout) in a tight
//! double-SHA256 loop on N threads. Counter flushes to an atomic every
//! 65 536 iterations to keep contention negligible.
//!
//! Compact bits conversion follows the Bitcoin convention used by
//! `bloch::core::bits_to_target`. The inverse `target_to_bits`
//! is implemented here in terms of plain u128 long division against
//! a 33-byte `[1, 0, 0, ..., 0]` dividend.
//!
//! Safety margin
//! =============
//!
//! The tool prints the raw bits for the measured hashrate. For a
//! mainnet launch, subtract 10-20% from the measured total to leave
//! headroom — if any machine is slower than benchmarked (thermal
//! throttling, co-tenancy on Akash) the network could stall. Rounding
//! DOWN the difficulty (easier target) is the safe direction: blocks
//! come a bit faster than 10s rather than much slower.

use clap::Parser;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sha2::{Sha256, Digest};

#[derive(Parser)]
#[command(name = "bloch-calibrate")]
#[command(about = "Measure hashrate + compute GENESIS_BITS for Bloch-SIS Protocol chain reset")]
struct Cli {
    /// Duration of the hashrate measurement in seconds.
    #[arg(long, default_value = "60")]
    duration: u64,

    /// Number of hashing threads. 0 = all available CPUs.
    #[arg(long, default_value = "0")]
    threads: usize,

    /// Skip the benchmark and compute bits for this hashrate (H/s).
    /// When set, --duration and --threads are ignored.
    #[arg(long)]
    hashrate: Option<u64>,

    /// Target average block time in seconds.
    #[arg(long, default_value = "10")]
    target_time: u64,

    /// Apply a safety margin (percent). Bits are computed for
    /// hashrate × (1 - margin/100), so blocks land a bit faster
    /// than target if the network is exactly at measured speed.
    #[arg(long, default_value = "15")]
    margin_pct: u64,
}

fn main() {
    let cli = Cli::parse();

    println!("================================================");
    println!("  Bloch-SIS Protocol GENESIS_BITS Calibration");
    println!("================================================");
    println!();

    let raw_hashrate = if let Some(h) = cli.hashrate {
        println!("Using supplied hashrate: {} H/s ({:.2} Mhash)", h, h as f64 / 1e6);
        h
    } else {
        measure_hashrate(cli.duration, cli.threads)
    };

    let adjusted = raw_hashrate.saturating_mul(100 - cli.margin_pct) / 100;

    println!();
    println!("Parameters");
    println!("  Raw hashrate:      {} H/s  ({:.2} Mhash/s)", raw_hashrate, raw_hashrate as f64 / 1e6);
    println!("  Safety margin:     {}%", cli.margin_pct);
    println!("  Design hashrate:   {} H/s  ({:.2} Mhash/s)", adjusted, adjusted as f64 / 1e6);
    println!("  Target block time: {} s", cli.target_time);
    println!();

    let expected_hashes = adjusted.saturating_mul(cli.target_time);
    if expected_hashes == 0 {
        eprintln!("error: design hashrate × target_time == 0; refusing to compute.");
        std::process::exit(1);
    }

    let target = div_2_256_by_u64(expected_hashes);
    let bits   = target_to_bits(&target);

    // Sanity-check the roundtrip via bits_to_target. For this we need
    // bloch-layer's own function — pulling in the lib crate keeps the
    // calibration tool honest about what the node will actually use.
    let roundtrip_target = bloch::core::bits_to_target(bits);
    let expected_at_roundtrip = count_hashes_per_block(&roundtrip_target);

    println!("Recommended GENESIS_BITS");
    println!("  bits:              0x{:08x}  ({})", bits, bits);
    println!();
    println!("Sanity check");
    println!("  expected hashes:   {}", expected_hashes);
    println!("  hashes at this bits: {}", expected_at_roundtrip);
    println!("  block time est:    {:.2} s", expected_at_roundtrip as f64 / raw_hashrate as f64);
    println!();
    println!("Next steps");
    println!("  1. Edit src/core/mod.rs:");
    println!("     pub const GENESIS_BITS: u32 = 0x{:08x};", bits);
    println!("  2. (Optional) Verify with `cargo test --test sprint_retarget`");
    println!("  3. Rebuild Docker image (see docs/operations/v0.6.0-reset.md)");
    println!();
}

/// SHA-256 double hash of a byte buffer.
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let a: [u8; 32] = Sha256::digest(data).into();
    Sha256::digest(a).into()
}

/// Spawn N threads hashing an 80-byte dummy Bitcoin-format header
/// tight-loop. Returns measured H/s.
fn measure_hashrate(duration_secs: u64, threads: usize) -> u64 {
    let n_threads = if threads == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    } else {
        threads
    };

    println!("Benchmarking on {} threads for {} seconds…", n_threads, duration_secs);
    println!();

    let counter = Arc::new(AtomicU64::new(0));
    let stop    = Arc::new(AtomicBool::new(false));

    let start = Instant::now();

    let mut handles = Vec::with_capacity(n_threads);
    for thread_id in 0..n_threads {
        let ctr   = counter.clone();
        let stop  = stop.clone();
        handles.push(std::thread::spawn(move || {
            // Dummy 80-byte header matching MiningHeader::to_bytes layout.
            // Content is arbitrary — we're measuring raw hash throughput.
            let mut header = [0u8; 80];
            header[0..4].copy_from_slice(&1u32.to_le_bytes());      // version
            header[4..36].copy_from_slice(&[0xAA; 32]);             // prev_hash
            header[36..68].copy_from_slice(&[0xBB; 32]);            // merkle_root
            header[68..72].copy_from_slice(&0x1234_5678u32.to_le_bytes()); // timestamp
            header[72..76].copy_from_slice(&0x1d00ffff_u32.to_le_bytes());  // bits

            let mut local = 0u64;
            let mut nonce: u32 = (thread_id as u32).wrapping_mul(0x0100_0000);

            while !stop.load(Ordering::Relaxed) {
                header[76..80].copy_from_slice(&nonce.to_le_bytes());
                let _ = double_sha256(&header);
                nonce = nonce.wrapping_add(1);
                local += 1;

                // Flush to global counter every 64k to keep contention
                // negligible in the hot loop.
                if local & 0xFFFF == 0 {
                    ctr.fetch_add(0x10000, Ordering::Relaxed);
                    local = 0;
                }
            }
            ctr.fetch_add(local, Ordering::Relaxed);
        }));
    }

    // Progress ticker: show running H/s each second.
    let ctr_display = counter.clone();
    let stop_display = stop.clone();
    let start_display = start;
    let display_handle = std::thread::spawn(move || {
        let mut last = 0u64;
        while !stop_display.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_secs(1));
            let now = ctr_display.load(Ordering::Relaxed);
            let elapsed = start_display.elapsed().as_secs_f64();
            let instant = now - last;
            last = now;
            let avg = now as f64 / elapsed;
            print!("\r  [{:>3}s]  instant: {:>10} H/s   avg: {:>10.0} H/s   ",
                   elapsed as u64, instant, avg);
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }
    });

    std::thread::sleep(Duration::from_secs(duration_secs));
    stop.store(true, Ordering::Relaxed);
    let _ = display_handle.join();

    for h in handles {
        let _ = h.join();
    }
    println!();

    let total = counter.load(Ordering::Relaxed);
    let elapsed = start.elapsed().as_secs_f64();
    let hashrate = (total as f64 / elapsed) as u64;

    println!("  Total hashes: {}", total);
    println!("  Elapsed:      {:.1} s", elapsed);
    println!("  Hashrate:     {} H/s  ({:.2} Mhash/s)", hashrate, hashrate as f64 / 1e6);

    hashrate
}

/// Compute 2^256 / divisor as a 32-byte big-endian integer.
///
/// Implemented as long division with carry in u128 (safe because
/// carry × 256 + byte ≤ (2^64 - 1) × 256 + 255 < 2^72).
fn div_2_256_by_u64(divisor: u64) -> [u8; 32] {
    assert!(divisor > 0);
    let d = divisor as u128;

    let mut result = [0u8; 32];
    // Dividend is [1, 0, 0, ..., 0] — 33 bytes. The leading 1 is the
    // initial carry; we then shift in 32 zero bytes.
    let mut carry: u128 = 1;

    for i in 0..32 {
        carry <<= 8; // shift in a zero byte
        let q = carry / d;
        // For realistic divisors (> 2^8), q fits u8. Clamp defensively.
        result[i] = q.min(255) as u8;
        carry -= q * d;
    }

    result
}

/// Compact-bits encoding from a 32-byte target.
/// Follows the same convention as `bloch::core::bits_to_target`.
fn target_to_bits(target: &[u8; 32]) -> u32 {
    let mut first_nonzero = 0;
    while first_nonzero < 32 && target[first_nonzero] == 0 {
        first_nonzero += 1;
    }
    if first_nonzero == 32 {
        return 0;
    }

    let exp = (32 - first_nonzero) as u32;

    let b0 = target[first_nonzero];
    let b1 = if first_nonzero + 1 < 32 { target[first_nonzero + 1] } else { 0 };
    let b2 = if first_nonzero + 2 < 32 { target[first_nonzero + 2] } else { 0 };

    let mut mant = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
    let mut exp_out = exp;

    // Bitcoin treats the top bit of mantissa as a sign flag; shift
    // right to keep the mantissa nominally positive.
    if mant & 0x0080_0000 != 0 {
        mant >>= 8;
        exp_out += 1;
    }

    (exp_out << 24) | (mant & 0x00FF_FFFF)
}

/// For diagnostics: rough count of hashes needed to hit the target.
/// Approximates 2^256 / target.
fn count_hashes_per_block(target: &[u8; 32]) -> u64 {
    // Approximation: take first non-zero byte, estimate bit position.
    let mut first_nz = 0;
    while first_nz < 32 && target[first_nz] == 0 { first_nz += 1; }
    if first_nz >= 28 {
        // Target is very small (< 2^32); hash count is huge. Return u64::MAX marker.
        return u64::MAX;
    }
    // Effective bit position of top bit
    let leading = target[first_nz].leading_zeros();
    let bit_pos = (31 - first_nz as u32) * 8 + (7 - leading);
    // 2^256 / target ≈ 2^(256 - bit_pos)
    let exp = 256u32.saturating_sub(bit_pos).saturating_sub(1);
    if exp >= 64 { u64::MAX } else { 1u64 << exp }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_to_bits_roundtrip_reference() {
        // 0x1d00ffff is the Bitcoin mainnet launch bits — target_to_bits
        // of its bits_to_target output should give us back 0x1d00ffff
        // (or very close).
        let target = bloch::core::bits_to_target(0x1d00ffff);
        let computed = target_to_bits(&target);
        assert_eq!(computed, 0x1d00ffff, "roundtrip should preserve canonical bits");
    }

    #[test]
    fn div_2_256_sanity() {
        // 2^256 / 1 ≈ 2^256 which doesn't fit in [u8; 32]; our implementation
        // saturates the top bytes. We don't call this with divisor=1 in
        // practice — just verify it doesn't panic.
        let _ = div_2_256_by_u64(1);

        // 2^256 / 2 = 2^255. Top byte should be 0x80.
        let r = div_2_256_by_u64(2);
        assert_eq!(r[0], 0x80, "2^256/2 top byte should be 0x80");
    }

    #[test]
    fn compute_pipeline_for_23_mhash() {
        // Reference calculation: 23 Mhash × 10s = 2.3e8 expected hashes.
        // target ≈ 2^256 / 2.3e8.
        let target = div_2_256_by_u64(23_000_000 * 10);
        let bits   = target_to_bits(&target);

        // Should land in the 0x1d range (similar to Bitcoin mainnet) or
        // 0x1e (slightly easier). Just sanity: non-zero, sensible exponent.
        let exp = (bits >> 24) & 0xff;
        assert!(exp >= 0x1c && exp <= 0x1e,
                "exponent should be 0x1c..0x1e for 23 Mhash × 10s, got 0x{:02x}", exp);

        // Round-trip: bits → target → hashes-per-block
        let rt_target = bloch::core::bits_to_target(bits);
        let hashes = count_hashes_per_block(&rt_target);
        let block_time = hashes as f64 / 23_000_000.0;
        assert!(block_time > 5.0 && block_time < 20.0,
                "block time should be 5..20s, got {:.2}s", block_time);
    }
}
