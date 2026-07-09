//! Bloch-SIS Protocol — SHA-256d Miner (multi-threaded)

use crate::core::{BlockHeader, bits_to_target, hash_meets_target};
use log::info;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

pub struct MineResult {
    pub found: bool,
    pub nonce: u64,
    pub hash:  [u8; 32],
}

/// Mine a block header using all available CPU cores.
/// Each thread searches a different nonce range.
/// `max_attempts` applies per-thread (u64::MAX = unlimited).
pub fn mine_block(header: &mut BlockHeader, max_attempts: u64) -> MineResult {
    let num_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    // Single-thread fast path (also used when header is mutable)
    if num_threads <= 1 {
        return mine_single(header, max_attempts);
    }

    let target = bits_to_target(header.bits);
    let found = Arc::new(AtomicBool::new(false));
    let winner_nonce = Arc::new(AtomicU64::new(0));
    let total_hashes = Arc::new(AtomicU64::new(0));

    // Each thread gets a copy of the header with a different nonce start
    let range_per_thread = u64::MAX / num_threads as u64;

    std::thread::scope(|s| {
        let mut handles = Vec::new();

        for tid in 0..num_threads {
            let mut h = header.clone();
            let start = (tid as u64) * range_per_thread;
            h.nonce = start;
            let target = target;
            let found = found.clone();
            let winner_nonce = winner_nonce.clone();
            let total_hashes = total_hashes.clone();

            handles.push(s.spawn(move || {
                let mut attempts: u64 = 0;
                loop {
                    if found.load(Ordering::Relaxed) { return; }

                    let hash = h.pow_hash();
                    if hash_meets_target(&hash, &target) {
                        found.store(true, Ordering::Relaxed);
                        winner_nonce.store(h.nonce, Ordering::Relaxed);
                        return;
                    }

                    h.nonce = h.nonce.wrapping_add(1);
                    attempts += 1;
                    if attempts >= max_attempts { return; }

                    // Progress reporting (only thread 0)
                    if tid == 0 && attempts % 1_000_000 == 0 {
                        let total = total_hashes.load(Ordering::Relaxed) + attempts;
                        info!("Mining... {} Mhash ({} threads)", total / 1_000_000, num_threads);
                    }
                    if attempts % 500_000 == 0 {
                        total_hashes.fetch_add(500_000, Ordering::Relaxed);
                    }
                }
            }));
        }

        for h in handles {
            let _ = h.join();
        }
    });

    if found.load(Ordering::Relaxed) {
        header.nonce = winner_nonce.load(Ordering::Relaxed);
        let hash = header.pow_hash();
        info!("Block mined! nonce={} hash={} ({} threads)",
            header.nonce, hex::encode(&hash[..8]), num_threads);
        MineResult { found: true, nonce: header.nonce, hash }
    } else {
        MineResult { found: false, nonce: header.nonce, hash: [0u8; 32] }
    }
}

/// Single-threaded mining (fallback)
fn mine_single(header: &mut BlockHeader, max_attempts: u64) -> MineResult {
    let target = bits_to_target(header.bits);
    let mut attempts: u64 = 0;

    loop {
        let hash = header.pow_hash();
        if hash_meets_target(&hash, &target) {
            info!("Block mined! nonce={} hash={}", header.nonce, hex::encode(&hash[..8]));
            return MineResult { found: true, nonce: header.nonce, hash };
        }
        header.nonce = header.nonce.wrapping_add(1);
        attempts += 1;
        if attempts >= max_attempts {
            return MineResult { found: false, nonce: header.nonce, hash };
        }
        if attempts % 1_000_000 == 0 {
            info!("Mining... {} Mhash", attempts / 1_000_000);
        }
    }
}
