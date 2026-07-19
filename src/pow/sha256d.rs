//! SHA-256d PoW miner — the Genesis-2 (ASIC-compatible) mining path.
//!
//! Grinds the 32-bit nonce of the 80-byte `MiningHeader` projection
//! (`bloch_crypto::core::MiningHeader::to_bytes` layout, Bitcoin-identical)
//! with double SHA-256, across `threads` workers on DISJOINT stride ranges —
//! mirroring `mine_sis_pow_parallel`'s shape: worker `t` tries candidate
//! indices `t, t+threads, t+2·threads, …` offset from `start_nonce`, and the
//! first worker to find a solution wins.
//!
//! ## 32-bit nonce truncation (consensus note)
//! `BlockHeader.nonce` is u64 but only its LOW 32 bits enter the 80-byte
//! projection (`to_mining_header`), so the searchable space per header is
//! exactly 2³². This miner therefore searches nonces in
//! `[start_nonce, 2³²)` and **returns `None` at nonce exhaustion** — it does
//! NOT roll the timestamp itself, because the timestamp is a consensus field
//! owned by the block-template builder (validate_timestamp bounds it against
//! the parent and wall-clock). On `None`, the caller must rebuild the
//! template with a fresh timestamp (or extranonce in the coinbase) and call
//! again — never re-search a silently wrapped space.
//!
//! The returned nonce is a u64 with the upper 32 bits ZERO: assigning it to
//! `BlockHeader.nonce` reproduces exactly the 80-byte buffer that was hashed,
//! so `Block::validate_pow` (Sha256d arm) accepts it byte-for-byte.

use bloch_crypto::core::{bits_to_target, hash_meets_target, BlockHeader};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Length of the nonce-less mining-header prefix (`BlockHeader::pow_preimage`).
const PREIMAGE_LEN: usize = 76;

/// How often each worker polls the shared found-flag.
const POLL_MASK: u64 = 0x3FF; // every 1024 attempts

/// Mine the SHA-256d PoW for `header` at compact difficulty `bits`.
///
/// Searches the 32-bit nonce space from `start_nonce` (values ≥ 2³² make the
/// range empty ⇒ `None`), spending at most `max_attempts` hashes PER WORKER
/// (same budget semantics as `mine_sis_pow_parallel`). Returns the winning
/// nonce as a u64 (upper 32 bits zero) to assign to `BlockHeader.nonce`, or
/// `None` on budget/nonce-space exhaustion — see the module docs for why
/// exhaustion is surfaced instead of rolling the timestamp internally.
pub fn mine_sha256d(
    header: &BlockHeader,
    bits: u32,
    start_nonce: u64,
    max_attempts: u64,
    threads: usize,
) -> Option<u64> {
    mine_sha256d_preimage(&header.pow_preimage(), bits, start_nonce, max_attempts, threads)
}

/// Preimage-level entry point used by the chain-dispatching
/// `pow::mine_pow_parallel`: `preimage` must be the 76-byte nonce-less
/// mining-header prefix (`BlockHeader::pow_preimage()`); anything else fails
/// closed (`None`). The hash computed here is bit-identical to
/// `BlockHeader::pow_hash()` for the header the preimage came from with
/// `nonce = returned value`.
pub fn mine_sha256d_preimage(
    preimage: &[u8],
    bits: u32,
    start_nonce: u64,
    max_attempts: u64,
    threads: usize,
) -> Option<u64> {
    if preimage.len() != PREIMAGE_LEN {
        return None; // fail closed: not a mining-header prefix
    }
    if start_nonce > u32::MAX as u64 {
        return None; // nonce space already exhausted
    }
    let target = bits_to_target(bits);
    let n_threads = threads.max(1);

    let found = AtomicBool::new(false);
    // Winning nonce; u64::MAX = sentinel "none". If several workers find
    // solutions concurrently, keep the smallest (deterministic preference —
    // any of them is consensus-valid).
    let best = AtomicU64::new(u64::MAX);

    std::thread::scope(|scope| {
        for t in 0..n_threads {
            let found = &found;
            let best = &best;
            let target = &target;
            scope.spawn(move || {
                let mut buf = [0u8; 80];
                buf[..PREIMAGE_LEN].copy_from_slice(preimage);
                for i in 0..max_attempts {
                    if i & POLL_MASK == 0 && found.load(Ordering::Relaxed) {
                        return;
                    }
                    // Disjoint stride ranges: worker t owns indices
                    // t, t+n, t+2n, … offset from start_nonce.
                    let Some(idx) = i
                        .checked_mul(n_threads as u64)
                        .and_then(|x| x.checked_add(t as u64))
                        .and_then(|x| x.checked_add(start_nonce))
                    else {
                        return;
                    };
                    if idx > u32::MAX as u64 {
                        return; // 32-bit nonce space exhausted for this worker
                    }
                    buf[PREIMAGE_LEN..].copy_from_slice(&(idx as u32).to_le_bytes());
                    let h: [u8; 32] = Sha256::digest(Sha256::digest(buf)).into();
                    if hash_meets_target(&h, target) {
                        best.fetch_min(idx, Ordering::SeqCst);
                        found.store(true, Ordering::SeqCst);
                        return;
                    }
                }
            });
        }
    });

    match best.load(Ordering::SeqCst) {
        u64::MAX => None,
        n => Some(n),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_crypto::core::{BlockHeader, MerkleRoot};

    fn test_header() -> BlockHeader {
        BlockHeader {
            version:     1,
            parents:     vec![[7u8; 32]],
            merkle_root: MerkleRoot([9u8; 32]),
            timestamp:   1_777_000_000,
            bits:        0x1f00ffff, // target 0x0000ffff… ⇒ ~2^-16 per hash
            nonce:       0,
        }
    }

    /// Mined nonce satisfies the target when recomputed independently via
    /// BlockHeader::pow_hash (the exact consensus-side computation), both
    /// single- and multi-threaded. Chain-id independent — no validate_pow here
    /// (that cross-chain acceptance/rejection lives in the per-process
    /// integration tests tests/genesis2_pow_*.rs).
    #[test]
    fn mined_nonce_meets_target_single_and_multi_thread() {
        let header = test_header();
        let target = bits_to_target(header.bits);

        for threads in [1usize, 4] {
            let nonce = mine_sha256d(&header, header.bits, 0, 1 << 22, threads)
                .expect("2^-16 target must be hit well within the budget");
            assert!(nonce <= u32::MAX as u64, "upper 32 bits must be zero");
            let mut mined = header.clone();
            mined.nonce = nonce;
            assert!(
                hash_meets_target(&mined.pow_hash(), &target),
                "consensus-side pow_hash must accept the mined nonce (threads={threads})",
            );
        }
    }

    /// Nonce exhaustion returns None instead of wrapping: starting past the
    /// 32-bit boundary, and starting near it with an impossible target, both
    /// terminate with None.
    #[test]
    fn nonce_exhaustion_returns_none() {
        let header = test_header();
        // Start beyond the 32-bit space entirely.
        assert_eq!(
            mine_sha256d(&header, header.bits, (u32::MAX as u64) + 1, 1_000, 4),
            None,
        );
        // Start 256 below the boundary with an unreachable all-zero target
        // (bits exp out of range): must scan ≤ 257 nonces and stop, not wrap.
        assert_eq!(
            mine_sha256d(&header, 0x0000_0001, u32::MAX as u64 - 256, 1 << 20, 4),
            None,
        );
    }

    /// A non-76-byte preimage fails closed.
    #[test]
    fn wrong_preimage_length_fails_closed() {
        assert_eq!(mine_sha256d_preimage(&[0u8; 80], 0x207fffff, 0, 10, 1), None);
        assert_eq!(mine_sha256d_preimage(&[0u8; 75], 0x207fffff, 0, 10, 1), None);
    }
}
