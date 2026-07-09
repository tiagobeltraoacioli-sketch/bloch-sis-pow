//! Bloch-SIS Protocol — Chain Analytics
//!
//! Sprint B: aggregated data primitives for node ops and explorer use.
//! All functions here are read-only, derived from storage + mempool state.
//! None of them affect consensus; safe to add/remove without hard fork.

use crate::storage::Storage;
use crate::mempool::Mempool;
use crate::core::{Block, TARGET_BLOCK_TIME};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Supply distribution
// ─────────────────────────────────────────────────────────────────────────────

/// Address balance tiers (in satoshis) for supply distribution histogram.
const TIER_BOUNDS: &[u64] = &[
    1_00_000_000,          // 1 BLOCH
    10_00_000_000,         // 10 BLOCH
    100_00_000_000,        // 100 BLOCH
    1_000_00_000_000,      // 1,000 BLOCH
    10_000_00_000_000,     // 10,000 BLOCH
    100_000_00_000_000,    // 100,000 BLOCH
    1_000_000_00_000_000,  // 1,000,000 BLOCH
];

const TIER_LABELS: &[&str] = &[
    "< 1 BLOCH",
    "1 – 10 BLOCH",
    "10 – 100 BLOCH",
    "100 – 1k BLOCH",
    "1k – 10k BLOCH",
    "10k – 100k BLOCH",
    "100k – 1M BLOCH",
    "> 1M BLOCH",
];

pub struct SupplyTier {
    pub label:          String,
    pub address_count:  u64,
    pub total_sats:     u64,
    pub total_bloch:     f64,
    pub pct_of_supply:  f64,
}

pub struct SupplyDistribution {
    pub tiers:           Vec<SupplyTier>,
    pub total_addresses: u64,
    pub total_sats:      u64,
    pub total_bloch:      f64,
}

/// Compute histogram of addresses by balance tier.
///
/// Iterates all UTXOs (O(n)) and groups by script_pubkey, then bins by tier.
/// Acceptable for current chain size (~309 treasury UTXOs + sparse user UTXOs).
/// For future scale, consider caching this per block or adding a dedicated index.
pub fn supply_distribution(storage: &Storage) -> Result<SupplyDistribution, String> {
    // Walk all blocks to find all unique script_pubkeys (addresses)
    // and sum their UTXO values. This is O(n_blocks + n_outputs).
    //
    // Alternative: iterate the UTXO column family directly — but current
    // Storage API doesn't expose iter_all_utxos(). Workaround: derive from
    // blocks + spent inputs.

    let blocks = storage.iter_all_blocks();
    let mut address_balances: HashMap<Vec<u8>, u64> = HashMap::new();
    let mut spent: std::collections::HashSet<([u8; 32], u32)> = std::collections::HashSet::new();

    // First pass: collect all spent outpoints
    for (_hash, block) in &blocks {
        for tx in &block.transactions {
            if tx.is_coinbase() { continue; }
            for inp in &tx.inputs {
                spent.insert((inp.prev_txid, inp.prev_index));
            }
        }
    }

    // Second pass: for each output, credit address if not spent
    for (_hash, block) in &blocks {
        for tx in &block.transactions {
            let txid = tx.txid();
            for (idx, out) in tx.outputs.iter().enumerate() {
                if spent.contains(&(txid, idx as u32)) { continue; }
                if out.script_pubkey.is_empty() { continue; }
                *address_balances.entry(out.script_pubkey.clone()).or_insert(0) += out.value;
            }
        }
    }

    // Bin into tiers
    let mut tier_counts = vec![0u64; TIER_LABELS.len()];
    let mut tier_sats = vec![0u64; TIER_LABELS.len()];
    let mut total_sats = 0u64;

    for (_addr, bal) in &address_balances {
        if *bal == 0 { continue; }
        total_sats = total_sats.saturating_add(*bal);
        let tier = TIER_BOUNDS.iter().position(|b| bal < b).unwrap_or(TIER_LABELS.len() - 1);
        tier_counts[tier] += 1;
        tier_sats[tier] = tier_sats[tier].saturating_add(*bal);
    }

    let tiers: Vec<SupplyTier> = TIER_LABELS.iter().enumerate().map(|(i, label)| {
        let total_bloch = tier_sats[i] as f64 / 1e8;
        let pct_of_supply = if total_sats > 0 { (tier_sats[i] as f64 / total_sats as f64) * 100.0 } else { 0.0 };
        SupplyTier {
            label:         label.to_string(),
            address_count: tier_counts[i],
            total_sats:    tier_sats[i],
            total_bloch,
            pct_of_supply,
        }
    }).collect();

    Ok(SupplyDistribution {
        tiers,
        total_addresses: address_balances.len() as u64,
        total_sats,
        total_bloch: total_sats as f64 / 1e8,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Chain stats
// ─────────────────────────────────────────────────────────────────────────────

pub struct ChainStats {
    pub total_blocks:        u64,
    pub total_txs:           u64,
    pub avg_txs_per_block:   f64,
    pub total_utxos:         u64,
    pub blocks_last_24h:     u64,
    pub txs_last_24h:        u64,
    pub avg_block_time:      f64,
    pub current_difficulty:  u32,
    pub hashrate_estimate:   f64,
}

pub fn chain_stats(storage: &Storage, _mempool: &Mempool) -> Result<ChainStats, String> {
    let blocks = storage.iter_all_blocks();
    let mut total_txs = 0u64;

    // Filter blocks from last 24h (86400 seconds)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let cutoff_24h = now.saturating_sub(86_400);

    let mut blocks_last_24h = 0u64;
    let mut txs_last_24h = 0u64;
    let mut latest_bits: u32 = 0x1d00ffff;
    let mut latest_height: u64 = 0;

    for (_hash, block) in &blocks {
        total_txs += block.transactions.len() as u64;
        if block.header.timestamp >= cutoff_24h {
            blocks_last_24h += 1;
            txs_last_24h += block.transactions.len() as u64;
        }
        if block.height > latest_height {
            latest_height = block.height;
            latest_bits = block.header.bits;
        }
    }

    let total_blocks = blocks.len() as u64;
    let avg_txs_per_block = if total_blocks > 0 { total_txs as f64 / total_blocks as f64 } else { 0.0 };

    // Rough block time from last 50 blocks
    let mut sorted_blocks: Vec<&Block> = blocks.iter().map(|(_, b)| b).collect();
    sorted_blocks.sort_by_key(|b| b.height);
    let sample: Vec<&Block> = sorted_blocks.iter().rev().take(50).copied().collect();
    let avg_block_time = if sample.len() >= 2 {
        let t_last = sample[0].header.timestamp;
        let t_first = sample.last().map(|b| b.header.timestamp).unwrap_or(t_last);
        let span = t_last.saturating_sub(t_first);
        span as f64 / (sample.len() - 1) as f64
    } else {
        TARGET_BLOCK_TIME as f64
    };

    let hashrate = estimate_hashrate(latest_bits, avg_block_time);

    Ok(ChainStats {
        total_blocks,
        total_txs,
        avg_txs_per_block,
        total_utxos: 0, // Would need iter_utxos — skip for now
        blocks_last_24h,
        txs_last_24h,
        avg_block_time,
        current_difficulty: latest_bits,
        hashrate_estimate: hashrate,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Hashrate estimate
// ─────────────────────────────────────────────────────────────────────────────

/// Estimate network hashrate in hashes per second from difficulty and block time.
///
/// Formula: target = bits_to_target(bits), expected_hashes_per_block = 2^256 / target
/// hashrate = expected_hashes_per_block / avg_block_time_seconds
pub fn estimate_hashrate(bits: u32, avg_block_time_secs: f64) -> f64 {
    if avg_block_time_secs <= 0.0 { return 0.0; }

    // Compute target from bits
    let exponent = ((bits >> 24) & 0xff) as i32;
    let mantissa = (bits & 0x00ffffff) as f64;

    // target = mantissa * 256^(exponent - 3)
    let target = mantissa * 256f64.powi(exponent - 3);
    if target <= 0.0 { return 0.0; }

    // 2^256 = max_target
    let max_target = 2f64.powi(256);

    // Expected hashes per block = max_target / target
    let hashes_per_block = max_target / target;

    hashes_per_block / avg_block_time_secs
}

// ─────────────────────────────────────────────────────────────────────────────
// Difficulty history
// ─────────────────────────────────────────────────────────────────────────────

pub struct DifficultyPoint {
    pub height:     u64,
    pub bits:       u32,
    pub timestamp:  u64,
    pub target_hex: String,
}

pub fn difficulty_history(storage: &Storage, limit: usize) -> Vec<DifficultyPoint> {
    let blocks = storage.iter_all_blocks();
    let mut sorted: Vec<&Block> = blocks.iter().map(|(_, b)| b).collect();
    sorted.sort_by_key(|b| b.height);

    let mut result = Vec::new();
    let mut last_bits: u32 = 0;

    for b in sorted.iter().rev() {
        if b.header.bits != last_bits {
            result.push(DifficultyPoint {
                height:     b.height,
                bits:       b.header.bits,
                timestamp:  b.header.timestamp,
                target_hex: hex::encode(crate::core::bits_to_target(b.header.bits)),
            });
            last_bits = b.header.bits;
            if result.len() >= limit { break; }
        }
    }

    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Block time percentiles
// ─────────────────────────────────────────────────────────────────────────────

pub struct BlockTimeStats {
    pub sample_size: usize,
    pub min:         u64,
    pub p50:         u64,
    pub p90:         u64,
    pub p99:         u64,
    pub max:         u64,
    pub avg:         f64,
}

pub fn block_time_percentiles(storage: &Storage, window: usize) -> BlockTimeStats {
    let blocks = storage.iter_all_blocks();
    let mut sorted: Vec<&Block> = blocks.iter().map(|(_, b)| b).collect();
    sorted.sort_by_key(|b| b.height);

    // Take last `window` blocks
    let sample: Vec<&Block> = sorted.iter().rev().take(window + 1).copied().collect();

    if sample.len() < 2 {
        return BlockTimeStats {
            sample_size: 0,
            min: 0, p50: 0, p90: 0, p99: 0, max: 0, avg: 0.0,
        };
    }

    // Compute deltas between consecutive blocks
    let mut deltas: Vec<u64> = Vec::new();
    for i in 1..sample.len() {
        let t1 = sample[i-1].header.timestamp;
        let t0 = sample[i].header.timestamp;
        deltas.push(t1.saturating_sub(t0));
    }

    if deltas.is_empty() {
        return BlockTimeStats {
            sample_size: 0,
            min: 0, p50: 0, p90: 0, p99: 0, max: 0, avg: 0.0,
        };
    }

    deltas.sort();
    let n = deltas.len();
    let p = |pct: f64| -> u64 {
        let idx = ((n - 1) as f64 * pct).round() as usize;
        deltas[idx.min(n - 1)]
    };

    let sum: u64 = deltas.iter().sum();
    let avg = sum as f64 / n as f64;

    BlockTimeStats {
        sample_size: n,
        min:         *deltas.first().unwrap(),
        p50:         p(0.50),
        p90:         p(0.90),
        p99:         p(0.99),
        max:         *deltas.last().unwrap(),
        avg,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mempool stats (beyond getmempoolinfo)
// ─────────────────────────────────────────────────────────────────────────────

pub struct MempoolStats {
    pub size:        usize,
    pub total_fees:  u64,
    pub min_fee:     u64,
    pub max_fee:     u64,
    pub median_fee:  u64,
    pub avg_fee:     f64,
    pub buckets:     Vec<MempoolFeeBucket>,
}

pub struct MempoolFeeBucket {
    pub range:       String,
    pub tx_count:    usize,
}

pub fn mempool_stats(mempool: &Mempool) -> MempoolStats {
    let entries = mempool.entries();
    let size = entries.len();

    if size == 0 {
        return MempoolStats {
            size: 0,
            total_fees: 0,
            min_fee: 0, max_fee: 0, median_fee: 0,
            avg_fee: 0.0,
            buckets: Vec::new(),
        };
    }

    let mut fees: Vec<u64> = entries.iter().map(|(_, fee, _)| *fee).collect();
    fees.sort();

    let total_fees: u64 = fees.iter().sum();
    let avg_fee = total_fees as f64 / size as f64;
    let median_fee = fees[size / 2];

    // Fee rate buckets (sats)
    let bucket_bounds: &[(u64, &str)] = &[
        (100,       "0-100"),
        (1_000,     "100-1k"),
        (10_000,    "1k-10k"),
        (100_000,   "10k-100k"),
        (u64::MAX,  ">100k"),
    ];

    let mut buckets = Vec::new();
    let mut last_bound = 0u64;
    for (bound, label) in bucket_bounds {
        let count = fees.iter().filter(|&&f| f >= last_bound && f < *bound).count();
        buckets.push(MempoolFeeBucket {
            range:    label.to_string(),
            tx_count: count,
        });
        last_bound = *bound;
    }

    MempoolStats {
        size,
        total_fees,
        min_fee:    *fees.first().unwrap(),
        max_fee:    *fees.last().unwrap(),
        median_fee,
        avg_fee,
        buckets,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Address info (aggregate view)
// ─────────────────────────────────────────────────────────────────────────────

pub struct AddressInfo {
    pub address:           String,
    pub balance_sats:      u64,
    pub balance_bloch:      f64,
    pub utxo_count:        usize,
    pub pending_incoming:  u64,
    pub pending_outgoing:  u64,
    pub pool_role:         Option<String>,
}

pub fn address_info(
    storage: &Storage,
    mempool: &Mempool,
    addr_str: &str,
    addr_hash: &[u8; 20],
) -> Result<AddressInfo, String> {
    let (balance_sats, utxo_count) = storage.get_balance(addr_hash).map_err(|e| e.to_string())?;

    // Pending balance from mempool
    let utxo_lookup = |txid: &[u8; 32], index: u32| -> Option<crate::core::TxOutput> {
        storage.get_utxo(txid.as_slice(), index).ok().flatten()
    };
    let (pending_incoming, pending_outgoing) = mempool.pending_balance_for(
        addr_hash,
        Some(&utxo_lookup),
    );

    // V2 (ADR-028): identify whether the queried address corresponds to
    // one of the protocol pools. Returns None for ordinary user addresses.
    use crate::core::tokenomics_v2 as v2;
    let pool_role: Option<String> =
        if matches!(v2::VALIDATOR_POOL_ADDRESS_HASH, Some(h) if &h == addr_hash) {
            Some("validator_pool".to_string())
        } else if matches!(v2::ORACLE_POOL_ADDRESS_HASH, Some(h) if &h == addr_hash) {
            Some("oracle_pool".to_string())
        } else if matches!(v2::FOUNDER_ADDRESS_HASH, Some(h) if &h == addr_hash) {
            Some("founder".to_string())
        } else {
            None
        };

    Ok(AddressInfo {
        address:          addr_str.to_string(),
        balance_sats,
        balance_bloch:     balance_sats as f64 / 1e8,
        utxo_count,
        pending_incoming,
        pending_outgoing,
        pool_role,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Fee estimation (advanced)
// ─────────────────────────────────────────────────────────────────────────────

pub struct FeeEstimate {
    pub next_block_sats:  u64,
    pub medium_priority:  u64,
    pub slow_priority:    u64,
    pub mempool_median:   u64,
    pub mempool_size:     usize,
}

pub fn estimate_fee_advanced(mempool: &Mempool) -> FeeEstimate {
    let entries = mempool.entries();
    let mut fees: Vec<u64> = entries.iter().map(|(_, fee, _)| *fee).collect();
    fees.sort_by(|a, b| b.cmp(a)); // highest first

    let mempool_size = fees.len();

    // Pessimistic default if mempool is sparse
    if mempool_size < 3 {
        return FeeEstimate {
            next_block_sats: 10_000,
            medium_priority: 5_000,
            slow_priority:   1_000,
            mempool_median:  if mempool_size > 0 { fees[0] } else { 1_000 },
            mempool_size,
        };
    }

    // Top 25% → next block
    // Top 50% → medium
    // Bottom 25% → slow
    let p25_idx = mempool_size / 4;
    let p50_idx = mempool_size / 2;
    let p75_idx = (mempool_size * 3) / 4;

    FeeEstimate {
        next_block_sats: fees.get(p25_idx).copied().unwrap_or(10_000),
        medium_priority: fees.get(p50_idx).copied().unwrap_or(5_000),
        slow_priority:   fees.get(p75_idx).copied().unwrap_or(1_000),
        mempool_median:  fees.get(p50_idx).copied().unwrap_or(1_000),
        mempool_size,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashrate_nonzero_for_valid_bits() {
        let h = estimate_hashrate(0x1d00ffff, 10.0);
        assert!(h > 0.0, "hashrate should be positive");
    }

    #[test]
    fn hashrate_zero_if_block_time_zero() {
        let h = estimate_hashrate(0x1d00ffff, 0.0);
        assert_eq!(h, 0.0);
    }

    #[test]
    fn hashrate_higher_difficulty_means_more_hashrate() {
        // 0x1d00ffff is easier than 0x1c00ffff (lower exponent = smaller target = more work)
        let easy = estimate_hashrate(0x1d00ffff, 10.0);
        let hard = estimate_hashrate(0x1c00ffff, 10.0);
        assert!(hard > easy, "harder target should imply higher hashrate for same block time");
    }

    #[test]
    fn supply_tier_bounds_are_monotonic() {
        for i in 1..TIER_BOUNDS.len() {
            assert!(TIER_BOUNDS[i] > TIER_BOUNDS[i-1]);
        }
    }
}
