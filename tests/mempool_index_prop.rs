//! Property tests for the P1 mempool fee-rate index (roadmap §3).
//!
//! No `proptest` crate is on the dep list (and Cargo.toml is out of scope for
//! this change), so this uses the same deterministic-SplitMix64 property style
//! as `tests/wire_roundtrip_props.rs`: hundreds of pseudo-random op sequences
//! per invocation, reproducible on failure.
//!
//! Asserts the two things the index has to get right:
//!   1. INVARIANT: `txs ↔ spent ↔ rate_index` never drift under any add /
//!      remove / remove_confirmed sequence (`debug_check_invariants`).
//!   2. SELECTION/EVICTION CONSISTENCY: `get_for_block` returns txs in
//!      non-increasing fee-RATE order (fee/byte), the SAME ordering eviction
//!      drains from — the behavior change §3 intends. (Pre-P1 it sorted by
//!      absolute fee, which disagreed with eviction.)

use bloch::core::{Transaction, TxInput, TxOutput};
use bloch::mempool::Mempool;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn range(&mut self, n: usize) -> usize {
        (self.next() as usize) % n.max(1)
    }
    fn arr32(&mut self) -> [u8; 32] {
        let mut a = [0u8; 32];
        for b in a.iter_mut() {
            *b = self.next() as u8;
        }
        a
    }
}

/// Build a tx with a controllable serialized size (via script_sig padding) and
/// a unique input (via `nonce`) so no two txs conflict on the same outpoint.
fn tx_with(nonce: u64, pad: usize) -> Transaction {
    let mut prev = [0u8; 32];
    prev[..8].copy_from_slice(&nonce.to_le_bytes());
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: prev,
            prev_index: 0,
            script_sig: vec![7u8; pad],
            sequence: 0xffff_ffff,
        }],
        outputs: vec![TxOutput { value: 1_000, script_pubkey: vec![1u8; 20] }],
        locktime: 0,
    }
}

const FEE_RATE_SCALE: u128 = 1_000_000;
fn rate(fee: u64, size: usize) -> u128 {
    (fee as u128 * FEE_RATE_SCALE) / (size.max(1) as u128)
}

#[test]
fn invariant_holds_under_random_ops() {
    let mut r = Rng(0xB10C_1DE0_0001);
    for _ in 0..40 {
        let mp = Mempool::new();
        let mut live: Vec<[u8; 32]> = Vec::new();
        let mut nonce = 0u64;
        for _ in 0..300 {
            match r.range(3) {
                0 => {
                    nonce += 1;
                    let pad = 8 + r.range(120);
                    let tx = tx_with(nonce, pad);
                    let fee = 100_000 + (r.next() % 5_000_000);
                    if let Ok(id) = mp.add(tx, fee) {
                        live.push(id);
                    }
                }
                1 => {
                    if !live.is_empty() {
                        let i = r.range(live.len());
                        let id = live.swap_remove(i);
                        mp.remove(&id);
                    }
                }
                _ => {
                    let n = r.range(4);
                    let mut batch = Vec::new();
                    for _ in 0..n {
                        if live.is_empty() {
                            break;
                        }
                        let i = r.range(live.len());
                        batch.push(live.swap_remove(i));
                    }
                    mp.remove_confirmed(&batch);
                }
            }
            mp.debug_check_invariants().expect("invariant after op");
        }
    }
}

#[test]
fn get_for_block_is_fee_rate_descending() {
    let mut r = Rng(0xB10C_1DE0_0002);
    for _ in 0..50 {
        let mp = Mempool::new();
        let mut nonce = 0u64;
        let n = 20 + r.range(60);
        for _ in 0..n {
            nonce += 1;
            let pad = 8 + r.range(300);
            let tx = tx_with(nonce, pad);
            let fee = 10_000 + (r.next() % 10_000_000);
            let _ = mp.add(tx, fee);
        }

        // Take a template and verify it is sorted by fee-RATE, non-increasing.
        let limit = 5 + r.range(30);
        let template = mp.get_for_block(limit);
        assert!(template.len() <= limit);

        let mut prev: Option<u128> = None;
        for tx in &template {
            // Recover this tx's fee from the mempool entry to compute its rate.
            let entry = mp.get_entry(&tx.txid()).expect("template tx is in mempool");
            let rk = rate(entry.fee, entry.tx.actual_size());
            if let Some(p) = prev {
                assert!(
                    rk <= p,
                    "template not fee-rate descending: {rk} came after {p}"
                );
            }
            prev = Some(rk);
        }
    }
}

/// The template head must be the mempool's maximum fee-rate tx — i.e. selection
/// agrees with what eviction keeps last. This is the concrete
/// selection/eviction-consistency assertion.
#[test]
fn template_head_is_max_fee_rate() {
    let mut r = Rng(0xB10C_1DE0_0003);
    for _ in 0..50 {
        let mp = Mempool::new();
        let mut nonce = 0u64;
        let mut max_rate = 0u128;
        let n = 10 + r.range(40);
        for _ in 0..n {
            nonce += 1;
            let pad = 8 + r.range(300);
            let tx = tx_with(nonce, pad);
            let fee = 10_000 + (r.next() % 10_000_000);
            if mp.add(tx.clone(), fee).is_ok() {
                max_rate = max_rate.max(rate(fee, tx.actual_size()));
            }
        }
        let head = mp.get_for_block(1);
        if let Some(tx) = head.first() {
            let e = mp.get_entry(&tx.txid()).unwrap();
            assert_eq!(rate(e.fee, e.tx.actual_size()), max_rate, "head is not max fee-rate");
        }
    }
}
