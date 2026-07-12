#![no_main]
//! Stateful fuzz target for the mempool (roadmap §1b / §3 guard).
//!
//! Interprets `data` as a sequence of ops (add / remove / remove_confirmed)
//! against a fresh `Mempool`, synthesizing small valid transactions from the
//! fuzz bytes so real add / eviction / spent-index paths run. After EVERY op it
//! asserts `debug_check_invariants()` holds — the three-way
//! `txs ↔ spent ↔ rate_index` invariant plus the P0 byte/count bounds. This is
//! the regression guard for the P1 fee-rate BTreeMap index: a drift bug between
//! the index and `txs` surfaces here as an invariant failure, not a silent
//! wrong-eviction.
use bloch::core::{Transaction, TxInput, TxOutput};
use bloch::mempool::Mempool;
use libfuzzer_sys::fuzz_target;

/// Tiny byte cursor over the fuzz input.
struct Cur<'a> {
    d: &'a [u8],
    i: usize,
}
impl<'a> Cur<'a> {
    fn u8(&mut self) -> u8 {
        let b = self.d.get(self.i).copied().unwrap_or(0);
        self.i += 1;
        b
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }
    fn arr32(&mut self) -> [u8; 32] {
        let mut a = [0u8; 32];
        for x in a.iter_mut() {
            *x = self.u8();
        }
        a
    }
    fn done(&self) -> bool {
        self.i >= self.d.len()
    }
}

/// Build a small structurally-valid tx (1..=3 inputs, 1 output) from fuzz bytes.
fn synth_tx(c: &mut Cur) -> Transaction {
    let n_in = 1 + (c.u8() % 3) as usize;
    let inputs = (0..n_in)
        .map(|_| TxInput {
            prev_txid: c.arr32(),
            prev_index: c.u32(),
            script_sig: vec![0u8; 8],
            sequence: 0xffff_ffff,
        })
        .collect();
    Transaction {
        version: 1,
        inputs,
        outputs: vec![TxOutput {
            value: 1_000,
            script_pubkey: vec![1u8; 20],
        }],
        locktime: 0,
    }
}

fuzz_target!(|data: &[u8]| {
    let mp = Mempool::new();
    let mut c = Cur { d: data, i: 0 };
    let mut live: Vec<[u8; 32]> = Vec::new();

    // Bound the op count so a huge input can't wedge the fuzzer.
    let mut ops = 0;
    while !c.done() && ops < 4096 {
        ops += 1;
        match c.u8() % 3 {
            0 => {
                // add: fee derived from a fuzz byte (kept above the min-relay
                // floor for the tx's size so the low_fee reject isn't the only
                // path exercised).
                let tx = synth_tx(&mut c);
                let fee = 100_000u64.wrapping_add(c.u32() as u64);
                if let Ok(txid) = mp.add(tx, fee) {
                    live.push(txid);
                }
            }
            1 => {
                // remove a previously-added tx (by index selector).
                if !live.is_empty() {
                    let idx = (c.u32() as usize) % live.len();
                    let txid = live.swap_remove(idx);
                    mp.remove(&txid);
                }
            }
            _ => {
                // remove_confirmed a small batch.
                let n = (c.u8() % 4) as usize;
                let mut batch = Vec::new();
                for _ in 0..n {
                    if live.is_empty() {
                        break;
                    }
                    let idx = (c.u32() as usize) % live.len();
                    batch.push(live.swap_remove(idx));
                }
                mp.remove_confirmed(&batch);
            }
        }
        // The invariant must hold after every single op.
        if let Err(e) = mp.debug_check_invariants() {
            panic!("mempool invariant broken: {e}");
        }
    }
});
