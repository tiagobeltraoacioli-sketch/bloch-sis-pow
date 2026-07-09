//! Property-style round-trip tests for the consensus wire formats.
//!
//! The parsers consume untrusted peer bytes (fuzzed in `fuzz/`); their dual is
//! that a value must survive serialize→parse unchanged. This runs hundreds of
//! pseudo-random cases per invocation inside the normal suite (deterministic
//! splitmix64 PRNG — no external randomness), catching serialization drift the
//! fixed-example tests miss.

use bloch::coherence::ShieldedTx;
use bloch::core::{Block, BlockHeader, Transaction, TxInput, TxOutput};

/// Deterministic PRNG (splitmix64) — reproducible, no wall-clock/random deps.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn range(&mut self, n: usize) -> usize { (self.next() as usize) % n.max(1) }
    fn bytes(&mut self, n: usize) -> Vec<u8> { (0..n).map(|_| self.next() as u8).collect() }
    fn arr32(&mut self) -> [u8; 32] {
        let mut a = [0u8; 32];
        for b in a.iter_mut() { *b = self.next() as u8; }
        a
    }
}

fn rand_tx(r: &mut Rng) -> Transaction {
    let n_in = 1 + r.range(4);
    let n_out = 1 + r.range(4);
    Transaction {
        version: 1,
        inputs: (0..n_in).map(|_| {
            let prev_txid = r.arr32();
            let prev_index = r.next() as u32;
            let sslen = r.range(40);
            TxInput { prev_txid, prev_index, script_sig: r.bytes(sslen), sequence: r.next() as u32 }
        }).collect(),
        outputs: (0..n_out).map(|_| TxOutput {
            value: r.next() % 21_000_000_00000000,
            script_pubkey: r.bytes(20),
        }).collect(),
        locktime: r.next() as u32,
    }
}

fn rand_shielded(r: &mut Rng) -> ShieldedTx {
    let n_nf = r.range(3);
    let n_out = r.range(3);
    let anchor = r.arr32();
    let nullifiers: Vec<[u8; 32]> = (0..n_nf).map(|_| r.arr32()).collect();
    let outputs: Vec<[u8; 32]> = (0..n_out).map(|_| r.arr32()).collect();
    let fee = r.next() % 1_000_000;
    let proof_len = r.range(200);
    let proof = r.bytes(proof_len);
    let sig_len = r.range(64);
    let binding_sig = r.bytes(sig_len);
    ShieldedTx { anchor, nullifiers, outputs, fee, proof, binding_sig }
}

#[test]
fn transaction_wire_round_trips_for_random_values() {
    let mut r = Rng(0xB10C_5157_0001);
    for _ in 0..500 {
        let tx = rand_tx(&mut r);
        let bytes = tx.to_stratum_bytes(true);
        let parsed = Transaction::from_stratum_bytes(&bytes)
            .expect("valid serialized tx must parse");
        assert_eq!(parsed.to_stratum_bytes(true), bytes, "tx round-trip must be byte-stable");
    }
}

#[test]
fn block_with_shielded_wire_round_trips_for_random_values() {
    let mut r = Rng(0xB10C_5157_0002);
    for _ in 0..300 {
        let cb = rand_tx(&mut r);
        let n_sh = r.range(4);
        let shielded: Vec<ShieldedTx> = (0..n_sh).map(|_| rand_shielded(&mut r)).collect();
        let block = Block {
            header: BlockHeader {
                version: 1, parents: vec![],
                merkle_root: Transaction::merkle_root(&[cb.clone()]),
                timestamp: r.next(), bits: 0x2100ffff, nonce: r.next(),
            },
            transactions: vec![cb],
            blue_score: r.next(),
            height: r.next(),
            pow_solution: vec![],
            shielded_transactions: shielded.clone(),
        };
        let bytes = block.to_bitcoin_bytes();
        let parsed = Block::from_bitcoin_bytes(&bytes).expect("valid block must parse");
        assert_eq!(parsed.shielded_transactions.len(), shielded.len());
        assert_eq!(parsed.to_bitcoin_bytes(), bytes, "block round-trip must be byte-stable");
    }
}
