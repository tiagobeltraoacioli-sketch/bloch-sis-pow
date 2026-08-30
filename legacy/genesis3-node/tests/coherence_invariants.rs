//! Property-based invariants for the shielded-pool consensus engine.
//!
//! Hammers `ShieldedEngine::apply_block` with random blocks (mixing fresh spends,
//! double-spends, intra-block duplicates, and unknown anchors) and asserts the
//! security invariants that protect the shielded pool:
//!   1. no double-spend — an accepted nullifier can never be accepted again;
//!   2. atomicity — a rejected block spends NONE of its nullifiers;
//!   3. consistency — `is_spent(nf)` matches the set of accepted nullifiers.
//!
//! Proof verification is mocked (SP1/FRI is a separate concern); this tests the
//! consensus logic. Deterministic PRNG — no wall-clock/random deps.

use std::collections::HashSet;

use bloch::coherence::{ShieldedEngine, ShieldedTx, SpendPublic};

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
    fn arr32_tag(&mut self, tag: u8) -> [u8; 32] {
        let mut a = [tag; 32];
        a[..8].copy_from_slice(&self.next().to_le_bytes());
        a
    }
}

fn tx(anchor: [u8; 32], nfs: Vec<[u8; 32]>, outs: Vec<[u8; 32]>) -> ShieldedTx {
    // One structurally well-formed (all-zero) note ciphertext per output —
    // validate() enforces ciphertexts_well_formed() as a precondition.
    let cts = outs.iter().map(|_| bloch::coherence::NoteCiphertext {
        kem_ct: vec![0u8; bloch::coherence::NOTE_KEM_CT_LEN],
        nonce: [0u8; bloch::coherence::NOTE_AEAD_NONCE_LEN],
        payload: vec![0u8; bloch::coherence::NOTE_PLAINTEXT_LEN + bloch::coherence::NOTE_AEAD_TAG_LEN],
    }).collect();
    ShieldedTx { anchor, nullifiers: nfs, outputs: outs, output_ciphertexts: cts, fee: 0, proof: vec![1], binding_sig: vec![] }
}

/// A fixed nullifier pool so the random stream forces real reuse/double-spends.
fn pool() -> Vec<[u8; 32]> {
    (0u8..24).map(|i| { let mut a = [0u8; 32]; a[0] = i; a }).collect()
}

#[test]
fn shielded_engine_upholds_no_double_spend_atomicity_and_consistency() {
    let mut eng = ShieldedEngine::new();
    let ok = |_p: &SpendPublic, _pf: &[u8]| true;
    let mut r = Rng(0xC0DE_5157_0001);
    let nfs = pool();
    let mut accepted: HashSet<[u8; 32]> = HashSet::new();

    for _ in 0..2000 {
        // The current root is always a known anchor (recorded on new() + after
        // each accepted block). Build spends against it, or against a random
        // (unknown) anchor to exercise the reject path.
        let cur = eng.anchor();
        let n_tx = 1 + r.range(3);
        let block: Vec<ShieldedTx> = (0..n_tx)
            .map(|_| {
                let anchor = if r.range(8) == 0 { r.arr32_tag(0xEE) } else { cur };
                let k = 1 + r.range(2);
                let nulls: Vec<[u8; 32]> = (0..k).map(|_| nfs[r.range(nfs.len())]).collect();
                let n_out = r.range(3);
                let outs: Vec<[u8; 32]> = (0..n_out).map(|_| r.arr32_tag(0xC0)).collect();
                tx(anchor, nulls, outs)
            })
            .collect();

        // Whether this block SHOULD be accepted: every tx anchored at `cur`, no
        // nullifier already accepted, and no duplicate nullifier within the block.
        let mut seen_in_block: HashSet<[u8; 32]> = HashSet::new();
        let should_accept = block.iter().all(|t| {
            let anchor_ok = t.anchor == cur;
            let fresh = t.nullifiers.iter().all(|nf| {
                !accepted.contains(nf) && seen_in_block.insert(*nf)
            });
            anchor_ok && fresh
        });

        let res = eng.apply_block(r.arr32_tag(0x1D), &block, ok);

        match res {
            Ok(_) => {
                assert!(should_accept, "engine accepted a block it should have rejected");
                for t in &block {
                    for nf in &t.nullifiers {
                        // invariant 1: no double-spend — was fresh, now spent.
                        accepted.insert(*nf);
                    }
                }
            }
            Err(_) => {
                assert!(!should_accept, "engine rejected a valid block");
                // invariant 2: atomicity — nothing from this block became spent.
                for t in &block {
                    for nf in &t.nullifiers {
                        if !accepted.contains(nf) {
                            assert!(!eng.is_spent(nf), "rejected block leaked a spend (not atomic)");
                        }
                    }
                }
            }
        }

        // invariant 3: consistency across the whole pool.
        for nf in &nfs {
            assert_eq!(eng.is_spent(nf), accepted.contains(nf), "is_spent diverged from ledger");
        }
    }

    // Sanity: the random stream actually exercised both accept and reject paths.
    assert!(!accepted.is_empty(), "no spend was ever accepted — test is not exercising the engine");
}
