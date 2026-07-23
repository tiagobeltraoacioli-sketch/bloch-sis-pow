#![no_main]
//! Stateful fuzz target for GhostDAG ordering under adversarial DAG topologies.
//!
//! Interprets `data` as a sequence of `add_block` ops against a fresh
//! `GhostDAG`, wiring each new block's parents to an attacker-chosen subset of
//! already-accepted blocks. This drives the real PHANTOM coloring code
//! (`select_parent`, `compute_mergeset`, `classify_mergeset`, blue/red anticone
//! sizing) and the past-set walk on hostile shapes: wide fan-outs, deep linear
//! chains, many-parent merges, and self-referential parent lists. After every
//! accepted block the ordering queries a node exposes to peers
//! (`selected_tip`, `tip_blue_score`, `tips`, `is_blue`, `ordered_hashes_from`)
//! must return — never panic, recurse unboundedly, or hang.
//!
//! Fills scanner Part-A gap #3 (no GhostDAG-Q ordering / past_blue_set target).
use bloch::consensus::GhostDAG;
use libfuzzer_sys::fuzz_target;

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
    fn done(&self) -> bool {
        self.i >= self.d.len()
    }
}

fuzz_target!(|data: &[u8]| {
    let mut dag = GhostDAG::with_default_k();

    // Deterministic genesis (all-zero hash), so every run starts from an
    // identical single-block DAG and the fuzz bytes only drive the topology.
    let genesis = [0u8; 32];
    dag.add_genesis(genesis, 0);
    let mut live: Vec<[u8; 32]> = vec![genesis];

    let mut c = Cur { d: data, i: 0 };
    let mut ops: u64 = 0;

    // Bound the op count so a huge input can't wedge the fuzzer.
    while !c.done() && ops < 2048 {
        ops += 1;

        // 1..=4 parents, each an index into the already-accepted blocks. This
        // guarantees parents exist in the store (so we exercise the accept
        // path, not just the MissingSelectedParent reject) while still letting
        // the fuzzer build arbitrary valid DAG shapes.
        let n_parents = 1 + (c.u8() % 4) as usize;
        let mut parents: Vec<[u8; 32]> = Vec::with_capacity(n_parents);
        for _ in 0..n_parents {
            let sel = (c.u8() as usize) % live.len();
            parents.push(live[sel]);
        }

        // Fresh, unique hash for the new block: the op counter in the low 8
        // bytes makes it distinct from genesis and every prior block, so we
        // never trip the DuplicateBlock reject by accident.
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&ops.to_le_bytes());
        hash[8] = c.u8();

        let timestamp = c.u8() as u64;
        let work = 1u128 + c.u8() as u128;

        if dag.add_block(hash, parents, timestamp, work).is_ok() {
            live.push(hash);

            // Ordering / query surface must never panic on this topology.
            let _ = dag.selected_tip();
            let _ = dag.tip_blue_score();
            let _ = dag.tips();
            let _ = dag.is_blue(&hash);
            let _ = dag.ordered_hashes_from(0, 64);
        }
    }
});
