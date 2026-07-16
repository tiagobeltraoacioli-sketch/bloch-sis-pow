//! Differential test: legacy (bounded-BFS) GhostDAG coloring vs the fast
//! interval-index coloring must produce BYTE-IDENTICAL `GhostdagData` — same
//! blue set, blue_score, selected parent, mergeset order, and
//! `blues_anticone_sizes` map — for every block, across many DAG shapes.
//!
//! # What this proves (and what it does not)
//!
//! This is the gate for the reachability perf change. Per the implementation
//! plan (§0), the fast unbounded coloring is authorized to replace the legacy
//! bounded coloring on the live consensus path ONLY IF it is byte-identical to
//! it on the real ≥397k mainnet history. This test proves byte-identity on
//! synthetic DAG shapes; the real-chain replay (which requires a mainnet
//! RocksDB snapshot, not available in CI) is the remaining, authoritative step.
//!
//! Where legacy and fast would diverge, the legacy (bug-compatible) answer is
//! the consensus-correct one to keep — adopting fast's answer there is a FORK
//! and needs an activation-height gate. The `wide_deep_probe` test below is a
//! diagnostic that measures whether the legacy bound ever actually bit on an
//! aggressively wide+deep DAG.

use std::collections::HashMap;
use bloch::consensus::{GhostDAG, ColoringMode, BlockHash, GhostdagData, canonical_encode};
use bloch::consensus::reachability::brute_force_is_ancestor;

// ── deterministic RNG (xorshift64*) ──────────────────────────────────────────

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next_u64() % n as u64) as usize }
    }
}

// A block spec in topological order: (hash, parents, timestamp, work).
type Spec = (BlockHash, Vec<BlockHash>, u64, u128);

fn hh(a: u8, b: u16) -> BlockHash {
    let mut h = [0u8; 32];
    h[0] = a;
    h[1] = (b >> 8) as u8;
    h[2] = (b & 0xff) as u8;
    h
}

/// Replay a topological block sequence into a fresh GhostDAG of the given mode.
fn build(genesis: BlockHash, specs: &[Spec], k: usize, mode: ColoringMode) -> GhostDAG {
    let mut dag = match mode {
        ColoringMode::Legacy => GhostDAG::with_k(k),
        ColoringMode::Fast => GhostDAG::with_k_fast(k),
    };
    dag.add_genesis(genesis, 0);
    for (hash, parents, ts, work) in specs {
        dag.add_block(*hash, parents.clone(), *ts, *work)
            .unwrap_or_else(|e| panic!("add_block failed for {}: {e:?}", hex::encode(&hash[..4])));
    }
    dag
}

/// Compare every block's canonical GhostdagData between two DAGs. Returns the
/// list of hashes that differ, with a human-readable field diff.
fn diff_blocks(
    a: &GhostDAG,
    b: &GhostDAG,
    order: &[BlockHash],
) -> Vec<(BlockHash, String)> {
    let mut diffs = Vec::new();
    for h in order {
        let da = a.get_block_data(h);
        let db = b.get_block_data(h);
        match (da, db) {
            (Some(da), Some(db)) => {
                if canonical_encode(da) != canonical_encode(db) {
                    diffs.push((*h, field_diff(da, db)));
                }
            }
            _ => diffs.push((*h, "block missing in one DAG".to_string())),
        }
    }
    diffs
}

fn field_diff(a: &GhostdagData, b: &GhostdagData) -> String {
    let mut s = String::new();
    if a.blue_score != b.blue_score {
        s += &format!("blue_score {}!={} ", a.blue_score, b.blue_score);
    }
    if a.blue_work != b.blue_work {
        s += &format!("blue_work {}!={} ", a.blue_work, b.blue_work);
    }
    if a.selected_parent != b.selected_parent {
        s += "selected_parent differs ";
    }
    if a.mergeset_blues != b.mergeset_blues {
        s += &format!("mergeset_blues len {}!={} ", a.mergeset_blues.len(), b.mergeset_blues.len());
    }
    if a.mergeset_reds != b.mergeset_reds {
        s += &format!("mergeset_reds len {}!={} ", a.mergeset_reds.len(), b.mergeset_reds.len());
    }
    if a.blues_anticone_sizes != b.blues_anticone_sizes {
        s += &format!("blues_anticone_sizes len {}!={} ",
            a.blues_anticone_sizes.len(), b.blues_anticone_sizes.len());
    }
    if s.is_empty() { s = "canonical bytes differ (unknown field)".into(); }
    s
}

/// Build both modes over the same specs and assert byte-identity. Panics with a
/// field-level diff on the first mismatch.
fn assert_identical(genesis: BlockHash, specs: &[Spec], k: usize, label: &str) {
    let legacy = build(genesis, specs, k, ColoringMode::Legacy);
    let fast = build(genesis, specs, k, ColoringMode::Fast);
    let mut order = vec![genesis];
    order.extend(specs.iter().map(|(h, ..)| *h));
    let diffs = diff_blocks(&legacy, &fast, &order);
    assert!(
        diffs.is_empty(),
        "[{label}] legacy != fast on {} block(s); first: {} -> {}",
        diffs.len(),
        hex::encode(&diffs[0].0[..4]),
        diffs[0].1,
    );
    // Selected chain / tip must also match.
    assert_eq!(legacy.selected_tip(), fast.selected_tip(), "[{label}] tip differs");
    assert_eq!(legacy.tip_blue_score(), fast.tip_blue_score(), "[{label}] tip blue_score differs");
    assert_eq!(legacy.selected_chain(), fast.selected_chain(), "[{label}] selected chain differs");
}

/// Validate the fast DAG's reachability index against the unbounded brute-force
/// oracle for all block pairs.
fn assert_index_matches_oracle(dag: &GhostDAG, all: &[BlockHash], label: &str) {
    let store = &dag.store;
    let reach = dag.reachability();
    for a in all {
        for b in all {
            let idx = reach.is_dag_ancestor(a, b);
            let bf = brute_force_is_ancestor(store, a, b);
            assert_eq!(
                idx, bf,
                "[{label}] index/oracle mismatch: is_ancestor({},{}) index={} oracle={}",
                hex::encode(&a[..4]), hex::encode(&b[..4]), idx, bf,
            );
        }
    }
}

// ── shape generators ─────────────────────────────────────────────────────────

fn linear(genesis: BlockHash, n: u16) -> Vec<Spec> {
    let mut specs = Vec::new();
    let mut prev = genesis;
    for i in 1..=n {
        let b = hh(b'L', i);
        specs.push((b, vec![prev], i as u64, 1000));
        prev = b;
    }
    specs
}

/// Repeated diamond merges: Left_i, Right_i (siblings of prev), Merge_i.
fn merging(genesis: BlockHash, iters: u16) -> Vec<Spec> {
    let mut specs = Vec::new();
    let mut prev = genesis;
    let mut ts = 1u64;
    for i in 1..=iters {
        let l = hh(b'A', i);
        let r = hh(b'B', i);
        let m = hh(b'M', i);
        specs.push((l, vec![prev], ts, 1000)); ts += 1;
        specs.push((r, vec![prev], ts, 1000)); ts += 1;
        specs.push((m, vec![l, r], ts, 1000)); ts += 1;
        prev = m;
    }
    specs
}

/// Wide fan-out then a merge: W parallel siblings merged by one block, repeated.
fn wide_layers(genesis: BlockHash, layers: u16, width: u16) -> Vec<Spec> {
    let mut specs = Vec::new();
    let mut prev = genesis;
    let mut ts = 1u64;
    let mut id = 0u16;
    for _ in 0..layers {
        let mut sibs = Vec::new();
        for _ in 0..width {
            id += 1;
            let s = hh(b'S', id);
            specs.push((s, vec![prev], ts, 1000)); ts += 1;
            sibs.push(s);
        }
        id += 1;
        let m = hh(b'W', id);
        specs.push((m, sibs, ts, 1000)); ts += 1;
        prev = m;
    }
    specs
}

/// Random valid DAG: each new block picks 1..=maxpar parents among recent tips.
fn random_dag(genesis: BlockHash, n: u16, maxpar: usize, seed: u64) -> Vec<Spec> {
    let mut rng = Rng::new(seed);
    let mut specs = Vec::new();
    let mut pool: Vec<BlockHash> = vec![genesis];
    let mut ts = 1u64;
    for i in 1..=n {
        let b = hh(b'R', i);
        let np = 1 + rng.below(maxpar);
        let mut parents = Vec::new();
        // Prefer recent blocks so the DAG has realistic locality.
        let window = pool.len().min(24);
        let base = pool.len() - window;
        for _ in 0..np {
            let idx = base + rng.below(window);
            let p = pool[idx];
            if !parents.contains(&p) {
                parents.push(p);
            }
        }
        if parents.is_empty() {
            parents.push(*pool.last().unwrap());
        }
        specs.push((b, parents, ts, 1000));
        ts += 1;
        pool.push(b);
    }
    specs
}

fn order_of(genesis: BlockHash, specs: &[Spec]) -> Vec<BlockHash> {
    let mut v = vec![genesis];
    v.extend(specs.iter().map(|(h, ..)| *h));
    v
}

// ── tests: byte-identity on standard shapes ──────────────────────────────────

#[test]
fn identical_linear() {
    let g = hh(0, 0);
    for k in [1usize, 3, 10] {
        assert_identical(g, &linear(g, 300), k, "linear");
    }
}

#[test]
fn identical_parallel_merge() {
    let g = hh(0, 0);
    // The classic G->A, G->B, C=merge(A,B) plus a few more merges.
    let specs = vec![
        (hh(b'A', 1), vec![g], 1, 1000),
        (hh(b'B', 1), vec![g], 2, 1000),
        (hh(b'C', 1), vec![hh(b'A', 1), hh(b'B', 1)], 3, 1000),
        (hh(b'A', 2), vec![hh(b'C', 1)], 4, 1000),
        (hh(b'B', 2), vec![hh(b'C', 1)], 5, 1000),
        (hh(b'C', 2), vec![hh(b'A', 2), hh(b'B', 2)], 6, 1000),
    ];
    for k in [1usize, 3, 10] {
        assert_identical(g, &specs, k, "parallel_merge");
    }
}

#[test]
fn identical_merging_dag_h5_shape() {
    // The 110-iteration merging DAG from the H-5 regression, which deliberately
    // exceeds the old bounds. k=10 (live value) and k=100.
    let g = hh(0, 0);
    for k in [10usize, 100] {
        assert_identical(g, &merging(g, 110), k, "merging_h5");
    }
}

#[test]
fn identical_wide_layers() {
    let g = hh(0, 0);
    // Wide anticones (width 8) over 30 layers — the regime where a full blue
    // set is exercised. k=10 (live).
    assert_identical(g, &wide_layers(g, 30, 8), 10, "wide_layers");
}

#[test]
fn identical_random_dags() {
    let g = hh(0, 0);
    for seed in 0..40u64 {
        let specs = random_dag(g, 120, 3, seed ^ 0x9E3779B97F4A7C15);
        assert_identical(g, &specs, 10, "random");
    }
}

#[test]
fn identical_random_small_k() {
    // Small K makes PHANTOM classification flip more blocks red — stresses the
    // anticone counting where legacy/fast must still agree.
    let g = hh(0, 0);
    for seed in 0..40u64 {
        let specs = random_dag(g, 120, 4, seed.wrapping_mul(2862933555777941757).wrapping_add(3));
        assert_identical(g, &specs, 2, "random_k2");
    }
}

// ── tests: reachability index == unbounded oracle ────────────────────────────

#[test]
fn index_matches_oracle_all_shapes() {
    let g = hh(0, 0);
    let cases: Vec<(String, Vec<Spec>)> = vec![
        ("linear".into(), linear(g, 200)),
        ("merging".into(), merging(g, 60)),
        ("wide".into(), wide_layers(g, 20, 10)),
        ("random-a".into(), random_dag(g, 150, 3, 12345)),
        ("random-b".into(), random_dag(g, 150, 5, 999983)),
    ];
    for (label, specs) in &cases {
        let fast = build(g, specs, 10, ColoringMode::Fast);
        assert_index_matches_oracle(&fast, &order_of(g, specs), label);
    }
}

// ── diagnostic: does the legacy bound ever actually bite? ─────────────────────

/// Aggressive wide+deep DAG. Measures — but does not assert — whether legacy
/// and fast diverge, i.e. whether the legacy bounded BFS / past_blue_set bound
/// ever changed a coloring result. It DOES assert that the fast index is
/// consensus-correct (matches the unbounded oracle) throughout.
///
/// If this reports zero divergences, the equivalence lemma held on this
/// synthetic stress shape (evidence, not proof — the mainnet replay remains
/// authoritative). If it reports > 0, those blocks are exactly where promoting
/// fast to the live path would fork, and they must go behind an activation gate.
#[test]
fn wide_deep_probe_reports_divergence() {
    let g = hh(0, 0);
    // 6 layers of width 40 = 240 siblings + 6 merges ≈ 246 blocks. Width 40
    // exceeds the legacy is_ancestor visited cap (depth_limit*10 ≈ 30 at shallow
    // height differences), which is the regime where the legacy bound can bite.
    // Kept modest because the legacy path is O(n²·BFS) here — precisely the
    // cost this change removes.
    let specs = wide_layers(g, 6, 40);
    let k = 10;
    let legacy = build(g, &specs, k, ColoringMode::Legacy);
    let fast = build(g, &specs, k, ColoringMode::Fast);
    let order = order_of(g, &specs);

    // The fast index must be consensus-correct regardless.
    assert_index_matches_oracle(&fast, &order, "wide_deep_probe");

    let diffs = diff_blocks(&legacy, &fast, &order);
    eprintln!(
        "wide_deep_probe: {} blocks, legacy-vs-fast divergences = {}",
        order.len(),
        diffs.len(),
    );
    for (h, d) in diffs.iter().take(5) {
        eprintln!("  diverged at {}: {}", hex::encode(&h[..4]), d);
    }
    // Intentionally no equality assertion here: divergence, if any, is a
    // consensus finding to be gated, not a test failure. The assertion that
    // matters for safety (index correctness) is above.
    let _ = &diffs;
}

/// Sanity: the two constructors really do select different code paths, so the
/// identity tests above are meaningful (not comparing a mode against itself).
#[test]
fn modes_are_distinct() {
    let g = hh(0, 0);
    let legacy = build(g, &linear(g, 3), 10, ColoringMode::Legacy);
    let fast = build(g, &linear(g, 3), 10, ColoringMode::Fast);
    assert_eq!(legacy.coloring, ColoringMode::Legacy);
    assert_eq!(fast.coloring, ColoringMode::Fast);
    // Fast maintains the index; legacy leaves it empty.
    assert!(!fast.reachability().is_empty());
    assert!(legacy.reachability().is_empty());
    let _ : HashMap<BlockHash, u8> = HashMap::new(); // keep HashMap import used
}
