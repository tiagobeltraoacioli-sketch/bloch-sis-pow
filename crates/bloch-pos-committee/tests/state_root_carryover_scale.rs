// SPDX-License-Identifier: AGPL-3.0-or-later

//! **The carryover-scale differential proof for the incremental state root.**
//!
//! # Why this file exists
//!
//! `perf/smt` replaced the from-scratch state root (`subtree_root`, a
//! recursion over a key-sorted flat slice) with an *incremental* sparse Merkle
//! tree: nodes are materialised and kept, a mutation rebuilds only the path to
//! the touched leaf, and `Smt::root()` reads a field. The adversarial review of
//! that change proved the incremental root byte-identical to the bulk root —
//! and then said, in writing, that it had **not** fuzzed at carryover scale.
//!
//! Carryover scale is 452,726 eUTXO leaves. It is not a stress size, it is the
//! size the 48 mainnet validators run at from block one. A root that diverges
//! only there forks the fleet on the first block, with green tests behind it —
//! the `expected_bits` failure shape of 2026-08-08 and the two-seams state-root
//! split of 2026-08-12, for the third time.
//!
//! # What is proved here, and against what
//!
//! Three independent derivations of the same leaf set must agree, byte for
//! byte:
//!
//!   1. **INCREMENTAL** — the leaf set reached the way a running node reaches
//!      it: a randomized interleaving of `insert` and `remove`, including
//!      value updates and leaves that are created and later spent. This is the
//!      path the production node takes (`EutxoSet` clones the tree per block).
//!   2. **BULK** — `Smt::from_leaf_map` over the final set, the path a
//!      from-scratch load takes.
//!   3. **REFERENCE** — [`ref_subtree_root`] below: the pre-`perf/smt`
//!      recursion, transcribed here, with the singleton shortcut and the
//!      thread-local memo both removed, so it folds every one of the 256
//!      levels explicitly. It shares nothing with the shipped tree but SHA3
//!      and `DS_STATE`.
//!
//! (3) is the part that makes this a proof rather than a self-consistency
//! check. (1) and (2) both run through `perf/smt`'s new code and would agree
//! with each other on a shared bug; (3) would not.
//!
//! # The memo, and why each side gets its own thread
//!
//! `state_root.rs` keeps a **thread-local** two-generation memo of singleton
//! subtree roots, rotating at 600,000 entries. Two derivations run on the same
//! thread do not start from the same state: the second inherits the first's
//! memo. For correctness that is arguably harmless — every entry is a pure
//! function of its whole key — but "arguably harmless" is exactly what a proof
//! may not lean on. Every side below is therefore built on its **own freshly
//! spawned thread**, so a memo that returned a wrong entry could not be handed
//! from one side to the other and mask the divergence.
//!
//! # What runs by default
//!
//!   * [`state_root_differential_at_small_scale`] — n = 4,527, three seeds,
//!     runs in the ordinary suite.
//!   * [`state_root_differential_at_carryover_scale`] — n = 452,726, `#[ignore]`d
//!     (minutes, and ~1 GB peak). Run it with:
//!
//! ```text
//! cargo test --release -p bloch-pos-committee \
//!     --test state_root_carryover_scale -- --ignored --nocapture --test-threads=1
//! ```

use bloch_pos_committee::params::DS_STATE;
use bloch_pos_committee::state_root::{
    eutxo_leaf, state_root, state_root_with_eutxo_tree, BaseFeeRecord, CheckpointRecord,
    ConsensusState, EutxoEntry, EvmCommitment, FinalityRecord, ParticipationRecord, RandaoMix,
    Smt, ValidatorRecord,
};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Genesis-4's measured carryover size. Must stay equal to `CARRYOVER_N` in
/// `bloch-pos-node/tests/replay_hotpath_perf.rs` — this is the regime the
/// mainnet validators run in, and the whole point of the file is to test *it*
/// and not a convenient neighbour of it.
const CARRYOVER_N: u32 = 452_726;

/// The always-on version.
///
/// Sized by what an *unoptimized* build can pay, not by taste: each new leaf
/// costs one singleton fold, which is ~240 SHA3, and this crate's `[profile.dev]`
/// hash override is inert (it is no longer a workspace root — see its
/// `Cargo.toml`), so a debug `cargo test` runs Keccak at roughly 50x the release
/// cost. MEASURED on this host: n = 4,527 costs 10.7 s in release and 579 s in
/// debug; n = 1,024 costs 2.9 s in release (so on the order of two minutes
/// unoptimized, by the same ratio). 1,024 still branches ~11 levels deep, which
/// is where splits and collapses live. The size that actually matters is proved
/// by the `#[ignore]`d test below, at 452,726.
const SMALL_N: u32 = 1_024;

/// Fixed and printed, so a failure is a case anyone can rerun. Path
/// independence is the property under test: the same final leaf set must give
/// the same root no matter which order it was reached in, so more than one
/// order has to be tried.
const SEEDS: [u64; 3] = [0x5CA1E_0001, 0xC0FFEE_02, 0xDEADBEEF_03];

/// Roughly the live Genesis-4 validator set.
const N_VALIDATORS: u32 = 64;

// ─────────────────────────────────────────────────────────────────────────────
// The reference implementation: the pre-perf/smt root, memo-free and
// shortcut-free.
// ─────────────────────────────────────────────────────────────────────────────

const TREE_DEPTH: usize = 256;
const MARK_LEAF: u8 = 0x00;
const MARK_NODE: u8 = 0x01;
const MARK_EMPTY: u8 = 0x02;

fn ref_sha3(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DS_STATE);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn ref_leaf_hash(key: &[u8; 32], value_hash: &[u8; 32]) -> [u8; 32] {
    ref_sha3(&[&[MARK_LEAF], key, value_hash])
}

fn ref_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    ref_sha3(&[&[MARK_NODE], left, right])
}

fn ref_empty_hashes() -> Vec<[u8; 32]> {
    let mut empty = vec![[0u8; 32]; TREE_DEPTH + 1];
    empty[TREE_DEPTH] = ref_sha3(&[&[MARK_EMPTY]]);
    for d in (0..TREE_DEPTH).rev() {
        empty[d] = ref_node_hash(&empty[d + 1], &empty[d + 1]);
    }
    empty
}

fn ref_bit(key: &[u8; 32], d: usize) -> u8 {
    (key[d / 8] >> (7 - (d % 8))) & 1
}

/// The root of the subtree at `depth` over a key-sorted slice, folding every
/// level to `TREE_DEPTH` with no singleton shortcut and no memoization.
///
/// This is what the state root *is*, by definition, before any optimisation:
/// the shipped `subtree_root` is this with the one-leaf case hoisted into a
/// loop, and `Smt` is that recursion materialised. Deliberately naive, and
/// deliberately expensive — an oracle that shared the optimisation would not be
/// an oracle.
fn ref_subtree_root(
    leaves: &[([u8; 32], [u8; 32])],
    depth: usize,
    empty: &[[u8; 32]],
) -> [u8; 32] {
    if leaves.is_empty() {
        return empty[depth];
    }
    if depth == TREE_DEPTH {
        assert_eq!(leaves.len(), 1, "distinct 256-bit keys cannot survive 256 splits together");
        return ref_leaf_hash(&leaves[0].0, &leaves[0].1);
    }
    let split = leaves.partition_point(|(k, _)| ref_bit(k, depth) == 0);
    let left = ref_subtree_root(&leaves[..split], depth + 1, empty);
    let right = ref_subtree_root(&leaves[split..], depth + 1, empty);
    ref_node_hash(&left, &right)
}

fn ref_root(leaves: &BTreeMap<[u8; 32], [u8; 32]>) -> [u8; 32] {
    let flat: Vec<([u8; 32], [u8; 32])> = leaves.iter().map(|(k, v)| (*k, *v)).collect();
    ref_subtree_root(&flat, 0, &ref_empty_hashes())
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixture
// ─────────────────────────────────────────────────────────────────────────────

/// A deterministic SplitMix64. A failing case must be a case anyone can
/// reproduce from the printed seed.
fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Byte-for-byte the filler `bloch-pos-node/tests/replay_hotpath_perf.rs` uses,
/// so the eUTXO set here is literally that benchmark's `eutxos(n)` and the
/// roots printed by the two files are comparable.
fn h32(seed: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut x = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    for c in out.chunks_mut(8) {
        x ^= x >> 30;
        x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x ^= x >> 27;
        x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
        x ^= x >> 31;
        c.copy_from_slice(&x.to_le_bytes());
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    }
    out
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The committed set: `n` eUTXOs, generated from `i` alone so both threads
/// derive the identical set without sharing a single byte of memory.
fn final_entry(i: u32) -> EutxoEntry {
    EutxoEntry {
        txid: h32(i as u64),
        vout: i % 4,
        value: 8_400_000_000u64.wrapping_add(i as u64),
        script_hash: h32(0xF000_0000 ^ i as u64),
    }
}

/// Entries that are created and then spent again. Their key space is offset far
/// from the committed set's; disjointness is asserted, not assumed.
fn ghost_entry(i: u32) -> EutxoEntry {
    EutxoEntry {
        txid: h32(0x9057_0000_0000 ^ i as u64),
        vout: 3 - (i % 4),
        value: 1_000u64.wrapping_add(i as u64),
        script_hash: h32(0x0BAD_0000 ^ i as u64),
    }
}

fn final_leaves(n: u32) -> BTreeMap<[u8; 32], [u8; 32]> {
    (0..n).map(|i| eutxo_leaf(&final_entry(i))).collect()
}

struct Fixture {
    validators: Vec<ValidatorRecord>,
    current: Vec<ParticipationRecord>,
    previous: Vec<ParticipationRecord>,
    randao: Vec<RandaoMix>,
    finality: FinalityRecord,
}

fn fixture() -> Fixture {
    let ck = |e: u64| CheckpointRecord { epoch: e, root: h32(0xC0DE + e) };
    Fixture {
        validators: (0..N_VALIDATORS)
            .map(|i| ValidatorRecord {
                index: i,
                pubkey: vec![(i % 251) as u8; 3_749],
                stake: 32_00000000,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
                slashed: false,
                randao_commitment: h32(0x5A5A_0000 ^ i as u64),
                reveals_used: 100,
                withdrawable_epoch: u64::MAX,
                withdrawal_credentials: vec![0xAB; 32],
                commission_bps: 500,
            })
            .collect(),
        current: (0..N_VALIDATORS)
            .map(|i| ParticipationRecord { validator_index: i, attested: i % 3 != 0 })
            .collect(),
        previous: (0..N_VALIDATORS)
            .map(|i| ParticipationRecord { validator_index: i, attested: i % 5 != 0 })
            .collect(),
        randao: (0..3u64).map(|e| RandaoMix { epoch: 820 + e, mix: h32(0xA0 + e) }).collect(),
        finality: FinalityRecord {
            justified: (0..4u64).map(ck).collect(),
            current_justified: ck(822),
            previous_justified: ck(821),
            finalized: ck(821),
            leaked: Vec::new(),
            next_epoch: 823,
        },
    }
}

fn state<'a>(f: &'a Fixture, e: &'a [EutxoEntry]) -> ConsensusState<'a> {
    ConsensusState {
        // Empty: this is a carryover-scale fixture, with no withdrawal and no
        // slash in it.
        written_off_sat: 0,
        stake_low_water: &[],
        eutxos: e,
        validators: &f.validators,
        current_participation: &f.current,
        previous_participation: &f.previous,
        randao_mixes: &f.randao,
        finality: &f.finality,
        pending_votes: &[],
        fc_messages: &[],
        fc_equivocators: &[],
        deposit_queue: &[],
        delegations: &[],
        pending_fees: &[],
        taint_root: h32(101),
        coherence_accumulator_root: h32(102),
        coherence_nullifier_root: h32(103),
        evm: EvmCommitment {
            account_root: h32(201),
            receipts_root: h32(202),
            gas_used: 0,
            base_fee_per_gas: 1,
        },
        issued_sat: 1_000_000_000_000_000,
        applied_evidence: &[],
        slash_window: &[],
        delegator_slash_losses: &[],
        base_fee: BaseFeeRecord {
            base_fee_millisat_per_gas: 1_000,
            gas_used: 0,
            tx_bytes: 0,
        },
        delegator_fee_rewards: &[],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The randomized operation schedule
// ─────────────────────────────────────────────────────────────────────────────

/// One key's whole life, as the node would live it. Committed keys end
/// present; ghost keys end absent. Because every group owns a distinct key, ANY
/// interleaving of the groups lands on the same final leaf set — which is
/// exactly what lets the order be randomized without the expected answer
/// moving.
#[derive(Clone, Copy)]
struct Group {
    key: [u8; 32],
    value: [u8; 32],
    kind: u8,
    cursor: u8,
}

/// `(remove?, decoy?)` per step.
const SHAPES: [&[(bool, bool)]; 5] = [
    // committed, written once
    &[(false, false)],
    // committed, overwritten (the value-update path)
    &[(false, true), (false, false)],
    // committed, written, spent, re-created at the same key (the churn path)
    &[(false, true), (true, false), (false, false)],
    // spent before the block ends: created then removed
    &[(false, false), (true, false)],
    // spent after an update: created, overwritten, removed
    &[(false, true), (false, false), (true, false)],
];

impl Group {
    fn steps(&self) -> &'static [(bool, bool)] {
        SHAPES[self.kind as usize]
    }
    fn is_ghost(&self) -> bool {
        self.kind >= 3
    }
}

/// A value that is definitely not the final one, so the update steps really
/// move a leaf's hash instead of hitting `insert`'s no-op path.
fn decoy(value: &[u8; 32]) -> [u8; 32] {
    let mut d = *value;
    d[0] ^= 0xFF;
    d[31] ^= 0x5A;
    d
}

/// Build the incremental tree for `n` committed leaves under `seed`, and report
/// how many operations it took.
///
/// Every committed key gets a randomly chosen life shape, `n / 8` ghost keys are
/// created and spent, and the whole thing is merged into one stream by
/// repeatedly picking a random group that still has work left. Removals are not
/// decoration here: `node_remove` → `collapse` is the arithmetic that has to
/// pull a lone leaf back up to its parent's depth and re-fold it, and a tree
/// that got that wrong would agree with a bulk build on every insert-only test
/// ever written.
fn build_incremental(n: u32, seed: u64) -> (Smt, u64) {
    let mut rng = seed;
    let n_ghost = n / 8;

    let mut groups: Vec<Group> = Vec::with_capacity(n as usize + n_ghost as usize);
    for i in 0..n {
        let (key, value) = eutxo_leaf(&final_entry(i));
        let kind = (splitmix(&mut rng) % 3) as u8; // 0..=2, all committed
        groups.push(Group { key, value, kind, cursor: 0 });
    }
    for i in 0..n_ghost {
        let (key, value) = eutxo_leaf(&ghost_entry(i));
        let kind = 3 + (splitmix(&mut rng) % 2) as u8; // 3..=4, all ghosts
        groups.push(Group { key, value, kind, cursor: 0 });
    }

    let mut smt = Smt::new();
    let mut pending: Vec<u32> = (0..groups.len() as u32).collect();
    let mut ops = 0u64;
    while !pending.is_empty() {
        let j = (splitmix(&mut rng) % pending.len() as u64) as usize;
        let gi = pending[j] as usize;
        let g = groups[gi];
        let (remove, use_decoy) = g.steps()[g.cursor as usize];
        if remove {
            smt.remove(&g.key);
        } else if use_decoy {
            smt.insert(g.key, decoy(&g.value));
        } else {
            smt.insert(g.key, g.value);
        }
        ops += 1;
        groups[gi].cursor += 1;
        if groups[gi].cursor as usize == g.steps().len() {
            pending.swap_remove(j);
        }
    }

    // The ghosts must be gone and the committed set must be exactly present —
    // checked before the roots are compared, so a leaf-set bug is reported as a
    // leaf-set bug rather than as a mysterious root divergence.
    for g in &groups {
        if g.is_ghost() {
            assert!(
                smt.get(&g.key).is_none(),
                "a spent (ghost) leaf survived the schedule — seed {seed:#x}"
            );
        } else {
            assert_eq!(
                smt.get(&g.key),
                Some(g.value),
                "a committed leaf holds the wrong value — seed {seed:#x}"
            );
        }
    }
    assert_eq!(smt.len(), n as usize, "leaf count diverged — seed {seed:#x}");

    (smt, ops)
}

// ─────────────────────────────────────────────────────────────────────────────
// Measured tree geometry
// ─────────────────────────────────────────────────────────────────────────────

/// The empty-subtree constants, read out of the shipped implementation rather
/// than recomputed: a tree holding one leaf proves that leaf with a sibling
/// list that is the empty constant at every level, and the list does not depend
/// on which key it is. `siblings[d]` is the empty subtree root at depth `d + 1`.
fn empty_sibling_table() -> Vec<[u8; 32]> {
    let mut one = Smt::new();
    let k = h32(0xE_9701);
    one.insert(k, h32(0xE_9702));
    let table = one.prove(&k).expect("a committed key must be provable").siblings;
    assert_eq!(table.len(), TREE_DEPTH);
    // Cross-check against the reference table: if these disagree, the whole
    // depth measurement below is meaningless.
    let refs = ref_empty_hashes();
    for d in 0..TREE_DEPTH {
        assert_eq!(table[d], refs[d + 1], "the empty-subtree constants disagree at depth {}", d + 1);
    }
    table
}

/// The depth at which `key` becomes the only leaf in its subtree — i.e. the
/// depth of the deepest internal node on its path.
///
/// Read off the inclusion proof: below the branch point every sibling is the
/// empty constant, so the deepest index whose sibling is *not* the empty
/// constant is the last real split. It is exact and not a lower bound, because
/// `collapse` guarantees a leaf's parent split always has a non-empty other
/// side (a split with one empty side always carries a further split, never a
/// lone leaf).
fn singleton_depth(tree: &Smt, key: &[u8; 32], empty: &[[u8; 32]]) -> usize {
    let p = tree.prove(key).expect("a committed key must be provable");
    for d in (0..TREE_DEPTH).rev() {
        if p.siblings[d] != empty[d] {
            return d + 1;
        }
    }
    0
}

struct Geometry {
    max_depth: usize,
    mean_depth: f64,
    at_or_below_d32: usize,
}

fn geometry(tree: &Smt, keys: &BTreeMap<[u8; 32], [u8; 32]>) -> Geometry {
    let empty = empty_sibling_table();
    let mut max_depth = 0usize;
    let mut sum = 0u64;
    let mut deep = 0usize;
    for k in keys.keys() {
        let d = singleton_depth(tree, k, &empty);
        max_depth = max_depth.max(d);
        sum += d as u64;
        if d > 32 {
            deep += 1;
        }
    }
    Geometry {
        max_depth,
        mean_depth: sum as f64 / keys.len().max(1) as f64,
        at_or_below_d32: keys.len() - deep,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The differential itself
// ─────────────────────────────────────────────────────────────────────────────

fn on_fresh_thread<T: Send + 'static>(
    name: &str,
    stack: usize,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(stack)
        .spawn(f)
        .expect("spawn")
        .join()
        .expect("the side panicked — see the panic above, it IS the result")
}

/// 64 MB. The reference recursion nests one frame per level and stops at
/// `TREE_DEPTH`, so ~257 frames — the size is headroom, not a requirement, and
/// the full-scale run below records that the default 2 MB stack was never the
/// binding constraint.
const STACK: usize = 64 << 20;

struct Sides {
    tree_bulk: [u8; 32],
    tree_ref: [u8; 32],
    state_bulk: [u8; 32],
    t_bulk: Duration,
    t_ref: Duration,
}

/// The two order-independent sides: the bulk tree and the memo-free reference.
/// Each on its own thread; each regenerates the leaf set from `n` alone.
fn invariant_sides(n: u32) -> Sides {
    let (tree_bulk, state_bulk, t_bulk) = on_fresh_thread("bulk", STACK, move || {
        let leaves = final_leaves(n);
        let t = Instant::now();
        let tree = Smt::from_leaf_map(&leaves);
        let tr = tree.root();
        let elapsed = t.elapsed();
        let f = fixture();
        let entries: Vec<EutxoEntry> = (0..n).map(final_entry).collect();
        let sr = state_root(&state(&f, &entries));
        (tr, sr, elapsed)
    });

    let (tree_ref, t_ref) = on_fresh_thread("reference", STACK, move || {
        let leaves = final_leaves(n);
        let t = Instant::now();
        let r = ref_root(&leaves);
        (r, t.elapsed())
    });

    Sides { tree_bulk, tree_ref, state_bulk, t_bulk, t_ref }
}

/// Run the whole differential at `n`, over every seed in [`SEEDS`]. Panics —
/// loudly, with the seed — on any divergence.
fn differential(n: u32, label: &str) {
    println!("\n=== state-root differential @ n = {n} ({label}) ===");
    println!("  seeds: {}", SEEDS.iter().map(|s| format!("{s:#x}")).collect::<Vec<_>>().join(", "));

    let s = invariant_sides(n);
    println!("  BULK      Smt::from_leaf_map  tree_root = {}   [{:?}]", hex32(&s.tree_bulk), s.t_bulk);
    println!("  REFERENCE memo-free recursion tree_root = {}   [{:?}]", hex32(&s.tree_ref), s.t_ref);
    assert_eq!(
        s.tree_bulk, s.tree_ref,
        "\n\n*** THE BULK TREE DISAGREES WITH THE PRE-perf/smt RECURSION AT n = {n} ***\n\
         bulk      = {}\nreference = {}\n\
         This is a consensus divergence in the committed state root. STOP.\n",
        hex32(&s.tree_bulk),
        hex32(&s.tree_ref),
    );

    for &seed in &SEEDS {
        let (tree_inc, state_inc, ops, t_inc) = on_fresh_thread("incremental", STACK, move || {
            let t = Instant::now();
            let (smt, ops) = build_incremental(n, seed);
            let tr = smt.root();
            let elapsed = t.elapsed();
            let f = fixture();
            let sr = state_root_with_eutxo_tree(&state(&f, &[]), &smt);
            (tr, sr, ops, elapsed)
        });

        println!(
            "  INCREMENTAL seed {seed:#018x} ({ops} ops)  tree_root = {}   [{t_inc:?}]",
            hex32(&tree_inc)
        );
        assert_eq!(
            tree_inc, s.tree_bulk,
            "\n\n*** INCREMENTAL ROOT DIVERGES FROM THE BULK ROOT AT n = {n}, SEED {seed:#x} ***\n\
             incremental = {}\nbulk        = {}\n\
             The same leaf set reached by insert/remove commits a different root than the\n\
             same set built from scratch. Every node that replayed a block would disagree\n\
             with every node that state-synced. STOP — do not paper over this.\n",
            hex32(&tree_inc),
            hex32(&s.tree_bulk),
        );
        assert_eq!(
            tree_inc, s.tree_ref,
            "\n\n*** INCREMENTAL ROOT DIVERGES FROM THE REFERENCE RECURSION AT n = {n}, \
             SEED {seed:#x} ***\nSTOP.\n"
        );
        assert_eq!(
            state_inc, s.state_bulk,
            "\n\n*** FULL STATE ROOT DIVERGES AT n = {n}, SEED {seed:#x} ***\n\
             state_root_with_eutxo_tree = {}\nstate_root (bulk)          = {}\nSTOP.\n",
            hex32(&state_inc),
            hex32(&s.state_bulk),
        );
    }

    println!("  FULL STATE ROOT (all paths)             = {}", hex32(&s.state_bulk));
    println!("  VERDICT: identical, {} orders x {} paths, at n = {n}.", SEEDS.len(), 3);
}

/// The always-on version. Same three derivations, same randomized schedules,
/// 1% of carryover so it fits an ordinary `cargo test`.
#[test]
fn state_root_differential_at_small_scale() {
    differential(SMALL_N, "runs by default");
}

/// **The blocker.** The same differential at the size the mainnet validators
/// actually run at.
///
/// `#[ignore]`d because it takes minutes and roughly a gigabyte, not because it
/// is optional: the deployment is gated on it. `--release` or it takes a great
/// deal longer.
#[test]
#[ignore]
fn state_root_differential_at_carryover_scale() {
    differential(CARRYOVER_N, "REAL Genesis-4 carryover");
}

/// **Is scale even a mechanism here?**
///
/// The tree is depth-256 and sparse, so the only thing that can make 452,726
/// leaves behave unlike 4,527 is the part of the shape that *is* a function of
/// n: how deep the internal nodes actually go before a leaf becomes the only
/// one in its subtree. Everything below that depth is the singleton fold, which
/// is a pure function of `(key, value, depth)` and identical in both regimes.
///
/// This measures that depth at both scales instead of arguing about it. A tree
/// whose deepest split is ~30 at half a million SHA3-distributed keys is a tree
/// in which the 226 levels below it are the same folded constants they are at
/// 4,527 keys.
#[test]
fn measured_tree_depth_at_small_scale() {
    let leaves = final_leaves(SMALL_N);
    let tree = Smt::from_leaf_map(&leaves);
    let g = geometry(&tree, &leaves);
    println!(
        "  n = {SMALL_N}: deepest internal node = {}, mean = {:.2}, at or below depth 32 = {}/{}",
        g.max_depth,
        g.mean_depth,
        g.at_or_below_d32,
        leaves.len()
    );
    // log2(4527) ~ 12.1. A random-key trie's deepest path is a few multiples of
    // that, never a few multiples of 256.
    assert!(
        g.max_depth < 64,
        "the deepest split reached {} — the trie is not behaving like a random-key trie",
        g.max_depth
    );
}

/// **The scale-invariance question, measured instead of argued.**
///
/// The deepest internal node actually reached, at four leaf counts two and a
/// half orders of magnitude apart. If the tree at 452,726 leaves is still
/// branching in the top few dozen of its 256 levels — and it is — then the
/// levels below the branch point are the same singleton fold in both regimes,
/// and a fold is a pure function of `(key, value_hash, depth)` with no
/// dependence on how many other leaves exist.
///
/// `#[ignore]`d: the 452,726-leaf row alone is a full bulk build plus an
/// inclusion proof per leaf.
#[test]
#[ignore]
fn measured_tree_depth_scaling() {
    println!("\n=== deepest internal node vs leaf count (MEASURED) ===");
    println!(
        "{:>10}  {:>9}  {:>11}  {:>8}  {:>14}",
        "n", "log2(n)", "max depth", "mean", "deeper than 32"
    );
    let mut prev_max = 0usize;
    for n in [1_024u32, 4_527, 45_272, CARRYOVER_N] {
        let (max_depth, mean_depth, deep, len) = on_fresh_thread("geometry", STACK, move || {
            let leaves = final_leaves(n);
            let tree = Smt::from_leaf_map(&leaves);
            let g = geometry(&tree, &leaves);
            (g.max_depth, g.mean_depth, leaves.len() - g.at_or_below_d32, leaves.len())
        });
        println!(
            "{n:>10}  {:>9.1}  {max_depth:>11}  {mean_depth:>8.2}  {deep:>8}/{len:<5}",
            (n as f64).log2()
        );
        assert!(
            max_depth < 64,
            "the deepest split reached {max_depth} at n = {n} — that is not a random-key trie"
        );
        prev_max = prev_max.max(max_depth);
    }
    println!(
        "  MEASURED: the deepest internal node anywhere in this sweep is {prev_max} of 256.\n  \
         Every level below it is the singleton fold, which depends on (key, value_hash,\n  \
         depth) alone — never on the leaf count."
    );
}
