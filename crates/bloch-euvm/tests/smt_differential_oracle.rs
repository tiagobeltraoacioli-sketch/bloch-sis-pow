//! # Differential oracle: the incremental SMT vs. the original recompute-everything one
//!
//! `src/state.rs`'s `SparseMerkleTree` was rewritten from "rebuild the whole tree on
//! every `root()`" into an incremental engine (memoized node hashes + eager root).
//! The roots it produces are a **committed identity** — they ride in the harness's
//! "EUV1" block section (src/harness.rs:194, :232) — so the refactor is only correct
//! if it is byte-identical to what it replaced, not merely self-consistent.
//!
//! `tests/euvm_pinned_roots.rs` pins five fixtures byte-for-byte. This file is the
//! stronger check: it carries the **pre-refactor algorithm verbatim** (copied from
//! main@751afdae `src/state.rs`, lines 82-171: `shake32`/`key_hash`/`leaf_hash`/
//! `node_hash`/`bit_at`/`empty_hashes`/`partition`/`subtree_hash`) as an independent
//! oracle, and asserts the two agree at *every* step of a 184-mutation script —
//! inserts of varying key/value length, removals, and overwrites.
//!
//! **Marked `#[ignore]` for runtime, not for doubt.** The oracle is quadratic by
//! construction (that is the thing the refactor removed): it re-hashes every entry
//! and re-walks all 256 levels on every one of the 184 steps. In a debug build's
//! SHAKE-256 (measured ~425 µs/hash on the dev machine) that is minutes. Run it as:
//!
//! ```text
//! cargo test -p bloch-euvm --release --test smt_differential_oracle -- --ignored
//! ```
//!
//! Do not "fix" a failure here by regenerating the oracle. A divergence means the
//! incremental engine changed a committed root.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use std::collections::BTreeMap;
type Hash = [u8; 32];
const TREE_DEPTH: usize = 256;
const KEY_TAG: u8 = 0x02;
const LEAF_TAG: u8 = 0x00;
const NODE_TAG: u8 = 0x01;
fn shake32(parts: &[&[u8]]) -> Hash {
    let mut h = Shake256::default();
    for p in parts { h.update(p); }
    let mut r = h.finalize_xof();
    let mut out = [0u8; 32];
    r.read(&mut out);
    out
}
fn key_hash(key: &[u8]) -> Hash { shake32(&[&[KEY_TAG], key]) }
fn leaf_hash(kh: &Hash, value: &[u8]) -> Hash {
    let len = (value.len() as u64).to_le_bytes();
    shake32(&[&[LEAF_TAG], kh, &len, value])
}
fn node_hash(left: &Hash, right: &Hash) -> Hash { shake32(&[&[NODE_TAG], left, right]) }
fn bit_at(h: &Hash, depth: usize) -> u8 { (h[depth / 8] >> (7 - (depth % 8))) & 1 }
fn empty_hashes() -> [Hash; TREE_DEPTH + 1] {
    let mut e = [[0u8; 32]; TREE_DEPTH + 1];
    let mut d = TREE_DEPTH;
    while d > 0 { d -= 1; e[d] = node_hash(&e[d + 1], &e[d + 1]); }
    e
}
fn partition(entries: &[(Hash, Hash)], depth: usize) -> usize {
    entries.partition_point(|(kh, _)| bit_at(kh, depth) == 0)
}
fn subtree_hash(entries: &[(Hash, Hash)], depth: usize, empty: &[Hash; TREE_DEPTH + 1]) -> Hash {
    if entries.is_empty() { return empty[depth]; }
    if depth == TREE_DEPTH { return entries[0].1; }
    let split = partition(entries, depth);
    let (l, r) = entries.split_at(split);
    node_hash(&subtree_hash(l, depth + 1, empty), &subtree_hash(r, depth + 1, empty))
}
fn old_root(map: &BTreeMap<Vec<u8>, Vec<u8>>) -> Hash {
    let empty = empty_hashes();
    let mut v: Vec<(Hash, Hash)> = map.iter().map(|(k, val)| { let kh = key_hash(k); (kh, leaf_hash(&kh, val)) }).collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    subtree_hash(&v, 0, &empty)
}
#[test]
#[ignore = "quadratic reference oracle: minutes in debug; run with --release -- --ignored"]
fn differential_old_vs_new_roots_and_proofs() {
    use bloch_euvm::state::{verify, SparseMerkleTree};
    // 120 pseudo-random-ish keys of varying length + removals, checking the OLD
    // root equals the NEW root at EVERY step (not just at the end).
    let mut map: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let mut t = SparseMerkleTree::new();
    for i in 0..120u32 {
        let k = format!("key-{}-{}", i, "x".repeat((i % 7) as usize)).into_bytes();
        let v = vec![(i % 251) as u8; (i % 40) as usize];
        map.insert(k.clone(), v.clone());
        t.insert(&k, &v);
        assert_eq!(old_root(&map), t.root(), "root diverged at insert {i}");
        // proofs must verify against the (identical) root, both polarities
        let p = t.prove(&k);
        assert!(verify(&t.root(), &p));
        let absent = t.prove(b"definitely-not-here");
        assert!(verify(&t.root(), &absent));
        assert!(!absent.is_membership());
    }
    // interleaved removals + overwrites
    for i in (0..120u32).step_by(3) {
        let k = format!("key-{}-{}", i, "x".repeat((i % 7) as usize)).into_bytes();
        map.remove(&k);
        t.remove(&k);
        assert_eq!(old_root(&map), t.root(), "root diverged at remove {i}");
    }
    for i in (1..120u32).step_by(5) {
        let k = format!("key-{}-{}", i, "x".repeat((i % 7) as usize)).into_bytes();
        map.insert(k.clone(), b"OVERWRITTEN".to_vec());
        t.insert(&k, b"OVERWRITTEN");
        assert_eq!(old_root(&map), t.root(), "root diverged at overwrite {i}");
    }
    println!("DIFFERENTIAL OK: old == new across 120 inserts + 40 removes + 24 overwrites");
}
