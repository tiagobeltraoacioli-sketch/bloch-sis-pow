//! Interval-based reachability index for GhostDAG (Kaspa-style).
//!
//! # Why this exists
//!
//! The legacy `is_ancestor` in `mod.rs` answers DAG-ancestry with a **bounded**
//! backwards BFS (`MAX_REACHABILITY_DEPTH = 1024`, plus a `depth_limit*10`
//! visited cap). When the height-difference between two blocks exceeds that
//! bound the BFS silently clamps and can return a **false negative** — it is
//! O(height_diff) and, worse, *result-affecting when the bound is hit*.
//!
//! This module provides an **unbounded, O(1)/O(log n)** replacement based on
//! the selected-parent-tree interval labeling + future-covering-set (FCS)
//! technique from Sompolinsky/Wyborski/Zohar and its implementation in
//! kaspanet/rusty-kaspa (`consensus/src/processes/reachability`).
//!
//! # SAFETY / consensus status
//!
//! This index is **NOT wired into the live consensus hot path.** It is used
//! only by `GhostDAG` when its `ColoringMode` is set to `Fast`, which is an
//! opt-in mode exercised by the differential test (`tests/ghostdag_differential.rs`).
//!
//! The reason is spelled out in the implementation plan: replacing the bounded
//! `is_ancestor` with a *correct* unbounded one is only a pure-performance,
//! result-identical change **if** the bound never actually bit on the real
//! chain. The bounded path can, in principle, produce a different (bug-compatible)
//! blue set / blue_score than the correct path on pathological deep+wide DAGs.
//! Adopting the correct answer where they differ would be a **consensus rule
//! change / fork** and must go behind an activation-height gate with network
//! coordination — never baked silently into the hot path.
//!
//! The differential test is what proves, per DAG shape, whether legacy and
//! fast agree byte-for-byte. On the real ≥397k mainnet history that proof must
//! be run against a snapshot before this index can be promoted to the default.
//!
//! # Correctness harness
//!
//! Every query answered by this index is validated in tests against
//! [`brute_force_is_ancestor`], an unbounded BFS oracle over the parent graph.
//! A mis-labeled interval or a stale FCS silently mis-colors blocks, so this
//! oracle equivalence is the single highest-value guard in the whole change.

use std::collections::HashMap;
use super::{BlockHash, DagStore};

/// A half-open-free interval `[start, end]` (both inclusive) in the reachability
/// labeling. A node's own identity point is its `end`; its tree-children are
/// laid out within `[start, end-1]`. Thus node `a` is a *chain* (selected-parent
/// tree) ancestor of node `b` iff `a`'s interval strictly contains `b`'s.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interval {
    pub start: u64,
    pub end: u64,
}

impl Interval {
    #[inline]
    fn contains(&self, other: &Interval) -> bool {
        self.start <= other.start && other.end <= self.end
    }
    #[inline]
    fn capacity(&self) -> u64 {
        // number of integer slots this interval can host, inclusive
        self.end - self.start + 1
    }
}

/// Root interval upper bound. 2^62 leaves head-room so that, for any realistic
/// DAG, reindexing is rare and never runs out of address space.
const ROOT_END: u64 = 1u64 << 62;
const ROOT_START: u64 = 1;

/// Interval-labeling + future-covering-set reachability index.
///
/// Owns no `GhostdagData` and feeds nothing into `canonical_encode` /
/// `compute_integrity_hash`; it is a pure cache and can be rebuilt freely by
/// replaying block insertions in topological order.
pub struct ReachabilityStore {
    interval: HashMap<BlockHash, Interval>,
    tree_parent: HashMap<BlockHash, BlockHash>,
    children: HashMap<BlockHash, Vec<BlockHash>>,
    /// Free trailing sub-range within a node's `[start, end-1]` not yet handed
    /// out to children: `(next_free_start, last_free_end)`. When `lo > hi` the
    /// node is full and a reindex is required to make room.
    remaining: HashMap<BlockHash, (u64, u64)>,
    /// Future covering set per block: blocks `b` for which this block is in
    /// `mergeset(b)`. Kept sorted by interval start. Used to answer non-tree
    /// (merge-edge) ancestry.
    fcs: HashMap<BlockHash, Vec<BlockHash>>,
    root: Option<BlockHash>,
}

impl Default for ReachabilityStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ReachabilityStore {
    pub fn new() -> Self {
        Self {
            interval: HashMap::new(),
            tree_parent: HashMap::new(),
            children: HashMap::new(),
            remaining: HashMap::new(),
            fcs: HashMap::new(),
            root: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.interval.is_empty()
    }

    pub fn len(&self) -> usize {
        self.interval.len()
    }

    pub fn has(&self, hash: &BlockHash) -> bool {
        self.interval.contains_key(hash)
    }

    /// Register the genesis / root block. Idempotent-guarded by the caller.
    pub fn add_genesis(&mut self, hash: BlockHash) {
        let iv = Interval { start: ROOT_START, end: ROOT_END };
        self.interval.insert(hash, iv);
        self.children.insert(hash, Vec::new());
        self.remaining.insert(hash, (iv.start, iv.end - 1));
        self.fcs.insert(hash, Vec::new());
        self.root = Some(hash);
    }

    /// Add a non-genesis block: `selected_parent` is the tree edge, `mergeset`
    /// is `past(block) \ past(selected_parent) \ {selected_parent}` (exactly the
    /// GhostDAG mergeset). Both the tree interval and the future-covering sets
    /// are updated.
    ///
    /// Blocks MUST be added in a topological order (parents before children);
    /// `GhostDAG::add_block` guarantees this.
    pub fn add_block(
        &mut self,
        hash: BlockHash,
        selected_parent: &BlockHash,
        mergeset: &[BlockHash],
    ) {
        self.add_tree_block(hash, selected_parent);
        // Update the future covering set of every merged block.
        for m in mergeset {
            self.insert_to_fcs(*m, hash);
        }
    }

    // ── tree interval maintenance ───────────────────────────────────────────

    fn add_tree_block(&mut self, child: BlockHash, parent: &BlockHash) {
        self.tree_parent.insert(child, *parent);
        self.children.entry(*parent).or_default().push(child);
        self.children.entry(child).or_default();
        self.fcs.entry(child).or_default();

        // Try to carve a slice from the parent's trailing free range.
        let (lo, hi) = *self.remaining.get(parent).unwrap_or(&(1, 0));
        if lo <= hi {
            // Exponential allocation: give the new child up to half of the
            // parent's remaining space, keeping the rest for future siblings.
            let span = hi - lo + 1;
            let give = (span / 2).max(1);
            let child_start = lo;
            let child_end = lo + give - 1;
            let iv = Interval { start: child_start, end: child_end };
            self.interval.insert(child, iv);
            self.remaining.insert(child, (iv.start, iv.end.saturating_sub(1)));
            self.remaining.insert(*parent, (child_end + 1, hi));
        } else {
            // Parent is out of room — reindex its subtree (or a higher ancestor
            // with slack) so the new child gets a valid interval.
            self.interval.insert(child, Interval { start: 0, end: 0 }); // placeholder
            self.remaining.insert(child, (1, 0));
            self.reindex(*parent);
        }
    }

    /// Recompute the interval labeling for `node`'s entire subtree, in place,
    /// within `node`'s current interval. If `node`'s interval is too small to
    /// hold its subtree, first reindex `node`'s parent to enlarge `node`.
    fn reindex(&mut self, node: BlockHash) {
        let size = self.subtree_size(&node);
        let cap = self.interval.get(&node).map(|iv| iv.capacity()).unwrap_or(0);
        if cap < size {
            // Not enough room here — push the reindex up one level. The root
            // has ROOT_END capacity, so this always terminates.
            if let Some(parent) = self.tree_parent.get(&node).copied() {
                self.reindex(parent);
                return;
            }
            // At the root with insufficient capacity: this only happens for
            // astronomically large DAGs (> 2^62 blocks). Grow the root.
            let iv = Interval { start: ROOT_START, end: ROOT_END.max(size + ROOT_START) };
            self.interval.insert(node, iv);
        }
        let iv = *self.interval.get(&node).expect("node has interval");
        self.assign_subtree(node, iv);
    }

    /// Lay out `node` and all its tree-descendants within `iv` using a
    /// count-based proportional split, distributing slack in proportion to
    /// subtree sizes. `node`'s own identity point is `iv.end`.
    fn assign_subtree(&mut self, node: BlockHash, iv: Interval) {
        self.interval.insert(node, iv);
        let children = self.children.get(&node).cloned().unwrap_or_default();
        if children.is_empty() {
            self.remaining.insert(node, (iv.start, iv.end.saturating_sub(1)));
            return;
        }
        // Children occupy [iv.start, iv.end-1]; iv.end reserved for `node`.
        let region_start = iv.start;
        let region_len = iv.end - iv.start; // slots available to children
        let sizes: Vec<u64> = children.iter().map(|c| self.subtree_size(c)).collect();
        let total: u64 = sizes.iter().sum::<u64>().max(1);
        let slack = region_len.saturating_sub(total);

        let mut cursor = region_start;
        for (c, &sz) in children.iter().zip(sizes.iter()) {
            // proportional share of slack, plus the child's own subtree size
            let extra = if total > 0 { slack.saturating_mul(sz) / total } else { 0 };
            let child_len = (sz + extra).max(1);
            let child_start = cursor;
            let child_end = (cursor + child_len - 1).min(iv.end - 1);
            let child_iv = Interval { start: child_start, end: child_end.max(child_start) };
            cursor = child_end + 1;
            self.assign_subtree(*c, child_iv);
        }
        // Any trailing slots stay free on `node` for future children.
        let free_lo = cursor.min(iv.end);
        self.remaining.insert(node, (free_lo, iv.end.saturating_sub(1)));
    }

    fn subtree_size(&self, node: &BlockHash) -> u64 {
        // iterative DFS to avoid stack overflow on deep chains
        let mut count = 0u64;
        let mut stack = vec![*node];
        while let Some(n) = stack.pop() {
            count += 1;
            if let Some(ch) = self.children.get(&n) {
                for c in ch {
                    stack.push(*c);
                }
            }
        }
        count
    }

    // ── future covering set maintenance ─────────────────────────────────────

    fn insert_to_fcs(&mut self, block: BlockHash, new_future: BlockHash) {
        let new_iv = match self.interval.get(&new_future) {
            Some(iv) => *iv,
            None => return,
        };
        // Snapshot the current FCS for the search phase (avoids a simultaneous
        // mutable+immutable borrow of `self`).
        let fcs_snapshot = self.fcs.get(&block).cloned().unwrap_or_default();
        // rightmost element whose start <= new_iv.start
        let pp = partition_point(&fcs_snapshot, |h, this| {
            this.interval.get(h).map(|iv| iv.start <= new_iv.start).unwrap_or(false)
        }, self);
        if pp > 0 {
            let cand = fcs_snapshot[pp - 1];
            if let Some(civ) = self.interval.get(&cand) {
                if civ.contains(&new_iv) {
                    // `new_future` is already covered by an existing FCS block
                    // that is its chain ancestor — nothing to insert.
                    return;
                }
            }
        }
        // `new_future` is the newest block, so it cannot be an ancestor of any
        // existing FCS member — a plain sorted insert keeps the set correct.
        self.fcs.entry(block).or_default().insert(pp, new_future);
    }

    // ── queries ─────────────────────────────────────────────────────────────

    /// Is `a` a selected-parent-tree (chain) ancestor of `b`? Strict: returns
    /// `false` when `a == b`. O(1).
    pub fn is_chain_ancestor(&self, a: &BlockHash, b: &BlockHash) -> bool {
        if a == b {
            return false;
        }
        match (self.interval.get(a), self.interval.get(b)) {
            (Some(ia), Some(ib)) => ia.contains(ib),
            _ => false,
        }
    }

    /// Is `a` a DAG ancestor of `b` (i.e. `a ∈ past(b)`)? Strict: `false` when
    /// `a == b`, matching the semantics of the legacy `is_ancestor`.
    /// O(log |FCS|).
    pub fn is_dag_ancestor(&self, a: &BlockHash, b: &BlockHash) -> bool {
        if a == b {
            return false;
        }
        if self.is_chain_ancestor(a, b) {
            return true;
        }
        let b_iv = match self.interval.get(b) {
            Some(iv) => *iv,
            None => return false,
        };
        let fcs = match self.fcs.get(a) {
            Some(f) => f,
            None => return false,
        };
        // rightmost FCS element whose start <= b.start
        let pp = partition_point(fcs, |h, this| {
            this.interval.get(h).map(|iv| iv.start <= b_iv.start).unwrap_or(false)
        }, self);
        if pp > 0 {
            let cand = fcs[pp - 1];
            // cand is a chain ancestor of b  ⇒  a → cand → b, so a reaches b.
            if self.is_chain_ancestor(&cand, b) || cand == *b {
                return true;
            }
        }
        false
    }

    /// Remove a childless leaf, exactly inverting a just-performed `add_block`.
    /// Used by the reorg-undo path. Returns `false` (no mutation) if the block
    /// is unknown or still has tree children.
    pub fn remove_leaf(&mut self, hash: &BlockHash, mergeset: &[BlockHash]) -> bool {
        if self.children.get(hash).map_or(false, |c| !c.is_empty()) {
            return false;
        }
        if !self.interval.contains_key(hash) {
            return false;
        }
        // Undo FCS insertions.
        for m in mergeset {
            if let Some(f) = self.fcs.get_mut(m) {
                if let Some(pos) = f.iter().position(|x| x == hash) {
                    f.remove(pos);
                }
            }
        }
        // Undo tree edge.
        if let Some(parent) = self.tree_parent.remove(hash) {
            if let Some(ch) = self.children.get_mut(&parent) {
                if let Some(pos) = ch.iter().position(|x| x == hash) {
                    ch.remove(pos);
                }
            }
        }
        self.interval.remove(hash);
        self.remaining.remove(hash);
        self.children.remove(hash);
        self.fcs.remove(hash);
        true
    }
}

/// `Vec` partition point where the elements form a prefix satisfying `pred`.
/// Reimplemented (rather than `slice::partition_point`) because the predicate
/// needs `&ReachabilityStore` to look up intervals.
fn partition_point<F>(v: &[BlockHash], pred: F, store: &ReachabilityStore) -> usize
where
    F: Fn(&BlockHash, &ReachabilityStore) -> bool,
{
    let mut lo = 0usize;
    let mut hi = v.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if pred(&v[mid], store) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// Unbounded brute-force DAG-ancestry oracle over the raw parent graph.
///
/// This is the ground truth the interval index is validated against. It is the
/// *correct* (unbounded) answer — note this can differ from the legacy bounded
/// `is_ancestor` when the legacy bound is hit; that difference is precisely the
/// latent-consensus question the differential test exists to answer.
pub fn brute_force_is_ancestor(store: &DagStore, a: &BlockHash, b: &BlockHash) -> bool {
    use std::collections::{HashSet, VecDeque};
    if a == b {
        return false;
    }
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    if let Some(d) = store.get(b) {
        for p in &d.parents {
            queue.push_back(*p);
        }
    }
    while let Some(h) = queue.pop_front() {
        if &h == a {
            return true;
        }
        if visited.insert(h) {
            if let Some(d) = store.get(&h) {
                for p in &d.parents {
                    if !visited.contains(p) {
                        queue.push_back(*p);
                    }
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u16) -> BlockHash {
        let mut out = [0u8; 32];
        out[0] = (n >> 8) as u8;
        out[1] = (n & 0xff) as u8;
        out
    }

    #[test]
    fn chain_ancestry_linear() {
        let mut r = ReachabilityStore::new();
        let g = h(0);
        r.add_genesis(g);
        let mut prev = g;
        let mut all = vec![g];
        for i in 1..=50u16 {
            let b = h(i);
            r.add_block(b, &prev, &[]); // linear: empty mergeset
            prev = b;
            all.push(b);
        }
        // Every earlier block is an ancestor of every later block.
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert!(r.is_dag_ancestor(a, b), "{i} should be ancestor");
                assert!(!r.is_dag_ancestor(b, a), "reverse must be false");
            }
            assert!(!r.is_dag_ancestor(a, a), "strict: not self-ancestor");
        }
    }

    #[test]
    fn diamond_merge_ancestry() {
        // g -> a, g -> b, c merges {a,b} (selected_parent = a, mergeset = {b})
        let mut r = ReachabilityStore::new();
        let (g, a, b, c) = (h(0), h(1), h(2), h(3));
        r.add_genesis(g);
        r.add_block(a, &g, &[]);
        r.add_block(b, &g, &[]);
        // suppose a is selected parent of c; b is merged
        r.add_block(c, &a, &[b]);
        assert!(r.is_dag_ancestor(&g, &c));
        assert!(r.is_dag_ancestor(&a, &c));
        assert!(r.is_dag_ancestor(&b, &c), "merge-edge ancestry via FCS");
        assert!(!r.is_dag_ancestor(&a, &b), "siblings are anticone");
        assert!(!r.is_dag_ancestor(&b, &a));
        assert!(!r.is_dag_ancestor(&c, &a));
    }
}
