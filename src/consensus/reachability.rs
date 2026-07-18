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
    /// Durability tracking (Phase 1 — persistent reachability index).
    ///
    /// `dirty` holds every block whose persisted record (interval / remaining /
    /// tree_parent / children / fcs) changed since the last
    /// [`take_persist_delta`]. A single `add_block` can dirty many blocks when a
    /// reindex reshuffles a subtree, so this set — not just the newly-added hash
    /// — is what must be flushed to keep the on-disk index consistent with
    /// memory. `tombstones` holds blocks removed by [`remove_leaf`] that must be
    /// deleted from the CF. Both are drained atomically alongside the CF_DAG
    /// write; see `docs/adr/ADR-035-*` and `Storage::put_dag_with_integrity_and_reach`.
    ///
    /// These sets are pure bookkeeping — they are NOT part of any query answer,
    /// NOT consensus state, and are empty on a freshly-loaded index.
    dirty: std::collections::HashSet<BlockHash>,
    tombstones: std::collections::HashSet<BlockHash>,
}

/// Version tag for the serialized per-block reachability record layout. Bumped
/// whenever [`ReachabilityStore::encode_record`] / [`decode_record`] change
/// incompatibly, so a boot against an older on-disk index triggers a rebuild
/// rather than mis-decoding. Persisted as `reachability/meta/version` in CF_META.
pub const REACHABILITY_RECORD_VERSION: u32 = 1;

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
            dirty: std::collections::HashSet::new(),
            tombstones: std::collections::HashSet::new(),
        }
    }

    /// The root (genesis) block of the labeling, if registered.
    pub fn root(&self) -> Option<BlockHash> {
        self.root
    }

    #[inline]
    fn mark_dirty(&mut self, hash: BlockHash) {
        // A block cannot be both live-and-dirty and a tombstone.
        self.tombstones.remove(&hash);
        self.dirty.insert(hash);
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
        self.mark_dirty(hash);
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
            self.mark_dirty(child);
            self.mark_dirty(*parent);
        } else {
            // Parent is out of room — reindex its subtree (or a higher ancestor
            // with slack) so the new child gets a valid interval.
            self.interval.insert(child, Interval { start: 0, end: 0 }); // placeholder
            self.remaining.insert(child, (1, 0));
            self.mark_dirty(child);
            self.mark_dirty(*parent);
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
        // This node's interval (and, below, its `remaining`) just changed, so
        // its persisted record is stale — flag it for the next durable flush.
        self.mark_dirty(node);
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
        self.mark_dirty(block);
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
                    self.mark_dirty(*m);
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
            self.mark_dirty(parent);
        }
        self.interval.remove(hash);
        self.remaining.remove(hash);
        self.children.remove(hash);
        self.fcs.remove(hash);
        // Removal wins over any pending dirty flag for this block.
        self.dirty.remove(hash);
        self.tombstones.insert(*hash);
        true
    }

    // ── durable serialization (Phase 1) ──────────────────────────────────────

    /// Deterministically encode a single block's reachability record.
    ///
    /// Layout (all integers little-endian):
    /// ```text
    /// [start u64][end u64][rem_lo u64][rem_hi u64]
    /// [parent_tag u8][parent 32B]           // tag 0 = no tree parent (root)
    /// [children_len u32][children 32B*]      // insertion order preserved
    /// [fcs_len u32][fcs 32B*]                // interval-start-sorted order
    /// ```
    /// Byte-for-byte reproducible from equal in-memory state. Returns `None`
    /// if the block has no interval (never registered / already removed).
    fn encode_record(&self, hash: &BlockHash) -> Option<Vec<u8>> {
        let iv = self.interval.get(hash)?;
        let (lo, hi) = self.remaining.get(hash).copied().unwrap_or((1, 0));
        let children = self.children.get(hash).cloned().unwrap_or_default();
        let fcs = self.fcs.get(hash).cloned().unwrap_or_default();
        let mut out = Vec::with_capacity(41 + 4 + children.len() * 32 + 4 + fcs.len() * 32);
        out.extend_from_slice(&iv.start.to_le_bytes());
        out.extend_from_slice(&iv.end.to_le_bytes());
        out.extend_from_slice(&lo.to_le_bytes());
        out.extend_from_slice(&hi.to_le_bytes());
        match self.tree_parent.get(hash) {
            Some(p) => { out.push(1); out.extend_from_slice(p); }
            None => { out.push(0); out.extend_from_slice(&[0u8; 32]); }
        }
        out.extend_from_slice(&(children.len() as u32).to_le_bytes());
        for c in &children { out.extend_from_slice(c); }
        out.extend_from_slice(&(fcs.len() as u32).to_le_bytes());
        for f in &fcs { out.extend_from_slice(f); }
        Some(out)
    }

    /// Drain the pending durability delta: `(upserts, deletes)`. `upserts` are
    /// `(block_hash, encoded_record)` pairs for every block whose record changed
    /// since the last drain; `deletes` are blocks removed from the index. The
    /// caller MUST persist all of these in the SAME atomic batch as the
    /// corresponding CF_DAG write, then this drain leaves the tracking sets
    /// empty. Idempotent when nothing changed (returns two empty vecs).
    pub fn take_persist_delta(&mut self) -> (Vec<(BlockHash, Vec<u8>)>, Vec<BlockHash>) {
        let mut upserts = Vec::with_capacity(self.dirty.len());
        // Deterministic order (sorted by hash) so identical logical state
        // produces identical write sequences — helps reproducibility/debugging.
        let mut dirty: Vec<BlockHash> = self.dirty.drain().collect();
        dirty.sort_unstable();
        for h in dirty {
            if let Some(rec) = self.encode_record(&h) {
                upserts.push((h, rec));
            }
        }
        let mut deletes: Vec<BlockHash> = self.tombstones.drain().collect();
        deletes.sort_unstable();
        (upserts, deletes)
    }

    /// Snapshot the ENTIRE index as `(block_hash, encoded_record)` pairs, in
    /// hash-sorted order. Used to write a freshly-rebuilt index in one batch and
    /// by round-trip tests. Does not touch the dirty/tombstone tracking.
    pub fn export_all(&self) -> Vec<(BlockHash, Vec<u8>)> {
        let mut hashes: Vec<BlockHash> = self.interval.keys().copied().collect();
        hashes.sort_unstable();
        hashes.iter().filter_map(|h| self.encode_record(h).map(|r| (*h, r))).collect()
    }

    /// Rebuild the whole index in-memory from persisted records + the stored
    /// root. Replaces any current state. Returns `Err` on a malformed record.
    /// After this the dirty/tombstone sets are empty (the on-disk copy is
    /// authoritative and already matches memory).
    pub fn load_from_records(
        &mut self,
        records: &[(BlockHash, Vec<u8>)],
        root: Option<BlockHash>,
    ) -> Result<(), String> {
        self.interval.clear();
        self.tree_parent.clear();
        self.children.clear();
        self.remaining.clear();
        self.fcs.clear();
        self.dirty.clear();
        self.tombstones.clear();
        self.root = root;
        for (h, bytes) in records {
            let (iv, rem, parent, children, fcs) = decode_record(bytes)
                .map_err(|e| format!("reachability record for {} malformed: {e}", hex::encode(&h[..4])))?;
            self.interval.insert(*h, iv);
            self.remaining.insert(*h, rem);
            if let Some(p) = parent { self.tree_parent.insert(*h, p); }
            self.children.insert(*h, children);
            self.fcs.insert(*h, fcs);
        }
        Ok(())
    }
}

/// Decode a record produced by `ReachabilityStore::encode_record`.
#[allow(clippy::type_complexity)]
fn decode_record(
    b: &[u8],
) -> Result<(Interval, (u64, u64), Option<BlockHash>, Vec<BlockHash>, Vec<BlockHash>), String> {
    let mut o = 0usize;
    let rd_u64 = |b: &[u8], o: &mut usize| -> Result<u64, String> {
        if *o + 8 > b.len() { return Err("truncated u64".into()); }
        let v = u64::from_le_bytes(b[*o..*o + 8].try_into().unwrap());
        *o += 8; Ok(v)
    };
    let rd_hash = |b: &[u8], o: &mut usize| -> Result<BlockHash, String> {
        if *o + 32 > b.len() { return Err("truncated hash".into()); }
        let mut h = [0u8; 32]; h.copy_from_slice(&b[*o..*o + 32]); *o += 32; Ok(h)
    };
    let start = rd_u64(b, &mut o)?;
    let end = rd_u64(b, &mut o)?;
    let lo = rd_u64(b, &mut o)?;
    let hi = rd_u64(b, &mut o)?;
    if o >= b.len() { return Err("truncated parent tag".into()); }
    let tag = b[o]; o += 1;
    let parent_raw = rd_hash(b, &mut o)?;
    let parent = if tag == 1 { Some(parent_raw) } else { None };
    if o + 4 > b.len() { return Err("truncated children len".into()); }
    let clen = u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) as usize; o += 4;
    let mut children = Vec::with_capacity(clen);
    for _ in 0..clen { children.push(rd_hash(b, &mut o)?); }
    if o + 4 > b.len() { return Err("truncated fcs len".into()); }
    let flen = u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) as usize; o += 4;
    let mut fcs = Vec::with_capacity(flen);
    for _ in 0..flen { fcs.push(rd_hash(b, &mut o)?); }
    Ok((Interval { start, end }, (lo, hi), parent, children, fcs))
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

    /// Serialize → clear → reload must answer every ancestry query identically.
    #[test]
    fn persist_roundtrip_matches() {
        let mut r = ReachabilityStore::new();
        let g = h(0);
        r.add_genesis(g);
        // Build a merging DAG that forces at least one reindex + non-trivial FCS.
        let mut prev = g;
        let mut all = vec![g];
        for i in 1..=40u16 {
            let l = h(i);
            let rr = h(1000 + i);
            let m = h(2000 + i);
            r.add_block(l, &prev, &[]);
            r.add_block(rr, &prev, &[]);
            r.add_block(m, &l, &[rr]); // selected_parent = l, merges rr
            all.push(l); all.push(rr); all.push(m);
            prev = m;
        }
        let root = r.root();
        let records = r.export_all();

        let mut restored = ReachabilityStore::new();
        restored.load_from_records(&records, root).expect("reload");
        assert_eq!(restored.len(), r.len());
        for a in &all {
            for b in &all {
                assert_eq!(
                    r.is_dag_ancestor(a, b),
                    restored.is_dag_ancestor(a, b),
                    "roundtrip mismatch for pair"
                );
            }
        }
    }

    /// The incremental delta drain reproduces the same records as a full export.
    #[test]
    fn delta_drain_reconstructs_full_index() {
        let mut r = ReachabilityStore::new();
        let g = h(0);
        r.add_genesis(g);
        let mut prev = g;
        for i in 1..=25u16 {
            let a = h(i);
            let b = h(500 + i);
            r.add_block(a, &prev, &[]);
            r.add_block(b, &a, &[]); // linear-ish with occasional sibling
            prev = a;
            let _ = b;
        }
        // Apply the drained upserts into a fresh map and compare to export_all.
        let (upserts, deletes) = r.take_persist_delta();
        assert!(deletes.is_empty(), "no removals happened");
        let mut disk: std::collections::HashMap<BlockHash, Vec<u8>> =
            upserts.into_iter().collect();
        // A second drain must be empty (idempotent).
        let (u2, d2) = r.take_persist_delta();
        assert!(u2.is_empty() && d2.is_empty(), "delta must be empty after drain");
        let full: std::collections::HashMap<BlockHash, Vec<u8>> =
            r.export_all().into_iter().collect();
        // Every current block's delta-record equals its full-export record.
        for (h, rec) in &full {
            assert_eq!(disk.remove(h).as_ref(), Some(rec), "record mismatch");
        }
        assert!(disk.is_empty(), "delta had records for unknown blocks");
    }
}
