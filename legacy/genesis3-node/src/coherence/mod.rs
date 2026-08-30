//! Coherence — shielded pool (node integration).
//!
//! The pure primitives — notes, SHAKE-256 commitments/nullifiers, the Merkle
//! accumulator, and `check_spend` (the exact statement the ZK circuit proves) —
//! live in the lean `coherence-core` crate, shared as the single source of truth
//! by the node, the SP1 guest prover (`crates/coherence-prover`), and the mobile
//! wallet. This module re-exports them and adds the node-only consensus state
//! (anchor history + nullifier set) — kept here because it uses std collections
//! and is never part of the zkVM guest.
//!
//! Zero-security testnet: no privacy claim until audited (Coherence C4).

pub use coherence_core::*;

pub mod verifier;
pub use verifier::ShieldedVerifier;

use std::collections::{HashSet, VecDeque};

/// How many recent commitment-tree roots are accepted as spend anchors.
pub const ANCHOR_HISTORY: usize = 100;

/// The shielded-pool state a node maintains and validates against.
#[derive(Debug, Default, Clone)]
pub struct ShieldedState {
    anchors: VecDeque<[u8; 32]>,
    spent_nullifiers: HashSet<[u8; 32]>,
}

/// Why a shielded tx is rejected at the consensus layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxError {
    UnknownAnchor,
    DuplicateNullifierInTx([u8; 32]),
    DoubleSpend([u8; 32]),
    /// output_ciphertexts is not one well-formed NoteCiphertext per output
    /// commitment (index-aligned). Without this structural precondition a
    /// block could carry outputs whose recipients can never discover them.
    MalformedCiphertexts,
    ProofInvalid,
    /// Reorg wants to disconnect a block older than the bounded undo horizon —
    /// the caller must rebuild the shielded state from the canonical chain.
    ReorgBeyondUndoHorizon,
    /// Disconnect was asked to undo a block that is NOT the top of the undo
    /// stack (audit: apply happens in arrival order across branches, so a bare
    /// LIFO pop could undo the wrong block). We refuse and demand a resync
    /// rather than silently corrupt the shielded state. `{expected}` vs the
    /// actual top block id.
    ReorgOrderMismatch { expected: [u8; 32], found: [u8; 32] },
}

/// How many recently-applied blocks can be undone on a reorg before a full
/// shielded-state resync is required. Bounds the undo memory.
pub const MAX_REORG_UNDO: usize = 128;

/// Everything needed to exactly reverse one applied block's effect on the
/// shielded state (reorg undo). Cheap: a length + the block's nullifiers + a
/// clone of the bounded anchor window (never the whole commitment tree).
#[derive(Debug, Clone)]
struct BlockUndo {
    /// The block whose effect this record reverses — checked on disconnect so a
    /// LIFO pop can never silently undo the wrong block.
    block_id: [u8; 32],
    tree_len: usize,
    nullifiers: Vec<[u8; 32]>,
    anchors: VecDeque<[u8; 32]>,
}

impl ShieldedState {
    pub fn new() -> Self { Self::default() }

    /// Record a new tree root as an acceptable anchor (bounded history).
    pub fn record_anchor(&mut self, root: [u8; 32]) {
        if self.anchors.contains(&root) { return; }
        self.anchors.push_back(root);
        while self.anchors.len() > ANCHOR_HISTORY { self.anchors.pop_front(); }
    }

    pub fn knows_anchor(&self, a: &[u8; 32]) -> bool { self.anchors.contains(a) }
    pub fn is_spent(&self, nf: &[u8; 32]) -> bool { self.spent_nullifiers.contains(nf) }

    /// Validate a shielded tx WITHOUT seeing the witness: the anchor must be
    /// recent, every nullifier unseen (and unique within the tx), and the FRI
    /// proof must verify. `verify_proof` is pluggable — the SP1/FRI verifier, or
    /// a closure in tests.
    pub fn validate<F>(&self, tx: &ShieldedTx, verify_proof: F) -> Result<(), TxError>
    where
        F: Fn(&SpendPublic, &[u8]) -> bool,
    {
        if !self.knows_anchor(&tx.anchor) {
            return Err(TxError::UnknownAnchor);
        }
        // Structural precondition (analogous to check_spend's C2 count binds):
        // exactly one well-formed note ciphertext per output commitment, so
        // every accepted output is discoverable by its recipient.
        if !tx.ciphertexts_well_formed() {
            return Err(TxError::MalformedCiphertexts);
        }
        let mut seen = HashSet::new();
        for nf in &tx.nullifiers {
            if !seen.insert(*nf) {
                return Err(TxError::DuplicateNullifierInTx(*nf));
            }
            if self.spent_nullifiers.contains(nf) {
                return Err(TxError::DoubleSpend(*nf));
            }
        }
        if !verify_proof(&tx.public(), &tx.proof) {
            return Err(TxError::ProofInvalid);
        }
        Ok(())
    }

    /// Apply an already-validated tx: mark its nullifiers spent.
    pub fn apply(&mut self, tx: &ShieldedTx) {
        for nf in &tx.nullifiers { self.spent_nullifiers.insert(*nf); }
    }

    // ── reorg undo helpers ──────────────────────────────────────────────────
    /// Snapshot the bounded anchor window (cheap; ≤ ANCHOR_HISTORY entries).
    fn anchor_snapshot(&self) -> VecDeque<[u8; 32]> { self.anchors.clone() }
    /// Restore the anchor window to a snapshot (exact reversal on reorg).
    fn restore_anchors(&mut self, snap: VecDeque<[u8; 32]>) { self.anchors = snap; }
    /// Un-spend nullifiers when their block is disconnected.
    fn unspend(&mut self, nfs: &[[u8; 32]]) {
        for nf in nfs { self.spent_nullifiers.remove(nf); }
    }
}

/// The shielded pool as the node runs it: the commitment tree (whose root is the
/// current anchor) plus the `ShieldedState` (anchor history + nullifier set).
/// This is the consensus engine a block-acceptance path drives; wiring it into
/// the `Block` wire format + `accept_block` + mempool is the remaining node
/// integration (a block-format change, tracked separately).
#[derive(Debug, Clone)]
pub struct ShieldedEngine {
    tree: CommitmentTree,
    state: ShieldedState,
    /// LIFO reorg-undo, one record per applied block, bounded by MAX_REORG_UNDO.
    undo: Vec<BlockUndo>,
}

impl Default for ShieldedEngine {
    fn default() -> Self { Self::new() }
}

impl ShieldedEngine {
    pub fn new() -> Self {
        let tree = CommitmentTree::new();
        let mut state = ShieldedState::new();
        state.record_anchor(tree.root()); // the empty-tree root is a valid anchor
        Self { tree, state, undo: Vec::new() }
    }

    /// The current anchor (commitment-tree root) new spends should reference.
    pub fn anchor(&self) -> [u8; 32] { self.tree.root() }
    pub fn is_spent(&self, nf: &[u8; 32]) -> bool { self.state.is_spent(nf) }

    /// Validate + apply a block's shielded txs **atomically**: nothing is
    /// committed unless every tx validates against the *accumulating* state
    /// (so an intra-block double-spend fails the whole block). On success the
    /// nullifiers are spent, output commitments appended, and each resulting
    /// root recorded as an anchor. Returns the number of txs applied.
    pub fn apply_block<F>(&mut self, block_id: [u8; 32], txs: &[ShieldedTx], verify_proof: F) -> Result<usize, TxError>
    where
        F: Fn(&SpendPublic, &[u8]) -> bool + Copy,
    {
        let mut tree = self.tree.clone();
        let mut state = self.state.clone();
        for tx in txs {
            state.validate(tx, verify_proof)?;
            state.apply(tx);
            for cm in &tx.outputs { tree.append(*cm); }
            state.record_anchor(tree.root());
        }
        // Atomic success: capture an undo record of the PRE-apply state (keyed to
        // this block's id) so this block can be reversed on a reorg, then commit.
        let undo = BlockUndo {
            block_id,
            tree_len: self.tree.len(),
            nullifiers: txs.iter().flat_map(|t| t.nullifiers.iter().copied()).collect(),
            anchors: self.state.anchor_snapshot(),
        };
        self.tree = tree;
        self.state = state;
        self.undo.push(undo);
        if self.undo.len() > MAX_REORG_UNDO { self.undo.remove(0); }
        Ok(txs.len())
    }

    /// Reverse the most recently applied block (reorg disconnect): truncate the
    /// commitment tree, un-spend that block's nullifiers, and restore the anchor
    /// window — an exact inverse of `apply_block`. `expected` is the block the
    /// caller intends to undo; if it is NOT the top of the undo stack we refuse
    /// with `ReorgOrderMismatch` rather than silently undo the wrong block (the
    /// audit's finding: apply happens in arrival order, so the stack may hold a
    /// side/losing-fork block on top). Errs `ReorgBeyondUndoHorizon` if the stack
    /// is empty — the caller must rebuild from the canonical chain. Disconnect
    /// tip-first.
    pub fn disconnect_block(&mut self, expected: [u8; 32]) -> Result<(), TxError> {
        match self.undo.last() {
            None => return Err(TxError::ReorgBeyondUndoHorizon),
            Some(top) if top.block_id != expected =>
                return Err(TxError::ReorgOrderMismatch { expected, found: top.block_id }),
            Some(_) => {}
        }
        let u = self.undo.pop().expect("checked non-empty above");
        self.tree.truncate(u.tree_len);
        self.state.unspend(&u.nullifiers);
        self.state.restore_anchors(u.anchors);
        Ok(())
    }

    /// How many applied blocks can currently be undone (bounded reorg depth).
    pub fn undo_depth(&self) -> usize { self.undo.len() }

    /// Validate a tx against the current committed state WITHOUT applying it —
    /// same per-tx checks as block acceptance (anchor recent, nullifiers unseen
    /// + unique within the tx, proof verifies). Used for mempool admission.
    pub fn validate_tx<F>(&self, tx: &ShieldedTx, verify_proof: F) -> Result<(), TxError>
    where
        F: Fn(&SpendPublic, &[u8]) -> bool,
    {
        self.state.validate(tx, verify_proof)
    }
}

/// Pending shielded transactions awaiting inclusion in a block. Admission
/// rejects anything the chain would reject (anchor/nullifier/proof) AND anything
/// that conflicts with an already-pending tx (a nullifier claimed twice), so the
/// selected set is internally consistent by construction. Proof verification is
/// pluggable — the SP1/FRI verifier in the node (stubbed to reject until wired),
/// or a closure in tests.
#[derive(Debug, Default, Clone)]
pub struct ShieldedMempool {
    txs: Vec<ShieldedTx>,
    pending_nullifiers: HashSet<[u8; 32]>,
}

impl ShieldedMempool {
    pub fn new() -> Self { Self::default() }
    pub fn len(&self) -> usize { self.txs.len() }
    pub fn is_empty(&self) -> bool { self.txs.is_empty() }

    /// Admit a shielded tx into the pool. Rejects unknown anchor, a nullifier
    /// already spent on-chain OR claimed by a pending tx (mempool double-spend),
    /// a duplicate nullifier within the tx, or a failing proof.
    pub fn admit<F>(&mut self, tx: ShieldedTx, engine: &ShieldedEngine, verify_proof: F)
        -> Result<(), TxError>
    where
        F: Fn(&SpendPublic, &[u8]) -> bool,
    {
        engine.validate_tx(&tx, verify_proof)?;
        for nf in &tx.nullifiers {
            if self.pending_nullifiers.contains(nf) {
                return Err(TxError::DoubleSpend(*nf));
            }
        }
        for nf in &tx.nullifiers { self.pending_nullifiers.insert(*nf); }
        self.txs.push(tx);
        Ok(())
    }

    /// Select up to `max` pending txs for a block (insertion order; internally
    /// conflict-free by construction).
    pub fn select(&self, max: usize) -> Vec<ShieldedTx> {
        self.txs.iter().take(max).cloned().collect()
    }

    /// Drop pending txs whose nullifiers were included on-chain (or otherwise
    /// invalidated), freeing those nullifiers for eviction accounting.
    pub fn remove_included(&mut self, included: &[ShieldedTx]) {
        let mut gone: HashSet<[u8; 32]> = HashSet::new();
        for tx in included {
            for nf in &tx.nullifiers { gone.insert(*nf); }
        }
        let mut kept = Vec::with_capacity(self.txs.len());
        for tx in std::mem::take(&mut self.txs) {
            if tx.nullifiers.iter().any(|nf| gone.contains(nf)) {
                for nf in &tx.nullifiers { self.pending_nullifiers.remove(nf); }
            } else {
                kept.push(tx);
            }
        }
        self.txs = kept;
    }
}

/// The node's shielded pool: the committed `ShieldedEngine` plus the pending
/// `ShieldedMempool`. One unit so block acceptance can apply committed txs AND
/// evict them from the mempool atomically.
#[derive(Debug, Default, Clone)]
pub struct ShieldedPool {
    pub engine: ShieldedEngine,
    pub mempool: ShieldedMempool,
    /// How shielded proofs are verified. Default `RejectAll` (safe); set
    /// `BLOCH_SHIELDED_VERIFY=sp1` (feature `sp1-verify`) to verify FRI proofs.
    pub verifier: ShieldedVerifier,
}

impl ShieldedPool {
    pub fn new() -> Self {
        Self {
            engine: ShieldedEngine::new(),
            mempool: ShieldedMempool::new(),
            verifier: ShieldedVerifier::from_env(),
        }
    }

    /// Apply a block's shielded txs using the pool's configured verifier (no
    /// external closure). This is what the node drives from `accept_block`:
    /// transparent blocks are a no-op; a shielded tx is admitted only if
    /// `self.verifier` accepts its proof (RejectAll until SP1 is wired).
    pub fn apply_block_self(&mut self, block_id: [u8; 32], txs: &[ShieldedTx]) -> Result<usize, TxError> {
        // Disjoint field borrows so the verifier can be read while the engine is
        // mutated.
        let Self { engine, mempool, verifier } = self;
        let n = engine.apply_block(block_id, txs, |p, pf| verifier.verify(p, pf))?;
        mempool.remove_included(txs);
        Ok(n)
    }

    /// Reverse block `expected`'s shielded effect on a reorg (tip-first). The
    /// node's reorg driver calls this for each block it disconnects, mirroring
    /// `apply_block_self` for connects. `expected` guards against undoing the
    /// wrong block (see `ShieldedEngine::disconnect_block`).
    pub fn disconnect_block_self(&mut self, expected: [u8; 32]) -> Result<(), TxError> {
        self.engine.disconnect_block(expected)
    }

    pub fn anchor(&self) -> [u8; 32] { self.engine.anchor() }
    pub fn mempool_len(&self) -> usize { self.mempool.len() }

    /// Admit a tx into the mempool (validated against the committed engine).
    pub fn admit<F>(&mut self, tx: ShieldedTx, verify_proof: F) -> Result<(), TxError>
    where
        F: Fn(&SpendPublic, &[u8]) -> bool,
    {
        self.mempool.admit(tx, &self.engine, verify_proof)
    }

    /// Apply a block's shielded txs to the engine, then evict them from the
    /// mempool. Err (block rejected) if any tx fails; the engine is unchanged on
    /// failure (atomic), and the mempool is only touched on success.
    pub fn apply_block<F>(&mut self, block_id: [u8; 32], txs: &[ShieldedTx], verify_proof: F) -> Result<usize, TxError>
    where
        F: Fn(&SpendPublic, &[u8]) -> bool + Copy,
    {
        let n = self.engine.apply_block(block_id, txs, verify_proof)?;
        self.mempool.remove_included(txs);
        Ok(n)
    }

    /// Select up to `max` pending txs for block construction.
    pub fn select_for_block(&self, max: usize) -> Vec<ShieldedTx> {
        self.mempool.select(max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One structurally well-formed (all-zero) note ciphertext per output —
    /// validate() enforces ciphertexts_well_formed() as a precondition.
    fn dummy_cts(n: usize) -> Vec<NoteCiphertext> {
        (0..n).map(|_| NoteCiphertext {
            kem_ct: vec![0u8; NOTE_KEM_CT_LEN],
            nonce: [0u8; NOTE_AEAD_NONCE_LEN],
            payload: vec![0u8; NOTE_PLAINTEXT_LEN + NOTE_AEAD_TAG_LEN],
        }).collect()
    }

    fn dummy_tx(anchor: [u8; 32], nfs: Vec<[u8; 32]>) -> ShieldedTx {
        ShieldedTx { anchor, nullifiers: nfs, outputs: vec![], output_ciphertexts: vec![], fee: 0, proof: vec![1], binding_sig: vec![] }
    }

    #[test]
    fn shielded_state_accepts_valid_and_rejects_bad() {
        let mut st = ShieldedState::new();
        let anchor = [0x55u8; 32];
        st.record_anchor(anchor);
        let ok = |_p: &SpendPublic, _pf: &[u8]| true;
        let bad = |_p: &SpendPublic, _pf: &[u8]| false;

        let tx = dummy_tx(anchor, vec![[1u8; 32], [2u8; 32]]);
        assert_eq!(st.validate(&tx, ok), Ok(()));
        assert_eq!(st.validate(&dummy_tx([9u8; 32], vec![[3u8; 32]]), ok), Err(TxError::UnknownAnchor));
        assert!(matches!(
            st.validate(&dummy_tx(anchor, vec![[1u8; 32], [1u8; 32]]), ok),
            Err(TxError::DuplicateNullifierInTx(_))));
        assert_eq!(st.validate(&tx, bad), Err(TxError::ProofInvalid));

        st.apply(&tx);
        assert!(matches!(
            st.validate(&dummy_tx(anchor, vec![[1u8; 32]]), ok),
            Err(TxError::DoubleSpend(_))));
    }

    fn tx_with(anchor: [u8; 32], nfs: Vec<[u8; 32]>, outs: Vec<[u8; 32]>) -> ShieldedTx {
        let cts = dummy_cts(outs.len());
        ShieldedTx { anchor, nullifiers: nfs, outputs: outs, output_ciphertexts: cts, fee: 0, proof: vec![1], binding_sig: vec![] }
    }

    #[test]
    fn validate_rejects_missing_or_malformed_output_ciphertexts() {
        let mut st = ShieldedState::new();
        let anchor = [0x66u8; 32];
        st.record_anchor(anchor);
        let ok = |_p: &SpendPublic, _pf: &[u8]| true;

        // One output, zero ciphertexts → recipient could never discover it.
        let mut no_ct = tx_with(anchor, vec![[1u8; 32]], vec![[2u8; 32]]);
        no_ct.output_ciphertexts.clear();
        assert_eq!(st.validate(&no_ct, ok), Err(TxError::MalformedCiphertexts));

        // Wrong-length kem_ct → structurally malformed.
        let mut short = tx_with(anchor, vec![[1u8; 32]], vec![[2u8; 32]]);
        short.output_ciphertexts[0].kem_ct.pop();
        assert_eq!(st.validate(&short, ok), Err(TxError::MalformedCiphertexts));

        // Count-matched, well-formed → passes the structural gate.
        let good = tx_with(anchor, vec![[1u8; 32]], vec![[2u8; 32]]);
        assert_eq!(st.validate(&good, ok), Ok(()));
    }

    #[test]
    fn disconnect_block_exactly_reverses_apply() {
        let ok = |_p: &SpendPublic, _pf: &[u8]| true;
        let mut eng = ShieldedEngine::new();
        let root0 = eng.anchor();
        let id_a = [0xAA; 32];

        // Apply a block: spend a nullifier + append two note commitments.
        eng.apply_block(id_a, &[tx_with(root0, vec![[1u8; 32]], vec![[10u8; 32], [11u8; 32]])], ok).unwrap();
        let a1 = eng.anchor();
        assert_ne!(a1, root0);
        assert!(eng.is_spent(&[1u8; 32]));
        assert_eq!(eng.undo_depth(), 1);

        // Disconnect it → the shielded state returns EXACTLY to genesis.
        eng.disconnect_block(id_a).unwrap();
        assert_eq!(eng.anchor(), root0, "commitment-tree root reverts");
        assert!(!eng.is_spent(&[1u8; 32]), "nullifier is un-spent");
        assert_eq!(eng.undo_depth(), 0);
        // Soundness: the reverted branch's anchor is no longer accepted, so a
        // note that only existed on the reverted branch can't be spent.
        assert_eq!(eng.apply_block([0xBB; 32], &[tx_with(a1, vec![[2u8; 32]], vec![])], ok),
                   Err(TxError::UnknownAnchor));
    }

    #[test]
    fn disconnect_is_lifo_and_bounded() {
        let ok = |_p: &SpendPublic, _pf: &[u8]| true;
        let mut eng = ShieldedEngine::new();
        let r0 = eng.anchor();
        let (id_a, id_b) = ([0xA1; 32], [0xB2; 32]);
        eng.apply_block(id_a, &[tx_with(eng.anchor(), vec![[1u8; 32]], vec![[10u8; 32]])], ok).unwrap();
        let ra = eng.anchor();
        eng.apply_block(id_b, &[tx_with(ra, vec![[2u8; 32]], vec![[20u8; 32]])], ok).unwrap();
        assert_eq!(eng.undo_depth(), 2);

        eng.disconnect_block(id_b).unwrap(); // undo the tip (block B) only
        assert_eq!(eng.anchor(), ra);
        assert!(eng.is_spent(&[1u8; 32]) && !eng.is_spent(&[2u8; 32]));
        eng.disconnect_block(id_a).unwrap(); // undo block A
        assert_eq!(eng.anchor(), r0);
        assert!(!eng.is_spent(&[1u8; 32]));
        // Nothing left → beyond the undo horizon (caller must full-resync).
        assert_eq!(eng.disconnect_block(id_a), Err(TxError::ReorgBeyondUndoHorizon));
    }

    #[test]
    fn disconnect_refuses_wrong_block_order() {
        // AUDIT (Finding 1): apply happens in arrival order across branches, so
        // the undo top may not be the block a reorg wants to undo. Disconnecting
        // the WRONG id must error, not silently corrupt state.
        let ok = |_p: &SpendPublic, _pf: &[u8]| true;
        let mut eng = ShieldedEngine::new();
        let (id_a, id_b) = ([0xA1; 32], [0xB2; 32]);
        eng.apply_block(id_a, &[tx_with(eng.anchor(), vec![[1u8; 32]], vec![[10u8; 32]])], ok).unwrap();
        let anchor_after_a = eng.anchor();
        eng.apply_block(id_b, &[tx_with(eng.anchor(), vec![[2u8; 32]], vec![[20u8; 32]])], ok).unwrap();
        // Ask to undo A while B is on top → refused, state untouched.
        assert!(matches!(eng.disconnect_block(id_a),
                         Err(TxError::ReorgOrderMismatch { .. })));
        assert_eq!(eng.undo_depth(), 2, "nothing was popped");
        assert!(eng.is_spent(&[2u8; 32]), "B's effect is intact");
        // The correct tip-first order still works.
        eng.disconnect_block(id_b).unwrap();
        assert_eq!(eng.anchor(), anchor_after_a);
    }

    #[test]
    fn anchor_history_is_bounded() {
        let mut st = ShieldedState::new();
        for i in 0..(ANCHOR_HISTORY as u32 + 10) {
            let mut a = [0u8; 32];
            a[..4].copy_from_slice(&i.to_le_bytes());
            st.record_anchor(a);
        }
        assert!(!st.knows_anchor(&[0u8; 32]));
        let mut last = [0u8; 32];
        last[..4].copy_from_slice(&(ANCHOR_HISTORY as u32 + 9).to_le_bytes());
        assert!(st.knows_anchor(&last));
    }

    // Proof verification is SP1/FRI in production; the engine tests mock it to
    // exercise the CONSENSUS logic (anchors, nullifiers, tree, atomicity).
    fn tx(anchor: [u8; 32], nfs: Vec<[u8; 32]>, outs: Vec<[u8; 32]>) -> ShieldedTx {
        let cts = dummy_cts(outs.len());
        ShieldedTx { anchor, nullifiers: nfs, outputs: outs, output_ciphertexts: cts, fee: 0, proof: vec![1], binding_sig: vec![] }
    }

    #[test]
    fn engine_applies_shield_then_spend_and_advances_anchor() {
        let mut eng = ShieldedEngine::new();
        let ok = |_p: &SpendPublic, _pf: &[u8]| true;

        let a0 = eng.anchor();
        // Shield: mint one output commitment (no nullifiers), anchored at a0.
        assert_eq!(eng.apply_block([0x01; 32], &[tx(a0, vec![], vec![[0xAA; 32]])], ok), Ok(1));
        let a1 = eng.anchor();
        assert_ne!(a0, a1, "appending a commitment must advance the anchor");

        // Spend: burn a nullifier, anchored at the now-known a1.
        let nf = [0xBB; 32];
        assert_eq!(eng.apply_block([0x02; 32], &[tx(a1, vec![nf], vec![])], ok), Ok(1));
        assert!(eng.is_spent(&nf));
    }

    #[test]
    fn engine_rejects_intra_block_double_spend_atomically() {
        let mut eng = ShieldedEngine::new();
        let ok = |_p: &SpendPublic, _pf: &[u8]| true;
        let a = eng.anchor();
        let nf = [0xCC; 32];
        let before = eng.anchor();
        // Two txs spending the SAME nullifier in one block → whole block rejected.
        let r = eng.apply_block([0x03; 32], &[tx(a, vec![nf], vec![]), tx(a, vec![nf], vec![])], ok);
        assert!(matches!(r, Err(TxError::DoubleSpend(_))));
        // Atomic: nothing was committed.
        assert!(!eng.is_spent(&nf));
        assert_eq!(eng.anchor(), before);
    }

    #[test]
    fn shielded_mempool_admits_and_rejects() {
        let eng = ShieldedEngine::new();
        let a = eng.anchor();
        let ok = |_p: &SpendPublic, _pf: &[u8]| true;
        let bad = |_p: &SpendPublic, _pf: &[u8]| false;
        let mut mp = ShieldedMempool::new();

        // valid admission
        assert_eq!(mp.admit(tx(a, vec![[1u8; 32]], vec![]), &eng, ok), Ok(()));
        assert_eq!(mp.len(), 1);

        // same nullifier already pending → mempool double-spend
        assert!(matches!(
            mp.admit(tx(a, vec![[1u8; 32]], vec![]), &eng, ok),
            Err(TxError::DoubleSpend(_))));
        assert_eq!(mp.len(), 1);

        // unknown anchor + failing proof rejected, pool unchanged
        assert_eq!(mp.admit(tx([9u8; 32], vec![[2u8; 32]], vec![]), &eng, ok), Err(TxError::UnknownAnchor));
        assert_eq!(mp.admit(tx(a, vec![[3u8; 32]], vec![]), &eng, bad), Err(TxError::ProofInvalid));
        assert_eq!(mp.len(), 1);

        // select for a block, then drop once included
        assert_eq!(mp.select(10).len(), 1);
        mp.remove_included(&[tx(a, vec![[1u8; 32]], vec![])]);
        assert!(mp.is_empty());
        // the freed nullifier can be admitted again
        assert_eq!(mp.admit(tx(a, vec![[1u8; 32]], vec![]), &eng, ok), Ok(()));
    }
}
