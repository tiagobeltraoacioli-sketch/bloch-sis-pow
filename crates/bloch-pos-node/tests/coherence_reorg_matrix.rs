// SPDX-License-Identifier: AGPL-3.0-or-later

//! DEV-15, Coherence wave — the G11 reorg matrix
//! (`docs/specs/COHERENCE-G11-SHADOW-FORKS.md`).
//!
//! Two layers, matching where each rule actually lives on this branch:
//!
//! **Pool layer** (the C1-frozen `coherence-core` primitives, which are what
//! the wave wires into the node): connect + disconnect + reconnect of a
//! block carrying a shielded transaction must return the accumulator root,
//! the nullifier-set root, the leaf count and the pool balance
//! **byte-identical** — in both directions, including a fork switch and the
//! witness/non-membership continuity Fork C demands. The disconnect
//! discipline under test is the one the primitives were designed for:
//! `CommitmentTree::truncate` to the pre-block leaf count and
//! `NullifierSet::remove` of exactly the block's recorded nullifiers.
//!
//! **Consensus floor**: the rule this network's own recorded violation makes
//! non-negotiable (the finality-rewind incident: nodes re-finalizing below
//! their own finalized checkpoint) — a reorg attempting to descend below the
//! finalized checkpoint must be REFUSED:
//!   - at the transition: a header contradicting parent-committed finality
//!     is a deterministic `FinalityRegression`;
//!   - at fork choice: the head walk STARTS at the justified checkpoint, so
//!     a branch that forked below it is structurally unelectable no matter
//!     how much stake votes for it.
//!
//! The engine's own reorg path (`Engine::do_reorg`, `FcStore` ratchets) is a
//! binary-crate internal `tests/` cannot reach; these two layers are the
//! consensus floor it composes, and `coherence_crash_consistency.rs` drives
//! the binary end to end.

mod coherence_harness;

use coherence_core::{
    check_spend, verify_non_membership, verify_path, CommitmentTree, Note, NullifierSet,
    SpendInput, SpendPublic, SpendWitness, NFSET_DEPTH,
};
use coherence_harness as h;

// ── Pool layer ──────────────────────────────────────────────────────────────

/// Everything a snapshot must pin, byte for byte. `PartialEq + Debug` so one
/// `assert_eq!` compares the whole pool identity and prints the divergence.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PoolSnapshot {
    accumulator_root: [u8; 32],
    nullifier_root: [u8; 32],
    leaf_count: usize,
    nullifier_count: usize,
    /// Sum of unspent note values — "saldo" in the gate text. Tracked by the
    /// harness (the pool itself is value-blind by design); byte-identical
    /// here means the u128 is equal, which is the same claim.
    balance: u128,
}

/// The pool plus the balance ledger the harness keeps beside it.
struct Pool {
    tree: CommitmentTree,
    nfs: NullifierSet,
    balance: u128,
}

impl Pool {
    fn new() -> Self {
        Pool { tree: CommitmentTree::new(), nfs: NullifierSet::new(), balance: 0 }
    }

    fn snapshot(&self) -> PoolSnapshot {
        PoolSnapshot {
            accumulator_root: self.tree.root(),
            nullifier_root: self.nfs.root(),
            leaf_count: self.tree.len(),
            nullifier_count: self.nfs.len(),
            balance: self.balance,
        }
    }
}

/// One block's shielded effects, with everything needed to UNDO it — the
/// journal a node-side pool must persist (or re-derive) for its reorg path.
struct PoolBlock {
    /// Notes shielded (appended) by this block, in body order.
    shields: Vec<Note>,
    /// Spends: (note, its consensus position, the spender's nk). The
    /// nullifier is DERIVED at apply time from `LE64(position)` — never
    /// carried — because that binding is exactly what crash/reorg can break.
    spends: Vec<(Note, u64, [u8; 32])>,
}

/// Journal entry produced by [`connect`], consumed by [`disconnect`].
struct Undo {
    leaves_before: usize,
    nfs_added: Vec<[u8; 32]>,
    balance_before: u128,
}

fn connect(pool: &mut Pool, block: &PoolBlock) -> Undo {
    let undo = Undo {
        leaves_before: pool.tree.len(),
        nfs_added: Vec::new(),
        balance_before: pool.balance,
    };
    let mut undo = undo;
    for (note, position, nk) in &block.spends {
        let nf = note.nullifier(nk, *position);
        assert!(pool.nfs.insert(nf), "double spend inside the fixture");
        undo.nfs_added.push(nf);
        pool.balance -= note.v as u128;
    }
    for (i, note) in block.shields.iter().enumerate() {
        let pos = pool.tree.append(note.commitment());
        // The position law: a new leaf's position is EXACTLY the leaf count
        // before the append. The nullifier binds LE64(position), so this is
        // not bookkeeping — it is consensus.
        assert_eq!(
            pos as usize,
            undo.leaves_before + i,
            "append did not hand out the next position"
        );
        pool.balance += note.v as u128;
    }
    undo
}

fn disconnect(pool: &mut Pool, undo: &Undo) {
    pool.tree.truncate(undo.leaves_before);
    for nf in &undo.nfs_added {
        assert!(pool.nfs.remove(nf), "undoing a nullifier the block never added");
    }
    pool.balance = undo.balance_before;
}

fn note(v: u64, tag: u8) -> Note {
    Note { v, pk_d: [tag; 32], rho: [tag ^ 0x11; 32], psi: [tag ^ 0x22; 32] }
}

/// The G11 core: connect + disconnect + reconnect of a block with a shielded
/// transaction returns accumulator, nullifier set and balance byte-identical
/// — and the reconnect re-derives the SAME nullifier, because the position
/// re-assigned is the same position.
#[test]
fn connect_disconnect_reconnect_is_byte_identical() {
    let nk = [3u8; 32];
    let n0 = note(1_000, 1);
    let n1 = note(500, 2);
    let change_b2 = note(450, 3);
    let change_b3 = note(990, 4);

    let mut pool = Pool::new();

    // B1: shield n0, n1 → positions 0, 1.
    let b1 = PoolBlock { shields: vec![n0.clone(), n1.clone()], spends: vec![] };
    let _u1 = connect(&mut pool, &b1);
    assert_eq!(pool.tree.len(), 2);

    // B2: the shielded transaction — spend n1 (position 1), shield change.
    let b2 = PoolBlock {
        shields: vec![change_b2.clone()],
        spends: vec![(n1.clone(), 1, nk)],
    };
    let u2 = connect(&mut pool, &b2);
    let s2 = pool.snapshot();
    assert_eq!(s2.leaf_count, 3);
    assert_eq!(s2.nullifier_count, 1);
    assert_eq!(s2.balance, 1_000 + 450);

    // The pre-B3 witness for n0, as of the S2 anchor — §6.6.1's "witness
    // computed under the old tree".
    let n0_path_at_s2 = pool.tree.path(0).expect("n0 is in the tree");
    assert!(verify_path(&n0.commitment(), 0, &n0_path_at_s2, &s2.accumulator_root));

    // B3: spend n0, shield change → the block the reorg exercises.
    let b3 = PoolBlock {
        shields: vec![change_b3.clone()],
        spends: vec![(n0.clone(), 0, nk)],
    };
    let u3 = connect(&mut pool, &b3);
    let s3 = pool.snapshot();
    let nf0_first_connect = n0.nullifier(&nk, 0);
    assert!(pool.nfs.contains(&nf0_first_connect));

    // DISCONNECT B3: every component byte-identical to S2. `assert_eq!` on
    // the snapshot struct compares the raw 32-byte roots — this is the
    // byte-identity claim, not an "equivalent state" claim.
    disconnect(&mut pool, &u3);
    assert_eq!(pool.snapshot(), s2, "disconnect did not restore the exact pool");

    // The old witness still verifies against the restored anchor, and the
    // whole spend statement still checks — the note is spendable again.
    assert!(verify_path(&n0.commitment(), 0, &pool.tree.path(0).unwrap(), &s2.accumulator_root));
    let public = SpendPublic {
        anchor: s2.accumulator_root,
        nullifiers: vec![n0.nullifier(&nk, 0)],
        out_commitments: vec![change_b3.commitment()],
        fee: 10,
    };
    let witness = SpendWitness {
        inputs: vec![SpendInput {
            note: n0.clone(),
            position: 0,
            path: n0_path_at_s2.clone(),
            nk,
        }],
        outputs: vec![change_b3.clone()],
    };
    assert_eq!(check_spend(&public, &witness), Ok(()));

    // RECONNECT B3: byte-identical to the first connect, including the
    // re-derived nullifier — same note, same nk, same LE64(position).
    let u3_again = connect(&mut pool, &b3);
    assert_eq!(pool.snapshot(), s3, "reconnect did not reproduce the exact pool");
    assert_eq!(u3_again.nfs_added, vec![nf0_first_connect], "the nullifier moved on reconnect");

    // And a second, DEEPER cycle, because one round can pass by luck of
    // symmetric bugs: disconnect B3 and B2 both, then reconnect both.
    disconnect(&mut pool, &u3_again);
    assert_eq!(pool.snapshot(), s2);
    disconnect(&mut pool, &u2);
    assert_eq!(pool.tree.len(), 2, "the depth-2 disconnect lost a leaf");
    assert_eq!(pool.nfs.len(), 0, "the depth-2 disconnect left a nullifier");
    assert_eq!(pool.balance, 1_500);
    let _u2b = connect(&mut pool, &b2);
    assert_eq!(pool.snapshot(), s2);
    let _u3b = connect(&mut pool, &b3);
    assert_eq!(pool.snapshot(), s3);
}

/// Fork switch: connect A, switch to fork B (disconnect A, connect B1+B2),
/// switch back — every stop pinned byte for byte. This is the "shadow fork"
/// shape: two branches spending different notes at the same height.
#[test]
fn a_fork_switch_and_return_restores_every_root_byte_for_byte() {
    let nk = [7u8; 32];
    let n0 = note(2_000, 10);
    let n1 = note(3_000, 11);

    let mut pool = Pool::new();
    let base = PoolBlock { shields: vec![n0.clone(), n1.clone()], spends: vec![] };
    let _ub = connect(&mut pool, &base);
    let s_base = pool.snapshot();

    // Branch A: spend n0.
    let block_a = PoolBlock {
        shields: vec![note(1_990, 12)],
        spends: vec![(n0.clone(), 0, nk)],
    };
    // Branch B: spend n1, then shield another note on top.
    let block_b1 = PoolBlock {
        shields: vec![note(2_990, 13)],
        spends: vec![(n1.clone(), 1, nk)],
    };
    let block_b2 = PoolBlock { shields: vec![note(40, 14)], spends: vec![] };

    let ua = connect(&mut pool, &block_a);
    let s_a = pool.snapshot();

    // Reorg to B: disconnect A, connect B1 + B2.
    disconnect(&mut pool, &ua);
    assert_eq!(pool.snapshot(), s_base, "leaving branch A did not restore the base");
    let ub1 = connect(&mut pool, &block_b1);
    let ub2 = connect(&mut pool, &block_b2);
    let s_b = pool.snapshot();
    assert_ne!(s_b, s_a, "the two branches commit identically — vacuous fixture");

    // Reorg back to A: disconnect B2 + B1 (reverse order), reconnect A.
    disconnect(&mut pool, &ub2);
    disconnect(&mut pool, &ub1);
    assert_eq!(pool.snapshot(), s_base, "leaving branch B did not restore the base");
    let _ua2 = connect(&mut pool, &block_a);
    assert_eq!(pool.snapshot(), s_a, "returning to branch A did not reproduce it");
}

/// Fork C's non-membership case: a non-membership proof taken at the
/// pre-reorg anchor keeps verifying after disconnect+reconnect of an
/// unrelated block, and DIES the moment the nullifier is actually spent.
#[test]
fn non_membership_survives_the_reorg_and_dies_on_the_spend() {
    let nk = [9u8; 32];
    let n0 = note(100, 20);
    let n1 = note(200, 21);
    let mut pool = Pool::new();
    let base = PoolBlock { shields: vec![n0.clone(), n1.clone()], spends: vec![] };
    let _ = connect(&mut pool, &base);

    let nf0 = n0.nullifier(&nk, 0);
    let proof = pool.nfs.non_membership_proof(&nf0).expect("nf0 unspent");
    assert_eq!(proof.len(), NFSET_DEPTH);
    let root_before = pool.nfs.root();
    assert!(verify_non_membership(&nf0, &proof, &root_before));

    // An unrelated spend connects and disconnects; the restored root must
    // accept the SAME proof bytes — root-of-the-set, not root-of-the-history.
    let other = PoolBlock { shields: vec![], spends: vec![(n1.clone(), 1, nk)] };
    let u = connect(&mut pool, &other);
    assert!(
        !verify_non_membership(&nf0, &proof, &pool.nfs.root()),
        "a proof anchored at the old root verified against the new root"
    );
    disconnect(&mut pool, &u);
    assert_eq!(pool.nfs.root(), root_before);
    assert!(verify_non_membership(&nf0, &proof, &pool.nfs.root()));

    // Now spend n0 for real: no fresh proof exists, and the old proof fails
    // against the new root — the replay-rejection lookup, provable form.
    let spend = PoolBlock { shields: vec![], spends: vec![(n0.clone(), 0, nk)] };
    let _ = connect(&mut pool, &spend);
    assert!(pool.nfs.non_membership_proof(&nf0).is_none());
    assert!(!verify_non_membership(&nf0, &proof, &pool.nfs.root()));
}

// ── Consensus floor: no reorg below finality ────────────────────────────────

use bloch_pos_committee::forkchoice::{BlockTree, LatestMessage, Store as FcStore};
use bloch_pos_committee::interfaces::{StateTransition, TransitionError};

/// The transition half: a header contradicting the parent's committed
/// finality is a deterministic, named refusal — "a block may never
/// un-finalize anything". This network RECORDED a finality-rewind violation
/// (nodes re-finalizing epochs below their own finalized checkpoint); the
/// transition is the layer where the refusal is a pure function, so it is
/// pinned here with the same determinism discipline as the flag-day rejects.
#[test]
fn a_block_contradicting_committed_finality_is_refused_deterministically() {
    let (t, genesis, mut chains) = h::genesis_fixture(4, &[]);

    for mutation in [0u8, 1u8] {
        let mut env = h::speculative_block(&t, &genesis, 1, &[], &mut chains);
        match mutation {
            0 => env.header.finalized_root = [0xEE; 32],
            _ => env.header.justified_root = [0xDD; 32],
        }
        let first = t.apply_block(&genesis, &env, &[], &[]);
        assert_eq!(
            first,
            Err(TransitionError::FinalityRegression),
            "mutation {mutation}: wrong or missing refusal"
        );
        for _ in 0..3 {
            assert_eq!(t.apply_block(&genesis, &env, &[], &[]), first);
        }
    }
}

/// The fork-choice half: the head walk starts AT the justified checkpoint.
/// A branch that forked off below it is structurally unelectable — even
/// carrying every validator's latest vote and 100× the stake — because no
/// walk from `justified` can reach it. This is the property that makes
/// "reorg below finality" impossible to *select*, complementing the
/// transition's refusal to *apply* one.
#[test]
fn fork_choice_cannot_select_a_branch_that_forks_below_the_justified_checkpoint() {
    use std::collections::HashMap;

    // genesis ── f1 ── f2 (justified) ── c1
    //     └───── x1 ── x2   ← forks BELOW justified, carries all the votes
    let genesis = [0u8; 32];
    let f1 = [1u8; 32];
    let f2 = [2u8; 32];
    let c1 = [3u8; 32];
    let x1 = [0xA1u8; 32];
    let x2 = [0xA2u8; 32];

    let mut parents: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
    parents.insert(f1, genesis);
    parents.insert(f2, f1);
    parents.insert(c1, f2);
    parents.insert(x1, genesis);
    parents.insert(x2, x1);
    let mut children: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();
    children.insert(genesis, vec![f1, x1]);
    children.insert(f1, vec![f2]);
    children.insert(f2, vec![c1]);
    children.insert(x1, vec![x2]);
    let tree = BlockTree { parents: &parents };

    let mut fc = FcStore::new();
    // 99 validators, heavy stake, all voting the sub-justified branch…
    for v in 0..99u32 {
        fc.set_stake(v, 1_000_000);
        assert!(fc.observe(v, LatestMessage { slot: 10, root: x2 }));
    }
    // …one validator, minimal stake, voting the canonical child.
    fc.set_stake(99, 1);
    assert!(fc.observe(99, LatestMessage { slot: 10, root: c1 }));

    // Non-vacuity: the rebel branch really does dominate by raw weight.
    assert!(
        fc.weight(&tree, &x2) > 90 * fc.weight(&tree, &c1),
        "fixture failed to give the sub-justified branch overwhelming weight"
    );

    // And yet: walking from the justified checkpoint can only ever land on
    // a descendant of it.
    let head = fc.head(&tree, f2, &children);
    assert_eq!(
        head, c1,
        "fork choice selected {head:02x?} — a branch below the justified \
         checkpoint became electable, which is the finality-rewind violation \
         this suite exists to keep dead"
    );
}
