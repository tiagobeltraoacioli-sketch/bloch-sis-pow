//! Coherence shielded-pool primitives — the lean, portable core.
//!
//! Single source of truth shared by the node (`bloch::coherence` re-exports
//! this), the SP1 guest prover (`crates/coherence-prover`), and the mobile
//! wallet. Implements the C1-frozen formats (`docs/specs/COHERENCE-C1.md`):
//! SHAKE-256 note commitments, hash-derived nullifiers, a SHAKE-256 incremental
//! Merkle accumulator, and `check_spend` — the exact statement the ZK circuit
//! proves. No node/std-heavy dependencies, so it compiles for the zkVM target.

use serde::{Serialize, Deserialize};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

pub const TREE_DEPTH: usize = 32;

const DOM_CM: &[u8] = b"bloch:coherence:cm:v1";
const DOM_NF: &[u8] = b"bloch:coherence:nf:v1";
const DOM_MT: &[u8] = b"bloch:coherence:mt:v1";

/// SHAKE-256 squeezed to 32 bytes over the concatenation of `parts`.
fn shake256_32(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Shake256::default();
    for p in parts { h.update(p); }
    let mut xof = h.finalize_xof();
    let mut out = [0u8; 32];
    xof.read(&mut out);
    out
}

// ── Notes ────────────────────────────────────────────────────────────────────

/// A shielded note (private).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub v: u64,
    pub pk_d: [u8; 32],
    pub rho: [u8; 32],
    pub psi: [u8; 32],
}

impl Note {
    /// cm = SHAKE256(DOM_CM ‖ v ‖ pk_d ‖ rho ‖ psi).
    pub fn commitment(&self) -> [u8; 32] {
        shake256_32(&[DOM_CM, &self.v.to_le_bytes(), &self.pk_d, &self.rho, &self.psi])
    }
    /// Nullifier at `position` under nullifier key `nk`.
    pub fn nullifier(&self, nk: &[u8; 32], position: u64) -> [u8; 32] {
        shake256_32(&[DOM_NF, nk, &self.rho, &position.to_le_bytes()])
    }
}

fn merkle_parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    shake256_32(&[DOM_MT, left, right])
}

// ── Commitment tree (incremental, fixed depth, SHAKE-256) ─────────────────────

/// Append-only Merkle accumulator of note commitments; the root is the anchor.
#[derive(Debug, Clone, Default)]
pub struct CommitmentTree {
    leaves: Vec<[u8; 32]>,
}

impl CommitmentTree {
    pub fn new() -> Self { Self { leaves: Vec::new() } }

    pub fn append(&mut self, cm: [u8; 32]) -> u64 {
        let pos = self.leaves.len() as u64;
        self.leaves.push(cm);
        pos
    }

    /// Number of appended leaves (commitments).
    pub fn len(&self) -> usize { self.leaves.len() }
    pub fn is_empty(&self) -> bool { self.leaves.is_empty() }

    /// Drop leaves back to the first `n` (reorg undo). The root recomputes from
    /// the remaining leaves; truncating to a prior length restores the exact
    /// earlier root (append-only tree over a `Vec`).
    pub fn truncate(&mut self, n: usize) { self.leaves.truncate(n); }

    fn empty_roots() -> [[u8; 32]; TREE_DEPTH + 1] {
        let mut e = [[0u8; 32]; TREE_DEPTH + 1];
        e[0] = shake256_32(&[DOM_MT, b"empty-leaf"]);
        for d in 1..=TREE_DEPTH {
            e[d] = merkle_parent(&e[d - 1], &e[d - 1]);
        }
        e
    }

    pub fn root(&self) -> [u8; 32] {
        let empty = Self::empty_roots();
        let mut level: Vec<[u8; 32]> = self.leaves.clone();
        for d in 0..TREE_DEPTH {
            let mut next = Vec::with_capacity((level.len() + 1) / 2);
            let mut i = 0;
            while i < level.len() {
                let l = level[i];
                let r = if i + 1 < level.len() { level[i + 1] } else { empty[d] };
                next.push(merkle_parent(&l, &r));
                i += 2;
            }
            if next.is_empty() { next.push(empty[d + 1]); }
            level = next;
        }
        level[0]
    }

    pub fn path(&self, index: u64) -> Option<Vec<[u8; 32]>> {
        if index as usize >= self.leaves.len() { return None; }
        let empty = Self::empty_roots();
        let mut idx = index as usize;
        let mut level: Vec<[u8; 32]> = self.leaves.clone();
        let mut path = Vec::with_capacity(TREE_DEPTH);
        for d in 0..TREE_DEPTH {
            let sib = idx ^ 1;
            let s = if sib < level.len() { level[sib] } else { empty[d] };
            path.push(s);
            let mut next = Vec::with_capacity((level.len() + 1) / 2);
            let mut i = 0;
            while i < level.len() {
                let l = level[i];
                let r = if i + 1 < level.len() { level[i + 1] } else { empty[d] };
                next.push(merkle_parent(&l, &r));
                i += 2;
            }
            if next.is_empty() { next.push(empty[d + 1]); }
            level = next;
            idx /= 2;
        }
        Some(path)
    }
}

/// Verify a Merkle path: fold `leaf` up with `path` and compare to `root`.
pub fn verify_path(leaf: &[u8; 32], index: u64, path: &[[u8; 32]], root: &[u8; 32]) -> bool {
    if path.len() != TREE_DEPTH { return false; }
    let mut cur = *leaf;
    let mut idx = index;
    for sib in path {
        cur = if idx & 1 == 0 { merkle_parent(&cur, sib) } else { merkle_parent(sib, &cur) };
        idx >>= 1;
    }
    &cur == root
}

// ── Spend statement (the SP1 guest logic; proved in ZK) ───────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendPublic {
    pub anchor: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub out_commitments: Vec<[u8; 32]>,
    pub fee: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendInput {
    pub note: Note,
    pub position: u64,
    pub path: Vec<[u8; 32]>,
    pub nk: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendWitness {
    pub inputs: Vec<SpendInput>,
    pub outputs: Vec<Note>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendError {
    Membership(usize),
    Nullifier(usize),
    OutputCommitment(usize),
    Overflow,
    Unbalanced { inputs: u128, outputs: u128, fee: u64 },
}

/// The EXACT statement the ZK circuit proves (runs on the PRIVATE witness).
pub fn check_spend(public: &SpendPublic, w: &SpendWitness) -> Result<(), SpendError> {
    let mut in_sum: u128 = 0;
    for (i, inp) in w.inputs.iter().enumerate() {
        let cm = inp.note.commitment();
        if !verify_path(&cm, inp.position, &inp.path, &public.anchor) {
            return Err(SpendError::Membership(i));
        }
        let nf = inp.note.nullifier(&inp.nk, inp.position);
        if public.nullifiers.get(i) != Some(&nf) {
            return Err(SpendError::Nullifier(i));
        }
        in_sum = in_sum.checked_add(inp.note.v as u128).ok_or(SpendError::Overflow)?;
    }
    let mut out_sum: u128 = 0;
    for (i, out) in w.outputs.iter().enumerate() {
        if public.out_commitments.get(i) != Some(&out.commitment()) {
            return Err(SpendError::OutputCommitment(i));
        }
        out_sum = out_sum.checked_add(out.v as u128).ok_or(SpendError::Overflow)?;
    }
    if in_sum != out_sum + public.fee as u128 {
        return Err(SpendError::Unbalanced { inputs: in_sum, outputs: out_sum, fee: public.fee });
    }
    Ok(())
}

// ── Shielded transaction (wire type) ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldedTx {
    pub anchor: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub outputs: Vec<[u8; 32]>,
    pub fee: u64,
    pub proof: Vec<u8>,
    pub binding_sig: Vec<u8>,
}

impl ShieldedTx {
    pub fn public(&self) -> SpendPublic {
        SpendPublic {
            anchor: self.anchor,
            nullifiers: self.nullifiers.clone(),
            out_commitments: self.outputs.clone(),
            fee: self.fee,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(v: u64, tag: u8) -> Note {
        Note { v, pk_d: [tag; 32], rho: [tag ^ 0x11; 32], psi: [tag ^ 0x22; 32] }
    }

    #[test]
    fn commitment_and_nullifier_are_deterministic_and_distinct() {
        let n = note(100, 1);
        assert_eq!(n.commitment(), n.commitment());
        assert_ne!(n.commitment(), n.nullifier(&[9; 32], 0));
        assert_ne!(n.nullifier(&[9; 32], 0), n.nullifier(&[9; 32], 1));
    }

    #[test]
    fn merkle_membership_roundtrips() {
        let mut t = CommitmentTree::new();
        let cms: Vec<_> = (0..5u8).map(|i| note(i as u64, i).commitment()).collect();
        for cm in &cms { t.append(*cm); }
        let root = t.root();
        for (i, cm) in cms.iter().enumerate() {
            let path = t.path(i as u64).unwrap();
            assert!(verify_path(cm, i as u64, &path, &root));
        }
        assert!(!verify_path(&[0xAB; 32], 0, &t.path(0).unwrap(), &root));
    }

    #[test]
    fn check_spend_accepts_valid_and_rejects_inflation_and_forgery() {
        let mut t = CommitmentTree::new();
        let inp = note(1000, 7);
        let pos = t.append(inp.commitment());
        let anchor = t.root();
        let path = t.path(pos).unwrap();
        let nk = [3u8; 32];

        let out = note(900, 8);
        let public = SpendPublic {
            anchor, nullifiers: vec![inp.nullifier(&nk, pos)],
            out_commitments: vec![out.commitment()], fee: 100,
        };
        let w = SpendWitness {
            inputs: vec![SpendInput { note: inp.clone(), position: pos, path: path.clone(), nk }],
            outputs: vec![out],
        };
        assert_eq!(check_spend(&public, &w), Ok(()));

        // inflation
        let big = note(5000, 8);
        let pub2 = SpendPublic {
            anchor, nullifiers: vec![inp.nullifier(&nk, pos)],
            out_commitments: vec![big.commitment()], fee: 0,
        };
        let w2 = SpendWitness {
            inputs: vec![SpendInput { note: inp.clone(), position: pos, path: path.clone(), nk }],
            outputs: vec![big],
        };
        assert!(matches!(check_spend(&pub2, &w2), Err(SpendError::Unbalanced { .. })));

        // forged membership
        let bad = SpendPublic { anchor: [0xCD; 32], ..public.clone() };
        assert!(matches!(check_spend(&bad, &w), Err(SpendError::Membership(0))));
    }
}
