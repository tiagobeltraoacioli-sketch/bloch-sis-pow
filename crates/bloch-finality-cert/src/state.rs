// SPDX-License-Identifier: AGPL-3.0-or-later

//! Committed-state leaves `getlcproof` carries and its verifiers read, decoded from their
//! committed bytes and checked against a trusted state root.
//!
//! Nothing here is new consensus data. Every leaf is one the Genesis-4 state
//! root already commits (or will, once the gate that writes it is reached):
//!
//! | leaf | key | from |
//! |---|---|---|
//! | validator record | `state_root::validator_leaf_key(i)` (0x02) | genesis |
//! | finality record, incl. the frozen finality set | `state_root::finality_leaf_key()` (0x09) | set: HF1, e7180 |
//! | KES entry | `state_root::kes_leaf_key(i)` (0x22) | HF3 registration, e7360 |
//! | KES bind epoch | `state_root::kes_enforced_leaf_key()` (0x22) | KES bind, >= e8620 |
//!
//! Decoders are strict (exact lengths, no trailing bytes); they never decide
//! anything on their own: a leaf is only used after [`prove_leaf`] has
//! matched its bytes to the root.

use crate::CompressedProof;
use bloch_pos_committee::kes::{KesEntry, KesPublic, RetiredKes, MAX_DEPTH};
use bloch_pos_committee::state_root::{empty_subtree_hashes, leaf_value_hash, verify_absence, verify_inclusion};
use std::collections::BTreeMap;

/// Leaf `bytes` is committed under `key` in `state_root`.
pub fn prove_leaf(state_root: &[u8; 32], key: &[u8; 32], bytes: &[u8], proof: &CompressedProof) -> bool {
    let empty = empty_subtree_hashes();
    match proof.expand(&empty) {
        Some(p) => verify_inclusion(state_root, key, &leaf_value_hash(bytes), &p),
        None => false,
    }
}

/// Nothing is committed under `key` in `state_root`.
pub fn prove_absent(state_root: &[u8; 32], key: &[u8; 32], proof: &CompressedProof) -> bool {
    let empty = empty_subtree_hashes();
    match proof.expand(&empty) {
        Some(p) => verify_absence(state_root, key, &p),
        None => false,
    }
}

struct Cursor<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cursor { b, at: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let out = self.b.get(self.at..end)?;
        self.at = end;
        Some(out)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn h32(&mut self) -> Option<[u8; 32]> {
        self.take(32)?.try_into().ok()
    }
    fn rest(&self) -> &'a [u8] {
        &self.b[self.at..]
    }
    fn done(&self) -> bool {
        self.at == self.b.len()
    }
    /// A `u64` count of `item`-byte entries that fits in what is left.
    fn count(&mut self, item: usize) -> Option<usize> {
        let n = usize::try_from(self.u64()?).ok()?;
        (n <= (self.b.len() - self.at) / item).then_some(n)
    }
}

/// A checkpoint as the finality leaf commits it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointLeaf {
    pub epoch: u64,
    pub root: [u8; 32],
}

/// A frozen finality set (`finality::FinalitySet`): epoch and member stakes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenSet {
    pub epoch: u64,
    pub members: BTreeMap<u32, u64>,
}

impl FrozenSet {
    pub fn total(&self) -> u128 {
        self.members.values().map(|s| *s as u128).sum()
    }
    pub fn weight(&self, validator: u32) -> u64 {
        self.members.get(&validator).copied().unwrap_or(0)
    }
}

/// The HF1 extension of the finality leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalitySetLeaf {
    pub current: FrozenSet,
    pub pending: Option<FrozenSet>,
    pub last_seen: BTreeMap<u32, u64>,
}

/// `state_root::FinalityRecord`, decoded from its committed bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalityLeaf {
    pub justified: Vec<CheckpointLeaf>,
    pub current_justified: CheckpointLeaf,
    pub previous_justified: CheckpointLeaf,
    pub finalized: CheckpointLeaf,
    pub leaked: Vec<(u32, u64)>,
    pub next_epoch: u64,
    /// `None` below `params::HF1_FROZEN_FINALITY_SET_EPOCH`.
    pub finality_set: Option<FinalitySetLeaf>,
    /// Empty below `params::HF1_OWN_TARGET_VOTES_EPOCH`.
    pub own_checkpoints: Vec<CheckpointLeaf>,
}

/// `state_root::FINALITY_SET_EXTENSION_TAG`.
pub const FINALITY_SET_EXTENSION_TAG: &[u8; 16] = b"BLOCH-FFG-FSETv1";
/// `state_root::OWN_CHECKPOINTS_TAG`.
pub const OWN_CHECKPOINTS_TAG: &[u8] = bloch_pos_committee::state_root::OWN_CHECKPOINTS_TAG;

fn checkpoint(c: &mut Cursor<'_>) -> Option<CheckpointLeaf> {
    Some(CheckpointLeaf { epoch: c.u64()?, root: c.h32()? })
}

fn pairs(c: &mut Cursor<'_>) -> Option<BTreeMap<u32, u64>> {
    let n = c.count(12)?;
    let mut out = BTreeMap::new();
    let mut last = None;
    for _ in 0..n {
        let v = c.u32()?;
        let x = c.u64()?;
        // Committed sorted by validator, one entry each.
        if last.is_some_and(|l| v <= l) {
            return None;
        }
        last = Some(v);
        out.insert(v, x);
    }
    Some(out)
}

impl FinalityLeaf {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(bytes);
        let n = c.count(40)?;
        let mut justified = Vec::with_capacity(n);
        for _ in 0..n {
            justified.push(checkpoint(&mut c)?);
        }
        let current_justified = checkpoint(&mut c)?;
        let previous_justified = checkpoint(&mut c)?;
        let finalized = checkpoint(&mut c)?;
        let nl = c.count(12)?;
        let mut leaked = Vec::with_capacity(nl);
        for _ in 0..nl {
            leaked.push((c.u32()?, c.u64()?));
        }
        let next_epoch = c.u64()?;
        let mut finality_set = None;
        if c.rest().starts_with(FINALITY_SET_EXTENSION_TAG) {
            c.take(FINALITY_SET_EXTENSION_TAG.len())?;
            let epoch = c.u64()?;
            let current = FrozenSet { epoch, members: pairs(&mut c)? };
            let pending = match c.u8()? {
                0 => None,
                1 => {
                    let epoch = c.u64()?;
                    Some(FrozenSet { epoch, members: pairs(&mut c)? })
                }
                _ => return None,
            };
            let last_seen = pairs(&mut c)?;
            finality_set = Some(FinalitySetLeaf { current, pending, last_seen });
        }
        let mut own_checkpoints = Vec::new();
        if c.rest().starts_with(OWN_CHECKPOINTS_TAG) {
            c.take(OWN_CHECKPOINTS_TAG.len())?;
            let n = c.count(40)?;
            if n == 0 {
                // Written only while non-empty.
                return None;
            }
            for _ in 0..n {
                own_checkpoints.push(checkpoint(&mut c)?);
            }
        }
        c.done().then_some(FinalityLeaf {
            justified,
            current_justified,
            previous_justified,
            finalized,
            leaked,
            next_epoch,
            finality_set,
            own_checkpoints,
        })
    }
}

fn kes_public(c: &mut Cursor<'_>) -> Option<KesPublic> {
    let depth = c.u8()?;
    if depth > MAX_DEPTH {
        return None;
    }
    Some(KesPublic { depth, root: c.h32()?, start_period: c.u64()? })
}

/// `kes::KesEntry` from its committed bytes (component 0x22 value):
/// `key ‖ [successor] ‖ [0xFF ‖ u32 n ‖ n × (key ‖ u64 end_period)]`.
pub fn decode_kes_entry(bytes: &[u8]) -> Option<KesEntry> {
    let mut c = Cursor::new(bytes);
    let current = kes_public(&mut c)?;
    let mut next = None;
    if !c.done() && c.rest()[0] != 0xFF {
        next = Some(kes_public(&mut c)?);
    }
    let mut retired = Vec::new();
    if !c.done() {
        if c.u8()? != 0xFF {
            return None;
        }
        let n = c.u32()? as usize;
        if n == 0 || n > c.rest().len() / 49 {
            return None;
        }
        for _ in 0..n {
            let public = kes_public(&mut c)?;
            retired.push(RetiredKes { public, end_period: c.u64()? });
        }
    }
    let entry = KesEntry { current, next, retired };
    // Exactly the bytes this entry commits: the encoding is canonical.
    (c.done() && entry.committed_bytes() == bytes).then_some(entry)
}
