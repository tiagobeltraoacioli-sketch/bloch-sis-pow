// SPDX-License-Identifier: AGPL-3.0-or-later

//! Checkpoint-sync state snapshots: the canonical byte form of a
//! [`CommittedState`], and the ONLY way back from bytes to a state —
//! [`restore`], which recomputes the state root and refuses the whole
//! artifact on a mismatch.
//!
//! ## What this is for
//!
//! A weak-subjectivity checkpoint (`crate::ws`) pins a finalized
//! `(epoch, block_root, state_root)`. Until now that pin was only a floor and
//! a cross-check: a joining node still replayed every block from genesis to
//! *reach* the state the checkpoint named — ~0.6 s per block at carryover
//! scale, unconditionally, which is why no third party could join. This
//! module makes the checkpoint a **sync starting point**: the committed state
//! at the checkpoint's block travels as bytes, and the checkpoint's 32-byte
//! `state_root` is what makes those bytes trustworthy.
//!
//! ## The trust argument, stated completely
//!
//! The state root commits, leaf by leaf, to every consensus-relevant field of
//! [`CommittedState`] — the inventory is executable
//! (`transition::tests::every_committed_state_field_is_bound_by_the_root`).
//! So a restore that (1) decodes only committed fields from the wire,
//! (2) rebuilds every deliberately-uncommitted field from committed ones or
//! takes it from the caller's own trust anchors, and (3) recomputes the root
//! and compares it to the checkpoint's, accepts **no bit an attacker could
//! choose**. Concretely, the fields NOT decoded from the wire:
//!
//! - `slot` and `head`: header-bound, not root-bound. The caller passes them
//!   from the checkpoint's boundary block header, whose id the signed
//!   checkpoint pins (`block_root = BlockId::of(header)`) and whose
//!   `state_root` field must equal the checkpoint's. [`restore`] enforces the
//!   one committed consistency it can see from inside: `epoch`, which IS
//!   root-bound (the running RANDAO mix is keyed by it), must equal
//!   `epoch_of(head_slot)` — the invariant every transition-produced state
//!   holds.
//! - `genesis_mix`, `genesis_cohort`: chain identity, taken from the caller's
//!   OWN genesis state, never from the wire.
//! - `pubkey_index`: a pure index over the committed registry; rebuilt.
//! - `SlashingState::ejected`: exactly the slashed registry records
//!   (equivalence pinned by `ejected_set_is_exactly_the_slashed_registry`);
//!   rebuilt.
//!
//! One committed field is *narrowed* by the root: the registry commits
//! `stake` as `u64` (saturated from the registry's `u128`, unreachable by
//! supply). The wire therefore refuses any `staked_sat` above `u64::MAX` —
//! bytes the root could not distinguish are bytes this decoder does not
//! accept.
//!
//! ## Why the verification cannot be skipped
//!
//! There is no public decode function. [`restore`] is the only way to turn
//! snapshot bytes into a [`CommittedState`], and the root comparison is
//! inside it, between decode and return; the unverified value never escapes.
//! (The module-private `decode` exists, but `transition`'s privacy makes it
//! unreachable from outside; a future edit that widens it is the regression
//! the module docs here exist to make loud.)
//!
//! ## Canonical form
//!
//! Fixed field order, little-endian, length-prefixed collections, map keys
//! strictly ascending, and a decoder that refuses `encode(x) ‖ junk` — the
//! same discipline as every other byte format in this repo. Canonical matters
//! beyond aesthetics here: any two honest nodes serialising the same state
//! must produce identical bytes, so a chunked download can mix chunks from
//! different peers and still assemble the one artifact the root names.
//! Vector components whose order is chain history (`deposit_history`,
//! `delegations` — the latter positionally committed) are serialised in
//! stored order, which replay makes identical across honest nodes.
//!
//! This byte layout is consensus-adjacent (it is how state crosses node
//! boundaries) and versioned: [`SNAPSHOT_BODY_VERSION`] leads the stream, and
//! a reader refuses versions it does not know.

use std::collections::{BTreeMap, BTreeSet};

use sha3::{Digest, Sha3_256};

use super::{CommittedState, EutxoSet};
use crate::delegation::Delegation;
use crate::finality;
use crate::header::BlockId;
use crate::interfaces::ValidatorRecord;
use crate::slashing::SlashingState;
use crate::staking::QueuedDeposit;
use crate::state_root::{EutxoEntry, EvmCommitment};

/// Version of the snapshot body layout. Bump on ANY change to the byte form.
pub const SNAPSHOT_BODY_VERSION: u16 = 1;

/// What the caller vouches for — everything [`restore`] must not read from
/// the wire. `state_root` comes from the verified weak-subjectivity
/// checkpoint; `head` and `head_slot` from the checkpoint's boundary block
/// header (whose id the checkpoint's `block_root` pins, and whose own
/// `state_root` field the node layer additionally requires to equal the
/// checkpoint's).
#[derive(Clone, Copy, Debug)]
pub struct SnapshotTrust {
    /// The committed state root the restored state must reproduce.
    pub state_root: [u8; 32],
    /// Id of the block whose post-state this snapshot claims to be.
    pub head: BlockId,
    /// That block's slot.
    pub head_slot: u64,
}

/// Why a snapshot was refused. `StateRootMismatch` is the load-bearing one:
/// it means every byte decoded cleanly and the whole is still not the state
/// the checkpoint committed to.
#[derive(Debug, PartialEq, Eq)]
pub enum SnapshotError {
    /// Malformed bytes: truncation, trailing bytes, keys out of order, a
    /// length over cap, an unknown version — with a static reason.
    Decode(&'static str),
    /// The decoded state's recomputed root is not the trusted one.
    StateRootMismatch { expected: [u8; 32], got: [u8; 32] },
    /// The wire epoch does not match `epoch_of(trust.head_slot)` — the state
    /// cannot be the post-state of the block the checkpoint pins.
    EpochSlotMismatch { wire_epoch: u64, head_slot: u64 },
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotError::Decode(m) => write!(f, "snapshot decode error: {m}"),
            SnapshotError::StateRootMismatch { expected, got } => write!(
                f,
                "snapshot REFUSED: recomputed state root {} does not match the checkpoint's {} — \
                 the artifact is not the state the signed checkpoint commits to, whoever served it",
                hex(got),
                hex(expected),
            ),
            SnapshotError::EpochSlotMismatch { wire_epoch, head_slot } => write!(
                f,
                "snapshot REFUSED: wire epoch {wire_epoch} is not epoch_of({head_slot}) — \
                 not the post-state of the checkpoint's boundary block"
            ),
        }
    }
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ───────────────────────────────────────────────────────────────────────────
// Encode
// ───────────────────────────────────────────────────────────────────────────

fn put_u32_len(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&(n as u32).to_le_bytes());
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32_len(out, b.len());
    out.extend_from_slice(b);
}

impl CommittedState {
    /// The canonical snapshot bytes of this state.
    ///
    /// Pure function of the committed fields (plus none of the derived ones —
    /// see the module docs for the exact exclusion list); two honest nodes
    /// holding the same state produce identical bytes.
    pub fn snapshot_serialize(&self) -> Vec<u8> {
        // eUTXO dominates: 76 bytes an entry at carryover scale.
        let mut out = Vec::with_capacity(128 + self.eutxos.entries.len() * 80);
        out.extend_from_slice(&SNAPSHOT_BODY_VERSION.to_le_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.randao_mix);
        put_u32_len(&mut out, self.boundary_mixes.len());
        for (e, m) in &self.boundary_mixes {
            out.extend_from_slice(&e.to_le_bytes());
            out.extend_from_slice(m);
        }
        // Registry. The map key is the record's own index; encode the record
        // only and let the decoder re-key, so the two cannot disagree.
        put_u32_len(&mut out, self.validators.len());
        for v in self.validators.values() {
            out.extend_from_slice(&v.index.to_le_bytes());
            put_bytes(&mut out, &v.pubkey);
            out.extend_from_slice(&v.staked_sat.to_le_bytes());
            out.extend_from_slice(&v.randao_commitment);
            put_bytes(&mut out, &v.withdrawal_credentials);
            out.extend_from_slice(&v.activation_epoch.to_le_bytes());
            out.extend_from_slice(&v.exit_epoch.to_le_bytes());
            out.extend_from_slice(&v.withdrawable_epoch.to_le_bytes());
            out.push(v.slashed as u8);
            out.extend_from_slice(&v.commission_bps.to_le_bytes());
        }
        put_u32_len(&mut out, self.reveals_used.len());
        for (v, n) in &self.reveals_used {
            out.extend_from_slice(&v.to_le_bytes());
            out.extend_from_slice(&n.to_le_bytes());
        }
        // Finality fold state, exactly the components FinalityRecord commits.
        let fin = &self.finality_engine;
        let justified: Vec<finality::Checkpoint> = fin.justified_checkpoints().collect();
        put_u32_len(&mut out, justified.len());
        for cp in &justified {
            out.extend_from_slice(&cp.epoch.to_le_bytes());
            out.extend_from_slice(&cp.root);
        }
        let put_cp = |out: &mut Vec<u8>, epoch: u64, root: &[u8; 32]| {
            out.extend_from_slice(&epoch.to_le_bytes());
            out.extend_from_slice(root);
        };
        let cj = fin.current_justified();
        put_cp(&mut out, cj.epoch, &cj.root);
        let fz = fin.finalized();
        put_cp(&mut out, fz.epoch, &fz.root);
        let leaked: Vec<(u32, u64)> = fin.leaked_stakes().collect();
        put_u32_len(&mut out, leaked.len());
        for (v, s) in &leaked {
            out.extend_from_slice(&v.to_le_bytes());
            out.extend_from_slice(&s.to_le_bytes());
        }
        out.extend_from_slice(&fin.next_epoch().to_le_bytes());
        put_cp(&mut out, self.previous_justified.epoch, &self.previous_justified.root);
        // Pending epoch-boundary votes.
        put_u32_len(&mut out, self.pending_votes.len());
        for ((validator, signing_root), d) in &self.pending_votes {
            out.extend_from_slice(&validator.to_le_bytes());
            out.extend_from_slice(signing_root);
            out.extend_from_slice(&d.slot.to_le_bytes());
            out.extend_from_slice(&d.head);
            out.extend_from_slice(&d.source_epoch.to_le_bytes());
            out.extend_from_slice(&d.source_root);
            out.extend_from_slice(&d.target_epoch.to_le_bytes());
            out.extend_from_slice(&d.target_root);
        }
        // Fork-choice bookkeeping.
        put_u32_len(&mut out, self.latest_messages.len());
        for (v, (slot, root)) in &self.latest_messages {
            out.extend_from_slice(&v.to_le_bytes());
            out.extend_from_slice(&slot.to_le_bytes());
            out.extend_from_slice(root);
        }
        put_u32_len(&mut out, self.fc_equivocators.len());
        for v in &self.fc_equivocators {
            out.extend_from_slice(&v.to_le_bytes());
        }
        // Participation.
        put_u32_len(&mut out, self.current_participation.len());
        for (v, a) in &self.current_participation {
            out.extend_from_slice(&v.to_le_bytes());
            out.push(*a as u8);
        }
        put_u32_len(&mut out, self.previous_participation.len());
        for (v, a) in &self.previous_participation {
            out.extend_from_slice(&v.to_le_bytes());
            out.push(*a as u8);
        }
        // Staking history, in stored (chain) order.
        put_u32_len(&mut out, self.deposit_history.len());
        for d in &self.deposit_history {
            out.extend_from_slice(&d.pubkey_hash);
            out.extend_from_slice(&d.deposit_epoch.to_le_bytes());
            out.extend_from_slice(&d.amount_sat.to_le_bytes());
        }
        // Delegations: positionally committed, so stored order IS the record
        // key — preserved verbatim.
        put_u32_len(&mut out, self.delegations.len());
        for d in &self.delegations {
            out.extend_from_slice(&d.delegator.to_le_bytes());
            out.extend_from_slice(&d.validator.to_le_bytes());
            out.extend_from_slice(&d.amount_sat.to_le_bytes());
            out.extend_from_slice(&d.requested_epoch.to_le_bytes());
            match d.deactivate_epoch {
                Some(e) => {
                    out.push(1);
                    out.extend_from_slice(&e.to_le_bytes());
                }
                None => out.push(0),
            }
            out.push(d.eligible as u8);
        }
        put_u32_len(&mut out, self.pending_fee_rewards.len());
        for (v, amount) in &self.pending_fee_rewards {
            out.extend_from_slice(&v.to_le_bytes());
            out.extend_from_slice(&amount.to_le_bytes());
        }
        // Slashing: the two committed components only (ejected is derived).
        let applied: Vec<[u8; 32]> = self.slashing.applied_ids().copied().collect();
        put_u32_len(&mut out, applied.len());
        for id in &applied {
            out.extend_from_slice(id);
        }
        let window: Vec<(u64, u128)> = self.slashing.window_entries().collect();
        put_u32_len(&mut out, window.len());
        for (e, s) in &window {
            out.extend_from_slice(&e.to_le_bytes());
            out.extend_from_slice(&s.to_le_bytes());
        }
        put_u32_len(&mut out, self.delegator_slash_losses.len());
        for (d, loss) in &self.delegator_slash_losses {
            out.extend_from_slice(&d.to_le_bytes());
            out.extend_from_slice(&loss.to_le_bytes());
        }
        put_u32_len(&mut out, self.delegator_fee_rewards.len());
        for (d, r) in &self.delegator_fee_rewards {
            out.extend_from_slice(&d.to_le_bytes());
            out.extend_from_slice(&r.to_le_bytes());
        }
        // Fee market, carried roots, supply.
        out.extend_from_slice(&self.base_fee_millisat_per_gas.to_le_bytes());
        out.extend_from_slice(&self.block_gas_used.to_le_bytes());
        out.extend_from_slice(&self.block_tx_bytes.to_le_bytes());
        out.extend_from_slice(&self.taint_root);
        out.extend_from_slice(&self.coherence_accumulator_root);
        out.extend_from_slice(&self.coherence_nullifier_root);
        out.extend_from_slice(&self.evm.account_root);
        out.extend_from_slice(&self.evm.receipts_root);
        out.extend_from_slice(&self.evm.gas_used.to_le_bytes());
        out.extend_from_slice(&self.evm.base_fee_per_gas.to_le_bytes());
        out.extend_from_slice(&self.issued_sat.to_le_bytes());
        // The eUTXO set, last (it dominates and streams well). u64 count:
        // this is the one collection that outgrows u32-count intuitions.
        out.extend_from_slice(&(self.eutxos.entries.len() as u64).to_le_bytes());
        // 76 bytes an entry, which is exactly the canonical leaf encoding of a
        // LIQUID entry — `unlock_epoch` is deliberately not written, because
        // `EutxoEntry::leaf` omits it when zero and every entry on the live
        // chain is zero (`VESTING_LOCK_ACTIVATION_EPOCH` is inert, and the
        // five allocation outpoints its seeding would rewrite were measured
        // spent on 2026-08-31). If that gate is ever armed, this format
        // becomes lossy and a restore of a state holding a locked entry fails
        // at the root check. That is the safe direction, but it is a BARE root
        // mismatch, so the coupling is pinned by a test rather than left for
        // an operator to rediscover as suspected tampering.
        for e in self.eutxos.entries.values() {
            out.extend_from_slice(&e.txid);
            out.extend_from_slice(&e.vout.to_le_bytes());
            out.extend_from_slice(&e.value.to_le_bytes());
            out.extend_from_slice(&e.script_hash);
        }
        out
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Decode (module-private: `restore` is the only door)
// ───────────────────────────────────────────────────────────────────────────

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], SnapshotError> {
        if self.buf.len() - self.at < n {
            return Err(SnapshotError::Decode("truncated"));
        }
        let s = &self.buf[self.at..self.at + n];
        self.at += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, SnapshotError> {
        Ok(self.take(1)?[0])
    }
    fn flag(&mut self) -> Result<bool, SnapshotError> {
        // Strict 0x00/0x01: two byte forms for one bool would let two
        // encodings share a decoded state, breaking canonicality.
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(SnapshotError::Decode("boolean is not 0x00/0x01")),
        }
    }
    fn u16(&mut self) -> Result<u16, SnapshotError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, SnapshotError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, SnapshotError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn u128(&mut self) -> Result<u128, SnapshotError> {
        Ok(u128::from_le_bytes(self.take(16)?.try_into().unwrap()))
    }
    fn h32(&mut self) -> Result<[u8; 32], SnapshotError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn bytes(&mut self) -> Result<Vec<u8>, SnapshotError> {
        let n = self.u32()? as usize;
        if n > self.buf.len() - self.at {
            return Err(SnapshotError::Decode("length over remaining bytes"));
        }
        Ok(self.take(n)?.to_vec())
    }
    /// A collection count, sanity-bounded by the bytes actually left: `count
    /// × min_entry` may not exceed the remainder, so a forged count cannot
    /// command a giant allocation.
    fn count(&mut self, min_entry: usize) -> Result<usize, SnapshotError> {
        let n = self.u32()? as usize;
        if n.saturating_mul(min_entry) > self.buf.len() - self.at {
            return Err(SnapshotError::Decode("count over remaining bytes"));
        }
        Ok(n)
    }
    fn finish(self) -> Result<(), SnapshotError> {
        if self.at != self.buf.len() {
            return Err(SnapshotError::Decode("trailing bytes"));
        }
        Ok(())
    }
}

/// Read a map whose wire keys must be strictly ascending — one byte form per
/// map, and no duplicate-key last-wins ambiguity.
fn read_map<K: Ord + Copy, V>(
    r: &mut Reader<'_>,
    min_entry: usize,
    mut read_entry: impl FnMut(&mut Reader<'_>) -> Result<(K, V), SnapshotError>,
) -> Result<BTreeMap<K, V>, SnapshotError> {
    let n = r.count(min_entry)?;
    let mut map = BTreeMap::new();
    let mut prev: Option<K> = None;
    for _ in 0..n {
        let (k, v) = read_entry(r)?;
        if let Some(p) = prev {
            if k <= p {
                return Err(SnapshotError::Decode("map keys out of order"));
            }
        }
        prev = Some(k);
        map.insert(k, v);
    }
    Ok(map)
}

/// Everything decoded from the wire — an intermediate that is NOT a state.
/// Only [`restore`] consumes it, after which the root check decides.
struct Decoded {
    epoch: u64,
    randao_mix: [u8; 32],
    boundary_mixes: BTreeMap<u64, [u8; 32]>,
    validators: BTreeMap<u32, ValidatorRecord>,
    reveals_used: BTreeMap<u32, u32>,
    justified: BTreeMap<u64, [u8; 32]>,
    current_justified: finality::Checkpoint,
    finalized: finality::Checkpoint,
    leaked: BTreeMap<u32, u64>,
    next_epoch: u64,
    previous_justified: crate::interfaces::Checkpoint,
    pending_votes: BTreeMap<(u32, [u8; 32]), crate::attestation::AttestationData>,
    latest_messages: BTreeMap<u32, (u64, [u8; 32])>,
    fc_equivocators: BTreeSet<u32>,
    current_participation: BTreeMap<u32, bool>,
    previous_participation: BTreeMap<u32, bool>,
    deposit_history: Vec<QueuedDeposit>,
    delegations: Vec<Delegation>,
    pending_fee_rewards: BTreeMap<u32, u128>,
    slash_applied: BTreeSet<[u8; 32]>,
    slash_window: BTreeMap<u64, u128>,
    delegator_slash_losses: BTreeMap<u32, u128>,
    delegator_fee_rewards: BTreeMap<u32, u128>,
    base_fee_millisat_per_gas: u128,
    block_gas_used: u64,
    block_tx_bytes: u64,
    taint_root: [u8; 32],
    coherence_accumulator_root: [u8; 32],
    coherence_nullifier_root: [u8; 32],
    evm: EvmCommitment,
    issued_sat: u128,
    eutxos: Vec<EutxoEntry>,
}

fn decode(bytes: &[u8]) -> Result<Decoded, SnapshotError> {
    let mut r = Reader { buf: bytes, at: 0 };
    if r.u16()? != SNAPSHOT_BODY_VERSION {
        return Err(SnapshotError::Decode("unknown snapshot body version"));
    }
    let epoch = r.u64()?;
    let randao_mix = r.h32()?;
    let boundary_mixes = read_map(&mut r, 40, |r| Ok((r.u64()?, r.h32()?)))?;
    let validators = read_map(&mut r, 4 + 4 + 16 + 32 + 4 + 8 * 3 + 1 + 16, |r| {
        let index = r.u32()?;
        let pubkey = r.bytes()?;
        let staked_sat = r.u128()?;
        // The root commits stake saturated to u64; a wider value would be
        // invisible to the verification below, so it is refused here.
        if staked_sat > u64::MAX as u128 {
            return Err(SnapshotError::Decode("stake wider than the committed width"));
        }
        let randao_commitment = r.h32()?;
        let withdrawal_credentials = r.bytes()?;
        let activation_epoch = r.u64()?;
        let exit_epoch = r.u64()?;
        let withdrawable_epoch = r.u64()?;
        let slashed = r.flag()?;
        let commission_bps = r.u128()?;
        Ok((
            index,
            ValidatorRecord {
                index,
                pubkey,
                staked_sat,
                randao_commitment,
                withdrawal_credentials,
                activation_epoch,
                exit_epoch,
                withdrawable_epoch,
                slashed,
                commission_bps,
            },
        ))
    })?;
    let reveals_used = read_map(&mut r, 8, |r| Ok((r.u32()?, r.u32()?)))?;
    let justified = read_map(&mut r, 40, |r| Ok((r.u64()?, r.h32()?)))?;
    let read_cp = |r: &mut Reader<'_>| -> Result<finality::Checkpoint, SnapshotError> {
        Ok(finality::Checkpoint { epoch: r.u64()?, root: r.h32()? })
    };
    let current_justified = read_cp(&mut r)?;
    let finalized = read_cp(&mut r)?;
    let leaked = read_map(&mut r, 12, |r| Ok((r.u32()?, r.u64()?)))?;
    let next_epoch = r.u64()?;
    let previous_justified =
        crate::interfaces::Checkpoint { epoch: r.u64()?, root: r.h32()? };
    let pending_votes = read_map(&mut r, 4 + 32 + 8 + 32 + 8 + 32 + 8 + 32, |r| {
        let validator = r.u32()?;
        let signing_root = r.h32()?;
        let d = crate::attestation::AttestationData {
            slot: r.u64()?,
            head: r.h32()?,
            source_epoch: r.u64()?,
            source_root: r.h32()?,
            target_epoch: r.u64()?,
            target_root: r.h32()?,
        };
        Ok(((validator, signing_root), d))
    })?;
    let latest_messages = read_map(&mut r, 44, |r| Ok((r.u32()?, (r.u64()?, r.h32()?))))?;
    let fc_n = r.count(4)?;
    let mut fc_equivocators = BTreeSet::new();
    let mut prev: Option<u32> = None;
    for _ in 0..fc_n {
        let v = r.u32()?;
        if prev.is_some_and(|p| v <= p) {
            return Err(SnapshotError::Decode("set keys out of order"));
        }
        prev = Some(v);
        fc_equivocators.insert(v);
    }
    let current_participation = read_map(&mut r, 5, |r| Ok((r.u32()?, r.flag()?)))?;
    let previous_participation = read_map(&mut r, 5, |r| Ok((r.u32()?, r.flag()?)))?;
    let dep_n = r.count(32 + 8 + 16)?;
    let mut deposit_history = Vec::with_capacity(dep_n);
    for _ in 0..dep_n {
        deposit_history.push(QueuedDeposit {
            pubkey_hash: r.h32()?,
            deposit_epoch: r.u64()?,
            amount_sat: r.u128()?,
        });
    }
    let del_n = r.count(4 + 4 + 16 + 8 + 1 + 1)?;
    let mut delegations = Vec::with_capacity(del_n);
    for _ in 0..del_n {
        let delegator = r.u32()?;
        let validator = r.u32()?;
        let amount_sat = r.u128()?;
        let requested_epoch = r.u64()?;
        let deactivate_epoch = if r.flag()? { Some(r.u64()?) } else { None };
        let eligible = r.flag()?;
        delegations.push(Delegation {
            delegator,
            validator,
            amount_sat,
            requested_epoch,
            deactivate_epoch,
            eligible,
        });
    }
    let pending_fee_rewards = read_map(&mut r, 20, |r| Ok((r.u32()?, r.u128()?)))?;
    let ap_n = r.count(32)?;
    let mut slash_applied = BTreeSet::new();
    let mut prev_id: Option<[u8; 32]> = None;
    for _ in 0..ap_n {
        let id = r.h32()?;
        if prev_id.is_some_and(|p| id <= p) {
            return Err(SnapshotError::Decode("set keys out of order"));
        }
        prev_id = Some(id);
        slash_applied.insert(id);
    }
    let slash_window = read_map(&mut r, 24, |r| Ok((r.u64()?, r.u128()?)))?;
    let delegator_slash_losses = read_map(&mut r, 20, |r| Ok((r.u32()?, r.u128()?)))?;
    let delegator_fee_rewards = read_map(&mut r, 20, |r| Ok((r.u32()?, r.u128()?)))?;
    let base_fee_millisat_per_gas = r.u128()?;
    let block_gas_used = r.u64()?;
    let block_tx_bytes = r.u64()?;
    let taint_root = r.h32()?;
    let coherence_accumulator_root = r.h32()?;
    let coherence_nullifier_root = r.h32()?;
    let evm = EvmCommitment {
        account_root: r.h32()?,
        receipts_root: r.h32()?,
        gas_used: r.u64()?,
        base_fee_per_gas: r.u64()?,
    };
    let issued_sat = r.u128()?;
    let eutxo_n = {
        let n = r.u64()?;
        let remaining = (r.buf.len() - r.at) as u64;
        if n.saturating_mul(76) > remaining {
            return Err(SnapshotError::Decode("count over remaining bytes"));
        }
        n as usize
    };
    let mut eutxos = Vec::with_capacity(eutxo_n);
    let mut prev_out: Option<([u8; 32], u32)> = None;
    for _ in 0..eutxo_n {
        let txid = r.h32()?;
        let vout = r.u32()?;
        let value = r.u64()?;
        let script_hash = r.h32()?;
        let key = (txid, vout);
        if prev_out.is_some_and(|p| key <= p) {
            return Err(SnapshotError::Decode("map keys out of order"));
        }
        prev_out = Some(key);
        // `unlock_epoch: 0` is FAITHFUL, not a placeholder, and the reason is
        // the leaf encoding: `EutxoEntry::leaf` appends `unlock_epoch` ONLY
        // when it is nonzero, so the 76 bytes above ARE the canonical encoding
        // of a liquid entry. A locked entry (nonzero `unlock_epoch`, written
        // only by the vesting seeding behind `VESTING_LOCK_ACTIVATION_EPOCH`)
        // has no room in this format and would decode to a DIFFERENT state —
        // which `restore` catches at the root check and refuses, rather than
        // accepting. Fail-closed, never silent; pinned by
        // `a_vesting_locked_entry_cannot_survive_the_snapshot_round_trip`.
        eutxos.push(EutxoEntry { txid, vout, value, script_hash, unlock_epoch: 0 });
    }
    r.finish()?;
    Ok(Decoded {
        epoch,
        randao_mix,
        boundary_mixes,
        validators,
        reveals_used,
        justified,
        current_justified,
        finalized,
        leaked,
        next_epoch,
        previous_justified,
        pending_votes,
        latest_messages,
        fc_equivocators,
        current_participation,
        previous_participation,
        deposit_history,
        delegations,
        pending_fee_rewards,
        slash_applied,
        slash_window,
        delegator_slash_losses,
        delegator_fee_rewards,
        base_fee_millisat_per_gas,
        block_gas_used,
        block_tx_bytes,
        taint_root,
        coherence_accumulator_root,
        coherence_nullifier_root,
        evm,
        issued_sat,
        eutxos,
    })
}

// ───────────────────────────────────────────────────────────────────────────
// Restore — the only door, and the root check is inside it
// ───────────────────────────────────────────────────────────────────────────

/// Rebuild a [`CommittedState`] from snapshot bytes, **verifying it against
/// `trust.state_root` before it exists**. On any failure the state is never
/// produced.
///
/// `genesis` is the caller's OWN genesis state (built from its manifest, the
/// trust every node already makes to exist at all): chain identity —
/// `genesis_mix`, `genesis_cohort` — is copied from it, never read from the
/// wire. Derived fields (`pubkey_index`, the slashing ejected set) are
/// rebuilt from the committed registry. `slot` and `head` come from `trust`.
///
/// The verification is a full from-scratch root recomputation over the
/// restored state — the same `compute_root` every block commits with, so
/// there is no second definition of what the root covers.
pub fn restore(
    bytes: &[u8],
    genesis: &CommittedState,
    trust: &SnapshotTrust,
) -> Result<CommittedState, SnapshotError> {
    let d = decode(bytes)?;
    if d.epoch != crate::epoch_of(trust.head_slot) {
        return Err(SnapshotError::EpochSlotMismatch {
            wire_epoch: d.epoch,
            head_slot: trust.head_slot,
        });
    }
    // Registry consistency the root would also catch, but with a message that
    // names the artifact rather than a bare root mismatch: the map key is the
    // record's index by construction (`decode` re-keys on `index`), so no
    // check is needed there.
    // Rebuild the derived index over the committed registry (the genesis and
    // deposit paths both maintain `sha3(pubkey) → index`, one entry per
    // registered record).
    let mut pubkey_index = BTreeMap::new();
    for v in d.validators.values() {
        let hash: [u8; 32] = Sha3_256::digest(&v.pubkey).into();
        pubkey_index.insert(hash, v.index);
    }
    // The ejected set is exactly the slashed registry records — the
    // equivalence `slashing::ejected_ids` documents and the transition test
    // pins.
    let ejected: BTreeSet<u32> =
        d.validators.values().filter(|v| v.slashed).map(|v| v.index).collect();
    let eutxos: EutxoSet = d.eutxos.into_iter().collect();

    let state = CommittedState {
        slot: trust.head_slot,
        epoch: d.epoch,
        head: trust.head,
        validators: d.validators,
        reveals_used: d.reveals_used,
        randao_mix: d.randao_mix,
        boundary_mixes: d.boundary_mixes,
        genesis_mix: genesis.genesis_mix,
        genesis_cohort: genesis.genesis_cohort.clone(),
        finality_engine: finality::FinalityState::from_committed_parts(
            d.justified,
            d.current_justified,
            d.finalized,
            d.leaked,
            d.next_epoch,
        ),
        previous_justified: d.previous_justified,
        pending_votes: d.pending_votes,
        latest_messages: d.latest_messages,
        fc_equivocators: d.fc_equivocators,
        current_participation: d.current_participation,
        previous_participation: d.previous_participation,
        deposit_history: d.deposit_history,
        pubkey_index,
        delegations: d.delegations,
        pending_fee_rewards: d.pending_fee_rewards,
        slashing: SlashingState::from_committed_parts(d.slash_applied, d.slash_window, ejected),
        delegator_slash_losses: d.delegator_slash_losses,
        delegator_fee_rewards: d.delegator_fee_rewards,
        base_fee_millisat_per_gas: d.base_fee_millisat_per_gas,
        block_gas_used: d.block_gas_used,
        block_tx_bytes: d.block_tx_bytes,
        taint_root: d.taint_root,
        coherence_accumulator_root: d.coherence_accumulator_root,
        coherence_nullifier_root: d.coherence_nullifier_root,
        evm: d.evm,
        issued_sat: d.issued_sat,
        eutxos,
    };

    // THE check. Everything above only shaped bytes; this decides whether
    // they are the state the signed checkpoint commits to.
    let got = state.compute_root();
    if got != trust.state_root {
        return Err(SnapshotError::StateRootMismatch { expected: trust.state_root, got });
    }
    Ok(state)
}

// ───────────────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::tests::{build_block, state_with_live_bookkeeping};
    use super::*;
    use crate::interfaces::StateTransition;
    use crate::params::SLOTS_PER_EPOCH;

    fn trust_of(st: &CommittedState) -> SnapshotTrust {
        SnapshotTrust { state_root: st.compute_root(), head: st.head, head_slot: st.slot }
    }

    /// The fixture: a state where every bookkeeping component is live (the
    /// same one the root-coverage test uses, so an empty component cannot
    /// make a round trip pass vacuously).
    fn live_state() -> CommittedState {
        let (_t, st, _atts, _chains) = state_with_live_bookkeeping();
        st
    }

    #[test]
    fn round_trip_is_identity() {
        let st = live_state();
        let bytes = st.snapshot_serialize();
        let back = restore(&bytes, &st, &trust_of(&st)).expect("round trip");
        // Full structural equality — committed fields from the wire, derived
        // and trust fields rebuilt to the same values.
        assert_eq!(back, st);
        // And byte-level canonicality: re-serialising the restored state
        // reproduces the artifact, so a node that booted from a snapshot can
        // serve the very bytes it verified.
        assert_eq!(back.snapshot_serialize(), bytes);
    }

    /// The snapshot body has no field for `unlock_epoch`, so a vesting-LOCKED
    /// eUTXO entry cannot survive a round trip — and this pins that the loss
    /// is refused rather than absorbed.
    ///
    /// Why it matters and why it is a test rather than a fix: the 76 bytes an
    /// entry carries are exactly the canonical leaf encoding of a LIQUID entry
    /// (`EutxoEntry::leaf` appends `unlock_epoch` only when nonzero), so the
    /// format is lossless for every state the live chain can hold today —
    /// `VESTING_LOCK_ACTIVATION_EPOCH` is inert, and the allocation outpoints
    /// its seeding would rewrite were measured spent on 2026-08-31. The day
    /// that gate is armed, this format becomes lossy. The safe direction is
    /// the one asserted here: `restore` recomputes the root from scratch and
    /// refuses, so a checkpoint can never install a state whose locks were
    /// silently dropped.
    ///
    /// What the failure LOOKS like is the reason this is written down. It is a
    /// bare `StateRootMismatch`, indistinguishable from tampering — the same
    /// shape of defect as a published checksum that describes the wrong file:
    /// it penalises the operator who verifies. Whoever arms
    /// `VESTING_LOCK_ACTIVATION_EPOCH` must widen the snapshot body (a version
    /// bump, since `checkpoints/wscheckpoint-1536.bin` is published) or accept
    /// that checkpoint sync stops working at that epoch. This test is what
    /// turns that decision red instead of leaving it to be rediscovered.
    #[test]
    fn a_vesting_locked_entry_cannot_survive_the_snapshot_round_trip() {
        let mut st = live_state();
        st.eutxos.insert(EutxoEntry {
            txid: [0xA5; 32],
            vout: 0,
            value: 4_096,
            script_hash: [0x0E; 32],
            // Nonzero: the whole point. With 0 this entry round-trips fine,
            // which is what the liquid path already proves above.
            unlock_epoch: 9_999,
        });
        let bytes = st.snapshot_serialize();
        // `trust_of` takes the TRUE root of the locked state, so this is the
        // honest question: can the artifact reproduce the state it came from?
        match restore(&bytes, &st, &trust_of(&st)) {
            Err(SnapshotError::StateRootMismatch { .. }) => {}
            Ok(_) => panic!(
                "a locked entry round-tripped: the snapshot body dropped \
                 unlock_epoch and the root check did not notice — that is a \
                 checkpoint that can install a state with its vesting locks \
                 silently removed"
            ),
            other => panic!("expected a root mismatch, got {other:?}"),
        }
    }

    #[test]
    fn restore_refuses_a_wrong_root() {
        let st = live_state();
        let bytes = st.snapshot_serialize();
        let mut trust = trust_of(&st);
        trust.state_root[7] ^= 1;
        match restore(&bytes, &st, &trust) {
            Err(SnapshotError::StateRootMismatch { .. }) => {}
            other => panic!("wrong trusted root must be a root mismatch, got {other:?}"),
        }
    }

    #[test]
    fn a_tampered_balance_cannot_restore() {
        let st = live_state();
        let mut bytes = st.snapshot_serialize();
        // The eUTXO section is the tail; each entry ends with a 32-byte
        // script hash preceded by the 8-byte value. Flip one bit of the last
        // entry's value.
        let n = bytes.len();
        bytes[n - 33] ^= 1;
        match restore(&bytes, &st, &trust_of(&st)) {
            Err(SnapshotError::StateRootMismatch { .. }) => {}
            other => panic!("a moved balance must fail the root check, got {other:?}"),
        }
    }

    #[test]
    fn tampering_anywhere_is_refused() {
        // Not exhaustive bit-flipping, but a sweep across the whole span:
        // every flip must either fail to decode or fail the root check —
        // never restore.
        let st = live_state();
        let bytes = st.snapshot_serialize();
        let trust = trust_of(&st);
        let step = (bytes.len() / 64).max(1);
        for at in (0..bytes.len()).step_by(step) {
            let mut b = bytes.clone();
            b[at] ^= 0x40;
            assert!(
                restore(&b, &st, &trust).is_err(),
                "flip at byte {at} of {} restored anyway",
                bytes.len()
            );
        }
    }

    #[test]
    fn trailing_and_truncated_bytes_are_refused() {
        let st = live_state();
        let bytes = st.snapshot_serialize();
        let trust = trust_of(&st);
        let mut with_junk = bytes.clone();
        with_junk.push(0);
        assert_eq!(
            restore(&with_junk, &st, &trust).unwrap_err(),
            SnapshotError::Decode("trailing bytes")
        );
        assert!(restore(&bytes[..bytes.len() - 1], &st, &trust).is_err());
    }

    #[test]
    fn eutxo_order_is_canonical() {
        // Swapping two well-formed entries changes no set content, only the
        // byte order — and must be refused, or one state would have two byte
        // forms and a chunked download could not mix peers.
        let mut st = live_state();
        // The shared fixture leaves a single unspent output; a second one is
        // needed for an order swap to be expressible at all.
        st.eutxos.insert(EutxoEntry {
            txid: [0xFF; 32],
            vout: 0,
            value: 7,
            script_hash: [0x0F; 32],
            unlock_epoch: 0,
        });
        let mut bytes = st.snapshot_serialize();
        let n = bytes.len();
        assert!(st.eutxos.entries.len() >= 2);
        let (a, b) = (n - 152, n - 76); // the last two 76-byte entries
        let tmp = bytes[a..a + 76].to_vec();
        bytes.copy_within(b..b + 76, a);
        bytes[b..b + 76].copy_from_slice(&tmp);
        assert_eq!(
            restore(&bytes, &st, &trust_of(&st)).unwrap_err(),
            SnapshotError::Decode("map keys out of order")
        );
    }

    #[test]
    fn stake_beyond_the_committed_width_is_refused_at_decode() {
        // The root commits stake saturated to u64, so a u128 stake above it
        // would be invisible to the verification — the decoder must refuse it
        // before the root check can be asked.
        let mut st = live_state();
        st.validators.get_mut(&0).unwrap().staked_sat = u64::MAX as u128 + 1;
        let bytes = st.snapshot_serialize();
        assert_eq!(
            restore(&bytes, &st, &trust_of(&st)).unwrap_err(),
            SnapshotError::Decode("stake wider than the committed width")
        );
    }

    #[test]
    fn derived_fields_are_rebuilt_not_decoded() {
        // Poison the derived fields on the source state; the wire must not
        // carry the poison, and the restore must rebuild the honest values.
        let st = live_state();
        let mut poisoned = st.clone();
        poisoned.pubkey_index.clear();
        poisoned.pubkey_index.insert([0xEE; 32], 999);
        let bytes = poisoned.snapshot_serialize();
        assert_eq!(bytes, st.snapshot_serialize(), "derived fields must not reach the wire");
        let back = restore(&bytes, &st, &trust_of(&st)).expect("restores");
        assert_eq!(back.pubkey_index, st.pubkey_index, "pubkey_index is rebuilt from the registry");
        let ejected: Vec<u32> = back.slashing.ejected_ids().copied().collect();
        let slashed: Vec<u32> =
            back.validators.values().filter(|v| v.slashed).map(|v| v.index).collect();
        assert_eq!(ejected, slashed, "ejected is exactly the slashed registry");
    }

    #[test]
    fn slot_outside_the_wire_epoch_is_refused() {
        let st = live_state();
        let bytes = st.snapshot_serialize();
        let mut trust = trust_of(&st);
        trust.head_slot += SLOTS_PER_EPOCH; // same root claim, wrong epoch's slot
        assert!(matches!(
            restore(&bytes, &st, &trust).unwrap_err(),
            SnapshotError::EpochSlotMismatch { .. }
        ));
    }

    /// The milestone property: a state restored from checkpoint + snapshot
    /// walks forward to exactly where a from-genesis replay walks — same
    /// head, same roots, block for block, across an epoch boundary.
    #[test]
    fn restored_state_continues_identically_to_the_replayed_one() {
        let (t, st, _atts, mut chains) = state_with_live_bookkeeping();

        // The "snapshot at the checkpoint": serialize and restore. From here
        // on, `a` is the node that replayed from genesis and `b` the node
        // that verified a downloaded snapshot.
        let bytes = st.snapshot_serialize();
        let b0 = restore(&bytes, &st, &trust_of(&st)).expect("verified restore");
        assert_eq!(b0, st);

        let mut a = st;
        let mut b = b0;
        let next_slot = a.slot + 1;
        // One block inside the epoch, then one across the next epoch
        // boundary, so close_epoch (participation reset, rewards, the RANDAO
        // boundary, fee compounding) runs on both sides.
        let boundary_slot = (a.epoch + 1) * SLOTS_PER_EPOCH + 1;
        for slot in [next_slot, boundary_slot] {
            let blk = build_block(&t, &a, slot, &[], &[], &mut chains);
            let a2 = t.apply_block(&a, &blk, &[], &[]).expect("replayed node applies");
            let b2 = t.apply_block(&b, &blk, &[], &[]).expect("synced node applies");
            assert_eq!(a2.compute_root(), b2.compute_root(), "roots diverged at slot {slot}");
            assert_eq!(a2.head, b2.head, "heads diverged at slot {slot}");
            assert_eq!(a2, b2, "full state diverged at slot {slot}");
            a = a2;
            b = b2;
        }
        assert!(a.epoch >= 2, "the continuation must have crossed an epoch boundary");
    }
}
