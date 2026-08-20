// SPDX-License-Identifier: AGPL-3.0-or-later
//! Canonical encoding of a committed state, so a restarting node does not have
//! to replay the chain from genesis.
//!
//! # Why this exists
//!
//! On 19 August 2026 a security fix had to reach 64 validators. Every restart
//! replays the whole chain: measured at 2 h 06 for one node, and the rate
//! *decays* as the state grows (29.4 slots/min falling to 22.7 over six hours,
//! because each applied block costs more once the eUTXO set is larger). The
//! roll-out took two days, nodes died of OOM mid-replay at 2 GB and again at
//! 8 GB, and the fleet had to be moved to 30 GB machines to survive a restart
//! it should never have needed. A half-hour fix cost two days because the node
//! had no way to say "I already know the state at height H".
//!
//! # What makes this safe
//!
//! **A snapshot is a cache, never an authority.** It is loaded, the state root
//! is recomputed from it, and that root is compared against the one the block
//! header at that height already commits to. A snapshot that does not match is
//! discarded and the node replays as it does today. So a corrupt file, a
//! truncated write, a tampered copy or a snapshot from another chain are all
//! *detected*, not trusted — and the proof was already in the header.
//!
//! Nothing here is consensus. No byte on the wire changes, no rule changes,
//! and a node running this reaches the same state as a node without it. There
//! is no flag day.
//!
//! # Format
//!
//! Length-prefixed, little-endian, no padding. Maps and sets are written in
//! their iteration order, which for `BTreeMap`/`BTreeSet` is sorted by key —
//! so the encoding is deterministic and two nodes at the same state produce
//! identical bytes. That is a property worth having even though nothing
//! depends on it yet: it makes snapshots comparable.

/// Magic + version. A file that does not start with these bytes is not a
/// snapshot and is refused before anything else is read.
pub const SNAP_MAGIC: &[u8; 8] = b"BPOSSNP1";

#[derive(Debug, PartialEq, Eq)]
pub struct SnapErr(pub &'static str);

impl core::fmt::Display for SnapErr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "snapshot decode: {}", self.0)
    }
}

// ── writer ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct W(pub Vec<u8>);

impl W {
    pub fn new() -> Self { W(Vec::new()) }
    pub fn u8(&mut self, v: u8) { self.0.push(v); }
    pub fn bool(&mut self, v: bool) { self.0.push(v as u8); }
    pub fn u32(&mut self, v: u32) { self.0.extend_from_slice(&v.to_le_bytes()); }
    pub fn u64(&mut self, v: u64) { self.0.extend_from_slice(&v.to_le_bytes()); }
    pub fn u128(&mut self, v: u128) { self.0.extend_from_slice(&v.to_le_bytes()); }
    pub fn h32(&mut self, v: &[u8; 32]) { self.0.extend_from_slice(v); }
    pub fn bytes(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.0.extend_from_slice(v);
    }
    pub fn len(&mut self, n: usize) { self.u32(n as u32); }
    pub fn opt_u64(&mut self, v: Option<u64>) {
        match v { Some(x) => { self.u8(1); self.u64(x); } None => self.u8(0) }
    }
}

// ── reader ───────────────────────────────────────────────────────────────────

pub struct R<'a> { b: &'a [u8], i: usize }

impl<'a> R<'a> {
    pub fn new(b: &'a [u8]) -> Self { R { b, i: 0 } }
    fn take(&mut self, n: usize) -> Result<&'a [u8], SnapErr> {
        if self.i + n > self.b.len() { return Err(SnapErr("truncated")); }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    /// The 8 magic bytes, read before anything else. Returned rather than
    /// compared here so the caller words the error.
    pub fn take_magic(&mut self) -> Result<[u8; 8], SnapErr> {
        Ok(self.take(8)?.try_into().unwrap())
    }
    pub fn u8(&mut self) -> Result<u8, SnapErr> { Ok(self.take(1)?[0]) }
    pub fn bool(&mut self) -> Result<bool, SnapErr> {
        match self.u8()? { 0 => Ok(false), 1 => Ok(true), _ => Err(SnapErr("bool not 0 or 1")) }
    }
    pub fn u32(&mut self) -> Result<u32, SnapErr> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64, SnapErr> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn u128(&mut self) -> Result<u128, SnapErr> {
        Ok(u128::from_le_bytes(self.take(16)?.try_into().unwrap()))
    }
    pub fn h32(&mut self) -> Result<[u8; 32], SnapErr> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    pub fn bytes(&mut self) -> Result<Vec<u8>, SnapErr> {
        let n = self.u32()? as usize;
        // A length field is attacker-reachable only via a file on this node's
        // own disk, but a 4 GB allocation from a corrupt byte is still a crash.
        if n > 64 * 1024 * 1024 { return Err(SnapErr("field length over cap")); }
        Ok(self.take(n)?.to_vec())
    }
    /// A collection length, capped so a corrupt prefix cannot make the node
    /// try to reserve an absurd number of entries before failing.
    pub fn len(&mut self) -> Result<usize, SnapErr> {
        let n = self.u32()? as usize;
        if n > 8_000_000 { return Err(SnapErr("collection length over cap")); }
        Ok(n)
    }
    pub fn opt_u64(&mut self) -> Result<Option<u64>, SnapErr> {
        match self.u8()? { 0 => Ok(None), 1 => Ok(Some(self.u64()?)), _ => Err(SnapErr("bad option tag")) }
    }
    pub fn finish(&self) -> Result<(), SnapErr> {
        if self.i == self.b.len() { Ok(()) } else { Err(SnapErr("trailing bytes")) }
    }
}
