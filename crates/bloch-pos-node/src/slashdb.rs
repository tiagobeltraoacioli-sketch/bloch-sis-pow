// SPDX-License-Identifier: AGPL-3.0-or-later

//! Node-local anti-double-sign fence: a durable slashing-protection record
//! plus an exclusive lock on the data directory.
//!
//! # Why this file exists
//!
//! Until it did, the entire guard against signing twice for one slot was a
//! local variable in the slot loop:
//!
//! ```text
//! let mut last_attested: u64 = engine.state.slot();   // engine.rs:2569
//! ...
//! if !in_grace && slot > last_attested {              // engine.rs:2611
//!     engine.attest(slot);
//!     last_attested = slot;
//! }
//! ```
//!
//! Three properties that variable does not have, each sufficient on its own
//! to produce a slashable pair:
//!
//! 1. **It does not survive a restart.** It is re-seeded from the chain head,
//!    so every boot re-opens every slot the head does not already contain.
//! 2. **It trusts the clock.** `slot` is derived from `SystemTime::now()`
//!    (`engine.rs:146`) with `slot_ms = 30_000`. A backward step of one slot
//!    or more, spanning a restart, re-opens an already-voted slot — and boot
//!    is both when a clock step is likeliest and when the guard resets.
//! 3. **It does not exist across processes.** [`crate::store::Store::open`]
//!    took no lock, so two processes sharing one keystore double-sign as soon
//!    as their heads differ. No clock anomaly is required. This is what
//!    happened between 2026-08-21 and 2026-08-30: 48 validators, 364
//!    double-head slots, every pair cryptographically valid under the
//!    validator's own key.
//!
//! The asymmetry is the whole point. `store.rs`'s block-append fsync calls
//! itself *"the producer-side equivocation fence across restarts"* — so the
//! proposer path got a restart fence and the attester path, the offence that
//! actually happened, got none. This module gives the attester one, and gives
//! the proposer a second one that does not depend on the block log.
//!
//! # The rule, and why the ordering is structural
//!
//! [`SlashingProtection::attest_with`] and
//! [`SlashingProtection::propose_with`] take the closure that produces the
//! signature. They persist and `fsync` the new maxima **and only then** call
//! it. There is no public way to sign first and record afterwards, because a
//! fence written after the signature is released is not a fence: the window
//! it leaves open is exactly the window a crash lands in.
//!
//! The cost is one fsync per duty — one per 30 s slot, against the one per
//! block the store already pays.
//!
//! # What the fence is keyed to, and the store-transplant case
//!
//! Copying a canonical `blocks.log` from a healthy box onto a diverged one is
//! an established repair here (`~/bloch-rollout`, the 2026-08-31 transplants).
//! A fence keyed to the *store* — to the head slot, to the log length — would
//! either forbid that repair or be reset by it. This one is keyed to
//! **(validator public key, genesis digest)** and lives in its own file, so:
//!
//! - copying `blocks.log` (and `meta.bin`) does not touch it, in either
//!   direction: the repair stays safe and the fence stays armed;
//! - a whole-datadir `rsync` between boxes running *different* validators is
//!   refused at open with a named error, instead of silently importing
//!   another validator's maxima;
//! - a whole-datadir copy between boxes running the *same* validator — i.e.
//!   moving a validator, the operation that produced the incident — carries
//!   the maxima with it, which is the safe direction;
//! - a reorg, which rewrites the whole block log
//!   ([`crate::store::Store::rewrite`]), never lowers it.
//!
//! Stated limitation, because it is real and shared with every slashing
//! database that exists: restoring a **stale backup** of the fence file over
//! a newer one lowers the floor and defeats it. Nothing node-local can detect
//! that. [`SlashingProtection::import`] therefore only ever raises, and the
//! documented repair copies the block log, never this file.
//!
//! # Durability
//!
//! An append-only log of fixed-size snapshot records, the same shape (and the
//! same crash story) as `blocks.log`: one `write_all` then an fsync, so a
//! crash leaves at most one torn trailing record, which the reader drops. The
//! live value is the field-wise **maximum over every valid record**, which is
//! monotone by construction — a dropped trailing record loses at most the one
//! write that had not yet returned, and can never move a maximum down. A
//! checksum failure anywhere but the last record is a hard refusal, not a
//! skip: silently ignoring a corrupt record could lower the floor.
//!
//! On macOS `fsync(2)` does not flush the drive's own cache; the fleet is
//! Linux, and [`fsync_hard`] asks for `F_FULLFSYNC` on Darwin anyway so the
//! developer machine tells the truth too.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use sha3::{Digest, Sha3_256};

/// One snapshot record, on disk.
const RECORD_LEN: usize = 120;
const MAGIC: &[u8; 8] = b"BPOSSLP1";
const VERSION: u32 = 1;
const FLAG_HAS_ATTESTED: u32 = 1 << 0;
const FLAG_HAS_PROPOSED: u32 = 1 << 1;

/// Domain tag for the owner binding. Not consensus — this digest never leaves
/// the box — but tagged anyway so it can never be confused with a signing
/// root by something that reads the file.
const DS_OWNER: &[u8] = b"BLOCH_G4_SLASHDB_OWNER";

/// Records tolerated before the log is compacted to a single one. At one
/// record per 30 s slot this is a rewrite roughly every 34 hours, of a file
/// that never exceeds ~490 kB.
const COMPACT_AFTER: u64 = 4_096;

pub const FENCE_FILE: &str = "slashing-protection.bin";
pub const LOCK_FILE: &str = "LOCK";

/// The highest thing this validator has ever signed, as far as durable local
/// state knows. Monotone in every field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Marks {
    pub has_attested: bool,
    /// Highest slot attested. Stronger than [EIP-3076]'s minimal policy and
    /// deliberately so: the incident was same-slot double-head votes, and the
    /// backward-clock case is a slot regression before it is anything else.
    pub attested_slot: u64,
    /// Highest source (justified) epoch ever voted. Refusing to go below it
    /// is what forbids a *surrounding* vote.
    pub source_epoch: u64,
    /// Highest target epoch ever voted. Refusing to repeat or go below it is
    /// what forbids a *double* vote — and, since the epoch's committees
    /// partition the active set (`committees.rs`: "every validator gets
    /// exactly one chance to contribute"), one target epoch per validator per
    /// epoch is also the honest cadence, so this rule costs nothing.
    pub target_epoch: u64,
    pub has_proposed: bool,
    /// Highest slot proposed. Independent of the block log on purpose: the
    /// log can be rewritten by a reorg or replaced by a transplant.
    pub proposed_slot: u64,
}

impl Marks {
    fn raise_to(&mut self, other: &Marks) {
        if other.has_attested {
            self.has_attested = true;
            self.attested_slot = self.attested_slot.max(other.attested_slot);
            self.source_epoch = self.source_epoch.max(other.source_epoch);
            self.target_epoch = self.target_epoch.max(other.target_epoch);
        }
        if other.has_proposed {
            self.has_proposed = true;
            self.proposed_slot = self.proposed_slot.max(other.proposed_slot);
        }
    }
}

/// Why a duty was refused. Every variant names the offence it prevented, so a
/// refusal in the log is a diagnosis rather than "attestation skipped".
#[derive(Debug)]
pub enum Refusal {
    /// `slot <= marks.attested_slot`. A repeat of, or a step back below, a
    /// slot already voted — the backward-clock case and the two-process
    /// same-slot case both land here.
    AttestSlotRegression { slot: u64, highest: u64 },
    /// `target_epoch <= marks.target_epoch`: a second vote for a target epoch
    /// already voted, which is `SlashableOffense::DoubleVote`.
    DoubleVote { target: u64, highest: u64 },
    /// `source_epoch < marks.source_epoch`: a span that would surround one
    /// already signed, which is `SlashableOffense::SurroundVote`.
    SurroundVote { source: u64, lowest: u64 },
    /// `slot <= marks.proposed_slot`: a second block for a slot already
    /// proposed, which is `SlashableOffense::ProposerEquivocation`.
    ProposeSlotRegression { slot: u64, highest: u64 },
    /// The fence could not be made durable. **Not signing is the safe side**,
    /// so this refuses the duty rather than proceeding unprotected.
    Io(io::Error),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::AttestSlotRegression { slot, highest } => write!(
                f,
                "refusing to attest slot {slot}: this validator has already attested slot \
                 {highest}. Signing again would be an equivocation. If the clock stepped \
                 backwards, fix the clock; the fence will not"
            ),
            Refusal::DoubleVote { target, highest } => write!(
                f,
                "refusing to attest target epoch {target}: already voted target epoch \
                 {highest} (this would be a DoubleVote)"
            ),
            Refusal::SurroundVote { source, lowest } => write!(
                f,
                "refusing to attest source epoch {source}: already voted from source epoch \
                 {lowest} (this would be a SurroundVote)"
            ),
            Refusal::ProposeSlotRegression { slot, highest } => write!(
                f,
                "refusing to propose slot {slot}: already proposed slot {highest} \
                 (this would be a ProposerEquivocation)"
            ),
            Refusal::Io(e) => write!(
                f,
                "refusing to sign: the slashing-protection record could not be made \
                 durable ({e}). Signing without it is the offence this fence exists to \
                 prevent"
            ),
        }
    }
}

/// An exclusive advisory lock on a data directory, held for the life of the
/// process.
///
/// `flock(2)` and not a PID file, for one reason that is the whole design:
/// **the kernel releases a flock when the holding process dies, however it
/// dies** — `SIGKILL`, OOM kill, panic, power loss. So this lock cannot
/// survive an unclean shutdown and turn a legitimate restart into an outage,
/// which is the failure mode a PID-file lock has and the reason operators
/// learn to delete lock files, which is the reason lock files stop working.
/// The `LOCK` file itself persists; only the lock on it does not. Nothing has
/// to be cleaned up by hand, ever.
///
/// Advisory means it binds processes that ask. Every `bloch-pos` asks, at
/// startup, before it can sign anything.
pub struct DirLock {
    _file: File,
    path: PathBuf,
}

/// Hand-written, not derived, and it prints the path only. Nothing in this
/// module ever formats key material, and a derive here would be one field
/// away from doing so.
impl std::fmt::Debug for DirLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DirLock({})", self.path.display())
    }
}

impl DirLock {
    /// Take the lock, or fail loudly. Never blocks: a second node on one data
    /// dir must be an error at startup, not a process that waits and then
    /// quietly starts signing when the first one exits.
    pub fn acquire(dir: &Path) -> io::Result<DirLock> {
        fs::create_dir_all(dir)?;
        let path = dir.join(LOCK_FILE);
        let file = OpenOptions::new().create(true).read(true).write(true).open(&path)?;
        // SAFETY: `file` owns the fd for the duration of the call.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let e = io::Error::last_os_error();
            let busy = matches!(
                e.raw_os_error(),
                Some(c) if c == libc::EWOULDBLOCK || c == libc::EAGAIN
            );
            if busy {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "another bloch-pos process already holds {}. Two processes on one \
                         data directory share one keystore and double-sign as soon as their \
                         heads differ — that is the 2026-08-21 incident, not a hypothetical. \
                         Refusing to start. (The lock is held by a live process; it is NOT a \
                         stale file, and deleting it will not help — find the other process.)",
                        path.display()
                    ),
                ));
            }
            return Err(e);
        }
        // Best-effort breadcrumb for a human reading the box. Never read back
        // for a decision: the lock is the flock, not this text.
        let _ = (&file).set_len(0);
        let _ = (&file).write_all(format!("pid {}\n", std::process::id()).as_bytes());
        Ok(DirLock { _file: file, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// The durable anti-double-sign record.
pub struct SlashingProtection {
    file: File,
    path: PathBuf,
    owner: [u8; 32],
    network: [u8; 32],
    marks: Marks,
    records: u64,
    /// Records tolerated before compaction. A field rather than a hard
    /// reference to [`COMPACT_AFTER`] so the compaction test can exercise the
    /// rewrite path without paying four thousand fsyncs to reach it — the
    /// value a node runs with is the constant, set in `open`.
    compact_after: u64,
}

/// Same rule as [`DirLock`]: path and maxima, never the owner digest and
/// never anything derived from a secret.
impl std::fmt::Debug for SlashingProtection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlashingProtection")
            .field("path", &self.path)
            .field("marks", &self.marks)
            .finish_non_exhaustive()
    }
}

impl SlashingProtection {
    /// Binding identity of a validator key. The public key, never the secret.
    pub fn owner_of(pubkey: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(DS_OWNER);
        h.update((pubkey.len() as u64).to_le_bytes());
        h.update(pubkey);
        h.finalize().into()
    }

    /// Open (or initialise) the fence for `pubkey` on the network identified
    /// by `genesis_digest`.
    ///
    /// A file belonging to another validator or another network is a
    /// **refusal, not a migration** — the same posture `Store::open` takes,
    /// for a stronger reason: importing someone else's maxima either bricks
    /// this validator or, in the other direction, silently unarms it.
    pub fn open(dir: &Path, pubkey: &[u8], genesis_digest: &[u8; 32]) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let path = dir.join(FENCE_FILE);
        let owner = Self::owner_of(pubkey);
        let (marks, records) = Self::read_file(&path, &owner, genesis_digest)?;
        let file = OpenOptions::new().create(true).append(true).read(true).open(&path)?;
        Ok(SlashingProtection {
            file,
            path,
            owner,
            network: *genesis_digest,
            marks,
            records,
            compact_after: COMPACT_AFTER,
        })
    }

    pub fn marks(&self) -> Marks {
        self.marks
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Sign an attestation — **after** the fence is durable, never before.
    ///
    /// `sign` is called exactly once, only on the `Ok` path, and only after
    /// `fsync` has returned. That ordering is the entire safety property, and
    /// it is enforced by this signature rather than by a convention a caller
    /// could get wrong.
    pub fn attest_with<T>(
        &mut self,
        slot: u64,
        source_epoch: u64,
        target_epoch: u64,
        sign: impl FnOnce() -> T,
    ) -> Result<T, Refusal> {
        if self.marks.has_attested {
            if slot <= self.marks.attested_slot {
                return Err(Refusal::AttestSlotRegression {
                    slot,
                    highest: self.marks.attested_slot,
                });
            }
            if target_epoch <= self.marks.target_epoch {
                return Err(Refusal::DoubleVote {
                    target: target_epoch,
                    highest: self.marks.target_epoch,
                });
            }
            if source_epoch < self.marks.source_epoch {
                return Err(Refusal::SurroundVote {
                    source: source_epoch,
                    lowest: self.marks.source_epoch,
                });
            }
        }
        let mut next = self.marks;
        next.has_attested = true;
        next.attested_slot = slot;
        next.source_epoch = source_epoch.max(next.source_epoch);
        next.target_epoch = target_epoch;
        self.commit(next).map_err(Refusal::Io)?;
        Ok(sign())
    }

    /// Sign a block proposal — same ordering, same reason.
    pub fn propose_with<T>(
        &mut self,
        slot: u64,
        sign: impl FnOnce() -> T,
    ) -> Result<T, Refusal> {
        if self.marks.has_proposed && slot <= self.marks.proposed_slot {
            return Err(Refusal::ProposeSlotRegression {
                slot,
                highest: self.marks.proposed_slot,
            });
        }
        let mut next = self.marks;
        next.has_proposed = true;
        next.proposed_slot = slot;
        self.commit(next).map_err(Refusal::Io)?;
        Ok(sign())
    }

    /// Raise the fence to at least `other`. Used when a validator is moved
    /// between boxes: the operator carries the fence forward rather than
    /// starting a fresh one.
    ///
    /// **Only ever raises.** An import can add safety and can never remove
    /// it, so a wrong file (an old backup, a copy from before a move) costs
    /// availability at worst and can never unarm the fence.
    pub fn import(&mut self, other: Marks) -> io::Result<()> {
        let mut next = self.marks;
        next.raise_to(&other);
        if next == self.marks {
            return Ok(());
        }
        self.commit(next)
    }

    /// Append one snapshot record and fsync it. Returns only when the value
    /// is on the device.
    fn commit(&mut self, next: Marks) -> io::Result<()> {
        let rec = encode(&next, &self.owner, &self.network);
        self.file.write_all(&rec)?;
        fsync_hard(&self.file)?;
        self.marks = next;
        self.records += 1;
        if self.records > self.compact_after {
            self.compact()?;
        }
        Ok(())
    }

    /// Collapse the log to the single record that carries the current maxima.
    ///
    /// Write-to-temp, fsync, rename — atomic in both crash directions: before
    /// the rename the old log survives (a superset of the maxima, so never
    /// lower), after it the new one does. There is no ordering in which the
    /// floor drops.
    fn compact(&mut self) -> io::Result<()> {
        let tmp = self.path.with_extension("bin.tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&encode(&self.marks, &self.owner, &self.network))?;
            fsync_hard(&f)?;
        }
        fs::rename(&tmp, &self.path)?;
        if let Ok(d) = File::open(self.path.parent().unwrap_or(Path::new("."))) {
            let _ = d.sync_all();
        }
        self.file = OpenOptions::new().create(true).append(true).read(true).open(&self.path)?;
        self.records = 1;
        Ok(())
    }

    /// Fold the log into its field-wise maximum, refusing anything that is
    /// not this validator's, not this network's, or corrupt anywhere but at
    /// the very end.
    fn read_file(
        path: &Path,
        owner: &[u8; 32],
        network: &[u8; 32],
    ) -> io::Result<(Marks, u64)> {
        let mut bytes = Vec::new();
        match File::open(path) {
            Ok(mut f) => {
                f.read_to_end(&mut bytes)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Marks::default(), 0)),
            Err(e) => return Err(e),
        }
        let whole = bytes.len() / RECORD_LEN;
        let mut marks = Marks::default();
        let mut count = 0u64;
        for i in 0..whole {
            let rec = &bytes[i * RECORD_LEN..(i + 1) * RECORD_LEN];
            let last = i + 1 == whole && bytes.len() % RECORD_LEN == 0;
            match decode(rec, owner, network) {
                Ok(m) => {
                    marks.raise_to(&m);
                    count += 1;
                }
                Err(DecodeError::Checksum) if last => {
                    // A torn trailing write — the same crash the block log
                    // tolerates. Dropping it loses at most the one duty whose
                    // fsync had not returned, which was therefore never
                    // signed.
                    eprintln!(
                        "slashdb: dropping a torn trailing record in {} (crash mid-append)",
                        path.display()
                    );
                }
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{} record {i}: {}. This file is the only thing standing between \
                             this validator and a slashable double signature; it will not be \
                             guessed at. Refusing to start.",
                            path.display(),
                            e.describe()
                        ),
                    ))
                }
            }
        }
        if bytes.len() % RECORD_LEN != 0 {
            eprintln!(
                "slashdb: dropping a truncated trailing record in {} (crash mid-append)",
                path.display()
            );
        }
        Ok((marks, count))
    }
}

enum DecodeError {
    Magic,
    Version,
    Owner,
    Network,
    Checksum,
}

impl DecodeError {
    fn describe(&self) -> &'static str {
        match self {
            DecodeError::Magic => "not a bloch-pos slashing-protection record",
            DecodeError::Version => "unknown slashing-protection schema version",
            DecodeError::Owner => {
                "belongs to a DIFFERENT validator key. A whole-datadir copy between boxes \
                 running different validators would have imported another validator's \
                 maxima; copy blocks.log and meta.bin only"
            }
            DecodeError::Network => "belongs to a different network (genesis digest mismatch)",
            DecodeError::Checksum => "checksum mismatch (corrupt record)",
        }
    }
}

fn encode(m: &Marks, owner: &[u8; 32], network: &[u8; 32]) -> [u8; RECORD_LEN] {
    let mut out = [0u8; RECORD_LEN];
    out[0..8].copy_from_slice(MAGIC);
    out[8..12].copy_from_slice(&VERSION.to_le_bytes());
    let mut flags = 0u32;
    if m.has_attested {
        flags |= FLAG_HAS_ATTESTED;
    }
    if m.has_proposed {
        flags |= FLAG_HAS_PROPOSED;
    }
    out[12..16].copy_from_slice(&flags.to_le_bytes());
    out[16..48].copy_from_slice(owner);
    out[48..80].copy_from_slice(network);
    out[80..88].copy_from_slice(&m.attested_slot.to_le_bytes());
    out[88..96].copy_from_slice(&m.source_epoch.to_le_bytes());
    out[96..104].copy_from_slice(&m.target_epoch.to_le_bytes());
    out[104..112].copy_from_slice(&m.proposed_slot.to_le_bytes());
    let sum: [u8; 32] = Sha3_256::digest(&out[0..112]).into();
    out[112..120].copy_from_slice(&sum[..8]);
    out
}

fn decode(rec: &[u8], owner: &[u8; 32], network: &[u8; 32]) -> Result<Marks, DecodeError> {
    if &rec[0..8] != MAGIC {
        return Err(DecodeError::Magic);
    }
    if u32::from_le_bytes(rec[8..12].try_into().unwrap()) != VERSION {
        return Err(DecodeError::Version);
    }
    let sum: [u8; 32] = Sha3_256::digest(&rec[0..112]).into();
    if rec[112..120] != sum[..8] {
        return Err(DecodeError::Checksum);
    }
    if &rec[16..48] != owner {
        return Err(DecodeError::Owner);
    }
    if &rec[48..80] != network {
        return Err(DecodeError::Network);
    }
    let flags = u32::from_le_bytes(rec[12..16].try_into().unwrap());
    Ok(Marks {
        has_attested: flags & FLAG_HAS_ATTESTED != 0,
        attested_slot: u64::from_le_bytes(rec[80..88].try_into().unwrap()),
        source_epoch: u64::from_le_bytes(rec[88..96].try_into().unwrap()),
        target_epoch: u64::from_le_bytes(rec[96..104].try_into().unwrap()),
        has_proposed: flags & FLAG_HAS_PROPOSED != 0,
        proposed_slot: u64::from_le_bytes(rec[104..112].try_into().unwrap()),
    })
}

/// `fsync`, and on Darwin `F_FULLFSYNC` first.
///
/// macOS's `fsync(2)` returns once the data reaches the drive's write cache,
/// not the platter. The fleet is Linux, where `fsync` means what this fence
/// needs; asking for `F_FULLFSYNC` on the developer machine keeps the local
/// test from proving something the production kernel does not do. A refusal
/// from `F_FULLFSYNC` (some filesystems do not implement it) falls through to
/// the ordinary `fsync` rather than failing the duty.
fn fsync_hard(f: &File) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: `f` owns the fd for the duration of the call.
        let rc = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_FULLFSYNC) };
        if rc != -1 {
            return Ok(());
        }
    }
    f.sync_all()
}

// ────────────────────────────────────────────────────────────────────────────
// Verification by violation
// ────────────────────────────────────────────────────────────────────────────
//
// Every test below first REPRODUCES the offence against the guard as it was —
// the three lines quoted at the top of this file, transcribed verbatim — and
// only then shows the fence refusing it. Where "before" produces two
// attestations, they are real hybrid ML-DSA-65 ‖ Falcon-1024 signatures over
// real `AttestationData` signing roots, and the verdict is not this module's
// opinion: the pair is handed to the pure consensus crate's
// `SlashingEvidence::offense()`, which is the same code the chain would use
// to slash for it.
#[cfg(test)]
mod tests {
    use super::*;
    use bloch_pos_committee::attestation::{Attestation, AttestationData, SignatureVerifier};
    use bloch_pos_committee::slashing::{SlashableOffense, SlashingEvidence};
    use bloch_pos_committee::{epoch_of, params::SLOTS_PER_EPOCH};
    use crate::keys::{HybridVerifier, Keystore};
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;

    /// Genesis digest of the throwaway network these tests pretend to be on.
    const NET: [u8; 32] = [0x44; 32];
    /// Slot cadence quoted from the live manifest, so the "step the clock back
    /// 60 s" arithmetic below is the arithmetic the fleet actually does.
    const SLOT_MS: u64 = 30_000;

    // ── The guard as it was ─────────────────────────────────────────────────

    /// Transcribed from `engine.rs`, not paraphrased:
    ///
    /// ```text
    /// let mut last_attested: u64 = engine.state.slot();   // :2569
    /// if !in_grace && slot > last_attested {              // :2611
    ///     engine.attest(slot);
    ///     last_attested = slot;
    /// }
    /// ```
    ///
    /// `on_boot` is `:2569` — the seed is the chain head, which is why every
    /// restart re-opens every slot the head does not contain.
    struct OldGuard {
        last_attested: u64,
    }
    impl OldGuard {
        fn on_boot(head_slot: u64) -> Self {
            OldGuard { last_attested: head_slot }
        }
        fn may_attest(&mut self, slot: u64) -> bool {
            if slot > self.last_attested {
                self.last_attested = slot;
                true
            } else {
                false
            }
        }
    }

    // ── Plumbing ────────────────────────────────────────────────────────────

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    impl Tmp {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    fn tmp(tag: &str) -> Tmp {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir()
            .join(format!("bloch-slashdb-{tag}-{}-{nanos}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("tmp dir");
        Tmp(d)
    }

    /// The attestation a run released, as it would have hit the wire.
    /// Written to a file because the process that produced it is about to be
    /// killed, and the point of the test is what escaped before it died.
    fn write_att(path: &Path, att: &Attestation) {
        let d = &att.data;
        let mut out = Vec::new();
        out.extend_from_slice(&att.validator.to_le_bytes());
        out.extend_from_slice(&d.slot.to_le_bytes());
        out.extend_from_slice(&d.source_epoch.to_le_bytes());
        out.extend_from_slice(&d.target_epoch.to_le_bytes());
        out.extend_from_slice(&d.head);
        out.extend_from_slice(&d.source_root);
        out.extend_from_slice(&d.target_root);
        out.extend_from_slice(&(att.signature.len() as u32).to_le_bytes());
        out.extend_from_slice(&att.signature);
        fs::write(path, out).expect("write attestation artifact");
    }
    fn read_att(path: &Path) -> Attestation {
        let b = fs::read(path).expect("read attestation artifact");
        let g8 = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let g32 = |o: usize| -> [u8; 32] { b[o..o + 32].try_into().unwrap() };
        Attestation {
            validator: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            data: AttestationData {
                slot: g8(4),
                source_epoch: g8(12),
                target_epoch: g8(20),
                head: g32(28),
                source_root: g32(60),
                target_root: g32(92),
            },
            signature: b[128..].to_vec(),
        }
    }

    fn att_data(slot: u64, head: u8) -> AttestationData {
        AttestationData {
            slot,
            head: [head; 32],
            source_epoch: epoch_of(slot).saturating_sub(1),
            source_root: [0x11; 32],
            target_epoch: epoch_of(slot),
            target_root: [0x22; 32],
        }
    }

    /// Re-invoke this very test binary as a child, running exactly the
    /// `child_process_body` test below, with `env` set. Returns the exit
    /// status. This is a real `fork`+`exec`, so "restart" and "kill the
    /// process" below mean what they say.
    fn spawn_child(env: &[(&str, String)]) -> std::process::ExitStatus {
        let exe = std::env::current_exe().expect("current_exe");
        let mut c = Command::new(exe);
        c.args([
            "--exact",
            "slashdb::tests::child_process_body",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ]);
        for (k, v) in env {
            c.env(k, v);
        }
        c.env("BLOCH_FENCE_CHILD", "1");
        c.output().expect("spawn child").status
    }

    fn killed_by_sigkill(st: &std::process::ExitStatus) -> bool {
        st.signal() == Some(libc::SIGKILL)
    }

    /// The body a spawned child runs. `#[ignore]` so it never runs as part of
    /// the suite — only when a parent names it explicitly.
    ///
    /// Modes:
    /// - `old`  — the pre-fence guard. Seeds from the chain head, signs,
    ///            *broadcasts* (writes the artifact), then dies.
    /// - `new`  — the fence. `attest_with` persists, then signs, then writes.
    /// - `new-crash-in-sign` — the fence, killed from *inside* the signing
    ///            closure: after the fsync returned, before any signature
    ///            exists. The crash window the old code could not have.
    #[test]
    #[ignore = "spawned by other tests as a child process"]
    fn child_process_body() {
        if std::env::var("BLOCH_FENCE_CHILD").is_err() {
            return;
        }
        let dir = PathBuf::from(std::env::var("BLOCH_FENCE_DIR").unwrap());
        let mode = std::env::var("BLOCH_FENCE_MODE").unwrap();

        // The lock-only modes hold no key and must not load one: a process
        // that is about to be refused the data directory has no business
        // touching the keystore in it.
        match mode.as_str() {
            "hold-lock" => {
                let _lock = DirLock::acquire(&dir).expect("child: acquire lock");
                fs::write(dir.join("locked.flag"), b"1").expect("flag");
                // Hold it until the parent kills us — uncleanly, on purpose.
                std::thread::sleep(std::time::Duration::from_secs(120));
                return;
            }
            "try-lock" => match DirLock::acquire(&dir) {
                Ok(_) => std::process::exit(0),
                Err(e) => {
                    println!("CHILD-LOCK-REFUSED: {e}");
                    std::process::exit(18);
                }
            },
            _ => {}
        }

        let out = PathBuf::from(std::env::var("BLOCH_FENCE_OUT").unwrap_or_default());
        let head: u8 = std::env::var("BLOCH_FENCE_HEAD").unwrap().parse().unwrap();
        // The wall clock, injected. `engine.rs` computes
        // `slot = (now_ms() - genesis_ms) / slot_ms`; the child does the same
        // arithmetic over a `now` the parent chooses, which is how a backward
        // clock step is expressed here.
        let now_ms: u64 = std::env::var("BLOCH_FENCE_NOW_MS").unwrap().parse().unwrap();
        let genesis_ms: u64 = std::env::var("BLOCH_FENCE_GENESIS_MS").unwrap().parse().unwrap();
        let slot = (now_ms - genesis_ms) / SLOT_MS;
        let head_slot: u64 = std::env::var("BLOCH_FENCE_HEAD_SLOT").unwrap().parse().unwrap();

        let ks = Keystore::load(&dir).expect("child: load keystore");
        let data = att_data(slot, head);

        match mode.as_str() {
            "old" => {
                // engine.rs:2569 — reseeded from the chain head on every boot.
                let mut guard = OldGuard::on_boot(head_slot);
                // engine.rs:2611
                if guard.may_attest(slot) {
                    let sig = ks.sign(&data.signing_root());
                    let att = Attestation { data, validator: ks.index, signature: sig };
                    // engine.rs:1021 — `self.net.broadcast(...)`. Once this
                    // returns the signature is on the wire and nothing can
                    // recall it.
                    write_att(&out, &att);
                }
                // The crash. Between broadcasting and persisting anything —
                // a window that is the whole lifetime of the process, because
                // nothing is ever persisted.
                unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
            }
            "new" | "new-crash-in-sign" => {
                let mut fence =
                    SlashingProtection::open(&dir, &ks.pubkey, &NET).expect("child: open fence");
                let crash_in_sign = mode == "new-crash-in-sign";
                let r = fence.attest_with(
                    slot,
                    data.source_epoch,
                    data.target_epoch,
                    || {
                        if crash_in_sign {
                            // Killed AFTER the fence is durable and BEFORE any
                            // signature exists. This is the ordering under
                            // test: if the fence were written after signing,
                            // this kill would leave a released signature and
                            // an unarmed fence.
                            unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
                        }
                        ks.sign(&data.signing_root())
                    },
                );
                match r {
                    Ok(sig) => {
                        let att = Attestation { data, validator: ks.index, signature: sig };
                        write_att(&out, &att);
                        println!("CHILD: attested slot {slot}");
                    }
                    Err(e) => {
                        println!("CHILD-REFUSED: {e}");
                        std::process::exit(17);
                    }
                }
                unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
            }
            other => panic!("unknown child mode {other}"),
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // VIOLATION 1 — kill the process between signing and persisting
    // ────────────────────────────────────────────────────────────────────────

    /// **Before.** Two real processes, one keystore, one slot. The first signs
    /// slot 100 against head `0xA1` and is `SIGKILL`ed the instant after the
    /// broadcast — exactly the crash the brief asks for. The restart re-seeds
    /// the guard from the chain head (slot 95, because the node's own vote
    /// produced no block and the blocks that would have advanced the head are
    /// not applied yet) and signs slot 100 again, now against head `0xB2`.
    ///
    /// The verdict is not this test's: the pair goes to the pure consensus
    /// crate, which calls it `DoubleVote`. Both signatures verify under the
    /// validator's own registered key, which is what makes it slashable rather
    /// than merely embarrassing.
    #[test]
    fn violation_1_before_crash_between_signing_and_persisting_double_signs() {
        let dir = tmp("v1-before");
        let ks = Keystore::generate(dir.path(), 0).expect("devnet keystore");
        let verifier = HybridVerifier::new(vec![ks.pubkey.clone()]);
        let genesis_ms = 1_000_000u64;
        let slot = 100u64;
        let now = genesis_ms + slot * SLOT_MS;

        for (n, head) in [(1u8, 0xA1u8), (2, 0xB2)] {
            let st = spawn_child(&[
                ("BLOCH_FENCE_DIR", dir.path().display().to_string()),
                ("BLOCH_FENCE_MODE", "old".into()),
                ("BLOCH_FENCE_OUT", dir.path().join(format!("att{n}.bin")).display().to_string()),
                ("BLOCH_FENCE_HEAD", head.to_string()),
                ("BLOCH_FENCE_NOW_MS", now.to_string()),
                ("BLOCH_FENCE_GENESIS_MS", genesis_ms.to_string()),
                // engine.rs:2569's seed: the chain head, NOT what was signed.
                ("BLOCH_FENCE_HEAD_SLOT", "95".to_string()),
            ]);
            assert!(killed_by_sigkill(&st), "run {n} must die by SIGKILL, got {st:?}");
        }

        let a = read_att(&dir.path().join("att1.bin"));
        let b = read_att(&dir.path().join("att2.bin"));
        assert_eq!(a.data.slot, 100);
        assert_eq!(b.data.slot, 100);
        assert_ne!(a.data.head, b.data.head, "two different heads for one slot");
        assert!(
            verifier.verify(a.validator, &a.data.signing_root(), &a.signature),
            "the first signature is valid under the validator's own key"
        );
        assert!(
            verifier.verify(b.validator, &b.data.signing_root(), &b.signature),
            "the second signature is valid under the validator's own key"
        );
        let ev = SlashingEvidence { first: a, second: b };
        assert_eq!(
            ev.offense(),
            Ok(SlashableOffense::DoubleVote),
            "the chain's own slashing code must call this an offence — otherwise \
             the test is not reproducing the incident"
        );
        println!(
            "BEFORE(v1): two valid signatures for slot 100, adjudicated DoubleVote, \
             evidence id {}",
            crate::codec::hex8(&ev.id())
        );
    }

    /// **After.** Same crash, same restart. The first run is killed from
    /// *inside* the signing closure: the fence is already durable, no
    /// signature was ever produced. The second run — a genuine restart of a
    /// genuine process — is refused.
    ///
    /// The cost is named rather than hidden: that slot's attestation is lost.
    /// Losing one vote is the safe side of this trade and the only side that
    /// is not slashable. The last assertion shows the fence is a floor and not
    /// a brick: the next epoch's duty is allowed.
    #[test]
    fn violation_1_after_the_fence_is_durable_before_the_signature_exists() {
        let dir = tmp("v1-after");
        let ks = Keystore::generate(dir.path(), 0).expect("devnet keystore");
        let genesis_ms = 1_000_000u64;
        let slot = 100u64;
        let now = genesis_ms + slot * SLOT_MS;

        let st = spawn_child(&[
            ("BLOCH_FENCE_DIR", dir.path().display().to_string()),
            ("BLOCH_FENCE_MODE", "new-crash-in-sign".into()),
            ("BLOCH_FENCE_OUT", dir.path().join("att1.bin").display().to_string()),
            ("BLOCH_FENCE_HEAD", "161".to_string()),
            ("BLOCH_FENCE_NOW_MS", now.to_string()),
            ("BLOCH_FENCE_GENESIS_MS", genesis_ms.to_string()),
            ("BLOCH_FENCE_HEAD_SLOT", "95".to_string()),
        ]);
        assert!(killed_by_sigkill(&st), "the first run must die by SIGKILL, got {st:?}");
        assert!(
            !dir.path().join("att1.bin").exists(),
            "no signature escaped: the process died before the closure could sign"
        );

        // The restart. Same slot, different head — the exact input that
        // produced the offence above.
        let st = spawn_child(&[
            ("BLOCH_FENCE_DIR", dir.path().display().to_string()),
            ("BLOCH_FENCE_MODE", "new".into()),
            ("BLOCH_FENCE_OUT", dir.path().join("att2.bin").display().to_string()),
            ("BLOCH_FENCE_HEAD", "178".to_string()),
            ("BLOCH_FENCE_NOW_MS", now.to_string()),
            ("BLOCH_FENCE_GENESIS_MS", genesis_ms.to_string()),
            ("BLOCH_FENCE_HEAD_SLOT", "95".to_string()),
        ]);
        assert_eq!(st.code(), Some(17), "the restart must be REFUSED, got {st:?}");
        assert!(
            !dir.path().join("att2.bin").exists(),
            "and refused before signing, not after"
        );

        // The fence survived the kill, and it is a floor rather than a brick.
        let fence = SlashingProtection::open(dir.path(), &ks.pubkey, &NET).expect("reopen");
        assert_eq!(fence.marks().attested_slot, 100, "the durable record is the killed run's");
        let st = spawn_child(&[
            ("BLOCH_FENCE_DIR", dir.path().display().to_string()),
            ("BLOCH_FENCE_MODE", "new".into()),
            ("BLOCH_FENCE_OUT", dir.path().join("att3.bin").display().to_string()),
            ("BLOCH_FENCE_HEAD", "200".to_string()),
            (
                "BLOCH_FENCE_NOW_MS",
                (genesis_ms + (slot + SLOTS_PER_EPOCH) * SLOT_MS).to_string(),
            ),
            ("BLOCH_FENCE_GENESIS_MS", genesis_ms.to_string()),
            ("BLOCH_FENCE_HEAD_SLOT", "95".to_string()),
        ]);
        assert!(killed_by_sigkill(&st), "the next epoch's duty must be allowed, got {st:?}");
        assert!(
            dir.path().join("att3.bin").exists(),
            "a fence that refuses the next epoch too is an outage, not a fence"
        );
    }

    /// The ordering itself, proved rather than assumed: inside the signing
    /// closure — the moment before the signature exists — the record is
    /// already readable from a *freshly opened* file descriptor with the new
    /// slot in it.
    ///
    /// A fence written after signing would fail this: the read would see the
    /// old value, or no file at all.
    #[test]
    fn the_record_is_on_disk_before_the_signing_closure_runs() {
        let dir = tmp("ordering");
        let ks = Keystore::generate(dir.path(), 0).expect("devnet keystore");
        let mut fence = SlashingProtection::open(dir.path(), &ks.pubkey, &NET).expect("open");
        let path = fence.path().to_path_buf();
        let owner = SlashingProtection::owner_of(&ks.pubkey);

        let seen_at_sign_time = fence
            .attest_with(77, 1, 2, || {
                // A fresh open, not the handle the fence holds — this reads
                // what the filesystem would give a different process.
                let (m, n) = SlashingProtection::read_file(&path, &owner, &NET)
                    .expect("read the fence from disk, mid-sign");
                assert!(n >= 1, "at least one durable record exists before signing");
                m
            })
            .expect("allowed");
        assert!(seen_at_sign_time.has_attested);
        assert_eq!(
            seen_at_sign_time.attested_slot, 77,
            "the slot was durable BEFORE the closure ran, not after it returned"
        );
        assert_eq!(seen_at_sign_time.target_epoch, 2);
    }

    /// The other half of the ordering: when the record cannot be made durable,
    /// the closure is never reached. Not signing is the safe side of an I/O
    /// error, and the caller cannot opt out of that.
    #[test]
    fn a_fence_that_cannot_be_persisted_refuses_to_sign() {
        let dir = tmp("io-fail");
        let ks = Keystore::generate(dir.path(), 0).expect("devnet keystore");
        let mut fence = SlashingProtection::open(dir.path(), &ks.pubkey, &NET).expect("open");
        // Swap the append handle for a read-only one: `write_all` now fails
        // with EBADF, which is an ordinary `commit` failure.
        fence.file = File::open(fence.path()).expect("read-only handle");

        let mut signed = false;
        let r = fence.attest_with(5, 0, 1, || {
            signed = true;
        });
        assert!(matches!(r, Err(Refusal::Io(_))), "expected an I/O refusal, got {r:?}");
        assert!(!signed, "the signing closure must not run when the fence is not durable");
    }

    // ────────────────────────────────────────────────────────────────────────
    // VIOLATION 2 — step the clock back 60 s across a restart
    // ────────────────────────────────────────────────────────────────────────

    /// **Before.** 60 s is two slots at `slot_ms = 30_000`. The node votes
    /// slot 100 (epoch 3), restarts, the clock is 60 s behind, and the wall
    /// slot is now 98 — still epoch 3. `last_attested` was re-seeded from the
    /// chain head at 95, `98 > 95` holds, and the node signs a second
    /// attestation for the same target epoch against a different head.
    ///
    /// Note what is *not* required for this: no malice, no second process, no
    /// reorg. A restart plus NTP.
    #[test]
    fn violation_2_before_a_backward_clock_step_reopens_a_voted_epoch() {
        let dir = tmp("v2-before");
        let ks = Keystore::generate(dir.path(), 0).expect("devnet keystore");
        let verifier = HybridVerifier::new(vec![ks.pubkey.clone()]);
        let genesis_ms = 1_000_000u64;
        let t1 = genesis_ms + 100 * SLOT_MS;
        let t2 = t1 - 60_000; // NTP steps back one minute across the restart.

        for (n, head, now) in [(1u8, 0xA1u8, t1), (2, 0xB2, t2)] {
            let st = spawn_child(&[
                ("BLOCH_FENCE_DIR", dir.path().display().to_string()),
                ("BLOCH_FENCE_MODE", "old".into()),
                ("BLOCH_FENCE_OUT", dir.path().join(format!("att{n}.bin")).display().to_string()),
                ("BLOCH_FENCE_HEAD", head.to_string()),
                ("BLOCH_FENCE_NOW_MS", now.to_string()),
                ("BLOCH_FENCE_GENESIS_MS", genesis_ms.to_string()),
                ("BLOCH_FENCE_HEAD_SLOT", "95".to_string()),
            ]);
            assert!(killed_by_sigkill(&st), "run {n} ends by SIGKILL, got {st:?}");
        }
        let a = read_att(&dir.path().join("att1.bin"));
        let b = read_att(&dir.path().join("att2.bin"));
        assert_eq!((a.data.slot, b.data.slot), (100, 98), "the clock went backwards");
        assert_eq!(
            (a.data.target_epoch, b.data.target_epoch),
            (3, 3),
            "two slots apart is the same epoch, so the same target"
        );
        assert!(verifier.verify(a.validator, &a.data.signing_root(), &a.signature));
        assert!(verifier.verify(b.validator, &b.data.signing_root(), &b.signature));
        assert_eq!(
            SlashingEvidence { first: a, second: b }.offense(),
            Ok(SlashableOffense::DoubleVote),
            "adjudicated by the pure crate"
        );
    }

    /// **After.** Identical inputs. The guard is monotone in *persisted*
    /// state, so the backward step is a slot regression against a durable
    /// number and never reaches the signing closure. `SystemTime` is not
    /// consulted anywhere in the decision.
    #[test]
    fn violation_2_after_the_guard_is_monotone_in_persisted_state_not_the_clock() {
        let dir = tmp("v2-after");
        Keystore::generate(dir.path(), 0).expect("devnet keystore");
        let genesis_ms = 1_000_000u64;
        let t1 = genesis_ms + 100 * SLOT_MS;
        let t2 = t1 - 60_000;

        let st = spawn_child(&[
            ("BLOCH_FENCE_DIR", dir.path().display().to_string()),
            ("BLOCH_FENCE_MODE", "new".into()),
            ("BLOCH_FENCE_OUT", dir.path().join("att1.bin").display().to_string()),
            ("BLOCH_FENCE_HEAD", "161".to_string()),
            ("BLOCH_FENCE_NOW_MS", t1.to_string()),
            ("BLOCH_FENCE_GENESIS_MS", genesis_ms.to_string()),
            ("BLOCH_FENCE_HEAD_SLOT", "95".to_string()),
        ]);
        assert!(killed_by_sigkill(&st), "the first duty is allowed, got {st:?}");
        assert!(dir.path().join("att1.bin").exists());

        let st = spawn_child(&[
            ("BLOCH_FENCE_DIR", dir.path().display().to_string()),
            ("BLOCH_FENCE_MODE", "new".into()),
            ("BLOCH_FENCE_OUT", dir.path().join("att2.bin").display().to_string()),
            ("BLOCH_FENCE_HEAD", "178".to_string()),
            ("BLOCH_FENCE_NOW_MS", t2.to_string()),
            ("BLOCH_FENCE_GENESIS_MS", genesis_ms.to_string()),
            ("BLOCH_FENCE_HEAD_SLOT", "95".to_string()),
        ]);
        assert_eq!(st.code(), Some(17), "the rewound slot must be refused, got {st:?}");
        assert!(!dir.path().join("att2.bin").exists(), "and no second signature exists");
    }

    /// The clock claim, isolated: the fence's decision is a pure function of
    /// the persisted marks and the arguments. Move the system clock however
    /// you like — the same call is refused, because nothing in the path reads
    /// a clock.
    #[test]
    fn the_fence_reads_no_clock() {
        let dir = tmp("noclock");
        let ks = Keystore::generate(dir.path(), 0).expect("devnet keystore");
        let mut fence = SlashingProtection::open(dir.path(), &ks.pubkey, &NET).expect("open");
        fence.attest_with(1_000, 30, 31, || ()).expect("first");
        for slot in [1_000u64, 999, 500, 0] {
            let r = fence.attest_with(slot, 30, 31, || ());
            assert!(
                matches!(r, Err(Refusal::AttestSlotRegression { .. })),
                "slot {slot} must be refused regardless of wall time, got {r:?}"
            );
        }
        // Surround and double-vote, the two offences a slot rule alone misses.
        assert!(matches!(
            fence.attest_with(1_001, 30, 31, || ()),
            Err(Refusal::DoubleVote { .. })
        ));
        assert!(matches!(
            fence.attest_with(1_002, 29, 32, || ()),
            Err(Refusal::SurroundVote { .. })
        ));
        fence.attest_with(1_002, 30, 32, || ()).expect("an honest next-epoch vote is allowed");
    }

    // ────────────────────────────────────────────────────────────────────────
    // VIOLATION 3 — two processes on one data dir
    // ────────────────────────────────────────────────────────────────────────

    /// **Before.** `Store::open` takes no lock, so one data dir opens twice in
    /// one process, let alone two. The two nodes then sign for the same slot
    /// against the heads they each believe — which is the incident: 48
    /// validators, 364 double-head slots, no clock anomaly required.
    #[test]
    fn violation_3_before_two_openers_share_one_data_dir_and_double_sign() {
        let dir = tmp("v3-before");
        let ks = Keystore::generate(dir.path(), 0).expect("devnet keystore");
        let verifier = HybridVerifier::new(vec![ks.pubkey.clone()]);

        // The real `Store::open`, twice, on one directory. Both succeed.
        let a = crate::store::Store::open(dir.path(), &NET).expect("first opener");
        let b = crate::store::Store::open(dir.path(), &NET).expect("second opener");
        drop((a, b));

        // And what two such processes then do. Two real processes, one
        // keystore, one slot, two heads.
        let genesis_ms = 1_000_000u64;
        let now = genesis_ms + 100 * SLOT_MS;
        for (n, head) in [(1u8, 0xA1u8), (2, 0xB2)] {
            let st = spawn_child(&[
                ("BLOCH_FENCE_DIR", dir.path().display().to_string()),
                ("BLOCH_FENCE_MODE", "old".into()),
                ("BLOCH_FENCE_OUT", dir.path().join(format!("att{n}.bin")).display().to_string()),
                ("BLOCH_FENCE_HEAD", head.to_string()),
                ("BLOCH_FENCE_NOW_MS", now.to_string()),
                ("BLOCH_FENCE_GENESIS_MS", genesis_ms.to_string()),
                ("BLOCH_FENCE_HEAD_SLOT", "95".to_string()),
            ]);
            assert!(killed_by_sigkill(&st));
        }
        let a = read_att(&dir.path().join("att1.bin"));
        let b = read_att(&dir.path().join("att2.bin"));
        assert!(verifier.verify(a.validator, &a.data.signing_root(), &a.signature));
        assert!(verifier.verify(b.validator, &b.data.signing_root(), &b.signature));
        assert_eq!(
            SlashingEvidence { first: a, second: b }.offense(),
            Ok(SlashableOffense::DoubleVote)
        );
    }

    /// **After.** The second process fails at startup, loudly, before it can
    /// load a key — an error the operator reads, not a slashable event they
    /// discover from the chain.
    ///
    /// This is the case the twelve classic boxes are one `systemctl start`
    /// away from: 64 armed `validator.key` copies, units disabled but not
    /// masked, every index simultaneously active on the live chain.
    #[test]
    fn violation_3_after_a_second_process_on_one_data_dir_is_refused_at_startup() {
        let dir = tmp("v3-after");
        let _held = DirLock::acquire(dir.path()).expect("first process takes the lock");

        let err = DirLock::acquire(dir.path()).expect_err("the second must be refused");
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
        assert!(
            err.to_string().contains("already holds"),
            "the error must name the cause: {err}"
        );

        // And across processes, which is the case that matters.
        let st = spawn_child(&[
            ("BLOCH_FENCE_DIR", dir.path().display().to_string()),
            ("BLOCH_FENCE_MODE", "try-lock".into()),
            ("BLOCH_FENCE_HEAD", "0".into()),
            ("BLOCH_FENCE_NOW_MS", "0".into()),
            ("BLOCH_FENCE_GENESIS_MS", "0".into()),
            ("BLOCH_FENCE_HEAD_SLOT", "0".into()),
        ]);
        assert_eq!(st.code(), Some(18), "a second process must be refused, got {st:?}");
    }

    // ────────────────────────────────────────────────────────────────────────
    // VIOLATION 4 — an unclean shutdown must not become an outage
    // ────────────────────────────────────────────────────────────────────────

    /// A lock that survives a crash and blocks a legitimate restart is its own
    /// outage. `flock(2)` is released by the kernel when the holder dies,
    /// however it dies — so a `SIGKILL`ed node's successor starts immediately,
    /// with no file to delete and no `--force` to learn.
    ///
    /// Both halves are asserted: the lock *was* held (a concurrent attempt is
    /// refused while the holder lives), and it is *gone* the moment the holder
    /// is killed — while the `LOCK` file itself is still on disk, so nothing
    /// about the recovery depends on cleanup.
    #[test]
    fn violation_4_the_lock_does_not_survive_the_process_that_held_it() {
        let dir = tmp("v4");
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = Command::new(exe)
            .args([
                "--exact",
                "slashdb::tests::child_process_body",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("BLOCH_FENCE_CHILD", "1")
            .env("BLOCH_FENCE_DIR", dir.path())
            .env("BLOCH_FENCE_MODE", "hold-lock")
            .env("BLOCH_FENCE_HEAD", "0")
            .env("BLOCH_FENCE_NOW_MS", "0")
            .env("BLOCH_FENCE_GENESIS_MS", "0")
            .env("BLOCH_FENCE_HEAD_SLOT", "0")
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn the lock holder");

        let flag = dir.path().join("locked.flag");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !flag.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(flag.exists(), "the child never reported holding the lock");

        // It really is held.
        assert_eq!(
            DirLock::acquire(dir.path()).expect_err("held").kind(),
            io::ErrorKind::AddrInUse
        );

        // The unclean shutdown: SIGKILL, no unwinding, no Drop, no cleanup.
        unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
        let st = child.wait().expect("reap");
        assert_eq!(st.signal(), Some(libc::SIGKILL));

        // The successor starts. Immediately, and with the LOCK file still
        // sitting there — the lock is the flock, not the file.
        assert!(dir.path().join(LOCK_FILE).exists(), "the lock FILE outlives the process");
        let recovered = DirLock::acquire(dir.path())
            .expect("a legitimate restart after a crash must not be blocked");
        assert!(recovered.path().exists());
    }

    // ────────────────────────────────────────────────────────────────────────
    // VIOLATION 5 — the store transplant
    // ────────────────────────────────────────────────────────────────────────

    /// Transplanting a canonical `blocks.log` is the established repair. It
    /// must neither break the fence nor defeat it, and the reason it does
    /// neither is that the fence is keyed to the validator key and lives in
    /// its own file.
    ///
    /// Both directions are checked: a *longer* foreign log does not raise the
    /// fence (so a transplant cannot be used to skip a slot the fence still
    /// forbids), and an *empty* log does not lower it (so the repair cannot
    /// unarm the node it repairs).
    #[test]
    fn violation_5_a_blocks_log_transplant_neither_breaks_nor_defeats_the_fence() {
        let good = tmp("v5-donor");
        let sick = tmp("v5-patient");
        let ks = Keystore::generate(sick.path(), 7).expect("devnet keystore");

        let mut fence = SlashingProtection::open(sick.path(), &ks.pubkey, &NET).expect("open");
        fence.attest_with(500, 14, 15, || ()).expect("a vote at slot 500");
        fence.propose_with(500, || ()).expect("and a block at slot 500");
        drop(fence);

        // A donor store with a long canonical log, and the transplant itself:
        // the documented repair copies blocks.log (+ meta.bin), nothing else.
        {
            let mut donor = crate::store::Store::open(good.path(), &NET).expect("donor store");
            for slot in 1..=9u64 {
                donor.append(&sample_envelope(slot)).expect("append");
            }
        }
        fs::copy(good.path().join("blocks.log"), sick.path().join("blocks.log"))
            .expect("transplant the block log");
        fs::copy(good.path().join("meta.bin"), sick.path().join("meta.bin")).expect("and meta");

        let mut fence = SlashingProtection::open(sick.path(), &ks.pubkey, &NET).expect("reopen");
        assert_eq!(
            fence.marks().attested_slot,
            500,
            "the transplant did not move the fence"
        );
        assert!(
            matches!(
                fence.attest_with(500, 14, 15, || ()),
                Err(Refusal::AttestSlotRegression { .. })
            ),
            "still armed after the repair"
        );
        assert!(matches!(
            fence.propose_with(500, || ()),
            Err(Refusal::ProposeSlotRegression { .. })
        ));

        // And the other direction: wiping the log entirely — the harsher
        // repair — leaves the fence exactly where it was.
        fs::remove_file(sick.path().join("blocks.log")).expect("wipe the log");
        let fence = SlashingProtection::open(sick.path(), &ks.pubkey, &NET).expect("reopen");
        assert_eq!(fence.marks().attested_slot, 500);
        assert_eq!(fence.marks().proposed_slot, 500);
    }

    /// The failure a whole-datadir `rsync` between two boxes would cause: box
    /// B would inherit box A's validator's maxima. It is refused by name, at
    /// open, before a key is used for anything.
    #[test]
    fn violation_5_a_fence_from_another_validator_is_refused_by_name() {
        let a = tmp("v5-vA");
        let b = tmp("v5-vB");
        let ka = Keystore::generate(a.path(), 0).expect("key A");
        let kb = Keystore::generate(b.path(), 1).expect("key B");
        let mut fa = SlashingProtection::open(a.path(), &ka.pubkey, &NET).expect("open A");
        fa.attest_with(900, 27, 28, || ()).expect("A votes");
        drop(fa);

        fs::copy(a.path().join(FENCE_FILE), b.path().join(FENCE_FILE)).expect("careless rsync");
        let err = SlashingProtection::open(b.path(), &kb.pubkey, &NET)
            .expect_err("must refuse another validator's fence");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("DIFFERENT validator"), "{err}");

        // Same file, same key, a different network: also refused.
        let other_net = [0x55u8; 32];
        let err = SlashingProtection::open(a.path(), &ka.pubkey, &other_net)
            .expect_err("must refuse another network's fence");
        assert!(err.to_string().contains("different network"), "{err}");
    }

    /// Moving a validator *legitimately* — the same key to a new box — carries
    /// the fence forward. Import only ever raises, so a wrong or stale file
    /// costs availability and can never unarm the fence.
    #[test]
    fn importing_a_fence_only_ever_raises_it() {
        let dir = tmp("import");
        let ks = Keystore::generate(dir.path(), 0).expect("devnet keystore");
        let mut fence = SlashingProtection::open(dir.path(), &ks.pubkey, &NET).expect("open");
        fence.attest_with(100, 2, 3, || ()).expect("vote");

        fence
            .import(Marks { has_attested: true, attested_slot: 50, source_epoch: 1, target_epoch: 1, ..Default::default() })
            .expect("import a stale record");
        assert_eq!(fence.marks().attested_slot, 100, "a stale import must not lower the floor");
        assert_eq!(fence.marks().target_epoch, 3);

        fence
            .import(Marks { has_attested: true, attested_slot: 400, source_epoch: 11, target_epoch: 12, has_proposed: true, proposed_slot: 399 })
            .expect("import a newer record");
        assert_eq!(fence.marks().attested_slot, 400);
        assert_eq!(fence.marks().proposed_slot, 399);
        assert!(matches!(
            fence.attest_with(300, 11, 12, || ()),
            Err(Refusal::AttestSlotRegression { .. })
        ));

        // And it is durable, not just in memory.
        drop(fence);
        let fence = SlashingProtection::open(dir.path(), &ks.pubkey, &NET).expect("reopen");
        assert_eq!(fence.marks().attested_slot, 400);
    }

    // ── Durability of the record itself ─────────────────────────────────────

    /// A torn trailing record is the crash the append-and-fsync shape allows,
    /// and it must cost at most the one duty whose fsync had not returned —
    /// never a lower floor. A corrupt record anywhere else is a refusal to
    /// start, because guessing could lower it.
    #[test]
    fn a_torn_trailing_record_is_dropped_and_a_corrupt_middle_one_refuses() {
        let dir = tmp("torn");
        let ks = Keystore::generate(dir.path(), 0).expect("devnet keystore");
        let mut fence = SlashingProtection::open(dir.path(), &ks.pubkey, &NET).expect("open");
        fence.attest_with(10, 0, 1, || ()).expect("first");
        fence.attest_with(42, 1, 2, || ()).expect("second");
        let path = fence.path().to_path_buf();
        drop(fence);

        // Torn tail: a full-length record whose checksum no longer holds.
        let mut bytes = fs::read(&path).expect("read");
        assert_eq!(bytes.len(), 2 * RECORD_LEN);
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        fs::write(&path, &bytes).expect("write");
        let fence = SlashingProtection::open(dir.path(), &ks.pubkey, &NET).expect("torn tail is ok");
        assert_eq!(fence.marks().attested_slot, 10, "falls back to the last durable record");
        drop(fence);

        // Truncated tail: fewer bytes than a record.
        fs::write(&path, &bytes[..RECORD_LEN + 7]).expect("write");
        let fence = SlashingProtection::open(dir.path(), &ks.pubkey, &NET).expect("short tail is ok");
        assert_eq!(fence.marks().attested_slot, 10);
        drop(fence);

        // Corrupt middle: refuse.
        let mut bytes3 = fs::read(&path).expect("read");
        bytes3.truncate(RECORD_LEN);
        bytes3[0] ^= 0xFF; // record 0 of 2 once we append a good one
        let mut good = SlashingProtection::open(dir.path(), &ks.pubkey, &NET).expect("open");
        good.attest_with(99, 2, 3, || ()).expect("append a good record");
        drop(good);
        let mut all = fs::read(&path).expect("read");
        all[0] ^= 0xFF;
        fs::write(&path, &all).expect("write");
        let err = SlashingProtection::open(dir.path(), &ks.pubkey, &NET)
            .expect_err("a corrupt non-trailing record must refuse to start");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// Compaction keeps the file bounded and can never lower the floor.
    #[test]
    fn compaction_preserves_the_maxima() {
        let dir = tmp("compact");
        let ks = Keystore::generate(dir.path(), 0).expect("devnet keystore");
        let mut fence = SlashingProtection::open(dir.path(), &ks.pubkey, &NET).expect("open");
        // The rewrite path, not the constant: 4,096 F_FULLFSYNCs to reach the
        // real threshold would make this test a minute long and prove nothing
        // extra. The production value is asserted separately, below.
        let threshold = 8u64;
        fence.compact_after = threshold;
        for slot in 1..=(threshold + 5) {
            fence.attest_with(slot, 0, slot, || ()).expect("vote");
        }
        let len = fs::metadata(fence.path()).expect("stat").len();
        assert!(
            len <= (threshold + 6) * RECORD_LEN as u64,
            "the log is bounded, {len} bytes"
        );
        assert!(len < 8 * RECORD_LEN as u64, "and was actually compacted, {len} bytes");
        assert_eq!(COMPACT_AFTER, 4_096, "the value a node actually runs with");
        let top = fence.marks();
        drop(fence);
        let fence = SlashingProtection::open(dir.path(), &ks.pubkey, &NET).expect("reopen");
        assert_eq!(fence.marks(), top, "compaction preserved every maximum");
    }

    fn sample_envelope(slot: u64) -> bloch_pos_committee::header::BlockEnvelope {
        use bloch_pos_committee::header::{BlockEnvelope, BlockHeaderV4, Body, VERSION_G4};
        BlockEnvelope {
            header: BlockHeaderV4 {
                version: VERSION_G4,
                parent: [1; 32],
                state_root: [2; 32],
                body_root: [3; 32],
                slot,
                proposer_index: 0,
                randao_reveal: [4; 32],
                randao_mix: [5; 32],
                justified_root: [6; 32],
                finalized_root: [7; 32],
                attestation_root: [8; 32],
                coherence_root: [9; 32],
            },
            proposer_sig: vec![0xAA; 32],
            body: Body { transactions: Vec::new(), attestations: Vec::new() },
        }
    }
}
