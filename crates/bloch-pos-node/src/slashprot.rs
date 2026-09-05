// SPDX-License-Identifier: AGPL-3.0-or-later

//! Slashing protection: the last-signed watermarks, on disk, **before** the
//! signature exists.
//!
//! ## Why this file exists
//!
//! Genesis-4 punishes equivocation. `slashing.rs` in the pure crate takes a
//! pair of conflicting messages from one validator index and burns stake for
//! it; `finality.rs` additionally makes an equivocator count toward *no*
//! target, so a validator that signs twice in one epoch loses its vote as
//! well as part of its stake. Both of those are *detection*. Until this
//! module there was no *prevention*: nothing in the node structurally stopped
//! it from producing a second signature for a duty it had already signed.
//!
//! That is not a theoretical gap. Every one of these is an ordinary operator
//! action on the live fleet:
//!
//! - a node is restarted inside the slot it just attested in, replays, and
//!   reaches the same duty again;
//! - a keystore is copied to a second box "to have a spare" and both run;
//! - the wall clock steps backwards (NTP correction) and the slot loop
//!   revisits slots that were already signed.
//!
//! In all three the honest node signs twice, and honest intent is not a
//! defence: the evidence is the two signatures.
//!
//! ## The ordering rule, and why the API is a closure
//!
//! A watermark that is written *after* the signature is released protects
//! nothing — the crash window is exactly the window that matters. So the
//! signing call is passed *in*, and this module runs it only after the new
//! watermark has been written and `fsync`-ed:
//!
//! ```text
//!   check guards → write watermark → fsync → THEN call sign()
//! ```
//!
//! Taking the closure is what makes that ordering structural rather than a
//! convention a future edit can quietly break: a caller cannot obtain a
//! signature from this module without the durable write having already
//! happened, because the closure is the only thing that produces one and this
//! module owns when it runs. The ordering test reads the file back through a
//! *fresh descriptor from inside the closure*, so it observes what a separate
//! process would have observed at the instant the signature was made.
//!
//! ## What is guarded
//!
//! Proposals: the slot must strictly exceed the last proposed slot.
//!
//! Attestations: the slot must strictly exceed the last attested slot, the
//! target epoch must strictly exceed the last target epoch (a double vote in
//! this protocol is *any two different attestations sharing a target epoch* —
//! see `AttestationData::is_double_vote`, which compares target epochs and
//! then `self != other`, so differing only in slot or head is enough), and
//! the source epoch may not go backwards (that is the surrounding half of
//! `AttestationData::surrounds`).
//!
//! Strict target-epoch monotonicity costs an honest validator nothing here
//! because Genesis-4's epoch committees **partition** the active set — the
//! comment on `committees::total_active_stake` states it: "every validator
//! gets exactly one chance to contribute". One duty per epoch is the honest
//! maximum, so refusing the second is refusing an offence.
//!
//! ## Failure posture
//!
//! Unreadable or corrupt watermark file = refuse to open. A node that cannot
//! prove what it has already signed must not sign; that is the whole point,
//! and "assume nothing was signed" is the one recovery that can get a
//! validator slashed.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use sha3::digest::{ExtendableOutput, Update, XofReader};

/// File name inside the data dir.
pub const FILE_NAME: &str = "slashing_protection.bin";

const MAGIC: &[u8; 8] = b"BPOSSLP1";
const VERSION: u32 = 1;
/// magic ‖ version ‖ 4 × u64 ‖ 32-byte digest.
const RECORD_LEN: usize = 8 + 4 + 8 * 4 + 32;
/// `None`, on disk. No real slot or epoch can reach it.
const NONE: u64 = u64::MAX;

/// The last-signed watermarks. `None` = nothing of that kind signed yet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Watermarks {
    pub proposal_slot: Option<u64>,
    pub attestation_slot: Option<u64>,
    pub source_epoch: Option<u64>,
    pub target_epoch: Option<u64>,
}

/// Why a signature was refused. Every variant names the offence it prevented,
/// because an operator reading this line needs to know whether the node is
/// broken or was just stopped from slashing itself.
#[derive(Debug)]
pub enum Refusal {
    /// Would have been a second block for a slot at or below the watermark.
    Proposal { slot: u64, watermark: u64 },
    /// Would have been a second attestation for a slot at or below the watermark.
    AttestationSlot { slot: u64, watermark: u64 },
    /// Would have shared a target epoch with an attestation already signed —
    /// a double vote under `AttestationData::is_double_vote`.
    DoubleVote { target_epoch: u64, watermark: u64 },
    /// Source epoch going backwards — the surrounding half of `surrounds`.
    SurroundVote { source_epoch: u64, watermark: u64 },
    /// The watermark could not be made durable. The signature was NOT made.
    Io(io::Error),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Proposal { slot, watermark } => write!(
                f,
                "slashing protection: refusing to propose for slot {slot}; slot {watermark} \
                 is already signed (a second block here is a proposer offence)"
            ),
            Refusal::AttestationSlot { slot, watermark } => write!(
                f,
                "slashing protection: refusing to attest at slot {slot}; slot {watermark} \
                 is already signed"
            ),
            Refusal::DoubleVote { target_epoch, watermark } => write!(
                f,
                "slashing protection: refusing to attest to target epoch {target_epoch}; \
                 target epoch {watermark} is already signed (double vote)"
            ),
            Refusal::SurroundVote { source_epoch, watermark } => write!(
                f,
                "slashing protection: refusing to attest from source epoch {source_epoch}; \
                 source epoch {watermark} is already signed (surround vote)"
            ),
            Refusal::Io(e) => write!(
                f,
                "slashing protection: refusing to sign because the watermark could not be \
                 made durable: {e}"
            ),
        }
    }
}

/// The watermark file, loaded, plus the durable write that must precede any
/// signature this node makes.
///
/// `Debug` is derivable and derived: nothing here is secret — two paths and
/// four integers — and tests need it to report a refusal.
#[derive(Debug)]
pub struct SlashingProtection {
    path: PathBuf,
    dir: PathBuf,
    wm: Watermarks,
}

impl SlashingProtection {
    /// Load (or initialize) `dir/slashing_protection.bin`.
    ///
    /// A missing file is a fresh validator: all watermarks `None`. A file
    /// that does not decode is an error, never a reset.
    pub fn open(dir: &Path) -> io::Result<SlashingProtection> {
        fs::create_dir_all(dir)?;
        let path = dir.join(FILE_NAME);
        let wm = match fs::read(&path) {
            Ok(bytes) => decode(&bytes).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{} is corrupt. This node cannot prove which duties it has already \
                         signed, so it will not sign. Restore the file from the box's backup \
                         (deleting it re-arms double-signing).",
                        path.display()
                    ),
                )
            })?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Watermarks::default(),
            Err(e) => return Err(e),
        };
        Ok(SlashingProtection { path, dir: dir.to_path_buf(), wm })
    }

    /// The loaded watermarks. Read-only: the only writer is a guarded sign.
    pub fn watermarks(&self) -> Watermarks {
        self.wm
    }

    /// Sign a block proposal for `slot`, or refuse.
    ///
    /// `sign` runs **only after** the new watermark is on disk and fsync-ed.
    pub fn guard_proposal<T>(
        &mut self,
        slot: u64,
        sign: impl FnOnce() -> T,
    ) -> Result<T, Refusal> {
        if let Some(w) = self.wm.proposal_slot {
            if slot <= w {
                return Err(Refusal::Proposal { slot, watermark: w });
            }
        }
        let next = Watermarks { proposal_slot: Some(slot), ..self.wm };
        self.commit(next)?;
        Ok(sign())
    }

    /// Sign an attestation for `slot` linking `source_epoch → target_epoch`,
    /// or refuse.
    ///
    /// `sign` runs **only after** the new watermark is on disk and fsync-ed.
    pub fn guard_attestation<T>(
        &mut self,
        slot: u64,
        source_epoch: u64,
        target_epoch: u64,
        sign: impl FnOnce() -> T,
    ) -> Result<T, Refusal> {
        if let Some(w) = self.wm.attestation_slot {
            if slot <= w {
                return Err(Refusal::AttestationSlot { slot, watermark: w });
            }
        }
        if let Some(w) = self.wm.target_epoch {
            if target_epoch <= w {
                return Err(Refusal::DoubleVote { target_epoch, watermark: w });
            }
        }
        if let Some(w) = self.wm.source_epoch {
            if source_epoch < w {
                return Err(Refusal::SurroundVote { source_epoch, watermark: w });
            }
        }
        let next = Watermarks {
            attestation_slot: Some(slot),
            source_epoch: Some(source_epoch),
            target_epoch: Some(target_epoch),
            ..self.wm
        };
        self.commit(next)?;
        Ok(sign())
    }

    /// Write `next` durably, then adopt it in memory.
    ///
    /// Temp file + fsync + rename + fsync of the directory: a crash leaves
    /// either the old record or the new one, and a `rename` that the reader
    /// can see is a `rename` the next boot will see. In-memory state moves
    /// only after all of that returns, so a failed write can never leave this
    /// process believing a watermark that is not on disk.
    fn commit(&mut self, next: Watermarks) -> Result<(), Refusal> {
        self.write_durably(next).map_err(Refusal::Io)?;
        self.wm = next;
        Ok(())
    }

    fn write_durably(&self, next: Watermarks) -> io::Result<()> {
        let tmp = self.path.with_extension("bin.tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&encode(&next))?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        // The rename itself must be durable, or a crash can resurrect the
        // previous watermark and re-arm the duty this call just consumed.
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }
}

fn encode(wm: &Watermarks) -> Vec<u8> {
    let mut out = Vec::with_capacity(RECORD_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    for v in [wm.proposal_slot, wm.attestation_slot, wm.source_epoch, wm.target_epoch] {
        out.extend_from_slice(&v.unwrap_or(NONE).to_le_bytes());
    }
    out.extend_from_slice(&digest(&out));
    out
}

fn decode(bytes: &[u8]) -> Option<Watermarks> {
    if bytes.len() != RECORD_LEN
        || &bytes[..8] != MAGIC
        || bytes[8..12] != VERSION.to_le_bytes()
        || bytes[RECORD_LEN - 32..] != digest(&bytes[..RECORD_LEN - 32])
    {
        return None;
    }
    let field = |i: usize| {
        let at = 12 + i * 8;
        let v = u64::from_le_bytes(bytes[at..at + 8].try_into().ok()?);
        Some((v != NONE).then_some(v))
    };
    Some(Watermarks {
        proposal_slot: field(0)?,
        attestation_slot: field(1)?,
        source_epoch: field(2)?,
        target_epoch: field(3)?,
    })
}

/// SHAKE-256/32 over the record body — a torn write is detected, not adopted.
/// The same XOF the rest of the tree hashes with; nothing here is consensus.
fn digest(body: &[u8]) -> [u8; 32] {
    let mut x = sha3::Shake256::default();
    x.update(body);
    let mut out = [0u8; 32];
    x.finalize_xof().read(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    struct Dir(PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn dir(tag: &str) -> Dir {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "bloch-slashprot-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        Dir(p)
    }

    /// Read the watermark file the way a *separate process* would: a fresh
    /// descriptor, opened now, no shared state with the `SlashingProtection`
    /// that wrote it.
    fn read_fresh(path: &Path) -> Watermarks {
        let mut f = File::open(path).expect("the watermark file must exist by now");
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes).expect("read");
        decode(&bytes).expect("decode")
    }

    /// **The ordering claim.** The watermark is durable BEFORE the signature
    /// is released.
    ///
    /// Proved from inside the signing closure, through a fresh descriptor —
    /// the state a crash (or a second process) would find at the instant the
    /// signature came into existence. Moving the write after the closure, or
    /// dropping the fsync ordering so the in-memory value moves first, makes
    /// this fail: the closure reads a file that either does not exist or
    /// still carries the old watermark.
    #[test]
    fn watermark_is_durable_before_the_signature_exists() {
        let d = dir("order");
        let mut sp = SlashingProtection::open(&d.0).expect("open");
        let path = d.0.join(FILE_NAME);

        let sig = sp
            .guard_attestation(9, 1, 2, || {
                let seen = read_fresh(&path);
                assert_eq!(
                    seen.attestation_slot,
                    Some(9),
                    "the signature is being made before the watermark is on disk — a crash \
                     in this window re-arms the duty and the node double-signs"
                );
                assert_eq!(seen.target_epoch, Some(2));
                assert_eq!(seen.source_epoch, Some(1));
                "signature-bytes"
            })
            .expect("first attestation of this slot must be allowed");
        assert_eq!(sig, "signature-bytes", "the guard returns what the closure produced");

        let p = sp
            .guard_proposal(11, || {
                assert_eq!(
                    read_fresh(&path).proposal_slot,
                    Some(11),
                    "the proposal watermark is not durable before the block is signed"
                );
                7u8
            })
            .expect("first proposal of this slot must be allowed");
        assert_eq!(p, 7);
    }

    /// **The restart claim.** A watermark loaded from disk refuses a re-sign
    /// of a duty the previous process already signed.
    ///
    /// This is the restart-inside-the-slot case: the node comes back, replays,
    /// reaches the same duty. Without the loaded watermark it signs again.
    #[test]
    fn a_restart_refuses_to_re_sign_an_already_signed_slot() {
        let d = dir("restart");
        {
            let mut sp = SlashingProtection::open(&d.0).expect("open");
            sp.guard_attestation(5, 1, 2, || ()).expect("first");
            sp.guard_proposal(5, || ()).expect("first");
        } // process ends here

        let mut sp = SlashingProtection::open(&d.0).expect("reopen");
        assert_eq!(sp.watermarks().attestation_slot, Some(5), "the watermark survived");

        let mut signed = false;
        let again = sp.guard_attestation(5, 1, 2, || signed = true);
        assert!(
            matches!(again, Err(Refusal::AttestationSlot { slot: 5, watermark: 5 })),
            "re-signing slot 5 after a restart must be refused, got {again:?}"
        );
        let again = sp.guard_proposal(5, || signed = true);
        assert!(
            matches!(again, Err(Refusal::Proposal { slot: 5, watermark: 5 })),
            "re-proposing slot 5 after a restart must be refused, got {again:?}"
        );
        assert!(!signed, "a refused duty must never reach the signing closure");

        // And the node is not bricked: the next real duty still signs.
        sp.guard_attestation(6, 2, 3, || ()).expect("a genuinely new duty still signs");
        sp.guard_proposal(6, || ()).expect("a genuinely new proposal still signs");
    }

    /// **The double-vote claim.** A second attestation in the same target
    /// epoch is refused even though its slot is new.
    ///
    /// `is_double_vote` is `target_epoch == other.target_epoch && self !=
    /// other`, so two attestations differing only in slot or head are already
    /// slashable evidence. The slot guard alone does not catch that; this is
    /// the guard that does.
    #[test]
    fn a_second_vote_in_one_target_epoch_is_refused() {
        let d = dir("double");
        let mut sp = SlashingProtection::open(&d.0).expect("open");
        sp.guard_attestation(8, 1, 2, || ()).expect("first");

        let mut signed = false;
        let r = sp.guard_attestation(9, 1, 2, || signed = true);
        assert!(
            matches!(r, Err(Refusal::DoubleVote { target_epoch: 2, watermark: 2 })),
            "a later slot in an already-voted target epoch is a double vote, got {r:?}"
        );
        assert!(!signed);
    }

    /// **The surround claim.** A source epoch going backwards is refused.
    #[test]
    fn a_vote_whose_source_goes_backwards_is_refused() {
        let d = dir("surround");
        let mut sp = SlashingProtection::open(&d.0).expect("open");
        sp.guard_attestation(8, 4, 5, || ()).expect("first");

        let mut signed = false;
        // source 2 < 4 with target 9 > 5 surrounds the vote just signed.
        let r = sp.guard_attestation(9, 2, 9, || signed = true);
        assert!(
            matches!(r, Err(Refusal::SurroundVote { source_epoch: 2, watermark: 4 })),
            "a vote reaching back over an already-signed source surrounds it, got {r:?}"
        );
        assert!(!signed);
    }

    /// A corrupt watermark file is a refusal to open, never a silent reset —
    /// "assume nothing was signed" is the recovery that gets a validator
    /// slashed.
    #[test]
    fn a_corrupt_watermark_file_refuses_to_open() {
        let d = dir("corrupt");
        {
            let mut sp = SlashingProtection::open(&d.0).expect("open");
            sp.guard_proposal(3, || ()).expect("sign");
        }
        let path = d.0.join(FILE_NAME);
        let mut bytes = fs::read(&path).expect("read");
        bytes[20] ^= 0xFF; // flip a slot byte; the digest no longer matches
        fs::write(&path, &bytes).expect("write");

        let err = SlashingProtection::open(&d.0).expect_err("must refuse");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// The encoding round-trips, including the `None` sentinel.
    #[test]
    fn watermarks_round_trip() {
        for wm in [
            Watermarks::default(),
            Watermarks {
                proposal_slot: Some(0),
                attestation_slot: Some(u64::MAX - 1),
                source_epoch: None,
                target_epoch: Some(7),
            },
        ] {
            assert_eq!(decode(&encode(&wm)), Some(wm));
        }
    }
}
