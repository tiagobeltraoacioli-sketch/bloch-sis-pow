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
//! RANDAO recommits: persist a bound epoch/generation/commitment/signing-root
//! intent before signing; conflicting or regressing intents are refused. This
//! upgrades local persistence to V3, which older binaries deliberately reject.
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
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use sha3::digest::{ExtendableOutput, Update, XofReader};

/// File name inside the data dir.
pub const FILE_NAME: &str = "slashing_protection.bin";

/// Marker beside the record: this data dir booted a validator key with no
/// record and no host signer anchor, so nothing here says what the key signed
/// before wall slot `<decimal in the file>`. See
/// [`SlashingProtection::settle_missing_history`].
pub const UNPROVEN_FILE_NAME: &str = "slashing_protection.unproven";

/// `--acknowledge-missing-slashing-protection`: the operator states that the
/// key has no signature this node does not know about.
pub const ENV_ACK_MISSING: &str = "BLOCH_ACK_MISSING_SLASHING_PROTECTION";

/// Unbound record: what every fleet node wrote before the binding existed.
const MAGIC_V1: &[u8; 8] = b"BPOSSLP1";
const VERSION_V1: u32 = 1;
/// magic ‖ version ‖ 4 × u64 ‖ 32-byte digest.
const RECORD_LEN_V1: usize = 8 + 4 + 8 * 4 + 32;
/// Bound record (audit round 3, M-8): magic ‖ version ‖ 4 × u64 ‖
/// validator pubkey sha3 ‖ genesis digest ‖ 32-byte digest.
const MAGIC_V2: &[u8; 8] = b"BPOSSLP2";
const VERSION_V2: u32 = 2;
const RECORD_LEN_V2: usize = RECORD_LEN_V1 + 32 + 32;
/// V3 adds a recommit epoch floor and last epoch/generation/commitment/root.
/// Older binaries reject the new magic instead of discarding this protection.
const MAGIC_V3: &[u8; 8] = b"BPOSSLP3";
const VERSION_V3: u32 = 3;
pub const MAX_RECORD_LEN: usize = RECORD_LEN_V2 + 8 + 8 + 4 + 32 + 32;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RecommitIntent {
    epoch: u64,
    generation: u32,
    commitment: [u8; 32],
    signing_root: [u8; 32],
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RecommitProtection {
    /// Conservative offline recovery floor; intents at or below it are refused.
    epoch_floor: Option<u64>,
    intent: Option<RecommitIntent>,
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
    Recommit { epoch: u64, generation: u32, reason: &'static str },
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
            Refusal::Recommit { epoch, generation, reason } => write!(f,
                "slashing protection: refusing RANDAO recommit at epoch {epoch}, generation {generation}: {reason}"),
            Refusal::Io(e) => write!(
                f,
                "slashing protection: refusing to sign because the watermark could not be \
                 made durable: {e}"
            ),
        }
    }
}

/// Whose watermarks these are (audit round 3, M-8).
///
/// A watermark file that is not bound to an identity protects the wrong
/// thing in two ordinary operator moves: a data dir restored from another
/// validator's backup (its watermarks are *lower* than this validator's, so
/// the guard admits a duty this key already signed) and a data dir carried
/// across a network reset (the same slot numbers mean different duties). With
/// the binding, either move is a loud refusal at boot naming the mismatch,
/// instead of a signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    /// SHA3-256 of the validator's suite-enveloped public key — the same
    /// identifier `keygen` and `keys inspect` print.
    pub validator_pubkey_sha3: [u8; 32],
    /// The network digest the data dir was initialised for (`Store::open`).
    pub genesis_digest: [u8; 32],
}

/// The watermark file, loaded, plus the durable write that must precede any
/// signature this node makes.
///
/// `Debug` is derivable and derived: nothing here is secret — two paths,
/// four integers and two public digests — and tests need it to report a
/// refusal.
#[derive(Debug)]
pub struct SlashingProtection {
    path: PathBuf,
    wm: Watermarks,
    /// Identity the file is (or will be, on the next commit) bound to.
    /// `None` only for a caller that supplied none over a legacy file.
    binding: Option<Binding>,
    /// Some means V3 must be retained, including after importing older backups.
    recommit: Option<RecommitProtection>,
    /// Host-level copy of the record outside the data dir
    /// ([`crate::signer_anchor`]). Written after the data-dir record and
    /// before the signature is released, so a restored data dir cannot be
    /// older than this copy without the boot noticing.
    mirror: Option<PathBuf>,
    /// Holds the host-level key lock for as long as this record can sign.
    anchor: Option<crate::signer_anchor::SignerAnchor>,
    /// There was no record file when this was opened: the watermarks are
    /// empty because nothing is known, not because nothing was signed.
    opened_without_record: bool,
    /// Review CR-8: `Some(slot)` while nothing in this data dir or on this
    /// host says what the key signed before wall slot `slot`. A key whose
    /// duties began before that slot must not sign.
    unproven_before_slot: Option<u64>,
    /// The anchor record already existed when this boot attached it. An
    /// anchor created on this boot holds no history and vouches for nothing
    /// (review PER-2).
    anchor_preexisting: bool,
    /// The reference slot above was taken from this boot's wall clock, which
    /// the chain has not confirmed yet (review PER-6).
    reference_from_wall_clock: bool,
}

/// What [`SlashingProtection::settle_missing_history`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MissingHistory {
    /// A record existed (or a host anchor that predates this boot vouches
    /// for a fresh data dir).
    Proven,
    /// No record and no anchor that predates this boot: duties of a key that was active before `slot`
    /// are refused until the operator supplies a record, a floor, or an
    /// acknowledgement.
    Unproven { before_slot: u64 },
    /// The operator acknowledged the missing record; the marker was removed.
    Acknowledged,
}

/// What [`SlashingProtection::attach_anchor`] found when it compared the
/// data-dir record with the host-level anchor copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorCheck {
    /// No anchor existed yet; it now holds a copy of the data-dir record.
    Adopted,
    /// Both copies already agreed.
    InSync,
    /// The anchor lagged (crash between the two writes, or an imported
    /// record); it was raised to the data-dir record.
    AnchorRaised,
    /// The data dir was BEHIND the anchor and the operator accepted it; the
    /// data-dir record was raised to the anchor before any signature.
    DataDirRolledForward,
}

/// Which kind of signature of this key was seen on the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Published {
    Proposal { slot: u64 },
    Attestation { slot: u64, source_epoch: u64, target_epoch: u64 },
}

/// Export a bound record while the validator is stopped. No secret key is read.
pub fn export_bound(dir: &Path, binding: Binding) -> io::Result<Vec<u8>> {
    crate::keys::ensure_mutation_ownership(dir)?;
    let _lock = crate::store::DirLock::acquire(dir)?;
    use std::io::Read;
    let mut record = Vec::new();
    fs::File::open(dir.join(FILE_NAME))?.take(MAX_RECORD_LEN.saturating_add(1) as u64).read_to_end(&mut record)?;
    let (_, actual, _) = decode_record(&record).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid slashing protection record"))?;
    if actual != Some(binding) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "export requires a bound record matching the validator and network"));
    }
    Ok(record)
}

/// Merge a bound backup without ever decreasing a local watermark. This
/// protects local recovery; it cannot stop an old host from signing.
pub fn import_bound(dir: &Path, binding: Binding, bytes: &[u8]) -> io::Result<Watermarks> {
    let (incoming, actual, recommit) = decode_record(bytes).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid slashing protection backup"))?;
    if actual != Some(binding) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "backup validator/network binding mismatch or absent"));
    }
    merge_bound(dir, binding, incoming, recommit)
}

/// Refuse proposal/attestation slots below `min_slot` after recovery. Epoch
/// protection conservatively skips the remainder of its preceding epoch.
/// Operators must independently fence every old host before using this.
pub fn initialize_floor(dir: &Path, binding: Binding, min_slot: u64) -> io::Result<Watermarks> {
    if min_slot == 0 || min_slot == u64::MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "minimum slot must be between 1 and u64::MAX - 1"));
    }
    let slot = min_slot.checked_sub(1).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "minimum slot must be positive"))?;
    let epoch = slot / bloch_pos_committee::params::SLOTS_PER_EPOCH;
    merge_bound(dir, binding, Watermarks {
        proposal_slot: Some(slot), attestation_slot: Some(slot),
        source_epoch: Some(epoch), target_epoch: Some(epoch),
    }, Some(RecommitProtection { epoch_floor: Some(epoch), intent: None }))
}

fn merge_bound(dir: &Path, binding: Binding, incoming: Watermarks, incoming_recommit: Option<RecommitProtection>) -> io::Result<Watermarks> {
    fs::create_dir_all(dir)?;
    crate::keys::ensure_mutation_ownership(dir)?;
    let _lock = crate::store::DirLock::acquire(dir)?;
    let protection = SlashingProtection::open_bound(dir, binding)?;
    let old = protection.watermarks();
    let merged = Watermarks {
        proposal_slot: old.proposal_slot.max(incoming.proposal_slot),
        attestation_slot: old.attestation_slot.max(incoming.attestation_slot),
        source_epoch: old.source_epoch.max(incoming.source_epoch),
        target_epoch: old.target_epoch.max(incoming.target_epoch),
    };
    let recommit = merge_recommit(protection.recommit, incoming_recommit)?;
    protection.write_record(merged, recommit)?;
    // An imported record or an operator floor is the history the marker
    // said was missing (review CR-8).
    remove_unproven_marker(&protection.unproven_marker_path())?;
    Ok(merged)
}

fn remove_unproven_marker(marker: &Path) -> io::Result<()> {
    match fs::remove_file(marker) {
        Ok(()) => {
            if let Some(dir) = marker.parent() {
                fs::File::open(dir)?.sync_all()?;
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

impl SlashingProtection {
    /// Load (or initialize) `dir/slashing_protection.bin` without checking
    /// whose it is. Kept for callers that have no identity to check against
    /// (an observer, tooling, tests); a validator boots through
    /// [`SlashingProtection::open_bound`]. A bound file opened this way keeps
    /// its binding on every write, so this path can never *strip* one.
    ///
    /// A missing file yields empty watermarks. Whether that is a fresh
    /// validator or a lost record is decided by
    /// [`SlashingProtection::settle_missing_history`] at boot. A file that
    /// does not decode is an error, never a reset.
    pub fn open(dir: &Path) -> io::Result<SlashingProtection> {
        Self::open_with(dir, None)
    }

    /// Load (or initialize) the watermarks **for this validator on this
    /// network**, refusing a file written for any other.
    ///
    /// - A `BPOSSLP2` file bound to a different key or network → error naming
    ///   which of the two differs (and both digests, truncated).
    /// - A legacy `BPOSSLP1` file (unbound) → adopted as-is, and bound on its
    ///   next commit; the upgrade is announced on stdout. Nothing about the
    ///   watermarks themselves changes, so the fleet's existing files keep
    ///   protecting exactly what they protected.
    /// - No file → empty watermarks, bound on first commit (and see
    ///   [`SlashingProtection::settle_missing_history`]).
    pub fn open_bound(dir: &Path, binding: Binding) -> io::Result<SlashingProtection> {
        Self::open_with(dir, Some(binding))
    }

    fn open_with(dir: &Path, want: Option<Binding>) -> io::Result<SlashingProtection> {
        fs::create_dir_all(dir)?;
        let path = dir.join(FILE_NAME);
        // A malformed local record must not allocate according to its file size.
        let read_record = || -> io::Result<Vec<u8>> {
            use std::io::Read;
            let mut bytes = Vec::with_capacity(MAX_RECORD_LEN.saturating_add(1));
            fs::File::open(&path)?.take(MAX_RECORD_LEN.saturating_add(1) as u64).read_to_end(&mut bytes)?;
            Ok(bytes)
        };
        let mut opened_without_record = false;
        let (wm, on_disk, recommit) = match read_record() {
            Ok(bytes) => decode_record(&bytes).ok_or_else(|| {
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
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                opened_without_record = true;
                (Watermarks::default(), None, None)
            }
            Err(e) => return Err(e),
        };
        let binding = match (on_disk, want) {
            (Some(file), Some(mine)) if file != mine => {
                let what = match (
                    file.validator_pubkey_sha3 == mine.validator_pubkey_sha3,
                    file.genesis_digest == mine.genesis_digest,
                ) {
                    (false, true) => "a DIFFERENT VALIDATOR KEY",
                    (true, false) => "a DIFFERENT NETWORK",
                    _ => "a different validator key AND a different network",
                };
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{} was written for {what}: file has validator key {} on network {}, this \
                         node is validator key {} on network {}. Refusing to sign: another \
                         validator's watermarks say nothing about what THIS key has signed. \
                         If this data dir was restored from another box's backup, restore this \
                         validator's own slashing_protection.bin (or accept the double-signing \
                         risk explicitly by removing the file).",
                        path.display(),
                        crate::codec::hex8(&file.validator_pubkey_sha3),
                        crate::codec::hex8(&file.genesis_digest),
                        crate::codec::hex8(&mine.validator_pubkey_sha3),
                        crate::codec::hex8(&mine.genesis_digest),
                    ),
                ));
            }
            (Some(file), _) => Some(file),
            (None, Some(mine)) => {
                if path.exists() {
                    println!(
                        "slashing protection: {} is a legacy unbound record; it will be bound to \
                         validator key {} / network {} on its next write",
                        path.display(),
                        crate::codec::hex8(&mine.validator_pubkey_sha3),
                        crate::codec::hex8(&mine.genesis_digest),
                    );
                }
                Some(mine)
            }
            (None, None) => None,
        };
        Ok(SlashingProtection {
            path, wm, binding, recommit, mirror: None, anchor: None,
            opened_without_record, unproven_before_slot: None,
            anchor_preexisting: false, reference_from_wall_clock: false,
        })
    }

    fn unproven_marker_path(&self) -> PathBuf {
        self.path.with_file_name(UNPROVEN_FILE_NAME)
    }

    /// The copy of the marker beside the anchor record. It keeps "unproven"
    /// true when the data dir (and its marker) is wiped after an unproven
    /// boot; without it the anchor that boot created would vouch next time.
    fn anchor_marker_path(&self) -> Option<PathBuf> {
        self.anchor.as_ref().map(|a| a.dir().join(UNPROVEN_FILE_NAME))
    }

    /// Decide, once per boot and BEFORE replay, whether this node knows what
    /// its key has signed (review CR-8). Call after [`Self::attach_anchor`].
    ///
    /// A missing record used to mean "fresh validator". It also describes a
    /// data dir that lost its record (restored without it, wiped for a
    /// resync, key copied to a new directory) for a key that has been signing
    /// for months, and the watermarks are equally empty in both cases. The
    /// host signer anchor tells the two apart on one host, provided it held
    /// this key's record BEFORE this boot; an anchor created on this boot is
    /// the new-host case and says nothing (review PER-2). So when there is no
    /// record and no such anchor, the wall slot of this boot is written to a marker file and kept in
    /// [`Self::unproven_before_slot`]: a key whose duties began before that
    /// slot is refused ([`Self::missing_history_blocks`]); a key activated at
    /// or after it has signed nothing this record did not see, and starts
    /// without ceremony.
    ///
    /// The marker, not the absence of the record, carries the state across
    /// restarts: replay raises the record to the key's on-chain signatures
    /// (which creates the file), and that evidence does not cover votes that
    /// were signed and never included. It is removed by an import or a floor
    /// (`slashing-protection import|set-floor`) or by `acknowledged`. A copy
    /// is kept beside the anchor record when one is attached, so wiping the
    /// data dir after an unproven boot does not turn the anchor that boot
    /// created into proof.
    pub fn settle_missing_history(&mut self, boot_wall_slot: u64, acknowledged: bool) -> io::Result<MissingHistory> {
        let read_marker = |marker: &Path| -> io::Result<Option<u64>> {
            match fs::read(marker) {
                // An unreadable marker still says "unproven"; be conservative
                // about since when.
                Ok(bytes) => Ok(Some(
                    std::str::from_utf8(&bytes).ok().and_then(|t| t.trim().parse::<u64>().ok()).unwrap_or(u64::MAX),
                )),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        };
        let marker = self.unproven_marker_path();
        let anchor_marker = self.anchor_marker_path();
        let in_data_dir = read_marker(&marker)?;
        // The anchor's copy only matters while the data dir has no record of
        // its own: a record with no marker beside it is a known history (it
        // was there all along, or was imported or floored).
        let anchor_copy = match &anchor_marker {
            Some(path) => read_marker(path)?,
            None => None,
        };
        let in_anchor = if self.opened_without_record { anchor_copy } else { None };
        let recorded = in_data_dir.max(in_anchor);
        // A fresh data dir under a host anchor that ALREADY held this key's
        // record is what the anchor is for: a key this host already ran is
        // caught by `attach_anchor`. An anchor created on this boot is as
        // empty as the missing record and proves nothing (review PER-2): that
        // is a key copied to a new host.
        let vouched = recorded.is_none() && self.anchor.is_some() && self.anchor_preexisting;
        if recorded.is_none() && (!self.opened_without_record || vouched) {
            if !self.opened_without_record {
                if let Some(path) = &anchor_marker {
                    remove_unproven_marker(path)?;
                }
            }
            self.unproven_before_slot = None;
            return Ok(MissingHistory::Proven);
        }
        if acknowledged {
            remove_unproven_marker(&marker)?;
            if let Some(path) = &anchor_marker {
                remove_unproven_marker(path)?;
            }
            self.unproven_before_slot = None;
            return Ok(MissingHistory::Acknowledged);
        }
        let before_slot = match recorded {
            Some(slot) if !self.opened_without_record => slot,
            // Only the data dir was lost: the anchor predates this boot and
            // has mirrored every signature since its own marker was written.
            Some(slot) if in_data_dir.is_none() && self.anchor_preexisting => slot,
            // The record went missing (again) now: nothing before THIS boot
            // is known either.
            Some(slot) => {
                self.reference_from_wall_clock = true;
                slot.max(boot_wall_slot)
            }
            None => {
                self.reference_from_wall_clock = true;
                boot_wall_slot
            }
        };
        self.write_unproven_markers(before_slot, in_data_dir, anchor_copy)?;
        self.unproven_before_slot = Some(before_slot);
        Ok(MissingHistory::Unproven { before_slot })
    }

    fn write_unproven_markers(&self, before_slot: u64, in_data_dir: Option<u64>, in_anchor: Option<u64>) -> io::Result<()> {
        let text = before_slot.to_string();
        if in_data_dir != Some(before_slot) {
            crate::store::atomic_private_write(&self.unproven_marker_path(), text.as_bytes())?;
        }
        if let Some(path) = self.anchor_marker_path() {
            if in_anchor != Some(before_slot) {
                crate::store::atomic_private_write(&path, text.as_bytes())?;
            }
        }
        Ok(())
    }

    /// Review PER-6: the reference slot written by
    /// [`Self::settle_missing_history`] on this boot came from the wall clock
    /// alone. A clock at or before genesis (no RTC before NTP, a stepped
    /// clock) makes it 0, which refuses nobody, and the marker would keep
    /// that value for good. Call after replay with the slot of the replayed
    /// head (0 for an empty log, which changes nothing): the chain this node already holds is a lower bound on
    /// "now" that the clock cannot lower. Only raises, and only on the boot
    /// that set the reference; a reference kept from an earlier boot is left
    /// alone, so a validator activated since then is not refused.
    pub fn raise_unproven_reference(&mut self, chain_slot: u64) -> io::Result<()> {
        let Some(before) = self.unproven_before_slot else { return Ok(()) };
        if !self.reference_from_wall_clock || chain_slot <= before {
            return Ok(());
        }
        self.write_unproven_markers(chain_slot, Some(before), Some(before))?;
        self.unproven_before_slot = Some(chain_slot);
        Ok(())
    }

    /// `Some(slot)` while this node cannot say what its key signed before
    /// wall slot `slot` ([`Self::settle_missing_history`]).
    pub fn unproven_before_slot(&self) -> Option<u64> {
        self.unproven_before_slot
    }

    /// Must a validator whose duties began at `activation_epoch` be refused?
    /// True when its first duty slot lies before the slot from which this
    /// record is known to be complete.
    pub fn missing_history_blocks(&self, activation_epoch: u64) -> bool {
        self.unproven_before_slot.is_some_and(|before| {
            activation_epoch.saturating_mul(bloch_pos_committee::params::SLOTS_PER_EPOCH) < before
        })
    }

    /// The refusal, saying exactly what to do.
    pub fn missing_history_refusal(&self, validator: u32, activation_epoch: u64, wall_slot: u64) -> String {
        let dir = self.path.parent().map(|d| d.display().to_string()).unwrap_or_default();
        let (key, network) = match self.binding {
            Some(b) => (crate::codec::hex(&b.validator_pubkey_sha3), crate::codec::hex(&b.genesis_digest)),
            None => ("<validator pubkey sha3>".into(), "<genesis digest>".into()),
        };
        format!(
            "SLASHING PROTECTION MISSING: validator {validator} has had duties on chain since epoch \
             {activation_epoch}, but this data dir had no {FILE_NAME} when it first booted this key \
             (wall slot {}) and no host signer anchor that already held this key's record was in \
             use. This node cannot know which duties \
             the key has already signed, so it REFUSES TO SIGN. First stop and fence every other \
             instance of this key. Then do ONE of: \
             (1) restore the key's record: on the previous data dir run `bloch-pos slashing-protection \
             export --data-dir <old dir> --validator-pubkey-sha3 {key} --genesis-digest {network} --out \
             record.bin`, then here `bloch-pos slashing-protection import --data-dir {dir} \
             --validator-pubkey-sha3 {key} --genesis-digest {network} --in record.bin`; \
             (2) if the record is lost, set a floor above anything the key can have signed (the wall \
             slot is now {wall_slot}): `bloch-pos slashing-protection set-floor --data-dir {dir} \
             --validator-pubkey-sha3 {key} --genesis-digest {network} --min-slot {}`; \
             (3) only if this key has never signed anywhere else, restart with \
             --acknowledge-missing-slashing-protection (or {ENV_ACK_MISSING}=1). \
             To have a lost or rolled-back record detected on this host from now on, give the service \
             a writable --signer-anchor-dir.",
            self.unproven_before_slot.unwrap_or(0),
            wall_slot.saturating_add(1),
        )
    }

    /// The identity the file is bound to (or will be bound to on the next
    /// commit). `None` only for an unbound legacy file opened without one.
    pub fn binding(&self) -> Option<Binding> {
        self.binding
    }

    /// The loaded watermarks. Recovery tooling only advances these floors.
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

    /// Persist a RANDAO signing intent before releasing a signature. Repeating
    /// the exact intent is safe; changing its root within an epoch, changing a
    /// generation's commitment, or moving epoch/generation backwards is not.
    pub fn guard_recommit<T>(
        &mut self, epoch: u64, generation: u32, commitment: [u8; 32], signing_root: [u8; 32],
        sign: impl FnOnce() -> T,
    ) -> Result<T, Refusal> {
        let refusal = |reason| Refusal::Recommit { epoch, generation, reason };
        if self.binding.is_none() { return Err(refusal("an explicit validator/network binding is required")); }
        if epoch == u64::MAX || generation == 0 { return Err(refusal("invalid epoch or generation")); }
        let mut next = self.recommit.unwrap_or_default();
        if next.epoch_floor.is_some_and(|floor| epoch <= floor) { return Err(refusal("at or below the recovery epoch floor")); }
        if let Some(previous) = next.intent {
            if epoch < previous.epoch { return Err(refusal("epoch is below the durable intent")); }
            if generation < previous.generation { return Err(refusal("generation is below the durable intent")); }
            if epoch == previous.epoch && signing_root != previous.signing_root { return Err(refusal("different signing root in an already signed epoch")); }
            if generation == previous.generation && commitment != previous.commitment { return Err(refusal("different commitment for an already used generation")); }
            if epoch == previous.epoch && generation != previous.generation { return Err(refusal("different generation in an already signed epoch")); }
        }
        next.intent = Some(RecommitIntent { epoch, generation, commitment, signing_root });
        self.write_record(self.wm, Some(next)).map_err(Refusal::Io)?;
        self.recommit = Some(next);
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
        self.write_record(next, self.recommit)
    }

    fn write_record(&self, next: Watermarks, recommit: Option<RecommitProtection>) -> io::Result<()> {
        let bytes = if let Some(protection) = recommit {
            let binding = self.binding.as_ref().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "V3 recommit protection requires identity binding"))?;
            encode_v3(&next, binding, &protection)
        } else {
            encode(&next, self.binding.as_ref())
        };
        crate::store::atomic_private_write(&self.path, &bytes)?;
        if let Some(mirror) = &self.mirror {
            crate::store::atomic_private_write(mirror, &bytes)?;
        }
        Ok(())
    }

    /// The bytes this record would have on disk now.
    fn encoded(&self) -> io::Result<Vec<u8>> {
        Ok(match self.recommit {
            Some(protection) => {
                let binding = self.binding.as_ref().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "V3 recommit protection requires identity binding"))?;
                encode_v3(&self.wm, binding, &protection)
            }
            None => encode(&self.wm, self.binding.as_ref()),
        })
    }

    /// Compare this data-dir record with the host-level anchor copy at
    /// `anchor`, then mirror every later write there.
    ///
    /// The anchor lives outside the data dir, so restoring an old data-dir
    /// backup (or starting a fresh data dir for a key this host already ran)
    /// leaves the anchor AHEAD of the record. That is refused unless
    /// `accept_rollback`, in which case the record is raised to the anchor
    /// (monotone, never lowered) before anything can sign. An anchor that
    /// lags is simply raised: that is the crash window between the two
    /// writes, and the data-dir record is the one written first.
    pub fn attach_anchor(&mut self, anchor: crate::signer_anchor::SignerAnchor, accept_rollback: bool) -> io::Result<AnchorCheck> {
        let check = self.attach_anchor_path(&anchor.record_path(), accept_rollback)?;
        self.anchor_preexisting = check != AnchorCheck::Adopted;
        self.anchor = Some(anchor);
        Ok(check)
    }

    fn attach_anchor_path(&mut self, anchor: &Path, accept_rollback: bool) -> io::Result<AnchorCheck> {
        let binding = self.binding.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "a signer anchor requires a bound record"))?;
        let bytes = match fs::read(anchor) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        let Some(bytes) = bytes else {
            crate::store::atomic_private_write(anchor, &self.encoded()?)?;
            self.mirror = Some(anchor.to_path_buf());
            return Ok(AnchorCheck::Adopted);
        };
        let (anchor_wm, anchor_binding, anchor_recommit) = decode_record(&bytes).ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            format!("signer anchor {} is corrupt; refusing to sign. Restore it or remove it deliberately.", anchor.display()),
        ))?;
        if anchor_binding != Some(binding) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!(
                "signer anchor {} is bound to another validator key or network", anchor.display())));
        }
        let merged = max_marks(self.wm, anchor_wm);
        let recommit = merge_recommit(self.recommit, anchor_recommit)?;
        let data_behind = merged != self.wm || recommit != self.recommit;
        let anchor_behind = merged != anchor_wm || recommit != anchor_recommit;
        if data_behind && !accept_rollback {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!(
                "SIGNING ROLLBACK REFUSED: {} is OLDER than this host's signer anchor {} \
                 (data dir {:?}, anchor {:?}). The data dir was restored from a backup, \
                 replaced, or never received this key's record. Signing from it could \
                 repeat a duty this key already signed. Stop every other instance of this \
                 key, then restart with --accept-signing-rollback (raises the record to the \
                 anchor; never lowers it).",
                self.path.display(), anchor.display(), self.wm, anchor_wm)));
        }
        if data_behind {
            self.write_record(merged, recommit)?;
            self.wm = merged;
            self.recommit = recommit;
        }
        self.mirror = Some(anchor.to_path_buf());
        if anchor_behind {
            self.write_record(self.wm, self.recommit)?;
        }
        Ok(if data_behind {
            AnchorCheck::DataDirRolledForward
        } else if anchor_behind {
            AnchorCheck::AnchorRaised
        } else {
            AnchorCheck::InSync
        })
    }

    /// True when `seen` is a signature of this key that the record does not
    /// cover: the record is stale (restored backup) or another instance of
    /// the key is signing. Pure; see [`SlashingProtection::raise_to_published`].
    pub fn is_uncovered(&self, seen: Published) -> bool {
        let above = |value: u64, mark: Option<u64>| mark.is_none_or(|m| value > m);
        match seen {
            Published::Proposal { slot } => above(slot, self.wm.proposal_slot),
            Published::Attestation { slot, target_epoch, .. } => {
                above(slot, self.wm.attestation_slot) || above(target_epoch, self.wm.target_epoch)
            }
        }
    }

    /// Raise the record durably so it covers `seen`. Never lowers anything.
    pub fn raise_to_published(&mut self, seen: Published) -> io::Result<Watermarks> {
        let incoming = match seen {
            Published::Proposal { slot } => Watermarks { proposal_slot: Some(slot), ..Watermarks::default() },
            Published::Attestation { slot, source_epoch, target_epoch } => Watermarks {
                attestation_slot: Some(slot),
                source_epoch: Some(source_epoch),
                target_epoch: Some(target_epoch),
                ..Watermarks::default()
            },
        };
        let next = max_marks(self.wm, incoming);
        if next != self.wm {
            self.write_record(next, self.recommit)?;
            self.wm = next;
        }
        Ok(next)
    }
}

fn max_marks(a: Watermarks, b: Watermarks) -> Watermarks {
    Watermarks {
        proposal_slot: a.proposal_slot.max(b.proposal_slot),
        attestation_slot: a.attestation_slot.max(b.attestation_slot),
        source_epoch: a.source_epoch.max(b.source_epoch),
        target_epoch: a.target_epoch.max(b.target_epoch),
    }
}

/// Monotone max of two bound records for the same identity (export merges
/// the data-dir record with the host anchor this way).
pub fn merge_records(binding: Binding, left: &[u8], right: &[u8]) -> io::Result<Vec<u8>> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "invalid or foreign slashing protection record");
    let (lw, lb, lr) = decode_record(left).ok_or_else(bad)?;
    let (rw, rb, rr) = decode_record(right).ok_or_else(bad)?;
    if lb != Some(binding) || rb != Some(binding) {
        return Err(bad());
    }
    let wm = max_marks(lw, rw);
    Ok(match merge_recommit(lr, rr)? {
        Some(protection) => encode_v3(&wm, &binding, &protection),
        None => encode(&wm, Some(&binding)),
    })
}

fn encode(wm: &Watermarks, binding: Option<&Binding>) -> Vec<u8> {
    let mut out = Vec::with_capacity(RECORD_LEN_V2);
    match binding {
        Some(_) => {
            out.extend_from_slice(MAGIC_V2);
            out.extend_from_slice(&VERSION_V2.to_le_bytes());
        }
        None => {
            out.extend_from_slice(MAGIC_V1);
            out.extend_from_slice(&VERSION_V1.to_le_bytes());
        }
    }
    for v in [wm.proposal_slot, wm.attestation_slot, wm.source_epoch, wm.target_epoch] {
        out.extend_from_slice(&v.unwrap_or(NONE).to_le_bytes());
    }
    if let Some(b) = binding {
        out.extend_from_slice(&b.validator_pubkey_sha3);
        out.extend_from_slice(&b.genesis_digest);
    }
    out.extend_from_slice(&digest(&out));
    out
}

/// All record versions. Length, magic and version must agree with each
/// other AND with the digest, so a V1 body wearing a V2 magic (or the reverse)
/// is corrupt, not a downgrade.
#[cfg(test)]
fn decode(bytes: &[u8]) -> Option<(Watermarks, Option<Binding>)> {
    decode_record(bytes).map(|(marks, binding, _)| (marks, binding))
}

fn decode_record(bytes: &[u8]) -> Option<(Watermarks, Option<Binding>, Option<RecommitProtection>)> {
    let (body_len, bound) = match bytes.len() {
        RECORD_LEN_V1 if &bytes[..8] == MAGIC_V1 && bytes[8..12] == VERSION_V1.to_le_bytes() => {
            (RECORD_LEN_V1 - 32, false)
        }
        RECORD_LEN_V2 if &bytes[..8] == MAGIC_V2 && bytes[8..12] == VERSION_V2.to_le_bytes() => {
            (RECORD_LEN_V2 - 32, true)
        }
        MAX_RECORD_LEN if &bytes[..8] == MAGIC_V3 && bytes[8..12] == VERSION_V3.to_le_bytes() => {
            (MAX_RECORD_LEN - 32, true)
        }
        _ => return None,
    };
    if bytes[body_len..] != digest(&bytes[..body_len]) {
        return None;
    }
    // Field `i` is the i-th 8-byte word after the 12-byte preamble — the
    // same bytes `12 + i * 8 .. 12 + i * 8 + 8` named, walked without the
    // arithmetic. `bytes.len()` is one of the RECORD_LENs matched above,
    // so every field the record defines is present.
    let field = |i: usize| {
        let word = bytes.get(12..)?.chunks_exact(8).nth(i)?;
        let v = u64::from_le_bytes(word.try_into().ok()?);
        Some((v != NONE).then_some(v))
    };
    let wm = Watermarks {
        proposal_slot: field(0)?,
        attestation_slot: field(1)?,
        source_epoch: field(2)?,
        target_epoch: field(3)?,
    };
    let binding = if bound {
        let at = 12 + 4 * 8;
        Some(Binding {
            validator_pubkey_sha3: bytes[at..at + 32].try_into().ok()?,
            genesis_digest: bytes[at + 32..at + 64].try_into().ok()?,
        })
    } else {
        None
    };
    let recommit = if bytes.len() == MAX_RECORD_LEN {
        let floor = u64::from_le_bytes(bytes[108..116].try_into().ok()?);
        let epoch = u64::from_le_bytes(bytes[116..124].try_into().ok()?);
        let generation = u32::from_le_bytes(bytes[124..128].try_into().ok()?);
        let commitment = bytes[128..160].try_into().ok()?;
        let signing_root = bytes[160..192].try_into().ok()?;
        let intent = if epoch == NONE {
            if generation != 0 || commitment != [0; 32] || signing_root != [0; 32] { return None; }
            None
        } else {
            if generation == 0 { return None; }
            Some(RecommitIntent { epoch, generation, commitment, signing_root })
        };
        Some(RecommitProtection { epoch_floor: (floor != NONE).then_some(floor), intent })
    } else { None };
    Some((wm, binding, recommit))
}

fn encode_v3(wm: &Watermarks, binding: &Binding, protection: &RecommitProtection) -> Vec<u8> {
    let mut bytes = encode(wm, Some(binding));
    bytes.truncate(108); // V2 body, before its checksum.
    bytes[..8].copy_from_slice(MAGIC_V3);
    bytes[8..12].copy_from_slice(&VERSION_V3.to_le_bytes());
    bytes.extend_from_slice(&protection.epoch_floor.unwrap_or(NONE).to_le_bytes());
    let intent = protection.intent.unwrap_or(RecommitIntent { epoch: NONE, generation: 0, commitment: [0; 32], signing_root: [0; 32] });
    bytes.extend_from_slice(&intent.epoch.to_le_bytes());
    bytes.extend_from_slice(&intent.generation.to_le_bytes());
    bytes.extend_from_slice(&intent.commitment);
    bytes.extend_from_slice(&intent.signing_root);
    bytes.extend_from_slice(&digest(&bytes));
    bytes
}

fn merge_recommit(left: Option<RecommitProtection>, right: Option<RecommitProtection>) -> io::Result<Option<RecommitProtection>> {
    let (Some(left), Some(right)) = (left, right) else { return Ok(left.or(right)); };
    let intent = match (left.intent, right.intent) {
        (Some(a), Some(b)) => {
            if (a.epoch == b.epoch && a != b)
                || (a.generation == b.generation && a.commitment != b.commitment)
                || (a.epoch < b.epoch && a.generation > b.generation)
                || (b.epoch < a.epoch && b.generation > a.generation) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "conflicting RANDAO intent history; refusing to merge"));
            }
            Some(if a.epoch >= b.epoch { a } else { b })
        }
        (a, b) => a.or(b),
    };
    Ok(Some(RecommitProtection { epoch_floor: left.epoch_floor.max(right.epoch_floor), intent }))
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
    use std::fs::File;

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
        decode(&bytes).expect("decode").0
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
            assert_eq!(decode(&encode(&wm, None)), Some((wm, None)));
            let b = Binding { validator_pubkey_sha3: [0xAB; 32], genesis_digest: [0xCD; 32] };
            assert_eq!(decode(&encode(&wm, Some(&b))), Some((wm, Some(b))));
        }
    }

    // ----- review CR-8: a missing record is not proof of a fresh validator -----

    const EPOCH: u64 = bloch_pos_committee::params::SLOTS_PER_EPOCH;

    /// No record and no anchor: a key that was active before this boot is
    /// refused, a key activated at or after it is not, and the decision
    /// survives the record being created from on-chain evidence and a restart.
    #[test]
    fn a_missing_record_without_an_anchor_refuses_a_key_that_was_already_active() {
        let d = dir("cr8-unproven");
        let boot = 100 * EPOCH + 5;
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        assert_eq!(sp.unproven_before_slot(), None, "inert until the boot settles it");
        assert!(!sp.missing_history_blocks(0));
        assert_eq!(sp.settle_missing_history(boot, false).unwrap(), MissingHistory::Unproven { before_slot: boot });
        assert!(sp.missing_history_blocks(0), "a genesis validator has signed before");
        assert!(sp.missing_history_blocks(100), "epoch 100 began before the boot slot");
        assert!(!sp.missing_history_blocks(101), "activated after this boot: genuinely new");
        assert!(!sp.missing_history_blocks(u64::MAX));
        let message = sp.missing_history_refusal(7, 3, boot + 9);
        for needle in [
            "--acknowledge-missing-slashing-protection",
            "slashing-protection import",
            "set-floor",
            &format!("--min-slot {}", boot + 10),
            &crate::codec::hex(&KEY_A.validator_pubkey_sha3),
            "--signer-anchor-dir",
        ] {
            assert!(message.contains(needle), "refusal must name {needle}: {message}");
        }

        // Replay raises the record to what the chain shows: the file now
        // exists, and that must not look like a known history on restart.
        sp.raise_to_published(Published::Attestation { slot: 40, source_epoch: 0, target_epoch: 1 }).unwrap();
        assert!(d.0.join(FILE_NAME).exists());
        drop(sp);
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        assert_eq!(
            sp.settle_missing_history(boot + 1_000, false).unwrap(),
            MissingHistory::Unproven { before_slot: boot },
            "the first unproven boot stays the reference"
        );
        assert!(sp.missing_history_blocks(100));
    }

    /// A pre-genesis boot of a fresh validator (wall slot 0) blocks nothing.
    #[test]
    fn a_fresh_validator_booting_at_genesis_is_not_refused() {
        let d = dir("cr8-genesis");
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        assert_eq!(sp.settle_missing_history(0, false).unwrap(), MissingHistory::Unproven { before_slot: 0 });
        assert!(!sp.missing_history_blocks(0));
    }

    /// An existing record is a known history: nothing changes for a
    /// validator that upgrades with its record in place.
    #[test]
    fn an_existing_record_is_never_treated_as_unproven() {
        let d = dir("cr8-existing");
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        sp.guard_proposal(9, || ()).unwrap();
        drop(sp);
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        assert_eq!(sp.settle_missing_history(1_000_000, false).unwrap(), MissingHistory::Proven);
        assert!(!sp.missing_history_blocks(0));
        assert!(!d.0.join(UNPROVEN_FILE_NAME).exists());
    }

    /// The three ways out: acknowledgement, a floor, an imported record.
    #[test]
    fn an_acknowledgement_a_floor_or_an_import_clears_the_refusal() {
        // Acknowledgement: one boot, marker removed.
        let d = dir("cr8-ack");
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        sp.settle_missing_history(500, false).unwrap();
        assert!(d.0.join(UNPROVEN_FILE_NAME).exists());
        drop(sp);
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        assert_eq!(sp.settle_missing_history(600, true).unwrap(), MissingHistory::Acknowledged);
        assert!(!sp.missing_history_blocks(0));
        assert!(!d.0.join(UNPROVEN_FILE_NAME).exists());

        // Floor.
        let d = dir("cr8-floor");
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        sp.settle_missing_history(500, false).unwrap();
        drop(sp);
        initialize_floor(&d.0, KEY_A, 501).unwrap();
        assert!(!d.0.join(UNPROVEN_FILE_NAME).exists());
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        assert_eq!(sp.settle_missing_history(700, false).unwrap(), MissingHistory::Proven);
        assert!(!sp.missing_history_blocks(0));
        assert!(sp.guard_proposal(500, || ()).is_err(), "and the floor itself holds");

        // Import.
        let source = dir("cr8-import-src");
        let mut old = SlashingProtection::open_bound(&source.0, KEY_A).unwrap();
        old.guard_proposal(77, || ()).unwrap();
        drop(old);
        let backup = export_bound(&source.0, KEY_A).unwrap();
        let d = dir("cr8-import");
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        sp.settle_missing_history(500, false).unwrap();
        drop(sp);
        import_bound(&d.0, KEY_A, &backup).unwrap();
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        assert_eq!(sp.settle_missing_history(700, false).unwrap(), MissingHistory::Proven);
    }

    /// A host anchor that already held this key's record vouches for a
    /// fresh data dir (it would have refused a key this host already ran).
    /// An anchor created on this very boot does not (review PER-2): that is
    /// a key copied to a new host. It does not lift a refusal that was
    /// already recorded; and losing the record again moves the reference
    /// slot forward.
    #[test]
    fn an_anchor_vouches_only_for_a_fresh_data_dir_and_a_second_loss_moves_the_reference() {
        // The anchor already holds a record from an earlier data dir.
        let root = dir("cr8-anchor-root");
        let old = dir("cr8-anchor-old");
        let mut sp = SlashingProtection::open_bound(&old.0, KEY_A).unwrap();
        sp.guard_proposal(9, || ()).unwrap();
        drop(sp);
        let mut sp = SlashingProtection::open_bound(&old.0, KEY_A).unwrap();
        let held = crate::signer_anchor::SignerAnchor::acquire(&root.0, &KEY_A).unwrap();
        assert_eq!(sp.attach_anchor(held, false).unwrap(), AnchorCheck::Adopted);
        assert_eq!(sp.settle_missing_history(800, false).unwrap(), MissingHistory::Proven, "a record existed");
        drop(sp);
        let d = dir("cr8-anchor");
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        let held = crate::signer_anchor::SignerAnchor::acquire(&root.0, &KEY_A).unwrap();
        assert_eq!(sp.attach_anchor(held, true).unwrap(), AnchorCheck::DataDirRolledForward);
        assert_eq!(sp.settle_missing_history(900, false).unwrap(), MissingHistory::Proven);
        assert!(!d.0.join(UNPROVEN_FILE_NAME).exists());
        assert!(sp.guard_proposal(9, || ()).is_err(), "and the anchor's history holds");
        drop(sp);

        let d = dir("cr8-anchor-late");
        let root = dir("cr8-anchor-late-root");
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        sp.settle_missing_history(900, false).unwrap();
        drop(sp);
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        let held = crate::signer_anchor::SignerAnchor::acquire(&root.0, &KEY_A).unwrap();
        sp.attach_anchor(held, false).unwrap();
        assert_eq!(
            sp.settle_missing_history(2_000, false).unwrap(),
            MissingHistory::Unproven { before_slot: 2_000 },
            "still no record, so nothing before this boot is known either"
        );
        assert!(sp.missing_history_blocks(0));

        // A corrupt marker is conservative: everything is refused.
        fs::write(d.0.join(UNPROVEN_FILE_NAME), b"not a slot").unwrap();
        sp.guard_proposal(3_000, || ()).unwrap();
        drop(sp);
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        assert_eq!(sp.settle_missing_history(4_000, false).unwrap(), MissingHistory::Unproven { before_slot: u64::MAX });
        assert!(sp.missing_history_blocks(u64::MAX / EPOCH - 1));
    }

    /// Review PER-2: no record in the data dir and an anchor that did not
    /// exist before this boot is the host-migration case. The anchor created
    /// now is not proof; the key is refused exactly as with no anchor, and
    /// wiping the data dir afterwards does not turn that anchor into proof.
    #[test]
    fn an_anchor_created_on_this_boot_does_not_vouch_for_a_missing_record() {
        let d = dir("per2-adopted");
        let root = dir("per2-adopted-root");
        let boot = 100 * EPOCH + 5;
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        let held = crate::signer_anchor::SignerAnchor::acquire(&root.0, &KEY_A).unwrap();
        let anchor_dir = held.dir().to_path_buf();
        assert_eq!(sp.attach_anchor(held, false).unwrap(), AnchorCheck::Adopted);
        assert_eq!(sp.settle_missing_history(boot, false).unwrap(), MissingHistory::Unproven { before_slot: boot });
        assert!(sp.missing_history_blocks(100), "a key active before this boot is refused");
        assert!(!sp.missing_history_blocks(101), "a key activated after it is a new validator");
        assert!(d.0.join(UNPROVEN_FILE_NAME).exists());
        assert!(anchor_dir.join(UNPROVEN_FILE_NAME).exists());
        // Replay raises the record (and the anchor) to on-chain signatures.
        sp.raise_to_published(Published::Attestation { slot: 40, source_epoch: 0, target_epoch: 1 }).unwrap();
        drop(sp);

        // The data dir is wiped; the anchor now predates the boot, but it was
        // created by the unproven boot and still says so.
        let d2 = dir("per2-adopted-wiped");
        let mut sp = SlashingProtection::open_bound(&d2.0, KEY_A).unwrap();
        let held = crate::signer_anchor::SignerAnchor::acquire(&root.0, &KEY_A).unwrap();
        assert_eq!(sp.attach_anchor(held, true).unwrap(), AnchorCheck::DataDirRolledForward);
        assert_eq!(
            sp.settle_missing_history(boot + 1_000, false).unwrap(),
            MissingHistory::Unproven { before_slot: boot },
            "the anchor has mirrored every signature since its marker"
        );
        assert!(sp.missing_history_blocks(100));
        drop(sp);

        // An acknowledgement clears both copies.
        let mut sp = SlashingProtection::open_bound(&d2.0, KEY_A).unwrap();
        let held = crate::signer_anchor::SignerAnchor::acquire(&root.0, &KEY_A).unwrap();
        sp.attach_anchor(held, false).unwrap();
        assert_eq!(sp.settle_missing_history(boot + 2_000, true).unwrap(), MissingHistory::Acknowledged);
        assert!(!d2.0.join(UNPROVEN_FILE_NAME).exists());
        assert!(!anchor_dir.join(UNPROVEN_FILE_NAME).exists());
        drop(sp);

        // An import into the data dir is the missing history: the next boot
        // is proven and drops the anchor's copy of the marker.
        let d3 = dir("per2-import");
        let root3 = dir("per2-import-root");
        let mut sp = SlashingProtection::open_bound(&d3.0, KEY_A).unwrap();
        let held = crate::signer_anchor::SignerAnchor::acquire(&root3.0, &KEY_A).unwrap();
        let anchor_dir3 = held.dir().to_path_buf();
        sp.attach_anchor(held, false).unwrap();
        sp.settle_missing_history(boot, false).unwrap();
        drop(sp);
        initialize_floor(&d3.0, KEY_A, boot + 1).unwrap();
        let mut sp = SlashingProtection::open_bound(&d3.0, KEY_A).unwrap();
        let held = crate::signer_anchor::SignerAnchor::acquire(&root3.0, &KEY_A).unwrap();
        assert_eq!(sp.attach_anchor(held, false).unwrap(), AnchorCheck::AnchorRaised);
        assert_eq!(sp.settle_missing_history(boot + 50, false).unwrap(), MissingHistory::Proven);
        assert!(!anchor_dir3.join(UNPROVEN_FILE_NAME).exists());
    }

    /// Review PER-6: a boot whose clock reads at or before genesis writes
    /// reference slot 0, which refuses nobody. The replayed chain is a lower
    /// bound on "now"; the reference is raised to it on that boot, durably,
    /// and a reference kept from an earlier boot is not moved.
    #[test]
    fn a_wall_clock_behind_the_chain_does_not_disarm_the_refusal() {
        let d = dir("per6-clock");
        let head_slot = 50 * EPOCH + 3;
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        assert_eq!(sp.settle_missing_history(0, false).unwrap(), MissingHistory::Unproven { before_slot: 0 });
        assert!(!sp.missing_history_blocks(0), "fixture: slot 0 refuses nobody");
        sp.raise_unproven_reference(head_slot + 1).unwrap();
        assert_eq!(sp.unproven_before_slot(), Some(head_slot + 1));
        assert!(sp.missing_history_blocks(50), "a validator active below the replayed head is refused");
        assert!(!sp.missing_history_blocks(51));
        sp.raise_unproven_reference(7).unwrap();
        assert_eq!(sp.unproven_before_slot(), Some(head_slot + 1), "never lowered");
        sp.raise_to_published(Published::Attestation { slot: 40, source_epoch: 0, target_epoch: 1 }).unwrap();
        drop(sp);

        // Next boot: the raised value is what was stored, and a longer chain
        // does not move a reference this boot did not set.
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        assert_eq!(
            sp.settle_missing_history(90 * EPOCH, false).unwrap(),
            MissingHistory::Unproven { before_slot: head_slot + 1 }
        );
        sp.raise_unproven_reference(80 * EPOCH).unwrap();
        assert_eq!(sp.unproven_before_slot(), Some(head_slot + 1));
        assert!(!sp.missing_history_blocks(60), "a validator activated since the first boot is not refused");

        // A proven record is never touched.
        let d = dir("per6-proven");
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        sp.guard_proposal(9, || ()).unwrap();
        drop(sp);
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        sp.settle_missing_history(0, false).unwrap();
        sp.raise_unproven_reference(1_000).unwrap();
        assert_eq!(sp.unproven_before_slot(), None);
        assert!(!d.0.join(UNPROVEN_FILE_NAME).exists());
    }

    // ----- audit round 3, M-8: the watermark file is bound to an identity -----

    const KEY_A: Binding = Binding { validator_pubkey_sha3: [0xA1; 32], genesis_digest: [0x44; 32] };
    const KEY_B: Binding = Binding { validator_pubkey_sha3: [0xB2; 32], genesis_digest: [0x44; 32] };
    const KEY_A_OTHER_NET: Binding =
        Binding { validator_pubkey_sha3: [0xA1; 32], genesis_digest: [0x55; 32] };

    #[test]
    fn recommit_intent_is_durable_before_signing_and_survives_restart() {
        let d = dir("recommit-order");
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        sp.guard_proposal(1, || ()).unwrap();
        assert_eq!(&fs::read(d.0.join(FILE_NAME)).unwrap()[..8], MAGIC_V2);
        sp.guard_recommit(2884, 1, [7; 32], [8; 32], || {
            let bytes = fs::read(d.0.join(FILE_NAME)).unwrap();
            assert_eq!(bytes.len(), MAX_RECORD_LEN);
            assert_eq!(&bytes[..8], MAGIC_V3);
            let intent = decode_record(&bytes).unwrap().2.unwrap().intent.unwrap();
            assert_eq!(intent.epoch, 2884);
            assert_eq!(intent.signing_root, [8; 32]);
        }).unwrap();
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        sp.guard_proposal(2, || ()).unwrap();
        assert!(sp.guard_recommit(2884, 1, [9; 32], [10; 32], || panic!("conflicting signature")).is_err());
        assert!(sp.guard_recommit(2883, 1, [7; 32], [8; 32], || panic!("old epoch")).is_err());
        sp.guard_recommit(2884, 1, [7; 32], [8; 32], || ()).unwrap();
        sp.guard_recommit(2885, 1, [7; 32], [11; 32], || ()).unwrap();
        sp.guard_recommit(2886, 2, [12; 32], [13; 32], || ()).unwrap();
        assert!(sp.guard_recommit(2887, 1, [7; 32], [14; 32], || panic!("old generation")).is_err());
    }

    #[test]
    fn recommit_write_failure_and_unbound_identity_never_sign() {
        let d = dir("recommit-failure");
        let mut unbound = SlashingProtection::open(&d.0).unwrap();
        assert!(unbound.guard_recommit(10, 1, [1; 32], [2; 32], || panic!("unbound")).is_err());
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        fs::create_dir(d.0.join(FILE_NAME)).unwrap();
        assert!(sp.guard_recommit(10, 1, [1; 32], [2; 32], || panic!("failed persistence")).is_err());
        assert_eq!(sp.recommit, None);
    }

    #[test]
    fn recommit_backup_merge_and_recovery_floor_cannot_drop_history() {
        let source = dir("recommit-source");
        let target = dir("recommit-target");
        let mut sp = SlashingProtection::open_bound(&source.0, KEY_A).unwrap();
        sp.guard_recommit(10, 2, [1; 32], [2; 32], || ()).unwrap();
        let backup = export_bound(&source.0, KEY_A).unwrap();
        import_bound(&target.0, KEY_A, &backup).unwrap();
        let legacy = encode(&Watermarks::default(), Some(&KEY_A));
        import_bound(&target.0, KEY_A, &legacy).unwrap();
        let mut reopened = SlashingProtection::open_bound(&target.0, KEY_A).unwrap();
        assert!(reopened.guard_recommit(11, 1, [3; 32], [4; 32], || panic!("generation rollback")).is_err());
        let before = fs::read(target.0.join(FILE_NAME)).unwrap();
        let conflicting = encode_v3(&Watermarks::default(), &KEY_A, &RecommitProtection {
            epoch_floor: None,
            intent: Some(RecommitIntent { epoch: 10, generation: 2, commitment: [9; 32], signing_root: [9; 32] }),
        });
        assert!(import_bound(&target.0, KEY_A, &conflicting).is_err());
        assert_eq!(fs::read(target.0.join(FILE_NAME)).unwrap(), before);
        initialize_floor(&target.0, KEY_A, 20 * bloch_pos_committee::params::SLOTS_PER_EPOCH).unwrap();
        let mut reopened = SlashingProtection::open_bound(&target.0, KEY_A).unwrap();
        assert!(reopened.guard_recommit(19, 3, [3; 32], [4; 32], || panic!("recovery floor")).is_err());
        assert_eq!(reopened.recommit.unwrap().intent.unwrap().generation, 2);
        let mut corrupted = backup.clone();
        corrupted[128] ^= 1;
        assert!(decode_record(&corrupted).is_none());
        let mut trailing = backup; trailing.push(0);
        assert!(decode_record(&trailing).is_none());
    }

    /// THE regression test for M-8. A watermark file written for validator A
    /// is refused by validator B and by A on another network, and the refusal
    /// names which of the two differs. A itself reopens it with the watermarks
    /// intact.
    #[test]
    fn audit_recovery_is_bound_monotone_and_durable() {
        let source = dir("recovery-source");
        let destination = dir("recovery-destination");
        initialize_floor(&source.0, KEY_A, 97).unwrap();
        let backup = export_bound(&source.0, KEY_A).unwrap();
        assert!(import_bound(&destination.0, KEY_B, &backup).is_err());
        assert!(!destination.0.exists(), "validate before creating recovery state");
        let mut bad = backup.clone(); bad.push(0);
        assert!(import_bound(&destination.0, KEY_A, &bad).is_err());
        import_bound(&destination.0, KEY_A, &backup).unwrap();
        initialize_floor(&destination.0, KEY_A, 193).unwrap();
        let merged = import_bound(&destination.0, KEY_A, &backup).unwrap();
        assert_eq!(merged.proposal_slot, Some(192));
        let mut reopened = SlashingProtection::open_bound(&destination.0, KEY_A).unwrap();
        assert_eq!(reopened.watermarks(), merged);
        assert!(reopened.guard_proposal(192, || panic!("must not sign")).is_err());
        assert!(reopened.guard_attestation(193, 0, 1, || panic!("must not sign")).is_err());
        assert!(initialize_floor(&destination.0, KEY_A, 0).is_err());
        assert!(initialize_floor(&destination.0, KEY_A, u64::MAX).is_err());
        let _lock = crate::store::DirLock::acquire(&destination.0).unwrap();
        assert!(import_bound(&destination.0, KEY_A, &backup).is_err());
        assert!(initialize_floor(&destination.0, KEY_A, 300).is_err());
        assert!(export_bound(&destination.0, KEY_A).is_err());
    }

    #[test]
    fn a_watermark_file_bound_to_another_identity_is_refused_naming_the_mismatch() {
        let d = dir("bound");
        {
            let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).expect("fresh, bound");
            assert_eq!(sp.binding(), Some(KEY_A));
            sp.guard_proposal(5, || ()).expect("first commit writes a V2 record");
        }
        let raw = fs::read(d.0.join(FILE_NAME)).unwrap();
        assert_eq!(&raw[..8], MAGIC_V2);

        let e = SlashingProtection::open_bound(&d.0, KEY_B).err().expect("B must be refused");
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(e.to_string().contains("DIFFERENT VALIDATOR KEY"), "{e}");

        let e = SlashingProtection::open_bound(&d.0, KEY_A_OTHER_NET).err().expect("other net refused");
        assert!(e.to_string().contains("DIFFERENT NETWORK"), "{e}");

        let sp = SlashingProtection::open_bound(&d.0, KEY_A).expect("the owner reopens it");
        assert_eq!(sp.watermarks().proposal_slot, Some(5));
    }

    /// The fleet's existing files are unbound `BPOSSLP1`. They are adopted
    /// with their watermarks, and the first commit binds them; from then on
    /// another identity is refused.
    #[test]
    fn a_legacy_unbound_record_is_adopted_and_bound_on_its_next_commit() {
        let d = dir("legacy");
        let legacy = Watermarks {
            proposal_slot: Some(100),
            attestation_slot: Some(101),
            source_epoch: Some(2),
            target_epoch: Some(3),
        };
        fs::create_dir_all(&d.0).unwrap();
        fs::write(d.0.join(FILE_NAME), encode(&legacy, None)).unwrap();

        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).expect("legacy file adopted");
        assert_eq!(sp.watermarks(), legacy, "watermarks are preserved exactly");
        assert_eq!(sp.binding(), Some(KEY_A));
        // Still refuses what it refused before the binding existed.
        assert!(sp.guard_attestation(101, 2, 3, || ()).is_err());
        sp.guard_attestation(102, 3, 4, || ()).expect("a later duty commits");

        let raw = fs::read(d.0.join(FILE_NAME)).unwrap();
        assert_eq!(&raw[..8], MAGIC_V2, "the commit upgraded the record");
        assert!(SlashingProtection::open_bound(&d.0, KEY_B).is_err());
        assert!(SlashingProtection::open_bound(&d.0, KEY_A).is_ok());
    }

    /// The unbound `open` can never strip a binding: a bound file opened
    /// without an identity keeps its binding on every write.
    #[test]
    fn an_unbound_open_preserves_an_existing_binding() {
        let d = dir("preserve");
        SlashingProtection::open_bound(&d.0, KEY_A)
            .unwrap()
            .guard_proposal(1, || ())
            .unwrap();
        let mut sp = SlashingProtection::open(&d.0).expect("unbound open of a bound file");
        assert_eq!(sp.binding(), Some(KEY_A));
        sp.guard_proposal(2, || ()).unwrap();
        assert!(SlashingProtection::open_bound(&d.0, KEY_B).is_err(), "binding survived");
        assert_eq!(
            SlashingProtection::open_bound(&d.0, KEY_A).unwrap().watermarks().proposal_slot,
            Some(2)
        );
    }

    /// A V1 body wearing the V2 magic (or the reverse) is corrupt, not a
    /// downgrade — the digest covers the header, so neither decodes.
    #[test]
    fn a_relabelled_record_is_corrupt_not_a_version_change() {
        let wm = Watermarks { proposal_slot: Some(9), ..Default::default() };
        let mut v1 = encode(&wm, None);
        v1[..8].copy_from_slice(MAGIC_V2);
        assert_eq!(decode(&v1), None);
        let mut v2 = encode(&wm, Some(&KEY_A));
        v2[..8].copy_from_slice(MAGIC_V1);
        assert_eq!(decode(&v2), None);
        // And flipping one byte of the binding is detected.
        let mut v2 = encode(&wm, Some(&KEY_A));
        v2[12 + 32] ^= 1;
        assert_eq!(decode(&v2), None);
    }

    #[test]
    fn legacy_reservation_survives_restart_and_blocks_old_or_surrounding_duties() {
        use std::process::Command;

        assert_eq!(bloch_pos_committee::params::SLOTS_PER_EPOCH, 32);
        let d = dir("recovery-fence");
        fs::create_dir(&d.0).unwrap();
        let meta = d.0.join("meta.bin");
        let mut bytes = b"BPOSMETA".to_vec();
        bytes.extend_from_slice(&bloch_pos_committee::header::VERSION_G4.to_le_bytes());
        bytes.extend_from_slice(&[2; 32]);
        fs::write(&meta, bytes).unwrap();
        let journal = d.0.join(FILE_NAME);
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/prepare-validator-recovery-fence.py");
        let run = || {
            Command::new("python3")
                .arg(&script)
                .arg("--meta")
                .arg(&meta)
                .arg("--pubkey-hash")
                .arg("01".repeat(32))
                .arg("--through-slot")
                .arg("320")
                .arg("--output")
                .arg(&journal)
                .output()
                .unwrap()
        };
        let prepared = run();
        assert!(
            prepared.status.success(),
            "{}",
            String::from_utf8_lossy(&prepared.stderr)
        );
        let original = fs::read(&journal).unwrap();
        let invalid_output = d.0.join("invalid.bin");
        for slot in ["0", "-1", "18446744073709551615"] {
            let rejected = Command::new("python3")
                .arg(&script)
                .arg("--meta")
                .arg(&meta)
                .arg("--pubkey-hash")
                .arg("01".repeat(32))
                .arg("--through-slot")
                .arg(slot)
                .arg("--output")
                .arg(&invalid_output)
                .output()
                .unwrap();
            assert!(!rejected.status.success());
            assert!(
                !invalid_output.exists(),
                "invalid fence must not create a journal"
            );
        }
        let valid_meta = fs::read(&meta).unwrap();
        fs::write(&meta, [0; 44]).unwrap();
        let rejected = Command::new("python3")
            .arg(&script)
            .arg("--meta")
            .arg(&meta)
            .arg("--pubkey-hash")
            .arg("01".repeat(32))
            .arg("--through-slot")
            .arg("320")
            .arg("--output")
            .arg(&invalid_output)
            .output()
            .unwrap();
        assert!(
            !rejected.status.success(),
            "invalid network metadata must be refused"
        );
        assert!(!invalid_output.exists());
        fs::write(&meta, valid_meta).unwrap();
        assert!(
            !run().status.success(),
            "an existing journal must never be replaced"
        );
        assert_eq!(fs::read(&journal).unwrap(), original);
        let binding = Binding {
            validator_pubkey_sha3: [1; 32],
            genesis_digest: [2; 32],
        };
        let mut protection = SlashingProtection::open_bound(&d.0, binding).unwrap();
        assert!(matches!(
            protection.guard_proposal(320, || panic!("signed old proposal")),
            Err(Refusal::Proposal { .. })
        ));
        assert!(matches!(
            protection.guard_attestation(320, 10, 11, || panic!("signed old slot")),
            Err(Refusal::AttestationSlot { .. })
        ));
        assert!(matches!(
            protection.guard_attestation(352, 10, 10, || panic!("double vote")),
            Err(Refusal::DoubleVote { .. })
        ));
        assert!(matches!(
            protection.guard_attestation(352, 9, 11, || panic!("surround vote")),
            Err(Refusal::SurroundVote { .. })
        ));
        drop(protection);
        let mut reopened = SlashingProtection::open_bound(&d.0, binding).unwrap();
        assert_eq!(reopened.watermarks().proposal_slot, Some(320));
        assert_eq!(reopened.watermarks().source_epoch, Some(10));
        reopened.guard_proposal(352, || ()).unwrap();
        reopened.guard_attestation(352, 10, 11, || ()).unwrap();
        drop(reopened);
        let wrong = Binding {
            validator_pubkey_sha3: [3; 32],
            ..binding
        };
        assert!(SlashingProtection::open_bound(&d.0, wrong).is_err());
        let other_network = Binding {
            genesis_digest: [4; 32],
            ..binding
        };
        assert!(SlashingProtection::open_bound(&d.0, other_network).is_err());
        let reopened = SlashingProtection::open_bound(&d.0, binding).unwrap();
        assert_eq!(reopened.watermarks().target_epoch, Some(11));
    }

    // ── P3a: host signer anchor, rollback guard, key lock (fault injection) ──

    fn anchored(data: &Path, root: &Path, accept: bool) -> io::Result<(SlashingProtection, AnchorCheck)> {
        let mut sp = SlashingProtection::open_bound(data, KEY_A)?;
        let anchor = crate::signer_anchor::SignerAnchor::acquire(root, &KEY_A)?;
        let check = sp.attach_anchor(anchor, accept)?;
        Ok((sp, check))
    }

    /// Fault: the operator restores an old data-dir backup. Its record is
    /// internally consistent and LOWER than what the key signed; the anchor
    /// outside the data dir refuses it, and the explicit flag raises it.
    #[test]
    fn restored_old_data_dir_is_refused_unless_accepted_and_then_raised() {
        let data = dir("rb-data");
        let root = dir("rb-root");
        let backup;
        {
            let (mut sp, check) = anchored(&data.0, &root.0, false).unwrap();
            assert_eq!(check, AnchorCheck::Adopted);
            sp.guard_attestation(64, 0, 1, || ()).unwrap();
            backup = fs::read(data.0.join(FILE_NAME)).unwrap();
            sp.guard_attestation(128, 1, 2, || ()).unwrap();
            sp.guard_proposal(130, || ()).unwrap();
        } // process exits, locks released
        crate::store::atomic_private_write(&data.0.join(FILE_NAME), &backup).unwrap();
        let err = anchored(&data.0, &root.0, false).expect_err("rollback must be refused");
        assert!(err.to_string().contains("SIGNING ROLLBACK REFUSED"), "{err}");
        // A fresh, empty data dir for a key this host already ran is the same thing.
        let empty = dir("rb-empty");
        assert!(anchored(&empty.0, &root.0, false).is_err());

        let (mut sp, check) = anchored(&data.0, &root.0, true).unwrap();
        assert_eq!(check, AnchorCheck::DataDirRolledForward);
        assert_eq!(sp.watermarks().attestation_slot, Some(128));
        assert!(sp.guard_attestation(129, 1, 2, || panic!("double vote")).is_err());
        assert!(sp.guard_proposal(130, || panic!("second block")).is_err());
        assert_eq!(read_fresh(&data.0.join(FILE_NAME)).proposal_slot, Some(130), "raised durably");
    }

    /// Fault: crash after the data-dir record is durable but before the anchor
    /// copy is written. The signature was never released (both writes precede
    /// it), and the next boot raises the lagging anchor instead of refusing.
    #[test]
    fn crash_between_record_and_anchor_write_recovers_without_refusal() {
        let data = dir("crash-data");
        let root = dir("crash-root");
        {
            let (mut sp, _) = anchored(&data.0, &root.0, false).unwrap();
            sp.guard_attestation(10, 0, 1, || ()).unwrap();
        }
        let anchor_path = crate::signer_anchor::key_dir(&root.0, &KEY_A).join(crate::signer_anchor::RECORD_FILE);
        let lagging = fs::read(&anchor_path).unwrap();
        {
            let (mut sp, _) = anchored(&data.0, &root.0, false).unwrap();
            sp.guard_attestation(20, 1, 2, || ()).unwrap();
        }
        // Simulate the crash window: data dir has slot 20, anchor still has 10.
        crate::store::atomic_private_write(&anchor_path, &lagging).unwrap();
        let (sp, check) = anchored(&data.0, &root.0, false).unwrap();
        assert_eq!(check, AnchorCheck::AnchorRaised);
        assert_eq!(read_fresh(&anchor_path).attestation_slot, Some(20));
        assert_eq!(sp.watermarks().attestation_slot, Some(20));
    }

    /// Fault: the anchor write fails (crash/IO error before release). The
    /// signing closure must never run, and memory must not advance.
    #[test]
    fn anchor_write_failure_never_releases_a_signature() {
        let data = dir("fail-data");
        let root = dir("fail-root");
        let (mut sp, _) = anchored(&data.0, &root.0, false).unwrap();
        let key = crate::signer_anchor::key_dir(&root.0, &KEY_A);
        let record = key.join(crate::signer_anchor::RECORD_FILE);
        fs::remove_file(&record).unwrap();
        fs::create_dir(&record).unwrap(); // a directory cannot be replaced by rename
        let r = sp.guard_attestation(5, 0, 1, || panic!("signature released before the anchor was durable"));
        assert!(matches!(r, Err(Refusal::Io(_))));
        assert_eq!(sp.watermarks().attestation_slot, None);
    }

    /// Fault: a second instance of the same key on this host, from another
    /// data dir. The per-key flock refuses it; it is free again after exit.
    #[test]
    fn second_instance_of_a_key_on_one_host_is_refused() {
        let first_dir = dir("two-a");
        let second_dir = dir("two-b");
        let root = dir("two-root");
        let (first, _) = anchored(&first_dir.0, &root.0, false).unwrap();
        let err = anchored(&second_dir.0, &root.0, false).expect_err("second signer must be refused");
        assert!(err.to_string().contains("SECOND SIGNER REFUSED"), "{err}");
        // A different key on the same host is unaffected.
        assert!(crate::signer_anchor::SignerAnchor::acquire(&root.0, &KEY_B).is_ok());
        drop(first);
        // The second data dir has no record but the anchor has one only if
        // something was signed; nothing was, so it may now start.
        assert!(anchored(&second_dir.0, &root.0, false).is_ok());
    }

    #[test]
    fn retired_key_refuses_to_boot_on_this_host() {
        let data = dir("ret-data");
        let root = dir("ret-root");
        drop(anchored(&data.0, &root.0, false).unwrap());
        let key = crate::signer_anchor::key_dir(&root.0, &KEY_A);
        crate::signer_anchor::write_retired(&key, "migrated to host-b").unwrap();
        let err = anchored(&data.0, &root.0, false).expect_err("retired");
        assert!(err.to_string().contains("RETIRED"), "{err}");
        crate::signer_anchor::write_retired(&data.0, "migrated").unwrap();
        assert!(crate::signer_anchor::check_not_retired(&[&data.0]).is_err());
        // Tools may still take the lock to export.
        assert!(crate::signer_anchor::SignerAnchor::acquire_for_tool(&root.0, &KEY_A).is_ok());
    }

    /// Sandboxed default root (systemd `ProtectHome=` / `ProtectSystem=strict`
    /// turn `$HOME` read-only or invisible): the DEFAULT anchor degrades to
    /// "unavailable" instead of refusing boot; the explicit path stays strict.
    #[cfg(unix)]
    #[test]
    fn unwritable_default_root_degrades_but_explicit_root_is_strict() {
        use crate::signer_anchor::{is_unreachable_root_error, SignerAnchor};
        use std::os::unix::fs::PermissionsExt;
        let home = dir("sandbox-home");
        fs::create_dir_all(&home.0).unwrap();
        fs::set_permissions(&home.0, fs::Permissions::from_mode(0o500)).unwrap();
        let root = home.0.join(".bloch-signer");
        // Running as root ignores mode bits; nothing to simulate then.
        if fs::create_dir(&root).is_ok() {
            fs::set_permissions(&home.0, fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        assert!(matches!(SignerAnchor::acquire_default(&root, &KEY_A), Ok(None)));
        let err = SignerAnchor::acquire(&root, &KEY_A).expect_err("explicit root must be strict");
        assert!(is_unreachable_root_error(&err), "{err}");
        // A missing parent (ProtectHome=true hides /home entirely) also degrades.
        let hidden = home.0.join("absent").join(".bloch-signer");
        assert!(matches!(SignerAnchor::acquire_default(&hidden, &KEY_A), Ok(None)));
        fs::set_permissions(&home.0, fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// The degraded path never swallows a held key lock or a retirement.
    #[test]
    fn default_root_still_refuses_a_second_signer_and_a_retired_key() {
        use crate::signer_anchor::SignerAnchor;
        let root = dir("default-root");
        let first = SignerAnchor::acquire_default(&root.0, &KEY_A).unwrap().expect("writable root");
        let err = SignerAnchor::acquire_default(&root.0, &KEY_A).expect_err("second signer");
        assert!(err.to_string().contains("SECOND SIGNER REFUSED"), "{err}");
        drop(first);
        crate::signer_anchor::write_retired(&crate::signer_anchor::key_dir(&root.0, &KEY_A), "moved").unwrap();
        let err = SignerAnchor::acquire_default(&root.0, &KEY_A).expect_err("retired");
        assert!(err.to_string().contains("RETIRED"), "{err}");
    }

    /// Runtime rollback guard: a published signature of this key beyond the
    /// record is detected and the record is raised so no later duty conflicts.
    #[test]
    fn published_signature_beyond_the_record_is_detected_and_covered() {
        let d = dir("pub");
        let mut sp = SlashingProtection::open_bound(&d.0, KEY_A).unwrap();
        sp.guard_attestation(40, 3, 4, || ()).unwrap();
        let echo = Published::Attestation { slot: 40, source_epoch: 3, target_epoch: 4 };
        assert!(!sp.is_uncovered(echo), "our own echo is covered");
        assert!(sp.is_uncovered(Published::Proposal { slot: 1 }), "no proposal recorded yet");
        let foreign = Published::Attestation { slot: 50, source_epoch: 4, target_epoch: 5 };
        assert!(sp.is_uncovered(foreign));
        sp.raise_to_published(foreign).unwrap();
        assert!(!sp.is_uncovered(foreign));
        assert!(sp.guard_attestation(51, 4, 5, || panic!("double vote with the foreign one")).is_err());
        assert_eq!(read_fresh(&d.0.join(FILE_NAME)).target_epoch, Some(5));
    }

    /// Migration export merges data dir and anchor monotonically.
    #[test]
    fn merge_records_takes_the_maximum_and_rejects_foreign() {
        let a = dir("merge-a");
        let b = dir("merge-b");
        let mut sa = SlashingProtection::open_bound(&a.0, KEY_A).unwrap();
        sa.guard_proposal(90, || ()).unwrap();
        let mut sb = SlashingProtection::open_bound(&b.0, KEY_A).unwrap();
        sb.guard_attestation(70, 1, 2, || ()).unwrap();
        let merged = merge_records(KEY_A, &fs::read(a.0.join(FILE_NAME)).unwrap(), &fs::read(b.0.join(FILE_NAME)).unwrap()).unwrap();
        let (wm, binding) = decode(&merged).unwrap();
        assert_eq!(binding, Some(KEY_A));
        assert_eq!((wm.proposal_slot, wm.attestation_slot, wm.target_epoch), (Some(90), Some(70), Some(2)));
        assert!(merge_records(KEY_B, &merged, &merged).is_err());
    }
}
