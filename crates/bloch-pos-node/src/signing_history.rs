// SPDX-License-Identifier: AGPL-3.0-or-later

//! Node-local slashing protection: the durable record of what this
//! validator key has already signed, consulted **before** every signature.
//!
//! Format and operator procedures: `docs/specs/BLOCH-SLASHING-PROTECTION.md`.
//!
//! ## What this is, and what it is not
//!
//! This module changes what this node will **sign**, never what it will
//! **accept**. It is pure node-local policy — two nodes with and without it
//! validate identically, so shipping it needs no flag day. The risk it
//! introduces is exactly the dual of the risk it removes: a node refusing a
//! duty it could safely have performed (one missed slot or one missed
//! attestation) instead of a node signing something slashable. Every refusal
//! path below is deliberately biased that way, because a missed duty costs a
//! reward and an equivocation costs 5% of stake plus ejection
//! ([`bloch_pos_committee::slashing`]).
//!
//! ## The record, and why watermarks are enough
//!
//! Per validator key the store holds three numbers:
//!
//! - the **highest slot** this key ever signed a block proposal for, and
//! - for attestations, the **highest source epoch** and **highest target
//!   epoch** ever signed.
//!
//! Signing is then permitted only strictly above the watermarks:
//!
//! - a proposal only for `slot > highest_proposed_slot`;
//! - an attestation only for `source ≥ max_source` **and** `target > max_target`.
//!
//! Against everything previously signed, that refuses all three slashable
//! offences of [`bloch_pos_committee::slashing::SlashableOffense`]:
//!
//! - **Proposer equivocation** — a second header for a signed slot needs
//!   `slot ≤ highest`, refused.
//! - **Double vote** — a second vote for a signed target needs
//!   `target ≤ max_target`, refused.
//! - **Surround vote**, both directions — the new vote surrounding an old
//!   one needs `source < old.source ≤ max_source`; the new vote being
//!   surrounded by an old one needs `target < old.target ≤ max_target`.
//!   Both refused.
//!
//! Watermarks are *stricter* than a full list of signed pairs — they also
//! refuse some pairs that would have been safe to sign — but for this
//! protocol the strictness is free: committees partition the active set, so
//! an honest validator attests exactly once per epoch with a non-decreasing
//! justified source, and proposes at strictly increasing slots. The honest
//! sequence never trips the watermark; only a rewind does. In exchange the
//! store is a fixed-size record with no growth, no pruning decision, and an
//! interchange format small enough to read aloud.
//!
//! ## Crash ordering — the load-bearing rule
//!
//! The watermark is advanced and **fsynced before the signature is
//! produced**, never after. The crash cases are therefore:
//!
//! - crash before the record is durable → nothing was signed, nothing is
//!   recorded, the duty simply happens (or not) on the next boot. Safe.
//! - crash after the record, before or during signing/broadcast → the store
//!   claims a signature that may never have existed. On restart the node
//!   refuses to re-sign that duty: **one missed duty, zero equivocations.**
//!   Fail safe, by construction rather than by luck.
//!
//! The reverse order — sign, then record — has a window where the signature
//! exists and the record does not, and a crash in that window re-signs after
//! restart. That is precisely the double-signing accident this store exists
//! to prevent, so the order is not configurable and
//! `crash_after_record_before_sign_misses_the_duty_instead_of_double_signing`
//! pins it.
//!
//! ## What it cannot do, stated honestly
//!
//! The store travels with the *data directory*. It protects against restarts,
//! restored VM snapshots and key migrations done by the book
//! (`protection-export` / `protection-import`). It cannot protect against the
//! same key signing **concurrently on two machines** — both nodes would hold
//! independent stores and each would happily advance its own. No node-local
//! record can close that; only the operator running one node per key does.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// File name inside the data directory, next to `validator.key`.
pub const HISTORY_FILE: &str = "signing_history.bin";

const MAGIC: &[u8; 8] = b"BSIGHIS1";

const FLAG_NETWORK_BOUND: u8 = 0b0000_0001;
const FLAG_HAS_PROPOSAL: u8 = 0b0000_0010;
const FLAG_HAS_ATTESTATION: u8 = 0b0000_0100;

/// First line of the interchange text format (§ format doc).
pub const INTERCHANGE_HEADER: &str = "bloch-signing-history v1";

/// Why a signature was not produced.
///
/// `Refused` is the store doing its job; `Io` is the store being unable to
/// make the record durable — and an unrecordable signature is also refused,
/// because a signature the store cannot remember is a signature a restart
/// can repeat.
#[derive(Debug)]
pub enum GuardError {
    Refused(String),
    Io(io::Error),
}

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardError::Refused(why) => write!(f, "slashing protection refused to sign: {why}"),
            GuardError::Io(e) => write!(
                f,
                "slashing protection could not record the signature before releasing it \
                 ({e}); refusing to sign, because a signature the store cannot remember \
                 is a signature a restart can repeat"
            ),
        }
    }
}

impl From<io::Error> for GuardError {
    fn from(e: io::Error) -> Self {
        GuardError::Io(e)
    }
}

/// The parsed content of an interchange file (`protection-export` output).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interchange {
    /// Genesis-manifest digest the history is bound to, or `None` for a
    /// store exported before its first run bound it.
    pub network: Option<[u8; 32]>,
    /// Suite-enveloped hybrid public key of the validator, verbatim.
    pub pubkey: Vec<u8>,
    pub highest_proposed_slot: Option<u64>,
    /// `(max_source_epoch, max_target_epoch)`.
    pub attestation: Option<(u64, u64)>,
}

/// The durable signing-history store for one validator key.
#[derive(Debug)]
pub struct SigningHistory {
    dir: PathBuf,
    network: Option<[u8; 32]>,
    pubkey: Vec<u8>,
    highest_proposed_slot: Option<u64>,
    /// `(max_source_epoch, max_target_epoch)`.
    attestation: Option<(u64, u64)>,
}

impl SigningHistory {
    // ── Creation and loading ────────────────────────────────────────────

    /// Create a fresh, empty history for `pubkey`, not yet bound to a
    /// network — `keygen` calls this the moment the key exists, so a key
    /// never travels without its history. Refuses to overwrite: an existing
    /// file is a record of signatures, and destroying one is never this
    /// code's decision.
    pub fn create_unbound(dir: &Path, pubkey: &[u8]) -> io::Result<SigningHistory> {
        Self::create(dir, None, pubkey)
    }

    /// Create a fresh history already bound to `network`. This is the
    /// `--accept-new-signing-history` first-boot path: the operator has
    /// asserted, loudly, that this key has never signed anywhere.
    pub fn create_bound(
        dir: &Path,
        network: &[u8; 32],
        pubkey: &[u8],
    ) -> io::Result<SigningHistory> {
        Self::create(dir, Some(*network), pubkey)
    }

    fn create(dir: &Path, network: Option<[u8; 32]>, pubkey: &[u8]) -> io::Result<SigningHistory> {
        fs::create_dir_all(dir)?;
        let path = dir.join(HISTORY_FILE);
        if path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "{} already exists; refusing to overwrite a signing history \
                     (it is the record of what this key has signed)",
                    path.display()
                ),
            ));
        }
        let h = SigningHistory {
            dir: dir.to_path_buf(),
            network,
            pubkey: pubkey.to_vec(),
            highest_proposed_slot: None,
            attestation: None,
        };
        h.persist()?;
        Ok(h)
    }

    /// Create a history from an imported interchange record (the data dir
    /// has none yet). Same no-overwrite rule as [`Self::create`].
    pub fn create_from_interchange(dir: &Path, rec: &Interchange) -> io::Result<SigningHistory> {
        let mut h = Self::create(dir, rec.network, &rec.pubkey)?;
        h.highest_proposed_slot = rec.highest_proposed_slot;
        h.attestation = rec.attestation;
        h.persist()?;
        Ok(h)
    }

    /// Load the store from `dir`. A missing file surfaces as
    /// `ErrorKind::NotFound`; anything else unreadable or unparseable is an
    /// error the caller must treat as "do not sign", never as "start fresh".
    pub fn open(dir: &Path) -> io::Result<SigningHistory> {
        let bytes = fs::read(dir.join(HISTORY_FILE))?;
        let bad = |m: &'static str| io::Error::new(io::ErrorKind::InvalidData, m);
        let mut r = crate::codec::Reader::new(&bytes);
        let magic = r.take(8).map_err(|_| bad("truncated signing history"))?;
        if magic != MAGIC {
            return Err(bad("not a bloch-pos signing history"));
        }
        let flags = r.u8().map_err(|_| bad("truncated signing history"))?;
        let network_raw = r.h32().map_err(|_| bad("truncated signing history"))?;
        let pubkey = r.bytes().map_err(|_| bad("truncated signing history"))?;
        let proposal_raw = r.u64().map_err(|_| bad("truncated signing history"))?;
        let source_raw = r.u64().map_err(|_| bad("truncated signing history"))?;
        let target_raw = r.u64().map_err(|_| bad("truncated signing history"))?;
        r.finish()
            .map_err(|_| bad("trailing bytes in signing history"))?;
        let h = SigningHistory {
            dir: dir.to_path_buf(),
            network: (flags & FLAG_NETWORK_BOUND != 0).then_some(network_raw),
            pubkey,
            highest_proposed_slot: (flags & FLAG_HAS_PROPOSAL != 0).then_some(proposal_raw),
            attestation: (flags & FLAG_HAS_ATTESTATION != 0).then_some((source_raw, target_raw)),
        };
        if let Some((s, t)) = h.attestation {
            if s >= t {
                return Err(bad("signing history holds source ≥ target — corrupt"));
            }
        }
        Ok(h)
    }

    /// Bind the store to the running network and key, at boot.
    ///
    /// - a pubkey mismatch means this history belongs to a *different
    ///   validator key* — refusal, because its watermarks say nothing about
    ///   what THIS key signed;
    /// - a network mismatch means this history was written on a different
    ///   chain — refusal rather than silent reuse in either direction;
    /// - an unbound store (fresh from `keygen`, which cannot know the
    ///   genesis digest) is bound now, durably.
    pub fn bind(&mut self, network: &[u8; 32], pubkey: &[u8]) -> io::Result<()> {
        if self.pubkey != pubkey {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}/{HISTORY_FILE} records the signing history of a DIFFERENT validator \
                     key. Signing with this key over that history would protect nothing. If \
                     this key really has its own history, import it with `bloch-pos \
                     protection-import`.",
                    self.dir.display()
                ),
            ));
        }
        match self.network {
            None => {
                self.network = Some(*network);
                self.persist()
            }
            Some(n) if n == *network => Ok(()),
            Some(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}/{HISTORY_FILE} was written on a different network (different genesis \
                     digest). Refusing to sign over a history that says nothing about this \
                     chain. If this key is genuinely new to THIS network and has never \
                     signed on it, move the old file aside and start with \
                     --accept-new-signing-history.",
                    self.dir.display()
                ),
            )),
        }
    }

    // ── The two record-before-sign gates ────────────────────────────────

    /// Gate a block-proposal signature for `slot`. On `Ok(())` the advanced
    /// watermark is durable on disk and the caller may sign; on any `Err`
    /// the caller must not sign.
    pub fn record_proposal(&mut self, slot: u64) -> Result<(), GuardError> {
        if let Some(h) = self.highest_proposed_slot {
            if slot <= h {
                return Err(GuardError::Refused(format!(
                    "a proposal for slot {slot} when this key has already signed a proposal \
                     at slot {h} — signing it could be the proposer equivocation this store \
                     exists to prevent (double-signed slot, or a rewound data dir)"
                )));
            }
        }
        let prev = self.highest_proposed_slot;
        self.highest_proposed_slot = Some(slot);
        if let Err(e) = self.persist() {
            // Not signed, so the memory must agree with the disk again.
            self.highest_proposed_slot = prev;
            return Err(GuardError::Io(e));
        }
        Ok(())
    }

    /// Gate an attestation signature for `(source, target)`. Same contract
    /// as [`Self::record_proposal`].
    pub fn record_attestation(&mut self, source: u64, target: u64) -> Result<(), GuardError> {
        if source >= target {
            return Err(GuardError::Refused(format!(
                "an attestation with source epoch {source} ≥ target epoch {target} — \
                 malformed by construction, and not something to sign"
            )));
        }
        if let Some((ms, mt)) = self.attestation {
            if target <= mt {
                let offence = if target == mt {
                    "a second vote for an already-signed target epoch is a DOUBLE VOTE"
                } else {
                    "its span could be surrounded by a vote this key already signed \
                     (SURROUND VOTE, outer half already released)"
                };
                return Err(GuardError::Refused(format!(
                    "an attestation for target epoch {target} when this key has already \
                     signed up to target epoch {mt} — {offence}"
                )));
            }
            if source < ms {
                return Err(GuardError::Refused(format!(
                    "an attestation with source epoch {source} below the highest source \
                     already signed ({ms}) — it would SURROUND a vote this key already \
                     released"
                )));
            }
        }
        let prev = self.attestation;
        self.attestation = Some((
            self.attestation.map_or(source, |(ms, _)| ms.max(source)),
            target,
        ));
        if let Err(e) = self.persist() {
            self.attestation = prev;
            return Err(GuardError::Io(e));
        }
        Ok(())
    }

    // ── Import / export ─────────────────────────────────────────────────

    /// The interchange text form of this store — see the format doc.
    pub fn export_text(&self) -> String {
        let num = |v: Option<u64>| v.map_or("none".to_string(), |n| n.to_string());
        format!(
            "{INTERCHANGE_HEADER}\n\
             network: {}\n\
             pubkey: {}\n\
             highest-proposed-slot: {}\n\
             max-source-epoch: {}\n\
             max-target-epoch: {}\n",
            self.network
                .map_or("unbound".to_string(), |n| crate::codec::hex32(&n)),
            crate::codec::hex(&self.pubkey),
            num(self.highest_proposed_slot),
            num(self.attestation.map(|(s, _)| s)),
            num(self.attestation.map(|(_, t)| t)),
        )
    }

    /// Parse an interchange file. Strict: unknown keys, missing keys, or a
    /// half-present attestation pair are errors — a protection file that
    /// parses "mostly" protects mostly.
    pub fn parse_interchange(text: &str) -> Result<Interchange, String> {
        let mut lines = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'));
        match lines.next() {
            Some(h) if h == INTERCHANGE_HEADER => {}
            Some(h) => {
                return Err(format!(
                    "first line is `{h}`, expected `{INTERCHANGE_HEADER}`"
                ))
            }
            None => return Err("empty file".to_string()),
        }
        let mut network = None;
        let mut pubkey = None;
        let mut proposed = None;
        let mut source = None;
        let mut target = None;
        for line in lines {
            let (key, value) = line
                .split_once(':')
                .ok_or_else(|| format!("line `{line}` is not `key: value`"))?;
            let (key, value) = (key.trim(), value.trim());
            let opt_u64 = |v: &str| -> Result<Option<u64>, String> {
                if v == "none" {
                    Ok(None)
                } else {
                    v.parse::<u64>()
                        .map(Some)
                        .map_err(|_| format!("`{v}` is not a number or `none`"))
                }
            };
            match key {
                "network" => {
                    network = Some(if value == "unbound" {
                        None
                    } else {
                        let b = crate::codec::unhex(value)
                            .map_err(|e| format!("network: {e}"))?;
                        let arr: [u8; 32] = b
                            .try_into()
                            .map_err(|_| "network digest must be 32 bytes of hex".to_string())?;
                        Some(arr)
                    })
                }
                "pubkey" => {
                    let b = crate::codec::unhex(value).map_err(|e| format!("pubkey: {e}"))?;
                    if b.is_empty() {
                        return Err("pubkey is empty".to_string());
                    }
                    pubkey = Some(b);
                }
                "highest-proposed-slot" => proposed = Some(opt_u64(value)?),
                "max-source-epoch" => source = Some(opt_u64(value)?),
                "max-target-epoch" => target = Some(opt_u64(value)?),
                other => return Err(format!("unknown key `{other}`")),
            }
        }
        let network = network.ok_or("missing `network`")?;
        let pubkey = pubkey.ok_or("missing `pubkey`")?;
        let proposed = proposed.ok_or("missing `highest-proposed-slot`")?;
        let source = source.ok_or("missing `max-source-epoch`")?;
        let target = target.ok_or("missing `max-target-epoch`")?;
        let attestation = match (source, target) {
            (None, None) => None,
            (Some(s), Some(t)) if s < t => Some((s, t)),
            (Some(_), Some(_)) => {
                return Err("max-source-epoch must be strictly below max-target-epoch".to_string())
            }
            _ => {
                return Err(
                    "max-source-epoch and max-target-epoch must both be numbers or both `none`"
                        .to_string(),
                )
            }
        };
        Ok(Interchange {
            network,
            pubkey,
            highest_proposed_slot: proposed,
            attestation,
        })
    }

    /// Merge an imported record into this store and persist. Watermarks only
    /// ever go **up** (element-wise max): merging can make the node refuse
    /// more, never less. Returns a human-readable summary of what moved.
    pub fn merge_interchange(&mut self, rec: &Interchange) -> Result<String, GuardError> {
        if rec.pubkey != self.pubkey {
            return Err(GuardError::Refused(
                "the imported history belongs to a different validator key".to_string(),
            ));
        }
        match (self.network, rec.network) {
            (Some(a), Some(b)) if a != b => {
                return Err(GuardError::Refused(
                    "the imported history was written on a different network \
                     (different genesis digest)"
                        .to_string(),
                ))
            }
            (None, Some(b)) => self.network = Some(b),
            _ => {}
        }
        let before = (self.highest_proposed_slot, self.attestation);
        self.highest_proposed_slot = match (self.highest_proposed_slot, rec.highest_proposed_slot)
        {
            (a, None) => a,
            (None, b) => b,
            (Some(a), Some(b)) => Some(a.max(b)),
        };
        self.attestation = match (self.attestation, rec.attestation) {
            (a, None) => a,
            (None, b) => b,
            (Some((s1, t1)), Some((s2, t2))) => Some((s1.max(s2), t1.max(t2))),
        };
        if let Err(e) = self.persist() {
            (self.highest_proposed_slot, self.attestation) = before;
            return Err(GuardError::Io(e));
        }
        Ok(format!(
            "proposal watermark {} -> {}, attestation watermark {} -> {}",
            fmt_opt(before.0),
            fmt_opt(self.highest_proposed_slot),
            fmt_pair(before.1),
            fmt_pair(self.attestation),
        ))
    }

    // ── Accessors (logging and tests) ───────────────────────────────────

    pub fn highest_proposed_slot(&self) -> Option<u64> {
        self.highest_proposed_slot
    }

    pub fn attestation_watermark(&self) -> Option<(u64, u64)> {
        self.attestation
    }

    // ── Durability ──────────────────────────────────────────────────────

    /// Write the whole store durably: full bytes to a temp file, fsync the
    /// file, rename over [`HISTORY_FILE`], fsync the directory. A crash at
    /// any point leaves either the old record or the new one — never a torn
    /// file — and once this returns `Ok` the record survives power loss.
    /// Only after that may a signature exist.
    fn persist(&self) -> io::Result<()> {
        let mut out = Vec::with_capacity(8 + 1 + 32 + 4 + self.pubkey.len() + 24);
        out.extend_from_slice(MAGIC);
        let mut flags = 0u8;
        if self.network.is_some() {
            flags |= FLAG_NETWORK_BOUND;
        }
        if self.highest_proposed_slot.is_some() {
            flags |= FLAG_HAS_PROPOSAL;
        }
        if self.attestation.is_some() {
            flags |= FLAG_HAS_ATTESTATION;
        }
        out.push(flags);
        out.extend_from_slice(&self.network.unwrap_or([0u8; 32]));
        crate::codec::put_bytes(&mut out, &self.pubkey);
        out.extend_from_slice(&self.highest_proposed_slot.unwrap_or(0).to_le_bytes());
        let (s, t) = self.attestation.unwrap_or((0, 0));
        out.extend_from_slice(&s.to_le_bytes());
        out.extend_from_slice(&t.to_le_bytes());

        let tmp = self.dir.join(format!("{HISTORY_FILE}.tmp"));
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(&out)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, self.dir.join(HISTORY_FILE))?;
        // The rename itself must survive a crash: fsync the directory. On a
        // filesystem where opening a directory for fsync is not supported,
        // failing here refuses the signature — the conservative direction.
        File::open(&self.dir)?.sync_all()
    }
}

fn fmt_opt(v: Option<u64>) -> String {
    v.map_or("none".to_string(), |n| n.to_string())
}

fn fmt_pair(v: Option<(u64, u64)>) -> String {
    v.map_or("none".to_string(), |(s, t)| format!("({s}, {t})"))
}

// ═════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Dir(PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn tmp_dir(tag: &str) -> Dir {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "bloch-sighist-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("create test dir");
        Dir(d)
    }

    const NET: [u8; 32] = [7u8; 32];
    const KEY: &[u8] = b"a stand-in hybrid pubkey";

    fn fresh(dir: &Dir) -> SigningHistory {
        SigningHistory::create_bound(&dir.0, &NET, KEY).expect("create store")
    }

    // ── Requirement 5, test 1: double proposal refused ──────────────────

    #[test]
    fn a_second_proposal_for_the_same_or_a_lower_slot_is_refused() {
        let dir = tmp_dir("dblprop");
        let mut h = fresh(&dir);
        h.record_proposal(10).expect("first proposal at slot 10");
        // The same slot again — the literal double proposal.
        assert!(matches!(
            h.record_proposal(10),
            Err(GuardError::Refused(_))
        ));
        // A lower slot — the rewound-data-dir shape.
        assert!(matches!(h.record_proposal(9), Err(GuardError::Refused(_))));
        // Strictly above the watermark is what honest progress looks like.
        h.record_proposal(11).expect("slot 11 is above the watermark");
    }

    // ── Requirement 5, test 2: surround and double votes refused ────────

    #[test]
    fn surround_and_double_votes_are_refused_in_both_directions() {
        let dir = tmp_dir("surround");
        let mut h = fresh(&dir);
        h.record_attestation(2, 5).expect("first vote (2 → 5)");

        // Double vote: same target epoch, any source.
        assert!(matches!(
            h.record_attestation(3, 5),
            Err(GuardError::Refused(_))
        ));
        // New vote would SURROUND the signed one: source below 2, target above 5.
        assert!(matches!(
            h.record_attestation(1, 6),
            Err(GuardError::Refused(_))
        ));
        // New vote would BE SURROUNDED by the signed one: inside (2, 5).
        assert!(matches!(
            h.record_attestation(3, 4),
            Err(GuardError::Refused(_))
        ));
        // Malformed span never signs.
        assert!(matches!(
            h.record_attestation(6, 6),
            Err(GuardError::Refused(_))
        ));
        // Honest progress: source moved up with justification, target advanced.
        h.record_attestation(2, 6).expect("(2 → 6) extends the chain");
        h.record_attestation(5, 7).expect("(5 → 7) after justification moved");
    }

    // ── Requirement 5, test 3: the crash case fails safe ────────────────

    /// The record is durable BEFORE the signature exists. A crash in the
    /// window between the two leaves a store that claims a signature that
    /// was never released — and reopening it refuses the duty. That is the
    /// fail-safe direction: the cost is one missed slot, never a slashing.
    #[test]
    fn crash_after_record_before_sign_misses_the_duty_instead_of_double_signing() {
        let dir = tmp_dir("crash");
        {
            let mut h = fresh(&dir);
            h.record_proposal(42).expect("record slot 42");
            h.record_attestation(3, 9).expect("record vote (3 → 9)");
            // Process "crashes" here: the signature for slot 42 / target 9
            // was never produced, never broadcast. Drop simulates the death.
        }
        let mut h = SigningHistory::open(&dir.0).expect("reopen after the crash");
        assert_eq!(h.highest_proposed_slot(), Some(42), "the record survived");
        assert_eq!(h.attestation_watermark(), Some((3, 9)));
        assert!(
            matches!(h.record_proposal(42), Err(GuardError::Refused(_))),
            "the restarted node must refuse to re-sign the duty the record claims"
        );
        assert!(matches!(
            h.record_attestation(3, 9),
            Err(GuardError::Refused(_))
        ));
        // The chain moves on and so does the node.
        h.record_proposal(43).expect("the next slot signs normally");
        h.record_attestation(3, 10).expect("the next target too");
    }

    /// A crash DURING the persist itself leaves either the old file or the
    /// new one (write-temp → fsync → rename), never a torn record. Simulate
    /// the worst leftover: a garbage `.tmp` next to a healthy store.
    #[test]
    fn a_leftover_tmp_file_from_a_crash_mid_persist_is_harmless() {
        let dir = tmp_dir("tmpfile");
        {
            let mut h = fresh(&dir);
            h.record_proposal(5).expect("record slot 5");
        }
        fs::write(dir.0.join(format!("{HISTORY_FILE}.tmp")), b"torn garbage")
            .expect("plant the leftover");
        let mut h = SigningHistory::open(&dir.0).expect("the real file is untouched");
        assert_eq!(h.highest_proposed_slot(), Some(5));
        h.record_proposal(6).expect("recording over the leftover works");
    }

    /// When the record cannot be made durable, the answer is "do not sign",
    /// and memory must keep agreeing with disk so a later retry is judged
    /// against what is actually recorded.
    #[cfg(unix)]
    #[test]
    fn an_unwritable_store_refuses_the_signature_rather_than_signing_unrecorded() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir("rodir");
        let mut h = fresh(&dir);
        h.record_proposal(1).expect("record slot 1 while writable");
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o555))
            .expect("make the dir read-only");
        let res = h.record_proposal(2);
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755))
            .expect("restore permissions");
        assert!(
            matches!(res, Err(GuardError::Io(_))),
            "an unrecordable signature must be refused, got {res:?}"
        );
        assert_eq!(
            h.highest_proposed_slot(),
            Some(1),
            "memory must roll back to what the disk actually holds"
        );
        // Writable again: the duty that was refused is still signable,
        // because it was never signed.
        h.record_proposal(2).expect("retry once the store is writable");
    }

    // ── Requirement 5, test 4: the restored-snapshot scenario ───────────

    /// The operator snapshots the VM, the validator keeps signing, the
    /// snapshot is restored. Because every signature was recorded (and
    /// fsynced) BEFORE it was released, the snapshot's store already covers
    /// everything signed before the snapshot was taken — so the restored
    /// node refuses to re-sign any of it.
    #[test]
    fn a_restored_snapshot_refuses_every_duty_signed_before_the_snapshot() {
        let live = tmp_dir("snap-live");
        let mut h = fresh(&live);
        h.record_proposal(100).expect("sign slot 100");
        h.record_attestation(10, 12).expect("sign vote (10 → 12)");

        // The snapshot: a byte-for-byte copy of the data dir, taken while
        // the validator runs.
        let restored = tmp_dir("snap-restored");
        fs::copy(
            live.0.join(HISTORY_FILE),
            restored.0.join(HISTORY_FILE),
        )
        .expect("take the snapshot");

        // Life goes on on the original machine.
        h.record_proposal(101).expect("sign slot 101 after the snapshot");
        h.record_attestation(12, 13).expect("sign vote (12 → 13) after");

        // The restore boots. Everything signed BEFORE the snapshot is
        // refused — the store in the snapshot already knew about it.
        let mut r = SigningHistory::open(&restored.0).expect("boot from the snapshot");
        assert!(matches!(r.record_proposal(100), Err(GuardError::Refused(_))));
        assert!(matches!(r.record_proposal(99), Err(GuardError::Refused(_))));
        assert!(matches!(
            r.record_attestation(10, 12),
            Err(GuardError::Refused(_))
        ));
        assert!(matches!(
            r.record_attestation(9, 13),
            Err(GuardError::Refused(_)),
        ), "a vote surrounding the pre-snapshot one is refused too");

        // Honest limitation, pinned so nobody reads more protection into
        // this than exists: duties signed AFTER the snapshot are invisible
        // to the restored store. The restored node re-signing those is the
        // dual-machine problem, and only running one node per key fixes it.
        r.record_proposal(101)
            .expect("the post-snapshot slot is NOT covered — documented limitation");
    }

    // ── Store integrity: missing / unreadable / foreign ─────────────────

    #[test]
    fn a_missing_store_is_not_found_and_garbage_is_invalid_never_fresh() {
        let dir = tmp_dir("integrity");
        let err = SigningHistory::open(&dir.0).expect_err("nothing there");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        fs::write(dir.0.join(HISTORY_FILE), b"BADMAGIC and then some").expect("plant");
        let err = SigningHistory::open(&dir.0).expect_err("bad magic");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        fs::write(dir.0.join(HISTORY_FILE), &MAGIC[..6]).expect("plant");
        let err = SigningHistory::open(&dir.0).expect_err("truncated");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn create_refuses_to_overwrite_and_bind_refuses_foreign_key_or_network() {
        let dir = tmp_dir("bind");
        let _h = fresh(&dir);
        let err = SigningHistory::create_bound(&dir.0, &NET, KEY)
            .expect_err("a second create must not clobber the record");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);

        let mut h = SigningHistory::open(&dir.0).expect("reopen");
        h.bind(&NET, KEY).expect("same network, same key");
        assert!(h.bind(&NET, b"someone else's key").is_err());
        assert!(h.bind(&[9u8; 32], KEY).is_err());
    }

    #[test]
    fn an_unbound_store_binds_durably_on_first_boot() {
        let dir = tmp_dir("unbound");
        {
            let mut h = SigningHistory::create_unbound(&dir.0, KEY).expect("keygen path");
            h.bind(&NET, KEY).expect("first boot binds");
        }
        let mut h = SigningHistory::open(&dir.0).expect("reopen");
        assert!(h.bind(&[9u8; 32], KEY).is_err(), "bound now — another network refused");
        h.bind(&NET, KEY).expect("the bound network still opens");
    }

    // ── Import / export ─────────────────────────────────────────────────

    #[test]
    fn export_parses_back_to_the_same_record() {
        let dir = tmp_dir("roundtrip");
        let mut h = fresh(&dir);
        h.record_proposal(77).expect("record");
        h.record_attestation(4, 8).expect("record");
        let text = h.export_text();
        let rec = SigningHistory::parse_interchange(&text).expect("parse own export");
        assert_eq!(
            rec,
            Interchange {
                network: Some(NET),
                pubkey: KEY.to_vec(),
                highest_proposed_slot: Some(77),
                attestation: Some((4, 8)),
            }
        );
        // And an empty store round-trips its `none`s.
        let dir2 = tmp_dir("roundtrip2");
        let h2 = fresh(&dir2);
        let rec2 = SigningHistory::parse_interchange(&h2.export_text()).expect("parse");
        assert_eq!(rec2.highest_proposed_slot, None);
        assert_eq!(rec2.attestation, None);
    }

    #[test]
    fn import_merges_upward_only_and_refuses_foreign_records() {
        let dir = tmp_dir("merge");
        let mut h = fresh(&dir);
        h.record_proposal(50).expect("record");
        h.record_attestation(5, 9).expect("record");

        // A record that is behind moves nothing (watermarks never go down).
        h.merge_interchange(&Interchange {
            network: Some(NET),
            pubkey: KEY.to_vec(),
            highest_proposed_slot: Some(40),
            attestation: Some((3, 7)),
        })
        .expect("merging an older record is a no-op, not an error");
        assert_eq!(h.highest_proposed_slot(), Some(50));
        assert_eq!(h.attestation_watermark(), Some((5, 9)));

        // A record that is ahead raises the watermarks, durably.
        h.merge_interchange(&Interchange {
            network: Some(NET),
            pubkey: KEY.to_vec(),
            highest_proposed_slot: Some(60),
            attestation: Some((6, 11)),
        })
        .expect("merging a newer record");
        drop(h);
        let h = SigningHistory::open(&dir.0).expect("reopen");
        assert_eq!(h.highest_proposed_slot(), Some(60));
        assert_eq!(h.attestation_watermark(), Some((6, 11)));

        let mut h = h;
        assert!(matches!(
            h.merge_interchange(&Interchange {
                network: Some(NET),
                pubkey: b"not this validator".to_vec(),
                highest_proposed_slot: None,
                attestation: None,
            }),
            Err(GuardError::Refused(_))
        ));
        assert!(matches!(
            h.merge_interchange(&Interchange {
                network: Some([9u8; 32]),
                pubkey: KEY.to_vec(),
                highest_proposed_slot: None,
                attestation: None,
            }),
            Err(GuardError::Refused(_))
        ));
    }

    #[test]
    fn the_parser_is_strict_about_what_a_protection_file_must_say() {
        let ok = format!(
            "{INTERCHANGE_HEADER}\n# a comment\nnetwork: unbound\npubkey: 00ff\n\
             highest-proposed-slot: none\nmax-source-epoch: none\nmax-target-epoch: none\n"
        );
        SigningHistory::parse_interchange(&ok).expect("minimal valid file");

        for bad in [
            "".to_string(),
            "not-the-header v9\nnetwork: unbound\n".to_string(),
            // Missing pubkey.
            format!(
                "{INTERCHANGE_HEADER}\nnetwork: unbound\nhighest-proposed-slot: none\n\
                 max-source-epoch: none\nmax-target-epoch: none\n"
            ),
            // Half an attestation pair.
            format!(
                "{INTERCHANGE_HEADER}\nnetwork: unbound\npubkey: 00ff\n\
                 highest-proposed-slot: none\nmax-source-epoch: 3\nmax-target-epoch: none\n"
            ),
            // source ≥ target.
            format!(
                "{INTERCHANGE_HEADER}\nnetwork: unbound\npubkey: 00ff\n\
                 highest-proposed-slot: none\nmax-source-epoch: 5\nmax-target-epoch: 5\n"
            ),
            // Unknown key.
            format!(
                "{INTERCHANGE_HEADER}\nnetwork: unbound\npubkey: 00ff\nsurprise: 1\n\
                 highest-proposed-slot: none\nmax-source-epoch: none\nmax-target-epoch: none\n"
            ),
        ] {
            assert!(
                SigningHistory::parse_interchange(&bad).is_err(),
                "must refuse: {bad:?}"
            );
        }
    }
}
