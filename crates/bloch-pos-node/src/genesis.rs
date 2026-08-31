// SPDX-License-Identifier: AGPL-3.0-or-later

//! Genesis manifest: the one file every node of a network loads (integration
//! plan §3.4), and the deterministic synthesis of block 0 and its committed
//! state from it.
//!
//! Two independently built nodes must agree on genesis byte-for-byte before
//! the first slot ticks. Everything here is therefore a pure function of the
//! manifest bytes: the genesis header is fixed-field, the genesis
//! `CommittedState` comes from `CommittedState::genesis`, and the manifest's
//! SHA3-256 digest is pinned into the data dir's `meta` so a node can never
//! silently switch networks (§3.1 refusal rule).
//!
//! What the devnet manifest does NOT yet carry, honestly: the stake-eligibility
//! policy (integration plan §3.4 / decision 9). This is a *devnet* genesis: a
//! validator set and a clock. The mainnet shape is the same format with the
//! carryover commitment and the vested allocations filled in — the balance set
//! itself arrives out of band, through [`Manifest::ingest_carryover`].

use std::fs;
use std::io;
use std::io::{BufRead, BufReader};
use std::path::Path;

use bloch_pos_committee::header::{BlockHeaderV4, BlockId, VERSION_G4};
use bloch_pos_committee::state_root::{EutxoEntry, EvmCommitment};
use bloch_pos_committee::tokenomics_v4;
use bloch_pos_committee::transition::{CommittedState, GenesisValidator};
use sha3::{Digest, Sha3_256};

const MANIFEST_MAGIC: &[u8; 8] = b"BPOSMAN1";

/// The beacon mix that seeds epoch 0 — fixed before any validator could have
/// influenced it (same convention as the pure crate's tests).
pub const GENESIS_MIX: [u8; 32] = [0u8; 32];

/// One genesis validator, public parts only.
#[derive(Clone)]
pub struct ManifestValidator {
    pub index: u32,
    pub stake_sat: u128,
    pub randao_commitment: [u8; 32],
    pub pubkey: Vec<u8>,
    pub withdrawal_credentials: Vec<u8>,
    /// Commission on delegators' rewards, in basis points. Published in the
    /// manifest because it is a committed registry column (2026-08-12): the
    /// epoch boundary splits both issuance and producer fees with it, so a
    /// launch validator's rate has to be part of the genesis every node
    /// agrees on, not a local setting.
    pub commission_bps: u128,
}

pub struct Manifest {
    /// Slot-0 wall-clock origin, unix milliseconds.
    pub genesis_time_ms: u64,
    /// Slot duration in milliseconds. 30_000 is the §5.1 consensus cadence;
    /// a devnet may run faster — the value is wall-clock pacing only, it
    /// never enters any consensus object (slots are numbers, not times).
    pub slot_ms: u64,
    pub validators: Vec<ManifestValidator>,
    /// Genesis-cohort indices (founder-operated launch set, cap tapered by
    /// `genesis_cohort.rs`). Empty on a devnet.
    pub cohort: Vec<u32>,
    /// The Genesis-3 balances this chain opens with. `None` on a devnet, where
    /// nobody holds anything and a fresh validator set is the whole state.
    ///
    /// The entries are **not** here. At the terminal height Genesis-3 has on
    /// the order of hundreds of thousands of outputs, and a manifest is a file
    /// every node reads, hashes and pins; carrying the set inline would make
    /// the thing nodes compare tens of megabytes long for no gain. What is
    /// here is the commitment — digest, count, total — and the node ingests
    /// the snapshot file separately and refuses it unless all three agree.
    /// Genesis-3 opened the same way (`carryover.tsv` + a `carryover_root` in
    /// meta) and that mechanism is the one piece of this that has been proven
    /// on a live chain.
    pub carryover: Option<CarryoverCommitment>,
    /// The consensus-vested allocations (`BLOCH-TOKENOMICS-V4.md` §3). Empty
    /// on a devnet.
    pub allocations: Vec<GenesisAllocation>,
    /// The ingested carryover set — **not encoded, not hashed, not part of the
    /// network digest**. It is the balance set the commitment above describes,
    /// materialised from the snapshot file by
    /// [`Manifest::ingest_carryover`], which is the only thing that should
    /// ever write it: the entries are meaningful precisely because they were
    /// checked against all three fields of [`CarryoverCommitment`], and a
    /// value assigned here by any other route carries no such evidence.
    ///
    /// A manifest that commits to a carryover and has this empty is the
    /// zero-balance launch this whole path exists to prevent, so
    /// [`Manifest::opening_balances`] refuses it rather than quietly
    /// committing an empty ledger.
    pub carryover_entries: Vec<EutxoEntry>,
}

/// What the genesis state must reproduce from the carryover snapshot: four
/// independent facts about it, checked in order by
/// [`CarryoverSnapshot::check_against`].
///
/// Four, not one, because they fail for different reasons and each one is
/// blind to the others' failure. A file can be corrupt in transit (digest), be
/// a different artifact that is internally perfect (set root), be the right
/// artifact truncated or padded (count), or be the right shape carrying the
/// wrong money (total). Only the fourth catches a snapshot taken at another
/// height with the same number of outputs, and only the first catches a byte
/// flipped by a bad disk in a file whose set was never re-derived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarryoverCommitment {
    /// SHA3-256 over the snapshot file's bytes, exactly as they sit on disk.
    /// **Integrity in transit**: this is the "did the file arrive intact"
    /// question, and it is asked of the bytes, not of anything parsed out of
    /// them.
    ///
    /// SHA-3 rather than SHA-2 deliberately: the Genesis-4 stack is SHA-3
    /// throughout (the manifest's own digest included) and a consensus
    /// artifact is the wrong place to introduce a second hash family. The
    /// `sha256sum` line in the carryover runbook stays what it is — an
    /// operator convenience for moving a file between machines, checked by
    /// nothing in here.
    pub digest: [u8; 32],
    /// SHAKE-256 (32 bytes of XOF output) over the canonical rows — the root
    /// `bloch-snapshot-utxo` prints, `tokenomics_v4::CARRYOVER_MEASURED_ROOT`
    /// records, and `build_carryover.py` / `genesis4-ceremony` recompute for
    /// their derived artifacts.
    ///
    /// **Identity of the content**: this is the "is this the same set of
    /// outputs" question, and it is asked of the parsed, re-serialised rows.
    /// It is what independent operators compare — several people snapshot the
    /// same halted data-dir and agree on this number, which is the evidence a
    /// single tool's say-so is not.
    pub set_root: [u8; 32],
    /// How many outputs the snapshot carries. Lines in the file, one per
    /// unspent Genesis-3 output — not addresses, and not entries after any
    /// aggregation.
    pub entry_count: u64,
    /// Their total value **in Genesis-4 satoshis**: the snapshot's Genesis-3
    /// total after the ×100/21 split (`tokenomics_v4::split_g3_sat`), which is
    /// the money this chain actually opens with. It is stated post-split
    /// because [`Manifest::check_supply`] adds it to the allocations and holds
    /// the sum against `GENESIS_ISSUED_SAT`, and that constant is denominated
    /// in the new unit — a pre-split figure would be short by a factor of
    /// 100/21 and the check would compare two different currencies.
    ///
    /// Held separately from the digest on purpose: a digest says "these exact
    /// bytes", a total says "this much money". Checking both catches a
    /// snapshot that is internally consistent but is not the one the
    /// tokenomics was written against — the failure a digest alone cannot see,
    /// because a wrong file has a perfectly good digest of its own.
    pub total_sat: u128,
}

/// One consensus-vested allocation output.
///
/// These are the buckets §3 names — founder, VC, team, marketing, liquidity,
/// validator emission — expressed as genesis outputs rather than as a promise
/// kept off-chain. `unlock_epoch` is what makes the vesting consensus: an
/// output is unspendable until the chain reaches that epoch, so the schedule
/// is enforced by every node instead of by whoever holds the key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisAllocation {
    /// Which bucket this is, as a stable tag (see `alloc_purpose`).
    pub purpose: u8,
    /// SHA3-256 of the locking script that owns it.
    pub script_hash: [u8; 32],
    pub amount_sat: u128,
    /// First epoch at which this output may be spent. 0 means liquid at
    /// genesis.
    pub unlock_epoch: u64,
}

/// Stable purpose tags. Never renumber: they are committed in the manifest,
/// therefore in its digest, therefore in what every node agrees it joined.
pub mod alloc_purpose {
    pub const FOUNDER: u8 = 0x01;
    pub const VC: u8 = 0x02;
    pub const TEAM: u8 = 0x03;
    pub const MARKETING: u8 = 0x04;
    pub const LIQUIDITY: u8 = 0x05;
    /// Held for validator emission — issued over time, not spendable at once.
    pub const VALIDATOR_EMISSION: u8 = 0x06;
}

// ── Genesis-3 carryover ingestion ───────────────────────────────────────────
//
// The snapshot is the file `bloch-snapshot-utxo` writes at the Genesis-3
// terminal height: one line per unspent output, tab-separated, no header,
//
//     txid_hex <TAB> vout <TAB> value_sat <TAB> address_hex
//
// sorted by (txid, vout) — the tool sorts explicitly so the artifact does not
// depend on a RocksDB iteration detail — with a trailing newline on every
// line. Measured on the real file (2026-08-13, h39,328): 452,133 lines, ~54 MB,
// 16 distinct addresses, 380,574,600,000,000,000 G3 satoshis; column 1 is 64
// hex characters and column 4 is 40 in every single row. It only grows until
// Genesis-3 halts.
//
// Three properties this reader is built around:
//
//   1. **Streaming.** 54 MB in one `String`, or one allocation per line across
//      452k lines, is a cost paid for nothing. One reused line buffer, one
//      reused hex buffer, hash-as-you-read.
//   2. **All four checks.** File digest, set root, count, total — see
//      `check_against`. A wrong file has a perfectly good digest *of itself*;
//      the count and the total are what say it is the *right* file, and the
//      set root is the number independent operators compare across machines.
//   3. **Strict parsing.** Anything a builder would not have written —
//      uppercase hex, a leading zero, five columns, a `\r`, rows out of order,
//      an address that is not 20 bytes — is refused with the line number,
//      never skipped. A silently skipped line is a balance that vanishes, and
//      a genesis is the one artifact nobody can re-derive later.

/// Cap on entries read from a snapshot: ~35× the measured Genesis-3 set. A
/// bound so a corrupt or hostile file cannot ask for unbounded memory; not a
/// policy about how large a real snapshot may be.
pub const MAX_CARRYOVER_ENTRIES: u64 = 16_000_000;

/// Cap on a single snapshot line. A real line is ~120 bytes (64 hex txid, a
/// small vout, a value, 40 hex address); this leaves room and still refuses a
/// file with no newlines in it.
const MAX_SNAPSHOT_LINE: usize = 4_096;

/// A Genesis-3 address as the snapshot carries it: hash160, 20 bytes. Measured
/// across all 452,133 rows of the 2026-08-13 snapshot — every one is 40 hex
/// characters, not one is a longer script.
const G3_ADDRESS_BYTES: usize = 20;
const G3_ADDRESS_HEX: usize = G3_ADDRESS_BYTES * 2;

/// What went wrong ingesting the snapshot.
///
/// Every variant names *which* check failed and by how much. "Carryover
/// invalid" tells an operator holding a 54 MB file nothing they can act on,
/// and at a genesis ceremony the difference between "these are not the bytes"
/// and "these are the bytes but 4 outputs short" is the difference between
/// re-fetching a file and stopping the launch.
#[derive(Debug)]
pub enum CarryoverError {
    Io(io::Error),
    /// A line that could not be parsed, with its 1-based number.
    Line { line: u64, what: String },
    /// The bytes are not the committed bytes.
    Digest { found: [u8; 32], expected: [u8; 32] },
    /// The bytes parse, and describe a different set of outputs.
    SetRoot { found: [u8; 32], expected: [u8; 32] },
    /// The right kind of file, the wrong number of outputs.
    Count { found: u64, expected: u64 },
    /// The right shape, the wrong money.
    Total { found: u128, expected: u128 },
    /// A snapshot was offered to a manifest that commits to none.
    NotCommitted,
}

impl std::fmt::Display for CarryoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CarryoverError::Io(e) => write!(f, "carryover snapshot: {e}"),
            CarryoverError::Line { line, what } => {
                write!(f, "carryover snapshot line {line}: {what}")
            }
            CarryoverError::Digest { found, expected } => write!(
                f,
                "carryover FILE-DIGEST mismatch: the file's bytes hash (SHA3-256) to {}, \
                 the manifest commits to {} — these are not the committed bytes; if the \
                 set root below still matches, suspect the transfer, not the snapshot",
                crate::codec::hex32(found),
                crate::codec::hex32(expected),
            ),
            CarryoverError::SetRoot { found, expected } => write!(
                f,
                "carryover SET-ROOT mismatch: the outputs in this file root (SHAKE-256) to {}, \
                 the manifest commits to {} — this is a different balance set, not a \
                 damaged copy of the committed one",
                crate::codec::hex32(found),
                crate::codec::hex32(expected),
            ),
            CarryoverError::Count { found, expected } => write!(
                f,
                "carryover ENTRY-COUNT mismatch: the file carries {found} outputs, \
                 the manifest commits to {expected} ({} {})",
                found.abs_diff(*expected),
                if found > expected { "too many" } else { "missing" },
            ),
            CarryoverError::Total { found, expected } => write!(
                f,
                "carryover TOTAL mismatch: the file carries {found} sat after the \
                 x100/21 split, the manifest commits to {expected} (difference {} sat, \
                 the file is {})",
                found.abs_diff(*expected),
                if found > expected { "richer" } else { "poorer" },
            ),
            CarryoverError::NotCommitted => write!(
                f,
                "this manifest commits to no carryover — refusing to open a chain \
                 with balances the network digest says nothing about"
            ),
        }
    }
}

impl std::error::Error for CarryoverError {}

impl From<CarryoverError> for io::Error {
    fn from(e: CarryoverError) -> io::Error {
        match e {
            CarryoverError::Io(e) => e,
            other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
        }
    }
}

/// A parsed snapshot: the Genesis-4 outputs it becomes, plus everything the
/// commitment is checked against and the arithmetic that got there.
#[derive(Debug)]
pub struct CarryoverSnapshot {
    /// The opening outputs, in file order — which is (txid, vout) order.
    pub entries: Vec<EutxoEntry>,
    /// SHA3-256 over the exact bytes read.
    pub digest: [u8; 32],
    /// SHAKE-256 over the canonical rows — the published set root.
    pub set_root: [u8; 32],
    /// The snapshot's own total, in Genesis-3 satoshis, before the split.
    pub g3_total_sat: u128,
    /// What `entries` sum to: Genesis-4 satoshis, dust included.
    pub total_sat: u128,
    /// Sub-satoshi remainders of the per-output split, gathered and given to
    /// one output — see [`read_carryover_snapshot`] for the rule and why one
    /// is needed.
    pub dust_sat: u128,
}

impl CarryoverSnapshot {
    /// The four checks, in the order that explains the most: file digest
    /// (wrong bytes explains everything after it), set root (right bytes,
    /// wrong set), count, total.
    pub fn check_against(&self, c: &CarryoverCommitment) -> Result<(), CarryoverError> {
        if self.digest != c.digest {
            return Err(CarryoverError::Digest { found: self.digest, expected: c.digest });
        }
        if self.set_root != c.set_root {
            return Err(CarryoverError::SetRoot { found: self.set_root, expected: c.set_root });
        }
        let n = self.entries.len() as u64;
        if n != c.entry_count {
            return Err(CarryoverError::Count { found: n, expected: c.entry_count });
        }
        if self.total_sat != c.total_sat {
            return Err(CarryoverError::Total { found: self.total_sat, expected: c.total_sat });
        }
        Ok(())
    }
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        // Lowercase only. `hex::encode` — what the snapshot tool writes —
        // emits lowercase, so uppercase means the bytes are not the bytes
        // that were hashed, and it would fail the digest check anyway; saying
        // so at the line is more use than a digest mismatch over 54 MB.
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Decode lowercase hex into `out` (cleared first). False on any non-hex byte
/// or an odd length.
fn hex_into(s: &str, out: &mut Vec<u8>) -> bool {
    out.clear();
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return false;
    }
    for pair in b.chunks_exact(2) {
        match (hex_nibble(pair[0]), hex_nibble(pair[1])) {
            (Some(hi), Some(lo)) => out.push((hi << 4) | lo),
            _ => return false,
        }
    }
    true
}

/// Canonical unsigned decimal: digits only, no sign, no leading zero unless
/// the number *is* zero. `str::parse` accepts `+7` and `007`; both would be
/// bytes no builder wrote, and both hash differently from what they mean.
fn canonical_u64(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    s.parse().ok()
}

/// Read, parse and split a Genesis-3 balance snapshot. No commitment is
/// consulted here — [`load_carryover`] is the checked entry point.
///
/// ## Who owns a carried output — founder decision, 2026-08-13
///
/// The snapshot's fourth column is 20 bytes in every one of the 452,133 rows:
/// a Genesis-3 hash160 address, not a script. The committed column
/// (`EutxoEntry::script_hash`) is 32. The conversion is therefore a consensus
/// rule — it decides who owns each output — and it was decided, not inferred:
///
/// ```text
/// script_hash[0..20]  = the snapshot's 20 bytes (the Genesis-3 hash160)
/// script_hash[20..32] = 0x00
/// ```
///
/// **Zero-extension to the right, no re-hashing.** The criterion was
/// auditability: a holder proves their balance crossed by comparing their own
/// Genesis-3 address against the first 20 bytes of the field, with no
/// conversion table and no preimage argument — and an exchange or an auditor
/// reconciling the migration will want exactly that comparison. Re-hashing
/// (`SHA3-256(tag ‖ address)`) would have made the column uniformly a SHA-3
/// digest, which is tidier, but it makes every such proof indirect.
///
/// The cost is known and accepted: **this column now carries a 20-byte format
/// inside a 32-byte field, permanently.** Whoever finds twelve zero bytes here
/// in two years is reading the reason for them right now. Two consequences
/// worth stating rather than discovering: the padding direction is itself
/// consensus (padding on the wrong side gives every output a different owner,
/// which is a different ledger), and a carried output is not spendable by any
/// rule of the form `SHA3-256(script) == script_hash`, so the migration spend
/// path must recognise carried outputs explicitly — that path does not exist
/// yet and this is the fact it has to be built around.
///
/// A row whose fourth column is not exactly 20 bytes is refused rather than
/// converted: there is no decided rule for it, and inventing one silently is
/// how an output acquires an owner nobody chose.
///
/// ## The split, and the dust rule this states
///
/// Every value crosses through `tokenomics_v4::split_g3_sat` — ×100/21,
/// truncating — because that is the policy the constants crate already
/// writes down, and the whole point of the 2026-08-12 decision is that every
/// balance moves by the same ratio.
///
/// Measured on the real snapshot (2026-08-13, 452,133 outputs): the aggregate
/// is exact — 380,574,600,000,000,000 G3 sat × 100/21 =
/// 1,812,260,000,000,000,000 with no remainder — and 452,021 rows split
/// exactly, because a Genesis-3 coinbase of 8,400 BLCH is divisible by 21.
/// **112 rows leave a remainder, and truncating them row by row loses 59
/// satoshis** across the whole ledger: 0.00000059 BLOCH. Tiny, and fatal
/// anyway — [`Manifest::check_supply`] demands equality, so a launch would
/// stop on a rounding error 59 satoshis wide.
///
/// **The rule, stated: the largest output absorbs the whole remainder.** The
/// remainder is `split_g3_sat(total) - Σ split_g3_sat(value_i)` — the exact
/// gap between splitting the aggregate and splitting the rows — and it goes
/// to the highest-value output, ties broken by the lowest (txid, vout), which
/// is the first such line in the file since the file is sorted. Determinism
/// is the point: two nodes that place the dust differently commit different
/// state roots, so "the largest" is not enough on its own and the tie-break
/// is part of the rule.
///
/// On the real snapshot that lands the 59 satoshis on the founder's address
/// (`e986db51…`, which holds 425,599 of the 452,133 outputs) — the same
/// posture as the 100 B split, where the founder absorbs the rounding. The
/// alternative considered and rejected was to declare the truncated sum as
/// the carryover total, which closes by construction but leaves
/// `CARRYOVER_TOTAL_BLOCH` a non-round 18,122,599,999.99999941. What is *not*
/// acceptable is dropping the remainder, the one option that cannot close the
/// accounting at all.
pub fn read_carryover_snapshot<R: BufRead>(
    mut src: R,
) -> Result<CarryoverSnapshot, CarryoverError> {
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    // Two hashers over one pass. `file` answers "did these bytes arrive
    // intact"; `set` answers "is this the same set of outputs", over the
    // canonical re-serialisation of what was parsed. On a well-formed
    // snapshot they cover identical bytes — the strict parser admits exactly
    // one encoding — and they are still two questions, asked of two things.
    let mut file = Sha3_256::new();
    let mut set = sha3::Shake256::default();
    // Reused across every line: `clear` keeps the allocation, so 452k lines
    // cost two allocations, not 904k.
    let mut line = Vec::with_capacity(256);
    // One scratch buffer for both hex columns: the txid is decoded and copied
    // out before the script column overwrites it.
    let mut hexbuf = Vec::with_capacity(64);

    let mut entries: Vec<EutxoEntry> = Vec::new();
    let mut g3_total_sat: u128 = 0;
    let mut split_total: u128 = 0;
    let mut prev: Option<([u8; 32], u32)> = None;
    let mut n: u64 = 0;

    loop {
        line.clear();
        // Bounded per line, not merely checked afterwards: `read_until` on a
        // file with no newline in it would otherwise pull the whole thing into
        // memory before the cap below could object — which is the allocation
        // the cap exists to prevent.
        let read = std::io::Read::take(&mut src, MAX_SNAPSHOT_LINE as u64 + 1)
            .read_until(b'\n', &mut line)
            .map_err(CarryoverError::Io)?;
        if read == 0 {
            break;
        }
        n += 1;
        // Hash the raw bytes, before any interpretation of them: the file
        // digest must be over the file as it sits on disk, or "these exact
        // bytes" silently becomes "these bytes as this parser understood
        // them".
        Digest::update(&mut file, &line);

        if n > MAX_CARRYOVER_ENTRIES {
            return Err(CarryoverError::Line {
                line: n,
                what: format!(
                    "snapshot exceeds the {MAX_CARRYOVER_ENTRIES}-entry cap — refusing to \
                     read further"
                ),
            });
        }
        if line.len() > MAX_SNAPSHOT_LINE {
            return Err(CarryoverError::Line {
                line: n,
                what: format!("line is {} bytes, over the {MAX_SNAPSHOT_LINE} cap", line.len()),
            });
        }

        let body = line.strip_suffix(b"\n").unwrap_or(&line);
        let text = match std::str::from_utf8(body) {
            Ok(t) => t,
            Err(_) => {
                return Err(CarryoverError::Line { line: n, what: "not UTF-8".into() });
            }
        };
        if text.ends_with('\r') {
            return Err(CarryoverError::Line {
                line: n,
                what: "CRLF line ending — the snapshot is written with bare LF, and \
                       a CRLF copy is not the bytes that were hashed"
                    .into(),
            });
        }
        if text.is_empty() {
            return Err(CarryoverError::Line {
                line: n,
                what: "empty line — the snapshot has no blank lines and no trailing \
                       separator"
                    .into(),
            });
        }

        let mut cols = text.split('\t');
        let (Some(txid_s), Some(vout_s), Some(value_s), Some(script_s), None) =
            (cols.next(), cols.next(), cols.next(), cols.next(), cols.next())
        else {
            return Err(CarryoverError::Line {
                line: n,
                what: format!(
                    "expected 4 tab-separated columns \
                     (txid<TAB>vout<TAB>value_sat<TAB>script_hex), got {}",
                    text.split('\t').count()
                ),
            });
        };

        let mut txid = [0u8; 32];
        if txid_s.len() != 64 || !hex_into(txid_s, &mut hexbuf) {
            return Err(CarryoverError::Line {
                line: n,
                what: format!("txid must be 64 lowercase-hex characters, got {txid_s:?}"),
            });
        }
        txid.copy_from_slice(&hexbuf);

        let Some(vout) = canonical_u64(vout_s).and_then(|v| u32::try_from(v).ok()) else {
            return Err(CarryoverError::Line {
                line: n,
                what: format!("vout must be a canonical u32 decimal, got {vout_s:?}"),
            });
        };
        let Some(value) = canonical_u64(value_s) else {
            return Err(CarryoverError::Line {
                line: n,
                what: format!("value must be a canonical u64 decimal of satoshis, got {value_s:?}"),
            });
        };
        // The address column: exactly 20 bytes in all 452,133 rows of the
        // measured snapshot, a Genesis-3 hash160. Any other length has no
        // decided conversion into the 32-byte committed field, and guessing
        // one would hand the output to an owner nobody chose.
        if script_s.len() != G3_ADDRESS_HEX || !hex_into(script_s, &mut hexbuf) {
            return Err(CarryoverError::Line {
                line: n,
                what: format!(
                    "address must be exactly {G3_ADDRESS_HEX} lowercase-hex characters \
                     (a Genesis-3 hash160), got {script_s:?} — there is no decided rule \
                     for carrying anything else across",
                ),
            });
        }
        let mut script_hash = [0u8; 32];
        // Zero-extension to the RIGHT — founder decision, 2026-08-13, see the
        // function docs. The direction is consensus: padded on the left, every
        // output has a different owner and this is a different chain.
        script_hash[..G3_ADDRESS_BYTES].copy_from_slice(&hexbuf);

        // The canonical row, into the set root: the same bytes the snapshot
        // tool wrote, rebuilt from what was parsed rather than replayed from
        // the line, so this root is a statement about the outputs and not
        // about the file's whitespace.
        Update::update(&mut set, txid_s.as_bytes());
        Update::update(&mut set, b"\t");
        Update::update(&mut set, vout_s.as_bytes());
        Update::update(&mut set, b"\t");
        Update::update(&mut set, value_s.as_bytes());
        Update::update(&mut set, b"\t");
        Update::update(&mut set, script_s.as_bytes());
        Update::update(&mut set, b"\n");

        // Strictly ascending (txid, vout). The tool sorts, so this costs
        // nothing on a real file — and it is the only check that catches a
        // duplicated outpoint, which `CommittedState::genesis` would otherwise
        // absorb into its map, dropping one copy and leaving the ledger short
        // of the total it just verified.
        if let Some(p) = prev {
            if (txid, vout) <= p {
                return Err(CarryoverError::Line {
                    line: n,
                    what: "outpoints must be strictly ascending by (txid, vout) — this row \
                           repeats or precedes the one before it"
                        .into(),
                });
            }
        }
        prev = Some((txid, vout));

        let split = tokenomics_v4::split_g3_sat(u128::from(value));
        let Ok(split_u64) = u64::try_from(split) else {
            return Err(CarryoverError::Line {
                line: n,
                what: format!("{value} sat becomes {split} sat under the split, past u64"),
            });
        };
        g3_total_sat += u128::from(value); // u128 over u64 rows: cannot overflow
        split_total += split;

        entries.push(EutxoEntry {
            // The Genesis-3 outpoint crosses unchanged. It is what wallets,
            // explorers and the published snapshot already call this output,
            // and a re-derived id would make every holder's coin unfindable
            // by the only name it has ever had.
            txid,
            vout,
            value: split_u64,
            // 20 bytes of Genesis-3 address, then 12 zeros. Not a hash of
            // anything — see the founder decision in this function's docs, and
            // note that `GenesisAllocation::script_hash` in the same state IS
            // a real SHA3-256, so this field is a union of two formats by
            // decision rather than by accident.
            script_hash,
        });
    }

    let digest: [u8; 32] = file.finalize().into();
    let mut set_root = [0u8; 32];
    set.finalize_xof().read(&mut set_root);

    // The dust rule, applied. `split_g3_sat` of the aggregate is what the
    // ledger is worth; the rows sum to that or just under it, never over
    // (a sum of floors never exceeds the floor of the sum).
    let exact = tokenomics_v4::split_g3_sat(g3_total_sat);
    let dust_sat = exact - split_total;
    if dust_sat > 0 {
        // Highest value; ties to the lowest (txid, vout). The strict `>` is
        // what implements the tie-break: entries are in strictly ascending
        // outpoint order (the parser enforces it), so keeping the first
        // maximum keeps the lowest outpoint. `>=` here would silently take the
        // last one instead, and two nodes disagreeing about where one satoshi
        // landed is two state roots.
        let mut best = 0usize;
        for (i, e) in entries.iter().enumerate() {
            if e.value > entries[best].value {
                best = i;
            }
        }
        let Ok(d) = u64::try_from(dust_sat) else {
            return Err(CarryoverError::Line {
                line: n,
                what: format!("split remainder {dust_sat} sat does not fit u64"),
            });
        };
        let Some(v) = entries[best].value.checked_add(d) else {
            return Err(CarryoverError::Line {
                line: n,
                what: format!(
                    "largest output {} sat overflows u64 absorbing {d} sat of split remainder",
                    entries[best].value
                ),
            });
        };
        entries[best].value = v;
    }

    Ok(CarryoverSnapshot {
        entries,
        digest,
        set_root,
        g3_total_sat,
        total_sat: exact,
        dust_sat,
    })
}

/// Read a snapshot file and hold it against all three fields of the
/// commitment. The only function that should produce carryover entries for a
/// live chain.
pub fn load_carryover(
    path: &Path,
    commitment: &CarryoverCommitment,
) -> Result<CarryoverSnapshot, CarryoverError> {
    let f = fs::File::open(path).map_err(CarryoverError::Io)?;
    // 1 MiB of buffer against a 54 MB file: ~54 syscalls instead of ~13,000.
    let snap = read_carryover_snapshot(BufReader::with_capacity(1 << 20, f))?;
    snap.check_against(commitment)?;
    Ok(snap)
}

impl Manifest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MANIFEST_MAGIC);
        out.extend_from_slice(&self.genesis_time_ms.to_le_bytes());
        out.extend_from_slice(&self.slot_ms.to_le_bytes());
        out.extend_from_slice(&(self.validators.len() as u32).to_le_bytes());
        for v in &self.validators {
            out.extend_from_slice(&v.index.to_le_bytes());
            out.extend_from_slice(&v.stake_sat.to_le_bytes());
            out.extend_from_slice(&v.randao_commitment);
            crate::codec::put_bytes(&mut out, &v.pubkey);
            crate::codec::put_bytes(&mut out, &v.withdrawal_credentials);
            out.extend_from_slice(&v.commission_bps.to_le_bytes());
        }
        out.extend_from_slice(&(self.cohort.len() as u32).to_le_bytes());
        for c in &self.cohort {
            out.extend_from_slice(&c.to_le_bytes());
        }
        match &self.carryover {
            None => out.push(0),
            Some(c) => {
                out.push(1);
                out.extend_from_slice(&c.digest);
                out.extend_from_slice(&c.set_root);
                out.extend_from_slice(&c.entry_count.to_le_bytes());
                out.extend_from_slice(&c.total_sat.to_le_bytes());
            }
        }
        out.extend_from_slice(&(self.allocations.len() as u32).to_le_bytes());
        for a in &self.allocations {
            out.push(a.purpose);
            out.extend_from_slice(&a.script_hash);
            out.extend_from_slice(&a.amount_sat.to_le_bytes());
            out.extend_from_slice(&a.unlock_epoch.to_le_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Manifest, crate::codec::DecodeErr> {
        use crate::codec::{DecodeErr, Reader};
        let mut r = Reader::new(bytes);
        if r.take(8)? != MANIFEST_MAGIC {
            return Err(DecodeErr("not a genesis manifest"));
        }
        let genesis_time_ms = r.u64()?;
        let slot_ms = r.u64()?;
        if slot_ms == 0 {
            return Err(DecodeErr("slot_ms zero"));
        }
        let n = r.u32()? as usize;
        if n > 1_000_000 {
            return Err(DecodeErr("validator count over cap"));
        }
        // BLP-02 (CertiK, 2026-08-17). THE SUITE IS CHECKED HERE, AT INGESTION.
        //
        // `bloch_crypto::crypto::verify` dispatches on the suite carried INSIDE the
        // public key. A registry key stamped SUITE_MLDSA65_ONLY (0x0002) is therefore
        // verified with the ML-DSA half alone — and `HybridVerifier`, despite its
        // name, hands the registered bytes straight to that dispatcher. Staking
        // deposits already reject 0x0002; the manifest path did not, so the hybrid
        // invariant rested on whoever assembled the file.
        //
        // Genesis-4's live manifest carries 64 keys, every one of them 0x0001 and
        // 3,749 bytes (4 header + 1,952 ML-DSA-65 + 1,793 Falcon-1024), so nothing on
        // the chain today is affected. This closes the door rather than reporting that
        // nobody walked through it.
        //
        // Refusing here — at decode, before a key can reach a verifier — is what makes
        // the rule hold for every consumer of a manifest, including ones not written
        // yet.
        fn check_hybrid_pubkey(pk: &[u8], index: u32) -> Result<(), DecodeErr> {
            use bloch_crypto::crypto::{MLDSA_PUBKEY_LEN, SUITE_HEADER_LEN, SUITE_MLDSA65_FALCON1024};
            if pk.len() < SUITE_HEADER_LEN {
                let _ = index;
                return Err(DecodeErr("validator pubkey shorter than its suite header"));
            }
            if pk[0] != 0xB1 || pk[1] != 0x0C {
                return Err(DecodeErr("validator pubkey is not suite-enveloped"));
            }
            let suite = u16::from_le_bytes([pk[2], pk[3]]);
            if suite != SUITE_MLDSA65_FALCON1024 {
                // Named rather than numbered: "suite 0x0002" tells an operator nothing.
                return Err(DecodeErr(
                    "validator pubkey is not the hybrid ML-DSA-65 + Falcon-1024 suite — \
                     Genesis-4 consensus signatures must verify on BOTH halves",
                ));
            }
            // Both halves must be present. A body of exactly the ML-DSA length would
            // carry no Falcon key at all while still claiming the hybrid suite.
            if pk.len() <= SUITE_HEADER_LEN + MLDSA_PUBKEY_LEN {
                return Err(DecodeErr(
                    "validator pubkey claims the hybrid suite but carries no Falcon-1024 half",
                ));
            }
            Ok(())
        }

        let mut validators = Vec::with_capacity(n);
        for _ in 0..n {
            let index = r.u32()?;
            let stake_sat = r.u128()?;
            let randao_commitment = r.h32()?;
            let pubkey = r.bytes()?;
            check_hybrid_pubkey(&pubkey, index)?;
            validators.push(ManifestValidator {
                index,
                stake_sat,
                randao_commitment,
                pubkey,
                withdrawal_credentials: r.bytes()?,
                commission_bps: r.u128()?,
            });
        }
        let nc = r.u32()? as usize;
        if nc > n {
            return Err(DecodeErr("cohort larger than set"));
        }
        let mut cohort = Vec::with_capacity(nc);
        for _ in 0..nc {
            cohort.push(r.u32()?);
        }
        let carryover = match r.u8()? {
            0 => None,
            1 => Some(CarryoverCommitment {
                digest: r.h32()?,
                set_root: r.h32()?,
                entry_count: r.u64()?,
                total_sat: r.u128()?,
            }),
            // A third value would mean two encodings of one manifest and so
            // two digests for one network.
            _ => return Err(DecodeErr("carryover flag not canonical")),
        };
        let na = r.u32()? as usize;
        if na > 64 {
            return Err(DecodeErr("allocation count over cap"));
        }
        let mut allocations = Vec::with_capacity(na);
        for _ in 0..na {
            allocations.push(GenesisAllocation {
                purpose: r.u8()?,
                script_hash: r.h32()?,
                amount_sat: r.u128()?,
                unlock_epoch: r.u64()?,
            });
        }
        r.finish()?;
        Ok(Manifest {
            genesis_time_ms,
            slot_ms,
            validators,
            cohort,
            carryover,
            allocations,
            // Decoding a manifest can never produce the balance set: the set
            // is not in these bytes by design. A mainnet manifest therefore
            // arrives here incomplete and stays that way until
            // `ingest_carryover` checks a snapshot against the commitment.
            carryover_entries: Vec::new(),
        })
    }

    /// What genesis puts into existence: carried balances plus allocations.
    pub fn genesis_issued_sat(&self) -> u128 {
        self.carryover.as_ref().map_or(0, |c| c.total_sat)
            + self.allocations.iter().map(|a| a.amount_sat).sum::<u128>()
    }

    /// Refuse a manifest that does not add up.
    ///
    /// This is the check that makes the manifest a claim rather than an
    /// assertion. A genesis file is the one artifact nobody can re-derive
    /// later — once a chain runs from it, whatever it said is what happened —
    /// so the arithmetic is verified before it is signed, not after someone
    /// notices the supply is wrong.
    pub fn check_supply(&self) -> Result<(), String> {
        use bloch_pos_committee::tokenomics_v4 as t;
        let issued = self.genesis_issued_sat();
        if issued > t::TOTAL_SUPPLY_SAT {
            return Err(format!(
                "genesis issues {issued} sat, above the hard cap {}",
                t::TOTAL_SUPPLY_SAT
            ));
        }
        // Validator emission is issued by blocks over decades; genesis must
        // leave exactly that much unissued, or the emission schedule and the
        // cap disagree and one of them silently wins.
        let expected = t::GENESIS_ISSUED_SAT;
        if self.carryover.is_some() && issued != expected {
            return Err(format!(
                "genesis issues {issued} sat; tokenomics §3 says {expected} \
                 (difference {})",
                issued.abs_diff(expected)
            ));
        }
        Ok(())
    }

    pub fn load(path: &Path) -> io::Result<(Manifest, [u8; 32])> {
        let bytes = fs::read(path)?;
        let digest: [u8; 32] = Sha3_256::digest(&bytes).into();
        let m = Manifest::decode(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Ok((m, digest))
    }

    /// The genesis block header, synthesized deterministically from the
    /// manifest. Fixed-field: genesis is a block, so its id derives from a
    /// header through the single §5.4 path — never from a label.
    pub fn genesis_header(&self) -> BlockHeaderV4 {
        BlockHeaderV4 {
            version: VERSION_G4,
            parent: [0u8; 32],
            state_root: [0u8; 32],
            body_root: [0u8; 32],
            slot: 0,
            proposer_index: 0,
            randao_reveal: [0u8; 32],
            randao_mix: GENESIS_MIX,
            justified_root: [0u8; 32],
            finalized_root: [0u8; 32],
            attestation_root: [0u8; 32],
            coherence_root: [0u8; 32],
        }
    }

    pub fn genesis_id(&self) -> BlockId {
        BlockId::of(&self.genesis_header())
    }

    /// The committed state of block 0. Coherence starts empty (integration
    /// plan decision 6) and taint is dissolved (decision 8): all three
    /// carried roots are zero.
    ///
    /// # The zeros are a SENTINEL, pinned — do not "fix" them
    ///
    /// `[0u8; 32]` is not the root of an empty pool. The C1-frozen empty
    /// accumulator and empty nullifier set hash to real values
    /// (`bloch_pos_committee::params::COHERENCE_EMPTY_ACCUMULATOR_ROOT` /
    /// `..._NULLIFIER_ROOT`), and the ceremony tool
    /// (`tools/genesis4-ceremony`) computes exactly those for an empty pool —
    /// its test `empty_pool_commits_a_real_root_never_the_zero_sentinel`
    /// pins that. The two genesis tools therefore DISAGREE, and the
    /// disagreement is intentional and must stay: the live chain launched
    /// from THIS code, the ceremony's roots never reached the node, and while
    /// the genesis header itself commits `state_root: [0u8; 32]` (so the
    /// genesis id does not pin the sentinel), **block 1's `state_root` was
    /// computed over the state these zeros seed** — change them and every
    /// node's boot replay dies at block 1 with a state-root mismatch. The
    /// test `the_live_sentinel_zeros_are_pinned_do_not_reconcile_with_the_ceremony`
    /// below is the mirror of the ceremony's test and exists to stop the
    /// "unification" that would brick the fleet.
    ///
    /// What resolves the sentinel on the live chain is the flag-day bridge:
    /// at the boundary opening
    /// `bloch_pos_committee::params::COHERENCE_ACTIVATION_EPOCH`, the
    /// transition rewrites each zero root to the real empty root
    /// (`bloch_pos_committee::transition::coherence_sentinel_bridge`),
    /// deterministically on every node. A FUTURE chain should not rely on
    /// the bridge: launch it from ceremony-computed roots.
    pub fn genesis_state(&self) -> CommittedState {
        let vals: Vec<GenesisValidator> = self
            .validators
            .iter()
            .map(|v| GenesisValidator {
                index: v.index,
                pubkey: v.pubkey.clone(),
                staked_sat: v.stake_sat,
                randao_commitment: v.randao_commitment,
                withdrawal_credentials: v.withdrawal_credentials.clone(),
                commission_bps: v.commission_bps,
            })
            .collect();
        CommittedState::genesis(
            self.genesis_id(),
            GENESIS_MIX,
            &vals,
            &self.cohort,
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            // Empty EVM segment at genesis. Spelled out rather than defaulted
            // so that adding a carried component breaks this call site and
            // someone decides what genesis commits, instead of it silently
            // becoming zero.
            EvmCommitment {
                account_root: [0u8; 32],
                receipts_root: [0u8; 32],
                gas_used: 0,
                base_fee_per_gas: 0,
            },
            &self.opening_balances(),
        )
    }

    /// Ingest the Genesis-3 balance snapshot this manifest commits to.
    ///
    /// The only supported way to fill [`Manifest::carryover_entries`]: it
    /// refuses a manifest with no commitment, and it refuses a file that fails
    /// any of the four checks. On success the manifest is complete — the
    /// genesis state it synthesises from here on carries every balance.
    ///
    /// Returns the snapshot, so a caller can print what it just accepted
    /// (count, totals, dust) instead of asserting it worked.
    pub fn ingest_carryover(&mut self, path: &Path) -> Result<CarryoverSnapshot, CarryoverError> {
        let Some(c) = self.carryover.clone() else {
            return Err(CarryoverError::NotCommitted);
        };
        let snap = load_carryover(path, &c)?;
        self.carryover_entries = snap.entries.clone();
        Ok(snap)
    }

    /// Everything genesis puts into the ledger: the carried Genesis-3 outputs
    /// first, then the vested allocations.
    ///
    /// # Panics
    ///
    /// If the manifest commits to a carryover and none was ingested. That
    /// combination is the bug this path exists to make impossible — a mainnet
    /// launched from it opens with a state root nobody else computes and
    /// 452,133 outputs missing, and it would do so silently, which is the one
    /// outcome worse than not starting. It also panics on a duplicated
    /// outpoint between the two sets: `CommittedState::genesis` keys its map
    /// by `(txid, vout)`, so a collision would drop an output and leave the
    /// ledger short of the total that was just verified.
    pub fn opening_balances(&self) -> Vec<EutxoEntry> {
        if let Some(c) = &self.carryover {
            assert!(
                !self.carryover_entries.is_empty(),
                "manifest commits to a carryover of {} outputs ({} sat) but none were \
                 ingested — call Manifest::ingest_carryover before building genesis, or \
                 this chain opens with a zero balance for every holder",
                c.entry_count,
                c.total_sat,
            );
        }
        let allocs = self.allocation_outputs();
        let mut out = Vec::with_capacity(self.carryover_entries.len() + allocs.len());
        out.extend_from_slice(&self.carryover_entries);
        out.extend(allocs);
        // O(n log n) on 452k entries, once per genesis synthesis. Worth it:
        // the alternative is an output that silently does not exist.
        let mut keys: Vec<(&[u8; 32], u32)> = out.iter().map(|e| (&e.txid, e.vout)).collect();
        keys.sort_unstable();
        for w in keys.windows(2) {
            assert_ne!(
                w[0], w[1],
                "duplicate genesis outpoint {}:{} — one of these two outputs would vanish \
                 into the state map",
                crate::codec::hex32(w[0].0),
                w[0].1,
            );
        }
        out
    }

    /// The vested allocation outputs, as genesis eUTXOs.
    ///
    /// Deterministic from the manifest alone — every node synthesises the same
    /// outputs from the same bytes, which is the property genesis lives or
    /// dies by. The txid is a domain-separated digest over the allocation's
    /// own fields rather than a counter, so reordering the manifest's
    /// allocation list cannot silently change which output is which.
    ///
    /// The carryover is NOT here. Those entries come from the signed snapshot
    /// file, which the node ingests and checks against
    /// [`CarryoverCommitment`]; a 54 MB balance set does not belong inside the
    /// file every node hashes to decide which network it joined. The two sets
    /// meet in [`Manifest::opening_balances`], which is what genesis commits.
    pub fn allocation_outputs(&self) -> Vec<bloch_pos_committee::state_root::EutxoEntry> {
        self.allocations
            .iter()
            .map(|a| {
                let mut h = Sha3_256::new();
                Digest::update(&mut h, b"BLCH4:genesis-alloc\0");
                Digest::update(&mut h, [a.purpose]);
                Digest::update(&mut h, a.script_hash);
                Digest::update(&mut h, a.amount_sat.to_le_bytes());
                Digest::update(&mut h, a.unlock_epoch.to_le_bytes());
                let txid: [u8; 32] = h.finalize().into();
                bloch_pos_committee::state_root::EutxoEntry {
                    txid,
                    vout: 0,
                    // Values are u64 in the entry; an allocation above u64 is
                    // a manifest that could not be committed truthfully, so it
                    // is refused rather than truncated into a smaller number.
                    value: u64::try_from(a.amount_sat)
                        .expect("allocation exceeds u64 satoshis — see check_supply"),
                    script_hash: a.script_hash,
                }
            })
            .collect()
    }

    /// The registered public keys, indexed by validator index (dense from 0).
    pub fn pubkeys(&self) -> Vec<Vec<u8>> {
        let mut pks: Vec<Vec<u8>> = vec![Vec::new(); self.validators.len()];
        for v in &self.validators {
            if (v.index as usize) < pks.len() {
                pks[v.index as usize] = v.pubkey.clone();
            }
        }
        pks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A validator pubkey shaped the way Genesis-4 requires: the 0x0001
    /// envelope, then the ML-DSA-65 half, then the Falcon-1024 half. These
    /// fixtures used sixteen filler bytes, which `Manifest::decode` now refuses
    /// (CertiK BLP-02). The bytes are still filler — only the SHAPE is real,
    /// which is all the decoder checks and all a round-trip test needs.
    fn shaped_pubkey(seed: u8) -> Vec<u8> {
        let mut v = vec![0xB1, 0x0C, 0x01, 0x00];
        v.extend(std::iter::repeat(seed).take(1952 + 1793));
        v
    }

    fn sample() -> Manifest {
        Manifest {
            genesis_time_ms: 1_800_000_000_000,
            slot_ms: 500,
            validators: (0..3)
                .map(|i| ManifestValidator {
                    index: i,
                    stake_sat: (i as u128 + 1) * 1_000,
                    randao_commitment: [i as u8; 32],
                    pubkey: shaped_pubkey(i as u8),
                    withdrawal_credentials: Vec::new(),
                    // Distinct non-zero rates, so a decoder that dropped or
                    // aliased the column would fail the round-trip below
                    // instead of round-tripping three identical zeros.
                    commission_bps: 250 * (i as u128 + 1),
                })
                .collect(),
            cohort: vec![0],
            carryover: None,
            allocations: Vec::new(),
            carryover_entries: Vec::new(),
        }
    }

    /// THE MIRROR of the ceremony's
    /// `empty_pool_commits_a_real_root_never_the_zero_sentinel`
    /// (`tools/genesis4-ceremony/src/lib.rs`) — and deliberately its
    /// OPPOSITE. The ceremony pins that an empty pool commits real roots;
    /// this pins that the LIVE chain's genesis committed the `[0u8; 32]`
    /// sentinel instead, and that it must keep doing so: block 1's
    /// `state_root` was computed over the state these zeros seed, so
    /// "reconciling" this file with the ceremony bricks every node's boot
    /// replay at block 1. The two tools disagreeing is recorded, on purpose,
    /// in both suites — see the doc on [`Manifest::genesis_state`]. The
    /// sentinel is resolved on the live chain by the
    /// `COHERENCE_ACTIVATION_EPOCH` flag-day bridge, not by editing genesis.
    #[test]
    fn the_live_sentinel_zeros_are_pinned_do_not_reconcile_with_the_ceremony() {
        use bloch_pos_committee::{derive, params};
        let m = sample();
        // The header carries the sentinel binding path: literal zeros.
        assert_eq!(m.genesis_header().coherence_root, [0u8; 32]);
        // The committed state carries the sentinel roots, and its binding is
        // the value every live block's header repeats — confirmed by RPC
        // against the running chain (2026-08-29):
        // 3ac97a48fe4c1dc2de33022b2473e76e609c85ce0c0bce96540851f682bccb56.
        const LIVE_SENTINEL_BINDING: [u8; 32] = [
            0x3A, 0xC9, 0x7A, 0x48, 0xFE, 0x4C, 0x1D, 0xC2,
            0xDE, 0x33, 0x02, 0x2B, 0x24, 0x73, 0xE7, 0x6E,
            0x60, 0x9C, 0x85, 0xCE, 0x0C, 0x0B, 0xCE, 0x96,
            0x54, 0x08, 0x51, 0xF6, 0x82, 0xBC, 0xCB, 0x56,
        ];
        assert_eq!(m.genesis_state().coherence_root(), LIVE_SENTINEL_BINDING);
        // And the sentinel is NOT the empty pool's real roots — the exact
        // disagreement with the ceremony this test exists to keep visible.
        assert_ne!(params::COHERENCE_EMPTY_ACCUMULATOR_ROOT, [0u8; 32]);
        assert_ne!(params::COHERENCE_EMPTY_NULLIFIER_ROOT, [0u8; 32]);
        assert_ne!(
            m.genesis_state().coherence_root(),
            derive::coherence_binding(
                &params::COHERENCE_EMPTY_ACCUMULATOR_ROOT,
                &params::COHERENCE_EMPTY_NULLIFIER_ROOT,
            ),
            "the live sentinel binding must differ from the ceremony's \
             empty-pool binding; if these ever agree, one of the two \
             definitions was silently rewritten"
        );
    }

    // ── Carryover fixtures ──────────────────────────────────────────────
    //
    // A hand-built snapshot in the shape `bloch-snapshot-utxo` writes:
    // `txid<TAB>vout<TAB>value_sat<TAB>script_hex`, sorted by (txid, vout),
    // every line closed with LF. Four outputs, three holders' worth of
    // structure in miniature:
    //
    //   - two outputs under one txid (vout 0 and 7), so (txid, vout) ordering
    //     is exercised rather than assumed;
    //   - one large value divisible by 21 — a Genesis-3 coinbase of 8,400
    //     BLCH is, so most real rows cross the split with no remainder at all;
    //   - three small values that are NOT, so the per-row truncation and the
    //     dust rule are live in every test that uses this file rather than
    //     being dead code until the real 452,133-line snapshot arrives.
    //
    // The arithmetic, in full, because a fixture whose numbers are asserted
    // but not derived is a fixture that can agree with a broken split:
    //   G3 total     840,000,000,021 sat (divisible by 21, so x100/21 is exact)
    //   exact split  4,000,000,000,100 sat
    //   rows split   4,000,000,000,098 sat  (840e9 -> 4e12; 1 -> 4; 2 -> 9; 18 -> 85)
    //   remainder    2 sat, to the largest output
    const SNAPSHOT: &str = concat!(
        "1111111111111111111111111111111111111111111111111111111111111111\t0\t840000000000\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        "1111111111111111111111111111111111111111111111111111111111111111\t7\t1\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        "2222222222222222222222222222222222222222222222222222222222222222\t0\t2\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t1\t18\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
    );
    /// Both roots of [`SNAPSHOT`], generated with CPython's `hashlib` —
    /// `sha3_256` over the bytes and `shake_256` read to 32 bytes, the latter
    /// being what `bloch-snapshot-utxo` prints and `build_carryover.py`
    /// recomputes. Known answers from outside this crate, so these tests pin
    /// the *conventions* and not merely this implementation's agreement with
    /// itself.
    const SNAPSHOT_DIGEST: &str =
        "f622f4eb2f5ad61921c43b6b190ce9cdf9f9eb20e9726d884298b2db5f58cbc9";
    const SNAPSHOT_SET_ROOT: &str =
        "00a2dd27d33501f96ecb6105e96dcb55b72fb1b10be122a1af7228a71e37b54e";
    const SNAPSHOT_G3_SAT: u128 = 840_000_000_021;
    const SNAPSHOT_SPLIT_SAT: u128 = 4_000_000_000_100;

    fn read(text: &str) -> Result<CarryoverSnapshot, CarryoverError> {
        read_carryover_snapshot(text.as_bytes())
    }

    /// The commitment a ceremony would publish for [`SNAPSHOT`] — derived from
    /// the file, never retyped, so the three tests below can each break
    /// exactly one field.
    fn snapshot_commitment() -> CarryoverCommitment {
        let s = read(SNAPSHOT).expect("the fixture parses");
        CarryoverCommitment {
            digest: s.digest,
            set_root: s.set_root,
            entry_count: s.entries.len() as u64,
            total_sat: s.total_sat,
        }
    }

    /// Write the fixture to a scratch file so the file-reading path — not just
    /// the in-memory reader — is what the ingestion tests exercise.
    fn snapshot_file(name: &str, text: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("bloch-pos-carryover-{name}.tsv"));
        fs::write(&p, text).expect("scratch write");
        p
    }

    /// A manifest exercising the mainnet fields, with values chosen so a
    /// field-order or width slip cannot round-trip: every integer differs and
    /// the two allocations differ in all four columns. The carryover
    /// commitment is the fixture snapshot's, and the entries are ingested, so
    /// this manifest is *complete* — the state it synthesises carries money.
    fn mainnet_sample() -> Manifest {
        let mut m = sample();
        m.carryover = Some(snapshot_commitment());
        m.carryover_entries = read(SNAPSHOT).expect("the fixture parses").entries;
        m.allocations = vec![
            GenesisAllocation {
                purpose: alloc_purpose::FOUNDER,
                script_hash: [0xF1; 32],
                amount_sat: 10_000_000_000 * 100_000_000,
                unlock_epoch: 0,
            },
            GenesisAllocation {
                purpose: alloc_purpose::TEAM,
                script_hash: [0x7E; 32],
                amount_sat: 10_000_000_000 * 100_000_000,
                unlock_epoch: 2_190,
            },
        ];
        m
    }

    /// The check that would have caught the empty balance component: a
    /// genesis carrying money must not commit the same root as one carrying
    /// none.
    ///
    /// Before the eUTXO set reached `CommittedState`, `compute_root` passed
    /// `&[]` and these two roots were identical — a chain with 20 billion
    /// BLOCH in it was indistinguishable, at the state root, from a chain with
    /// nothing. That is the whole bug in one assertion.
    /// Cheap structural clone for the reorder test — `Manifest` is not
    /// `Clone` in the crate, and making it so for a test would widen the
    /// public surface for no other reason.
    fn clone_of(m: &Manifest) -> Manifest {
        Manifest::decode(&m.encode()).expect("a manifest we just encoded decodes")
    }

    #[test]
    fn balances_change_the_genesis_state_root() {
        use bloch_pos_committee::interfaces::StateReader;
        let empty = sample();
        let funded = mainnet_sample();
        assert_ne!(
            empty.genesis_state().state_root(),
            funded.genesis_state().state_root(),
            "a genesis holding allocations must not commit an empty ledger's root"
        );
    }

    // ── Carryover ingestion ─────────────────────────────────────────────

    /// The ingestion itself: the file parses, the count is the file's, and the
    /// entries sum to exactly what the split says they should.
    #[test]
    fn carryover_ingestion_counts_and_sums() {
        let s = read(SNAPSHOT).expect("fixture parses");
        assert_eq!(s.entries.len(), 4);
        assert_eq!(s.g3_total_sat, SNAPSHOT_G3_SAT);
        assert_eq!(s.total_sat, SNAPSHOT_SPLIT_SAT);
        // The claim that matters: the entries the chain will hold add up to
        // the number the commitment is checked against. Summed in u128 —
        // u64 addition of real balances is the wrap this crate is built to
        // avoid.
        let summed: u128 = s.entries.iter().map(|e| u128::from(e.value)).sum();
        assert_eq!(summed, s.total_sat, "entries must sum to the stated total");
        // Order and identity are the file's: the Genesis-3 outpoint crosses
        // unchanged, so a holder can still find their coin.
        assert_eq!(s.entries[0].txid, [0x11; 32]);
        assert_eq!(s.entries[0].vout, 0);
        assert_eq!(s.entries[1].vout, 7, "the second output of the same txid");
        assert_eq!(s.entries[3].txid, [0xAA; 32]);
        // Two outputs of one holder land on one script hash.
        assert_eq!(s.entries[0].script_hash, s.entries[1].script_hash);
        assert_ne!(s.entries[0].script_hash, s.entries[2].script_hash);
    }

    /// The ownership rule, pinned in the only way that catches the failure
    /// that matters: the Genesis-3 address occupies the FIRST 20 bytes and the
    /// LAST 12 are zero.
    ///
    /// A test that checked only the length, or only that the address appears
    /// somewhere, would pass with the padding on the wrong side — and padding
    /// on the wrong side gives every carried output a different owner, which
    /// is a different ledger, launched, with no way back. (Founder decision,
    /// 2026-08-13: zero-extend, do not re-hash, so a holder can compare their
    /// own address against the prefix without a conversion table.)
    #[test]
    fn the_address_is_zero_extended_to_the_right() {
        let s = read(SNAPSHOT).expect("fixture parses");
        let h = s.entries[0].script_hash;
        assert_eq!(&h[..20], &[0xAA; 20], "the G3 hash160 must be the leading 20 bytes");
        assert_eq!(&h[20..], &[0u8; 12], "the trailing 12 bytes must be zero");
        // Explicitly not the left-padded arrangement, spelled out so the
        // wrong one cannot be introduced and still pass by symmetry.
        let mut left_padded = [0u8; 32];
        left_padded[12..].copy_from_slice(&[0xAA; 20]);
        assert_ne!(h, left_padded);
        // And explicitly not a re-hash of the address, the alternative that
        // was weighed and rejected.
        assert_ne!(h, <[u8; 32]>::from(Sha3_256::digest([0xAA; 20])));
        // The second holder differs in the same 20 bytes, so ownership tracks
        // the address rather than the position.
        assert_eq!(&s.entries[2].script_hash[..20], &[0xBB; 20]);
        assert_eq!(&s.entries[2].script_hash[20..], &[0u8; 12]);
    }

    /// An address column of any other width is refused. There is no decided
    /// conversion for it, and the one thing that must not happen is a silent
    /// choice of owner.
    #[test]
    fn a_non_hash160_address_column_is_refused() {
        let base = "1111111111111111111111111111111111111111111111111111111111111111\t0\t5\t";
        for addr in ["aa", &"aa".repeat(32)[..], &"aa".repeat(19)[..]] {
            let err = read(&format!("{base}{addr}\n")).expect_err("only 20 bytes crosses");
            let msg = err.to_string();
            assert!(msg.contains("hash160"), "{msg}");
        }
        assert!(read(&format!("{base}{}\n", "aa".repeat(20))).is_ok());
    }

    /// Both hash conventions, against answers computed outside this crate
    /// (CPython `hashlib`). If the set root fails, the node and the tool that
    /// publishes the root disagree about what "the root" means and the real
    /// snapshot is refused at the ceremony with a mismatch nobody can explain.
    #[test]
    fn carryover_digests_match_the_published_conventions() {
        let s = read(SNAPSHOT).expect("fixture parses");
        assert_eq!(crate::codec::hex32(&s.digest), SNAPSHOT_DIGEST, "SHA3-256 of the bytes");
        assert_eq!(
            crate::codec::hex32(&s.set_root),
            SNAPSHOT_SET_ROOT,
            "SHAKE-256 of the canonical rows — the root bloch-snapshot-utxo prints"
        );
        assert_ne!(s.digest, s.set_root, "two questions, two answers");
    }

    /// The split is applied per output, truncating, and the sub-satoshi
    /// remainders are not dropped: they are gathered and given to the largest
    /// output — the rule `read_carryover_snapshot` states.
    #[test]
    fn split_is_per_output_and_the_dust_lands_somewhere() {
        let s = read(SNAPSHOT).expect("fixture parses");
        assert_eq!(s.dust_sat, 2, "1, 2 and 18 sat truncate; 840e9 does not");
        // The largest output is the one that absorbed it: 4e12 exactly from
        // the split, plus the 2 sat of remainder.
        assert_eq!(s.entries[0].value, 4_000_000_000_002);
        // The three small rows kept their own truncated values.
        assert_eq!(s.entries[1].value, 4);
        assert_eq!(s.entries[2].value, 9);
        assert_eq!(s.entries[3].value, 85);
        // Dropping the dust instead would leave the total two satoshis under
        // the figure the manifest commits to — which is exactly the
        // "truncate-and-hope does not close the accounting" failure.
        let truncated_only: u128 =
            s.entries.iter().map(|e| u128::from(e.value)).sum::<u128>() - s.dust_sat;
        assert_ne!(truncated_only, s.total_sat);
        assert_eq!(
            tokenomics_v4::split_g3_sat(s.g3_total_sat),
            s.total_sat,
            "the ledger is worth the split of the aggregate, whatever the rows rounded to"
        );
    }

    /// The tie-break, on its own, because "the largest output" does not
    /// determine anything when two outputs are the largest — and two nodes
    /// that place the dust on different outputs commit different state roots
    /// from the same file. That is a chain split produced by a rounding
    /// remainder, so the rule is: highest value, ties to the lowest
    /// (txid, vout).
    ///
    /// Two rows of 11 sat (tied maximum after the split, 52 each) and one of
    /// 5; the aggregate splits to 128, the rows to 127, so exactly 1 sat has
    /// to land somewhere and only the tie-break says where.
    #[test]
    fn tied_largest_outputs_break_deterministically_by_outpoint() {
        let text = concat!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t0\t11\tcccccccccccccccccccccccccccccccccccccccc\n",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\t0\t11\tcccccccccccccccccccccccccccccccccccccccc\n",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\t0\t5\tcccccccccccccccccccccccccccccccccccccccc\n",
        );
        let s = read(text).expect("parses");
        assert_eq!(s.dust_sat, 1);
        assert_eq!(s.entries[0].value, 53, "the lower outpoint of the tied pair takes it");
        assert_eq!(s.entries[1].value, 52, "the higher outpoint does not");
        assert_eq!(s.entries[2].value, 23);

        // The same three outputs presented with the tied pair's outpoints
        // swapped must move the dust with the outpoint, not keep it on the
        // first line: the rule is about identity, not position.
        let swapped = concat!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t0\t5\tcccccccccccccccccccccccccccccccccccccccc\n",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\t0\t11\tcccccccccccccccccccccccccccccccccccccccc\n",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\t0\t11\tcccccccccccccccccccccccccccccccccccccccc\n",
        );
        let t = read(swapped).expect("parses");
        assert_eq!(t.entries[0].value, 23);
        assert_eq!(t.entries[1].value, 53, "still the lowest outpoint among the tied maxima");
        assert_eq!(t.entries[2].value, 52);
    }

    /// The accounting closes at scale, on a file where almost every row
    /// truncates. Four rows can be reasoned about by hand; 20,000 cannot, and
    /// the real snapshot is 452,133 — the case where a per-row dust rule
    /// either closes the total or quietly loses a few hundred thousand
    /// satoshis. Also the shape a streaming reader is for: this file is
    /// ~1.4 MB, the real one is ~54 MB, and neither is ever held as a
    /// `String` inside the reader.
    #[test]
    fn the_total_closes_over_twenty_thousand_rows() {
        const N: u64 = 20_000;
        let mut text = String::with_capacity(N as usize * 72);
        let mut g3_total: u128 = 0;
        for i in 0..N {
            // Ascending txids: a big-endian counter in the leading bytes, so
            // hex order is (txid, vout) order.
            let mut txid = [0u8; 32];
            txid[..8].copy_from_slice(&i.to_be_bytes());
            // Values that mostly are NOT multiples of 21, so per-row
            // truncation is the rule here rather than the exception.
            let value = 8_400_000_000u64 + (i * 7_919) % 1_000_003;
            g3_total += u128::from(value);
            let hex: String = txid.iter().map(|b| format!("{b:02x}")).collect();
            text.push_str(&format!("{hex}\t0\t{value}\t{}\n", "cd".repeat(20)));
        }
        let s = read(&text).expect("generated snapshot parses");
        assert_eq!(s.entries.len() as u64, N);
        assert_eq!(s.g3_total_sat, g3_total);
        assert!(s.dust_sat > 0, "most rows must truncate for this test to mean anything");
        let summed: u128 = s.entries.iter().map(|e| u128::from(e.value)).sum();
        assert_eq!(
            summed,
            tokenomics_v4::split_g3_sat(g3_total),
            "the rows must sum to the split of the aggregate — the whole reason the \
             remainder is placed instead of dropped"
        );
        assert_eq!(summed, s.total_sat);
        // Deterministic: the same bytes give the same digest and the same
        // outputs, which is what lets independent operators compare.
        let again = read(&text).expect("parses again");
        assert_eq!(again.digest, s.digest);
        assert_eq!(again.entries, s.entries);
    }

    /// Ingestion through the checked path, from an actual file.
    #[test]
    fn carryover_loads_from_a_file_against_its_commitment() {
        let path = snapshot_file("good", SNAPSHOT);
        let mut m = sample();
        m.carryover = Some(snapshot_commitment());
        let s = m.ingest_carryover(&path).expect("the committed file is accepted");
        assert_eq!(s.entries.len(), 4);
        assert_eq!(m.carryover_entries.len(), 4);
        let _ = fs::remove_file(&path);
    }

    /// Wrong bytes: the file did not arrive as it was sent.
    #[test]
    fn carryover_wrong_digest_is_refused() {
        let mut c = snapshot_commitment();
        c.digest[0] ^= 1;
        let err = read(SNAPSHOT).unwrap().check_against(&c).expect_err("must refuse");
        assert!(matches!(err, CarryoverError::Digest { .. }), "{err}");
        let msg = err.to_string();
        assert!(msg.contains("FILE-DIGEST mismatch"), "{msg}");
        // The message must carry both values, or an operator cannot tell which
        // artifact they are holding.
        assert!(msg.contains(SNAPSHOT_DIGEST), "{msg}");
        assert!(msg.contains(&crate::codec::hex32(&c.digest)), "{msg}");
    }

    /// Right bytes by the digest's own account, wrong set of outputs. The
    /// fourth check exists because the other three answer different questions:
    /// this is the one independent operators compare across machines.
    #[test]
    fn carryover_wrong_set_root_is_refused() {
        let mut c = snapshot_commitment();
        c.set_root[31] ^= 1;
        let err = read(SNAPSHOT).unwrap().check_against(&c).expect_err("must refuse");
        assert!(matches!(err, CarryoverError::SetRoot { .. }), "{err}");
        let msg = err.to_string();
        assert!(msg.contains("SET-ROOT mismatch"), "{msg}");
        assert!(msg.contains(SNAPSHOT_SET_ROOT), "{msg}");
    }

    /// Right bytes, wrong number of outputs. This is the check that catches a
    /// truncated or padded transfer whose commitment was copied from the
    /// wrong run.
    #[test]
    fn carryover_wrong_count_is_refused() {
        let mut c = snapshot_commitment();
        c.entry_count = 5;
        let err = read(SNAPSHOT).unwrap().check_against(&c).expect_err("must refuse");
        assert!(matches!(err, CarryoverError::Count { found: 4, expected: 5 }), "{err}");
        let msg = err.to_string();
        assert!(msg.contains("ENTRY-COUNT mismatch"), "{msg}");
        // By how much, and in which direction.
        assert!(msg.contains("1 missing"), "{msg}");
    }

    /// Right bytes, right count, wrong money — the failure a digest alone
    /// cannot see. A snapshot from a different height has a valid digest of
    /// itself and can even carry the same number of outputs.
    #[test]
    fn carryover_wrong_total_is_refused() {
        let mut c = snapshot_commitment();
        c.total_sat += 100_000_000;
        let err = read(SNAPSHOT).unwrap().check_against(&c).expect_err("must refuse");
        assert!(matches!(err, CarryoverError::Total { .. }), "{err}");
        let msg = err.to_string();
        assert!(msg.contains("TOTAL mismatch"), "{msg}");
        assert!(msg.contains("100000000"), "the message must say by how much: {msg}");
        assert!(msg.contains("poorer"), "{msg}");
    }

    /// A malformed line stops the ingestion. It is never skipped: a skipped
    /// line is a holder's balance quietly deleted, and the count check would
    /// then be the only thing standing between that and a launched chain.
    #[test]
    fn malformed_lines_are_refused_not_skipped() {
        let good = "1111111111111111111111111111111111111111111111111111111111111111\t0\t840000000000\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        let cases: [(&str, &str); 9] = [
            ("2222222222222222222222222222222222222222222222222222222222222222\t0\t7\n", "3 columns"),
            ("2222222222222222222222222222222222222222222222222222222222222222\t0\t7\tbb\tzz\n", "5 columns"),
            ("22222222\t0\t7\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n", "short txid"),
            ("2222222222222222222222222222222222222222222222222222222222222ZZ\t0\t7\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n", "non-hex txid"),
            ("2222222222222222222222222222222222222222222222222222222222222222\t0\t7\tBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n", "uppercase script"),
            ("2222222222222222222222222222222222222222222222222222222222222222\t00\t7\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n", "leading zero in vout"),
            ("2222222222222222222222222222222222222222222222222222222222222222\t0\t007\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n", "leading zeros in value"),
            ("2222222222222222222222222222222222222222222222222222222222222222\t0\t-7\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n", "negative value"),
            ("\n", "blank line"),
        ];
        for (bad, what) in cases {
            let text = format!("{good}{bad}");
            let err = read(&text).expect_err(what);
            match err {
                CarryoverError::Line { line, .. } => assert_eq!(line, 2, "{what}"),
                other => panic!("{what}: expected a line error, got {other}"),
            }
        }
        // And the same file without the bad line parses, so each case above
        // failed for its own reason and not because the fixture is broken.
        assert_eq!(read(good).expect("the good line alone parses").entries.len(), 1);
    }

    /// A repeated or out-of-order outpoint is refused. `CommittedState`
    /// stores eUTXOs in a map keyed by (txid, vout), so a duplicate would be
    /// absorbed silently — the file would verify and the ledger would be
    /// short by whatever the dropped copy was worth.
    #[test]
    fn duplicate_and_unsorted_outpoints_are_refused() {
        let line = "1111111111111111111111111111111111111111111111111111111111111111\t0\t5\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        let dup = format!("{line}{line}");
        assert!(matches!(read(&dup), Err(CarryoverError::Line { line: 2, .. })));

        let descending = format!(
            "2222222222222222222222222222222222222222222222222222222222222222\t0\t5\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n{line}"
        );
        assert!(matches!(read(&descending), Err(CarryoverError::Line { line: 2, .. })));
    }

    /// A manifest with no commitment refuses a snapshot outright: nothing in
    /// the network digest would hold those balances to anything.
    #[test]
    fn a_devnet_manifest_refuses_a_snapshot() {
        let path = snapshot_file("uncommitted", SNAPSHOT);
        let mut m = sample();
        let err = m.ingest_carryover(&path).expect_err("no commitment, no ingestion");
        assert!(matches!(err, CarryoverError::NotCommitted), "{err}");
        let _ = fs::remove_file(&path);
    }

    /// The whole point, at the state root: a genesis that carries the
    /// Genesis-3 balances commits something different from the same genesis
    /// without them. Without this, "the snapshot was ingested" is a claim with
    /// no consequence — which is precisely how a chain launches with every
    /// balance at zero and nobody notices until a holder tries to spend.
    #[test]
    fn a_carried_genesis_commits_a_different_root() {
        use bloch_pos_committee::interfaces::StateReader;
        let with = mainnet_sample();
        // The same manifest in every other respect: same validators, same
        // cohort, same allocations, same clock. Only the carried set differs.
        let mut without = mainnet_sample();
        without.carryover = None;
        without.carryover_entries = Vec::new();
        assert_eq!(with.allocations, without.allocations);
        assert_ne!(
            with.genesis_state().state_root(),
            without.genesis_state().state_root(),
            "452,133 outputs must not be invisible at the state root"
        );
        // And the carried outputs are actually in the committed set, not
        // merely different-looking: carryover first, then allocations.
        let opening = with.opening_balances();
        assert_eq!(opening.len(), 4 + 2);
        assert_eq!(&opening[..4], &with.carryover_entries[..]);
    }

    /// Committing to a carryover and building genesis without ingesting it is
    /// the zero-balance launch. It must be impossible to do quietly.
    #[test]
    #[should_panic(expected = "call Manifest::ingest_carryover")]
    fn a_committed_carryover_without_entries_refuses_to_build_genesis() {
        let mut m = sample();
        m.carryover = Some(snapshot_commitment());
        let _ = m.genesis_state();
    }

    /// A carryover outpoint colliding with an allocation's would vanish into
    /// the state map. Constructed directly, since the file parser's ordering
    /// rule makes it unreachable from a snapshot.
    #[test]
    #[should_panic(expected = "duplicate genesis outpoint")]
    fn duplicate_opening_outpoints_are_refused() {
        let mut m = mainnet_sample();
        let first = m.carryover_entries[0].clone();
        m.carryover_entries.push(first);
        let _ = m.opening_balances();
    }

    /// The measured Genesis-3 snapshot, as published: the numbers this
    /// ingestion will meet on launch day close against the tokenomics
    /// constants. Derived from the constants and the one measured figure, so
    /// the test moves when the terminal snapshot does instead of pinning a
    /// number that was true in August.
    #[test]
    fn the_measured_snapshot_closes_against_tokenomics() {
        use bloch_pos_committee::tokenomics_v4 as t;
        // The G3 total behind `CARRYOVER_TOTAL_BLOCH`, in G3 satoshis.
        let g3_total_sat: u128 = 3_810_744_000 * t::SAT_PER_BLOCH;
        assert_eq!(
            t::split_g3_sat(g3_total_sat),
            t::CARRYOVER_TOTAL_BLOCH * t::SAT_PER_BLOCH,
            "the measured ledger under the split IS the pinned carryover — if this \
             fails, the snapshot and the constants describe different chains"
        );
        // A manifest built the way the ceremony would build it, with the
        // published root, count and post-split total, adds up to §3.
        let mut m = sample();
        m.carryover = Some(CarryoverCommitment {
            // Both are published now. The terminal snapshot was taken on two
            // independently operated nodes and produced byte-identical files —
            // same count, same total, same set root, same file digest. That
            // agreement, not this tool's say-so, is what makes the numbers
            // usable.
            digest: t::CARRYOVER_MEASURED_FILE_SHA3_256,
            set_root: t::CARRYOVER_MEASURED_ROOT,
            entry_count: t::CARRYOVER_MEASURED_UTXOS,
            total_sat: t::CARRYOVER_TOTAL_BLOCH * t::SAT_PER_BLOCH,
        });
        m.allocations = [
            (alloc_purpose::FOUNDER, t::FOUNDER_BLOCH),
            (alloc_purpose::VC, t::VC_BLOCH),
            (alloc_purpose::TEAM, t::TEAM_BLOCH),
            (alloc_purpose::MARKETING, t::MARKETING_BLOCH),
            (alloc_purpose::LIQUIDITY, t::LIQUIDITY_BLOCH),
        ]
        .iter()
        .map(|(p, bloch)| GenesisAllocation {
            purpose: *p,
            script_hash: [*p; 32],
            amount_sat: bloch * t::SAT_PER_BLOCH,
            unlock_epoch: 0,
        })
        .collect();
        m.check_supply().expect("carryover + the five buckets must equal GENESIS_ISSUED_SAT");
        assert_eq!(t::CARRYOVER_MEASURED_UTXOS, 452_726);
        assert_eq!(t::CARRYOVER_MEASURED_HEIGHT, 39_918);
    }

    #[test]
    fn allocation_outputs_are_deterministic_and_distinct() {
        let m = mainnet_sample();
        let a = m.allocation_outputs();
        let b = m.allocation_outputs();
        assert_eq!(a, b, "same manifest must synthesise the same outputs");
        assert_eq!(a.len(), 2);
        assert_ne!(a[0].txid, a[1].txid, "two allocations must not share a txid");
        // Value survives the u128 -> u64 narrowing intact.
        assert_eq!(u128::from(a[0].value), m.allocations[0].amount_sat);
        assert_eq!(a[0].script_hash, m.allocations[0].script_hash);
    }

    /// Reordering the allocation list must not change what genesis commits:
    /// the txid is derived from each allocation's own fields, not its position.
    #[test]
    fn allocation_order_does_not_change_the_outputs() {
        let m = mainnet_sample();
        let mut swapped = clone_of(&m);
        swapped.allocations.reverse();
        let mut a = m.allocation_outputs();
        let mut b = swapped.allocation_outputs();
        a.sort_by_key(|e| e.txid);
        b.sort_by_key(|e| e.txid);
        assert_eq!(a, b);
    }

    #[test]
    fn mainnet_manifest_round_trips() {
        let m = mainnet_sample();
        let back = Manifest::decode(&m.encode()).expect("round trip");
        assert_eq!(back.carryover, m.carryover);
        assert_eq!(back.allocations, m.allocations);
        assert_eq!(back.encode(), m.encode(), "re-encoding must be byte-identical");
    }

    #[test]
    fn devnet_manifest_still_round_trips() {
        // The devnet shape is the same format with the carryover flag clear,
        // not a second format.
        let m = sample();
        let back = Manifest::decode(&m.encode()).expect("round trip");
        assert_eq!(back.carryover, None);
        assert!(back.allocations.is_empty());
    }

    #[test]
    fn carryover_flag_must_be_canonical() {
        let m = sample();
        let mut bytes = m.encode();
        // The flag sits after the cohort; find it by rebuilding a manifest
        // whose only difference is the flag byte.
        let flag_at = bytes.len() - 4 - 1;
        assert_eq!(bytes[flag_at], 0, "test targets the carryover flag");
        bytes[flag_at] = 2;
        assert!(Manifest::decode(&bytes).is_err(), "a third flag value must be refused");
    }

    #[test]
    fn genesis_issuance_is_checked_against_tokenomics() {
        use bloch_pos_committee::tokenomics_v4 as t;
        // A devnet manifest carries no balances and is not held to §3.
        assert!(sample().check_supply().is_ok());

        // A mainnet manifest that does not add up is refused, and the message
        // says by how much rather than just "invalid".
        let bad = mainnet_sample();
        let err = bad.check_supply().expect_err("27.97 B is not the §3 figure");
        assert!(err.contains("tokenomics"), "{err}");

        // And one that does add up passes. Built from the constants, never
        // from a number retyped here — a test that restates the figure would
        // pass while the chain issued something else.
        let mut good = sample();
        good.carryover = Some(CarryoverCommitment {
            digest: [0xC0; 32],
            set_root: [0xC1; 32],
            entry_count: 1,
            total_sat: t::CARRYOVER_TOTAL_BLOCH * t::SAT_PER_BLOCH,
        });
        let rest = t::GENESIS_ISSUED_SAT - t::CARRYOVER_TOTAL_BLOCH * t::SAT_PER_BLOCH;
        good.allocations = vec![GenesisAllocation {
            purpose: alloc_purpose::FOUNDER,
            script_hash: [0xF1; 32],
            amount_sat: rest,
            unlock_epoch: 0,
        }];
        good.check_supply().expect("carryover + allocations must equal GENESIS_ISSUED_SAT");
    }

    #[test]
    fn manifest_round_trips() {
        let m = sample();
        let bytes = m.encode();
        let back = Manifest::decode(&bytes).expect("round trip");
        assert_eq!(back.genesis_time_ms, m.genesis_time_ms);
        assert_eq!(back.slot_ms, m.slot_ms);
        assert_eq!(back.validators.len(), 3);
        assert_eq!(
            back.validators.iter().map(|v| v.commission_bps).collect::<Vec<_>>(),
            m.validators.iter().map(|v| v.commission_bps).collect::<Vec<_>>(),
        );
        assert_eq!(back.cohort, m.cohort);
        // Genesis identity and state are pure functions of the manifest.
        use bloch_pos_committee::interfaces::StateReader;
        assert_eq!(back.genesis_id(), m.genesis_id());
        assert_eq!(back.genesis_state().state_root(), m.genesis_state().state_root());
    }

    #[test]
    fn manifest_decode_rejects_trailing_bytes() {
        let mut bytes = sample().encode();
        bytes.push(0);
        assert!(Manifest::decode(&bytes).is_err());
    }
}

#[cfg(test)]
mod blp02_hybrid_suite {
    use super::*;

    // `Manifest` does not derive Debug, and it is not this test's business to
    // make a consensus type derive one. So: is_ok/is_err plus a match for the
    // message, never expect/expect_err.
    fn decode_err(bytes: &[u8]) -> Option<&'static str> {
        match Manifest::decode(bytes) {
            Ok(_) => None,
            Err(e) => Some(e.0),
        }
    }

    fn hybrid_pk() -> Vec<u8> {
        let mut v = vec![0xB1, 0x0C, 0x01, 0x00];
        v.extend(std::iter::repeat(0x11).take(1952 + 1793));
        v
    }
    fn mldsa_only_pk() -> Vec<u8> {
        let mut v = vec![0xB1, 0x0C, 0x02, 0x00];
        v.extend(std::iter::repeat(0x22).take(1952));
        v
    }
    fn manifest_with(pk: Vec<u8>) -> Manifest {
        Manifest {
            genesis_time_ms: 1_800_000_000_000,
            slot_ms: 30_000,
            validators: vec![ManifestValidator {
                index: 0,
                stake_sat: 25_000 * 100_000_000,
                randao_commitment: [0x44u8; 32],
                pubkey: pk,
                withdrawal_credentials: [0x55u8; 32].to_vec(),
                commission_bps: 0,
            }],
            cohort: vec![0],
            carryover: None,
            allocations: vec![],
            carryover_entries: vec![],
        }
    }

    #[test]
    fn mldsa_only_validator_key_is_refused_at_decode() {
        let bytes = manifest_with(mldsa_only_pk()).encode();
        let msg = decode_err(&bytes).expect("a 0x0002 validator key must not decode");
        assert!(msg.contains("hybrid"), "the refusal must name the reason, got: {msg}");
    }

    #[test]
    fn hybrid_validator_key_still_decodes() {
        let bytes = manifest_with(hybrid_pk()).encode();
        assert!(
            Manifest::decode(&bytes).is_ok(),
            "the hybrid suite is what Genesis-4 runs and must keep decoding"
        );
    }

    #[test]
    fn a_hybrid_claim_with_no_falcon_half_is_refused() {
        // Right suite id, ML-DSA bytes only — the dangerous middle case.
        let mut pk = vec![0xB1, 0x0C, 0x01, 0x00];
        pk.extend(std::iter::repeat(0x33).take(1952));
        let bytes = manifest_with(pk).encode();
        assert!(
            decode_err(&bytes).is_some(),
            "a hybrid claim carrying no Falcon half must not decode"
        );
    }

    #[test]
    fn the_live_mainnet_manifest_still_decodes() {
        // A check that refuses the running chain is worse than the gap it closes.
        // This reads the published artefact, not a fixture this test built.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../genesis/mainnet.manifest");
        let Ok(bytes) = std::fs::read(path) else { return };
        match Manifest::decode(&bytes) {
            Ok(m) => assert_eq!(m.validators.len(), 64, "the live set is 64 validators"),
            Err(e) => panic!("the live Genesis-4 manifest must decode, got: {}", e.0),
        }
    }
}
