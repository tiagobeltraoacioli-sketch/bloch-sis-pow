// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable withdrawal state — the half of the idempotency guarantee that
//! survives a crash.
//!
//! ## Why the store is load-bearing
//!
//! On this chain the transaction cannot be its own idempotency key: a rebuilt
//! attempt has different bytes and a different txid, and there is no
//! `gettransaction` to ask. The only identity a withdrawal has is the one
//! the CALLER gives it — the withdrawal id — and the only thing that makes
//! "pay this id at most once" survive a process restart is what this module
//! persists: which coins the id pinned, which attempts were built over them,
//! and how far the state machine got.
//!
//! The write discipline is write-ahead: a record is saved with its new
//! attempt **before** the attempt's bytes are submitted, and pinned coins are
//! saved **before** the first attempt over them is built. A crash between
//! save and submit re-submits the same bytes; a crash before save loses only
//! an attempt that was never sent. At no point can the process know less
//! than the network does.
//!
//! [`FileStore`] is a reference implementation (one JSON file per id, atomic
//! rename). An exchange with a real database implements [`Store`] over it —
//! the trait is three methods, and the semantics it must honor are documented
//! on each.

use std::collections::BTreeSet;
use std::io;
use std::path::PathBuf;

use crate::json::Json;

/// One spendable output the hot wallet controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Coin {
    pub txid: [u8; 32],
    pub vout: u32,
    pub value_sat: u64,
}

impl Coin {
    pub fn outpoint(&self) -> ([u8; 32], u32) {
        (self.txid, self.vout)
    }
}

/// Payment or cancellation sweep. Both spend the pinned set in full — the
/// sweep is "the attempt that pays nobody", not a different mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptKind {
    Pay,
    Sweep,
}

/// One signed attempt: everything needed to resubmit it byte-identically and
/// to recognize it on-chain later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub kind: AttemptKind,
    /// Derived transaction id — the key of the outputs this attempt creates,
    /// and how inclusion is recognized (`gettxout(txid, 0)`).
    pub txid: [u8; 32],
    /// The base fee these bytes commit to. The attempt is includable only in
    /// a block charging exactly this price; at any other price it is invalid.
    pub base_fee_msat_per_gas: u128,
    pub tip_msat_per_gas: u128,
    pub declared_tx_bytes: u64,
    /// The canonical bytes, hex — resubmission sends exactly these.
    pub canonical_hex: String,
    pub change_sat: u64,
}

/// Where a withdrawal stands. Terminal states are terminal: nothing moves a
/// record out of `Paid` or `Cancelled`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Coins pinned (or about to be); no attempt confirmed in flight yet, or
    /// the last observation saw the pinned coins unspent.
    Submitted,
    /// The pinned coins were observed SPENT at `observed_slot`. `landed` is
    /// the index of the attempt whose output was found, if identifiable.
    /// Waiting for the finalized boundary to pass `observed_slot`.
    AwaitingFinality { landed: Option<usize>, observed_slot: u64 },
    /// Terminal: a payment attempt is in finalized history. The recipient
    /// has the money; this id must never build again.
    Paid { attempt: Option<usize> },
    /// Terminal: the cancellation sweep is in finalized history. The
    /// recipient was NOT paid and the coins are back in the hot wallet.
    Cancelled { attempt: usize },
}

impl Status {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Status::Paid { .. } | Status::Cancelled { .. })
    }
}

/// The durable record of one withdrawal id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithdrawalRecord {
    /// The caller's idempotency key. The library never invents one.
    pub id: String,
    pub recipient_script_hash: [u8; 32],
    pub amount_sat: u64,
    /// The pinned inputs. INVARIANT: this set only ever grows, and every
    /// attempt in `attempts` spends exactly the set as of when it was built —
    /// which is why any two attempts conflict and at most one can land.
    pub pinned: Vec<Coin>,
    pub attempts: Vec<Attempt>,
    pub status: Status,
    /// Set by `cancel()`: the next build is a sweep instead of a payment.
    pub cancel_requested: bool,
}

/// Persistence for withdrawal records.
///
/// Contract:
/// - `save` must be atomic and durable before it returns — a torn record is
///   worse than a lost one, and a lost one can double-build.
/// - `load` returns exactly what the last successful `save` wrote.
/// - `list_ids` must see every saved record; coin reservation walks it.
pub trait Store {
    fn load(&self, id: &str) -> io::Result<Option<WithdrawalRecord>>;
    fn save(&self, record: &WithdrawalRecord) -> io::Result<()>;
    fn list_ids(&self) -> io::Result<Vec<String>>;
}

/// Every outpoint some non-terminal withdrawal has pinned, plus every output
/// a non-terminal withdrawal's attempts might create. Coin selection must
/// avoid both: the former because those coins are promised to another id, the
/// latter because spending an in-flight attempt's change before that
/// withdrawal terminalizes would blind its landed-attempt detection.
pub fn reserved_outpoints(store: &dyn Store) -> io::Result<BTreeSet<([u8; 32], u32)>> {
    let mut reserved = BTreeSet::new();
    for id in store.list_ids()? {
        let Some(rec) = store.load(&id)? else { continue };
        if rec.status.is_terminal() {
            continue;
        }
        for c in &rec.pinned {
            reserved.insert(c.outpoint());
        }
        for a in &rec.attempts {
            // A transfer creates at most 2 outputs (payment, change).
            reserved.insert((a.txid, 0));
            reserved.insert((a.txid, 1));
        }
    }
    Ok(reserved)
}

// ─── JSON (de)serialization ─────────────────────────────────────────────────

fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

impl WithdrawalRecord {
    pub fn to_json(&self) -> String {
        let status = match &self.status {
            Status::Submitted => Json::Obj(vec![("state".into(), Json::s("submitted"))]),
            Status::AwaitingFinality { landed, observed_slot } => Json::Obj(vec![
                ("state".into(), Json::s("awaiting_finality")),
                ("landed".into(), landed.map_or(Json::Null, |i| Json::u(i as u64))),
                ("observed_slot".into(), Json::u(*observed_slot)),
            ]),
            Status::Paid { attempt } => Json::Obj(vec![
                ("state".into(), Json::s("paid")),
                ("attempt".into(), attempt.map_or(Json::Null, |i| Json::u(i as u64))),
            ]),
            Status::Cancelled { attempt } => Json::Obj(vec![
                ("state".into(), Json::s("cancelled")),
                ("attempt".into(), Json::u(*attempt as u64)),
            ]),
        };
        Json::Obj(vec![
            ("id".into(), Json::s(self.id.clone())),
            ("recipient_script_hash".into(), Json::hex(&self.recipient_script_hash)),
            ("amount_sat".into(), Json::s(self.amount_sat.to_string())),
            (
                "pinned".into(),
                Json::Arr(
                    self.pinned
                        .iter()
                        .map(|c| {
                            Json::Obj(vec![
                                ("txid".into(), Json::hex(&c.txid)),
                                ("vout".into(), Json::u(u64::from(c.vout))),
                                ("value_sat".into(), Json::s(c.value_sat.to_string())),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "attempts".into(),
                Json::Arr(
                    self.attempts
                        .iter()
                        .map(|a| {
                            Json::Obj(vec![
                                (
                                    "kind".into(),
                                    Json::s(match a.kind {
                                        AttemptKind::Pay => "pay",
                                        AttemptKind::Sweep => "sweep",
                                    }),
                                ),
                                ("txid".into(), Json::hex(&a.txid)),
                                (
                                    "base_fee_msat_per_gas".into(),
                                    Json::s(a.base_fee_msat_per_gas.to_string()),
                                ),
                                (
                                    "tip_msat_per_gas".into(),
                                    Json::s(a.tip_msat_per_gas.to_string()),
                                ),
                                ("declared_tx_bytes".into(), Json::u(a.declared_tx_bytes)),
                                ("canonical_hex".into(), Json::s(a.canonical_hex.clone())),
                                ("change_sat".into(), Json::s(a.change_sat.to_string())),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("status".into(), status),
            ("cancel_requested".into(), Json::Bool(self.cancel_requested)),
        ])
        .to_json()
    }

    pub fn from_json(text: &str) -> Result<WithdrawalRecord, String> {
        let v = Json::parse(text)?;
        let str_field = |key: &str| -> Result<String, String> {
            v.get(key)
                .and_then(Json::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("`{key}` missing"))
        };
        let recipient_script_hash =
            crate::hex32(&str_field("recipient_script_hash")?).ok_or("bad recipient hash")?;
        let amount_sat = v
            .get("amount_sat")
            .and_then(Json::as_sat_u64)
            .ok_or("`amount_sat` missing")?;

        let mut pinned = Vec::new();
        if let Some(Json::Arr(items)) = v.get("pinned") {
            for item in items {
                pinned.push(Coin {
                    txid: item
                        .get("txid")
                        .and_then(Json::as_str)
                        .and_then(crate::hex32)
                        .ok_or("bad pinned txid")?,
                    vout: item
                        .get("vout")
                        .and_then(Json::as_u64)
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or("bad pinned vout")?,
                    value_sat: item
                        .get("value_sat")
                        .and_then(Json::as_sat_u64)
                        .ok_or("bad pinned value")?,
                });
            }
        } else {
            return Err("`pinned` missing".into());
        }

        let mut attempts = Vec::new();
        if let Some(Json::Arr(items)) = v.get("attempts") {
            for item in items {
                attempts.push(Attempt {
                    kind: match item.get("kind").and_then(Json::as_str) {
                        Some("pay") => AttemptKind::Pay,
                        Some("sweep") => AttemptKind::Sweep,
                        _ => return Err("bad attempt kind".into()),
                    },
                    txid: item
                        .get("txid")
                        .and_then(Json::as_str)
                        .and_then(crate::hex32)
                        .ok_or("bad attempt txid")?,
                    base_fee_msat_per_gas: item
                        .get("base_fee_msat_per_gas")
                        .and_then(Json::as_sat_u128)
                        .ok_or("bad attempt base fee")?,
                    tip_msat_per_gas: item
                        .get("tip_msat_per_gas")
                        .and_then(Json::as_sat_u128)
                        .ok_or("bad attempt tip")?,
                    declared_tx_bytes: item
                        .get("declared_tx_bytes")
                        .and_then(Json::as_u64)
                        .ok_or("bad attempt declared bytes")?,
                    canonical_hex: item
                        .get("canonical_hex")
                        .and_then(Json::as_str)
                        .map(str::to_string)
                        .ok_or("bad attempt bytes")?,
                    change_sat: item
                        .get("change_sat")
                        .and_then(Json::as_sat_u64)
                        .ok_or("bad attempt change")?,
                });
            }
        } else {
            return Err("`attempts` missing".into());
        }

        let status_v = v.get("status").ok_or("`status` missing")?;
        let attempt_idx = |key: &str| -> Option<usize> {
            status_v.get(key).and_then(Json::as_u64).and_then(|n| usize::try_from(n).ok())
        };
        let status = match status_v.get("state").and_then(Json::as_str) {
            Some("submitted") => Status::Submitted,
            Some("awaiting_finality") => Status::AwaitingFinality {
                landed: attempt_idx("landed"),
                observed_slot: status_v
                    .get("observed_slot")
                    .and_then(Json::as_u64)
                    .ok_or("bad observed_slot")?,
            },
            Some("paid") => Status::Paid { attempt: attempt_idx("attempt") },
            Some("cancelled") => {
                Status::Cancelled { attempt: attempt_idx("attempt").ok_or("bad attempt index")? }
            }
            _ => return Err("bad status".into()),
        };

        Ok(WithdrawalRecord {
            id: str_field("id")?,
            recipient_script_hash,
            amount_sat,
            pinned,
            attempts,
            status,
            cancel_requested: v
                .get("cancel_requested")
                .and_then(Json::as_bool)
                .unwrap_or(false),
        })
    }
}

// ─── File-backed store ──────────────────────────────────────────────────────

/// One JSON file per withdrawal id under a directory; `save` writes to a
/// temporary file, fsyncs it, and renames over the target — the standard
/// atomic-replace, so a crash leaves either the old record or the new one,
/// never a torn one.
pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<FileStore> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(FileStore { dir })
    }

    /// Ids are caller-chosen strings; the filename is their hex so no id can
    /// escape the directory or collide with another's encoding.
    fn path_of(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{}.json", hex_of(id.as_bytes())))
    }
}

impl Store for FileStore {
    fn load(&self, id: &str) -> io::Result<Option<WithdrawalRecord>> {
        let path = self.path_of(id);
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        WithdrawalRecord::from_json(&text)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{path:?}: {e}")))
    }

    fn save(&self, record: &WithdrawalRecord) -> io::Result<()> {
        use std::io::Write as _;
        let path = self.path_of(&record.id);
        let tmp = path.with_extension("json.tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(record.to_json().as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn list_ids(&self) -> io::Result<Vec<String>> {
        let mut ids = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(hex_id) = name.strip_suffix(".json") else { continue };
            if let Some(bytes) = decode_hex(hex_id) {
                if let Ok(id) = String::from_utf8(bytes) {
                    ids.push(id);
                }
            }
        }
        ids.sort();
        Ok(ids)
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in b.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// In-memory store for tests and for embedding under an exchange's own
/// transactional database (load-modify-save under the DB's own lock).
#[derive(Default)]
pub struct MemStore {
    records: std::sync::Mutex<std::collections::BTreeMap<String, String>>,
}

impl MemStore {
    pub fn new() -> MemStore {
        MemStore::default()
    }
}

impl Store for MemStore {
    fn load(&self, id: &str) -> io::Result<Option<WithdrawalRecord>> {
        let map = self.records.lock().unwrap();
        match map.get(id) {
            None => Ok(None),
            Some(text) => WithdrawalRecord::from_json(text)
                .map(Some)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        }
    }
    fn save(&self, record: &WithdrawalRecord) -> io::Result<()> {
        let mut map = self.records.lock().unwrap();
        map.insert(record.id.clone(), record.to_json());
        Ok(())
    }
    fn list_ids(&self) -> io::Result<Vec<String>> {
        Ok(self.records.lock().unwrap().keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> WithdrawalRecord {
        WithdrawalRecord {
            id: "wd/2026-08-31/0007".into(),
            recipient_script_hash: [0xAB; 32],
            amount_sat: 40_000_000,
            pinned: vec![Coin { txid: [1; 32], vout: 3, value_sat: 100_000_000 }],
            attempts: vec![Attempt {
                kind: AttemptKind::Pay,
                txid: [2; 32],
                base_fee_msat_per_gas: 10,
                tip_msat_per_gas: 0,
                declared_tx_bytes: 12_345,
                canonical_hex: "06aabb".into(),
                change_sat: 59_000_000,
            }],
            status: Status::AwaitingFinality { landed: Some(0), observed_slot: 48_000 },
            cancel_requested: false,
        }
    }

    #[test]
    fn record_roundtrips_through_json() {
        let rec = sample();
        let parsed = WithdrawalRecord::from_json(&rec.to_json()).unwrap();
        assert_eq!(parsed, rec);
    }

    #[test]
    fn file_store_roundtrip_and_listing() {
        let dir = std::env::temp_dir().join(format!("bloch-withdraw-test-{}", std::process::id()));
        let store = FileStore::open(&dir).unwrap();
        let rec = sample();
        assert!(store.load(&rec.id).unwrap().is_none());
        store.save(&rec).unwrap();
        assert_eq!(store.load(&rec.id).unwrap().unwrap(), rec);
        assert_eq!(store.list_ids().unwrap(), vec![rec.id.clone()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reservation_covers_pins_and_attempt_outputs_until_terminal() {
        let store = MemStore::new();
        let mut rec = sample();
        store.save(&rec).unwrap();
        let reserved = reserved_outpoints(&store).unwrap();
        assert!(reserved.contains(&([1; 32], 3)), "pinned coin reserved");
        assert!(reserved.contains(&([2; 32], 0)) && reserved.contains(&([2; 32], 1)));
        // Terminal records release everything.
        rec.status = Status::Paid { attempt: Some(0) };
        store.save(&rec).unwrap();
        assert!(reserved_outpoints(&store).unwrap().is_empty());
    }
}
