// SPDX-License-Identifier: AGPL-3.0-or-later
//! Node-local L2 brake (agent 169's `LOCAL-BRAKE-DESIGN.md`, built by agent 222).
//!
//! NOT CONSENSUS. A signed file in the data dir makes THIS node, while it is
//! valid:
//!
//! 1. as proposer, leave out of its blocks L2 withdrawal claims (wire 0x16)
//!    whose leaf index is at or above `claims_from_leaf_index`, and, with
//!    `settlements`, every L2 settlement proof;
//! 2. at the mempool door (RPC and gossip meet at `on_transaction`), refuse
//!    those same transactions as STATE-DEPENDENT (retry later), never as
//!    invalid, so no peer is penalized and nothing stays barred once the brake
//!    lifts.
//!
//! Block validation is untouched: a block from another proposer that carries a
//! held claim is checked and applied exactly as before. A brake cannot split
//! the chain. Against an attacker it is a speed bump unless the stake that runs
//! it proposes essentially every slot; its real job is G2b (own settler, honest
//! users relaying through the own RPCs), where it keeps the plain head reset
//! reachable.
//!
//! Fail-open by construction, so a mistake can never censor:
//! - no `--l2-brake-key`: the brake is DISABLED and the file is ignored;
//! - no file: off;
//! - unreadable, malformed, unsigned, badly signed, another network or another
//!   L2 chain, `until_epoch` past or more than [`MAX_AHEAD_EPOCHS`] ahead:
//!   off, with a CRIT line every slot while the file stays.
//!
//! Files: `<data dir>/l2-brake.json` and `<data dir>/l2-brake.json.sig` (the
//! hybrid ML-DSA-65 + Falcon-1024 signature, hex, one line) over
//! `SHA3-256("BLOCH:L2:BRAKE:1" || network admission domain || file bytes)`,
//! made with `bloch-pos l2-brake sign`. The public key comes from the
//! `--l2-brake-key` file, which belongs outside the data dir (root-owned), so
//! write access to the data dir alone cannot engage a brake. Both files are
//! re-read at most once per slot, and only when their size or mtime changed.

use crate::codec;
use crate::rpc::{parse_json, Json};
use bloch_pos_committee::transition::PosTransaction;
use sha3::{Digest, Sha3_256};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

pub const FILE: &str = "l2-brake.json";
pub const SIG_FILE: &str = "l2-brake.json.sig";
pub const DOMAIN: &[u8] = b"BLOCH:L2:BRAKE:1";
/// Two weeks of 960 s epochs: a forgotten file switches itself off.
pub const MAX_AHEAD_EPOCHS: u64 = 1_350;
pub const MAX_REASON_BYTES: usize = 200;
/// Larger brake files are refused unread (the format is a few hundred bytes).
pub const MAX_FILE_BYTES: u64 = 4_096;
/// The same for the signature file (a hybrid signature in hex is about 9 KiB).
pub const MAX_SIG_FILE_BYTES: u64 = 32_768;

/// A parsed, signed and in-range brake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Brake {
    pub chain_id: u64,
    /// Claims with `index >= claims_from` are held; `None` holds no claim.
    pub claims_from: Option<u64>,
    pub settlements: bool,
    /// Off from this epoch on.
    pub until_epoch: u64,
    pub reason: String,
}

/// What the signer signs.
pub fn digest(network_domain: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DOMAIN);
    h.update(network_domain);
    h.update(body);
    h.finalize().into()
}

/// Parse the JSON body, strictly: exactly the six keys, `version` 1.
pub fn parse(body: &[u8]) -> Result<Brake, String> {
    let text = std::str::from_utf8(body).map_err(|_| "not UTF-8".to_string())?;
    let doc = parse_json(text).map_err(|e| format!("JSON: {e}"))?;
    let Json::Obj(fields) = &doc else { return Err("not a JSON object".into()) };
    const KEYS: [&str; 6] = ["version", "chain_id", "claims_from_leaf_index", "settlements", "until_epoch", "reason"];
    for (key, _) in fields {
        if !KEYS.contains(&key.as_str()) {
            return Err(format!("unknown key `{key}`"));
        }
        if fields.iter().filter(|(k, _)| k == key).count() != 1 {
            return Err(format!("duplicate key `{key}`"));
        }
    }
    let num = |key: &str| -> Result<u64, String> {
        match doc.get(key) {
            Some(Json::Num(raw)) => raw.parse().map_err(|_| format!("`{key}` must be an unsigned integer")),
            _ => Err(format!("`{key}` must be an unsigned integer")),
        }
    };
    if num("version")? != 1 {
        return Err("`version` must be 1".into());
    }
    let claims_from = match doc.get("claims_from_leaf_index") {
        Some(Json::Null) => None,
        Some(_) => Some(num("claims_from_leaf_index")?),
        None => return Err("`claims_from_leaf_index` is required (a number, or null)".into()),
    };
    let settlements = match doc.get("settlements") {
        Some(Json::Bool(b)) => *b,
        _ => return Err("`settlements` must be true or false".into()),
    };
    let reason = match doc.get("reason") {
        Some(Json::Str(s)) if !s.is_empty() && s.len() <= MAX_REASON_BYTES => s.clone(),
        _ => return Err(format!("`reason` must be a string of 1 to {MAX_REASON_BYTES} bytes")),
    };
    Ok(Brake { chain_id: num("chain_id")?, claims_from, settlements, until_epoch: num("until_epoch")?, reason })
}

/// Parse, check the signature and the range against `epoch` and the L2
/// chain the node follows (`None`: no L2, and no brake).
pub fn load(
    body: &[u8],
    signature: &[u8],
    key: &[u8],
    network_domain: &[u8; 32],
    l2_chain_id: Option<u64>,
    epoch: u64,
) -> Result<Brake, String> {
    if !bloch_crypto::crypto::verify(key, &digest(network_domain, body), signature) {
        return Err("signature does not verify under --l2-brake-key for this network".into());
    }
    let brake = parse(body)?;
    if Some(brake.chain_id) != l2_chain_id {
        return Err(format!("chain_id {} is not this node's L2 ({l2_chain_id:?})", brake.chain_id));
    }
    if brake.until_epoch <= epoch {
        return Err(format!("until_epoch {} has passed (epoch {epoch})", brake.until_epoch));
    }
    if brake.until_epoch > epoch.saturating_add(MAX_AHEAD_EPOCHS) {
        return Err(format!("until_epoch {} is more than {MAX_AHEAD_EPOCHS} epochs ahead of {epoch}", brake.until_epoch));
    }
    Ok(brake)
}

impl Brake {
    /// Whether this brake holds `tx` in `epoch`.
    pub fn holds(&self, tx: &PosTransaction, epoch: u64) -> bool {
        if epoch >= self.until_epoch {
            return false;
        }
        match tx {
            PosTransaction::L2WithdrawClaim(claim) => {
                claim.l2_chain_id == self.chain_id && self.claims_from.is_some_and(|from| claim.index >= from)
            }
            PosTransaction::L2SettlementAsync(_) | PosTransaction::L2Settlement(_) => self.settlements,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// No `--l2-brake-key`: never reads the file.
    Disabled,
    /// No file.
    Off,
    /// A file that does not engage the brake, and why.
    Refused(String),
    On(Brake),
}

type Stamp = Option<(u64, SystemTime, u64, SystemTime)>;

struct Inner {
    checked_slot: Option<u64>,
    /// (len, mtime) of the file and of the signature at the last read, with
    /// the epoch and L2 chain it was judged against.
    stamp: Stamp,
    judged: Option<(u64, Option<u64>, [u8; 32])>,
    status: Status,
    held: u64,
}

/// The brake as the engine holds it: interior state behind a lock, so the
/// read-only proposer path can refresh it and count what it held.
pub struct BrakeCell {
    dir: Option<PathBuf>,
    key: Option<Vec<u8>>,
    inner: Mutex<Inner>,
}

impl BrakeCell {
    pub fn disabled() -> Self {
        Self::new(None, None)
    }

    /// `dir` is the data dir; `key` the enveloped hybrid public key.
    pub fn new(dir: Option<PathBuf>, key: Option<Vec<u8>>) -> Self {
        let status = if key.is_some() && dir.is_some() { Status::Off } else { Status::Disabled };
        Self {
            dir,
            key,
            inner: Mutex::new(Inner { checked_slot: None, stamp: None, judged: None, status, held: 0 }),
        }
    }

    /// Read `--l2-brake-key`: the hex enveloped public key (`ws-keygen .pk`).
    pub fn read_key(path: &Path) -> Result<Vec<u8>, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let key = codec::unhex(text.trim())?;
        if key.len() != bloch_pos_committee::transition::funded::ADMISSION_PQ_KEY_BYTES {
            return Err(format!(
                "{}: an enveloped hybrid public key has {} bytes, not {}",
                path.display(),
                bloch_pos_committee::transition::funded::ADMISSION_PQ_KEY_BYTES,
                key.len()
            ));
        }
        Ok(key)
    }

    /// Re-judge the file for `slot` (at most once per slot; the file is
    /// re-read only when it changed, or when the epoch or chain moved).
    pub fn refresh(&self, slot: u64, epoch: u64, network_domain: Option<[u8; 32]>, l2_chain_id: Option<u64>) {
        let (Some(dir), Some(key)) = (&self.dir, &self.key) else { return };
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if inner.checked_slot == Some(slot) {
            return;
        }
        inner.checked_slot = Some(slot);
        let (file, sig) = (dir.join(FILE), dir.join(SIG_FILE));
        let meta = |p: &Path| std::fs::metadata(p).ok().map(|m| (m.len(), m.modified().unwrap_or(SystemTime::UNIX_EPOCH)));
        let Some((flen, fmod)) = meta(&file) else {
            inner.stamp = None;
            inner.judged = None;
            inner.status = Status::Off;
            return;
        };
        let (slen, smod) = meta(&sig).unwrap_or((0, SystemTime::UNIX_EPOCH));
        let stamp = Some((flen, fmod, slen, smod));
        let Some(network) = network_domain else {
            inner.status = Status::Refused("this network has no admission domain".into());
            eprintln!("CRIT l2-brake: {} refused, brake OFF: no admission domain", file.display());
            return;
        };
        let judged = Some((epoch, l2_chain_id, network));
        if inner.stamp == stamp && inner.judged == judged {
            if let Status::Refused(why) = &inner.status {
                eprintln!("CRIT l2-brake: {} refused, brake OFF: {why}", file.display());
            }
            return;
        }
        inner.stamp = stamp;
        inner.judged = judged;
        let read = |p: &Path, max: u64| -> Result<Vec<u8>, String> {
            if std::fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()))?.len() > max {
                return Err(format!("{} exceeds {max} bytes", p.display()));
            }
            std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))
        };
        let verdict = read(&file, MAX_FILE_BYTES).and_then(|body| {
            let sig_text = read(&sig, MAX_SIG_FILE_BYTES)?;
            let signature = codec::unhex(String::from_utf8_lossy(&sig_text).trim()).map_err(|e| format!("signature file: {e}"))?;
            load(&body, &signature, key, &network, l2_chain_id, epoch)
        });
        let previous = std::mem::replace(&mut inner.status, Status::Off);
        inner.status = match verdict {
            Ok(brake) => {
                if previous != Status::On(brake.clone()) {
                    eprintln!(
                        "WARN l2-brake: ON for chain {}: claims from leaf {:?}, settlements {}, until epoch {}: {}",
                        brake.chain_id, brake.claims_from, brake.settlements, brake.until_epoch, brake.reason
                    );
                }
                Status::On(brake)
            }
            Err(why) => {
                eprintln!("CRIT l2-brake: {} refused, brake OFF: {why}", file.display());
                Status::Refused(why)
            }
        };
    }

    /// Whether the brake holds `tx` in `epoch` (as last refreshed). Counts the
    /// decision (`holds_since_start`), not distinct transactions; no log line
    /// per transaction, so a flood of resubmissions cannot fill the log.
    pub fn holds(&self, tx: &PosTransaction, epoch: u64) -> bool {
        if self.key.is_none() {
            return false;
        }
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let held = matches!(&inner.status, Status::On(brake) if brake.holds(tx, epoch));
        if held {
            inner.held = inner.held.saturating_add(1);
        }
        held
    }

    #[cfg(test)]
    pub fn status(&self) -> Status {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).status.clone()
    }

    /// The `getmempoolinfo.l2_brake` object.
    pub fn json(&self, epoch: u64) -> Json {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let (state, brake, why) = match &inner.status {
            Status::Disabled => ("disabled", None, None),
            Status::Off => ("off", None, None),
            Status::Refused(why) => ("refused", None, Some(why.clone())),
            Status::On(b) if epoch >= b.until_epoch => ("expired", Some(b), None),
            Status::On(b) => ("on", Some(b), None),
        };
        Json::obj(vec![
            ("state", Json::s(state)),
            ("active", Json::Bool(state == "on")),
            ("chain_id", brake.map_or(Json::Null, |b| Json::u(b.chain_id))),
            ("claims_from_leaf_index", brake.and_then(|b| b.claims_from).map_or(Json::Null, Json::u)),
            ("settlements", Json::Bool(brake.is_some_and(|b| b.settlements))),
            ("until_epoch", brake.map_or(Json::Null, |b| Json::u(b.until_epoch))),
            ("reason", brake.map_or(Json::Null, |b| Json::s(b.reason.clone()))),
            ("refused", why.map_or(Json::Null, Json::s)),
            ("holds_since_start", Json::u(inner.held)),
        ])
    }
}

/// `bloch-pos l2-brake …`: sign and check a brake file offline.
pub fn run(args: &[String]) -> Result<(), String> {
    use crate::l2_deposit_cli::{domain, get, options, read_text};
    const HELP: &str = "Node-local L2 brake (not consensus): sign and check the file a node reads from its data dir

sign --genesis TRUSTED_FILE --brake l2-brake.json --key SK_FILE --pubkey PK_FILE --out l2-brake.json.sig
        sign the exact file bytes for this network with the brake key (ws-keygen .sk/.pk)
check --genesis TRUSTED_FILE --brake l2-brake.json --sig l2-brake.json.sig --pubkey PK_FILE --epoch E [--chain-id ID]
        what a node started with --l2-brake-key PK_FILE would do with these files at epoch E

l2-brake.json (exactly these keys):
  {\"version\":1, \"chain_id\":700770, \"claims_from_leaf_index\":4128 | null,
   \"settlements\":false, \"until_epoch\":10700, \"reason\":\"G2 ...: reset target N\"}
Claims with a leaf index at or above claims_from_leaf_index, and every settlement
proof when settlements is true, are left out of this node's blocks and refused at
its mempool as retry-later. Blocks from other proposers are validated as always.
until_epoch must be ahead and at most 1350 epochs (two weeks) away. Copy both
files into each node's data dir; delete them (or let until_epoch pass) to lift.";
    match args.first().map(String::as_str) {
        Some("sign") => {
            let o = options(&args[1..], &["--genesis", "--brake", "--key", "--pubkey", "--out"])?;
            let body = std::fs::read(get(&o, "--brake")?).map_err(|e| e.to_string())?;
            parse(&body)?;
            let network = domain(get(&o, "--genesis")?)?;
            let pubkey = BrakeCell::read_key(Path::new(get(&o, "--pubkey")?))?;
            let sk = zeroize::Zeroizing::new(codec::unhex(read_text(get(&o, "--key")?)?.trim())?);
            let d = digest(&network, &body);
            let signature = bloch_crypto::crypto::sign_fitting(&sk, &d, usize::MAX).map_err(|e| format!("signing failed: {e:?}"))?;
            if !bloch_crypto::crypto::verify(&pubkey, &d, &signature) {
                return Err("the signature does not verify under --pubkey: wrong key pair".into());
            }
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(get(&o, "--out")?)
                .map_err(|e| e.to_string())?;
            use std::io::Write;
            writeln!(file, "{}", codec::hex(&signature)).map_err(|e| e.to_string())?;
            println!("signed brake digest {}", codec::hex32(&d));
            Ok(())
        }
        Some("check") => {
            let o = options(&args[1..], &["--genesis", "--brake", "--sig", "--pubkey", "--epoch", "--chain-id"])?;
            let body = std::fs::read(get(&o, "--brake")?).map_err(|e| e.to_string())?;
            let signature = codec::unhex(read_text(get(&o, "--sig")?)?.trim())?;
            let pubkey = BrakeCell::read_key(Path::new(get(&o, "--pubkey")?))?;
            let epoch: u64 = get(&o, "--epoch")?.parse().map_err(|_| "bad --epoch")?;
            let chain_id = match o.iter().find(|(f, _)| f == "--chain-id") {
                Some((_, v)) => v.parse().map_err(|_| "bad --chain-id")?,
                None => bloch_pos_committee::l2_settlement::MAINNET_CHAIN_ID,
            };
            let brake = load(&body, &signature, &pubkey, &domain(get(&o, "--genesis")?)?, Some(chain_id), epoch)?;
            println!(
                "ON at epoch {epoch}: chain {}, claims from leaf {:?}, settlements {}, until epoch {}: {}",
                brake.chain_id, brake.claims_from, brake.settlements, brake.until_epoch, brake.reason
            );
            Ok(())
        }
        _ => {
            println!("{HELP}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_pos_committee::l2_settlement::withdrawal::TREE_DEPTH;
    use bloch_pos_committee::transition::{FundingInput, L2WithdrawClaim, TransferOutput};

    const NET: [u8; 32] = [0x91; 32];

    pub(crate) fn claim(index: u64, chain: u64) -> PosTransaction {
        PosTransaction::L2WithdrawClaim(L2WithdrawClaim {
            network_domain: NET,
            funding_pubkey: vec![1; 8],
            inputs: vec![FundingInput { txid: [0x33; 32], vout: 0 }],
            l2_chain_id: chain,
            index,
            l1_recipient: [2; 32],
            sats: 1_000,
            siblings: [[0; 32]; TREE_DEPTH],
            release: TransferOutput { value: 1_000, script_hash: [2; 32] },
            change: TransferOutput { value: 0, script_hash: [3; 32] },
            tx_bytes: 0,
            tip_millisat_per_gas: 0,
            attestation: None,
            signature: vec![0; 8],
        })
    }

    pub(crate) fn body(from: &str, settlements: bool, until: u64) -> Vec<u8> {
        format!(
            r#"{{"version":1,"chain_id":700770,"claims_from_leaf_index":{from},"settlements":{settlements},"until_epoch":{until},"reason":"G2 drill: reset target 41"}}"#
        )
        .into_bytes()
    }

    pub(crate) fn sign(sk: &[u8], body: &[u8]) -> Vec<u8> {
        bloch_crypto::crypto::sign_fitting(sk, &digest(&NET, body), usize::MAX).unwrap()
    }

    #[test]
    fn a_signed_brake_holds_claims_from_its_index_and_nothing_else() {
        let (pk, sk) = bloch_crypto::crypto::generate_keypair();
        let b = body("4128", false, 10_700);
        let brake = load(&b, &sign(&sk, &b), &pk, &NET, Some(700_770), 10_000).unwrap();
        assert!(brake.holds(&claim(4128, 700_770), 10_000));
        assert!(brake.holds(&claim(9_999, 700_770), 10_699));
        assert!(!brake.holds(&claim(4127, 700_770), 10_000), "honest leaves below the index still pay");
        assert!(!brake.holds(&claim(4128, 700_771), 10_000), "another L2 chain");
        assert!(!brake.holds(&claim(4128, 700_770), 10_700), "off at until_epoch");
        let none = parse(&body("null", true, 10_700)).unwrap();
        assert!(!none.holds(&claim(0, 700_770), 1));
    }

    #[test]
    fn the_signature_binds_the_key_the_network_and_every_byte() {
        let (pk, sk) = bloch_crypto::crypto::generate_keypair();
        let (pk2, _) = bloch_crypto::crypto::generate_keypair();
        let b = body("0", true, 10_700);
        let sig = sign(&sk, &b);
        assert!(load(&b, &sig, &pk, &NET, Some(700_770), 10_000).is_ok());
        assert!(load(&b, &sig, &pk2, &NET, Some(700_770), 10_000).is_err(), "another key");
        assert!(load(&b, &sig, &pk, &[0x92; 32], Some(700_770), 10_000).is_err(), "another network");
        let mut edited = b.clone();
        edited.push(b' ');
        assert!(load(&edited, &sig, &pk, &NET, Some(700_770), 10_000).is_err(), "one byte more");
        assert!(load(&b, &[], &pk, &NET, Some(700_770), 10_000).is_err(), "unsigned");
    }

    #[test]
    fn the_range_and_the_shape_are_checked() {
        let (pk, sk) = bloch_crypto::crypto::generate_keypair();
        let at = |b: &[u8], epoch| load(b, &sign(&sk, b), &pk, &NET, Some(700_770), epoch);
        let b = body("7", false, 10_000);
        assert!(at(&b, 9_999).is_ok());
        assert!(at(&b, 10_000).is_err(), "until_epoch passed");
        assert!(at(&b, 10_000 - MAX_AHEAD_EPOCHS).is_ok());
        assert!(at(&b, 10_000 - MAX_AHEAD_EPOCHS - 1).is_err(), "more than two weeks ahead");
        assert!(load(&b, &sign(&sk, &b), &pk, &NET, None, 9_999).is_err(), "no L2");
        assert!(load(&b, &sign(&sk, &b), &pk, &NET, Some(700_771), 9_999).is_err(), "another L2");
        for bad in [
            r#"{"version":2,"chain_id":700770,"claims_from_leaf_index":1,"settlements":false,"until_epoch":5,"reason":"x"}"#,
            r#"{"version":1,"chain_id":700770,"settlements":false,"until_epoch":5,"reason":"x"}"#,
            r#"{"version":1,"chain_id":700770,"claims_from_leaf_index":-1,"settlements":false,"until_epoch":5,"reason":"x"}"#,
            r#"{"version":1,"chain_id":700770,"claims_from_leaf_index":1,"settlements":"no","until_epoch":5,"reason":"x"}"#,
            r#"{"version":1,"chain_id":700770,"claims_from_leaf_index":1,"settlements":false,"until_epoch":5,"reason":""}"#,
            r#"{"version":1,"chain_id":700770,"claims_from_leaf_index":1,"settlements":false,"until_epoch":5,"reason":"x","extra":1}"#,
            r#"{"version":1,"version":1,"chain_id":700770,"claims_from_leaf_index":1,"settlements":false,"until_epoch":5,"reason":"x"}"#,
            r#"[1]"#,
            "not json",
        ] {
            assert!(parse(bad.as_bytes()).is_err(), "{bad}");
        }
        let long = format!(
            r#"{{"version":1,"chain_id":700770,"claims_from_leaf_index":1,"settlements":false,"until_epoch":5,"reason":"{}"}}"#,
            "r".repeat(MAX_REASON_BYTES + 1)
        );
        assert!(parse(long.as_bytes()).is_err());
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("a222-brake-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_cell_reads_the_files_once_per_slot_and_fails_open() {
        let (pk, sk) = bloch_crypto::crypto::generate_keypair();
        let dir = scratch("cell");
        let cell = BrakeCell::new(Some(dir.clone()), Some(pk.clone()));
        let tx = claim(50, 700_770);
        cell.refresh(1, 10_000, Some(NET), Some(700_770));
        assert_eq!(cell.status(), Status::Off);
        assert!(!cell.holds(&tx, 10_000));
        let b = body("10", false, 10_100);
        std::fs::write(dir.join(FILE), &b).unwrap();
        std::fs::write(dir.join(SIG_FILE), codec::hex(&sign(&sk, &b))).unwrap();
        cell.refresh(1, 10_000, Some(NET), Some(700_770));
        assert_eq!(cell.status(), Status::Off, "at most once per slot");
        cell.refresh(2, 10_000, Some(NET), Some(700_770));
        assert!(matches!(cell.status(), Status::On(_)));
        assert!(cell.holds(&tx, 10_000) && !cell.holds(&claim(9, 700_770), 10_000));
        let info = cell.json(10_000);
        assert_eq!(info.get("active"), Some(&Json::Bool(true)));
        assert_eq!(info.get("claims_from_leaf_index"), Some(&Json::u(10)));
        assert_eq!(info.get("holds_since_start"), Some(&Json::u(1)));
        // A typo in the file: off, never on by accident.
        std::fs::write(dir.join(FILE), b"{\"version\":1,").unwrap();
        cell.refresh(3, 10_000, Some(NET), Some(700_770));
        assert!(matches!(cell.status(), Status::Refused(_)));
        assert!(!cell.holds(&tx, 10_000));
        // Signed for a passed epoch: off.
        let old = body("10", false, 10_000);
        std::fs::write(dir.join(FILE), &old).unwrap();
        std::fs::write(dir.join(SIG_FILE), codec::hex(&sign(&sk, &old))).unwrap();
        cell.refresh(4, 10_000, Some(NET), Some(700_770));
        assert!(matches!(cell.status(), Status::Refused(_)));
        // Valid again, then deleted: lifted.
        std::fs::write(dir.join(FILE), &b).unwrap();
        std::fs::write(dir.join(SIG_FILE), codec::hex(&sign(&sk, &b))).unwrap();
        cell.refresh(5, 10_000, Some(NET), Some(700_770));
        assert!(cell.holds(&tx, 10_000));
        assert!(!cell.holds(&tx, 10_100), "expires by itself at until_epoch");
        std::fs::remove_file(dir.join(FILE)).unwrap();
        cell.refresh(6, 10_000, Some(NET), Some(700_770));
        assert_eq!(cell.status(), Status::Off);
        assert!(!cell.holds(&tx, 10_000));
        // Without --l2-brake-key the same files are never read.
        std::fs::write(dir.join(FILE), &b).unwrap();
        let disabled = BrakeCell::new(Some(dir.clone()), None);
        disabled.refresh(7, 10_000, Some(NET), Some(700_770));
        assert_eq!(disabled.status(), Status::Disabled);
        assert!(!disabled.holds(&tx, 10_000));
        assert_eq!(disabled.json(10_000).get("state"), Some(&Json::s("disabled")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_key_file_must_be_an_enveloped_hybrid_key() {
        let (pk, _) = bloch_crypto::crypto::generate_keypair();
        let dir = scratch("key");
        std::fs::write(dir.join("brake.pk"), codec::hex(&pk)).unwrap();
        assert_eq!(BrakeCell::read_key(&dir.join("brake.pk")).unwrap(), pk);
        std::fs::write(dir.join("short.pk"), "00ff").unwrap();
        assert!(BrakeCell::read_key(&dir.join("short.pk")).is_err());
        assert!(BrakeCell::read_key(&dir.join("missing.pk")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
