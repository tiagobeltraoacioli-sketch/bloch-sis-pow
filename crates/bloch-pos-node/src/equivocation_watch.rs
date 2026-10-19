// SPDX-License-Identifier: AGPL-3.0-or-later
//! `bloch-pos watch-equivocation`: a node-local, read-only equivocation
//! detector.
//!
//! It follows one or more nodes over JSON-RPC (`getchaininfo`,
//! `getblockbyslot`, `getblockraw`), possibly on DIFFERENT forks, indexes
//! every attestation carried in every block it sees, and writes one JSON line
//! per double vote or surround vote. Nothing here changes consensus: it signs
//! nothing, submits nothing and only reads.
//!
//! The in-protocol gossip check (`gossip::AttestationPool`) only compares two
//! messages for the same `(validator, slot)` on the node that happens to see
//! both, and forgets them after a few slots. This tool closes the remaining
//! gaps: same target epoch at different slots, surround votes spanning many
//! epochs, and votes that only ever travelled on different branches. A vote
//! included in a block was signature-checked by the branch that included it,
//! so each indexed message is an authentic signed attestation of that branch.
//!
//! Output (`--out`, append-only JSON Lines, schema
//! `bloch.equivocation-evidence.v1`): the offence, both `AttestationData`,
//! where each was seen (rpc, block id, slot, position), the evidence id
//! (`slashing::SlashingEvidence::id`) and `evidence_tx_hex`, the canonical
//! `PosTransaction::SlashingEvidence` (tag 0x05, attestation arm 0x02) bytes
//! that `sendrawtransaction` would accept. The tool never submits it.
//!
//! Memory is bounded: per validator only votes whose target epoch is within
//! `--window-epochs` of the newest target are retained, with a hard per-
//! validator cap, and signatures are NOT retained — the first message of a
//! pair is re-fetched by block id when a finding is materialised. State
//! (cursor, retained votes, recent block ids, reported evidence ids) is
//! written atomically to `--state`, so a restart resumes without duplicates.

use crate::codec;
use crate::rpc::{parse_json, Json};
use bloch_pos_committee::attestation::{Attestation, AttestationData};
use bloch_pos_committee::header::BlockEnvelope;
use bloch_pos_committee::interfaces::{ProposalEnvelope, SlashingEvidence as WireEvidence};
use bloch_pos_committee::params::SLOTS_PER_EPOCH;
use bloch_pos_committee::slashing::{SlashableOffense, SlashingEvidence as Pair};
use bloch_pos_committee::transition::PosTransaction;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) const SCHEMA: &str = "bloch.equivocation-evidence.v1";
const STATE_MAGIC: &str = "bloch-equivocation-watch-state v1";
const MAX_SIGHTINGS: usize = 4;
const MAX_VOTES_PER_VALIDATOR: usize = 4_096;
const MAX_REPORTED: usize = 1 << 20;

// ── Pure index ──────────────────────────────────────────────────────────────

/// Where one attestation was observed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Sighting {
    pub rpc: String,
    pub block_id: [u8; 32],
    pub block_slot: u64,
    pub position: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Vote {
    pub data: AttestationData,
    pub root: [u8; 32],
    pub sightings: Vec<Sighting>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Finding {
    pub validator: u32,
    pub offense: SlashableOffense,
    pub id: [u8; 32],
    /// The previously indexed vote.
    pub first: Vote,
    /// The vote that completed the pair.
    pub second: Vote,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Index {
    votes: BTreeMap<u32, Vec<Vote>>,
    window_epochs: u64,
    max_target: u64,
    reported: BTreeSet<[u8; 32]>,
}

fn evidence_id(validator: u32, a: &AttestationData, b: &AttestationData) -> [u8; 32] {
    let att = |data: &AttestationData| Attestation { data: *data, validator, signature: Vec::new() };
    Pair { first: att(a), second: att(b) }.id()
}

fn offense_of(a: &AttestationData, b: &AttestationData) -> Option<SlashableOffense> {
    if a.is_double_vote(b) {
        Some(SlashableOffense::DoubleVote)
    } else if a.surrounds(b) || b.surrounds(a) {
        Some(SlashableOffense::SurroundVote)
    } else {
        None
    }
}

impl Index {
    pub fn new(window_epochs: u64) -> Self {
        Self { window_epochs: window_epochs.max(1), ..Self::default() }
    }

    pub fn retained(&self) -> usize {
        self.votes.values().map(Vec::len).sum()
    }

    /// Index one authentic attestation; returns every NEW offence it completes.
    pub fn observe(&mut self, validator: u32, data: AttestationData, seen: Sighting) -> Vec<Finding> {
        let root = data.signing_root();
        let votes = self.votes.entry(validator).or_default();
        if let Some(v) = votes.iter_mut().find(|v| v.root == root) {
            if v.sightings.len() < MAX_SIGHTINGS && !v.sightings.iter().any(|s| s.block_id == seen.block_id) {
                v.sightings.push(seen);
            }
            return Vec::new();
        }
        let new = Vote { data, root, sightings: vec![seen] };
        let mut found = Vec::new();
        for old in votes.iter() {
            let Some(offense) = offense_of(&old.data, &data) else { continue };
            let id = evidence_id(validator, &old.data, &data);
            if self.reported.contains(&id) {
                continue;
            }
            if self.reported.len() >= MAX_REPORTED {
                self.reported.pop_first();
            }
            self.reported.insert(id);
            found.push(Finding { validator, offense, id, first: old.clone(), second: new.clone() });
        }
        let stale = data.target_epoch.saturating_add(self.window_epochs) < self.max_target;
        if !stale {
            votes.push(new);
            if votes.len() > MAX_VOTES_PER_VALIDATOR {
                let (i, _) = votes.iter().enumerate().min_by_key(|(_, v)| v.data.target_epoch).expect("non-empty");
                votes.swap_remove(i);
            }
        }
        if data.target_epoch > self.max_target {
            self.max_target = data.target_epoch;
            let floor = self.max_target.saturating_sub(self.window_epochs);
            self.votes.retain(|_, vs| {
                vs.retain(|v| v.data.target_epoch >= floor);
                !vs.is_empty()
            });
        }
        found
    }
}

// ── JSON-RPC (read-only) ────────────────────────────────────────────────────

pub(crate) fn normalize_addr(s: &str) -> String {
    s.trim_start_matches("http://").trim_end_matches('/').to_string()
}

#[derive(Debug)]
#[allow(dead_code)] // fields are reported through Debug
enum RpcErr {
    /// The node answered with a JSON-RPC error object.
    Node(i64, String),
    Transport(String),
}

fn rpc_call(addr: &str, method: &str, params: Vec<Json>) -> Result<Json, RpcErr> {
    let request = Json::obj(vec![
        ("jsonrpc", Json::s("2.0")),
        ("id", Json::u(1)),
        ("method", Json::s(method)),
        ("params", Json::Arr(params)),
    ])
    .to_string();
    let t = |e: String| RpcErr::Transport(format!("{addr}: {e}"));
    let mut sock = TcpStream::connect(addr).map_err(|e| t(format!("connect: {e}")))?;
    let timeout = Some(Duration::from_secs(30));
    let _ = sock.set_read_timeout(timeout);
    let _ = sock.set_write_timeout(timeout);
    let head = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        request.len()
    );
    sock.write_all(head.as_bytes())
        .and_then(|()| sock.write_all(request.as_bytes()))
        .map_err(|e| t(format!("send: {e}")))?;
    let mut raw = Vec::new();
    let _ = sock.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw);
    let (status, rest) = text.split_once("\r\n").ok_or_else(|| t("malformed HTTP response".into()))?;
    if !status.contains(" 200 ") {
        return Err(t(status.to_string()));
    }
    let body = rest.split_once("\r\n\r\n").map(|(_, b)| b).ok_or_else(|| t("no body".into()))?;
    let json = parse_json(body.trim()).map_err(|e| t(format!("bad JSON: {e}")))?;
    if let Some(err) = json.get("error").filter(|e| !matches!(e, Json::Null)) {
        let code = match err.get("code") {
            Some(Json::Num(n)) => n.parse().unwrap_or(0),
            _ => 0,
        };
        let msg = err.get("message").and_then(Json::as_str).unwrap_or("").to_string();
        return Err(RpcErr::Node(code, msg));
    }
    json.get("result").cloned().ok_or_else(|| t(format!("{method}: no result")))
}

fn with_retry<T>(mut f: impl FnMut() -> Result<T, RpcErr>) -> Result<T, RpcErr> {
    let mut last = None;
    for attempt in 0..3u64 {
        match f() {
            Ok(v) => return Ok(v),
            Err(e @ RpcErr::Node(..)) => return Err(e),
            Err(e) => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(500 * (attempt + 1)));
            }
        }
    }
    Err(last.expect("at least one attempt"))
}

fn head_slot(addr: &str) -> Result<u64, RpcErr> {
    with_retry(|| rpc_call(addr, "getchaininfo", vec![]))?
        .get("slot")
        .and_then(Json::as_u64)
        .ok_or_else(|| RpcErr::Transport(format!("{addr}: getchaininfo without slot")))
}

/// Canonical block id at `slot` on `addr`'s branch, or None for an empty slot.
fn block_id_at(addr: &str, slot: u64) -> Result<Option<[u8; 32]>, RpcErr> {
    match with_retry(|| rpc_call(addr, "getblockbyslot", vec![Json::u(slot)])) {
        Ok(j) => {
            let id = j.get("block_id").and_then(Json::as_str).and_then(|s| codec::unhex(s).ok());
            id.and_then(|b| b.try_into().ok())
                .map(Some)
                .ok_or_else(|| RpcErr::Transport(format!("{addr}: block at {slot} has no block_id")))
        }
        Err(RpcErr::Node(_, m)) if m.contains("no canonical block") => Ok(None),
        Err(e) => Err(e),
    }
}

fn block_raw(addr: &str, id: &[u8; 32]) -> Result<BlockEnvelope, RpcErr> {
    let j = with_retry(|| rpc_call(addr, "getblockraw", vec![Json::hex(id)]))?;
    let bytes = j
        .as_str()
        .and_then(|s| codec::unhex(s).ok())
        .ok_or_else(|| RpcErr::Transport(format!("{addr}: getblockraw not hex")))?;
    codec::decode_envelope(&bytes).map_err(|e| RpcErr::Transport(format!("{addr}: decode: {e}")))
}

// ── Offline block logs (`--block-log`, e.g. a copy of a stopped node's blocks.log) ──

const LOG_PREFIX: &str = "log:";

/// Iterate `[u32 len][envelope]` frames, calling `f(offset, envelope)`.
fn for_each_log_block(path: &Path, mut f: impl FnMut(u64, BlockEnvelope) -> Result<(), String>) -> Result<(), String> {
    let mut file = std::io::BufReader::new(fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?);
    let mut offset = 0u64;
    let mut payload = Vec::new();
    loop {
        let mut prefix = [0u8; 4];
        match file.read_exact(&mut prefix) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.to_string()),
        }
        let size = u32::from_le_bytes(prefix) as usize;
        if size > codec::MAX_FIELD_LEN {
            return Err(format!("{}: frame at {offset} too large", path.display()));
        }
        payload.resize(size, 0);
        if file.read_exact(&mut payload).is_err() {
            eprintln!("{}: torn tail at {offset}, stopping", path.display());
            return Ok(());
        }
        let env = codec::decode_envelope(&payload).map_err(|e| format!("{}: frame at {offset}: {e}", path.display()))?;
        f(offset, env)?;
        offset += 4 + size as u64;
    }
}

fn log_block(path: &str, id: &[u8; 32]) -> Option<BlockEnvelope> {
    let mut hit = None;
    let _ = for_each_log_block(Path::new(path), |_, env| {
        if hit.is_none() && env.block_id().as_bytes() == id {
            hit = Some(env);
        }
        Ok(())
    });
    hit
}

const FILE_PREFIX: &str = "file:";

fn file_block(path: &Path) -> Result<BlockEnvelope, String> {
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    codec::decode_envelope(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

/// Slot of a one-envelope-per-file block (`<dir>/<block id>.bin`), header only.
fn file_slot(path: &Path) -> Option<u64> {
    use bloch_pos_committee::header::BlockHeaderV4;
    let mut buf = vec![0u8; BlockHeaderV4::ENCODED_LEN];
    fs::File::open(path).ok()?.read_exact(&mut buf).ok()?;
    BlockHeaderV4::canonical_deserialize(&buf).ok().map(|h| h.slot)
}

fn fetch_block(src: &str, id: &[u8; 32]) -> Option<BlockEnvelope> {
    if let Some(path) = src.strip_prefix(LOG_PREFIX) {
        return log_block(path, id);
    }
    if let Some(path) = src.strip_prefix(FILE_PREFIX) {
        return file_block(Path::new(path)).ok().filter(|e| e.block_id().as_bytes() == id);
    }
    block_raw(src, id).ok()
}

// ── State file ──────────────────────────────────────────────────────────────

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct State {
    pub cursor: u64,
    pub index: Index,
    /// Recently processed block ids (dedupe across sources and rescans).
    pub blocks: BTreeMap<[u8; 32], u64>,
    /// First slot scanned; roots below it are not chased.
    pub start: u64,
    /// First block seen per (slot, proposer), with the rpc that served it.
    pub proposals: BTreeMap<(u64, u32), ([u8; 32], String)>,
    /// Referenced roots already looked up (found or not), with a slot hint.
    pub tried: BTreeMap<[u8; 32], u64>,
}

fn h(b: &[u8; 32]) -> String {
    codec::hex32(b)
}

fn unh(s: &str) -> Option<[u8; 32]> {
    codec::unhex(s).ok()?.try_into().ok()
}

impl State {
    pub fn encode(&self) -> String {
        let mut o = String::new();
        o.push_str(STATE_MAGIC);
        o.push('\n');
        o.push_str(&format!("start {}\n", self.start));
        for ((slot, p), (id, rpc)) in &self.proposals {
            o.push_str(&format!("prop {slot} {p} {} {rpc}\n", h(id)));
        }
        for (id, slot) in &self.tried {
            o.push_str(&format!("tried {} {slot}\n", h(id)));
        }
        o.push_str(&format!("cursor {}\nmax_target {}\nwindow {}\n", self.cursor, self.index.max_target, self.index.window_epochs));
        for (v, votes) in &self.index.votes {
            for vote in votes {
                let d = &vote.data;
                let seen: Vec<String> = vote
                    .sightings
                    .iter()
                    .map(|s| format!("{},{},{},{}", s.rpc, h(&s.block_id), s.block_slot, s.position))
                    .collect();
                o.push_str(&format!(
                    "vote {v} {} {} {} {} {} {} {}\n",
                    d.slot, h(&d.head), d.source_epoch, h(&d.source_root), d.target_epoch, h(&d.target_root), seen.join(";")
                ));
            }
        }
        for id in &self.index.reported {
            o.push_str(&format!("reported {}\n", h(id)));
        }
        for (id, slot) in &self.blocks {
            o.push_str(&format!("block {} {slot}\n", h(id)));
        }
        o.push_str("end\n");
        o
    }

    pub fn decode(text: &str) -> Result<Self, String> {
        let mut lines = text.lines();
        if lines.next() != Some(STATE_MAGIC) {
            return Err("not an equivocation-watch state file".into());
        }
        let mut st = State::default();
        let mut complete = false;
        for (n, line) in lines.enumerate() {
            let bad = || format!("state line {}: {line:?}", n + 2);
            let f: Vec<&str> = line.split(' ').collect();
            let num = |i: usize| f.get(i).and_then(|s| s.parse::<u64>().ok()).ok_or_else(bad);
            let hx = |i: usize| f.get(i).and_then(|s| unh(s)).ok_or_else(bad);
            match f[0] {
                "cursor" => st.cursor = num(1)?,
                "start" => st.start = num(1)?,
                "prop" => {
                    let p = u32::try_from(num(2)?).map_err(|_| bad())?;
                    let rpc = f.get(4).ok_or_else(bad)?.to_string();
                    st.proposals.insert((num(1)?, p), (hx(3)?, rpc));
                }
                "tried" => {
                    st.tried.insert(hx(1)?, num(2)?);
                }
                "max_target" => st.index.max_target = num(1)?,
                "window" => st.index.window_epochs = num(1)?,
                "vote" => {
                    let data = AttestationData {
                        slot: num(2)?,
                        head: hx(3)?,
                        source_epoch: num(4)?,
                        source_root: hx(5)?,
                        target_epoch: num(6)?,
                        target_root: hx(7)?,
                    };
                    let mut sightings = Vec::new();
                    for s in f.get(8).copied().unwrap_or("").split(';').filter(|s| !s.is_empty()) {
                        let p: Vec<&str> = s.split(',').collect();
                        if p.len() != 4 {
                            return Err(bad());
                        }
                        sightings.push(Sighting {
                            rpc: p[0].to_string(),
                            block_id: unh(p[1]).ok_or_else(bad)?,
                            block_slot: p[2].parse().map_err(|_| bad())?,
                            position: p[3].parse().map_err(|_| bad())?,
                        });
                    }
                    let validator = u32::try_from(num(1)?).map_err(|_| bad())?;
                    st.index.votes.entry(validator).or_default().push(Vote { root: data.signing_root(), data, sightings });
                }
                "reported" => {
                    st.index.reported.insert(hx(1)?);
                }
                "block" => {
                    st.blocks.insert(hx(1)?, num(2)?);
                }
                "end" => complete = true,
                _ => return Err(bad()),
            }
        }
        if !complete {
            return Err("truncated state file (no end marker)".into());
        }
        Ok(st)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let tmp = path.with_extension("tmp");
        let mut f = fs::File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(self.encode().as_bytes()).and_then(|_| f.sync_all()).map_err(|e| e.to_string())?;
        fs::rename(&tmp, path).map_err(|e| e.to_string())?;
        if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            let _ = crate::store::fsync_dir(dir);
        }
        Ok(())
    }
}

// ── Evidence records ────────────────────────────────────────────────────────

fn data_json(d: &AttestationData) -> Json {
    Json::obj(vec![
        ("slot", Json::u(d.slot)),
        ("head", Json::hex(&d.head)),
        ("source_epoch", Json::u(d.source_epoch)),
        ("source_root", Json::hex(&d.source_root)),
        ("target_epoch", Json::u(d.target_epoch)),
        ("target_root", Json::hex(&d.target_root)),
    ])
}

fn vote_json(v: &Vote) -> Json {
    Json::obj(vec![
        ("data", data_json(&v.data)),
        ("signing_root", Json::hex(&v.root)),
        (
            "seen_in",
            Json::Arr(
                v.sightings
                    .iter()
                    .map(|s| {
                        Json::obj(vec![
                            ("rpc", Json::s(s.rpc.clone())),
                            ("block_id", Json::hex(&s.block_id)),
                            ("block_slot", Json::u(s.block_slot)),
                            ("attestation_index", Json::u(u64::from(s.position))),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

/// Human-oriented sub-classification; the consensus offence is `offense`.
pub(crate) fn kind(f: &Finding) -> &'static str {
    let (a, b) = (&f.first.data, &f.second.data);
    match f.offense {
        SlashableOffense::DoubleVote if a.slot == b.slot && a.head != b.head => "same_slot_different_head",
        SlashableOffense::DoubleVote if a.slot == b.slot => "same_slot_different_checkpoint",
        SlashableOffense::DoubleVote => "different_slot_same_target",
        SlashableOffense::SurroundVote => "surround",
        SlashableOffense::ProposerEquivocation => "proposer",
    }
}

/// Recover the signed attestation for `vote` by re-fetching a block it was
/// seen in. Tries the recorded sightings first, then every source.
fn refetch(vote: &Vote, validator: u32, sources: &[String]) -> Option<Attestation> {
    let mut tries: Vec<(String, [u8; 32], Option<u32>)> =
        vote.sightings.iter().map(|s| (s.rpc.clone(), s.block_id, Some(s.position))).collect();
    for s in &vote.sightings {
        for src in sources {
            tries.push((src.clone(), s.block_id, Some(s.position)));
        }
    }
    for (rpc, id, pos) in tries {
        let Some(env) = fetch_block(&rpc, &id) else { continue };
        let hit = pos
            .and_then(|p| env.body.attestations.get(p as usize))
            .filter(|a| a.validator == validator && a.data.signing_root() == vote.root)
            .or_else(|| env.body.attestations.iter().find(|a| a.validator == validator && a.data.signing_root() == vote.root));
        if let Some(a) = hit {
            return Some(a.clone());
        }
    }
    None
}

pub(crate) fn evidence_record(f: &Finding, first: Option<&Attestation>, second: Option<&Attestation>) -> Json {
    let offense = match f.offense {
        SlashableOffense::DoubleVote => "double_vote",
        SlashableOffense::SurroundVote => "surround_vote",
        SlashableOffense::ProposerEquivocation => "proposer_equivocation",
    };
    let (tx_hex, txid) = match (first, second) {
        (Some(a), Some(b)) => {
            let pair = Pair { first: a.clone(), second: b.clone() };
            debug_assert_eq!(pair.offense().ok(), Some(f.offense));
            let tx = PosTransaction::SlashingEvidence(pair.into());
            (Json::s(codec::hex(&tx.canonical_bytes())), Json::hex(&tx.txid()))
        }
        _ => (Json::Null, Json::Null),
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    Json::obj(vec![
        ("schema", Json::s(SCHEMA)),
        ("offense", Json::s(offense)),
        ("kind", Json::s(kind(f))),
        ("validator", Json::u(u64::from(f.validator))),
        ("evidence_id", Json::hex(&f.id)),
        ("first", vote_json(&f.first)),
        ("second", vote_json(&f.second)),
        ("complete", Json::Bool(first.is_some() && second.is_some())),
        ("evidence_tx_hex", tx_hex),
        ("evidence_txid", txid),
        ("detected_unix", Json::u(now)),
    ])
}

// ── Proposer equivocation (two blocks, one slot, one proposer) ──────────────

fn proposer_record(
    slot: u64,
    proposer: u32,
    first: (&[u8; 32], &str, Option<&BlockEnvelope>),
    second: (&[u8; 32], &str, &BlockEnvelope),
) -> Json {
    let env = |e: &BlockEnvelope| ProposalEnvelope { header: e.header.clone(), proposer_sig: e.proposer_sig.clone() };
    let (tx_hex, txid) = match first.2 {
        Some(f) => {
            let tx = PosTransaction::SlashingEvidence(WireEvidence::ProposerEquivocation {
                first: env(f),
                second: env(second.2),
            });
            (Json::s(codec::hex(&tx.canonical_bytes())), Json::hex(&tx.txid()))
        }
        None => (Json::Null, Json::Null),
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    Json::obj(vec![
        ("schema", Json::s(SCHEMA)),
        ("offense", Json::s("proposer_equivocation")),
        ("kind", Json::s("proposer")),
        ("validator", Json::u(u64::from(proposer))),
        ("slot", Json::u(slot)),
        ("first", Json::obj(vec![("block_id", Json::hex(first.0)), ("rpc", Json::s(first.1))])),
        ("second", Json::obj(vec![("block_id", Json::hex(second.0)), ("rpc", Json::s(second.1))])),
        ("complete", Json::Bool(first.2.is_some())),
        ("evidence_tx_hex", tx_hex),
        ("evidence_txid", txid),
        ("detected_unix", Json::u(now)),
    ])
}

// ── Driver ──────────────────────────────────────────────────────────────────

struct Options {
    sources: Vec<String>,
    state: PathBuf,
    out: PathBuf,
    from_slot: Option<u64>,
    to_slot: Option<u64>,
    window_epochs: u64,
    confirmations: u64,
    rescan_slots: u64,
    poll_secs: u64,
    max_orphans_per_pass: usize,
    logs: Vec<String>,
    dirs: Vec<String>,
    window_given: bool,
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut o = Options {
        sources: Vec::new(),
        state: PathBuf::new(),
        out: PathBuf::new(),
        from_slot: None,
        to_slot: None,
        window_epochs: 1024,
        confirmations: 2,
        rescan_slots: 64,
        poll_secs: 6,
        max_orphans_per_pass: 4096,
        logs: Vec::new(),
        dirs: Vec::new(),
        window_given: false,
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let val = it.next().ok_or_else(|| format!("{flag} requires a value"))?;
        let num = || val.parse::<u64>().map_err(|_| format!("{flag}: not an unsigned integer"));
        match flag.as_str() {
            "--rpc" => o.sources.push(normalize_addr(val)),
            "--block-log" => o.logs.push(val.clone()),
            "--block-dir" => o.dirs.push(val.clone()),
            "--state" => o.state = PathBuf::from(val),
            "--out" => o.out = PathBuf::from(val),
            "--from-slot" => o.from_slot = Some(num()?),
            "--to-slot" => o.to_slot = Some(num()?),
            "--window-epochs" => {
                o.window_epochs = num()?.max(1);
                o.window_given = true;
            }
            "--confirmations" => o.confirmations = num()?,
            "--rescan-slots" => o.rescan_slots = num()?,
            "--poll-secs" => o.poll_secs = num()?.max(1),
            "--max-orphans-per-pass" => o.max_orphans_per_pass = num()? as usize,
            _ => return Err(format!("unknown option {flag}")),
        }
    }
    if (o.sources.is_empty() && o.logs.is_empty() && o.dirs.is_empty()) || o.state.as_os_str().is_empty() || o.out.as_os_str().is_empty() {
        return Err("--rpc, --block-log or --block-dir (repeatable), --state and --out are required".into());
    }
    o.sources.dedup();
    Ok(o)
}

pub(crate) const USAGE: &str = "usage: bloch-pos watch-equivocation --rpc HOST:PORT [--rpc HOST:PORT ...] \
--state FILE --out EVIDENCE.jsonl [--from-slot N] [--to-slot N] [--window-epochs 1024] \
[--confirmations 2] [--rescan-slots 64] [--poll-secs 6] [--max-orphans-per-pass 4096]\n\
       bloch-pos watch-equivocation --block-log COPY/blocks.log [--block-log ...] --state FILE --out EVIDENCE.jsonl \
[--from-slot N] [--to-slot N]   (offline: every block in each log, any branch)\n\
       bloch-pos watch-equivocation --block-dir DIR_OF_<id>.bin [--block-dir ...] --state FILE --out EVIDENCE.jsonl   (offline, slot order)";

#[derive(Default)]
struct Counters {
    blocks: u64,
    orphans: u64,
    attestations: u64,
    findings: u64,
}

struct Run {
    o: Options,
    st: State,
    out: fs::File,
    n: Counters,
    /// Roots referenced (parent, attestation head/target) but not yet indexed.
    queue: Vec<([u8; 32], u64)>,
}

impl Run {
    fn emit(&mut self, rec: Json) -> Result<(), String> {
        self.n.findings += 1;
        writeln!(self.out, "{}", rec.to_string()).and_then(|_| self.out.sync_data()).map_err(|e| e.to_string())
    }

    fn note_root(&mut self, root: [u8; 32], hint_slot: u64) {
        if root != [0; 32] && !self.st.blocks.contains_key(&root) && !self.st.tried.contains_key(&root) {
            self.st.tried.insert(root, hint_slot);
            self.queue.push((root, hint_slot));
        }
    }

    fn process_block(&mut self, env: &BlockEnvelope, id: [u8; 32], src: &str, orphan: bool) -> Result<(), String> {
        let slot = env.header.slot;
        self.st.blocks.insert(id, slot);
        self.n.blocks += 1;
        if orphan && slot >= self.st.start {
            self.n.orphans += 1;
            eprintln!("orphan block {} slot {slot} proposer {} via {src}", codec::hex8(&id), env.header.proposer_index);
        }
        if slot < self.st.start {
            return Ok(());
        }
        // Proposer equivocation: a second distinct block for (slot, proposer).
        let key = (slot, env.header.proposer_index);
        match self.st.proposals.get(&key).cloned() {
            Some((other, rpc)) if other != id => {
                let first = fetch_block(&rpc, &other)
                    .or_else(|| self.o.sources.iter().find_map(|s| fetch_block(s, &other)));
                let rec = proposer_record(slot, key.1, (&other, &rpc, first.as_ref()), (&id, src, env));
                eprintln!("EQUIVOCATION v{} proposer slot {slot} blocks {}/{}", key.1, codec::hex8(&other), codec::hex8(&id));
                self.emit(rec)?;
            }
            Some(_) => {}
            None => {
                self.st.proposals.insert(key, (id, src.to_string()));
            }
        }
        for tx in &env.body.transactions {
            if let Ok(PosTransaction::SlashingEvidence(ev)) = PosTransaction::from_canonical_bytes(tx) {
                let line = Json::obj(vec![
                    ("schema", Json::s(SCHEMA)),
                    ("onchain_evidence_in_block", Json::hex(&id)),
                    ("block_slot", Json::u(slot)),
                    ("rpc", Json::s(src)),
                    ("evidence_txid", Json::hex(&PosTransaction::SlashingEvidence(ev).txid())),
                ]);
                println!("{}", line.to_string());
            }
        }
        self.note_root(env.header.parent, slot);
        for (pos, att) in env.body.attestations.iter().enumerate() {
            self.n.attestations += 1;
            self.note_root(att.data.head, att.data.slot);
            self.note_root(att.data.target_root, att.data.slot);
            let seen = Sighting { rpc: src.to_string(), block_id: id, block_slot: slot, position: pos as u32 };
            for f in self.st.index.observe(att.validator, att.data, seen) {
                let first = refetch(&f.first, f.validator, &self.o.sources);
                eprintln!(
                    "EQUIVOCATION v{} {} target {}/{} slots {}/{} blocks {}/{}",
                    f.validator,
                    kind(&f),
                    f.first.data.target_epoch,
                    f.second.data.target_epoch,
                    f.first.data.slot,
                    f.second.data.slot,
                    codec::hex8(&f.first.sightings[0].block_id),
                    codec::hex8(&id)
                );
                self.emit(evidence_record(&f, first.as_ref(), Some(att)))?;
            }
        }
        Ok(())
    }

    /// Chase referenced roots no canonical walk produced: blocks of other
    /// branches that a node still stores (`getblockraw` serves any stored id).
    fn drain_orphans(&mut self) -> Result<(), String> {
        let mut budget = self.o.max_orphans_per_pass;
        while let Some((root, _)) = self.queue.pop() {
            if self.st.blocks.contains_key(&root) {
                continue;
            }
            if budget == 0 {
                self.queue.clear();
                break;
            }
            budget -= 1;
            let sources = self.o.sources.clone();
            for src in &sources {
                if let Ok(env) = block_raw(src, &root) {
                    if env.block_id().as_bytes() == &root {
                        self.process_block(&env, root, src, true)?;
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn prune_and_save(&mut self, at_slot: u64) -> Result<(), String> {
        let keep = self.o.window_epochs.saturating_mul(SLOTS_PER_EPOCH);
        let floor = at_slot.saturating_sub(keep);
        self.st.blocks.retain(|_, s| *s >= floor);
        self.st.tried.retain(|_, s| *s >= floor);
        let pfloor = at_slot.saturating_sub(self.o.rescan_slots.max(4 * SLOTS_PER_EPOCH) * 4);
        self.st.proposals.retain(|(s, _), _| *s >= pfloor);
        self.st.save(&self.o.state)
    }
}

pub(crate) fn run(args: &[String]) -> Result<(), String> {
    let o = parse_options(args)?;
    let resumed = o.state.exists();
    let mut st = if resumed {
        let text = fs::read_to_string(&o.state).map_err(|e| e.to_string())?;
        let st = State::decode(&text)?;
        eprintln!("resumed at slot {} ({} retained votes)", st.cursor, st.index.retained());
        st
    } else {
        State { index: Index::new(o.window_epochs), ..State::default() }
    };
    st.index.window_epochs = o.window_epochs;
    let out = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&o.out)
        .map_err(|e| format!("{}: {e}", o.out.display()))?;
    let mut r = Run { o, st, out, n: Counters::default(), queue: Vec::new() };
    if !r.o.logs.is_empty() || !r.o.dirs.is_empty() {
        let (from, to) = (r.o.from_slot.unwrap_or(0), r.o.to_slot.unwrap_or(u64::MAX));
        // Logs are read one after another, so a sliding window would drop the
        // first log's votes before the second is compared. Offline runs are
        // bounded by the logs themselves; keep everything unless told not to.
        if !r.o.window_given {
            r.st.index.window_epochs = u64::MAX / 2;
        }
        r.st.start = from;
        for path in r.o.logs.clone() {
            let label = format!("{LOG_PREFIX}{path}");
            let mut frames = 0u64;
            for_each_log_block(Path::new(&path), |_, env| {
                frames += 1;
                let slot = env.header.slot;
                let id = *env.block_id().as_bytes();
                if slot < from || slot > to || r.st.blocks.contains_key(&id) {
                    return Ok(());
                }
                r.process_block(&env, id, &label, false)?;
                if frames % 20_000 == 0 {
                    eprintln!("{path}: {frames} frames, slot {slot}, findings {}", r.n.findings);
                }
                Ok(())
            })?;
            eprintln!("{path}: {frames} frames read");
        }
        let mut files: Vec<(u64, PathBuf)> = Vec::new();
        for dir in r.o.dirs.clone() {
            for entry in fs::read_dir(&dir).map_err(|e| format!("{dir}: {e}"))? {
                let path = entry.map_err(|e| e.to_string())?.path();
                if path.extension().is_some_and(|x| x == "bin") {
                    match file_slot(&path) {
                        Some(slot) if slot >= from && slot <= to => files.push((slot, path)),
                        Some(_) => {}
                        None => eprintln!("{}: undecodable header, skipped", path.display()),
                    }
                }
            }
            eprintln!("{dir}: indexed, {} candidate files so far", files.len());
        }
        files.sort();
        for (n, (slot, path)) in files.iter().enumerate() {
            let env = match file_block(path) {
                Ok(env) => env,
                Err(e) => {
                    eprintln!("{e}");
                    continue;
                }
            };
            let id = *env.block_id().as_bytes();
            if r.st.blocks.contains_key(&id) {
                continue;
            }
            let label = format!("{FILE_PREFIX}{}", path.display());
            r.process_block(&env, id, &label, false)?;
            if n % 20_000 == 0 {
                eprintln!("files: {n}/{} slot {slot} findings {}", files.len(), r.n.findings);
            }
        }
        r.queue.clear();
        r.st.blocks.clear();
        r.st.tried.clear();
        r.st.proposals.clear();
        r.st.save(&r.o.state)?;
        eprintln!(
            "done (offline): blocks {} attestations {} findings {}",
            r.n.blocks, r.n.attestations, r.n.findings
        );
        return Ok(());
    }
    let mut initialised = resumed;
    loop {
        let heads: Vec<Option<u64>> = r
            .o
            .sources
            .iter()
            .map(|s| match head_slot(s) {
                Ok(h) => Some(h),
                Err(e) => {
                    eprintln!("source {s} unavailable: {e:?}");
                    None
                }
            })
            .collect();
        let Some(tip) = heads.iter().flatten().max().map(|h| h.saturating_sub(r.o.confirmations)) else {
            std::thread::sleep(Duration::from_secs(r.o.poll_secs));
            continue;
        };
        if !initialised {
            r.st.cursor = r.o.from_slot.unwrap_or(tip.saturating_sub(r.o.rescan_slots));
            r.st.start = r.st.cursor;
            initialised = true;
        }
        let end = r.o.to_slot.map_or(tip, |t| t.min(tip));
        let start = if r.o.to_slot.is_none() { r.st.cursor.saturating_sub(r.o.rescan_slots).max(r.st.start) } else { r.st.cursor };
        let sources = r.o.sources.clone();
        let mut slot = start;
        while slot <= end {
            for (src, head) in sources.iter().zip(&heads) {
                if head.is_none_or(|h| slot > h) {
                    continue;
                }
                let id = match block_id_at(src, slot) {
                    Ok(Some(id)) => id,
                    Ok(None) => continue,
                    Err(e) => {
                        eprintln!("slot {slot} on {src}: {e:?}");
                        continue;
                    }
                };
                if r.st.blocks.contains_key(&id) {
                    continue;
                }
                match block_raw(src, &id) {
                    Ok(env) => r.process_block(&env, id, src, false)?,
                    Err(e) => eprintln!("block {} on {src}: {e:?}", codec::hex8(&id)),
                }
            }
            if slot % 32 == 31 {
                r.drain_orphans()?;
            }
            if slot % 512 == 0 {
                r.st.cursor = r.st.cursor.max(slot);
                r.prune_and_save(slot)?;
                eprintln!(
                    "progress slot {slot}/{end} blocks {} orphans {} attestations {} findings {} retained {}",
                    r.n.blocks,
                    r.n.orphans,
                    r.n.attestations,
                    r.n.findings,
                    r.st.index.retained()
                );
            }
            slot += 1;
        }
        r.drain_orphans()?;
        r.st.cursor = r.st.cursor.max(end.saturating_add(1));
        let at = r.st.cursor;
        r.prune_and_save(at)?;
        if r.o.to_slot.is_some_and(|t| r.st.cursor > t) {
            eprintln!(
                "done: slots {}..={} blocks {} orphans {} attestations {} findings {}",
                r.st.start,
                r.st.cursor - 1,
                r.n.blocks,
                r.n.orphans,
                r.n.attestations,
                r.n.findings
            );
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(r.o.poll_secs));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(slot: u64, head: u8, se: u64, te: u64) -> AttestationData {
        AttestationData { slot, head: [head; 32], source_epoch: se, source_root: [se as u8; 32], target_epoch: te, target_root: [te as u8; 32] }
    }

    fn seen(b: u8) -> Sighting {
        Sighting { rpc: "n:1".into(), block_id: [b; 32], block_slot: 1, position: 0 }
    }

    #[test]
    fn duplicate_inclusion_is_not_an_offence() {
        let mut ix = Index::new(64);
        assert!(ix.observe(7, d(32, 1, 0, 1), seen(1)).is_empty());
        assert!(ix.observe(7, d(32, 1, 0, 1), seen(2)).is_empty());
        assert_eq!(ix.votes[&7][0].sightings.len(), 2);
    }

    #[test]
    fn double_vote_across_forks_and_slots_is_found_once() {
        let mut ix = Index::new(64);
        ix.observe(7, d(64, 1, 1, 2), seen(1));
        let f = ix.observe(7, d(64, 2, 1, 2), seen(2));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].offense, SlashableOffense::DoubleVote);
        assert_eq!(kind(&f[0]), "same_slot_different_head");
        let g = ix.observe(7, d(70, 1, 1, 2), seen(3));
        assert_eq!(g.len(), 2, "pairs with both earlier votes");
        assert_eq!(kind(&g[0]), "different_slot_same_target");
        // Re-seeing the same pair yields nothing new.
        assert!(ix.observe(7, d(64, 2, 1, 2), seen(4)).is_empty());
        // Another validator voting differently is not an offence.
        assert!(ix.observe(8, d(64, 9, 1, 2), seen(5)).is_empty());
    }

    #[test]
    fn surround_both_orders() {
        let mut ix = Index::new(256);
        ix.observe(3, d(320, 1, 2, 10), seen(1));
        let f = ix.observe(3, d(200, 1, 4, 6), seen(2));
        assert_eq!(f[0].offense, SlashableOffense::SurroundVote);
        let mut ix = Index::new(256);
        ix.observe(3, d(200, 1, 4, 6), seen(1));
        let f = ix.observe(3, d(320, 1, 2, 10), seen(2));
        assert_eq!(f[0].offense, SlashableOffense::SurroundVote);
        // Honest progress (same source, later targets) is not slashable.
        let mut ix = Index::new(256);
        for t in 5..40 {
            assert!(ix.observe(3, d(t * 32, 1, 4, t), seen(t as u8)).is_empty());
        }
    }

    #[test]
    fn window_bounds_memory() {
        let mut ix = Index::new(8);
        for t in 1..1000u64 {
            ix.observe(1, d(t * 32, 1, t - 1, t), seen(1));
        }
        assert!(ix.retained() <= 9);
    }

    #[test]
    fn state_round_trips() {
        let mut ix = Index::new(16);
        ix.observe(7, d(64, 1, 1, 2), seen(1));
        ix.observe(7, d(64, 2, 1, 2), seen(2));
        ix.observe(9, d(65, 3, 1, 2), seen(3));
        let mut st = State { cursor: 99, index: ix, start: 7, ..State::default() };
        st.proposals.insert((5, 2), ([1; 32], "a:1".into()));
        st.tried.insert([3; 32], 4);
        st.blocks.insert([5; 32], 98);
        let back = State::decode(&st.encode()).unwrap();
        assert_eq!(back, st);
        assert!(State::decode(st.encode().trim_end_matches("end\n")).is_err());
    }

    #[test]
    fn complete_record_carries_decodable_evidence() {
        let mut ix = Index::new(16);
        ix.observe(7, d(64, 1, 1, 2), seen(1));
        let f = ix.observe(7, d(64, 2, 1, 2), seen(2)).remove(0);
        let a = Attestation { data: f.first.data, validator: 7, signature: vec![1, 2, 3] };
        let b = Attestation { data: f.second.data, validator: 7, signature: vec![4, 5] };
        let rec = evidence_record(&f, Some(&a), Some(&b));
        let hex = rec.get("evidence_tx_hex").and_then(Json::as_str).unwrap();
        let tx = PosTransaction::from_canonical_bytes(&codec::unhex(hex).unwrap()).unwrap();
        assert!(matches!(tx, PosTransaction::SlashingEvidence(_)));
        assert_eq!(rec.get("evidence_id").and_then(Json::as_str).unwrap(), codec::hex32(&f.id));
        let pair = Pair { first: a, second: b };
        assert_eq!(pair.id(), f.id);
        let partial = evidence_record(&f, None, Some(&pair.second));
        assert!(matches!(partial.get("evidence_tx_hex"), Some(Json::Null)));
    }
}
