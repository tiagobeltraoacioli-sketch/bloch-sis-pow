// SPDX-License-Identifier: AGPL-3.0-or-later

//! Checkpoint-sync state download: the snapshot **file** form, the chunked
//! transfer wire form, the serving side, the resumable download bookkeeping —
//! and the import path whose verification chain cannot be bypassed.
//!
//! ## The artifact
//!
//! One file (`*.snap`) carries everything a node needs to start from a
//! weak-subjectivity checkpoint instead of genesis:
//!
//! ```text
//! "BPOSSNP1" ‖ u32 version ‖ u32 len ‖ boundary BlockEnvelope ‖ u64 len ‖ state body
//! ```
//!
//! - the **boundary block envelope**: the block whose id the signed
//!   checkpoint's `block_root` pins. It is what binds the artifact to the
//!   checkpoint — `BlockId::of(header)` must equal `block_root`, and the
//!   header's own `state_root` must equal the checkpoint's `state_root` — and
//!   it supplies the two values the state root does not bind (`slot`, `head`)
//!   from bytes the quorum signed over.
//! - the **state body**: `CommittedState::snapshot_serialize` output, the
//!   canonical byte form defined in `bloch_pos_committee::transition::snapshot`.
//!
//! ## The verification chain ([`import`]) — in order, none skippable
//!
//! 1. `envelope.block_id() == checkpoint.block_root` — the artifact is about
//!    the block the signers signed about, or it is refused.
//! 2. `envelope.header.state_root == checkpoint.state_root` — the checkpoint
//!    is internally consistent with the header it pins (a mismatch means a
//!    malformed or forged artifact, and nothing downstream may paper over it).
//! 3. `snapshot::restore(body, genesis, trust)` — the pure crate decodes the
//!    body, rebuilds the derived fields, **recomputes the full state root and
//!    compares it to the checkpoint's**. The restore function is the only
//!    constructor; an unverified state never exists (see its module docs).
//!
//! The transport below this — chunk hashes, manifests, peers — is
//! convenience, not trust: a chunk hash lets a bad chunk be re-fetched early,
//! but nothing about the download is believed until step 3 passes. The trust
//! is the 32 bytes of `state_root`, never the peer that served the data.
//!
//! ## The transfer protocol
//!
//! Request/response, over both transports (framed devnet TCP and the libp2p
//! directed-sync protocol — see `net.rs` / `p2p.rs` for the carrying):
//!
//! - `Manifest { state_root }` → `Manifest { total_len, chunk_len,
//!   chunk_hashes }`: the artifact's size and the SHA3-256 of each
//!   [`STATE_CHUNK_LEN`]-byte chunk. Because the body is canonical, every
//!   honest node serving the same `state_root` produces byte-identical files,
//!   so manifests agree and chunks can be mixed across peers.
//! - `Chunk { state_root, index }` → `Chunk { bytes }`.
//! - `Unavailable { state_root }` when the server holds no such snapshot.
//!
//! Resumability: [`Download`] writes chunks into a `.part` file under
//! `<data-dir>/statesync/` at their final offsets; on restart it re-hashes
//! what is on disk against the manifest and re-fetches only what is missing
//! or wrong. A finished file is handed to [`import`] and deleted only after
//! the verification chain passes or definitively fails.
//!
//! ## Serving
//!
//! Nodes export the boundary state at every weak-subjectivity publication
//! epoch (`ws::is_publication_epoch`) into `<data-dir>/snapshots/<state-root
//! hex>.snap` (the engine does this on the boundary crossing; `run
//! --export-state-epoch` does it by replay for any past epoch). [`serve`]
//! answers from those files plus the node's own installed `state.snap`. A
//! manifest sidecar (`.manifest`) caches the hash list so serving a manifest
//! does not re-hash hundreds of megabytes per request.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use bloch_pos_committee::header::BlockEnvelope;
use bloch_pos_committee::transition::snapshot::{self, SnapshotTrust};
use bloch_pos_committee::transition::CommittedState;
use bloch_pos_committee::ws::WeakSubjectivityCheckpoint;
use sha3::{Digest, Sha3_256};

use crate::codec::{DecodeErr, Reader};

// ───────────────────────────────────────────────────────────────────────────
// File form
// ───────────────────────────────────────────────────────────────────────────

const SNAP_MAGIC: &[u8; 8] = b"BPOSSNP1";
const SNAP_VERSION: u32 = 1;

/// Name of the installed boot snapshot inside a data dir: the artifact this
/// node verified and started from, re-verified on every restart.
pub const INSTALLED_SNAPSHOT: &str = "state.snap";

/// Encode the snapshot file: framing ‖ boundary envelope ‖ state body.
pub fn encode_snapshot_file(env: &BlockEnvelope, body: &[u8]) -> Vec<u8> {
    let env_bytes = crate::codec::encode_envelope(env);
    let mut out = Vec::with_capacity(24 + env_bytes.len() + body.len());
    out.extend_from_slice(SNAP_MAGIC);
    out.extend_from_slice(&SNAP_VERSION.to_le_bytes());
    out.extend_from_slice(&(env_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&env_bytes);
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// Decode the file framing. Strict: bad magic, unknown version, wrong
/// lengths and trailing bytes are all refusals. The state body comes back as
/// bytes — only `snapshot::restore` (via [`import`]) may interpret them.
pub fn decode_snapshot_file(bytes: &[u8]) -> Result<(BlockEnvelope, &[u8]), DecodeErr> {
    if bytes.len() < 8 + 4 + 4 || &bytes[..8] != SNAP_MAGIC {
        return Err(DecodeErr("not a bloch-pos state snapshot"));
    }
    if u32::from_le_bytes(bytes[8..12].try_into().unwrap()) != SNAP_VERSION {
        return Err(DecodeErr("unknown snapshot file version"));
    }
    let env_len = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    if env_len > crate::codec::MAX_FIELD_LEN || bytes.len() < 16 + env_len + 8 {
        return Err(DecodeErr("truncated snapshot file"));
    }
    let env = crate::codec::decode_envelope(&bytes[16..16 + env_len])?;
    let at = 16 + env_len;
    let body_len = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap()) as usize;
    let body_at = at + 8;
    if bytes.len() - body_at != body_len {
        return Err(DecodeErr("snapshot body length mismatch"));
    }
    Ok((env, &bytes[body_at..]))
}

/// The whole point, in one function: bytes + the verified checkpoint + this
/// node's own genesis state → the committed state at the checkpoint, or a
/// refusal. See the module docs for the three-step chain; there is no other
/// entry into a snapshot, so there is no path around any step.
pub fn import(
    bytes: &[u8],
    genesis: &CommittedState,
    cp: &WeakSubjectivityCheckpoint,
) -> io::Result<(CommittedState, BlockEnvelope)> {
    let bad = |m: String| io::Error::new(io::ErrorKind::InvalidData, m);
    let (env, body) = decode_snapshot_file(bytes).map_err(|e| bad(e.to_string()))?;
    // 1. The artifact is about the block the signers signed about.
    let id = env.block_id();
    if id.as_bytes() != &cp.block_root {
        return Err(bad(format!(
            "snapshot REFUSED: its boundary block is {} but the checkpoint pins {} — \
             this is not the checkpoint's snapshot, whoever served it",
            crate::codec::hex8(id.as_bytes()),
            crate::codec::hex8(&cp.block_root),
        )));
    }
    // 2. The header the quorum pinned must itself carry the checkpoint's
    //    state root; a divergence means a forged or corrupted artifact.
    if env.header.state_root != cp.state_root {
        return Err(bad(format!(
            "snapshot REFUSED: boundary header commits state root {} but the checkpoint \
             says {} — inconsistent artifact",
            crate::codec::hex8(&env.header.state_root),
            crate::codec::hex8(&cp.state_root),
        )));
    }
    // 3. Decode-and-verify in the pure crate: the restored state must
    //    reproduce the checkpoint's state root or it never exists.
    let trust = SnapshotTrust { state_root: cp.state_root, head: id, head_slot: env.header.slot };
    let state = snapshot::restore(body, genesis, &trust).map_err(|e| bad(e.to_string()))?;
    Ok((state, env))
}

// ───────────────────────────────────────────────────────────────────────────
// Export + the snapshot store a node serves from
// ───────────────────────────────────────────────────────────────────────────

/// Where a node keeps the snapshots it serves.
pub fn snapshots_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("snapshots")
}

/// How many exported snapshots to keep. Old publication epochs age out —
/// anyone syncing uses a recent checkpoint, and the disk is not a chain
/// archive.
const KEEP_SNAPSHOTS: usize = 4;

/// Serialize `state` and write `<snapshots>/<state-root hex>.snap` (plus its
/// manifest sidecar), pruning to [`KEEP_SNAPSHOTS`] newest. Returns the path.
///
/// The file name is the state root because that is the request key: a peer
/// asks for a `state_root`, never for "latest" — the checkpoint decides which
/// root may be trusted, not the server.
pub fn export_to_dir(dir: &Path, state: &CommittedState, env: &BlockEnvelope) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let body = state.snapshot_serialize();
    let file = encode_snapshot_file(env, &body);
    let name = crate::codec::hex(&env.header.state_root);
    let path = dir.join(format!("{name}.snap"));
    let tmp = dir.join(format!("{name}.snap.tmp"));
    fs::write(&tmp, &file)?;
    fs::rename(&tmp, &path)?;
    let manifest = manifest_of(&file);
    fs::write(dir.join(format!("{name}.snap.manifest")), encode_response(&manifest))?;
    prune_snapshots(dir);
    Ok(path)
}

fn prune_snapshots(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    let mut snaps: Vec<(std::time::SystemTime, PathBuf)> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "snap"))
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    snaps.sort_by(|a, b| b.0.cmp(&a.0)); // newest first
    for (_, p) in snaps.into_iter().skip(KEEP_SNAPSHOTS) {
        let _ = fs::remove_file(&p);
        let mut m = p.into_os_string();
        m.push(".manifest");
        let _ = fs::remove_file(PathBuf::from(m));
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Wire form
// ───────────────────────────────────────────────────────────────────────────

/// Chunk size. Well under both transports' frame caps (8 MiB each) with room
/// for framing, and big enough that a carryover-scale artifact is a few dozen
/// requests.
pub const STATE_CHUNK_LEN: u32 = 2 * 1024 * 1024;

/// Ceiling on an artifact a node will offer or fetch: [`MAX_STATE_CHUNKS`] ×
/// [`STATE_CHUNK_LEN`] = 8 GiB. A manifest claiming more is refused — a lying
/// server must not be able to command an unbounded download.
pub const MAX_STATE_CHUNKS: u32 = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateSyncRequest {
    /// "Do you serve the snapshot whose file hashes chunk into `state_root`'s
    /// artifact, and what shape is it?"
    Manifest { state_root: [u8; 32] },
    /// One chunk of it.
    Chunk { state_root: [u8; 32], index: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateSyncResponse {
    Manifest {
        state_root: [u8; 32],
        total_len: u64,
        chunk_len: u32,
        /// SHA3-256 of each chunk, in order. Transport integrity only — the
        /// downloaded whole still faces [`import`]'s root check.
        chunk_hashes: Vec<[u8; 32]>,
    },
    Chunk { state_root: [u8; 32], index: u32, bytes: Vec<u8> },
    Unavailable { state_root: [u8; 32] },
}

const REQ_MANIFEST: u8 = 0x01;
const REQ_CHUNK: u8 = 0x02;
const RESP_MANIFEST: u8 = 0x01;
const RESP_CHUNK: u8 = 0x02;
const RESP_UNAVAILABLE: u8 = 0x03;

pub fn encode_request(req: &StateSyncRequest) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    match req {
        StateSyncRequest::Manifest { state_root } => {
            out.push(REQ_MANIFEST);
            out.extend_from_slice(state_root);
        }
        StateSyncRequest::Chunk { state_root, index } => {
            out.push(REQ_CHUNK);
            out.extend_from_slice(state_root);
            out.extend_from_slice(&index.to_le_bytes());
        }
    }
    out
}

pub fn decode_request(buf: &[u8]) -> Result<StateSyncRequest, DecodeErr> {
    let mut r = Reader::new(buf);
    let req = match r.u8()? {
        REQ_MANIFEST => StateSyncRequest::Manifest { state_root: r.h32()? },
        REQ_CHUNK => StateSyncRequest::Chunk { state_root: r.h32()?, index: r.u32()? },
        _ => return Err(DecodeErr("unknown state-sync request tag")),
    };
    r.finish()?;
    Ok(req)
}

pub fn encode_response(resp: &StateSyncResponse) -> Vec<u8> {
    match resp {
        StateSyncResponse::Manifest { state_root, total_len, chunk_len, chunk_hashes } => {
            let mut out = Vec::with_capacity(49 + chunk_hashes.len() * 32);
            out.push(RESP_MANIFEST);
            out.extend_from_slice(state_root);
            out.extend_from_slice(&total_len.to_le_bytes());
            out.extend_from_slice(&chunk_len.to_le_bytes());
            out.extend_from_slice(&(chunk_hashes.len() as u32).to_le_bytes());
            for h in chunk_hashes {
                out.extend_from_slice(h);
            }
            out
        }
        StateSyncResponse::Chunk { state_root, index, bytes } => {
            let mut out = Vec::with_capacity(41 + bytes.len());
            out.push(RESP_CHUNK);
            out.extend_from_slice(state_root);
            out.extend_from_slice(&index.to_le_bytes());
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
            out
        }
        StateSyncResponse::Unavailable { state_root } => {
            let mut out = Vec::with_capacity(33);
            out.push(RESP_UNAVAILABLE);
            out.extend_from_slice(state_root);
            out
        }
    }
}

pub fn decode_response(buf: &[u8]) -> Result<StateSyncResponse, DecodeErr> {
    let mut r = Reader::new(buf);
    let resp = match r.u8()? {
        RESP_MANIFEST => {
            let state_root = r.h32()?;
            let total_len = r.u64()?;
            let chunk_len = r.u32()?;
            let n = r.u32()?;
            if n > MAX_STATE_CHUNKS {
                return Err(DecodeErr("manifest over the chunk cap"));
            }
            let mut chunk_hashes = Vec::with_capacity(n as usize);
            for _ in 0..n {
                chunk_hashes.push(r.h32()?);
            }
            StateSyncResponse::Manifest { state_root, total_len, chunk_len, chunk_hashes }
        }
        RESP_CHUNK => {
            let state_root = r.h32()?;
            let index = r.u32()?;
            let n = r.u32()? as usize;
            if n > STATE_CHUNK_LEN as usize {
                return Err(DecodeErr("chunk over the chunk length"));
            }
            let bytes = r.take(n)?.to_vec();
            StateSyncResponse::Chunk { state_root, index, bytes }
        }
        RESP_UNAVAILABLE => StateSyncResponse::Unavailable { state_root: r.h32()? },
        _ => return Err(DecodeErr("unknown state-sync response tag")),
    };
    r.finish()?;
    Ok(resp)
}

fn sha3(bytes: &[u8]) -> [u8; 32] {
    Sha3_256::digest(bytes).into()
}

/// The manifest of one artifact's bytes.
fn manifest_of(file: &[u8]) -> StateSyncResponse {
    // The request key is the state root the file's own boundary header
    // carries; a file that does not decode has no business being served.
    let state_root = decode_snapshot_file(file)
        .map(|(env, _)| env.header.state_root)
        .unwrap_or([0u8; 32]);
    let chunk_hashes = file.chunks(STATE_CHUNK_LEN as usize).map(sha3).collect();
    StateSyncResponse::Manifest {
        state_root,
        total_len: file.len() as u64,
        chunk_len: STATE_CHUNK_LEN,
        chunk_hashes,
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Serving
// ───────────────────────────────────────────────────────────────────────────

/// Locate the artifact for `state_root` in this data dir: the exported
/// snapshots, or the node's own installed boot snapshot.
fn find_artifact(data_dir: &Path, state_root: &[u8; 32]) -> Option<PathBuf> {
    let name = crate::codec::hex(state_root);
    let published = snapshots_dir(data_dir).join(format!("{name}.snap"));
    if published.is_file() {
        return Some(published);
    }
    // The installed snapshot is keyed by content, not name — check its header.
    let installed = data_dir.join(INSTALLED_SNAPSHOT);
    if let Ok(bytes) = fs::read(&installed) {
        if let Ok((env, _)) = decode_snapshot_file(&bytes) {
            if &env.header.state_root == state_root {
                return Some(installed);
            }
        }
    }
    None
}

/// Answer one state-sync request from this node's disk. Never errors at the
/// caller: anything wrong on this side is `Unavailable`, because the peer's
/// remedy is the same either way — ask someone else.
pub fn serve(data_dir: &Path, req: &StateSyncRequest) -> StateSyncResponse {
    match req {
        StateSyncRequest::Manifest { state_root } => {
            let Some(path) = find_artifact(data_dir, state_root) else {
                return StateSyncResponse::Unavailable { state_root: *state_root };
            };
            // Sidecar first; recompute (and cache) when absent — the
            // installed snapshot has no sidecar, and losing one is not an
            // error.
            let mut m = path.clone().into_os_string();
            m.push(".manifest");
            let sidecar = PathBuf::from(m);
            if let Ok(bytes) = fs::read(&sidecar) {
                if let Ok(resp @ StateSyncResponse::Manifest { .. }) = decode_response(&bytes) {
                    return resp;
                }
            }
            match fs::read(&path) {
                Ok(file) => {
                    let resp = manifest_of(&file);
                    let _ = fs::write(&sidecar, encode_response(&resp));
                    resp
                }
                Err(_) => StateSyncResponse::Unavailable { state_root: *state_root },
            }
        }
        StateSyncRequest::Chunk { state_root, index } => {
            let unavailable = StateSyncResponse::Unavailable { state_root: *state_root };
            let Some(path) = find_artifact(data_dir, state_root) else { return unavailable };
            let Ok(mut f) = File::open(&path) else { return unavailable };
            let Ok(meta) = f.metadata() else { return unavailable };
            let total = meta.len();
            let offset = (*index as u64).saturating_mul(STATE_CHUNK_LEN as u64);
            if offset >= total {
                return unavailable;
            }
            let len = (total - offset).min(STATE_CHUNK_LEN as u64) as usize;
            let mut bytes = vec![0u8; len];
            if f.seek(SeekFrom::Start(offset)).is_err() || f.read_exact(&mut bytes).is_err() {
                return unavailable;
            }
            StateSyncResponse::Chunk { state_root: *state_root, index: *index, bytes }
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// The resumable download
// ───────────────────────────────────────────────────────────────────────────

/// Chunk bookkeeping for one in-progress artifact download.
///
/// The `.part` file lives in `<data-dir>/statesync/` and chunks land at
/// their final offsets, so a restart re-hashes what is on disk against the
/// manifest and continues. Nothing here is trusted: a chunk that matches the
/// manifest hash may still be part of a lie, which is why the assembled file
/// goes to [`import`] and is destroyed on refusal.
pub struct Download {
    path: PathBuf,
    file: File,
    state_root: [u8; 32],
    total_len: u64,
    chunk_hashes: Vec<[u8; 32]>,
    have: Vec<bool>,
}

impl Download {
    /// Open (or resume) the download of `state_root`'s artifact under the
    /// manifest `m`. Refuses a manifest whose shape is impossible or over the
    /// size cap; re-hashes any existing partial file so resume is exact.
    pub fn open(data_dir: &Path, m: &StateSyncResponse) -> io::Result<Download> {
        let bad = |msg: &str| io::Error::new(io::ErrorKind::InvalidData, msg.to_string());
        let StateSyncResponse::Manifest { state_root, total_len, chunk_len, chunk_hashes } = m
        else {
            return Err(bad("not a manifest"));
        };
        if *chunk_len != STATE_CHUNK_LEN {
            return Err(bad("manifest chunk length is not this protocol's"));
        }
        let n = chunk_hashes.len() as u64;
        if n == 0 || n > MAX_STATE_CHUNKS as u64 {
            return Err(bad("manifest chunk count out of range"));
        }
        let expect_n = total_len.div_ceil(STATE_CHUNK_LEN as u64);
        if n != expect_n {
            return Err(bad("manifest chunk count does not match its length"));
        }
        let dir = data_dir.join("statesync");
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{}.part", crate::codec::hex(state_root)));
        let mut file = OpenOptions::new().read(true).write(true).create(true).open(&path)?;
        // Resume: hash whatever full-length prefix is on disk.
        let mut have = vec![false; chunk_hashes.len()];
        let disk_len = file.metadata()?.len().min(*total_len);
        for (i, hash) in chunk_hashes.iter().enumerate() {
            let offset = i as u64 * STATE_CHUNK_LEN as u64;
            let len = (*total_len - offset).min(STATE_CHUNK_LEN as u64);
            if offset + len > disk_len {
                break;
            }
            let mut buf = vec![0u8; len as usize];
            file.seek(SeekFrom::Start(offset))?;
            if file.read_exact(&mut buf).is_ok() && &sha3(&buf) == hash {
                have[i] = true;
            }
        }
        Ok(Download {
            path,
            file,
            state_root: *state_root,
            total_len: *total_len,
            chunk_hashes: chunk_hashes.clone(),
            have,
        })
    }

    pub fn state_root(&self) -> [u8; 32] {
        self.state_root
    }

    /// Chunk indices still needed, capped at `limit`.
    pub fn missing(&self, limit: usize) -> Vec<u32> {
        self.have
            .iter()
            .enumerate()
            .filter(|(_, h)| !**h)
            .map(|(i, _)| i as u32)
            .take(limit)
            .collect()
    }

    pub fn complete(&self) -> bool {
        self.have.iter().all(|h| *h)
    }

    pub fn done_count(&self) -> (usize, usize) {
        (self.have.iter().filter(|h| **h).count(), self.have.len())
    }

    /// Accept one chunk: correct index, exact expected length, hash matching
    /// the manifest — anything else is ignored (`false`), and a duplicate of
    /// a chunk already held is ignored too.
    pub fn accept_chunk(&mut self, index: u32, bytes: &[u8]) -> io::Result<bool> {
        let i = index as usize;
        if i >= self.have.len() || self.have[i] {
            return Ok(false);
        }
        let offset = index as u64 * STATE_CHUNK_LEN as u64;
        let want = (self.total_len - offset).min(STATE_CHUNK_LEN as u64) as usize;
        if bytes.len() != want || sha3(bytes) != self.chunk_hashes[i] {
            return Ok(false);
        }
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(bytes)?;
        self.have[i] = true;
        Ok(true)
    }

    /// The assembled artifact bytes. Call only when [`Download::complete`].
    pub fn take_bytes(&mut self) -> io::Result<Vec<u8>> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut out = Vec::with_capacity(self.total_len as usize);
        (&mut self.file).take(self.total_len).read_to_end(&mut out)?;
        if out.len() as u64 != self.total_len {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "partial file shrank"));
        }
        Ok(out)
    }

    /// Delete the partial file — after a successful install, or after the
    /// assembled artifact failed [`import`] (in which case the manifest that
    /// shaped it is not to be resumed either).
    pub fn destroy(self) {
        let _ = fs::remove_file(&self.path);
    }
}


// ───────────────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_round_trip_req(req: StateSyncRequest) {
        let bytes = encode_request(&req);
        assert_eq!(decode_request(&bytes).unwrap(), req);
        let mut junk = bytes.clone();
        junk.push(0);
        assert!(decode_request(&junk).is_err(), "encode(x) ‖ junk must not decode");
    }

    #[test]
    fn requests_round_trip_strictly() {
        wire_round_trip_req(StateSyncRequest::Manifest { state_root: [7; 32] });
        wire_round_trip_req(StateSyncRequest::Chunk { state_root: [9; 32], index: 41 });
    }

    #[test]
    fn responses_round_trip_strictly() {
        for resp in [
            StateSyncResponse::Manifest {
                state_root: [1; 32],
                total_len: STATE_CHUNK_LEN as u64 + 5,
                chunk_len: STATE_CHUNK_LEN,
                chunk_hashes: vec![[2; 32], [3; 32]],
            },
            StateSyncResponse::Chunk { state_root: [4; 32], index: 1, bytes: vec![5; 17] },
            StateSyncResponse::Unavailable { state_root: [6; 32] },
        ] {
            let bytes = encode_response(&resp);
            assert_eq!(decode_response(&bytes).unwrap(), resp);
            let mut junk = bytes.clone();
            junk.push(0);
            assert!(decode_response(&junk).is_err());
        }
    }

    #[test]
    fn manifest_over_the_chunk_cap_is_refused() {
        let resp = StateSyncResponse::Manifest {
            state_root: [1; 32],
            total_len: 0,
            chunk_len: STATE_CHUNK_LEN,
            chunk_hashes: vec![],
        };
        let mut bytes = encode_response(&resp);
        // Patch the count field (offset 1 + 32 + 8 + 4) past the cap.
        let at = 45;
        bytes[at..at + 4].copy_from_slice(&(MAX_STATE_CHUNKS + 1).to_le_bytes());
        assert!(decode_response(&bytes).is_err());
    }

    #[test]
    fn download_resumes_and_verifies_chunks() {
        let dir = std::env::temp_dir().join(format!("bloch-statesync-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // A fake 2.5-chunk artifact.
        let file: Vec<u8> =
            (0..(2 * STATE_CHUNK_LEN as usize + 1234)).map(|i| (i % 251) as u8).collect();
        let chunks: Vec<&[u8]> = file.chunks(STATE_CHUNK_LEN as usize).collect();
        let manifest = StateSyncResponse::Manifest {
            state_root: [0xAB; 32],
            total_len: file.len() as u64,
            chunk_len: STATE_CHUNK_LEN,
            chunk_hashes: chunks.iter().map(|c| sha3(c)).collect(),
        };

        let mut d = Download::open(&dir, &manifest).unwrap();
        assert_eq!(d.missing(10), vec![0, 1, 2]);
        // Wrong bytes are ignored, not stored.
        assert!(!d.accept_chunk(0, &vec![0u8; STATE_CHUNK_LEN as usize]).unwrap());
        // Wrong length for the last chunk is ignored.
        assert!(!d.accept_chunk(2, chunks[0]).unwrap());
        // Out-of-range index is ignored.
        assert!(!d.accept_chunk(9, chunks[0]).unwrap());
        assert!(d.accept_chunk(0, chunks[0]).unwrap());
        assert!(d.accept_chunk(2, chunks[2]).unwrap());
        assert!(!d.complete());
        drop(d);

        // Resume: chunks 0 and 2 are found on disk, only 1 is missing.
        let mut d = Download::open(&dir, &manifest).unwrap();
        assert_eq!(d.missing(10), vec![1]);
        assert!(d.accept_chunk(1, chunks[1]).unwrap());
        assert!(d.complete());
        assert_eq!(d.take_bytes().unwrap(), file);
        d.destroy();
        let _ = fs::remove_dir_all(&dir);
    }

    // ── The verification chain, end to end ─────────────────────────────────

    use bloch_pos_committee::header::{BlockHeaderV4, BlockId, Body, VERSION_G4};
    use bloch_pos_committee::interfaces::StateReader;
    use bloch_pos_committee::state_root::{EutxoEntry, EvmCommitment};
    use bloch_pos_committee::transition::GenesisValidator;
    use bloch_pos_committee::ws::WS_FORMAT_VERSION;
    use bloch_pos_committee::derive;

    /// A real committed state, a boundary envelope whose header pins its
    /// root, and the checkpoint that pins the envelope — the full trust
    /// chain, in miniature.
    fn fixture() -> (CommittedState, BlockEnvelope, WeakSubjectivityCheckpoint) {
        let chain = bloch_pos_committee::beacon::RandaoChain::generate([1; 32]);
        let v = GenesisValidator {
            index: 0,
            pubkey: vec![1; 8],
            staked_sat: 200_000 * bloch_pos_committee::tokenomics_v4::SAT_PER_BLOCH,
            randao_commitment: chain.commitment(),
            withdrawal_credentials: vec![0; 4],
            commission_bps: 0,
        };
        let coins: Vec<EutxoEntry> = (0..5)
            .map(|i| EutxoEntry { txid: [i; 32], vout: 0, value: 1000 + i as u64, script_hash: [9; 32] })
            .collect();
        let genesis_header = BlockHeaderV4 {
            version: VERSION_G4,
            parent: [0; 32],
            state_root: [0; 32],
            body_root: [0; 32],
            slot: 0,
            proposer_index: 0,
            randao_reveal: [0; 32],
            randao_mix: [7; 32],
            justified_root: [0; 32],
            finalized_root: [0; 32],
            attestation_root: [0; 32],
            coherence_root: [0x33; 32],
        };
        let st = CommittedState::genesis(
            BlockId::of(&genesis_header),
            [7; 32],
            &[v],
            &[],
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            EvmCommitment { account_root: [0; 32], receipts_root: [0; 32], gas_used: 0, base_fee_per_gas: 1 },
            &coins,
        );
        // The "boundary block": a header that carries the state's root, the
        // way every applied block's header does.
        let header = BlockHeaderV4 {
            version: VERSION_G4,
            parent: [0xAA; 32],
            state_root: st.state_root(),
            body_root: derive::body_root(&[]),
            slot: 0,
            proposer_index: 0,
            randao_reveal: [0; 32],
            randao_mix: [7; 32],
            justified_root: [0; 32],
            finalized_root: [0; 32],
            attestation_root: derive::attestation_root(&[]),
            coherence_root: st.coherence_root(),
        };
        let env = BlockEnvelope {
            header,
            proposer_sig: vec![0; 8],
            body: Body { transactions: vec![], attestations: vec![] },
        };
        let cp = WeakSubjectivityCheckpoint {
            version: WS_FORMAT_VERSION,
            network_id: 1,
            genesis_root: [0; 32],
            epoch: 0,
            block_root: *env.block_id().as_bytes(),
            state_root: st.state_root(),
            validator_set_root: [0; 32],
            issued_at: 0,
            signer_set_id: 1,
        };
        (st, env, cp)
    }

    #[test]
    fn import_verifies_the_full_chain() {
        let (st, env, cp) = fixture();
        let file = encode_snapshot_file(&env, &st.snapshot_serialize());
        let (restored, renv) = import(&file, &st, &cp).expect("verified import");
        assert_eq!(restored.state_root(), cp.state_root);
        assert_eq!(*renv.block_id().as_bytes(), cp.block_root);
    }

    #[test]
    fn import_refuses_the_wrong_block() {
        // Step 1: an artifact about a different block than the checkpoint
        // pins, even with a plausible body, is refused before anything else.
        let (st, env, mut cp) = fixture();
        cp.block_root[0] ^= 1;
        let file = encode_snapshot_file(&env, &st.snapshot_serialize());
        let err = import(&file, &st, &cp).unwrap_err().to_string();
        assert!(err.contains("not the checkpoint's snapshot"), "{err}");
    }

    #[test]
    fn import_refuses_an_inconsistent_header() {
        // Step 2: envelope id matches, but its header commits a different
        // state root than the checkpoint claims — a forged pairing.
        let (st, mut env, mut cp) = fixture();
        env.header.state_root[0] ^= 1;
        cp.block_root = *env.block_id().as_bytes(); // step 1 passes
        let file = encode_snapshot_file(&env, &st.snapshot_serialize());
        let err = import(&file, &st, &cp).unwrap_err().to_string();
        assert!(err.contains("inconsistent artifact"), "{err}");
    }

    #[test]
    fn import_refuses_a_tampered_body() {
        // Step 3: everything consistent except the state bytes themselves.
        let (st, env, cp) = fixture();
        let mut file = encode_snapshot_file(&env, &st.snapshot_serialize());
        let n = file.len();
        file[n - 40] ^= 1; // inside the last eUTXO entry
        let err = import(&file, &st, &cp).unwrap_err().to_string();
        assert!(
            err.contains("does not match the checkpoint's") || err.contains("decode error"),
            "{err}"
        );
    }

    #[test]
    fn served_chunks_reassemble_into_a_verified_import() {
        // End to end without sockets: export to a snapshots dir, serve the
        // manifest and every chunk through `serve`, reassemble through
        // `Download`, and pass the result through the full import chain —
        // the same path a downloading node takes, transport aside.
        let (st, env, cp) = fixture();
        let base = std::env::temp_dir().join(format!("bloch-ss-e2e-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let server_dir = base.join("server");
        let client_dir = base.join("client");
        fs::create_dir_all(&client_dir).unwrap();
        export_to_dir(&snapshots_dir(&server_dir), &st, &env).unwrap();

        let manifest = serve(
            &server_dir,
            &StateSyncRequest::Manifest { state_root: cp.state_root },
        );
        let mut d = Download::open(&client_dir, &manifest).unwrap();
        while let Some(&index) = d.missing(1).first() {
            match serve(&server_dir, &StateSyncRequest::Chunk { state_root: cp.state_root, index })
            {
                StateSyncResponse::Chunk { bytes, .. } => {
                    assert!(d.accept_chunk(index, &bytes).unwrap());
                }
                other => panic!("server had the manifest but not chunk {index}: {other:?}"),
            }
        }
        assert!(d.complete());
        let bytes = d.take_bytes().unwrap();
        let (restored, _) = import(&bytes, &st, &cp).expect("downloaded artifact verifies");
        assert_eq!(restored.state_root(), cp.state_root);
        d.destroy();
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn unknown_roots_are_unavailable() {
        let dir = std::env::temp_dir().join(format!("bloch-ss-unavail-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let resp = serve(&dir, &StateSyncRequest::Manifest { state_root: [0xEE; 32] });
        assert_eq!(resp, StateSyncResponse::Unavailable { state_root: [0xEE; 32] });
    }

    #[test]
    fn impossible_manifests_are_refused() {
        let dir = std::env::temp_dir().join(format!("bloch-statesync-bad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        // Count does not match length.
        let m = StateSyncResponse::Manifest {
            state_root: [1; 32],
            total_len: STATE_CHUNK_LEN as u64 * 3,
            chunk_len: STATE_CHUNK_LEN,
            chunk_hashes: vec![[0; 32]; 2],
        };
        assert!(Download::open(&dir, &m).is_err());
        // Foreign chunk length.
        let m = StateSyncResponse::Manifest {
            state_root: [1; 32],
            total_len: 10,
            chunk_len: 1024,
            chunk_hashes: vec![[0; 32]],
        };
        assert!(Download::open(&dir, &m).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
