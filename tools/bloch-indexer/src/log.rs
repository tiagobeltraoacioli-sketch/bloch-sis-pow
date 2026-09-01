// SPDX-License-Identifier: AGPL-3.0-or-later

//! Seek-served reader over a node's `blocks.log`.
//!
//! ## Reused, not reinvented
//!
//! The frame table is the node's own, from `perf/network-sync` `e904a6db`
//! (`crates/bloch-pos-node/src/store.rs`), where it exists to serve a
//! `get-blocks` page without walking the log from byte 0 — time to first block
//! of a 512-block page at `after_slot=53,400` went 77.1 ms -> 2.1 ms and became
//! flat in the chain length. The same table answers the same question for an
//! indexer, so the shape (`FrameRef { slot, offset, len }`, built by one scan,
//! looked up by a per-entry filter with **no monotonicity assumption**) is
//! carried over deliberately, including the properties its tests pin:
//!
//! - `offset` points at the frame's **payload**, not at its 4-byte length
//!   prefix, because the payload is what an answer carries.
//! - Lookup filters entry by entry rather than binary-searching. Slots are
//!   strictly increasing when the engine writes the log, but that is an engine
//!   invariant and not a format guarantee, and `e904a6db`'s
//!   `indexed_and_scanned_answers_are_identical` proves the point by feeding
//!   slots `[4,1,9,9,2,40,7]`. This reader is exercised against the same shape.
//!
//! What is NOT carried over is `Store` itself: it opens the log for **append**
//! and refuses a data dir whose `meta.bin` names another genesis. An indexer
//! reads a file it must never write, and reads copies of archival data dirs it
//! did not initialise, so it opens the log read-only and takes the genesis
//! digest from the manifest instead.
//!
//! ## The frame format, and the two ways it lies
//!
//! `u32 LE payload length ‖ payload`, butted end to end from byte 0, no magic,
//! no checksum, no compression. Two things follow that an external reader must
//! handle and that are **not** corruption:
//!
//! 1. **A torn trailing frame is normal.** Appends are one `write_all` plus
//!    `sync_data`; a crash mid-append leaves a frame whose declared length runs
//!    past EOF. The node drops it (`store.rs:110`) and so does this.
//! 2. **A reorg replaces the file, inode and all.** `Store::rewrite` writes a
//!    fresh `blocks.log.tmp` holding the whole new chain and renames it over
//!    `blocks.log`, so the file can *shrink* and every offset a previous scan
//!    held is meaningless. [`LogReader::open`] therefore records the file's
//!    identity ([`LogFingerprint`]) and [`LogReader::changed`] reports when a
//!    re-scan is mandatory. Tailing by offset alone silently mis-parses after a
//!    reorg; that is the whole reason `changed` exists.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use bloch_pos_committee::header::{BlockEnvelope, BlockHeaderV4, VERSION_G4};

/// Largest payload this reader will accept, matching the node's
/// `codec::MAX_FIELD_LEN`. A corrupt length field must cost one failed read,
/// not a multi-gigabyte allocation.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Where one logged block sits in `blocks.log`, and what slot it is for.
///
/// `offset` points at the frame's PAYLOAD, not at its 4-byte length prefix —
/// the node's convention, kept so the two tables mean the same thing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameRef {
    pub slot: u64,
    pub offset: u64,
    pub len: u32,
}

/// Enough of a file's identity to know that re-scanning is mandatory.
///
/// Size alone is not enough: a reorg that replaces N blocks with N blocks of
/// the same total size leaves the size unchanged, and on a mirror pulled with
/// `scp` the mtime moves for reasons unrelated to content. The inode is what
/// actually changes under `rename`, and it changes on every reorg because
/// `rewrite` never edits in place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogFingerprint {
    pub len: u64,
    pub inode: u64,
    pub mtime_secs: i64,
}

impl LogFingerprint {
    fn of(path: &Path) -> io::Result<LogFingerprint> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let m = std::fs::metadata(path)?;
            Ok(LogFingerprint { len: m.len(), inode: m.ino(), mtime_secs: m.mtime() })
        }
        #[cfg(not(unix))]
        {
            let m = std::fs::metadata(path)?;
            let mtime = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            Ok(LogFingerprint { len: m.len(), inode: 0, mtime_secs: mtime })
        }
    }
}

/// Why a scan stopped before the end of the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanEnd {
    /// The whole file parsed into whole frames.
    Clean,
    /// The last frame's declared length runs past EOF — a crash mid-append.
    /// Normal; the node drops the same frame.
    TornTrailingFrame,
    /// A length field below the 304-byte header, so no header can be read.
    /// The node stops here too.
    ShortFrame,
}

/// A read-only, seek-served view of one `blocks.log`.
pub struct LogReader {
    path: PathBuf,
    file: File,
    frames: Vec<FrameRef>,
    fingerprint: LogFingerprint,
    end: ScanEnd,
}

impl LogReader {
    /// Open `path` read-only and build its frame table with one linear scan.
    ///
    /// The scan reads only the 4-byte length and the 304-byte header of each
    /// frame and seeks past the body, so it costs one seek per block rather
    /// than a full read of the file.
    pub fn open(path: &Path) -> io::Result<LogReader> {
        let fingerprint = LogFingerprint::of(path)?;
        let mut file = File::open(path)?;
        let (frames, end) = scan_frames(&mut file, fingerprint.len)?;
        Ok(LogReader { path: path.to_path_buf(), file, frames, fingerprint, end })
    }

    /// Re-scan in place. Call after [`changed`](Self::changed) says so.
    pub fn reopen(&mut self) -> io::Result<()> {
        let fingerprint = LogFingerprint::of(&self.path)?;
        let mut file = File::open(&self.path)?;
        let (frames, end) = scan_frames(&mut file, fingerprint.len)?;
        self.file = file;
        self.frames = frames;
        self.fingerprint = fingerprint;
        self.end = end;
        Ok(())
    }

    /// Has the file been replaced or extended since the table was built?
    ///
    /// `Ok(false)` means every offset in the table is still valid.
    pub fn changed(&self) -> io::Result<bool> {
        Ok(LogFingerprint::of(&self.path)? != self.fingerprint)
    }

    pub fn fingerprint(&self) -> LogFingerprint {
        self.fingerprint
    }

    pub fn scan_end(&self) -> ScanEnd {
        self.end
    }

    pub fn frames(&self) -> &[FrameRef] {
        &self.frames
    }

    pub fn len(&self) -> usize {
        self.frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Raw payload bytes of the `i`th frame, read by one seek.
    pub fn payload_at(&mut self, i: usize) -> io::Result<Vec<u8>> {
        let fr = *self
            .frames
            .get(i)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "frame index out of range"))?;
        self.file.seek(SeekFrom::Start(fr.offset))?;
        let mut buf = vec![0u8; fr.len as usize];
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Decoded envelope of the `i`th frame, through the node's own decoder.
    pub fn envelope_at(&mut self, i: usize) -> io::Result<BlockEnvelope> {
        let bytes = self.payload_at(i)?;
        crate::codec::decode_envelope(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    /// Just the header of the `i`th frame — 304 bytes, no body read.
    ///
    /// This is what makes a range query over blocks cheap: answering "blocks
    /// 30,000-30,100" touches 100 × 304 bytes, not 100 × ~14 KB of attestation
    /// signatures.
    pub fn header_at(&mut self, i: usize) -> io::Result<BlockHeaderV4> {
        let fr = *self
            .frames
            .get(i)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "frame index out of range"))?;
        self.file.seek(SeekFrom::Start(fr.offset))?;
        let mut buf = [0u8; BlockHeaderV4::ENCODED_LEN];
        self.file.read_exact(&mut buf)?;
        BlockHeaderV4::canonical_deserialize(&buf)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad header"))
    }

    /// Frames for slots strictly after `after_slot`, at most `limit` of them.
    ///
    /// Per-entry filter, no binary search: see the module docs.
    pub fn frames_after(&self, after_slot: u64, limit: usize) -> Vec<FrameRef> {
        self.frames.iter().copied().filter(|fr| fr.slot > after_slot).take(limit).collect()
    }
}

/// One linear scan producing the frame table.
///
/// Mirrors `e904a6db:store.rs:scan_frames` rule for rule, including which
/// malformations stop the scan quietly (torn tail, short frame) and which are
/// a hard error (an oversized length field).
fn scan_frames(file: &mut File, file_len: u64) -> io::Result<(Vec<FrameRef>, ScanEnd)> {
    const HDR: usize = BlockHeaderV4::ENCODED_LEN;
    let mut out = Vec::new();
    let mut at: u64 = 0;
    file.seek(SeekFrom::Start(0))?;
    let mut len_buf = [0u8; 4];
    let mut hdr_buf = [0u8; HDR];
    loop {
        if at + 4 > file_len {
            return Ok((out, ScanEnd::Clean));
        }
        if let Err(e) = file.read_exact(&mut len_buf) {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                return Ok((out, ScanEnd::Clean));
            }
            return Err(e);
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame at offset {at} declares {len} bytes, past the {MAX_FRAME_BYTES} cap"),
            ));
        }
        // A frame that runs past EOF is the crash-mid-append case, and a frame
        // too short to hold a header cannot be parsed at all. Both stop the
        // scan without discarding what came before, exactly as the node does.
        if at + 4 + len as u64 > file_len {
            return Ok((out, ScanEnd::TornTrailingFrame));
        }
        if len < HDR {
            return Ok((out, ScanEnd::ShortFrame));
        }
        file.read_exact(&mut hdr_buf)?;
        // The one sentinel this format has. There is no magic and no checksum,
        // so if the length prefix is ever wrong there is no resync — but every
        // payload begins with VERSION_G4, and checking it turns a silent
        // mis-parse into a stated error.
        let version = u32::from_le_bytes([hdr_buf[0], hdr_buf[1], hdr_buf[2], hdr_buf[3]]);
        if version != VERSION_G4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "frame at offset {at} starts with version {version:#010x}, not \
                     VERSION_G4 {:#010x}: the log is from another schema, or the length \
                     prefix before it is wrong and there is nothing to resync to",
                    VERSION_G4
                ),
            ));
        }
        let header = BlockHeaderV4::canonical_deserialize(&hdr_buf)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad header in frame"))?;
        out.push(FrameRef { slot: header.slot, offset: at + 4, len: len as u32 });
        file.seek(SeekFrom::Current((len - HDR) as i64))?;
        at += 4 + len as u64;
    }
}
