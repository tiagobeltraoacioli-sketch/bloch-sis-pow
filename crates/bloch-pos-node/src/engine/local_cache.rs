// SPDX-License-Identifier: AGPL-3.0-or-later
//! A disposable, local restart cache. The block log remains authoritative.
//! Never accept a downloaded cache as a weak-subjectivity state snapshot.
//!
//! ## The reorg anchor generation (security review 2026-11-10, PER-4 / V1-3)
//!
//! A boot that restores `state.cache` applies none of the cached prefix, so
//! it used to come up with no [`ReorgAnchors`] entry at or below the cached
//! height: until the finality latch passed the first block applied after the
//! restart (about three epochs), a reorg whose ancestor was below the cached
//! height replayed the whole chain from genesis on the consensus thread.
//!
//! Two things close that. The restored state itself is taken as the
//! `pending` anchor (free: it is the live state). And one older cache
//! generation is kept on disk as `state.cache.anchor`, taken from the
//! generations this module already writes, so it costs no additional state
//! serialization on the consensus thread:
//!
//! - when a new generation is written, the one about to be discarded
//!   (`state.cache.previous`) is renamed to `state.cache.anchor.next` if
//!   that name is free;
//! - a waiting generation whose height the finality latch has reached is
//!   renamed to `state.cache.anchor`.
//!
//! Only generations this process wrote, and whose block is still canonical,
//! are moved, so the anchor file always describes a canonical block at or
//! below the latch, which no reorg can cut. On restore it is verified like
//! the cache itself (checksum, network, build, exact log prefix, state root
//! of its block) in the same pass over the log, and becomes the `base`
//! anchor. A missing or unusable anchor file costs speed only: the genesis
//! replay remains the fallback, as before.
//!
//! A boot that replayed the whole log (no cache, or a new build, which the
//! cache is bound to) has a base anchor in memory and no anchor file until
//! several generations have been written. It writes that anchor once, at
//! boot ([`Engine::seed_anchor_generation`]), so a second restart soon after
//! does not come up without one.
use super::*;
use std::fs::{self, File};
use std::io::{Read, Write};
use sha3::{Digest, Sha3_256};

const MAGIC: &[u8; 8] = b"BPOSST01";
const CACHE: &str = "state.cache";
const PREVIOUS: &str = "state.cache.previous";
/// A generation at or below the finality latch; see the module docs.
const ANCHOR: &str = "state.cache.anchor";
/// The generation waiting for the latch to reach it.
const ANCHOR_NEXT: &str = "state.cache.anchor.next";
const MAX_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const INTERVAL: usize = 32;
#[cfg(test)]
thread_local! { static LOG_HASH_READ_BYTES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
fn invalid(s: impl ToString) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, s.to_string()) }

pub(super) fn check_replay_budget(blocks: usize, limit: Option<usize>) -> io::Result<()> {
    if limit.is_some_and(|limit| blocks > limit) {
        return Err(invalid(format!("recovery requires {blocks} replay blocks, exceeding the configured limit {limit:?}; use a qualified standby or explicitly permit full replay")));
    }
    Ok(())
}

/// SHA3 of the log's first `len` bytes for every requested length, in ONE
/// pass over the file. A length the file does not reach has no entry, which
/// the caller reads as "cache log prefix is truncated".
///
/// One pass because the anchor generation's prefix is a prefix of the
/// cache's: hashing each from the start would read the log twice on every
/// restart.
fn log_hashes(path: &std::path::Path, lens: &[u64]) -> io::Result<Vec<(u64, [u8; 32])>> {
    let mut lens = lens.to_vec();
    lens.sort_unstable();
    lens.dedup();
    let mut out = Vec::with_capacity(lens.len());
    let Some(&longest) = lens.last() else { return Ok(out) };
    let mut file = File::open(path)?.take(longest);
    let mut hash = Sha3_256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut seen = 0u64;
    for len in lens {
        while seen < len {
            // Stop exactly at the next requested length.
            let want = usize::try_from(len.saturating_sub(seen)).unwrap_or(usize::MAX).min(buf.len());
            let n = file.read(&mut buf[..want])?;
            if n == 0 { return Ok(out); }
            #[cfg(test)]
            LOG_HASH_READ_BYTES.with(|bytes| bytes.set(bytes.get().saturating_add(n as u64)));
            hash.update(&buf[..n]);
            seen = seen.checked_add(n as u64).ok_or_else(|| invalid("cache log prefix length overflow"))?;
        }
        out.push((len, hash.clone().finalize().into()));
    }
    Ok(out)
}

/// Byte length of the log's first `frames` frames: a `u32` little-endian
/// payload length, then the payload. Boot only; it walks the file.
fn log_prefix_len(path: &std::path::Path, frames: usize) -> io::Result<u64> {
    let mut file = io::BufReader::new(File::open(path)?);
    let mut at = 0u64;
    for _ in 0..frames {
        let mut prefix = [0u8; 4];
        file.read_exact(&mut prefix)?;
        let payload = u32::from_le_bytes(prefix);
        file.seek_relative(i64::from(payload))?;
        at = at.checked_add(4)
            .and_then(|at| at.checked_add(u64::from(payload)))
            .ok_or_else(|| invalid("cache log prefix length overflow"))?;
    }
    Ok(at)
}

/// `(log prefix length, block count)` from a cache file's fixed header.
/// Unverified: it only chooses which prefixes to hash and which generation
/// to move. Every use of a generation's CONTENT goes through the full checks.
fn peek_cache(path: &std::path::Path) -> Option<(u64, u64)> {
    let mut header = [0u8; 120];
    File::open(path).ok()?.read_exact(&mut header).ok()?;
    if &header[..8] != MAGIC { return None; }
    let number = |at: usize| {
        at.checked_add(8).and_then(|to| header.get(at..to)).and_then(|f| f.try_into().ok()).map(u64::from_le_bytes)
    };
    Some((number(72)?, number(112)?))
}

impl Engine {
    /// PER-4: before a new generation is written, keep the one about to be
    /// discarded as the next reorg anchor generation, and promote the waiting
    /// one once the finality latch has reached it. Renames only.
    ///
    /// A generation is moved only when this process wrote it (its height and
    /// block id are in `reorg_anchors.cached`) and that block is still on the
    /// canonical chain. A waiting file this process cannot vouch for (left by
    /// an earlier run, or orphaned by a reorg) is removed instead.
    fn retain_anchor_generation(&mut self, dir: &std::path::Path) -> io::Result<()> {
        let cached = std::mem::take(&mut self.reorg_anchors.cached);
        let on_chain = |g: &(usize, [u8; 32])| {
            self.chain.get(g.0).is_some_and(|(_, id)| id.as_bytes() == &g.1)
        };
        let waiting_path = dir.join(ANCHOR_NEXT);
        let mut waiting = cached.waiting.filter(on_chain);
        match waiting {
            Some((height, _)) => {
                if self.finalized_latch.is_some_and(|(latch, _)| height as u64 <= latch) {
                    fs::rename(&waiting_path, dir.join(ANCHOR))?;
                    waiting = None;
                }
            }
            None => match fs::remove_file(&waiting_path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                _ => {}
            },
        }
        let previous_path = dir.join(PREVIOUS);
        if waiting.is_none() {
            if let Some(previous) = cached.previous.filter(on_chain) {
                if peek_cache(&previous_path).is_some_and(|(_, count)| count == previous.0 as u64) {
                    fs::rename(&previous_path, &waiting_path)?;
                    waiting = Some(previous);
                }
            }
        }
        // Reinstated only on success: after an error the files on disk are
        // not known to match, and an unknown generation is never moved.
        self.reorg_anchors.cached = CachedGenerations { waiting, ..cached };
        Ok(())
    }

    /// A cache generation without its trailing checksum: the fixed header
    /// binding it to this network, this build and the log's first `len`
    /// bytes (`block_count` frames), then `state`.
    fn generation_bytes(
        &self,
        state: &CommittedState,
        len: u64,
        log_digest: &[u8; 32],
        block_count: usize,
    ) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&Sha3_256::digest(self.manifest.encode()));
        bytes.extend_from_slice(&Sha3_256::digest(env!("BLOCH_SOURCE_DIGEST").as_bytes()));
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(log_digest);
        bytes.extend_from_slice(&(block_count as u64).to_le_bytes());
        state.append_local_cache(&mut bytes).map_err(invalid)?;
        Ok(bytes)
    }

    /// PER-4: write the in-memory base anchor as the anchor generation.
    ///
    /// For the one boot that has an anchor in memory and none on disk: a
    /// boot that replayed the whole log. It reads the log prefix to bind the
    /// generation to it, which is why it runs at boot and never on the live
    /// path. Nothing is written when there is no base anchor yet.
    pub(super) fn seed_anchor_generation(&self) -> io::Result<()> {
        let Some((height, id, state)) = self.reorg_anchors.base.as_ref() else { return Ok(()) };
        if !self.chain.get(*height).is_some_and(|(_, cid)| cid.as_bytes() == id) {
            return Ok(());
        }
        let dir = self.store.directory();
        let log = dir.join("blocks.log");
        let len = log_prefix_len(&log, *height)?;
        let log_digest = log_hashes(&log, &[len])?
            .first()
            .map(|(_, digest)| *digest)
            .ok_or_else(|| invalid("block log ends below the reorg anchor"))?;
        let bytes = self.generation_bytes(state, len, &log_digest, *height)?;
        let checksum = Sha3_256::digest(&bytes);
        if (bytes.len() as u64).saturating_add(checksum.len() as u64) > MAX_BYTES {
            return Err(invalid("state cache exceeds 512 MiB"));
        }
        let destination = dir.join(ANCHOR);
        let mut staging = crate::store::PrivateStagingFile::create_for(&destination)?;
        staging.file_mut().write_all(&bytes)?;
        staging.file_mut().write_all(&checksum)?;
        staging.publish(&destination)?;
        println!("state-cache: reorg anchor generation written at height {height}");
        Ok(())
    }

    /// Called only after the canonical log is durable, while holding its lock.
    pub(super) fn write_local_cache(&mut self) -> io::Result<()> {
        if self.chain.len() <= 1 { return Ok(()); }
        let started = std::time::Instant::now();
        let dir = self.store.directory();
        // Store tracks the exact framed bytes through durable appends and
        // generation replacements. Rehashing all history here every 32
        // blocks used to pause the consensus loop for an increasing time.
        let (len, log_digest) = self.store.durable_log_fingerprint()?;
        let block_count = self.chain.len().checked_sub(1)
            .ok_or_else(|| invalid("cache canonical chain is empty"))?;
        let bytes = self.generation_bytes(&self.state, len, &log_digest, block_count)?;
        let checksum = Sha3_256::digest(&bytes);
        let file_len = bytes.len().checked_add(checksum.len())
            .ok_or_else(|| invalid("cache length overflow"))?;
        if file_len as u64 > MAX_BYTES { return Err(invalid("state cache exceeds 512 MiB")); }
        let dir = dir.to_path_buf();
        let destination = dir.join(CACHE);
        let mut staging = crate::store::PrivateStagingFile::create_for(&destination)?;
        staging.file_mut().write_all(&bytes)?;
        staging.file_mut().write_all(&checksum)?;
        staging.file_mut().sync_all()?;
        if let Err(e) = self.retain_anchor_generation(&dir) {
            eprintln!("state-cache: could not retain a reorg anchor generation: {e}");
        }
        // What each name holds from here on, as far as this process knows.
        let written = self.reorg_anchors.cached.current.take();
        self.reorg_anchors.cached.previous = None;
        if destination.exists() {
            fs::rename(&destination, dir.join(PREVIOUS))?;
            self.reorg_anchors.cached.previous = written;
        }
        staging.publish(&destination)?;
        self.reorg_anchors.cached.current = Some((block_count, *self.head_id().as_bytes()));
        println!("state-cache: persisted slot={} blocks={} bytes={} elapsed_ms={}", self.state.slot(), block_count, file_len, started.elapsed().as_millis());
        Ok(())
    }

    /// Validate completely before changing any engine state. A failed cache
    /// leaves the genesis engine and complete log intact for ordinary replay.
    /// Success moves the validated prefix into the engine and leaves only the
    /// uncached tail in `logged`; signatures and bodies are never deep-cloned.
    pub(super) fn restore_local_cache(&mut self, logged: &mut Vec<BlockEnvelope>) -> io::Result<usize> {
        let mut errors = Vec::new();
        let dir = self.store.directory().to_path_buf();
        // Every generation that may be read below, hashed in one pass.
        let lens: Vec<u64> = [CACHE, PREVIOUS, ANCHOR].iter()
            .filter_map(|name| peek_cache(&dir.join(name)))
            .map(|(len, _)| len)
            .collect();
        let digests = log_hashes(&dir.join("blocks.log"), &lens)?;
        let anchor_count = peek_cache(&dir.join(ANCHOR)).and_then(|(_, count)| usize::try_from(count).ok());
        // The anchor generation is the last resort, after both recent ones:
        // it is at or below the finality latch, so it still matches a log
        // that was truncated above finality (`--reject-block-root` at boot,
        // `Engine::truncate_rejected_log`), when both recent generations
        // covered the truncated blocks. It is verified exactly like them.
        for name in [CACHE, PREVIOUS, ANCHOR] {
            match self.read_local_cache(name, logged, &digests, anchor_count) {
                Ok((state, count, anchor_len)) => {
                    // PER-4: the retained anchor generation, checked against
                    // the prefix that was just verified, before it is drained.
                    let anchor = match anchor_count.zip(anchor_len) {
                        Some((n, len)) if n < count => self
                            .read_anchor_cache(&logged[..n], len, &digests)
                            .map_err(|e| println!("state-cache: reorg anchor generation unusable ({e})"))
                            .ok(),
                        _ => None,
                    };
                    for env in logged.drain(..count) {
                        let id = env.block_id();
                        self.chain.push((env.header.slot, id));
                        self.canonical.insert(*id.as_bytes());
                        self.note_tx_slots(env.header.slot, &body_transactions(&env).map_err(invalid)?);
                        self.blocks.insert(*id.as_bytes(), env);
                        // The cached prefix is this node's own canonical log,
                        // applied before the cache was written. It votes as
                        // replayed history does (FC-1), and it must be marked
                        // before the ratchet below releases finalized bodies.
                        self.blocks.mark_validated(id.as_bytes());
                    }
                    self.state.set(state);
                    self.remember_state(*self.state.head().as_bytes(), self.state.arc());
                    self.ratchet_finalized();
                    // PER-4: none of the prefix went through `apply_canonical`,
                    // so no reorg anchor was taken. The restored state is the
                    // pending one (free: it is the live state), the retained
                    // generation the base. Without them a reorg below this
                    // height would replay from genesis.
                    self.reorg_anchors.pending = Some((count, *self.state.head().as_bytes(), self.state.arc()));
                    match &anchor {
                        Some((height, ..)) => println!("state-cache: reorg anchor restored at height {height}"),
                        None => println!("state-cache: no reorg anchor at or below the finalized height; a reorg below height {count} replays from genesis until one is retained"),
                    }
                    self.reorg_anchors.base = anchor;
                    self.head_slot.store(self.state.slot(), Ordering::Relaxed);
                    // A cache hit may consume the entire log, leaving no tail
                    // block to pass through `apply_canonical`. Publish the
                    // restored canonical summary here so RPC cannot retain
                    // the genesis placeholder after a no-tail restart.
                    self.publish_block_count();
                    println!("state-cache: restored file={name} slot={} skipped_blocks={count}", self.state.slot());
                    return Ok(count);
                }
                Err(e) => { errors.push(format!("{name}: {e}")); }
            }
        }
        Err(invalid(errors.join("; ")))
    }

    /// PER-4: the anchor generation as a reorg anchor. `prefix` is the
    /// canonical prefix it must end at, already verified block by block by
    /// the cache restore that precedes this, and `prefix_len` its exact byte
    /// length in the log.
    fn read_anchor_cache(
        &self,
        prefix: &[BlockEnvelope],
        prefix_len: u64,
        digests: &[(u64, [u8; 32])],
    ) -> io::Result<ReorgAnchor> {
        let (bytes, end, len, count) = self.checked_cache_bytes(ANCHOR)?;
        let last = prefix.last().ok_or_else(|| invalid("anchor canonical prefix is empty"))?;
        if count != prefix.len() || len != prefix_len {
            return Err(invalid("anchor generation does not end at its log frame"));
        }
        if !digests.iter().any(|(at, digest)| *at == len && digest[..] == bytes[80..112]) {
            return Err(invalid("anchor generation log prefix changed"));
        }
        let state = CommittedState::decode_local_cache(&bytes[120..end], &last.header).map_err(invalid)?;
        if state.admission_network_domain() != self.state.admission_network_domain() {
            return Err(invalid("anchor generation admission domain mismatch"));
        }
        Ok((count, *last.block_id().as_bytes(), Arc::new(state)))
    }

    /// A cache file's bytes after the checks that need nothing but the file:
    /// size, checksum, schema, network and build. Returns the bytes, the
    /// offset of the trailing checksum, the log prefix length and the block
    /// count.
    fn checked_cache_bytes(&self, name: &str) -> io::Result<(Vec<u8>, usize, u64, usize)> {
        let path = self.store.directory().join(name);
        let file = File::open(path)?;
        if file.metadata()?.len() > MAX_BYTES { return Err(invalid("oversized state cache")); }
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
        // fixed header 120 bytes + checksum 32; variable state follows header.
        if bytes.len() < 152 || bytes.len() as u64 > MAX_BYTES { return Err(invalid("truncated state cache")); }
        let end = bytes.len().checked_sub(32).ok_or_else(|| invalid("cache checksum is truncated"))?;
        if Sha3_256::digest(&bytes[..end]).as_slice() != &bytes[end..] { return Err(invalid("state cache checksum mismatch")); }
        if &bytes[..8] != MAGIC || bytes[8..40] != Sha3_256::digest(self.manifest.encode())[..] ||
            bytes[40..72] != Sha3_256::digest(env!("BLOCH_SOURCE_DIGEST").as_bytes())[..] {
            return Err(invalid("state cache schema, network or build mismatch"));
        }
        let number = |at: usize| -> io::Result<u64> {
            let end = at.checked_add(8).ok_or_else(|| invalid("cache header offset overflow"))?;
            let value = bytes.get(at..end).ok_or_else(|| invalid("cache header is truncated"))?;
            Ok(u64::from_le_bytes(value.try_into().map_err(invalid)?))
        };
        let len = number(72)?;
        let count = usize::try_from(number(112)?).map_err(invalid)?;
        Ok((bytes, end, len, count))
    }

    /// `mark` asks for the byte length of the first `mark` log frames, which
    /// the prefix walk computes anyway (the anchor generation's prefix).
    fn read_local_cache(
        &self,
        name: &str,
        logged: &[BlockEnvelope],
        digests: &[(u64, [u8; 32])],
        mark: Option<usize>,
    ) -> io::Result<(CommittedState, usize, Option<u64>)> {
        let (bytes, end, len, count) = self.checked_cache_bytes(name)?;
        if count == 0 || count > logged.len() { return Err(invalid("state cache is ahead of the log")); }
        match digests.iter().find(|(at, _)| *at == len) {
            None => return Err(invalid("cache log prefix is truncated")),
            Some((_, digest)) if digest[..] != bytes[80..112] => return Err(invalid("state cache log prefix changed")),
            Some(_) => {}
        }
        let mut parent = self.manifest.genesis_id();
        let mut slot = 0;
        let mut prefix_len = 0u64;
        let mut mark_len = None;
        for (i, env) in logged[..count].iter().enumerate() {
            if env.header.parent != *parent.as_bytes() || env.header.slot <= slot {
                return Err(invalid("state cache prefix is not canonical"));
            }
            body_transactions(env).map_err(invalid)?;
            prefix_len = prefix_len.checked_add(4)
                .and_then(|len| len.checked_add(crate::codec::encode_envelope(env).len() as u64))
                .ok_or_else(|| invalid("cache frame prefix length overflow"))?;
            parent = env.block_id(); slot = env.header.slot;
            if mark == Some(i.saturating_add(1)) { mark_len = Some(prefix_len); }
        }
        if prefix_len != len { return Err(invalid("state cache does not end at its log frame")); }
        let last = logged.get(..count).and_then(|prefix| prefix.last())
            .ok_or_else(|| invalid("cache canonical prefix is empty"))?;
        let state = CommittedState::decode_local_cache(&bytes[120..end], &last.header).map_err(invalid)?;
        if state.admission_network_domain() != self.state.admission_network_domain() { return Err(invalid("state cache admission domain mismatch")); }
        Ok((state, count, mark_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_recovery_refuses_an_unbounded_tail() {
        assert!(check_replay_budget(63, Some(63)).is_ok());
        assert!(check_replay_budget(64, Some(63)).is_err());
        assert!(check_replay_budget(1, Some(0)).is_err());
        assert!(check_replay_budget(0, Some(0)).is_ok());
        assert!(check_replay_budget(100000, None).is_ok());
    }

    fn reset(engine: &mut Engine) {
        let genesis = engine.manifest.genesis_id();
        engine.state = StateCell::new(engine.manifest.genesis_state());
        engine.chain = vec![(0, genesis)];
        engine.canonical = BTreeSet::from([*genesis.as_bytes()]);
        engine.blocks.clear();
        engine.recent_states.clear();
        engine.tx_slot_index.clear();
        engine.tx_slot_index_order.clear();
        engine.finalized_latch = None;
        engine.live = false;
    }

    fn fixture() -> (Engine, perf_support::TestDir, Vec<BlockEnvelope>) {
        let (mut engine, dir) = perf_support::proposing_engine();
        engine.live = false;
        for slot in 1..=70 { engine.propose(slot); }
        assert_eq!(engine.state.slot(), 70);
        let logged: Vec<_> = engine.chain[1..].iter().map(|(_, id)| engine.blocks[id.as_bytes()].clone()).collect();
        engine.store.rewrite(&logged).unwrap();
        engine.write_local_cache().unwrap();
        (engine, dir, logged)
    }

    #[cfg(unix)]
    #[test]
    fn cache_staging_preserves_symlink_target_and_previous_generation() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let (mut engine, dir, mut logged) = fixture();
        let previous = fs::read(dir.0.join("state.cache")).unwrap();
        let victim = dir.0.join("unrelated-cache-target");
        fs::write(&victim, b"do not truncate").unwrap();
        let legacy = dir.0.join("state.cache.tmp");
        symlink(&victim, &legacy).unwrap();
        engine.write_local_cache().unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"do not truncate");
        assert!(fs::symlink_metadata(&legacy).unwrap().file_type().is_symlink());
        assert_eq!(fs::read(dir.0.join("state.cache.previous")).unwrap(), previous);
        assert_eq!(fs::metadata(dir.0.join("state.cache")).unwrap().permissions().mode() & 0o777, 0o600);
        reset(&mut engine);
        assert_eq!(engine.restore_local_cache(&mut logged).unwrap(), 70);
    }

    #[test]
    fn cache_restores_every_state_field_and_continues_identically() {
        let (mut engine, _dir, mut logged) = fixture();
        let at_cache = engine.state.arc();
        engine.propose(71);
        let next = engine.blocks[engine.head_id().as_bytes()].clone();
        let expected = engine.state.arc();
        logged.push(next.clone());
        engine.store.rewrite(&logged).unwrap();
        let full_log = logged.clone();
        let first_id = logged[0].block_id();
        assert!(!logged[0].proposer_sig.is_empty());
        let signature_ptr = logged[0].proposer_sig.as_ptr();
        reset(&mut engine);
        assert_eq!(engine.restore_local_cache(&mut logged).unwrap(), 70);
        assert_eq!(logged.len(), 1, "only uncached tail remains for replay");
        let published = match engine.block_count.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        assert_eq!(
            published,
            engine.block_count_reply(),
            "cache restore must publish its canonical height even before tail replay"
        );
        assert_eq!(logged[0].block_id(), next.block_id());
        assert_eq!(engine.blocks[first_id.as_bytes()].proposer_sig.as_ptr(), signature_ptr, "cached envelopes must retain their original allocations");
        assert_eq!(*engine.state, *at_cache);
        assert!(engine.ingest_replay(next));
        assert_eq!(*engine.state, *expected);
        let restored = engine.state.arc();
        reset(&mut engine);
        for block in full_log { assert!(engine.ingest_replay(block)); }
        assert_eq!(*engine.state, *restored, "cached continuation must equal full verified replay");
    }

    #[test]
    fn corrupt_or_torn_cache_falls_back_to_previous_generation() {
        let (mut engine, dir, mut logged) = fixture();
        engine.write_local_cache().unwrap();
        fs::write(dir.0.join("state.cache"), b"torn").unwrap();
        reset(&mut engine);
        assert_eq!(engine.restore_local_cache(&mut logged).unwrap(), 70);
        logged = engine.store.read_all().unwrap();
        fs::write(dir.0.join("state.cache.previous"), b"also torn").unwrap();
        reset(&mut engine);
        assert!(engine.restore_local_cache(&mut logged).is_err());
        assert_eq!(engine.state.slot(), 0);
        assert_eq!(logged.len(), 70, "failed restore must preserve every replay block");
        for block in logged { assert!(engine.ingest_replay(block)); }
        assert_eq!(engine.state.slot(), 70);
    }

    #[test]
    fn cache_writes_do_not_rescan_history_but_recovery_still_verifies_disk() {
        let (mut engine, dir, mut logged) = fixture();
        let log_path = dir.0.join("blocks.log");
        let log = fs::read(&log_path).unwrap();
        LOG_HASH_READ_BYTES.with(|bytes| bytes.set(0));
        for _ in 0..3 { engine.write_local_cache().unwrap(); }
        assert_eq!(LOG_HASH_READ_BYTES.with(|bytes| bytes.get()), 0,
            "periodic cache writes must not hash the growing history on the slot loop");
        reset(&mut engine);
        assert_eq!(engine.restore_local_cache(&mut logged).unwrap(), 70);
        assert_eq!(LOG_HASH_READ_BYTES.with(|bytes| bytes.get()), log.len() as u64,
            "restart must independently verify the complete on-disk prefix");

        // An out-of-band, same-length disk modification cannot be blessed by
        // the writer's in-memory fingerprint, even if another cache is saved.
        let mut changed = log;
        *changed.last_mut().unwrap() ^= 1;
        fs::write(&log_path, changed).unwrap();
        engine.write_local_cache().unwrap();
        logged = engine.chain[1..].iter().map(|(_, id)| engine.blocks[id.as_bytes()].clone()).collect();
        reset(&mut engine);
        assert!(engine.restore_local_cache(&mut logged).is_err());
        assert_eq!(engine.state.slot(), 0);
        assert_eq!(logged.len(), 70);
    }

    #[test]
    fn cache_rejects_changed_log_build_network_and_state_root() {
        let (mut engine, dir, mut logged) = fixture();
        let cache = fs::read(dir.0.join("state.cache")).unwrap();
        for offset in [8usize, 40, 120] {
            let mut changed = cache.clone();
            changed[offset] ^= 1;
            let end = changed.len() - 32;
            let checksum = Sha3_256::digest(&changed[..end]);
            changed[end..].copy_from_slice(&checksum);
            fs::write(dir.0.join("state.cache"), &changed).unwrap();
            reset(&mut engine);
            assert!(engine.restore_local_cache(&mut logged).is_err());
            assert_eq!(engine.chain.len(), 1);
        }
        fs::write(dir.0.join("state.cache"), cache).unwrap();
        engine.store.rewrite(&logged[..40]).unwrap();
        assert!(engine.restore_local_cache(&mut logged[..40].to_vec()).is_err());
        assert_eq!(engine.state.slot(), 0);
    }

    /// Propose `slots`, publish the canonical chain as the block log and
    /// write one cache generation, as the live node does every `INTERVAL`.
    fn extend_and_cache(engine: &mut Engine, slots: std::ops::RangeInclusive<u64>) -> Vec<BlockEnvelope> {
        for slot in slots { engine.propose(slot); }
        let logged: Vec<_> = engine.chain[1..].iter().map(|(_, id)| engine.blocks[id.as_bytes()].clone()).collect();
        engine.store.rewrite(&logged).unwrap();
        engine.write_local_cache().unwrap();
        logged
    }

    /// PER-4: a boot that restores the cache comes up with reorg anchors, so
    /// a reorg below the cached height does not replay from genesis.
    ///
    /// The genesis replay is observed the way the FC-2 test observes it: the
    /// block at height 1 is taken out of the store, which a replay from
    /// genesis cannot do without and a replay that starts above never reads.
    #[test]
    fn a_cache_restart_keeps_reorg_anchors_below_the_cached_height() {
        let (mut engine, dir) = perf_support::proposing_engine();
        engine.live = false;
        extend_and_cache(&mut engine, 1..=10);
        extend_and_cache(&mut engine, 11..=20);
        // As if finality had reached height 15: the generation at height 10
        // is at or below it, the one at height 20 is not.
        engine.finalized_latch = Some((15, *engine.chain[15].1.as_bytes()));
        extend_and_cache(&mut engine, 21..=30);
        assert!(dir.0.join(ANCHOR_NEXT).exists(), "the discarded generation waits for the latch");
        assert!(!dir.0.join(ANCHOR).exists(), "nothing is promoted before it was kept");
        let mut logged = extend_and_cache(&mut engine, 31..=40);
        assert_eq!(peek_cache(&dir.0.join(ANCHOR)).map(|(_, count)| count), Some(10));
        assert_eq!(peek_cache(&dir.0.join(ANCHOR_NEXT)).map(|(_, count)| count), Some(20));
        assert_eq!(peek_cache(&dir.0.join(PREVIOUS)).map(|(_, count)| count), Some(30));
        assert_eq!(peek_cache(&dir.0.join(CACHE)).map(|(_, count)| count), Some(40));

        let id_at = |engine: &Engine, h: usize| *engine.chain[h].1.as_bytes();
        let targets = [12usize, 35, 39];
        let expected: Vec<CommittedState> =
            targets.iter().map(|&h| engine.replay_to(id_at(&engine, h))).collect();
        let anchor_id = id_at(&engine, 10);

        // Restart from the cache with an empty tail.
        reset(&mut engine);
        engine.reorg_anchors = Default::default();
        LOG_HASH_READ_BYTES.with(|bytes| bytes.set(0));
        assert_eq!(engine.restore_local_cache(&mut logged).unwrap(), 40);
        assert_eq!(
            LOG_HASH_READ_BYTES.with(|bytes| bytes.get()),
            std::fs::metadata(dir.0.join("blocks.log")).unwrap().len(),
            "the anchor generation is verified in the same single pass over the log"
        );
        assert_eq!(
            engine.reorg_anchors.base.as_ref().map(|a| (a.0, a.1)),
            Some((10, anchor_id)),
            "the retained generation is the base anchor"
        );
        assert_eq!(
            engine.reorg_anchors.pending.as_ref().map(|a| (a.0, a.1)),
            Some((40, id_at(&engine, 40))),
            "the restored state is the pending anchor"
        );
        assert_eq!(
            engine.reorg_anchors.base.as_ref().map(|a| a.2.state_root()),
            Some(engine.blocks[&anchor_id].header.state_root),
            "the anchor state is its block's committed state"
        );

        // Two more blocks, as the finding's scenario has it.
        engine.live = true;
        engine.propose(41);
        engine.propose(42);
        assert_eq!(engine.chain.len(), 43);

        let first = id_at(&engine, 1);
        engine.blocks.remove(&first).expect("height 1 is stored");
        for (&h, want) in targets.iter().zip(&expected) {
            let id = id_at(&engine, h);
            assert!(
                !engine.recent_states.iter().any(|(bid, _)| *bid == id),
                "height {h}: fixture — the target is outside the two-state ring"
            );
            assert_eq!(*engine.state_at_canonical(id), *want, "height {h}: anchored replay differs");
        }
        // The reorg of the finding: an ancestor one below the cached height.
        let ancestor = id_at(&engine, 39);
        assert!(engine.do_reorg(ancestor, Vec::new()), "the reorg is adopted");
        assert_eq!(*engine.state, expected[2], "and lands on the genesis replay's state");
    }

    /// W2-8 (4): after a cache restart with the finality latch restored (as
    /// `reconcile_finalized_latch` does at boot), the bodies below it are
    /// released. A replay from the base anchor then reads those blocks back
    /// from the block log and reaches the same state.
    #[test]
    fn an_anchored_replay_after_a_cache_restart_reads_released_bodies_from_the_log() {
        let (mut engine, dir) = perf_support::proposing_engine();
        engine.live = false;
        extend_and_cache(&mut engine, 1..=10);
        extend_and_cache(&mut engine, 11..=20);
        engine.finalized_latch = Some((15, *engine.chain[15].1.as_bytes()));
        extend_and_cache(&mut engine, 21..=30);
        let mut logged = extend_and_cache(&mut engine, 31..=40);
        assert_eq!(peek_cache(&dir.0.join(ANCHOR)).map(|(_, count)| count), Some(10));
        let id_at = |engine: &Engine, h: usize| *engine.chain[h].1.as_bytes();
        let targets = [12usize, 14];
        let expected: Vec<CommittedState> =
            targets.iter().map(|&h| engine.replay_to(id_at(&engine, h))).collect();

        reset(&mut engine);
        engine.reorg_anchors = Default::default();
        assert_eq!(engine.restore_local_cache(&mut logged).unwrap(), 40);
        assert_eq!(engine.reorg_anchors.base.as_ref().map(|a| a.0), Some(10));
        engine.finalized_latch = Some((15, id_at(&engine, 15)));
        engine.hollow_finalized_bodies();
        for h in 1..15 {
            assert!(engine.blocks.is_hollow(&id_at(&engine, h)), "height {h}: body released below the latch");
        }
        for (&h, want) in targets.iter().zip(&expected) {
            assert_eq!(
                *engine.state_at_canonical(id_at(&engine, h)),
                *want,
                "height {h}: the anchored replay over released bodies differs"
            );
        }
    }

    /// A boot that replayed the whole log writes the base anchor it holds,
    /// so the next restart from the cache has one before any generation was
    /// rotated into place.
    #[test]
    fn a_replay_boot_seeds_the_anchor_generation() {
        let (mut engine, dir) = perf_support::proposing_engine();
        engine.live = false;
        for slot in 1..=3 { engine.propose(slot); }
        // As if finality had reached height 3: the anchor taken at height 1
        // becomes the base (the FC-2 promotion).
        engine.finalized_latch = Some((3, *engine.chain[3].1.as_bytes()));
        for slot in 4..=12 { engine.propose(slot); }
        let base = engine.reorg_anchors.base.as_ref().map(|a| (a.0, a.1)).expect("the latch passed an anchor");
        let mut logged: Vec<_> = engine.chain[1..].iter().map(|(_, id)| engine.blocks[id.as_bytes()].clone()).collect();
        engine.store.rewrite(&logged).unwrap();
        assert!(!dir.0.join(ANCHOR).exists());
        engine.seed_anchor_generation().unwrap();
        engine.write_local_cache().unwrap();
        assert_eq!(peek_cache(&dir.0.join(ANCHOR)).map(|(_, count)| count), Some(base.0 as u64));

        reset(&mut engine);
        engine.reorg_anchors = Default::default();
        assert_eq!(engine.restore_local_cache(&mut logged).unwrap(), 12);
        assert_eq!(engine.reorg_anchors.base.as_ref().map(|a| (a.0, a.1)), Some(base));
        assert_eq!(
            engine.reorg_anchors.base.as_ref().map(|a| a.2.state_root()),
            Some(engine.blocks[&base.1].header.state_root),
        );
        // Nothing to write, and no error, when there is no base anchor.
        engine.reorg_anchors.base = None;
        engine.seed_anchor_generation().unwrap();
    }

    /// A log truncated above the latch but below both recent generations
    /// (what `--reject-block-root` does at boot) restores from the anchor
    /// generation instead of replaying from genesis.
    #[test]
    fn a_log_truncated_below_both_recent_generations_restores_from_the_anchor() {
        let (mut engine, dir) = perf_support::proposing_engine();
        engine.live = false;
        extend_and_cache(&mut engine, 1..=10);
        extend_and_cache(&mut engine, 11..=20);
        engine.finalized_latch = Some((15, *engine.chain[15].1.as_bytes()));
        extend_and_cache(&mut engine, 21..=30);
        let logged = extend_and_cache(&mut engine, 31..=40);
        assert_eq!(peek_cache(&dir.0.join(ANCHOR)).map(|(_, count)| count), Some(10));
        let mut truncated = logged[..25].to_vec();
        engine.store.rewrite(&truncated).unwrap();
        reset(&mut engine);
        engine.reorg_anchors = Default::default();
        assert_eq!(engine.restore_local_cache(&mut truncated).unwrap(), 10);
        assert_eq!(truncated.len(), 15, "only the tail above the anchor is left to replay");
        for env in truncated { assert!(engine.ingest_replay(env)); }
        assert_eq!(engine.head_id(), logged[24].block_id());
    }

    /// Without a retained generation the restore still seeds the pending
    /// anchor, and says that the base is missing instead of failing.
    #[test]
    fn a_cache_restart_without_an_anchor_generation_still_restores() {
        let (mut engine, dir, mut logged) = fixture();
        assert!(!dir.0.join(ANCHOR).exists());
        reset(&mut engine);
        engine.reorg_anchors = Default::default();
        assert_eq!(engine.restore_local_cache(&mut logged).unwrap(), 70);
        assert!(engine.reorg_anchors.base.is_none());
        assert_eq!(engine.reorg_anchors.pending.as_ref().map(|a| a.0), Some(70));
    }

    /// A generation whose block left the canonical chain, or that this
    /// process did not write, is never kept as an anchor; a damaged anchor
    /// file costs the base anchor and nothing else.
    #[test]
    fn only_canonical_generations_written_by_this_process_become_anchors() {
        let (mut engine, dir) = perf_support::proposing_engine();
        engine.live = false;
        extend_and_cache(&mut engine, 1..=10);
        extend_and_cache(&mut engine, 11..=20);
        // Height 10 leaves the chain; a different block takes its place.
        // The blocks given back are taken out of the store, so the zero-weight
        // tie between the two branches cannot re-adopt them (see
        // `reorg_state_tests::forked`).
        let ancestor = *engine.chain[5].1.as_bytes();
        let given_back: Vec<[u8; 32]> = engine.chain[6..].iter().map(|(_, id)| *id.as_bytes()).collect();
        let old_height_10 = *engine.chain[10].1.as_bytes();
        assert!(engine.do_reorg(ancestor, Vec::new()));
        for id in &given_back { engine.blocks.remove(id).expect("stored"); }
        engine.finalized_latch = Some((5, ancestor));
        extend_and_cache(&mut engine, 21..=30);
        assert_ne!(*engine.chain[10].1.as_bytes(), old_height_10, "fixture: another block at height 10");
        assert!(
            !dir.0.join(ANCHOR_NEXT).exists(),
            "the generation at the old height 10 describes a block that is no longer canonical"
        );
        // A waiting file left by an earlier run is removed, not promoted.
        std::fs::copy(dir.0.join(CACHE), dir.0.join(ANCHOR_NEXT)).unwrap();
        engine.reorg_anchors.cached = Default::default();
        let mut logged = extend_and_cache(&mut engine, 31..=32);
        assert!(!dir.0.join(ANCHOR_NEXT).exists() && !dir.0.join(ANCHOR).exists());

        // A damaged anchor file: the restore succeeds without a base anchor.
        std::fs::copy(dir.0.join(PREVIOUS), dir.0.join(ANCHOR)).unwrap();
        let mut damaged = std::fs::read(dir.0.join(ANCHOR)).unwrap();
        let at = damaged.len() - 40;
        damaged[at] ^= 1;
        std::fs::write(dir.0.join(ANCHOR), damaged).unwrap();
        let count = logged.len();
        reset(&mut engine);
        engine.reorg_anchors = Default::default();
        assert_eq!(engine.restore_local_cache(&mut logged).unwrap(), count);
        assert!(engine.reorg_anchors.base.is_none(), "a damaged anchor generation is not used");
        assert_eq!(engine.reorg_anchors.pending.as_ref().map(|a| a.0), Some(count));
    }

    /// One pass yields the same digests as hashing each prefix on its own,
    /// and a length past the end of the file has no digest.
    #[test]
    fn log_hashes_match_independent_prefix_hashes() {
        let dir = std::env::temp_dir().join(format!("bloch-log-hashes-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blocks.log");
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &data).unwrap();
        let lens = [150_000u64, 0, 65_536, 200_000, 150_000, 200_001];
        let got = log_hashes(&path, &lens).unwrap();
        let want: Vec<(u64, [u8; 32])> = [0u64, 65_536, 150_000, 200_000]
            .iter()
            .map(|&len| (len, Sha3_256::digest(&data[..len as usize]).into()))
            .collect();
        assert_eq!(got, want);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn checksum_rejects_single_bit_corruption_and_trailing_bytes() {
        let (mut engine, dir, mut logged) = fixture();
        let cache = fs::read(dir.0.join("state.cache")).unwrap();
        let mut changed = cache.clone();
        changed[150] ^= 1;
        fs::write(dir.0.join("state.cache"), changed).unwrap();
        reset(&mut engine);
        assert!(engine.restore_local_cache(&mut logged).is_err());
        let mut changed = cache;
        changed.push(0);
        fs::write(dir.0.join("state.cache"), changed).unwrap();
        assert!(engine.restore_local_cache(&mut logged).is_err());
    }
}
