// SPDX-License-Identifier: AGPL-3.0-or-later
//! A disposable, local restart cache. The block log remains authoritative.
//! Never accept a downloaded cache as a weak-subjectivity state snapshot.
use super::*;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use sha3::{Digest, Sha3_256};

const MAGIC: &[u8; 8] = b"BPOSST01";
const MAX_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const INTERVAL: usize = 32;
fn invalid(s: impl ToString) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, s.to_string()) }

pub(super) fn check_replay_budget(blocks: usize, limit: Option<usize>) -> io::Result<()> {
    if limit.is_some_and(|limit| blocks > limit) {
        return Err(invalid(format!("recovery requires {blocks} replay blocks, exceeding the configured limit {limit:?}; use a qualified standby or explicitly permit full replay")));
    }
    Ok(())
}

fn log_hash(path: &std::path::Path, len: u64) -> io::Result<[u8; 32]> {
    let mut file = File::open(path)?.take(len);
    let mut hash = Sha3_256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut seen = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        hash.update(&buf[..n]);
        seen = seen.checked_add(n as u64).ok_or_else(|| invalid("cache log prefix length overflow"))?;
    }
    if seen != len { return Err(invalid("cache log prefix is truncated")); }
    Ok(hash.finalize().into())
}

impl Engine {
    /// Called only after the canonical log is durable, while holding its lock.
    pub(super) fn write_local_cache(&self) -> io::Result<()> {
        if self.chain.len() <= 1 { return Ok(()); }
        let started = std::time::Instant::now();
        let dir = self.store.directory();
        let log = dir.join("blocks.log");
        let len = log.metadata()?.len();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&Sha3_256::digest(self.manifest.encode()));
        bytes.extend_from_slice(&Sha3_256::digest(env!("BLOCH_SOURCE_DIGEST").as_bytes()));
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&log_hash(&log, len)?);
        let block_count = self.chain.len().checked_sub(1)
            .ok_or_else(|| invalid("cache canonical chain is empty"))?;
        bytes.extend_from_slice(&(block_count as u64).to_le_bytes());
        bytes.extend_from_slice(&self.state.encode_local_cache().map_err(invalid)?);
        let checksum = Sha3_256::digest(&bytes);
        bytes.extend_from_slice(&checksum);
        if bytes.len() as u64 > MAX_BYTES { return Err(invalid("state cache exceeds 512 MiB")); }
        let temporary = dir.join("state.cache.tmp");
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)] {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        if dir.join("state.cache").exists() {
            fs::rename(dir.join("state.cache"), dir.join("state.cache.previous"))?;
        }
        fs::rename(temporary, dir.join("state.cache"))?;
        crate::store::fsync_dir(dir)?;
        println!("state-cache: persisted slot={} blocks={} bytes={} elapsed_ms={}", self.state.slot(), block_count, bytes.len(), started.elapsed().as_millis());
        Ok(())
    }

    /// Validate completely before changing any engine state. A failed cache
    /// leaves the genesis engine intact, ready for the ordinary replay path.
    pub(super) fn restore_local_cache(&mut self, logged: &[BlockEnvelope]) -> io::Result<usize> {
        let mut errors = Vec::new();
        for name in ["state.cache", "state.cache.previous"] {
            match self.read_local_cache(name, logged) {
                Ok((state, count)) => {
                    for env in &logged[..count] {
                        let id = env.block_id();
                        self.chain.push((env.header.slot, id));
                        self.canonical.insert(*id.as_bytes());
                        self.blocks.insert(*id.as_bytes(), env.clone());
                        self.note_tx_slots(env.header.slot, &body_transactions(env).map_err(invalid)?);
                    }
                    self.state.set(state);
                    self.remember_state(*self.state.head().as_bytes(), self.state.arc());
                    self.ratchet_finalized();
                    self.head_slot.store(self.state.slot(), Ordering::Relaxed);
                    println!("state-cache: restored file={name} slot={} skipped_blocks={count}", self.state.slot());
                    return Ok(count);
                }
                Err(e) => { errors.push(format!("{name}: {e}")); }
            }
        }
        Err(invalid(errors.join("; ")))
    }

    fn read_local_cache(&self, name: &str, logged: &[BlockEnvelope]) -> io::Result<(CommittedState, usize)> {
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
        if count == 0 || count > logged.len() { return Err(invalid("state cache is ahead of the log")); }
        if log_hash(&self.store.directory().join("blocks.log"), len)? != bytes[80..112] { return Err(invalid("state cache log prefix changed")); }
        let mut parent = self.manifest.genesis_id();
        let mut slot = 0;
        let mut prefix_len = 0u64;
        for env in &logged[..count] {
            if env.header.parent != *parent.as_bytes() || env.header.slot <= slot {
                return Err(invalid("state cache prefix is not canonical"));
            }
            body_transactions(env).map_err(invalid)?;
            prefix_len = prefix_len.checked_add(4)
                .and_then(|len| len.checked_add(crate::codec::encode_envelope(env).len() as u64))
                .ok_or_else(|| invalid("cache frame prefix length overflow"))?;
            parent = env.block_id(); slot = env.header.slot;
        }
        if prefix_len != len { return Err(invalid("state cache does not end at its log frame")); }
        let last = logged.get(..count).and_then(|prefix| prefix.last())
            .ok_or_else(|| invalid("cache canonical prefix is empty"))?;
        let state = CommittedState::decode_local_cache(&bytes[120..end], &last.header).map_err(invalid)?;
        if state.admission_network_domain() != self.state.admission_network_domain() { return Err(invalid("state cache admission domain mismatch")); }
        Ok((state, count))
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

    #[test]
    fn cache_restores_every_state_field_and_continues_identically() {
        let (mut engine, _dir, mut logged) = fixture();
        let at_cache = engine.state.arc();
        engine.propose(71);
        let next = engine.blocks[engine.head_id().as_bytes()].clone();
        let expected = engine.state.arc();
        logged.push(next.clone());
        engine.store.rewrite(&logged).unwrap();
        reset(&mut engine);
        assert_eq!(engine.restore_local_cache(&logged).unwrap(), 70);
        assert_eq!(*engine.state, *at_cache);
        engine.ingest_replay(next);
        assert_eq!(*engine.state, *expected);
        let restored = engine.state.arc();
        reset(&mut engine);
        for block in logged { engine.ingest_replay(block); }
        assert_eq!(*engine.state, *restored, "cached continuation must equal full verified replay");
    }

    #[test]
    fn corrupt_or_torn_cache_falls_back_to_previous_generation() {
        let (mut engine, dir, logged) = fixture();
        engine.write_local_cache().unwrap();
        fs::write(dir.0.join("state.cache"), b"torn").unwrap();
        reset(&mut engine);
        assert_eq!(engine.restore_local_cache(&logged).unwrap(), 70);
        fs::write(dir.0.join("state.cache.previous"), b"also torn").unwrap();
        reset(&mut engine);
        assert!(engine.restore_local_cache(&logged).is_err());
        assert_eq!(engine.state.slot(), 0);
        for block in logged { engine.ingest_replay(block); }
        assert_eq!(engine.state.slot(), 70);
    }

    #[test]
    fn cache_rejects_changed_log_build_network_and_state_root() {
        let (mut engine, dir, logged) = fixture();
        let cache = fs::read(dir.0.join("state.cache")).unwrap();
        for offset in [8usize, 40, 120] {
            let mut changed = cache.clone();
            changed[offset] ^= 1;
            let end = changed.len() - 32;
            let checksum = Sha3_256::digest(&changed[..end]);
            changed[end..].copy_from_slice(&checksum);
            fs::write(dir.0.join("state.cache"), &changed).unwrap();
            reset(&mut engine);
            assert!(engine.restore_local_cache(&logged).is_err());
            assert_eq!(engine.chain.len(), 1);
        }
        fs::write(dir.0.join("state.cache"), cache).unwrap();
        engine.store.rewrite(&logged[..40]).unwrap();
        assert!(engine.restore_local_cache(&logged[..40]).is_err());
        assert_eq!(engine.state.slot(), 0);
    }

    #[test]
    fn checksum_rejects_single_bit_corruption_and_trailing_bytes() {
        let (mut engine, dir, logged) = fixture();
        let cache = fs::read(dir.0.join("state.cache")).unwrap();
        let mut changed = cache.clone();
        changed[150] ^= 1;
        fs::write(dir.0.join("state.cache"), changed).unwrap();
        reset(&mut engine);
        assert!(engine.restore_local_cache(&logged).is_err());
        let mut changed = cache;
        changed.push(0);
        fs::write(dir.0.join("state.cache"), changed).unwrap();
        assert!(engine.restore_local_cache(&logged).is_err());
    }
}
