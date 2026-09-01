// SPDX-License-Identifier: AGPL-3.0-or-later

//! `Engine::blocks`, split into the part that is read and the part that is
//! only stored.
//!
//! # The measurement this exists for
//!
//! `Engine::blocks` was a `BTreeMap<[u8; 32], BlockEnvelope>` holding every
//! structurally-valid block ever seen, unpruned. On the live fleet that map is
//! the asymptote: 9 validators to a 31,866 MiB box, ~1,258 MiB each, growing
//! 0.0198 MiB per block at 2,873 blocks/day. Composition measured over 30,578
//! real Genesis-4 blocks: header 2.2%, proposer signature 32.9%, attestations
//! 57.4%, transactions 7.5%. **Ninety percent of it is post-quantum signature
//! material that was verified once at ingest and is never read again** except
//! to re-verify on a replay, to rewrite the log, or to answer an RPC.
//!
//! Who actually reads the map, by lifetime:
//!
//! | reader | what it needs | how much |
//! |---|---|---|
//! | [`crate::engine::lmd_ghost_head`] | parent edge + attestation triples | ~139 B/block |
//! | `head_state_root`, `randao_positioned`, `ancestral_boundary_mix` | header fields | 0 |
//! | `path_to_canonical` → `do_reorg` | whole envelopes | the unfinalized suffix (85 blocks live) |
//! | `replay_to`, `do_reorg`'s log rewrite | whole envelopes from genesis, in chain order | streamed |
//! | `getblock*` | one whole envelope | one |
//!
//! Everything in the first two rows fits in [`BlockFacts`], a fixed 108 bytes
//! plus one 44-byte triple per attestation the block carried. Everything in
//! the last three rows is served from `blocks.log`, which **already holds a
//! byte-identical copy of what the map was keeping in RAM.**
//!
//! # How much of the map the log does NOT cover, measured
//!
//! `blocks.log` holds the canonical chain and only the canonical chain, so a
//! non-canonical block has to stay whole in RAM. It is worth stating what that
//! costs rather than assuming it is nothing, because the figure that was
//! quoted when this work started — `blocks_known == height`, zero fork
//! overhang — **is not what the fleet reports.** Four live validators, at
//! height 33,985:
//!
//! ```text
//!   139.84.205.54   blocks_known 34210   overhang 225
//!   67.219.108.230  blocks_known 33987   overhang   2
//!   149.28.180.128  blocks_known 34210   overhang 225
//!   139.84.201.52   blocks_known 34211   overhang 226
//! ```
//!
//! So the resident set is 0.66% of the map, ~3.1 MiB at 13,934 B/block, not
//! zero. That is small against the 396 MiB this removes, but it is the one
//! term here that still grows without bound, and it grows for the same reason
//! the whole map used to: nothing prunes it. [`BlockMap::resident_count`] is
//! reported on the boot line so it is visible as a number rather than only as
//! RSS.
//!
//! # Nothing is pruned
//!
//! This is the distinction that makes this change possible where pruning was
//! refused. A previous review turned down pruning `Engine::blocks` on three
//! grounds; two of them (fork choice walks from `justified`, and `finalized`
//! is not a latch) are arguments against *choosing a cut*. There is no cut
//! here. Every block this node has ever seen is still addressable, with the
//! same answer, forever. What moved is *where the bytes sit*, and the map's
//! key set — the thing `contains_key` answers `judge` with, the thing
//! `blocks.len()` bounds the `advance` loop by — is unchanged, entry for
//! entry.
//!
//! What survives of the third objection is its shape, and it is handled in
//! [`Home`]: during boot replay `live == false`, so a reorg does **not**
//! rewrite the log, and the log's order can therefore disagree with the
//! canonical chain at exactly the moment `replay_to` wants to read from it.
//! See [`Home::Logged`].

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bloch_pos_committee::header::{BlockEnvelope, BlockId};

/// How many whole envelopes stay decoded beside the map.
///
/// Sized for the two paths that ask for the same block twice in a row rather
/// than for a hit rate: `ingest` stores a block and `advance` immediately
/// reads it back through `path_to_canonical`, and a reorg reads its branch
/// once to validate and once to rewrite the log. 64 covers both with room for
/// a deep branch, and costs 64 × ~13 KB ≈ 0.8 MiB — three ten-thousandths of
/// what the map used to cost per validator.
const HOT_CAP: usize = 64;

/// One attestation as fork choice sees it: the triple
/// [`FcStore::observe`](bloch_pos_committee::forkchoice) is folded over, with
/// the ≈4,589-byte hybrid signature dropped.
///
/// Dropping the signature is safe here and only here: the signature was
/// checked when the block was validated, and fork choice never re-checks it —
/// `forkchoice_store` reads `att.validator`, `att.data.slot` and
/// `att.data.head` and nothing else. Keeping the triple and not the signature
/// is the whole 57.4%.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Vote {
    pub validator: u32,
    pub slot: u64,
    pub head: [u8; 32],
}

/// Everything read off a block that is not the block.
///
/// 108 fixed bytes plus the votes. Every field is copied out of the header at
/// insert time, so a reader that wants one of them touches no disk and decodes
/// nothing — which is what keeps `forkchoice_store`, called twice per block for
/// the whole map, off the I/O path entirely.
#[derive(Clone)]
pub struct BlockFacts {
    pub parent: [u8; 32],
    pub slot: u64,
    pub proposer_index: u32,
    pub randao_mix: [u8; 32],
    /// The post-state root the transition already checked against this block.
    /// `head_state_root` and `do_reorg`'s log line read it from here for the
    /// same reason they read it from the header today: `apply_block` returns
    /// `Ok(post)` on exactly one condition, `post.compute_root() ==
    /// header.state_root`.
    pub state_root: [u8; 32],
    /// Boxed, not `Vec`: this is written once and never pushed to, and a
    /// `Vec`'s spare capacity across 30,578 entries is not free.
    pub votes: Box<[Vote]>,
}

impl BlockFacts {
    fn of(env: &BlockEnvelope) -> BlockFacts {
        BlockFacts {
            parent: env.header.parent,
            slot: env.header.slot,
            proposer_index: env.header.proposer_index,
            randao_mix: env.header.randao_mix,
            state_root: env.header.state_root,
            votes: env
                .body
                .attestations
                .iter()
                .map(|a| Vote {
                    validator: a.validator,
                    slot: a.data.slot,
                    head: a.data.head,
                })
                .collect(),
        }
    }
}

/// Where a block's bytes are.
enum Home {
    /// At this byte offset in `blocks.log` — the offset of the frame's 4-byte
    /// length prefix.
    ///
    /// **Keyed by block id, never by height or by chain position.** That is
    /// the whole answer to the boot-replay divergence. During replay `live`
    /// is false, so an adopted reorg does not rewrite the log; the log's
    /// order and the canonical chain's order can differ from that moment
    /// until the next live reorg. A height-indexed or order-indexed table
    /// would be silently wrong for every block after the fork point. An
    /// offset table is not: the bytes at offset *o* are the bytes of the
    /// block whose id maps to *o*, and that stays true under any amount of
    /// reordering, because nothing moves them. Only two operations can
    /// invalidate an offset — `Store::rewrite`, which returns the new ones,
    /// and truncation of a crash-torn tail, which happens once at open before
    /// any offset is recorded.
    ///
    /// The claim is checked rather than assumed: every read verifies the
    /// decoded envelope's `BlockId` against the id it was asked for, and a
    /// mismatch is an error, not a wrong answer.
    Logged(u64),
    /// Held whole, because the log does not have it: a block that has not
    /// been applied yet, or one on a branch that lost. `blocks.log` holds the
    /// canonical chain and only the canonical chain.
    Resident(Arc<BlockEnvelope>),
}

struct Entry {
    facts: BlockFacts,
    home: Home,
}

/// What a lookup could not do.
///
/// The variants are separated because the callers must act differently, and
/// collapsing them is precisely the failure mode this change is required not
/// to introduce. `Missing` is a normal consensus event — a node that has not
/// synced far enough — and must reach `needs_sync`, never a panic and never
/// `process::exit`. `Io` is a broken disk.
#[derive(Debug)]
pub enum FetchErr {
    /// No entry for that id, or the log frame it named does not hold it.
    Missing,
    Io(io::Error),
}

impl std::fmt::Display for FetchErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchErr::Missing => write!(f, "block not stored"),
            FetchErr::Io(e) => write!(f, "block log read failed: {e}"),
        }
    }
}

struct Hot {
    by_id: HashMap<[u8; 32], Arc<BlockEnvelope>>,
    order: VecDeque<[u8; 32]>,
}

impl Hot {
    fn put(&mut self, id: [u8; 32], env: Arc<BlockEnvelope>) {
        if self.by_id.insert(id, env).is_none() {
            self.order.push_back(id);
            while self.order.len() > HOT_CAP {
                if let Some(old) = self.order.pop_front() {
                    self.by_id.remove(&old);
                }
            }
        }
    }
}

/// The map `Engine::blocks` used to be.
///
/// Same key set, same `len`, same `contains_key`. `get` is gone, replaced by
/// [`BlockMap::facts`] for the readers that only wanted a header field and
/// [`BlockMap::envelope`] for the three that really want the block.
pub struct BlockMap {
    entries: BTreeMap<[u8; 32], Entry>,
    log_path: PathBuf,
    /// One open handle, reused. `RefCell` because every envelope reader on the
    /// engine holds `&self` — and the engine is single-threaded by
    /// construction (one consensus thread owns it), so there is no contention
    /// to lose, only a borrow to keep short.
    reader: RefCell<Option<BufReader<File>>>,
    hot: RefCell<Hot>,
    /// How many entries are held whole — the blocks `blocks.log` does not
    /// have, which is the non-canonical set. Measured at 225 of 34,210 on the
    /// live fleet (see the module docs); it is the one term in this map that
    /// still grows without bound, and it is printed on the boot line so it is
    /// visible as a number rather than only as RSS.
    resident: usize,
}

impl BlockMap {
    pub fn new(dir: &Path) -> BlockMap {
        BlockMap {
            entries: BTreeMap::new(),
            log_path: dir.join("blocks.log"),
            reader: RefCell::new(None),
            hot: RefCell::new(Hot {
                by_id: HashMap::new(),
                order: VecDeque::new(),
            }),
            resident: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn resident_count(&self) -> usize {
        self.resident
    }

    pub fn contains_key(&self, id: &[u8; 32]) -> bool {
        self.entries.contains_key(id)
    }

    /// The header fields and attestation triples. No I/O, no decode.
    pub fn facts(&self, id: &[u8; 32]) -> Option<&BlockFacts> {
        self.entries.get(id).map(|e| &e.facts)
    }

    /// Every entry's facts, ascending by id — the iteration order the old
    /// `BTreeMap<_, BlockEnvelope>` had, preserved because `forkchoice_store`
    /// builds sibling lists from it.
    pub fn iter_facts(&self) -> impl Iterator<Item = (&[u8; 32], &BlockFacts)> {
        self.entries.iter().map(|(id, e)| (id, &e.facts))
    }

    /// Store a block whose bytes are not (yet) in the log.
    pub fn insert_resident(&mut self, id: [u8; 32], env: BlockEnvelope) {
        let facts = BlockFacts::of(&env);
        let env = Arc::new(env);
        self.hot.borrow_mut().put(id, Arc::clone(&env));
        if let Some(prev) = self.entries.insert(
            id,
            Entry {
                facts,
                home: Home::Resident(env),
            },
        ) {
            if matches!(prev.home, Home::Resident(_)) {
                self.resident -= 1;
            }
        }
        self.resident += 1;
    }

    /// Store a block whose bytes are already in the log at `offset` — the boot
    /// replay path, where the envelope was decoded straight out of the file it
    /// still lives in. The envelope is dropped after this returns; only the
    /// hot cache keeps it, and only until 64 more blocks go by.
    pub fn insert_logged(&mut self, id: [u8; 32], env: BlockEnvelope, offset: u64) {
        let facts = BlockFacts::of(&env);
        self.hot.borrow_mut().put(id, Arc::new(env));
        if let Some(prev) = self.entries.insert(
            id,
            Entry {
                facts,
                home: Home::Logged(offset),
            },
        ) {
            if matches!(prev.home, Home::Resident(_)) {
                self.resident -= 1;
            }
        }
    }

    /// Hand the block's bytes over to the log: it was just appended at
    /// `offset`, so the resident copy is now a duplicate of the file and is
    /// dropped. This is where the 90% actually leaves RAM on a live node.
    pub fn mark_logged(&mut self, id: &[u8; 32], offset: u64) {
        if let Some(e) = self.entries.get_mut(id) {
            if matches!(e.home, Home::Resident(_)) {
                self.resident -= 1;
            }
            e.home = Home::Logged(offset);
        }
    }

    /// True if this block's bytes are in the log.
    pub fn is_logged(&self, id: &[u8; 32]) -> bool {
        matches!(self.entries.get(id).map(|e| &e.home), Some(Home::Logged(_)))
    }

    pub fn log_offset(&self, id: &[u8; 32]) -> Option<u64> {
        match self.entries.get(id).map(|e| &e.home) {
            Some(Home::Logged(o)) => Some(*o),
            _ => None,
        }
    }

    /// Pull a logged block back into RAM, because the log is about to be
    /// rewritten without it.
    ///
    /// `Store::rewrite` writes the canonical chain and only the canonical
    /// chain, so a block that a reorg just orphaned would lose its bytes. It
    /// must not: `blocks` is the record of every block seen, an orphan can be
    /// voted for and can win again, and `judge` answers `known` from this map.
    /// Called for the losing branch before the rewrite, and bounded by the
    /// reorg's depth.
    pub fn make_resident(&mut self, id: &[u8; 32]) -> Result<(), FetchErr> {
        let off = match self.entries.get(id).map(|e| &e.home) {
            Some(Home::Logged(o)) => *o,
            Some(Home::Resident(_)) => return Ok(()),
            None => return Err(FetchErr::Missing),
        };
        let env = Arc::new(self.read_frame(off, id)?);
        if let Some(e) = self.entries.get_mut(id) {
            e.home = Home::Resident(env);
            self.resident += 1;
        }
        Ok(())
    }

    pub fn remove(&mut self, id: &[u8; 32]) {
        if let Some(prev) = self.entries.remove(id) {
            if matches!(prev.home, Home::Resident(_)) {
                self.resident -= 1;
            }
        }
        let mut hot = self.hot.borrow_mut();
        hot.by_id.remove(id);
    }

    /// The whole block. Resident copy, hot cache, or one seek and one decode.
    pub fn envelope(&self, id: &[u8; 32]) -> Result<Arc<BlockEnvelope>, FetchErr> {
        let off = match self.entries.get(id) {
            None => return Err(FetchErr::Missing),
            Some(Entry {
                home: Home::Resident(env),
                ..
            }) => return Ok(Arc::clone(env)),
            Some(Entry {
                home: Home::Logged(o),
                ..
            }) => *o,
        };
        if let Some(env) = self.hot.borrow().by_id.get(id) {
            return Ok(Arc::clone(env));
        }
        let env = Arc::new(self.read_frame(off, id)?);
        self.hot.borrow_mut().put(*id, Arc::clone(&env));
        Ok(env)
    }

    /// Called after `Store::rewrite` has landed: every logged block's bytes
    /// moved, and `new_offsets` says where. Ids not named kept whatever home
    /// they had — a rewrite only relocates the canonical chain, and everything
    /// else was made resident first.
    pub fn relocate(&mut self, new_offsets: &[([u8; 32], u64)]) {
        for (id, off) in new_offsets {
            if let Some(e) = self.entries.get_mut(id) {
                if matches!(e.home, Home::Resident(_)) {
                    self.resident -= 1;
                }
                e.home = Home::Logged(*off);
            }
        }
    }

    /// Read one frame and check it is the block that was asked for.
    ///
    /// The `BlockId` check is not decoration. An offset table is only as good
    /// as the invariant that nothing moves a frame without updating it, and
    /// that invariant is maintained by hand across `append`, `rewrite` and the
    /// open-time tail truncation. Verifying turns any future violation of it
    /// into a `Missing` — which every caller already has a correct answer for
    /// — instead of into a block silently standing in for another one, which
    /// is a consensus fault. It costs one hash of a 304-byte header.
    fn read_frame(&self, off: u64, want: &[u8; 32]) -> Result<BlockEnvelope, FetchErr> {
        let mut slot = self.reader.borrow_mut();
        if slot.is_none() {
            *slot = Some(BufReader::new(
                File::open(&self.log_path).map_err(FetchErr::Io)?,
            ));
        }
        let r = slot.as_mut().expect("just filled");
        r.seek(SeekFrom::Start(off)).map_err(FetchErr::Io)?;
        let mut len4 = [0u8; 4];
        r.read_exact(&mut len4).map_err(FetchErr::Io)?;
        let len = u32::from_le_bytes(len4) as usize;
        if len > crate::codec::MAX_FIELD_LEN {
            return Err(FetchErr::Missing);
        }
        let mut payload = vec![0u8; len];
        r.read_exact(&mut payload).map_err(FetchErr::Io)?;
        let env = crate::codec::decode_envelope(&payload).map_err(|_| FetchErr::Missing)?;
        if BlockId::of(&env.header).as_bytes() != want {
            return Err(FetchErr::Missing);
        }
        Ok(env)
    }

    /// Drop the read handle, so the next read reopens the file.
    ///
    /// Called after `Store::rewrite`: the handle points at an unlinked inode
    /// holding the pre-reorg log, and every offset now names the new file.
    pub fn reopen(&mut self) {
        *self.reader.borrow_mut() = None;
        let mut hot = self.hot.borrow_mut();
        hot.by_id.clear();
        hot.order.clear();
    }

    /// Build a map with every block held whole — the shape the tests want,
    /// where there is no log to serve from.
    #[cfg(test)]
    pub fn in_memory(envs: impl IntoIterator<Item = ([u8; 32], BlockEnvelope)>) -> BlockMap {
        let mut m = BlockMap::new(Path::new("/nonexistent-blockmap-test"));
        for (id, env) in envs {
            m.insert_resident(id, env);
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_pos_committee::attestation::{Attestation, AttestationData};
    use bloch_pos_committee::header::{BlockHeaderV4, Body, VERSION_G4};
    use crate::store::Store;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "bloch-blockmap-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    fn att(validator: u32, slot: u64, head: [u8; 32]) -> Attestation {
        Attestation {
            data: AttestationData {
                slot,
                head,
                source_epoch: 0,
                source_root: [0; 32],
                target_epoch: 0,
                target_root: head,
            },
            validator,
            // The 4,589-byte half of the block that this whole change is
            // about. Made big on purpose so a test that accidentally kept it
            // would be visible.
            signature: vec![0x5A; 4589],
        }
    }

    fn env_at(slot: u64, marker: u8, atts: Vec<Attestation>) -> BlockEnvelope {
        BlockEnvelope {
            header: BlockHeaderV4 {
                version: VERSION_G4,
                parent: [marker; 32],
                state_root: [marker.wrapping_add(1); 32],
                body_root: [3; 32],
                slot,
                proposer_index: marker as u32,
                randao_reveal: [4; 32],
                randao_mix: [marker.wrapping_add(9); 32],
                justified_root: [6; 32],
                finalized_root: [7; 32],
                attestation_root: [8; 32],
                coherence_root: [9; 32],
            },
            proposer_sig: vec![0xAA; 4589],
            body: Body { transactions: Vec::new(), attestations: atts },
        }
    }

    fn id_of(env: &BlockEnvelope) -> [u8; 32] {
        *BlockId::of(&env.header).as_bytes()
    }

    /// A block whose bytes went to the log comes back out of it whole.
    ///
    /// The point is not that a file round-trips — `store::tests` covers that.
    /// It is that the map answered `envelope` for a block it is NOT holding:
    /// `insert_logged` took the envelope, kept an offset, and the value that
    /// comes back is equal to what went in, field for field, signatures
    /// included.
    #[test]
    fn a_logged_block_comes_back_whole_from_an_offset_alone() {
        let d = dir("roundtrip");
        let mut store = Store::open(&d, &[7u8; 32]).expect("open");
        let mut map = BlockMap::new(&d);

        let mut written = Vec::new();
        for slot in 1..=8u64 {
            let env = env_at(slot, slot as u8, vec![att(slot as u32, slot, [slot as u8; 32])]);
            let off = store.append(&env).expect("append");
            map.insert_logged(id_of(&env), env.clone(), off);
            written.push(env);
        }
        // Past HOT_CAP would be better still, but the point is made by
        // clearing what caching there is: every answer below comes off disk.
        map.reopen();

        for env in &written {
            let got = map.envelope(&id_of(env)).expect("stored block reads back");
            assert_eq!(got.header, env.header, "header survives the round trip");
            assert_eq!(got.proposer_sig, env.proposer_sig, "the 4,589-byte proposer signature survives");
            assert_eq!(
                got.body.attestations.len(),
                env.body.attestations.len(),
                "attestations survive"
            );
            assert_eq!(
                got.body.attestations[0].signature, env.body.attestations[0].signature,
                "so does the attestation signature — the map dropped it, the log did not"
            );
        }
        assert_eq!(map.resident_count(), 0, "nothing is held whole");
        assert_eq!(map.len(), written.len(), "the key set is the whole chain");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **The guard, violated on purpose.**
    ///
    /// An offset table is only as good as the promise that nothing moves a
    /// frame without updating it. Here that promise is broken by hand — block
    /// A's entry is pointed at block B's frame, which is exactly the shape a
    /// future edit to `append` or `rewrite` would produce — and the read must
    /// refuse rather than hand back B under A's name. A block silently
    /// standing in for another one is a consensus fault; `Missing` is a
    /// condition every caller already handles.
    #[test]
    fn an_offset_pointing_at_the_wrong_frame_is_refused_not_answered() {
        let d = dir("wrongoffset");
        let mut store = Store::open(&d, &[7u8; 32]).expect("open");
        let mut map = BlockMap::new(&d);

        let a = env_at(1, 1, Vec::new());
        let b = env_at(2, 2, Vec::new());
        let off_a = store.append(&a).expect("append a");
        let off_b = store.append(&b).expect("append b");
        assert_ne!(off_a, off_b);
        map.insert_logged(id_of(&a), a.clone(), off_a);
        map.insert_logged(id_of(&b), b.clone(), off_b);
        map.reopen();

        // Control: with the true offset, A reads back as A.
        assert_eq!(
            map.envelope(&id_of(&a)).expect("control read").header.slot,
            1
        );

        // The violation.
        map.entries
            .get_mut(&id_of(&a))
            .expect("a is stored")
            .home = Home::Logged(off_b);
        map.reopen();

        match map.envelope(&id_of(&a)) {
            Err(FetchErr::Missing) => {}
            Err(e) => panic!("wrong error for a mis-keyed offset: {e}"),
            Ok(env) => panic!(
                "the map served block at slot {} under another block's id — the BlockId \
                 check that is supposed to stop this did not run",
                env.header.slot
            ),
        }
        // And B, whose offset is honest, is unaffected: the check refuses a
        // mismatch, it does not poison the file.
        assert_eq!(map.envelope(&id_of(&b)).expect("b still reads").header.slot, 2);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The log's order may differ from the chain's, and reads must not care.
    ///
    /// This is the boot-replay divergence in miniature. During replay `live`
    /// is false, so a reorg adopts a branch without rewriting the log: from
    /// that moment the file holds the pre-reorg sequence while `chain` holds
    /// the post-reorg one, and `replay_to` walks `chain`. A height-indexed or
    /// position-indexed table would answer with the wrong block for every
    /// entry past the fork. Here the blocks are appended in one order and read
    /// back in another, and each one is itself.
    #[test]
    fn reading_by_id_survives_a_log_whose_order_is_not_the_chains() {
        let d = dir("order");
        let mut store = Store::open(&d, &[7u8; 32]).expect("open");
        let mut map = BlockMap::new(&d);

        let envs: Vec<BlockEnvelope> = (1..=6u64).map(|s| env_at(s, s as u8, Vec::new())).collect();
        for env in &envs {
            let off = store.append(env).expect("append");
            map.insert_logged(id_of(env), env.clone(), off);
        }
        map.reopen();

        // Read in reverse, then interleaved — nothing like the write order.
        for env in envs.iter().rev() {
            assert_eq!(
                map.envelope(&id_of(env)).expect("read").header.slot,
                env.header.slot
            );
        }
        for i in [4usize, 0, 5, 1, 3, 2] {
            let env = &envs[i];
            assert_eq!(
                map.envelope(&id_of(env)).expect("read").header.slot,
                env.header.slot
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// `BlockFacts` keeps every vote the body carried, in order, and keeps
    /// nothing else of it.
    ///
    /// Fork choice folds `(validator, slot, head)` per attestation and reads
    /// no other field, so this equality is the whole claim that moving fork
    /// choice off the envelopes cannot change a head. Stated as a test rather
    /// than as a comment because it is a consensus-relevant claim.
    #[test]
    fn facts_carry_exactly_the_triples_fork_choice_folds() {
        let atts = vec![
            att(3, 10, [0xAA; 32]),
            att(1, 11, [0xBB; 32]),
            att(3, 12, [0xCC; 32]),
        ];
        let env = env_at(7, 4, atts.clone());
        let f = BlockFacts::of(&env);
        assert_eq!(f.votes.len(), atts.len(), "no vote is dropped");
        for (v, a) in f.votes.iter().zip(&atts) {
            assert_eq!(v.validator, a.validator);
            assert_eq!(v.slot, a.data.slot);
            assert_eq!(v.head, a.data.head);
        }
        assert_eq!(f.parent, env.header.parent);
        assert_eq!(f.slot, env.header.slot);
        assert_eq!(f.proposer_index, env.header.proposer_index);
        assert_eq!(f.randao_mix, env.header.randao_mix);
        assert_eq!(f.state_root, env.header.state_root);
    }

    /// The key set is what it was: nothing is pruned, and an entry whose bytes
    /// went to the log is still an entry.
    #[test]
    fn moving_bytes_to_the_log_does_not_change_the_key_set() {
        let d = dir("keyset");
        let mut store = Store::open(&d, &[7u8; 32]).expect("open");
        let mut map = BlockMap::new(&d);
        let envs: Vec<BlockEnvelope> = (1..=5u64).map(|s| env_at(s, s as u8, Vec::new())).collect();
        for env in &envs {
            map.insert_resident(id_of(env), env.clone());
        }
        assert_eq!(map.resident_count(), 5);
        for env in &envs {
            let off = store.append(env).expect("append");
            map.mark_logged(&id_of(env), off);
        }
        assert_eq!(map.resident_count(), 0, "the copies are gone");
        assert_eq!(map.len(), 5, "the entries are not");
        for env in &envs {
            assert!(
                map.contains_key(&id_of(env)),
                "`judge` answers `known` from this, and it must still say yes"
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
