// SPDX-License-Identifier: AGPL-3.0-or-later

//! The index itself: apply a block, undo a block, and converge on the node's
//! chain when the node changes its mind.
//!
//! ## Reorgs are the design, not an edge case
//!
//! The node **rewrites `blocks.log` on reorg** — `Store::rewrite` writes the
//! whole new canonical chain to `blocks.log.tmp` and renames it over the log,
//! so the file gets a new inode and can shrink. Reorg depths up to **13** have
//! been measured in this chain's own logs. An index that assumed the log only
//! grows would, after any reorg, keep byte offsets into a file that no longer
//! exists and serve balances from blocks that were never on the chain.
//!
//! And `finalized` is **not a latch across a reorg** here: a node has been
//! observed below its own previously finalized checkpoint (`FcStore::head`
//! ratchets downward), so "finalized" cannot be used as a watermark meaning
//! "this can never change". Concretely, that forbids the obvious optimisation —
//! dropping undo records below the finalized height — and this index does not
//! take it. The journal is kept for a configurable depth measured in blocks,
//! and when a reorg is deeper than the journal the index **rebuilds from
//! genesis** rather than guessing. Rebuilding is slow and correct; guessing is
//! fast and wrong.
//!
//! ## The invariant
//!
//! `chain[i].block_id` is the id of the `i`th block of the node's selected
//! chain, for every `i` the index has applied. [`Index::sync`] re-establishes
//! it on every tick:
//!
//! 1. **Detect.** Compare the log's frame table against `chain`, entry by
//!    entry, on `(slot, block_id)`. The first index where they disagree — or
//!    the end of the log if it is now shorter — is the fork point.
//! 2. **Roll back.** Undo every applied block above the fork point,
//!    newest-first, from the journal. Each record restores exactly what its
//!    block changed: the outpoints it created are deleted, the outpoints it
//!    spent are put back with their prior values, the balances it moved are
//!    moved back, and history entries above the fork are truncated by height.
//!    Rollback costs the work the orphaned blocks did, not a rescan.
//! 3. **Re-apply.** Walk forward from the fork point through the log's frames.
//!
//! The verification for all of this is in `tests::reorg` and in the
//! `verify-reorg` subcommand, which does it against real chain bytes.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;

use bloch_pos_committee::header::{BlockEnvelope, BlockId as CommitteeBlockId};
use bloch_pos_committee::transition::{PosTransaction, CommittedState, Transition};

use crate::log::LogReader;
use crate::model::*;

/// How many applied blocks' undo records are kept.
///
/// 4,096 is ~315× the deepest reorg measured on this chain (13) and ~2.4
/// hours of blocks at the observed cadence. It is a memory bound, not a
/// statement that a deeper reorg is impossible — a deeper one is handled, by
/// rebuilding.
pub const DEFAULT_UNDO_DEPTH: usize = 4_096;

/// What one applied block changed, in the form that undoes it.
#[derive(Clone, Debug, Default)]
struct Undo {
    /// Outpoints this block created — deleted on rollback.
    created: Vec<OutPoint>,
    /// Outpoints this block spent, with what they held — restored on rollback.
    spent: Vec<(OutPoint, Utxo)>,
    /// Net movement per script hash, in satoshi, signed. Subtracted on
    /// rollback. `i128` because a rollback of a large carried balance must not
    /// wrap, and because the chain's cap is 10^19 sat.
    deltas: Vec<(ScriptHash, i128)>,
    /// Script hashes whose history this block appended to. Rollback truncates
    /// each one to the entries strictly below the fork height.
    touched_history: Vec<ScriptHash>,
    /// Txids this block indexed — removed from the secondary index.
    txids: Vec<Txid>,
    /// (epoch, validator) participation counters this block incremented.
    participation: Vec<(u64, u32, Participation)>,
    /// The epoch row as it stood before this block, so the aggregate is
    /// restored exactly rather than recomputed approximately.
    epoch_before: Option<(u64, Option<EpochRow>)>,
    replay_before: Option<CommittedState>,
}

/// Counters an operator can read to tell whether the index is healthy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub blocks_applied: u64,
    pub blocks_rolled_back: u64,
    pub reorgs_handled: u64,
    pub deepest_reorg: u64,
    pub rebuilds: u64,
    pub undecodable_txs: u64,
}

/// Where and why the index stopped applying the log.
///
/// A block the archival accepted but this binary cannot apply is not a reorg
/// and not an I/O fault: re-reading or rebuilding produces the same refusal,
/// because the consensus rules compiled in here disagree with the chain's.
/// The one cause seen so far is a flag day that this build predates (the
/// native L2 activation at epoch 5850). The index therefore keeps everything
/// up to the last block it could apply, stops, and says so, instead of
/// exiting (a systemd restart loop) or rebuilding from genesis on every poll
/// (tens of minutes of CPU and several GB each time, for the same answer).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Halt {
    /// Height the refused block would have had.
    pub height: u64,
    pub slot: u64,
    pub epoch: u64,
    pub block_id: BlockId,
    pub reason: String,
}

impl Halt {
    pub fn describe(&self) -> String {
        let past_known = match crate::consensus::highest_armed_epoch() {
            Some(e) if self.epoch >= e => format!(
                " Epoch {} is at or past the newest activation gate this build knows (epoch {e}); \
                 a flag day this build predates is the likely cause.",
                self.epoch
            ),
            _ => String::new(),
        };
        format!(
            "halted before height {} (slot {}, epoch {}, block {}): {}.{past_known} Rebuild the \
             indexer from the node release the network runs (bloch-indexer gates shows this \
             build's activation schedule) and restart; the index up to height {} is intact.",
            self.height,
            self.slot,
            self.epoch,
            crate::hex32(&self.block_id),
            self.reason,
            self.height.saturating_sub(1)
        )
    }
}

/// The whole index.
pub struct Index {
    /// The node's selected chain as the index has applied it. `chain[0]` is
    /// genesis, which never appears in `blocks.log`.
    pub chain: Vec<BlockRow>,
    /// Live outputs, keyed exactly as consensus keys them.
    pub utxo: HashMap<OutPoint, Utxo>,
    /// Balance per script hash. `u128`: the supply is 10^19 sat and the
    /// largest carried holder is 3.5×10^17, so `u64` sums would wrap and `f64`
    /// would round — this is the type consensus itself uses for sums.
    pub balance: HashMap<ScriptHash, u128>,
    /// Live outpoints per script hash, so "this address's outputs" is a
    /// lookup and not a scan of the set.
    pub by_script: HashMap<ScriptHash, HashSet<OutPoint>>,
    /// Ordered history per script hash. Entries carry their height, which is
    /// what lets a rollback truncate exactly the orphaned ones.
    pub history: HashMap<ScriptHash, Vec<HistoryEntry>>,
    /// Every transaction, in chain order.
    pub txs: Vec<TxRow>,
    /// Secondary index. A `Vec` because `txid` is not unique for the staking
    /// variants — see `model`'s permalink note.
    pub by_txid: HashMap<Txid, Vec<usize>>,
    /// Where each block's transactions start in `txs`, parallel to `chain`.
    tx_starts: Vec<usize>,
    pub epochs: EpochTable,
    pub participation: BTreeMap<(u64, u32), Participation>,
    /// Newest-last undo records, one per applied block above the retention
    /// floor.
    undo: Vec<Undo>,
    /// Height of `undo[0]`. Below this the journal has nothing and a reorg
    /// forces a rebuild.
    undo_floor: u64,
    undo_depth: usize,
    /// Running totals, kept incrementally so a supply chart does not re-sum
    /// the set per block.
    eutxo_total_sat: u128,
    pub stats: Stats,
    pub all_outputs: HashMap<OutPoint, Utxo>,
    pub spent_at: HashMap<OutPoint, u64>,
    pub replay: Option<CommittedState>,
    pub checked_at: std::time::Instant,
    pub sync_error: Option<String>,
    /// Set when a block could not be applied (see [`Halt`]); cleared by the
    /// next sync that applies the whole log.
    pub halted: Option<Halt>,
    /// Cross-check the index's live-output count against the replayed
    /// consensus state after every block (see `try_apply`). On by default;
    /// switched off only if the opening ledgers already disagree, or by the
    /// operator (`--no-ledger-check`).
    pub ledger_check: bool,
}

impl Index {
    /// A new index seeded with genesis: the block at height 0 and the opening
    /// ledger it commits to.
    ///
    /// `genesis_outputs` is the carryover snapshot plus the manifest's
    /// allocations, each already carrying the outpoint consensus gave it. The
    /// index does not derive those; deriving an opening ledger twice is how a
    /// balance disagrees with the chain it claims to describe.
    pub fn new(
        genesis_id: BlockId,
        genesis_outputs: impl IntoIterator<Item = (OutPoint, Utxo)>,
        undo_depth: usize,
    ) -> Index {
        let mut ix = Index {
            chain: Vec::new(),
            utxo: HashMap::new(),
            balance: HashMap::new(),
            by_script: HashMap::new(),
            history: HashMap::new(),
            txs: Vec::new(),
            by_txid: HashMap::new(),
            tx_starts: Vec::new(),
            epochs: BTreeMap::new(),
            participation: BTreeMap::new(),
            undo: Vec::new(),
            undo_floor: 1,
            undo_depth: undo_depth.max(1),
            eutxo_total_sat: 0,
            stats: Stats::default(),
            all_outputs: HashMap::new(),
            spent_at: HashMap::new(),
            replay: None,
            checked_at: std::time::Instant::now(),
            sync_error: None,
            halted: None,
            ledger_check: true,
        };
        for (op, u) in genesis_outputs {
            ix.eutxo_total_sat += u.value_sat as u128;
            *ix.balance.entry(u.script_hash).or_insert(0) += u.value_sat as u128;
            ix.by_script.entry(u.script_hash).or_default().insert(op);
            ix.all_outputs.insert(op, u.clone());
            ix.history.entry(u.script_hash).or_default().push(HistoryEntry {
                height: 0, slot: 0, block_id: genesis_id, txid: op.txid,
                vout: op.vout, outpoint_txid: op.txid, direction: Direction::In,
                amount_sat: u.value_sat as u128,
            });
            ix.utxo.insert(op, u);
        }
        let count = ix.utxo.len() as u64;
        let total = ix.eutxo_total_sat;
        ix.chain.push(BlockRow {
            block_id: genesis_id,
            parent: [0u8; 32],
            slot: 0,
            epoch: 0,
            height: 0,
            proposer_index: u32::MAX,
            state_root: [0u8; 32],
            body_root: [0u8; 32],
            justified_root: [0u8; 32],
            finalized_root: [0u8; 32],
            tx_count: 0,
            attestation_count: 0,
            frame_len: 0,
            outputs_created_sat: total,
            inputs_spent_sat: 0,
            fees_sat: 0,
            eutxo_total_sat: total,
            eutxo_count: count,
        });
        ix.tx_starts.push(0);
        ix
    }

    /// Exercise rollback and replay against real archived envelopes without
    /// writing the node's log. Called before the read API starts serving.
    pub fn verify_undo_roundtrip(&mut self, reader: &mut LogReader, depth: usize) -> io::Result<()> {
        let depth = depth.min(self.undo.len()).min(self.height() as usize);
        if depth == 0 { return Ok(()); }
        let height = self.height();
        let stats = self.stats;
        let before = (self.utxo.clone(), self.all_outputs.clone(), self.spent_at.clone(),
            self.balance.clone(), self.history.clone(), self.txs.clone(), self.chain.clone());
        self.rollback_to(height - depth as u64);
        for frame in (height as usize - depth)..height as usize {
            let env = reader.envelope_at(frame)?;
            self.try_apply(&env, reader.frames()[frame].len)?;
        }
        if self.utxo != before.0 || self.all_outputs != before.1 || self.spent_at != before.2
            || self.balance != before.3 || self.history != before.4 || self.txs != before.5 || self.chain != before.6 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "undo/replay roundtrip changed indexed data"));
        }
        self.stats = stats;
        eprintln!("verified rollback/replay of {depth} archival blocks; all ledger tables unchanged");
        Ok(())
    }

    pub fn height(&self) -> u64 {
        self.chain.len() as u64 - 1
    }

    pub fn tip(&self) -> &BlockRow {
        self.chain.last().expect("genesis is always present")
    }

    pub fn eutxo_total_sat(&self) -> u128 {
        self.eutxo_total_sat
    }

    /// Balance of one `script_hash`, in satoshi. Zero for a hash the index has
    /// never seen — which is the same answer the node gives, and the reason a
    /// wrong derivation is silent.
    pub fn balance_of(&self, sh: &ScriptHash) -> u128 {
        self.balance.get(sh).copied().unwrap_or(0)
    }

    // ── Sync ────────────────────────────────────────────────────────────────

    /// Bring the index in line with `reader`, handling a reorg if the log has
    /// been rewritten under it.
    ///
    /// Returns `(applied, rolled_back)`.
    pub fn sync(&mut self, reader: &mut LogReader) -> io::Result<(u64, u64)> {
        // The log's `i`th frame is the block at height `i+1`, because genesis
        // is not in the log.
        let frames = reader.frames().to_vec();

        // 1. Detect. Walk both sequences together and find the first
        //    disagreement. Comparing on the block id and not merely on the
        //    slot is what catches the reorg that replaces a block with another
        //    block at the SAME slot — the shape a same-slot equivocation
        //    produces, and the one a slot-only comparison misses entirely.
        let mut agree_upto = 0usize; // number of log frames that match
        while agree_upto < frames.len() && agree_upto + 1 < self.chain.len() {
            let row = &self.chain[agree_upto + 1];
            let fr = frames[agree_upto];
            if row.slot != fr.slot {
                break;
            }
            // Cheap first: slot mismatch settles most cases without a read.
            let hdr = reader.header_at(agree_upto)?;
            if *CommitteeBlockId::of(&hdr).as_bytes() != row.block_id {
                break;
            }
            agree_upto += 1;
        }

        let applied_blocks = self.chain.len() - 1;
        let mut rolled = 0u64;
        if agree_upto < applied_blocks {
            let depth = (applied_blocks - agree_upto) as u64;
            let fork_height = agree_upto as u64; // last height that survives
            if fork_height + 1 < self.undo_floor {
                // The journal does not reach back far enough. Rebuilding is
                // the only honest option: a partial rollback would leave the
                // set holding outputs from blocks that are no longer on the
                // chain, and nothing downstream could tell.
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "reorg of depth {depth} reaches below the undo journal (floor height \
                         {}); rebuild required",
                        self.undo_floor
                    ),
                ));
            }
            self.rollback_to(fork_height);
            rolled = depth;
            self.stats.reorgs_handled += 1;
            self.stats.deepest_reorg = self.stats.deepest_reorg.max(depth);
            self.stats.blocks_rolled_back += depth;
        }

        // 3. Re-apply. A block this build cannot apply halts the index at the
        //    block before it (see `Halt`); the caller decides whether to keep
        //    serving the applied prefix.
        let mut applied = 0u64;
        for i in agree_upto..frames.len() {
            let env = reader.envelope_at(i)?;
            if let Err(e) = self.try_apply(&env, frames[i].len) {
                let halt = Halt {
                    height: self.height() + 1,
                    slot: env.header.slot,
                    epoch: bloch_pos_committee::epoch_of(env.header.slot),
                    block_id: *CommitteeBlockId::of(&env.header).as_bytes(),
                    reason: e.to_string(),
                };
                let msg = halt.describe();
                self.halted = Some(halt);
                return Err(io::Error::new(e.kind(), msg));
            }
            applied += 1;
            if applied % 5000 == 0 { eprintln!("replay: height {} / {}, slot {}", self.height(), frames.len(), self.tip().slot); }
        }
        self.halted = None;
        Ok((applied, rolled))
    }

    // ── Apply ───────────────────────────────────────────────────────────────

    /// Apply one block to the index, recording how to undo it.
    ///
    /// With `replay` initialized (the serving CLI's path), re-execute the state
    /// transition and check the resulting state root before updating tables.
    /// `ArchiveVerifier` skips cryptographic signature verification; this is
    /// state-consistency checking of a trusted archive, not independent node
    /// validation. Fixture callers without replay use bookkeeping alone.
    pub fn apply(&mut self, env: &BlockEnvelope, frame_len: u32) {
        self.try_apply(env, frame_len).expect("valid index block");
    }

    pub fn try_apply(&mut self, env: &BlockEnvelope, frame_len: u32) -> io::Result<()> {
        let decoded: Vec<PosTransaction> = env.body.transactions.iter()
            .map(|raw| PosTransaction::from_canonical_bytes(raw)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("transaction decode: {e:?}"))))
            .collect::<io::Result<_>>()?;
        let mut receipts = Vec::new();
        // Outputs consensus created past the count `created_output_bound`
        // allows for the transaction's kind: (tx index, vout).
        let mut unmodeled_outputs: Vec<(usize, u32)> = Vec::new();
        let all_outputs = &self.all_outputs;
        let post = if let Some(pre) = &self.replay {
            let proposal = bloch_pos_committee::interfaces::ProposalEnvelope {
                header: env.header.clone(), proposer_sig: env.proposer_sig.clone(),
            };
            let post = Transition::new(ArchiveVerifier).compute_post_state_observed(
                pre, &proposal, &env.body.attestations, &decoded, |i, state, charge| {
                    let tx = &decoded[i];
                    let id = tx.txid();
                    let n = created_output_bound(tx);
                    let outputs = (0..n).filter_map(|v| state.utxo(&id, v as u32)
                        .map(|u| (u.value, u.script_hash))).collect::<Vec<_>>();
                    // A new output past the modelled bound means consensus
                    // gave this kind a ledger effect the index does not know.
                    let past = OutPoint { txid: id, vout: n as u32 };
                    if state.utxo(&id, n as u32).is_some() && !all_outputs.contains_key(&past) {
                        unmodeled_outputs.push((i, n as u32));
                    }
                    receipts.push((outputs, charge.base_fee_sat + charge.priority_fee_sat));
                }).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("state replay: {e:?}")))?;
            if bloch_pos_committee::interfaces::StateReader::state_root(&post) != env.header.state_root {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "replayed state root mismatch"));
            }
            Some(post)
        } else { None };
        if let Some(&(i, vout)) = unmodeled_outputs.first() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!(
                "transaction {i} ({}) created output vout {vout}, past what this indexer models for \
                 that kind; balances would drift", kind_of(&decoded[i]).name())));
        }
        // Preflight the complete block before mutating index tables. This also
        // handles a transaction spending an output created earlier in this block.
        let mut staged = HashSet::new();
        let mut consumed = HashSet::new();
        for (i, tx) in decoded.iter().enumerate() {
            let (ins, outs, _, _) = transfer_parts(tx);
            for op in ins {
                if !consumed.insert(op) || (!self.utxo.contains_key(&op) && !staged.contains(&op)) {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "missing or duplicate input"));
                }
            }
            let outs = receipts.get(i).map(|r| &r.0).unwrap_or(&outs);
            for v in 0..outs.len() {
                let op = OutPoint { txid: tx.txid(), vout: v as u32 };
                if self.all_outputs.contains_key(&op) || !staged.insert(op) {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "output collision"));
                }
            }
        }
        // Ledger cross-check: after this block the index will hold
        // `utxo + created - spent` live outputs; consensus says how many it
        // holds. A difference means a transaction spent or created outputs
        // this build does not model (a new kind after a flag day, or a kind
        // whose effect changed). Stop here, loudly, rather than serve
        // balances that are internally consistent and wrong. O(1): the
        // committed set is a `BTreeMap` and its iterator knows its length.
        if let (Some(post), true) = (&post, self.ledger_check) {
            if let (lo, Some(hi)) = post.utxos().size_hint() {
                let predicted = self.utxo.len() + staged.len() - consumed.len();
                if lo == hi && lo != predicted {
                    let kinds: Vec<String> = decoded.iter().map(|t| kind_of(t).name()).collect();
                    return Err(io::Error::new(io::ErrorKind::InvalidData, format!(
                        "ledger drift: consensus holds {lo} live outputs after this block, the index \
                         would hold {predicted}; transaction kinds in the block: [{}]",
                        kinds.join(", "))));
                }
            }
        }
        let h = &env.header;
        let height = self.chain.len() as u64;
        let epoch = bloch_pos_committee::epoch_of(h.slot);
        let block_id = *CommitteeBlockId::of(h).as_bytes();
        let mut undo = Undo::default();
        undo.replay_before = self.replay.take();
        undo.epoch_before = Some((epoch, self.epochs.get(&epoch).cloned()));

        let mut deltas: HashMap<ScriptHash, i128> = HashMap::new();
        let mut created_sat: u128 = 0;
        let mut spent_sat: u128 = 0;
        let tx_start = self.txs.len();

        for (tx_index, raw) in env.body.transactions.iter().enumerate() {
            let tx = &decoded[tx_index];
            let kind = kind_of(tx);
            let txid = tx.txid();

            let mut row = TxRow {
                txid,
                block_id,
                height,
                slot: h.slot,
                tx_index: tx_index as u32,
                kind,
                inputs: Vec::new(),
                input_values: Vec::new(),
                size_bytes: raw.len() as u64,
                stake_sat: match tx {
                    PosTransaction::FundedDeposit(d) => d.amount_sat,
                    PosTransaction::FundedDelegate(d) => d.amount_sat,
                    _ => 0,
                },
                outputs: Vec::new(),
                declared_bytes: 0,
                tip_millisat_per_gas: 0,
                fee_sat: None,
            };

            {
                let (ins, mut outs, declared, tip) = transfer_parts(tx);
                if let Some(receipt) = receipts.get(tx_index) { outs = receipt.0.clone(); }
                row.declared_bytes = declared;
                row.tip_millisat_per_gas = tip;
                row.inputs = ins.clone();
                row.outputs = outs.clone();

                let mut in_sat: u128 = 0;
                let mut all_inputs_valued = true;
                for op in &ins {
                    match self.utxo.remove(op) {
                        Some(prev) => {
                            row.input_values.push(prev.clone());
                            self.spent_at.insert(*op, height);
                            in_sat += prev.value_sat as u128;
                            spent_sat += prev.value_sat as u128;
                            self.eutxo_total_sat -= prev.value_sat as u128;
                            *deltas.entry(prev.script_hash).or_insert(0) -=
                                prev.value_sat as i128;
                            if let Some(set) = self.by_script.get_mut(&prev.script_hash) {
                                set.remove(op);
                            }
                            push_history(
                                &mut self.history,
                                &mut undo.touched_history,
                                prev.script_hash,
                                HistoryEntry {
                                    height,
                                    slot: h.slot,
                                    block_id,
                                    txid,
                                    vout: op.vout,
                                    outpoint_txid: op.txid,
                                    direction: Direction::Out,
                                    amount_sat: prev.value_sat as u128,
                                },
                            );
                            if prev.created_height != height {
                                undo.spent.push((*op, prev));
                            }
                        }
                        None => {
                            // Spending something the index never saw. On a
                            // full index this cannot happen; on one built from
                            // a truncated log it can, and the fee for that
                            // transaction is then unknowable rather than zero.
                            all_inputs_valued = false;
                        }
                    }
                }

                let mut out_sat: u128 = 0;
                for (vout, (value, sh)) in outs.iter().enumerate() {
                    let op = OutPoint { txid, vout: vout as u32 };
                    out_sat += *value as u128;
                    created_sat += *value as u128;
                    self.eutxo_total_sat += *value as u128;
                    *deltas.entry(*sh).or_insert(0) += *value as i128;
                    self.by_script.entry(*sh).or_default().insert(op);
                    self.all_outputs.insert(op, Utxo { value_sat: *value, script_hash: *sh, created_height: height });
                    self.utxo.insert(
                        op,
                        Utxo { value_sat: *value, script_hash: *sh, created_height: height },
                    );
                    push_history(
                        &mut self.history,
                        &mut undo.touched_history,
                        *sh,
                        HistoryEntry {
                            height,
                            slot: h.slot,
                            block_id,
                            txid,
                            vout: op.vout,
                            outpoint_txid: op.txid,
                            direction: Direction::In,
                            amount_sat: *value as u128,
                        },
                    );
                    undo.created.push(op);
                }

                row.fee_sat = if let Some(receipt) = receipts.get(tx_index) { Some(receipt.1) }
                    else if all_inputs_valued { in_sat.checked_sub(out_sat).and_then(|v| v.checked_sub(row.stake_sat)) }
                    else { None };
            }

            self.by_txid.entry(txid).or_default().push(self.txs.len());
            undo.txids.push(txid);
            self.txs.push(row);
        }

        // Balances, applied once per script hash rather than once per output.
        for (sh, d) in deltas {
            let e = self.balance.entry(sh).or_insert(0);
            *e = (*e as i128 + d) as u128;
            if *e == 0 {
                self.balance.remove(&sh);
            }
            undo.deltas.push((sh, d));
        }

        // Attestations: participation, counted both ways.
        let mut bumped: HashMap<(u64, u32), Participation> = HashMap::new();
        for a in &env.body.attestations {
            let key = (a.data.target_epoch, a.validator);
            bumped.entry(key).or_default().attested_target += 1;
            let here = (epoch, a.validator);
            bumped.entry(here).or_default().included_here += 1;
        }
        bumped.entry((epoch, h.proposer_index)).or_default().proposed += 1;
        for (key, add) in bumped {
            let e = self.participation.entry(key).or_default();
            e.attested_target += add.attested_target;
            e.included_here += add.included_here;
            e.proposed += add.proposed;
            undo.participation.push((key.0, key.1, add));
        }

        let row = BlockRow {
            block_id,
            parent: h.parent,
            slot: h.slot,
            epoch,
            height,
            proposer_index: h.proposer_index,
            state_root: h.state_root,
            body_root: h.body_root,
            justified_root: h.justified_root,
            finalized_root: h.finalized_root,
            tx_count: env.body.transactions.len() as u32,
            attestation_count: env.body.attestations.len() as u32,
            frame_len,
            outputs_created_sat: created_sat,
            inputs_spent_sat: spent_sat,
            fees_sat: self.txs[tx_start..].iter().filter_map(|t| t.fee_sat).sum(),
            eutxo_total_sat: self.eutxo_total_sat,
            eutxo_count: self.utxo.len() as u64,
        };

        // Epoch aggregate.
        let er = self.epochs.entry(epoch).or_insert_with(|| EpochRow {
            epoch,
            first_slot: h.slot,
            last_slot: h.slot,
            ..Default::default()
        });
        er.last_slot = h.slot;
        er.blocks += 1;
        er.attestations_included += env.body.attestations.len() as u64;
        er.justified_root = h.justified_root;
        er.finalized_root = h.finalized_root;
        er.eutxo_total_sat = self.eutxo_total_sat;
        er.distinct_proposers = self
            .participation
            .range((epoch, 0)..=(epoch, u32::MAX))
            .filter(|(_, p)| p.proposed > 0)
            .count() as u32;

        self.chain.push(row);
        self.tx_starts.push(tx_start);
        self.undo.push(undo);
        if self.undo.len() > self.undo_depth {
            let drop = self.undo.len() - self.undo_depth;
            self.undo.drain(..drop);
            self.undo_floor += drop as u64;
        }
        self.stats.blocks_applied += 1;
        self.replay = post;
        Ok(())
    }

    // ── Undo ────────────────────────────────────────────────────────────────

    /// Undo every applied block above `height`, newest-first.
    fn rollback_to(&mut self, height: u64) {
        while self.height() > height {
            let undo = self.undo.pop().expect("journal reaches the fork; sync checked the floor");
            let row = self.chain.pop().expect("never pops genesis");

            self.replay = undo.replay_before;
            for op in &undo.created {
                self.all_outputs.remove(op);
                self.spent_at.remove(op);
                if let Some(u) = self.utxo.remove(op) {
                    self.eutxo_total_sat -= u.value_sat as u128;
                    if let Some(s) = self.by_script.get_mut(&u.script_hash) {
                        s.remove(op);
                    }
                }
            }
            for (op, u) in &undo.spent {
                self.spent_at.remove(op);
                self.eutxo_total_sat += u.value_sat as u128;
                self.by_script.entry(u.script_hash).or_default().insert(*op);
                self.utxo.insert(*op, u.clone());
            }
            for (sh, d) in &undo.deltas {
                let e = self.balance.entry(*sh).or_insert(0);
                *e = (*e as i128 - *d) as u128;
                if *e == 0 {
                    self.balance.remove(sh);
                }
            }
            // History entries carry their height, so the orphaned ones are
            // exactly the ones at or above the block being undone. No scan of
            // the whole table: only the hashes this block touched.
            for sh in &undo.touched_history {
                if let Some(v) = self.history.get_mut(sh) {
                    v.retain(|e| e.height < row.height);
                    if v.is_empty() {
                        self.history.remove(sh);
                    }
                }
            }
            for txid in &undo.txids {
                if let Some(v) = self.by_txid.get_mut(txid) {
                    v.retain(|i| *i < self.tx_starts[row.height as usize]);
                    if v.is_empty() {
                        self.by_txid.remove(txid);
                    }
                }
            }
            self.txs.truncate(self.tx_starts[row.height as usize]);
            self.tx_starts.pop();

            for (e, v, add) in &undo.participation {
                if let Some(p) = self.participation.get_mut(&(*e, *v)) {
                    p.attested_target -= add.attested_target;
                    p.included_here -= add.included_here;
                    p.proposed -= add.proposed;
                    if *p == Participation::default() {
                        self.participation.remove(&(*e, *v));
                    }
                }
            }
            if let Some((epoch, before)) = undo.epoch_before {
                match before {
                    Some(r) => {
                        self.epochs.insert(epoch, r);
                    }
                    None => {
                        self.epochs.remove(&epoch);
                    }
                }
            }
            self.undo_floor = self.undo_floor.min(row.height);
        }
    }

    /// Transactions of the block at `height`, as a slice of `txs`.
    pub fn txs_of_height(&self, height: u64) -> &[TxRow] {
        let i = height as usize;
        if i >= self.tx_starts.len() {
            return &[];
        }
        let start = self.tx_starts[i];
        let end = self.tx_starts.get(i + 1).copied().unwrap_or(self.txs.len());
        &self.txs[start..end]
    }

    /// Block row at `height`, if applied.
    pub fn block_at_height(&self, height: u64) -> Option<&BlockRow> {
        self.chain.get(height as usize)
    }

    /// Block row for `slot`. Linear over the chain by design — see
    /// `log::LogReader::frames_after` for why no binary search is assumed —
    /// but backed by a slot map built lazily by the server.
    pub fn block_at_slot(&self, slot: u64) -> Option<&BlockRow> {
        self.chain.iter().find(|r| r.slot == slot)
    }
}

fn push_history(
    table: &mut HashMap<ScriptHash, Vec<HistoryEntry>>,
    touched: &mut Vec<ScriptHash>,
    sh: ScriptHash,
    e: HistoryEntry,
) {
    let v = table.entry(sh).or_default();
    if v.last().map(|l| l.height) != Some(e.height) {
        touched.push(sh);
    } else if !touched.contains(&sh) {
        touched.push(sh);
    }
    v.push(e);
}

fn kind_of(tx: &PosTransaction) -> TxKind {
    match tx {
        PosTransaction::L2Settlement(_) => TxKind::L2Settlement,
        PosTransaction::L2SettlementAsync(_) => TxKind::L2SettlementAsync,
        PosTransaction::L2Deposit(_) => TxKind::L2Deposit,
        PosTransaction::L2DataAvailability(_) => TxKind::L2DataAvailability,
        PosTransaction::L2WithdrawClaim(_) => TxKind::L2WithdrawClaim,
        PosTransaction::Transfer { .. } => TxKind::Transfer,
        PosTransaction::TransferV2 { .. } => TxKind::TransferV2,
        PosTransaction::Deposit { .. } => TxKind::Deposit,
        PosTransaction::Exit { .. } => TxKind::Exit,
        PosTransaction::Delegate { .. } => TxKind::Delegate,
        PosTransaction::FundedDeposit(_) => TxKind::FundedDeposit,
        PosTransaction::FundedDelegate(_) => TxKind::FundedDelegate,
        PosTransaction::FundedUndelegate(_) => TxKind::FundedUndelegate,
        PosTransaction::FundedDelegationWithdraw(_) => TxKind::FundedDelegationWithdraw,
        PosTransaction::ValidatorCommissionUpdate(_) => TxKind::ValidatorCommissionUpdate,
        PosTransaction::Withdraw { .. } => TxKind::Withdraw,
        PosTransaction::ExitV2 { .. } => TxKind::ExitV2,
        PosTransaction::RandaoRecommit { .. } => TxKind::RandaoRecommit,
        PosTransaction::SlashingEvidence(_) => TxKind::SlashingEvidence,
    }
}

/// The four fields both transfer encodings share, flattened.
///
/// V1 and V2 are the same logical transfer with the witnesses arranged
/// differently — the signing root, and therefore the txid and every created
/// outpoint, is byte-identical between them. So the index treats them
/// identically here and records which encoding it was in `TxKind`, rather than
/// having two nearly-identical apply paths that could drift.
fn transfer_parts(tx: &PosTransaction) -> (Vec<OutPoint>, Vec<(u64, ScriptHash)>, u64, u128) {
    match tx {
        PosTransaction::Transfer { inputs, outputs, tx_bytes, tip_millisat_per_gas } => (
            inputs.iter().map(|i| OutPoint { txid: i.txid, vout: i.vout }).collect(),
            outputs.iter().map(|o| (o.value, o.script_hash)).collect(),
            *tx_bytes,
            *tip_millisat_per_gas,
        ),
        PosTransaction::TransferV2 { inputs, outputs, tx_bytes, tip_millisat_per_gas, .. } => (
            inputs.iter().map(|i| OutPoint { txid: i.txid, vout: i.vout }).collect(),
            outputs.iter().map(|o| (o.value, o.script_hash)).collect(),
            *tx_bytes,
            *tip_millisat_per_gas,
        ),
        PosTransaction::FundedDeposit(d) => (
            d.inputs.iter().map(|i| OutPoint { txid: i.txid, vout: i.vout }).collect(),
            vec![(d.change.value, d.change.script_hash)], d.tx_bytes, d.tip_millisat_per_gas,
        ),
        PosTransaction::FundedDelegate(d) => (
            d.inputs.iter().map(|i| OutPoint { txid: i.txid, vout: i.vout }).collect(),
            vec![(d.change.value, d.change.script_hash)], d.tx_bytes, d.tip_millisat_per_gas,
        ),
        // Native L2 bridge transactions spend funding UTXOs and create
        // eUTXOs like a transfer does. The escrowed deposit amount leaves the
        // spendable set (it is L2 inbox state, not an output). Replay
        // receipts replace these declared outputs with the outputs consensus
        // actually created.
        PosTransaction::L2Deposit(d) => (
            d.inputs.iter().map(|i| OutPoint { txid: i.txid, vout: i.vout }).collect(),
            nonzero_change(d.change.value, d.change.script_hash), d.tx_bytes, d.tip_millisat_per_gas,
        ),
        PosTransaction::L2DataAvailability(d) => (
            d.inputs.iter().map(|i| OutPoint { txid: i.txid, vout: i.vout }).collect(),
            nonzero_change(d.change.value, d.change.script_hash), d.tx_bytes, d.tip_millisat_per_gas,
        ),
        PosTransaction::L2WithdrawClaim(c) => {
            let mut outs = vec![(c.sats, c.l1_recipient)];
            outs.extend(nonzero_change(c.change.value, c.change.script_hash));
            (
                c.inputs.iter().map(|i| OutPoint { txid: i.txid, vout: i.vout }).collect(),
                outs, c.tx_bytes, c.tip_millisat_per_gas,
            )
        }
        // No eUTXO inputs. Withdraw-style payouts (FundedDelegationWithdraw,
        // Withdraw) create an output that only consensus can value; it comes
        // from the replay receipt (`created_output_bound`).
        //
        // NO wildcard arm. A new transaction kind must be classified here
        // (does it spend eUTXOs? which?) before the indexer compiles; the
        // flag-day checklist in docs/BLOCH-INDEXER.md says how.
        PosTransaction::L2Settlement(_)
        | PosTransaction::L2SettlementAsync(_)
        | PosTransaction::FundedUndelegate(_)
        | PosTransaction::FundedDelegationWithdraw(_)
        | PosTransaction::ValidatorCommissionUpdate(_)
        | PosTransaction::Deposit { .. }
        | PosTransaction::Exit { .. }
        | PosTransaction::Delegate { .. }
        | PosTransaction::Withdraw { .. }
        | PosTransaction::ExitV2 { .. }
        | PosTransaction::RandaoRecommit { .. }
        | PosTransaction::SlashingEvidence(_) => (Vec::new(), Vec::new(), 0, 0),
    }
}

/// How many outputs (vout `0..n`) consensus can create for one transaction of
/// this kind. Replay reads exactly these back from the post-state; anything
/// at vout `n` is reported as unmodelled. NO wildcard arm, for the same
/// reason as `transfer_parts`.
fn created_output_bound(tx: &PosTransaction) -> usize {
    match tx {
        PosTransaction::Transfer { outputs, .. } | PosTransaction::TransferV2 { outputs, .. } => outputs.len(),
        PosTransaction::FundedDeposit(_)
        | PosTransaction::FundedDelegate(_)
        | PosTransaction::FundedDelegationWithdraw(_)
        | PosTransaction::Withdraw { .. } => 1,
        // Native L2 bridge: change at vout 0 (deposit, DA); release at vout 0
        // and change at vout 1 (claim).
        PosTransaction::L2Deposit(_) | PosTransaction::L2DataAvailability(_) => 1,
        PosTransaction::L2WithdrawClaim(_) => 2,
        PosTransaction::L2Settlement(_)
        | PosTransaction::L2SettlementAsync(_)
        | PosTransaction::FundedUndelegate(_)
        | PosTransaction::ValidatorCommissionUpdate(_)
        | PosTransaction::Deposit { .. }
        | PosTransaction::Exit { .. }
        | PosTransaction::Delegate { .. }
        | PosTransaction::ExitV2 { .. }
        | PosTransaction::RandaoRecommit { .. }
        | PosTransaction::SlashingEvidence(_) => 0,
    }
}

fn nonzero_change(value: u64, script_hash: ScriptHash) -> Vec<(u64, ScriptHash)> {
    if value > 0 { vec![(value, script_hash)] } else { Vec::new() }
}

struct ArchiveVerifier;
impl bloch_pos_committee::attestation::SignatureVerifier for ArchiveVerifier {
    fn verify_with_key(&self, key: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
        bloch_crypto::crypto::verify(key, root, signature)
    }
    fn verify_with_key_under(
        &self,
        policy: bloch_pos_committee::attestation::SignaturePolicy,
        key: &[u8],
        root: &[u8; 32],
        signature: &[u8],
    ) -> bool {
        use bloch_crypto::crypto::SignaturePolicy as C;
        use bloch_pos_committee::attestation::SignaturePolicy as P;
        let policy = match policy {
            P::Compatible => C::Compatible,
            P::CompatiblePinned => C::CompatiblePinned,
            P::CanonicalUnbound => C::CanonicalUnbound,
            P::Bound => C::Bound,
        };
        bloch_crypto::crypto::verify_with_policy(policy, key, root, signature)
    }
}
