//! Bloch-SIS Protocol — Storage (RocksDB)

pub mod indexer;

use rocksdb::{DB, Options, ColumnFamilyDescriptor, IteratorMode};
use std::path::Path;
use crate::core::{Block, TxOutput};
use crate::consensus::{BlockHash, GhostdagData};

const CF_BLOCKS:     &str = "blocks";
const CF_UTXO:       &str = "utxo";
const CF_DAG:        &str = "dag";
const CF_BLUE_SCORE: &str = "blue_score";
const CF_META:       &str = "meta";
const CF_HEIGHT:     &str = "height";
const CF_TIMESTAMPS: &str = "timestamps";
const CF_ADDR_UTXO:  &str = "addr_utxo";  // address index: [20B addr][32B txid][4B idx] → empty
const CF_COINBASE:   &str = "coinbase";    // txid → height (for maturity check)
const CF_TX_INDEX:   &str = "tx_index";    // txid → [32B block_hash][8B height]
const CF_ADDR_TX_HISTORY: &str = "addr_tx_history";  // addr → chronological tx touches
const CF_UNDO:       &str = "undo";        // Sprint U.1: per-block undo data for reorg rollback
const CF_DAG_INTEGRITY: &str = "dag_integrity";  // Sprint Y (M-2): hash-chain over GhostdagData
const CF_REACHABILITY: &str = "reachability";    // Phase 1: durable interval-reachability index (non-consensus cache)

// ── PoBRS Column Families (Sprint 1.5) ─────────────────────────────────
// Persistence layer for the Proof-of-Blue-and-Red-Score subsystem.
// All keys use big-endian for u64/u32 to preserve lexicographic ordering
// on RocksDB iterators. Schema version stored in CF_POBRS_META.
pub(crate) const CF_POBRS_META:                &str = "pobrs_meta";                // key: ascii string  | value: bincode
pub(crate) const CF_POBRS_ORACLES:             &str = "pobrs_oracles";             // key: oracle_id 1B  | value: OracleRecord
pub(crate) const CF_POBRS_ORACLES_BY_PK:       &str = "pobrs_oracles_by_pk";       // key: pk 48B        | value: oracle_id 1B
pub(crate) const CF_POBRS_ORACLE_SNAPSHOTS:    &str = "pobrs_oracle_snapshots";    // key: height 8B BE  | value: OracleSetSnapshot (every 100 blocks)
pub(crate) const CF_POBRS_ORACLE_EVENTS:       &str = "pobrs_oracle_events";       // key: height 8B BE + seq 4B BE | value: OracleEvent
pub(crate) const CF_POBRS_ATTESTATIONS:        &str = "pobrs_attestations";        // key: wallet_hash 32B          | value: AttestationCore
pub(crate) const CF_POBRS_ATTESTATIONS_EXTRA:  &str = "pobrs_attestations_extra";  // key: wallet_hash 32B          | value: AttestationExtra
pub(crate) const CF_POBRS_ATTESTATION_HISTORY: &str = "pobrs_attestation_history"; // key: wallet_hash 32B + block 8B BE | value: AttestationCore
pub(crate) const CF_POBRS_MODELS:              &str = "pobrs_models";              // key: model_id 4B BE           | value: ModelRecord
pub(crate) const CF_POBRS_MODEL_PENDING:       &str = "pobrs_model_pending";       // key: update_id 8B BE         | value: PendingModelUpdate
pub(crate) const CF_POBRS_DISPUTES:            &str = "pobrs_disputes";            // key: wallet_hash 32B          | value: DisputeRecord
pub(crate) const CF_POBRS_TEE_PLATFORMS:       &str = "pobrs_tee_platforms";       // key: platform_byte 1B         | value: PlatformInfo

// ── Bonding CFs (Sprint 2.1.D, ADR-007 §4.7) ─────────────────────────────
pub(crate) const CF_BONDING_META:      &str = "bonding_meta";       // ascii string keys → bincode (schema_version, next_bond_id)
pub(crate) const CF_BONDING_REGISTRY:  &str = "bonding_registry";   // BondId 8B BE        → BondRecord (Day β)
pub(crate) const CF_BONDING_BY_UID:    &str = "bonding_by_uid";     // OperatorUid 32B     → BondId 8B BE
pub(crate) const CF_BONDING_BY_PUBKEY: &str = "bonding_by_pk";      // BlsPubkey 48B       → BondId 8B BE
pub(crate) const CF_BONDING_HISTORY:   &str = "bonding_history";    // BondId 8B BE        → Vec<SlashEvent>
pub(crate) const CF_PARTICIPATION:     &str = "participation";      // (epoch 8B BE, bond_id 8B BE) → ParticipationRecord

// ── FFG Column Families (Sprint 2.1) ───────────────────────────────────
// Persistence layer for the Friendly Finality Gadget committee subsystem.
// Schema version stored in CF_FFG_META.
pub(crate) const CF_FFG_META:                 &str = "ffg_meta";                 // key: ascii string  | value: u32 LE / bincode
pub(crate) const CF_FFG_COMMITTEE:            &str = "ffg_committee";            // key: epoch 8B BE   | value: bincode(Committee)
pub(crate) const CF_FFG_PENDING_COMMITTEE:    &str = "ffg_pending_committee";    // key: dkg_epoch 8B BE | value: bincode(PendingCommittee)

/// PoBRS schema version. Bumped when key/value layout changes incompatibly.
/// Stored as `CF_POBRS_META["schema_version"] = u32 LE`.
pub const POBRS_SCHEMA_VERSION: u32 = 1;

fn encode<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, StorageError> {
    bincode::serde::encode_to_vec(v, bincode::config::standard())
        .map_err(|e| StorageError::SerializeFailed(e.to_string()))
}

pub fn decode<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, StorageError> {
    bincode::serde::decode_from_slice(b, bincode::config::standard())
        .map(|(v, _)| v)
        .map_err(|e| StorageError::DeserializeFailed(e.to_string()))
}

pub struct Storage { db: DB }

impl Storage {
    /// Build the full column-family descriptor list. Shared by the read-write
    /// [`open`] and the read-only [`open_read_only`] paths so both agree on the
    /// exact schema (CF names + per-CF options) — the read-only replay harness
    /// must decode CF_DAG with the identical layout the node wrote.
    fn cf_descriptors() -> Vec<ColumnFamilyDescriptor> {
        let mut addr_utxo_opts = Options::default();
        addr_utxo_opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(20));
        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_BLOCKS,     Options::default()),
            ColumnFamilyDescriptor::new(CF_UTXO,       Options::default()),
            ColumnFamilyDescriptor::new(CF_DAG,        Options::default()),
            ColumnFamilyDescriptor::new(CF_BLUE_SCORE, Options::default()),
            ColumnFamilyDescriptor::new(CF_META,       Options::default()),
            ColumnFamilyDescriptor::new(CF_HEIGHT,     Options::default()),
            ColumnFamilyDescriptor::new(CF_TIMESTAMPS, Options::default()),
            ColumnFamilyDescriptor::new(CF_ADDR_UTXO,  addr_utxo_opts),
            ColumnFamilyDescriptor::new(CF_COINBASE,   Options::default()),
            ColumnFamilyDescriptor::new(CF_TX_INDEX,   Options::default()),
            {
                let mut opts = Options::default();
                opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(20));
                ColumnFamilyDescriptor::new(CF_ADDR_TX_HISTORY, opts)
            },
            ColumnFamilyDescriptor::new(CF_UNDO,       Options::default()),
            ColumnFamilyDescriptor::new(CF_DAG_INTEGRITY, Options::default()),
            // Phase 1: durable reachability index. Key = 32B block hash,
            // value = encode_record() bytes. A rebuildable cache, never part of
            // the integrity chain; see docs/adr/ADR-035-durable-reachability-index.md.
            ColumnFamilyDescriptor::new(CF_REACHABILITY, Options::default()),
            // ── PoBRS CFs (Sprint 1.5) ─────────────────────────────
            ColumnFamilyDescriptor::new(CF_POBRS_META,                Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_ORACLES,             Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_ORACLES_BY_PK,       Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_ORACLE_SNAPSHOTS,    Options::default()),
            {
                // Event log: prefix by height (8B) for efficient range scans
                let mut opts = Options::default();
                opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(8));
                ColumnFamilyDescriptor::new(CF_POBRS_ORACLE_EVENTS, opts)
            },
            ColumnFamilyDescriptor::new(CF_POBRS_ATTESTATIONS,        Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_ATTESTATIONS_EXTRA,  Options::default()),
            {
                // Attestation history: prefix by wallet_hash (32B)
                let mut opts = Options::default();
                opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(32));
                ColumnFamilyDescriptor::new(CF_POBRS_ATTESTATION_HISTORY, opts)
            },
            ColumnFamilyDescriptor::new(CF_POBRS_MODELS,              Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_MODEL_PENDING,       Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_DISPUTES,            Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_TEE_PLATFORMS,       Options::default()),
            // ── Bonding CFs (Sprint 2.1.D, ADR-007 §4.7) ────────────
            ColumnFamilyDescriptor::new(CF_BONDING_META,      Options::default()),
            ColumnFamilyDescriptor::new(CF_BONDING_REGISTRY,  Options::default()),
            ColumnFamilyDescriptor::new(CF_BONDING_BY_UID,    Options::default()),
            ColumnFamilyDescriptor::new(CF_BONDING_BY_PUBKEY, Options::default()),
            ColumnFamilyDescriptor::new(CF_BONDING_HISTORY,   Options::default()),
            ColumnFamilyDescriptor::new(CF_PARTICIPATION,     Options::default()),
            // ── FFG CFs (Sprint 2.1) ───────────────────────────────
            ColumnFamilyDescriptor::new(CF_FFG_META,                  Options::default()),
            ColumnFamilyDescriptor::new(CF_FFG_COMMITTEE,             Options::default()),
            ColumnFamilyDescriptor::new(CF_FFG_PENDING_COMMITTEE,     Options::default()),
        ];
        cfs
    }

    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_max_open_files(256);
        opts.set_write_buffer_size(64 * 1024 * 1024);
        let db = DB::open_cf_descriptors(&opts, path, Self::cf_descriptors())
            .map_err(|e| StorageError::OpenFailed(e.to_string()))?;
        Ok(Self { db })
    }

    /// Open an existing snapshot **read-only**. RocksDB is opened with
    /// `open_cf_descriptors_read_only`, which acquires no write lock, creates
    /// nothing, and rejects every mutating call — so a live node can keep the
    /// same data-dir open while this handle inspects it. Used by the GhostDAG
    /// differential replay harness (`tests/ghostdag_replay_snapshot.rs`) to read
    /// CF_DAG without any risk of touching mined history.
    ///
    /// `path` is the node data-dir (the same directory passed to [`open`]).
    /// The DB must already exist; this never creates column families.
    pub fn open_read_only(path: &Path) -> Result<Self, StorageError> {
        let opts = Options::default();
        // `error_if_log_file_exist = false`: tolerate a live/unclean WAL so we
        // can inspect a running node's dir. Read-only mode never replays into or
        // mutates the primary.
        let db = DB::open_cf_descriptors_read_only(&opts, path, Self::cf_descriptors(), false)
            .map_err(|e| StorageError::OpenFailed(e.to_string()))?;
        Ok(Self { db })
    }

    /// Returns a reference to the underlying RocksDB instance. Used by
    /// `PobrsStorage` (Sprint 1.5 L2) to share the same DB connection
    /// without owning it. Safe because RocksDB handles internal concurrency.
    pub fn db(&self) -> &DB {
        &self.db
    }

    /// Write a block and all of its derived index rows atomically.
    ///
    /// P0 crash-consistency (roadmap §3.2): previously this issued 4+ separate
    /// `put_cf` calls (block body, height→hash, timestamp, per-tx address
    /// index). A crash between any two left height→hash pointing at a block
    /// body that wasn't there, or an un-indexed block. All writes now go
    /// through a single RocksDB `WriteBatch` committed with one `db.write`, so
    /// either the whole block lands or none of it does. Keys/values/CFs are
    /// byte-identical to the old path — this is a durability fix only, not a
    /// schema or wire change.
    pub fn put_block(&self, block: &Block) -> Result<(), StorageError> {
        let hash = block.block_hash();
        let cf_b = self.db.cf_handle(CF_BLOCKS).ok_or(StorageError::CfNotFound(CF_BLOCKS.into()))?;
        let cf_h = self.db.cf_handle(CF_HEIGHT).ok_or(StorageError::CfNotFound(CF_HEIGHT.into()))?;
        let cf_t = self.db.cf_handle(CF_TIMESTAMPS).ok_or(StorageError::CfNotFound(CF_TIMESTAMPS.into()))?;
        let cf_ai = self.db.cf_handle(CF_ADDR_TX_HISTORY).ok_or(StorageError::CfNotFound(CF_ADDR_TX_HISTORY.into()))?;

        let mut batch = rocksdb::WriteBatch::default();

        // Sprint 1.b: Bitcoin-format wire serialization (replaces pre-v0.6.0 bincode).
        // Block bytes on disk are now byte-identical to the canonical network
        // wire format, so a future direct-from-disk broadcast path can skip
        // re-encoding. Consensus-breaking; existing v0.5.x RocksDB data-dirs
        // are unreadable at v0.6.0+ and must be reset.
        batch.put_cf(&cf_b, &hash, &block.to_bitcoin_bytes());
        batch.put_cf(&cf_h, &block.height.to_be_bytes(), &hash);
        batch.put_cf(&cf_t, &block.height.to_be_bytes(), &block.header.timestamp.to_le_bytes());

        // Sprint F: index address touches for each tx in this block. These were
        // previously best-effort (errors ignored). Folding them into the same
        // batch keeps the same entries but makes them crash-consistent with the
        // block body. An entry-computation error for one tx skips only that tx's
        // rows (matching the old best-effort semantics) rather than aborting.
        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            match self.addr_index_entries(tx, block.height, tx_idx as u32) {
                Ok(entries) => {
                    for (key, val) in entries {
                        batch.put_cf(&cf_ai, &key, &val);
                    }
                }
                Err(e) => log::warn!("addr-index skipped for tx {}: {}", tx_idx, e),
            }
        }

        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        Ok(())
    }

    pub fn get_block(&self, hash: &[u8; 32]) -> Result<Option<Block>, StorageError> {
        let cf = self.db.cf_handle(CF_BLOCKS).ok_or(StorageError::CfNotFound(CF_BLOCKS.into()))?;
        match self.db.get_cf(&cf, hash).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) => Ok(Some(
                Block::from_bitcoin_bytes(&d)
                    .map_err(StorageError::DeserializeFailed)?
            )),
            None    => Ok(None),
        }
    }

    pub fn get_block_hash_at_height(&self, height: u64) -> Result<Option<[u8; 32]>, StorageError> {
        let cf = self.db.cf_handle(CF_HEIGHT).ok_or(StorageError::CfNotFound(CF_HEIGHT.into()))?;
        match self.db.get_cf(&cf, &height.to_be_bytes()).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) if d.len() == 32 => { let mut h = [0u8;32]; h.copy_from_slice(&d); Ok(Some(h)) }
            _ => Ok(None),
        }
    }

    pub fn get_timestamp_at_height(&self, height: u64) -> Result<Option<u64>, StorageError> {
        let cf = self.db.cf_handle(CF_TIMESTAMPS).ok_or(StorageError::CfNotFound(CF_TIMESTAMPS.into()))?;
        match self.db.get_cf(&cf, &height.to_be_bytes()).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) if d.len() == 8 => Ok(Some(u64::from_le_bytes(d[..8].try_into().unwrap()))),
            _ => Ok(None),
        }
    }

    pub fn put_utxo(&self, txid: &[u8], index: u32, output: &TxOutput) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let key = utxo_key(txid, index);
        self.db.put_cf(&cf, &key, &encode(output)?)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))?;

        // Address index: key = [20B address][32B txid][4B index], value = empty
        if output.script_pubkey.len() >= 20 {
            let cf_ai = self.db.cf_handle(CF_ADDR_UTXO).ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
            let ai_key = addr_utxo_key(&output.script_pubkey, txid, index);
            self.db.put_cf(&cf_ai, &ai_key, &[])
                .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        }
        Ok(())
    }

    pub fn get_utxo(&self, txid: &[u8], index: u32) -> Result<Option<TxOutput>, StorageError> {
        let cf = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        match self.db.get_cf(&cf, &utxo_key(txid, index)).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) => Ok(Some(decode(&d)?)),
            None    => Ok(None),
        }
    }

    pub fn iter_all_blocks(&self) -> Vec<([u8; 32], crate::core::Block)> {
        let mut results = Vec::new();
        if let Some(cf) = self.db.cf_handle(CF_BLOCKS) {
            let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
            for item in iter {
                if let Ok((key, val)) = item {
                    if key.len() == 32 {
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&key);
                        // Sprint 1.b: Bitcoin-format decode (replaces bincode).
                        if let Ok(block) = crate::core::Block::from_bitcoin_bytes(&val) {
                            results.push((hash, block));
                        }
                    }
                }
            }
        }
        results
    }

    /// Iterate the entire UTXO set in DETERMINISTIC order for snapshotting.
    ///
    /// Returns `(txid, vout, value, script_pubkey)` sorted by the raw CF_UTXO key,
    /// which is `txid ‖ vout_be` — so the order is a pure function of the set's
    /// contents, independent of insertion history, RocksDB compaction state, or
    /// which node produced it. Two honest nodes at the same height MUST produce
    /// byte-identical output; that is what makes a commitment over this meaningful.
    ///
    /// Why this exists: block bodies below `pruned_height` are deleted (see
    /// [`Self::prune_blocks_below`]) but the UTXO set is retained in full. On this
    /// fleet in 2026-07 that left ~95% of history unservable while every balance
    /// stayed intact and queryable — so the SET is recoverable even when the CHAIN
    /// that produced it is not. A snapshot taken here is the carry-over artifact
    /// for any migration, and the input to an assumeutxo-style bootstrap for fresh
    /// nodes that cannot sync from genesis because no archival peer has the bodies.
    ///
    /// Read-only friendly: pair with [`Self::open_read_only`] to snapshot a data-dir
    /// while the node keeps running on it.
    pub fn iter_utxos_sorted(&self) -> Result<Vec<(Vec<u8>, u32, u64, Vec<u8>)>, StorageError> {
        let cf = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let mut out: Vec<(Vec<u8>, u32, u64, Vec<u8>)> = Vec::new();
        for item in self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
            let (key, val) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            // key = txid ‖ vout (4B BE); anything else is not ours — skip rather
            // than guess, so a malformed row can never silently enter a commitment.
            if key.len() < 36 { continue; }
            let txid = key[..key.len() - 4].to_vec();
            let vout = u32::from_be_bytes([key[key.len()-4], key[key.len()-3],
                                           key[key.len()-2], key[key.len()-1]]);
            // Same codec every other UTXO read in this file uses — never a
            // second decoder, or a snapshot could disagree with the node that
            // produced it while both look correct.
            let output: TxOutput = match decode::<TxOutput>(&val) {
                Ok(o)  => o,
                Err(_) => continue,
            };
            out.push((txid, vout, output.value, output.script_pubkey));
        }
        // RocksDB already yields keys in byte order; sort explicitly so the
        // guarantee is in THIS function rather than in an engine detail.
        out.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        Ok(out)
    }

    pub fn clear_utxos(&self) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let mut batch = rocksdb::WriteBatch::default();
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        for item in iter {
            if let Ok((key, _)) = item { batch.delete_cf(&cf, &key); }
        }
        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        Ok(())
    }

    pub fn delete_utxo(&self, txid: &[u8], index: u32) -> Result<(), StorageError> {
        // Fetch the UTXO first to get the address for index cleanup
        let cf = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        if let Some(data) = self.db.get_cf(&cf, &utxo_key(txid, index))
            .map_err(|e| StorageError::ReadFailed(e.to_string()))?
        {
            if let Ok(output) = decode::<TxOutput>(&data) {
                if output.script_pubkey.len() >= 20 {
                    let cf_ai = self.db.cf_handle(CF_ADDR_UTXO).ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
                    let _ = self.db.delete_cf(&cf_ai, &addr_utxo_key(&output.script_pubkey, txid, index));
                }
            }
        }
        self.db.delete_cf(&cf, &utxo_key(txid, index)).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// O(k) balance query via address index (was O(n) full UTXO scan)
    pub fn get_balance(&self, address_bytes: &[u8]) -> Result<(u64, usize), StorageError> {
        if address_bytes.len() < 20 {
            return Ok((0, 0)); // invalid address length
        }
        let cf_ai = self.db.cf_handle(CF_ADDR_UTXO).ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
        let cf_utxo = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let prefix = address_bytes.to_vec();

        let (mut total, mut count) = (0u64, 0usize);
        let iter = self.db.prefix_iterator_cf(&cf_ai, &prefix);
        for item in iter {
            if let Ok((k, _)) = item {
                // Stop when prefix no longer matches
                if k.len() < address_bytes.len() || &k[..address_bytes.len()] != address_bytes { break; }
                // Extract txid + index from key: [20B addr][32B txid][4B idx]
                let expected_len = address_bytes.len() + 36;
                if k.len() == expected_len {
                    let utxo_k = k[address_bytes.len()..expected_len].to_vec(); // 32B txid + 4B index
                    if let Some(v) = self.db.get_cf(&cf_utxo, &utxo_k)
                        .map_err(|e| StorageError::ReadFailed(e.to_string()))?
                    {
                        if let Ok(out) = decode::<TxOutput>(&v) {
                            total = total.saturating_add(out.value);
                            count += 1;
                        }
                    }
                }
            }
        }
        Ok((total, count))
    }

    /// Count distinct addresses that currently hold at least one UTXO — i.e.
    /// the number of on-chain "wallets" with a non-zero balance. Iterates
    /// CF_ADDR_UTXO whose keys are `[20B addr][32B txid][4B idx]`; the distinct
    /// 20-byte address prefixes are the wallets. Also returns the total UTXO
    /// entry count. O(n) over the UTXO-address index.
    pub fn count_addresses_with_balance(&self) -> Result<(usize, usize), StorageError> {
        let cf_ai = self.db.cf_handle(CF_ADDR_UTXO)
            .ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
        let mut set = std::collections::HashSet::<[u8; 20]>::new();
        let mut utxos = 0usize;
        for item in self.db.iterator_cf(&cf_ai, IteratorMode::Start) {
            if let Ok((k, _)) = item {
                if k.len() >= 20 {
                    let mut addr = [0u8; 20];
                    addr.copy_from_slice(&k[..20]);
                    set.insert(addr);
                    utxos += 1;
                }
            }
        }
        Ok((set.len(), utxos))
    }

    /// O(k) UTXO lookup via address index (was O(n) full UTXO scan)
    pub fn get_utxos_for_address(&self, address_bytes: &[u8]) -> Result<Vec<(Vec<u8>, u32, TxOutput)>, StorageError> {
        if address_bytes.len() < 20 {
            return Ok(vec![]);
        }
        let cf_ai = self.db.cf_handle(CF_ADDR_UTXO).ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
        let cf_utxo = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let prefix = address_bytes.to_vec();

        let mut result = Vec::new();
        let iter = self.db.prefix_iterator_cf(&cf_ai, &prefix);
        for item in iter {
            if let Ok((k, _)) = item {
                let alen = address_bytes.len();
                if k.len() < alen || &k[..alen] != address_bytes { break; }
                let expected = alen + 36;
                if k.len() == expected {
                    let txid = k[alen..alen+32].to_vec();
                    let idx = u32::from_le_bytes(k[alen+32..expected].try_into().unwrap());
                    let utxo_k = k[alen..expected].to_vec();
                    if let Some(v) = self.db.get_cf(&cf_utxo, &utxo_k)
                        .map_err(|e| StorageError::ReadFailed(e.to_string()))?
                    {
                        if let Ok(out) = decode::<TxOutput>(&v) {
                            result.push((txid, idx, out));
                        }
                    }
                }
            }
        }
        Ok(result)
    }

    // ── DAG persistence ─────────────────────────────────────────────────────

    /// Persist GhostDAG data for a single block
    pub fn put_dag_data(&self, hash: &BlockHash, data: &GhostdagData) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_DAG).ok_or(StorageError::CfNotFound(CF_DAG.into()))?;
        self.db.put_cf(&cf, hash, &encode(data)?)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Load GhostDAG data for a single block
    pub fn get_dag_data(&self, hash: &BlockHash) -> Result<Option<GhostdagData>, StorageError> {
        let cf = self.db.cf_handle(CF_DAG).ok_or(StorageError::CfNotFound(CF_DAG.into()))?;
        match self.db.get_cf(&cf, hash).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) => Ok(Some(decode(&d)?)),
            None    => Ok(None),
        }
    }

    // ── Sprint Y (M-2): GhostdagData integrity chain ──────────────────
    //
    // See `src/consensus/mod.rs::canonical_encode` and
    // `compute_integrity_hash` for the chain definition, and
    // `GhostDAG::load_persisted_validated` for the verifier.
    //
    // `put_dag_with_integrity` is the preferred write path: it looks up
    // the parent's integrity hash, computes this block's integrity, and
    // writes both CF_DAG and CF_DAG_INTEGRITY in a single WriteBatch so
    // they can never drift out of sync.
    //
    // The plain `put_dag_data` above is kept for backwards compatibility
    // and for call sites that have already computed integrity themselves.

    /// Persist GhostDAG data AND its integrity hash atomically.
    /// Returns the computed integrity hash (useful for logging / chaining).
    pub fn put_dag_with_integrity(
        &self,
        hash: &BlockHash,
        data: &GhostdagData,
    ) -> Result<[u8; 32], StorageError> {
        // 1. Parent lookup. Genesis uses all-zero parent integrity —
        //    matches the chain base convention in `load_persisted_validated`.
        let parent_integrity: [u8; 32] = match &data.selected_parent {
            Some(sp) => self.get_integrity_hash(sp)?.unwrap_or([0u8; 32]),
            None     => [0u8; 32],
        };

        // 2. Compute this block's chain link.
        let integrity = crate::consensus::compute_integrity_hash(hash, data, &parent_integrity);

        // 3. Atomic write. WriteBatch guarantees either both CFs are
        //    updated or neither, even if the process is killed mid-write.
        let cf_dag = self.db.cf_handle(CF_DAG)
            .ok_or(StorageError::CfNotFound(CF_DAG.into()))?;
        let cf_int = self.db.cf_handle(CF_DAG_INTEGRITY)
            .ok_or(StorageError::CfNotFound(CF_DAG_INTEGRITY.into()))?;

        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(&cf_dag, hash, &encode(data)?);
        batch.put_cf(&cf_int, hash, &integrity);
        self.db.write(batch)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))?;

        Ok(integrity)
    }

    /// Read a single block's integrity hash. `Ok(None)` if absent —
    /// the caller distinguishes between "pre-Sprint-Y database" (all
    /// absent) and "targeted deletion" (some absent) at load time.
    pub fn get_integrity_hash(&self, hash: &BlockHash) -> Result<Option<[u8; 32]>, StorageError> {
        let cf = self.db.cf_handle(CF_DAG_INTEGRITY)
            .ok_or(StorageError::CfNotFound(CF_DAG_INTEGRITY.into()))?;
        match self.db.get_cf(&cf, hash).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(b) if b.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&b);
                Ok(Some(out))
            }
            Some(_) => Err(StorageError::DeserializeFailed(
                "CF_DAG_INTEGRITY entry has wrong length (not 32 bytes)".into()
            )),
            None => Ok(None),
        }
    }

    /// Persist an integrity hash directly. Used by `load_persisted_validated`
    /// during the self-heal migration from pre-Sprint-Y databases.
    pub fn put_integrity_hash(
        &self,
        hash: &BlockHash,
        integrity: &[u8; 32],
    ) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_DAG_INTEGRITY)
            .ok_or(StorageError::CfNotFound(CF_DAG_INTEGRITY.into()))?;
        self.db.put_cf(&cf, hash, integrity)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Load every (block_hash → integrity_hash) record from CF_DAG_INTEGRITY.
    /// Returns an empty map on a pre-Sprint-Y database; the caller treats
    /// that as "self-heal on first boot".
    pub fn load_all_integrity_hashes(
        &self,
    ) -> Result<std::collections::HashMap<BlockHash, [u8; 32]>, StorageError> {
        let cf = self.db.cf_handle(CF_DAG_INTEGRITY)
            .ok_or(StorageError::CfNotFound(CF_DAG_INTEGRITY.into()))?;
        let mut map = std::collections::HashMap::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            if let Ok((k, v)) = item {
                if k.len() == 32 && v.len() == 32 {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&k);
                    let mut i = [0u8; 32];
                    i.copy_from_slice(&v);
                    map.insert(h, i);
                }
            }
        }
        Ok(map)
    }

    /// Load all persisted DAG data for full reconstruction on startup.
    /// Returns (hash, data) pairs in insertion order is NOT guaranteed —
    /// caller must handle topological insertion.
    pub fn load_all_dag_data(&self) -> Result<Vec<(BlockHash, GhostdagData)>, StorageError> {
        let cf = self.db.cf_handle(CF_DAG).ok_or(StorageError::CfNotFound(CF_DAG.into()))?;
        let mut entries = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            if let Ok((k, v)) = item {
                if k.len() == 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&k);
                    if let Ok(data) = decode::<GhostdagData>(&v) {
                        entries.push((hash, data));
                    }
                }
            }
        }
        Ok(entries)
    }

    // ── Durable reachability index (Phase 1) ────────────────────────────
    //
    // The interval-reachability index (`consensus::reachability::ReachabilityStore`)
    // is an O(1)/O(log n) DAG-ancestry cache. It is NOT consensus state — it is
    // never hashed into the integrity chain and can always be rebuilt by
    // replaying CF_DAG. To make it durable (and avoid an O(chain) rebuild every
    // boot) its per-block records live in CF_REACHABILITY, and — crucially —
    // each record delta is written in the SAME WriteBatch as the CF_DAG block it
    // derives from (`put_dag_with_integrity_and_reach`), so a crash can never
    // leave the index describing a block CF_DAG doesn't have, or vice-versa.
    //
    // The layout version + root live in CF_META under `reachability/meta/*`.

    /// Schema version for the CF_REACHABILITY record layout, mirrored from
    /// `consensus::reachability::REACHABILITY_RECORD_VERSION`. On boot a
    /// mismatch (or absent tag) forces a full rebuild from CF_DAG.
    pub const REACHABILITY_SCHEMA_VERSION: u32 =
        crate::consensus::reachability::REACHABILITY_RECORD_VERSION;

    /// Atomic CF_DAG + CF_DAG_INTEGRITY + CF_REACHABILITY write.
    ///
    /// Identical to [`put_dag_with_integrity`] for the DAG/integrity CFs, but
    /// additionally folds the reachability delta (`reach_upserts` /
    /// `reach_removals`, drained from `ReachabilityStore::take_persist_delta`)
    /// into the SAME `WriteBatch`. All-or-nothing: after a crash the block, its
    /// integrity link, and every reachability record touched by inserting it
    /// either all landed or none did.
    ///
    /// Used only when the reachability index is being maintained (Fast /
    /// armed-activation). On the live Legacy path the caller uses the plain
    /// [`put_dag_with_integrity`] and CF_REACHABILITY stays empty.
    pub fn put_dag_with_integrity_and_reach(
        &self,
        hash: &BlockHash,
        data: &GhostdagData,
        reach_upserts: &[(BlockHash, Vec<u8>)],
        reach_removals: &[BlockHash],
    ) -> Result<[u8; 32], StorageError> {
        let parent_integrity: [u8; 32] = match &data.selected_parent {
            Some(sp) => self.get_integrity_hash(sp)?.unwrap_or([0u8; 32]),
            None     => [0u8; 32],
        };
        let integrity = crate::consensus::compute_integrity_hash(hash, data, &parent_integrity);

        let cf_dag = self.db.cf_handle(CF_DAG)
            .ok_or(StorageError::CfNotFound(CF_DAG.into()))?;
        let cf_int = self.db.cf_handle(CF_DAG_INTEGRITY)
            .ok_or(StorageError::CfNotFound(CF_DAG_INTEGRITY.into()))?;
        let cf_reach = self.db.cf_handle(CF_REACHABILITY)
            .ok_or(StorageError::CfNotFound(CF_REACHABILITY.into()))?;

        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(&cf_dag, hash, &encode(data)?);
        batch.put_cf(&cf_int, hash, &integrity);
        for (h, rec) in reach_upserts {
            batch.put_cf(&cf_reach, h, rec);
        }
        for h in reach_removals {
            batch.delete_cf(&cf_reach, h);
        }
        self.db.write(batch)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        Ok(integrity)
    }

    /// Persist a full reachability snapshot + its version tag + root in one
    /// batch. Used after a boot-time rebuild to write the freshly-materialized
    /// index. Clears any stale records first so the CF exactly mirrors memory.
    pub fn store_reachability_snapshot(
        &self,
        records: &[(BlockHash, Vec<u8>)],
        root: Option<BlockHash>,
    ) -> Result<(), StorageError> {
        let cf_reach = self.db.cf_handle(CF_REACHABILITY)
            .ok_or(StorageError::CfNotFound(CF_REACHABILITY.into()))?;
        let cf_meta = self.db.cf_handle(CF_META)
            .ok_or(StorageError::CfNotFound(CF_META.into()))?;
        let mut batch = rocksdb::WriteBatch::default();
        // Wipe existing records (rebuild replaces the whole index).
        for item in self.db.iterator_cf(&cf_reach, IteratorMode::Start) {
            if let Ok((k, _)) = item { batch.delete_cf(&cf_reach, &k); }
        }
        for (h, rec) in records {
            batch.put_cf(&cf_reach, h, rec);
        }
        batch.put_cf(&cf_meta, b"reachability/meta/version",
                     &Self::REACHABILITY_SCHEMA_VERSION.to_le_bytes());
        match root {
            Some(r) => batch.put_cf(&cf_meta, b"reachability/meta/root", &r),
            None    => batch.delete_cf(&cf_meta, b"reachability/meta/root"),
        }
        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Load every persisted `(block_hash, record_bytes)` from CF_REACHABILITY.
    pub fn load_all_reachability(&self) -> Result<Vec<(BlockHash, Vec<u8>)>, StorageError> {
        let cf = self.db.cf_handle(CF_REACHABILITY)
            .ok_or(StorageError::CfNotFound(CF_REACHABILITY.into()))?;
        let mut out = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            if let Ok((k, v)) = item {
                if k.len() == 32 {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&k);
                    out.push((h, v.to_vec()));
                }
            }
        }
        Ok(out)
    }

    /// Read the persisted reachability schema version, if present.
    pub fn get_reachability_version(&self) -> Result<Option<u32>, StorageError> {
        Ok(self.get_meta("reachability/meta/version")?
            .and_then(|b| b.as_slice().try_into().ok().map(u32::from_le_bytes)))
    }

    /// Read the persisted reachability root (genesis) hash, if present.
    pub fn get_reachability_root(&self) -> Result<Option<BlockHash>, StorageError> {
        Ok(self.get_meta("reachability/meta/root")?
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()))
    }

    // ── Coinbase maturity tracking (FIX VULN-03) ────────────────────────

    /// Record that a txid is a coinbase transaction created at the given height.
    pub fn put_coinbase_info(&self, txid: &[u8; 32], height: u64) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_COINBASE).ok_or(StorageError::CfNotFound(CF_COINBASE.into()))?;
        self.db.put_cf(&cf, txid, &height.to_le_bytes())
            .map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Get the height at which a coinbase transaction was created.
    /// Returns None if the txid is not a coinbase.
    pub fn get_coinbase_height(&self, txid: &[u8; 32]) -> Result<Option<u64>, StorageError> {
        let cf = self.db.cf_handle(CF_COINBASE).ok_or(StorageError::CfNotFound(CF_COINBASE.into()))?;
        match self.db.get_cf(&cf, txid).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) if d.len() == 8 => Ok(Some(u64::from_le_bytes(d[..8].try_into().unwrap()))),
            _ => Ok(None),
        }
    }

    /// Sprint U.2 — Remove a coinbase-info record. Used by rollback_block to
    /// unmark a coinbase whose creating block was reverted out of the chain.
    /// Idempotent: deleting a missing record is not an error.
    pub fn delete_coinbase_info(&self, txid: &[u8; 32]) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_COINBASE).ok_or(StorageError::CfNotFound(CF_COINBASE.into()))?;
        self.db.delete_cf(&cf, txid).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    // ── Transaction index (O(1) tx lookup) ────────────────────────────

    /// Index a transaction: txid → (block_hash, block_height)
    pub fn put_tx_index(&self, txid: &[u8; 32], block_hash: &[u8; 32], height: u64) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_TX_INDEX).ok_or(StorageError::CfNotFound(CF_TX_INDEX.into()))?;
        let mut val = Vec::with_capacity(40);
        val.extend_from_slice(block_hash);
        val.extend_from_slice(&height.to_le_bytes());
        self.db.put_cf(&cf, txid, &val).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Lookup transaction location: returns (block_hash, block_height)
    pub fn get_tx_location(&self, txid: &[u8; 32]) -> Result<Option<([u8; 32], u64)>, StorageError> {
        let cf = self.db.cf_handle(CF_TX_INDEX).ok_or(StorageError::CfNotFound(CF_TX_INDEX.into()))?;
        match self.db.get_cf(&cf, txid).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) if d.len() == 40 => {
                let mut bh = [0u8; 32];
                bh.copy_from_slice(&d[..32]);
                let height = u64::from_le_bytes(d[32..40].try_into().unwrap());
                Ok(Some((bh, height)))
            }
            _ => Ok(None),
        }
    }

    /// Sprint U.2 — Remove a tx_index entry. Used by rollback_block to unpoint
    /// a txid away from a block that's being reverted. Idempotent.
    pub fn delete_tx_index(&self, txid: &[u8; 32]) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_TX_INDEX).ok_or(StorageError::CfNotFound(CF_TX_INDEX.into()))?;
        self.db.delete_cf(&cf, txid).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    pub fn put_meta(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        self.db.put_cf(&cf, key.as_bytes(), value).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        self.db.get_cf(&cf, key.as_bytes()).map_err(|e| StorageError::ReadFailed(e.to_string()))
    }

    // ── Sprint U.1: Undo data for reorg rollback ─────────────────────────
    //
    // Each accepted block writes one UndoData record keyed by block hash.
    // Sprint U.2 will add rollback_block() which reads it; Sprint U.3 will
    // prune records whose block has dropped below finalized_height.

    /// Persist the undo record for a block. Should be called once per block,
    /// immediately after all UTXO/index mutations for that block complete.
    pub fn put_undo_data(&self, block_hash: &[u8; 32], data: &crate::core::UndoData)
        -> Result<(), StorageError>
    {
        let cf = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        self.db.put_cf(&cf, block_hash, &encode(data)?)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Fetch the undo record for a block. Returns Ok(None) if the block was
    /// accepted before U.1 landed, or if its undo record has been pruned.
    pub fn get_undo_data(&self, block_hash: &[u8; 32])
        -> Result<Option<crate::core::UndoData>, StorageError>
    {
        let cf = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        match self.db.get_cf(&cf, block_hash).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) => Ok(Some(decode(&d)?)),
            None    => Ok(None),
        }
    }

    /// Remove an undo record. Called when the block has passed the finality
    /// window and can no longer be part of a reorg candidate chain.
    pub fn delete_undo_data(&self, block_hash: &[u8; 32]) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        self.db.delete_cf(&cf, block_hash).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Sprint U.2 — Reverse every mutation recorded in the block's UndoData.
    ///
    /// This is the storage-level primitive the reorg logic (U.3) will call for
    /// each block of the losing chain, in tip-toward-LCA order. It is purely
    /// about rolling back **state** (UTXO set, tx index, coinbase index,
    /// address indices, undo record itself) — it deliberately does NOT touch:
    ///
    ///   - CF_BLOCKS, CF_HEIGHT, CF_TIMESTAMPS: the block still exists as a
    ///     known DAG node; U.3 repoints selected-chain membership, not block
    ///     knowledge.
    ///   - CF_DAG: GhostDAG metadata for the block stays valid.
    ///   - Mempool: caller's job to re-inject invalidated txs if desired.
    ///
    /// # Order of operations (reversed from accept_block, with rationale)
    ///
    ///   1. Un-index addr_tx_history — needs the block body + spent lookup
    ///      from UndoData, both still intact at this point.
    ///   2. Restore spent UTXOs via put_utxo — also repopulates CF_ADDR_UTXO.
    ///   3. Delete created UTXOs via delete_utxo — also cleans CF_ADDR_UTXO.
    ///   4. Delete coinbase_info entries.
    ///   5. Delete tx_index entries.
    ///   6. Delete the UndoData record itself — final step, marks rollback
    ///      as complete and prevents accidental re-rollback.
    ///
    /// # Errors
    ///
    /// Returns Err if the undo record is missing or if the block body is
    /// missing. These are abnormal conditions: an accepted-post-U.1 block
    /// should always have both. In practice U.3 should never attempt to
    /// rollback a block outside the finality window where undo records have
    /// been pruned.
    ///
    /// Individual inner ops use `let _ =` for idempotent sub-operations: if
    /// a delete target was never present (e.g. intra-block chains that
    /// weren't indexed) the rollback still makes progress rather than
    /// aborting halfway through.
    ///
    /// # Returns
    ///
    /// The `UndoData` that was applied, so callers can, e.g., re-inject
    /// invalidated transactions into the mempool or emit reorg events.
    pub fn rollback_block(&self, block_hash: &[u8; 32])
        -> Result<crate::core::UndoData, StorageError>
    {
        // 1. Load the undo record. Missing record = nothing to roll back;
        //    treat as error so caller can distinguish "already rolled back"
        //    (or "pre-U.1 block we can't roll back") from success.
        let hash_prefix = format!(
            "{:02x}{:02x}{:02x}{:02x}..",
            block_hash[0], block_hash[1], block_hash[2], block_hash[3]
        );
        let undo = self.get_undo_data(block_hash)?
            .ok_or_else(|| StorageError::ReadFailed(format!(
                "rollback_block: no undo data for block {}",
                hash_prefix
            )))?;

        // 2. Load the block body — needed for addr_tx_history unindex, which
        //    walks every transaction. Also serves as a sanity check that the
        //    block we're rolling back actually exists in storage.
        let block = self.get_block(block_hash)?
            .ok_or_else(|| StorageError::ReadFailed(format!(
                "rollback_block: block body missing for {}",
                hash_prefix
            )))?;

        // 3. Build a lookup from (prev_txid, prev_index) → spent TxOutput so
        //    unindex_tx_addresses can resolve input addresses without going
        //    through get_utxo_including_spent (which becomes stale as we
        //    mutate the UTXO set below).
        let mut spent_lookup: std::collections::HashMap<([u8; 32], u32), TxOutput> =
            std::collections::HashMap::with_capacity(undo.spent_utxos.len());
        for entry in &undo.spent_utxos {
            spent_lookup.insert((entry.prev_txid, entry.prev_index), entry.output.clone());
        }

        // 4. Un-index addr_tx_history (must run BEFORE UTXO mutations —
        //    see doc comment on ordering above).
        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            // Best-effort: log on failure but keep going. A partial unindex
            // is still better than aborting mid-rollback.
            if let Err(e) = self.unindex_tx_addresses(
                tx, block.height, tx_idx as u32, &spent_lookup
            ) {
                log::warn!(
                    "rollback_block h={}: addr_tx_history unindex failed for tx {}: {}",
                    block.height, tx_idx, e
                );
            }
        }

        // 5. Restore spent UTXOs. put_utxo also rewrites the CF_ADDR_UTXO
        //    entry, so we don't have to handle that column family manually.
        for entry in &undo.spent_utxos {
            let _ = self.put_utxo(&entry.prev_txid, entry.prev_index, &entry.output);
        }

        // 6. Delete created UTXOs. delete_utxo also removes the CF_ADDR_UTXO
        //    entry if present.
        for (txid, idx) in &undo.created_utxo_keys {
            let _ = self.delete_utxo(txid, *idx);
        }

        // 7. Delete coinbase-info entries for any coinbase txs this block
        //    introduced. A reverted coinbase must not be treated as mature
        //    by downstream validation.
        for txid in &undo.coinbase_txids {
            let _ = self.delete_coinbase_info(txid);
        }

        // 8. Delete tx_index entries. After rollback the txid is no longer
        //    locatable at this block — either the tx will land in a replacement
        //    block (and get re-indexed there by accept_block) or it reverts
        //    to the mempool.
        for txid in &undo.tx_index_keys {
            let _ = self.delete_tx_index(txid);
        }

        // 9. Finally, delete the undo record itself. Must be last: if any
        //    earlier step erred after we deleted this first, the caller
        //    would have no way to retry or to introspect the record.
        self.delete_undo_data(block_hash)?;

        Ok(undo)
    }

    // ── Pruning ─────────────────────────────────────────────────────────

    /// Prune block bodies below `below_height`.
    /// Keeps: height→hash mapping, DAG data, TX index, UTXO set.
    /// Removes: full block data from CF_BLOCKS (saves ~90% of storage).
    /// Returns number of blocks pruned.
    pub fn prune_blocks_below(&self, below_height: u64) -> Result<usize, StorageError> {
        let cf_blocks = self.db.cf_handle(CF_BLOCKS).ok_or(StorageError::CfNotFound(CF_BLOCKS.into()))?;
        let cf_height = self.db.cf_handle(CF_HEIGHT).ok_or(StorageError::CfNotFound(CF_HEIGHT.into()))?;
        let mut pruned = 0usize;

        for h in 0..below_height {
            let key = h.to_be_bytes();
            if let Some(hash_bytes) = self.db.get_cf(&cf_height, &key)
                .map_err(|e| StorageError::ReadFailed(e.to_string()))?
            {
                // Only prune if block data exists
                if self.db.get_cf(&cf_blocks, &hash_bytes)
                    .map_err(|e| StorageError::ReadFailed(e.to_string()))?.is_some()
                {
                    self.db.delete_cf(&cf_blocks, &hash_bytes)
                        .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
                    pruned += 1;
                }
            }
        }

        if pruned > 0 {
            self.put_meta("pruned_height", &below_height.to_le_bytes())?;
        }
        Ok(pruned)
    }

    /// Get the height below which blocks have been pruned
    pub fn pruned_height(&self) -> u64 {
        self.get_meta("pruned_height").ok().flatten()
            .and_then(|b| b.as_slice().try_into().ok().map(u64::from_le_bytes))
            .unwrap_or(0)
    }

    /// Sprint F: get block timestamp by height (used by listtransactions RPC).
    pub fn get_block_timestamp_at_height(&self, height: u64) -> Result<Option<u64>, StorageError> {
        let cf = self.db.cf_handle(CF_TIMESTAMPS).ok_or(StorageError::CfNotFound(CF_TIMESTAMPS.into()))?;
        match self.db.get_cf(&cf, &height.to_be_bytes()).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) if d.len() == 8 => Ok(Some(u64::from_le_bytes(d.try_into().unwrap()))),
            _ => Ok(None),
        }
    }

    /// Sprint F: get tip height (highest block number).
    pub fn get_tip_height(&self) -> Result<u64, StorageError> {
        let cf = self.db.cf_handle(CF_HEIGHT).ok_or(StorageError::CfNotFound(CF_HEIGHT.into()))?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::End);
        for item in iter {
            let (k, _) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if k.len() == 8 {
                return Ok(u64::from_be_bytes(k.as_ref().try_into().unwrap()));
            }
        }
        Ok(0)
    }

    // ── Genesis-2 carry-over ingestion ──────────────────────────────────────

    /// Write a FULLY-VERIFIED carry-over snapshot into the UTXO set, in one
    /// atomic `WriteBatch`. Callers MUST obtain `snap` from
    /// [`verify_carryover_snapshot`] — that is the only constructor — so by the
    /// time this runs, root, count and supply have all matched the CARRYOVER_*
    /// constants. Nothing is written on any earlier failure ("no partial
    /// ingestion: verify fully, then write").
    ///
    /// The same batch stamps `meta["carryover_root"]`, so a later boot can
    /// prove ingestion happened (and against WHICH root) without re-reading
    /// the file. UTXOs and marker land together or not at all.
    /// Re-derive the carry-over root FROM THE DATABASE and compare it to the
    /// constant this binary was built with.
    ///
    /// The `carryover_root` meta stamp records what a FILE hashed to at ingest
    /// time. It says nothing about what the database contains now, and cannot:
    /// it is a copied string. A data-dir handed out as a "fast bootstrap"
    /// tarball would therefore run an arbitrary ledger while logging the
    /// reassuring "carry-over already ingested (matches d3de5e51…)".
    ///
    /// That is the exact trust this migration exists to remove — a chain nobody
    /// has to take on faith — so re-opening it one layer down would defeat the
    /// point. This function reads every live UTXO back out, rebuilds the
    /// snapshot's canonical lines in the same sorted order, hashes them, and
    /// returns what the set ACTUALLY hashes to.
    ///
    /// Cost is a full scan, so it is a deliberate `--verify-carryover` run
    /// rather than something every boot pays for.
    pub fn derive_carryover_root(&self) -> Result<([u8; 32], u64, u128), StorageError> {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let rows = self.iter_utxos_sorted()?;
        let mut hasher = sha3::Shake256::default();
        let mut total: u128 = 0;
        for (txid, vout, value, spk) in &rows {
            // Byte-identical to what bloch-snapshot-utxo writes, or the roots
            // could not be compared at all.
            let line = format!("{}\t{}\t{}\t{}\n",
                hex::encode(txid), vout, value, hex::encode(spk));
            Update::update(&mut hasher, line.as_bytes());
            total += *value as u128;
        }
        let mut reader = hasher.finalize_xof();
        let mut root = [0u8; 32];
        reader.read(&mut root);
        Ok((root, rows.len() as u64, total))
    }

    pub fn ingest_carryover(&self, snap: &CarryoverSnapshot) -> Result<u64, StorageError> {
        let cf_utxo = self.db.cf_handle(CF_UTXO)
            .ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let cf_ai = self.db.cf_handle(CF_ADDR_UTXO)
            .ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
        let cf_meta = self.db.cf_handle(CF_META)
            .ok_or(StorageError::CfNotFound(CF_META.into()))?;

        let mut batch = rocksdb::WriteBatch::default();
        for (txid, vout, output) in &snap.entries {
            batch.put_cf(&cf_utxo, utxo_key(txid, *vout), encode(output)?);
            // Address index — same shape put_utxo maintains, so balance and
            // wallet queries see carried-over coins like any mined coin.
            if output.script_pubkey.len() >= 20 {
                batch.put_cf(&cf_ai, addr_utxo_key(&output.script_pubkey, txid, *vout), [0u8; 0]);
            }
        }
        batch.put_cf(&cf_meta, b"carryover_root", snap.root);
        batch.put_cf(&cf_meta, b"carryover_source_height",
                     crate::core::CARRYOVER_SOURCE_HEIGHT.to_le_bytes());
        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        Ok(snap.entries.len() as u64)
    }
}

/// A carry-over snapshot that has passed EVERY check in
/// [`verify_carryover_snapshot`]. Field access is public for logging; the only
/// way to construct one outside this module is through verification.
#[derive(Debug)]
pub struct CarryoverSnapshot {
    entries: Vec<(Vec<u8>, u32, TxOutput)>,
    pub root: [u8; 32],
    pub count: u64,
    pub total_sat: u128,
}

/// Verify a carry-over file against the chain's baked-in CARRYOVER_* constants.
///
/// Two layers: [`parse_carryover_file`] enforces the structural invariants that
/// hold for ANY snapshot, then this compares the result to what THIS chain
/// requires. Fail closed — returns every mismatch, and nothing is written here.
pub fn verify_carryover_snapshot(path: &Path) -> Result<CarryoverSnapshot, Vec<String>> {
    use crate::core::{CARRYOVER_SNAPSHOT_ROOT, CARRYOVER_UTXO_COUNT, CARRYOVER_TOTAL_SAT};
    let snap = parse_carryover_file(path)?;
    let mut failures = Vec::new();
    if snap.root != CARRYOVER_SNAPSHOT_ROOT {
        failures.push(format!("root mismatch: file hashes to {} but this chain requires {} \
            (SHAKE-256 over raw bytes; any edit, truncation or reordering changes it)",
            hex::encode(snap.root), hex::encode(CARRYOVER_SNAPSHOT_ROOT)));
    }
    if snap.count != CARRYOVER_UTXO_COUNT {
        failures.push(format!("utxo count mismatch: file has {} line(s), chain requires {}",
            snap.count, CARRYOVER_UTXO_COUNT));
    }
    if snap.total_sat != CARRYOVER_TOTAL_SAT {
        failures.push(format!("total supply mismatch: file sums to {} sat, chain requires {} \
            (difference {} sat)", snap.total_sat, CARRYOVER_TOTAL_SAT,
            snap.total_sat as i128 - CARRYOVER_TOTAL_SAT as i128));
    }
    if failures.is_empty() { Ok(snap) } else { Err(failures) }
}

/// Structural parse of a carry-over file: every invariant that holds for ANY
/// snapshot, independent of which chain it is destined for.
///
/// Split out from [`verify_carryover_snapshot`] because that function compares
/// against the baked-in CARRYOVER_* constants, so it can only ever succeed for
/// one exact file. That made the structural rules — unique outpoints, no
/// zero-value rows, well-formed lines, the byte-root — untestable except against
/// the production snapshot, which is a poor way to protect invariants that must
/// hold for every future one too.
///
/// Returns the parsed set with its root, or the full list of structural
/// failures. Says nothing about whether this is the RIGHT ledger — that is the
/// caller's comparison against the constants.
pub fn parse_carryover_file(path: &Path) -> Result<CarryoverSnapshot, Vec<String>> {
    parse_carryover_inner(path)
}

impl CarryoverSnapshot {
    /// Number of parsed entries. Distinct from [`Self::count`], which is what the
    /// chain REQUIRES — comparing the two is the count check, so a test that
    /// asserts on this is asserting on what the file actually held.
    pub fn entry_count(&self) -> usize { self.entries.len() }
}

/// Verify a Genesis-2 carry-over snapshot file against the baked-in
/// CARRYOVER_* constants (bloch-crypto core). Fail closed: returns the FULL
/// list of mismatches so the operator sees every specific failure, and nothing
/// is ever written here — ingestion ([`Storage::ingest_carryover`]) only
/// accepts the value this function returns on success.
///
/// Checks, all of them always evaluated (no short-circuit):
///   1. SHAKE-256 over the file's RAW BYTES == CARRYOVER_SNAPSHOT_ROOT.
///      The bytes are hashed exactly as given — deliberately NO sorting or
///      normalisation: a reordered file has a different root and is rejected,
///      because "same set, different order" is indistinguishable from
///      tampering once the commitment is over the byte stream.
///   2. line count == CARRYOVER_UTXO_COUNT.
///   3. summed output value == CARRYOVER_TOTAL_SAT.
///   plus: every line must parse as `txid_hex \t vout \t value_sat \t spk_hex`
///   with a 32-byte txid — a malformed line is a failure, never skipped.
fn parse_carryover_inner(path: &Path) -> Result<CarryoverSnapshot, Vec<String>> {
    use sha3::digest::{Update, ExtendableOutput, XofReader};

    let bytes = match std::fs::read(path) {
        Ok(b)  => b,
        Err(e) => return Err(vec![format!("cannot read {}: {e}", path.display())]),
    };

    // Check 1: root over raw bytes.
    let mut hasher = sha3::Shake256::default();
    Update::update(&mut hasher, &bytes);
    let mut root = [0u8; 32];
    XofReader::read(&mut hasher.finalize_xof(), &mut root);

    let mut failures: Vec<String> = Vec::new();

    // Checks 2 + 3: count and supply over the same bytes, in file order.
    let mut segments: Vec<&[u8]> = bytes.split(|&b| b == b'\n').collect();
    if segments.last().is_some_and(|s| s.is_empty()) {
        segments.pop(); // trailing newline, not an empty record
    }
    let mut entries: Vec<(Vec<u8>, u32, TxOutput)> = Vec::with_capacity(segments.len());
    let mut total_sat: u128 = 0;
    let mut malformed: u64 = 0;
    // Outpoints must be DISTINCT. The count check is line-based and the supply
    // check is value-based, so a file that duplicates one line over another of
    // equal value passes both — and ingest would then collapse the two into one
    // key, writing FEWER UTXOs than it reports. The log line "N UTXOs written
    // atomically" would be false, and the ledger short by one output, with two
    // of the three checks having approved it.
    let mut seen: std::collections::HashSet<(Vec<u8>, u32)> = std::collections::HashSet::with_capacity(segments.len());
    let mut duplicates: u64 = 0;
    for (i, seg) in segments.iter().enumerate() {
        match parse_carryover_line(seg) {
            Some((txid, vout, output)) => {
                if !seen.insert((txid.clone(), vout)) {
                    duplicates += 1;
                    if duplicates <= 5 {
                        failures.push(format!("line {} duplicates outpoint {}:{} — \
                            outpoints must be unique", i + 1, hex::encode(&txid), vout));
                    }
                    continue;
                }
                total_sat += output.value as u128;
                entries.push((txid, vout, output));
            }
            None => {
                malformed += 1;
                if malformed <= 5 {
                    failures.push(format!("line {} is malformed (want \
                        txid_hex\\tvout\\tvalue_sat\\tspk_hex, 32-byte txid)", i + 1));
                }
            }
        }
    }
    if malformed > 5 {
        failures.push(format!("... and {} more malformed line(s)", malformed - 5));
    }
    if duplicates > 5 {
        failures.push(format!("... and {} more duplicated outpoint(s)", duplicates - 5));
    }
    let count = (entries.len() as u64) + malformed; // every line counts toward shape

    if failures.is_empty() {
        Ok(CarryoverSnapshot { entries, root, count, total_sat })
    } else {
        Err(failures)
    }
}

/// One snapshot line: `txid_hex \t vout \t value_sat \t script_pubkey_hex`.
/// Exactly four fields; 32-byte txid. Anything else is None (malformed).
fn parse_carryover_line(line: &[u8]) -> Option<(Vec<u8>, u32, TxOutput)> {
    let s = std::str::from_utf8(line).ok()?;
    let mut it = s.split('\t');
    let txid = hex::decode(it.next()?).ok()?;
    let vout: u32 = it.next()?.parse().ok()?;
    let value: u64 = it.next()?.parse().ok()?;
    let script_pubkey = hex::decode(it.next()?).ok()?;
    if it.next().is_some() || txid.len() != 32 { return None; }
    // A zero-value output is not a spendable UTXO and never appears in a
    // snapshot this node produced. Accepting one lets a tampered file add rows
    // that pass BOTH the count and the supply checks — they change the line
    // count while adding nothing to the total — leaving the byte-root as the
    // only thing standing between a forged ledger and ingestion. Refuse.
    if value == 0 { return None; }
    Some((txid, vout, TxOutput { value, script_pubkey }))
}

fn utxo_key(txid: &[u8], index: u32) -> Vec<u8> {
    let mut k = txid.to_vec(); k.extend_from_slice(&index.to_le_bytes()); k
}

/// Address index key: [20B address][32B txid][4B index] = 56 bytes
fn addr_utxo_key(address: &[u8], txid: &[u8], index: u32) -> Vec<u8> {
    let mut k = Vec::with_capacity(56);
    k.extend_from_slice(address);
    k.extend_from_slice(txid);
    k.extend_from_slice(&index.to_le_bytes());
    k
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("open: {0}")]        OpenFailed(String),
    #[error("cf: {0}")]          CfNotFound(String),
    #[error("serialize: {0}")]   SerializeFailed(String),
    #[error("deserialize: {0}")] DeserializeFailed(String),
    #[error("write: {0}")]       WriteFailed(String),
    #[error("read: {0}")]        ReadFailed(String),
}

impl From<rocksdb::Error> for StorageError {
    fn from(e: rocksdb::Error) -> Self { StorageError::ReadFailed(e.to_string()) }
}

// Sprint F — tests for address history indexer and related RPCs.
// (appended from scaffold; // instead of //! because this is not a module root)

#[cfg(test)]
mod sprint_f_tests {
    use super::*;
    use crate::core::{Block, BlockHeader, Transaction, TxInput, TxOutput};
    use crate::storage::indexer::{make_key, make_value, parse_key, parse_value, DIR_IN, DIR_OUT, ENTRY_SIZE};
    use tempfile::TempDir;

    fn mk_storage() -> (TempDir, Storage) {
        let tmp = TempDir::new().unwrap();
        let s = Storage::open(tmp.path()).unwrap();
        (tmp, s)
    }

    fn dummy_addr(byte: u8) -> [u8; 20] {
        [byte; 20]
    }

    fn mk_output(addr_byte: u8, value: u64) -> TxOutput {
        TxOutput {
            value,
            script_pubkey: vec![addr_byte; 20],
        }
    }

    fn mk_tx_coinbase(addr_byte: u8, value: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0u8; 32],
                prev_index: 0xffffffff,
                script_sig: b"height:1".to_vec(),
                sequence: 0xffffffff,
            }],
            outputs: vec![mk_output(addr_byte, value)],
            locktime: 0,
        }
    }

    #[test]
    fn key_value_encoding_roundtrip() {
        let addr = dummy_addr(0x42);
        let txid = [0x99u8; 32];

        let k = make_key(&addr, 100, 5, 2);
        let v = make_value(&txid, DIR_OUT, 1_000_000_000);

        assert_eq!(k.len(), 36);
        assert_eq!(v.len(), ENTRY_SIZE);

        let (pa, ph, pti, pii) = parse_key(&k).unwrap();
        assert_eq!(pa, addr);
        assert_eq!(ph, 100);
        assert_eq!(pti, 5);
        assert_eq!(pii, 2);

        let (ptxid, pdir, pamt) = parse_value(&v).unwrap();
        assert_eq!(ptxid, txid);
        assert_eq!(pdir, DIR_OUT);
        assert_eq!(pamt, 1_000_000_000);
    }

    #[test]
    fn key_ordering_is_chronological() {
        let addr = dummy_addr(0x11);
        let k1 = make_key(&addr, 10, 0, 0);
        let k2 = make_key(&addr, 100, 0, 0);
        let k3 = make_key(&addr, 1000, 0, 0);
        assert!(k1 < k2);
        assert!(k2 < k3);
    }

    #[test]
    fn parse_invalid_sizes_returns_none() {
        assert!(parse_key(&[0u8; 10]).is_none());
        assert!(parse_key(&[0u8; 50]).is_none());
        assert!(parse_value(&[0u8; 20]).is_none());
    }

    #[test]
    fn index_coinbase_adds_out_entry() {
        let (_tmp, store) = mk_storage();
        let tx = mk_tx_coinbase(0x42, 33 * 100_000_000);
        store.index_tx_addresses(&tx, 1, 0).unwrap();
        let entries = store.query_address_history(&dummy_addr(0x42), 0, 100, 10, 0).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_incoming());
        assert_eq!(entries[0].amount, 33 * 100_000_000);
        assert_eq!(entries[0].height, 1);
    }

    #[test]
    fn query_respects_height_range() {
        let (_tmp, store) = mk_storage();
        for h in 1..=10 {
            let tx = mk_tx_coinbase(0x55, 100);
            store.index_tx_addresses(&tx, h, 0).unwrap();
        }
        let mid = store.query_address_history(&dummy_addr(0x55), 3, 7, 100, 0).unwrap();
        assert_eq!(mid.len(), 5);
        assert_eq!(mid[0].height, 3);
        assert_eq!(mid[4].height, 7);
    }

    #[test]
    fn query_respects_limit_and_offset() {
        let (_tmp, store) = mk_storage();
        for h in 1..=20 {
            let tx = mk_tx_coinbase(0x77, 100);
            store.index_tx_addresses(&tx, h, 0).unwrap();
        }
        let page1 = store.query_address_history(&dummy_addr(0x77), 0, 1000, 5, 0).unwrap();
        let page2 = store.query_address_history(&dummy_addr(0x77), 0, 1000, 5, 5).unwrap();
        let page3 = store.query_address_history(&dummy_addr(0x77), 0, 1000, 5, 10).unwrap();

        assert_eq!(page1.len(), 5);
        assert_eq!(page2.len(), 5);
        assert_eq!(page3.len(), 5);

        // Pages should not overlap
        assert_eq!(page1[0].height, 1);
        assert_eq!(page2[0].height, 6);
        assert_eq!(page3[0].height, 11);
    }

    #[test]
    fn count_is_consistent_with_query() {
        let (_tmp, store) = mk_storage();
        for h in 1..=15 {
            let tx = mk_tx_coinbase(0xAA, 100);
            store.index_tx_addresses(&tx, h, 0).unwrap();
        }
        let count = store.count_address_history(&dummy_addr(0xAA), 0, 15).unwrap();
        assert_eq!(count, 15);
        let count_range = store.count_address_history(&dummy_addr(0xAA), 5, 10).unwrap();
        assert_eq!(count_range, 6);
    }

    #[test]
    fn balance_at_height_sums_incoming() {
        let (_tmp, store) = mk_storage();
        for h in 1..=5 {
            let tx = mk_tx_coinbase(0xBB, 100);
            store.index_tx_addresses(&tx, h, 0).unwrap();
        }
        // All incoming, balance at tip = 500
        let bal_tip = store.balance_at_height(&dummy_addr(0xBB), 5).unwrap();
        assert_eq!(bal_tip, 500);
        // At height 3, only 3 entries counted = 300
        let bal_3 = store.balance_at_height(&dummy_addr(0xBB), 3).unwrap();
        assert_eq!(bal_3, 300);
    }

    #[test]
    fn different_addresses_isolated() {
        let (_tmp, store) = mk_storage();
        let tx_a = mk_tx_coinbase(0xAA, 100);
        let tx_b = mk_tx_coinbase(0xBB, 200);
        store.index_tx_addresses(&tx_a, 1, 0).unwrap();
        store.index_tx_addresses(&tx_b, 1, 1).unwrap();

        let a = store.query_address_history(&dummy_addr(0xAA), 0, 100, 10, 0).unwrap();
        let b = store.query_address_history(&dummy_addr(0xBB), 0, 100, 10, 0).unwrap();

        assert_eq!(a.len(), 1);
        assert_eq!(a[0].amount, 100);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].amount, 200);
    }

    #[test]
    fn empty_address_returns_empty() {
        let (_tmp, store) = mk_storage();
        let e = store.query_address_history(&dummy_addr(0x00), 0, 1000, 100, 0).unwrap();
        assert!(e.is_empty());
        let c = store.count_address_history(&dummy_addr(0x00), 0, 1000).unwrap();
        assert_eq!(c, 0);
        let b = store.balance_at_height(&dummy_addr(0x00), 1000).unwrap();
        assert_eq!(b, 0);
    }
}

