//! Bloch-SIS Protocol — Address Transaction History Indexer (Sprint F)
//!
//! Appends entries to `CF_ADDR_TX_HISTORY` for each (address, tx) touch —
//! whether as output recipient or as input spender. Chronologically ordered
//! by height, enabling O(log n + k) queries instead of O(n) full chain scans.
//!
//! Key schema:   [20B addr_hash][8B height BE][4B tx_index BE][4B out_or_in_idx BE]
//! Value schema: [32B txid][1B direction: 0=in, 1=out][8B amount_sats LE]
//!
//! Properties:
//! - Append-only. Never modified after write, even on reorg (future work).
//! - Height in BE so prefix-iteration returns chronological order.
//! - Key is unique per (addr, height, tx, vout/vin) — no collisions.
//! - Prefix extractor of 20 bytes enables efficient address-scoped range scans.

use rocksdb::{IteratorMode, ReadOptions};
use crate::storage::{Storage, StorageError};
use crate::core::Transaction;

pub const CF_ADDR_TX_HISTORY: &str = "addr_tx_history";

// Entry size: 32 (txid) + 1 (direction) + 8 (amount) = 41 bytes
pub const ENTRY_SIZE: usize = 41;
pub const DIR_IN: u8 = 0;
pub const DIR_OUT: u8 = 1;

/// Parsed history entry.
#[derive(Debug, Clone)]
pub struct AddrHistoryEntry {
    pub addr_hash: [u8; 20],
    pub height:    u64,
    pub tx_index:  u32,
    pub io_index:  u32,
    pub txid:      [u8; 32],
    pub direction: u8,      // 0 = in (spent), 1 = out (received)
    pub amount:    u64,
}

impl AddrHistoryEntry {
    pub fn is_incoming(&self) -> bool { self.direction == DIR_OUT }
    pub fn is_outgoing(&self) -> bool { self.direction == DIR_IN }
    pub fn direction_str(&self) -> &'static str {
        if self.direction == DIR_OUT { "in" } else { "out" }
    }
}

/// Compose the key bytes for a history entry.
pub fn make_key(addr_hash: &[u8; 20], height: u64, tx_index: u32, io_index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(36);
    key.extend_from_slice(addr_hash);
    key.extend_from_slice(&height.to_be_bytes());
    key.extend_from_slice(&tx_index.to_be_bytes());
    key.extend_from_slice(&io_index.to_be_bytes());
    key
}

/// Compose the value bytes for a history entry.
pub fn make_value(txid: &[u8; 32], direction: u8, amount: u64) -> Vec<u8> {
    let mut val = Vec::with_capacity(ENTRY_SIZE);
    val.extend_from_slice(txid);
    val.push(direction);
    val.extend_from_slice(&amount.to_le_bytes());
    val
}

/// Parse a key into (addr_hash, height, tx_index, io_index).
pub fn parse_key(key: &[u8]) -> Option<([u8; 20], u64, u32, u32)> {
    if key.len() != 36 { return None; }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&key[..20]);
    let height = u64::from_be_bytes(key[20..28].try_into().ok()?);
    let tx_index = u32::from_be_bytes(key[28..32].try_into().ok()?);
    let io_index = u32::from_be_bytes(key[32..36].try_into().ok()?);
    Some((addr, height, tx_index, io_index))
}

/// Parse a value into (txid, direction, amount).
pub fn parse_value(val: &[u8]) -> Option<([u8; 32], u8, u64)> {
    if val.len() != ENTRY_SIZE { return None; }
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&val[..32]);
    let direction = val[32];
    let amount = u64::from_le_bytes(val[33..41].try_into().ok()?);
    Some((txid, direction, amount))
}

// ─────────────────────────────────────────────────────────────────────────────
// Indexing API (called by Storage::put_block)
// ─────────────────────────────────────────────────────────────────────────────

impl Storage {
    /// Extract the 20-byte address hash from a script_pubkey.
    /// Our script_pubkey format is simply the 20-byte SHA3-256(pubkey)[..20].
    fn script_pubkey_to_addr_hash(script_pubkey: &[u8]) -> Option<[u8; 20]> {
        if script_pubkey.len() < 20 { return None; }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&script_pubkey[..20]);
        Some(addr)
    }

    /// Compute the (key, value) `CF_ADDR_TX_HISTORY` writes for one transaction
    /// WITHOUT touching the DB. Shared by `index_tx_addresses` (direct write)
    /// and `put_block`'s atomic `WriteBatch` path so both produce byte-identical
    /// entries. Kept private to the crate; the keys/values are an internal index.
    pub(crate) fn addr_index_entries(
        &self,
        tx: &Transaction,
        height: u64,
        tx_index: u32,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let txid = tx.txid();
        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

        // Index outputs (DIR_OUT — address RECEIVED funds)
        for (vout_idx, output) in tx.outputs.iter().enumerate() {
            if let Some(addr) = Self::script_pubkey_to_addr_hash(&output.script_pubkey) {
                entries.push((
                    make_key(&addr, height, tx_index, vout_idx as u32),
                    make_value(&txid, DIR_OUT, output.value),
                ));
            }
        }

        // Index inputs (DIR_IN — address SPENT funds)
        // Coinbase has no real inputs — skip.
        if !tx.is_coinbase() {
            for (vin_idx, input) in tx.inputs.iter().enumerate() {
                // Look up the previous output to find which address was spent
                if let Ok(Some(prev_output)) = self.get_utxo_including_spent(&input.prev_txid, input.prev_index) {
                    if let Some(addr) = Self::script_pubkey_to_addr_hash(&prev_output.script_pubkey) {
                        // Use a high bit offset for io_index to avoid collision with vout indices
                        // (a tx cannot have 2^31 outputs, so bit 31 marks "this is an input entry")
                        entries.push((
                            make_key(&addr, height, tx_index, 0x80000000 | vin_idx as u32),
                            make_value(&txid, DIR_IN, prev_output.value),
                        ));
                    }
                }
                // If prev_output can't be found (shouldn't happen on valid chain),
                // skip silently — we prefer partial index to indexing failure.
            }
        }

        Ok(entries)
    }

    /// Index one transaction's address touches.
    /// Called during put_block for each tx. For inputs, looks up the previous
    /// output to find which address was spent.
    pub fn index_tx_addresses(&self, tx: &Transaction, height: u64, tx_index: u32) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_ADDR_TX_HISTORY)
            .ok_or_else(|| StorageError::CfNotFound(CF_ADDR_TX_HISTORY.into()))?;
        for (key, val) in self.addr_index_entries(tx, height, tx_index)? {
            self.db.put_cf(&cf, &key, &val)
                .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        }
        Ok(())
    }

    /// Sprint U.2 — Inverse of `index_tx_addresses`. Called by `rollback_block`
    /// to un-record address touches when a block is being reverted out of the
    /// selected chain.
    ///
    /// For inputs we use `spent_lookup` (sourced from UndoData.spent_utxos)
    /// rather than `get_utxo_including_spent`. The latter could fail after
    /// UTXO restoration re-inserts spent outputs, and could also succeed with
    /// stale data for intra-block chains if rollback order changes. Using the
    /// lookup captured at accept-time is deterministic.
    ///
    /// Silently skips entries whose address can't be resolved — matches the
    /// best-effort semantics of `index_tx_addresses`, so any key that wasn't
    /// created in the first place isn't attempted for delete.
    pub fn unindex_tx_addresses(
        &self,
        tx: &Transaction,
        height: u64,
        tx_index: u32,
        spent_lookup: &std::collections::HashMap<([u8; 32], u32), crate::core::TxOutput>,
    ) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_ADDR_TX_HISTORY)
            .ok_or_else(|| StorageError::CfNotFound(CF_ADDR_TX_HISTORY.into()))?;

        // Unindex outputs (DIR_OUT entries created by index_tx_addresses)
        for (vout_idx, output) in tx.outputs.iter().enumerate() {
            if let Some(addr) = Self::script_pubkey_to_addr_hash(&output.script_pubkey) {
                let key = make_key(&addr, height, tx_index, vout_idx as u32);
                self.db.delete_cf(&cf, &key)
                    .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
            }
        }

        // Unindex inputs (DIR_IN entries — only exist for non-coinbase txs)
        if !tx.is_coinbase() {
            for (vin_idx, input) in tx.inputs.iter().enumerate() {
                if let Some(prev_output) = spent_lookup.get(&(input.prev_txid, input.prev_index)) {
                    if let Some(addr) = Self::script_pubkey_to_addr_hash(&prev_output.script_pubkey) {
                        // Mirror index_tx_addresses's bit-31 IN marker.
                        let key = make_key(&addr, height, tx_index, 0x80000000 | vin_idx as u32);
                        self.db.delete_cf(&cf, &key)
                            .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
                    }
                }
                // If not in spent_lookup (e.g. intra-block chain that was never
                // successfully indexed), there's nothing to delete — skip.
            }
        }

        Ok(())
    }
    pub fn get_utxo_including_spent(&self, prev_txid: &[u8; 32], prev_index: u32)
        -> Result<Option<crate::core::TxOutput>, StorageError>
    {
        // Try UTXO set first (fast path for unspent outputs)
        if let Some(utxo) = self.get_utxo(prev_txid, prev_index)? {
            return Ok(Some(utxo));
        }
        // Fallback: look up the tx location, load the block, find the output
        match self.get_tx_location(prev_txid)? {
            Some((block_hash, _height)) => {
                if let Some(block) = self.get_block(&block_hash)? {
                    for tx in &block.transactions {
                        if &tx.txid() == prev_txid {
                            if let Some(out) = tx.outputs.get(prev_index as usize) {
                                return Ok(Some(out.clone()));
                            }
                        }
                    }
                }
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// Query address history by range. Returns entries sorted by height ascending.
    pub fn query_address_history(
        &self,
        addr_hash: &[u8; 20],
        start_height: u64,
        end_height: u64,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AddrHistoryEntry>, StorageError> {
        let cf = self.db.cf_handle(CF_ADDR_TX_HISTORY)
            .ok_or_else(|| StorageError::CfNotFound(CF_ADDR_TX_HISTORY.into()))?;

        let mut lower = Vec::with_capacity(36);
        lower.extend_from_slice(addr_hash);
        lower.extend_from_slice(&start_height.to_be_bytes());
        lower.extend_from_slice(&[0u8; 8]); // tx_index + io_index = 0

        let mut upper = Vec::with_capacity(36);
        upper.extend_from_slice(addr_hash);
        upper.extend_from_slice(&end_height.saturating_add(1).to_be_bytes());
        upper.extend_from_slice(&[0u8; 8]);

        let mut read_opts = ReadOptions::default();
        read_opts.set_iterate_upper_bound(upper);

        let iter = self.db.iterator_cf_opt(&cf, read_opts, IteratorMode::From(&lower, rocksdb::Direction::Forward));

        let mut results = Vec::new();
        let mut skipped = 0;
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            // Verify prefix still matches our address (paranoia)
            if key.len() < 20 || &key[..20] != addr_hash {
                break;
            }
            if skipped < offset {
                skipped += 1;
                continue;
            }
            if results.len() >= limit {
                break;
            }
            if let (Some((a, h, ti, ii)), Some((txid, dir, amt))) = (parse_key(&key), parse_value(&value)) {
                results.push(AddrHistoryEntry {
                    addr_hash: a,
                    height:    h,
                    tx_index:  ti,
                    io_index:  ii,
                    txid,
                    direction: dir,
                    amount:    amt,
                });
            }
        }
        Ok(results)
    }

    /// Count total entries for an address within a height range (for pagination).
    pub fn count_address_history(
        &self,
        addr_hash: &[u8; 20],
        start_height: u64,
        end_height: u64,
    ) -> Result<u64, StorageError> {
        let cf = self.db.cf_handle(CF_ADDR_TX_HISTORY)
            .ok_or_else(|| StorageError::CfNotFound(CF_ADDR_TX_HISTORY.into()))?;

        let mut lower = Vec::with_capacity(36);
        lower.extend_from_slice(addr_hash);
        lower.extend_from_slice(&start_height.to_be_bytes());
        lower.extend_from_slice(&[0u8; 8]);

        let mut upper = Vec::with_capacity(36);
        upper.extend_from_slice(addr_hash);
        upper.extend_from_slice(&end_height.saturating_add(1).to_be_bytes());
        upper.extend_from_slice(&[0u8; 8]);

        let mut read_opts = ReadOptions::default();
        read_opts.set_iterate_upper_bound(upper);

        let iter = self.db.iterator_cf_opt(&cf, read_opts, IteratorMode::From(&lower, rocksdb::Direction::Forward));

        let mut count = 0u64;
        for item in iter {
            let (key, _) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if key.len() < 20 || &key[..20] != addr_hash { break; }
            count += 1;
        }
        Ok(count)
    }

    /// Compute balance at a specific height by replaying the address history.
    /// balance(height) = sum(received up to height) - sum(spent up to height)
    pub fn balance_at_height(&self, addr_hash: &[u8; 20], height: u64) -> Result<u64, StorageError> {
        let entries = self.query_address_history(addr_hash, 0, height, usize::MAX, 0)?;
        let mut balance: i128 = 0;
        for e in entries.iter() {
            if e.is_incoming() {
                balance += e.amount as i128;
            } else {
                balance -= e.amount as i128;
            }
        }
        if balance < 0 { return Ok(0); }
        Ok(balance as u64)
    }
}
