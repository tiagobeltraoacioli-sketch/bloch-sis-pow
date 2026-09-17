// SPDX-License-Identifier: AGPL-3.0-or-later
//! Node-local admission limits. None of these rules changes block validity.
use super::*;

/// Encoded payload budget. Transaction objects and bookkeeping add bounded
/// overhead; this is not a claim that resident memory equals payload bytes.
pub(super) const MAX_MEMPOOL_BYTES: usize = 16 * 1024 * 1024;

#[derive(Default)]
pub(super) struct Mempool {
    entries: BTreeMap<Vec<u8>, PosTransaction>,
    identities: BTreeMap<[u8; 32], usize>,
    sources: BTreeMap<[u8; 32], usize>,
    bytes: usize,
}
impl std::ops::Deref for Mempool {
    type Target = BTreeMap<Vec<u8>, PosTransaction>;
    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}
impl<'a> IntoIterator for &'a Mempool {
    type Item = (&'a Vec<u8>, &'a PosTransaction);
    type IntoIter = std::collections::btree_map::Iter<'a, Vec<u8>, PosTransaction>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}
impl Mempool {
    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }
    pub(super) fn has_txid(&self, id: &[u8; 32]) -> bool {
        self.identities.contains_key(id)
    }
    pub(super) fn source_count(&self, source: &[u8; 32]) -> usize {
        self.sources.get(source).copied().unwrap_or(0)
    }
    pub(super) fn insert(&mut self, key: Vec<u8>, tx: PosTransaction) -> Option<PosTransaction> {
        let old = self.remove(&key);
        self.bytes = self.bytes.saturating_add(key.len());
        let count = self.identities.entry(tx.txid()).or_default();
        *count = count.saturating_add(1);
        if let Some(source) = tx_source_hash(&tx) {
            let count = self.sources.entry(source).or_default();
            *count = count.saturating_add(1);
        }
        self.entries.insert(key, tx);
        old
    }
    pub(super) fn remove(&mut self, key: &Vec<u8>) -> Option<PosTransaction> {
        let tx = self.entries.remove(key)?;
        self.bytes = self.bytes.saturating_sub(key.len());
        decrement(&mut self.identities, tx.txid());
        if let Some(source) = tx_source_hash(&tx) {
            decrement(&mut self.sources, source);
        }
        Some(tx)
    }
    pub(super) fn retain(&mut self, mut keep: impl FnMut(&Vec<u8>, &PosTransaction) -> bool) {
        let removed: Vec<_> = self
            .entries
            .iter()
            .filter(|(k, v)| !keep(k, v))
            .map(|(k, _)| k.clone())
            .collect();
        for key in removed {
            self.remove(&key);
        }
    }
    #[cfg(test)]
    pub(super) fn clear(&mut self) {
        *self = Self::default();
    }
}
fn decrement(map: &mut BTreeMap<[u8; 32], usize>, key: [u8; 32]) {
    if let Some(n) = map.get_mut(&key) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            map.remove(&key);
        }
    }
}

/// Reject impossible spends before hybrid signature verification. Unknown
/// parents are intentionally refused: package/child admission is unsupported.
pub(super) fn check_transfer(
    state: &CommittedState,
    tx: &PosTransaction,
    encoded: usize,
    epoch: u64,
) -> Result<(), Refusal> {
    let (points, outputs, declared, tip, verifications): (Vec<_>, _, _, _, _) = match tx {
        PosTransaction::Transfer {
            inputs,
            outputs,
            tx_bytes,
            tip_millisat_per_gas,
        } => (
            inputs
                .iter()
                .map(|i| ((i.txid, i.vout), i.pubkey.as_slice()))
                .collect(),
            outputs,
            *tx_bytes,
            *tip_millisat_per_gas,
            inputs.len(),
        ),
        PosTransaction::TransferV2 {
            inputs,
            keys,
            outputs,
            tx_bytes,
            tip_millisat_per_gas,
        } => {
            let mut points = Vec::with_capacity(inputs.len());
            for i in inputs {
                let key = keys
                    .get(i.key_index as usize)
                    .ok_or(Refusal::Invalid("transfer has an invalid key index"))?;
                points.push(((i.txid, i.vout), key.pubkey.as_slice()));
            }
            (
                points,
                outputs,
                *tx_bytes,
                *tip_millisat_per_gas,
                keys.len(),
            )
        }
        PosTransaction::FundedDeposit(tx) => {
            if (encoded as u64).max(tx.tx_bytes) > fee_market::max_block_tx_bytes(epoch) {
                return Err(Refusal::Invalid("transaction exceeds block byte budget"));
            }
            return Ok(());
        }
        _ => return Ok(()),
    };
    if (encoded as u64).max(declared) > fee_market::max_block_tx_bytes(epoch) {
        return Err(Refusal::Invalid("transaction exceeds block byte budget"));
    }
    if declared < encoded as u64 {
        return Err(Refusal::Invalid("transaction underdeclares encoded bytes"));
    }
    let class = fee_market::TxClass::Eutxo {
        inputs: verifications as u32,
    };
    price_bounds(class, declared, tip).map_err(Refusal::Invalid)?;
    let mut seen = BTreeSet::new();
    let mut spent = 0u128;
    for (point, pk) in points {
        if !seen.insert(point) {
            return Err(Refusal::Invalid("transfer repeats an input"));
        }
        let entry = state
            .utxo(&point.0, point.1)
            .ok_or(Refusal::StateDependent(
                "transfer input is absent from committed state",
            ))?;
        let hash: [u8; 32] = Sha3_256::digest(pk).into();
        if hash != entry.script_hash
            && !(entry.script_hash[20..] == [0; 12] && hash[..20] == entry.script_hash[..20])
        {
            return Err(Refusal::Invalid("transfer key does not own its input"));
        }
        spent = spent
            .checked_add(u128::from(entry.value))
            .ok_or(Refusal::Invalid("transfer input sum overflows"))?;
    }
    let charge = fee_market::charge(class, declared, state.next_base_fee_at(epoch), tip);
    let created = outputs
        .iter()
        .try_fold(0u128, |total, output| {
            total.checked_add(u128::from(output.value))
        })
        .and_then(|total| total.checked_add(charge.base_fee_sat))
        .and_then(|total| total.checked_add(charge.priority_fee_sat))
        .ok_or(Refusal::Invalid("transfer output and fee sum overflows"))?;
    if spent != created {
        return Err(Refusal::StateDependent(
            "transfer value is not conserved at the current base fee",
        ));
    }
    Ok(())
}

/// Transactional capacity plan; callers commit it only after authenticating the
/// incoming transaction. Stale entries are not placed in a rejection cache.
pub(super) struct CapacityPlan {
    pub stale: BTreeSet<Vec<u8>>,
    pub lower_fee: Option<Vec<u8>>,
}

impl Engine {
    pub(super) fn plan_mempool_capacity(&self, incoming: &PosTransaction, encoded: usize, epoch: u64) -> Result<CapacityPlan, Refusal> {
        let source = tx_source_hash(incoming);
        let mut count = self.mempool.len();
        let mut bytes = self.mempool.bytes();
        let mut source_count = source.map_or(0, |s| self.mempool.source_count(&s));
        let mut plan = CapacityPlan { stale: BTreeSet::new(), lower_fee: None };
        let mut funded_context = None;
        // No full-pool revalidation on ordinary admission. Under any capacity
        // pressure, stale backing must not retain priority through claimed tips.
        if count >= MEMPOOL_MAX || bytes.saturating_add(encoded) > MAX_MEMPOOL_BYTES
            || source_count >= MEMPOOL_MAX_PER_SOURCE {
            let mut candidates: Vec<_> = self.mempool.iter().map(|(key, candidate)| {
                (source.is_some() && tx_source_hash(candidate) == source, key, candidate)
            }).collect();
            if source_count >= MEMPOOL_MAX_PER_SOURCE {
                candidates.sort_by_key(|(same_source, _, _)| !same_source);
            }
            for (same_source, key, candidate) in candidates {
                if source_count >= MEMPOOL_MAX_PER_SOURCE && !same_source { continue; }
                if self.candidate_is_backed(candidate, key.len(), epoch, &mut funded_context) { continue; }
                plan.stale.insert(key.clone());
                count = count.saturating_sub(1);
                bytes = bytes.saturating_sub(key.len());
                if same_source { source_count = source_count.saturating_sub(1); }
                if count < MEMPOOL_MAX && bytes.saturating_add(encoded) <= MAX_MEMPOOL_BYTES
                    && source_count < MEMPOOL_MAX_PER_SOURCE { break; }
            }
        }
        if bytes.saturating_add(encoded) > MAX_MEMPOOL_BYTES { return Err(Refusal::AtCapacity); }
        if source_count >= MEMPOOL_MAX_PER_SOURCE { return Err(Refusal::TooManyFromSource); }
        if count >= MEMPOOL_MAX {
            let lowest = self.mempool.iter().filter(|(key, _)| !plan.stale.contains(*key))
                .min_by_key(|(_, tx)| tx_tip_rate(tx));
            match lowest {
                Some((key, tx)) if tx_tip_rate(incoming) > tx_tip_rate(tx) => plan.lower_fee = Some(key.clone()),
                _ => return Err(Refusal::AtCapacity),
            }
        }
        Ok(plan)
    }
}
