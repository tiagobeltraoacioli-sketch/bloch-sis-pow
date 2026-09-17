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
    let charge = fee_market::charge(class, declared, state.next_base_fee(), tip);
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
