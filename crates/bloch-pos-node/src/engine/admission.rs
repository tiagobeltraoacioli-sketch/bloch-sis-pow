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
    /// Outpoints named by pending entries, each with the mempool keys of the
    /// entries that name it (audit L1N-02). It used to be a count only, so
    /// finding the entry that holds an input meant walking the pool, which
    /// is why that test had to wait until the newcomer was authenticated.
    /// One shared copy of the key per entry, however many inputs it names;
    /// an entry naming an outpoint twice is listed twice and removed twice.
    spenders: BTreeMap<([u8; 32], u32), Vec<Arc<[u8]>>>,
    /// Keys inserted by [`Self::insert`], i.e. not through admission.
    unverified: BTreeSet<Vec<u8>>,
    bytes: usize,
    lifecycle_verification_slot: Option<u64>,
    lifecycle_verifications_total: usize,
    lifecycle_verifications: BTreeMap<[u8; 32], usize>,
    lifecycle_verifications_by_deliverer: BTreeMap<[u8; 32], usize>,
    /// Audit L1S-02: `(kind, validator)` -> the signed epoch of the last
    /// credential rotation / commission update admitted or seen in a
    /// canonical block. One entry per validator and kind, overwritten by a
    /// newer epoch, so it never grows past twice the registry.
    once_per_epoch: BTreeMap<(u8, u32), u64>,
}

/// The allowance key of one (deliverer, identity) pair (audit L1-02). This
/// node's own submissions (`None`) have a key no remote source can produce.
fn lifecycle_pair_key(deliverer: Option<[u8; 32]>, identity: &[u8; 32]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut hash = Sha3_256::new();
    hash.update(b"bloch-node-lifecycle-allowance-pair-v1");
    match deliverer {
        Some(deliverer) => {
            hash.update([0x01]);
            hash.update(deliverer);
        }
        None => hash.update([0x00]),
    }
    hash.update(identity);
    hash.finalize().into()
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
    /// Whether any pending entry names `point` as an input.
    pub(super) fn spends_outpoint(&self, point: &([u8; 32], u32)) -> bool {
        self.spenders.contains_key(point)
    }
    /// The mempool keys of the pending entries that name `point` as an
    /// input: one index lookup, no pool walk (audit L1N-02).
    pub(super) fn spenders_of(&self, point: &([u8; 32], u32)) -> &[Arc<[u8]>] {
        self.spenders.get(point).map_or(&[], Vec::as_slice)
    }
    /// The distinct pending entries naming any of `points`, in mempool key
    /// order (the order a pool walk visits them).
    pub(super) fn entries_spending<'a>(
        &'a self,
        points: &[([u8; 32], u32)],
    ) -> BTreeMap<&'a [u8], &'a PosTransaction> {
        let mut found = BTreeMap::new();
        for point in points {
            for key in self.spenders_of(point) {
                if let Some((key, tx)) = self.entries.get_key_value(&key[..]) {
                    found.insert(key.as_slice(), tx);
                }
            }
        }
        found
    }
    /// Whether the entry under `key` was inserted by the admission path,
    /// which authenticates a transaction before it inserts it.
    pub(super) fn admission_verified(&self, key: &[u8]) -> bool {
        !self.unverified.contains(key)
    }
    /// Reserve one expensive lifecycle authorization call for `identity`
    /// (the validator, funding key or rescue key the transaction speaks for)
    /// as delivered by `deliverer` (the peer or RPC client's verification
    /// source; `None` for this node's own submissions).
    ///
    /// Audit L1-02: the allowance used to be keyed by the identity alone, a
    /// value taken from the transaction's own fields, so anyone could spend a
    /// chosen validator's two units per slot with well-formed forgeries and
    /// starve its genuine `KesRotate`, `KesRegister`, exit or commission
    /// update (including this node's automatic KES rotation). It is now keyed
    /// by the (deliverer, identity) pair, so a forger only spends its own
    /// pair; each deliverer is further capped across identities so one source
    /// cannot exhaust the global ceiling alone; and this node's own
    /// submissions draw on a private pair that no remote deliverer can touch
    /// and are not subject to the per-deliverer or global ceilings.
    pub(super) fn reserve_lifecycle_verification(
        &mut self,
        deliverer: Option<[u8; 32]>,
        identity: [u8; 32],
        wall_slot: u64,
    ) -> bool {
        if self.lifecycle_verification_slot != Some(wall_slot) {
            self.lifecycle_verification_slot = Some(wall_slot);
            self.lifecycle_verifications_total = 0;
            self.lifecycle_verifications.clear();
            self.lifecycle_verifications_by_deliverer.clear();
        }
        let pair = lifecycle_pair_key(deliverer, &identity);
        if self.lifecycle_verifications.get(&pair).copied().unwrap_or(0) >= LIFECYCLE_VERIFICATIONS_PER_SOURCE_PER_SLOT {
            return false;
        }
        if let Some(deliverer) = deliverer {
            if self.lifecycle_verifications_total >= LIFECYCLE_VERIFICATIONS_TOTAL_PER_SLOT {
                return false;
            }
            let by_deliverer = self.lifecycle_verifications_by_deliverer.entry(deliverer).or_default();
            if *by_deliverer >= LIFECYCLE_VERIFICATIONS_PER_DELIVERER_PER_SLOT {
                return false;
            }
            *by_deliverer = by_deliverer.saturating_add(1);
            self.lifecycle_verifications_total = self.lifecycle_verifications_total.saturating_add(1);
        }
        let used = self.lifecycle_verifications.entry(pair).or_default();
        *used = used.saturating_add(1);
        true
    }
    /// Whether a message of this `(kind, validator)` signed for `epoch` was
    /// already admitted or included (audit L1S-02).
    pub(super) fn once_per_epoch_seen(&self, key: (u8, u32), epoch: u64) -> bool {
        self.once_per_epoch.get(&key) == Some(&epoch)
    }
    pub(super) fn note_once_per_epoch(&mut self, key: (u8, u32), epoch: u64) {
        let seen = self.once_per_epoch.entry(key).or_insert(epoch);
        *seen = (*seen).max(epoch);
    }
    /// Forget that `key` was used in `epoch`: the block that carried the
    /// message left canonical history. A record of another epoch stays.
    pub(super) fn release_once_per_epoch(&mut self, key: (u8, u32), epoch: u64) {
        if self.once_per_epoch.get(&key) == Some(&epoch) {
            self.once_per_epoch.remove(&key);
        }
    }
    pub(super) fn insert(&mut self, key: Vec<u8>, tx: PosTransaction) -> Option<PosTransaction> {
        let txid = tx.txid();
        let old = self.insert_with_txid(key.clone(), tx, txid);
        // Nothing vouches for an entry placed here directly, so selection and
        // capacity planning keep judging its witnesses themselves.
        self.unverified.insert(key);
        old
    }
    /// Insert with the identity already derived by the admission path from
    /// this exact transaction. Kept inside the engine module: the supplied
    /// identity drives duplicate accounting and must never come from another
    /// value. The ordinary fixture-facing [`Self::insert`] remains the
    /// self-contained authority for callers without a prepared identity.
    ///
    /// The caller is the admission path and has already authenticated `tx`:
    /// the entry is recorded as verified (see [`Self::admission_verified`]).
    pub(super) fn insert_with_txid(
        &mut self,
        key: Vec<u8>,
        tx: PosTransaction,
        txid: [u8; 32],
    ) -> Option<PosTransaction> {
        let old = self.remove(&key);
        self.bytes = self.bytes.saturating_add(key.len());
        let count = self.identities.entry(txid).or_default();
        *count = count.saturating_add(1);
        if let Some(source) = tx_source_hash(&tx) {
            let count = self.sources.entry(source).or_default();
            *count = count.saturating_add(1);
        }
        let points = Engine::spent_outpoints(&tx).unwrap_or_default();
        if !points.is_empty() {
            let shared: Arc<[u8]> = Arc::from(key.as_slice());
            for point in points {
                self.spenders.entry(point).or_default().push(Arc::clone(&shared));
            }
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
        for point in Engine::spent_outpoints(&tx).unwrap_or_default() {
            if let Some(keys) = self.spenders.get_mut(&point) {
                if let Some(at) = keys.iter().position(|held| held[..] == key[..]) {
                    keys.swap_remove(at);
                }
                if keys.is_empty() {
                    self.spenders.remove(&point);
                }
            }
        }
        self.unverified.remove(key);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_verification_budget_is_per_source_and_renews_each_slot() {
        let mut pool = Mempool::default();
        let peer = Some([0x0a; 32]);
        let first = validator_lifecycle_source(7);
        let second = validator_lifecycle_source(8);
        for _ in 0..LIFECYCLE_VERIFICATIONS_PER_SOURCE_PER_SLOT {
            assert!(pool.reserve_lifecycle_verification(peer, first, 100));
        }
        assert!(!pool.reserve_lifecycle_verification(peer, first, 100));
        assert!(pool.reserve_lifecycle_verification(peer, second, 100));
        assert!(pool.reserve_lifecycle_verification(peer, first, 101));
    }

    #[test]
    fn lifecycle_verification_budget_is_globally_bounded_and_renews_each_slot() {
        let mut pool = Mempool::default();
        for n in 0..LIFECYCLE_VERIFICATIONS_TOTAL_PER_SLOT {
            let mut deliverer = [0u8; 32];
            deliverer[..8].copy_from_slice(&((n / LIFECYCLE_VERIFICATIONS_PER_DELIVERER_PER_SLOT) as u64).to_le_bytes());
            let mut identity = [0u8; 32];
            identity[..8].copy_from_slice(&(n as u64).to_le_bytes());
            assert!(pool.reserve_lifecycle_verification(Some(deliverer), identity, 200));
        }
        assert!(!pool.reserve_lifecycle_verification(Some([0xfe; 32]), [0xff; 32], 200));
        assert_eq!(
            pool.lifecycle_verifications.len(),
            LIFECYCLE_VERIFICATIONS_TOTAL_PER_SLOT,
        );
        // This node's own submission is not subject to the global ceiling.
        assert!(pool.reserve_lifecycle_verification(None, [0xff; 32], 200));
        assert!(pool.reserve_lifecycle_verification(Some([0xfe; 32]), [0xff; 32], 201));
        assert_eq!(pool.lifecycle_verifications_total, 1);
        assert_eq!(pool.lifecycle_verifications.len(), 1);
    }

    /// Audit L1-02: forgeries naming a validator spend only their deliverer's
    /// allowance for it, never another deliverer's or this node's own; and
    /// one deliverer cannot exhaust the global ceiling by cycling identities.
    #[test]
    fn a_forger_cannot_spend_another_deliverers_lifecycle_allowance() {
        let mut pool = Mempool::default();
        let target = validator_lifecycle_source(5);
        let attacker = Some([0xa1; 32]);
        let honest = Some([0xb2; 32]);
        for _ in 0..LIFECYCLE_VERIFICATIONS_PER_SOURCE_PER_SLOT {
            assert!(pool.reserve_lifecycle_verification(attacker, target, 300));
        }
        assert!(!pool.reserve_lifecycle_verification(attacker, target, 300), "the attacker's own pair is spent");
        assert!(pool.reserve_lifecycle_verification(honest, target, 300), "another deliverer still verifies it");
        assert!(pool.reserve_lifecycle_verification(None, target, 300), "and so does this node's own submission");

        let cycler = Some([0xc3; 32]);
        let mut admitted = 0;
        for n in 0..LIFECYCLE_VERIFICATIONS_TOTAL_PER_SLOT {
            if pool.reserve_lifecycle_verification(cycler, validator_lifecycle_source(1_000 + n as u32), 300) {
                admitted += 1;
            }
        }
        assert_eq!(admitted, LIFECYCLE_VERIFICATIONS_PER_DELIVERER_PER_SLOT);
        assert!(pool.lifecycle_verifications_total < LIFECYCLE_VERIFICATIONS_TOTAL_PER_SLOT);
    }

    #[test]
    fn lifecycle_mempool_sources_bind_identity_not_witness_bytes() {
        let a = PosTransaction::ExitV2 { pubkey_hash: [0x31; 32], epoch: 9, signature: vec![1] };
        let b = PosTransaction::ExitV2 { pubkey_hash: [0x31; 32], epoch: 9, signature: vec![2, 3] };
        assert_eq!(tx_source_hash(&a), tx_source_hash(&b));
        assert_ne!(tx_source_hash(&a), tx_source_hash(&PosTransaction::ExitV2 {
            pubkey_hash: [0x32; 32], epoch: 9, signature: vec![1],
        }));
        assert_eq!(
            tx_source_hash(&PosTransaction::Withdraw { validator: 7 }),
            tx_source_hash(&PosTransaction::RandaoRecommit {
                validator: 7, epoch: 9, new_commitment: [0x44; 32], signature: vec![5],
            }),
        );
    }

    /// Audit L1-13: a commission update has the validator's mempool source,
    /// so `MEMPOOL_MAX_PER_SOURCE` bounds one validator's variants, and the
    /// source does not depend on the commission or the signature bytes.
    #[test]
    fn commission_updates_have_a_mempool_source() {
        let update = |validator: u32, commission_bps: u128, signature: Vec<u8>| {
            PosTransaction::ValidatorCommissionUpdate(
                bloch_pos_committee::transition::ValidatorCommissionUpdate {
                    network_domain: [0x11; 32],
                    epoch: 9,
                    validator,
                    commission_bps,
                    signature,
                },
            )
        };
        let a = tx_source_hash(&update(7, 100, vec![1]));
        assert!(a.is_some());
        assert_eq!(a, tx_source_hash(&update(7, 200, vec![2, 3])));
        assert_eq!(a, tx_source_hash(&PosTransaction::Withdraw { validator: 7 }));
        assert_ne!(a, tx_source_hash(&update(8, 100, vec![1])));
    }

    #[test]
    fn prepared_txid_insert_matches_authority_and_preserves_variant_multiplicity() {
        use bloch_pos_committee::transition::{TransferInput, TransferOutput};

        let first = PosTransaction::Transfer {
            inputs: vec![TransferInput {
                txid: [0x11; 32],
                vout: 3,
                pubkey: vec![0x22; 32],
                signature: vec![0x33],
            }],
            outputs: vec![TransferOutput { value: 7, script_hash: [0x44; 32] }],
            tx_bytes: 512,
            tip_millisat_per_gas: 9,
        };
        let mut variant = first.clone();
        let PosTransaction::Transfer { inputs, .. } = &mut variant else {
            unreachable!()
        };
        inputs[0].signature.push(0x55);
        let txid = first.txid();
        assert_eq!(variant.txid(), txid, "witness variants share one transaction identity");
        let first_key = first.canonical_bytes();
        let variant_key = variant.canonical_bytes();
        assert_ne!(first_key, variant_key, "fixture must exercise two canonical entries");

        let mut ordinary = Mempool::default();
        ordinary.insert(first_key.clone(), first.clone());
        let mut prepared = Mempool::default();
        prepared.insert_with_txid(first_key.clone(), first, txid);
        assert_eq!(prepared.bytes, ordinary.bytes);
        assert_eq!(prepared.identities, ordinary.identities);
        assert_eq!(prepared.sources, ordinary.sources);
        assert_eq!(prepared.entries, ordinary.entries);

        prepared.insert_with_txid(variant_key.clone(), variant, txid);
        assert_eq!(prepared.identities.get(&txid), Some(&2));
        prepared.remove(&first_key);
        assert_eq!(prepared.identities.get(&txid), Some(&1));
        assert!(prepared.has_txid(&txid));
        prepared.remove(&variant_key);
        assert!(!prepared.has_txid(&txid));
        assert!(prepared.entries.is_empty());
        assert_eq!(prepared.bytes(), 0);
    }
}
fn decrement<K: Ord>(map: &mut BTreeMap<K, usize>, key: K) {
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
    let (points, outputs, declared, tip, class): (Vec<_>, _, _, _, _) = match tx {
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
            fee_market::eutxo_class_for_keys(epoch, inputs.iter().map(|i| i.pubkey.as_slice())),
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
                fee_market::eutxo_class_for_keys(epoch, keys.iter().map(|k| k.pubkey.as_slice())),
            )
        }
        PosTransaction::FundedDeposit(tx) => {
            if (encoded as u64).max(tx.tx_bytes) > fee_market::max_block_tx_bytes(epoch) {
                return Err(Refusal::Invalid("transaction exceeds block byte budget"));
            }
            return Ok(());
        }
        PosTransaction::L2Deposit(_)
        | PosTransaction::L2DataAvailability(_)
        | PosTransaction::L2WithdrawClaim(_) => return check_l2_funded(state, tx, encoded, epoch),
        _ => return Ok(()),
    };
    if (encoded as u64).max(declared) > fee_market::max_block_tx_bytes(epoch) {
        return Err(Refusal::Invalid("transaction exceeds block byte budget"));
    }
    if declared < encoded as u64 {
        return Err(Refusal::Invalid("transaction underdeclares encoded bytes"));
    }
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

/// The proof-free state preflight of the three fee-paying L2 transactions
/// (deposit 0x14, data availability 0x15, withdrawal claim 0x16), the
/// counterpart of [`check_transfer`] for them (review EXE-1, V2-1).
///
/// Without it these types reached the mempool on a signature by any key and
/// were "backed" forever: ordered by a tip nobody could be made to pay,
/// budgeted by a self-declared size, and holding the input reservation of
/// outpoints their key does not own. The proposer's probe then refused them
/// and the block went out without the transactions they displaced.
///
/// Every refusal below is the transition's own, taken from the committee's
/// shared check functions against `state` at the price of a block in `epoch`,
/// so nothing is refused that the next block could carry; the additions are
/// the block byte budget and the declared-size slack, the relay bounds
/// transfers already have. Signatures are not judged here (admission verifies them
/// after this, under the per-source budget).
fn check_l2_funded(
    state: &CommittedState,
    tx: &PosTransaction,
    encoded: usize,
    epoch: u64,
) -> Result<(), Refusal> {
    use bloch_pos_committee::transition::{
        L2DataAvailabilityReject as Da, L2DepositReject as Deposit, L2WithdrawClaimReject as Claim,
    };
    if let Some(why) = l2_admission_refusal(tx, state.l2_settlement()) {
        return Err(Refusal::Invalid(why));
    }
    let declared = match tx {
        PosTransaction::L2Deposit(tx) => tx.tx_bytes,
        PosTransaction::L2DataAvailability(tx) => tx.tx_bytes,
        PosTransaction::L2WithdrawClaim(tx) => tx.tx_bytes,
        _ => return Ok(()),
    };
    if (encoded as u64).max(declared) > fee_market::max_block_tx_bytes(epoch) {
        return Err(Refusal::Invalid("transaction exceeds block byte budget"));
    }
    // Relay policy, the bound transfers already have (`declared_size_bound`,
    // audit H-R7-2; review W1-1): the declared size is what the block byte
    // cap counts, and consensus puts no ceiling on it for these types, so a
    // small transaction declaring a block of bytes displaced everything
    // behind it from a selection. Honest builders declare the unsigned
    // encoding plus the largest signature, a few bytes above the encoding.
    if declared > (encoded as u64).saturating_add(fee_market::TX_BYTES_DECLARE_SLACK) {
        return Err(Refusal::Invalid("L2 transaction declares far more bytes than its encoding carries"));
    }
    let base_fee = state.next_base_fee_at(epoch);
    match tx {
        PosTransaction::L2Deposit(deposit) => match state.l2_deposit_refusal_at(deposit, base_fee) {
            None => Ok(()),
            Some(Deposit::MissingInput) => Err(Refusal::StateDependent(
                "L2 deposit input is absent from committed state",
            )),
            Some(Deposit::Conservation) => Err(Refusal::StateDependent(
                "L2 deposit value is not conserved at the current base fee",
            )),
            Some(Deposit::NotActive | Deposit::OutputCollision | Deposit::Inbox) => Err(
                Refusal::StateDependent("L2 deposit cannot be applied to the current L2 state"),
            ),
            Some(Deposit::Ownership) => Err(Refusal::Invalid("L2 deposit key does not own its input")),
            Some(_) => Err(Refusal::Invalid("L2 deposit fails committed-state validation")),
        },
        PosTransaction::L2DataAvailability(batch) => match state.l2_data_availability_refusal_at(batch, base_fee) {
            None => Ok(()),
            Some(Da::MissingInput) => Err(Refusal::StateDependent(
                "L2 data availability input is absent from committed state",
            )),
            Some(Da::Conservation) => Err(Refusal::StateDependent(
                "L2 data availability value is not conserved at the current base fee",
            )),
            Some(Da::Number | Da::Duplicate | Da::Full | Da::NotActive | Da::OutputCollision) => Err(
                Refusal::StateDependent(
                    "L2 data availability batch is settled, out of window, already recorded or the record set is full",
                ),
            ),
            Some(Da::Ownership) => Err(Refusal::Invalid("L2 data availability key does not own its input")),
            Some(_) => Err(Refusal::Invalid("L2 data availability fails committed-state validation")),
        },
        PosTransaction::L2WithdrawClaim(claim) => match match state.l2_withdraw_claim_refusal_at(claim, base_fee) {
            // The one refusal an empty epoch boundary can lift: the block
            // being built is judged on this state rolled to its epoch, and
            // the roll may finalize the settlement the claim proves against.
            // When the block is in a later epoch than the head, do not hold
            // the head's finality against the claim (the transition will).
            // Everything that does not depend on finality is still judged:
            // funding, ownership, conservation and the outputs (review W1-2;
            // this arm used to check that the inputs exist and are owned
            // and nothing else, so a claim paying no fee was admitted).
            Some(Claim::NotFinalized) if epoch > epoch_of(state.slot()) => {
                state.l2_withdraw_claim_refusal_before_finality_at(claim, base_fee)
            }
            other => other,
        } {
            None => Ok(()),
            Some(Claim::MissingInput) => Err(Refusal::StateDependent(
                "L2 withdrawal claim input is absent from committed state",
            )),
            Some(Claim::Conservation) => Err(Refusal::StateDependent(
                "L2 withdrawal claim value is not conserved at the current base fee",
            )),
            Some(Claim::NotMatured | Claim::NotFinalized | Claim::RateLimited) => Err(Refusal::StateDependent(
                "L2 withdrawal claim is not yet payable: its root is not matured or finalized, or the release window is used up",
            )),
            Some(
                Claim::Proof | Claim::Index | Claim::AlreadyClaimed | Claim::Escrow | Claim::NotActive
                | Claim::OutputCollision,
            ) => Err(Refusal::StateDependent(
                "L2 withdrawal claim does not prove an unclaimed leaf of a withdrawal root this node retains",
            )),
            Some(Claim::Ownership) => Err(Refusal::Invalid("L2 withdrawal claim key does not own its input")),
            Some(_) => Err(Refusal::Invalid("L2 withdrawal claim fails committed-state validation")),
        },
        _ => Ok(()),
    }
}

/// The refusal text of a newcomer whose input a pending, still-backed entry
/// holds. One text for the lookup before verification and the plan after it.
pub(super) const INPUT_ALREADY_PENDING: &str =
    "transaction spends an input that a pending transaction already spends";

/// The refusal text of a funded pair that conflicts with a pending input or
/// validator key, and of a spend whose input a pending funded pair holds.
pub(super) const FUNDED_INPUT_CONFLICT: &str =
    "funded deposit conflicts with a pending input or validator key";

/// Pending holders of the newcomer's inputs visited before its signatures are
/// verified (audit L1N-02). Each costs at most one proof-free state preflight.
pub(super) const MAX_PENDING_HOLDERS_EXAMINED_BEFORE_VERIFICATION: usize = 8;

/// Funded pairs are outside the input reservation of
/// [`Engine::plan_input_conflicts`]: `funded_mempool_conflict` judges them
/// and also reserves the validator key.
fn input_reservation_exempt(tx: &PosTransaction) -> bool {
    matches!(tx, PosTransaction::FundedDeposit(_) | PosTransaction::FundedDelegate(_))
}

/// Transactional capacity plan; callers build it and commit it only after
/// authenticating the incoming transaction. Stale entries are not placed in a
/// rejection cache.
pub(super) struct CapacityPlan {
    pub stale: BTreeSet<Vec<u8>>,
    pub lower_fee: Option<Vec<u8>>,
}

impl Engine {
    /// Pending spends reserve their inputs: two pending transactions naming
    /// one outpoint can never both be included, so the second only took a
    /// slot, a relay and (before this rule) a place in every later capacity
    /// plan. The newcomer is refused while the entry holding the input is
    /// still backed by the current state; an entry that no longer is (its fee
    /// fell behind, its input was spent) is planned out as stale instead, so
    /// an owner is never locked out of an input by their own dead transaction.
    /// Returns the keys to plan out. Funded pairs are left to
    /// `funded_mempool_conflict`, which also reserves the validator key.
    fn plan_input_conflicts(&self, incoming: &PosTransaction, epoch: u64,
        funded_context: &mut Option<(Arc<CommittedState>, u128)>) -> Result<BTreeSet<Vec<u8>>, Refusal> {
        let mut stale = BTreeSet::new();
        let points = Self::spent_outpoints(incoming).unwrap_or_default();
        // The common case costs one index lookup per input and no pool walk.
        if input_reservation_exempt(incoming) || !points.iter().any(|point| self.mempool.spends_outpoint(point)) {
            return Ok(stale);
        }
        // Audit L1N-02: the entries sharing an input come from the outpoint
        // index, in the order the pool walk used to meet them.
        for (key, other) in self.mempool.entries_spending(&points) {
            if input_reservation_exempt(other) { continue; }
            if self.candidate_is_backed(other, key, epoch, funded_context) {
                return Err(Refusal::StateDependent(INPUT_ALREADY_PENDING));
            }
            stale.insert(key.to_vec());
        }
        Ok(stale)
    }

    /// The lookup half of [`Self::plan_input_conflicts`], safe to run BEFORE
    /// the newcomer's signatures are verified (audit L1N-02).
    ///
    /// A transfer whose signature is valid and whose input a pending
    /// transaction already holds used to be verified first and refused
    /// afterwards, free of charge: variants of one funded transfer drained
    /// the verification allowance every source shares. The refusal is now
    /// answered from the outpoint index, at the cost of one lookup per input
    /// and one state preflight of the holder, with no cryptography.
    ///
    /// Nothing is planned out or evicted here: an unauthenticated newcomer
    /// changes no pool state. Only a holder that admission itself
    /// authenticated and that the current state still backs refuses it. A
    /// holder that is no longer backed (its fee fell behind, its input was
    /// spent) refuses nothing, so the newcomer goes on to verification and
    /// the plan replaces the dead entry: an owner is still never locked out
    /// of an input by their own dead transaction. A holder placed without
    /// admission is left to the plan as well, because judging it needs its
    /// witnesses checked, which is work only an authenticated newcomer buys;
    /// so is a funded pair, whose backing needs a projected state. For every
    /// holder judged here, "backed" is the signature-free state preflight alone.
    pub(super) fn pending_input_refusal(&self, incoming: &PosTransaction, epoch: u64) -> Option<Refusal> {
        if input_reservation_exempt(incoming) { return None; }
        let points = Self::spent_outpoints(incoming)?;
        let mut examined = 0usize;
        let mut funded_context = None;
        for point in &points {
            for key in self.mempool.spenders_of(point) {
                // At most one admitted, backed entry holds an outpoint, and a
                // dead one is replaced by the next admitted spender, so this
                // loop is short. The ceiling makes that a guarantee and not
                // an argument: past it the newcomer is simply verified and
                // judged by the plan, as before.
                if examined >= MAX_PENDING_HOLDERS_EXAMINED_BEFORE_VERIFICATION { return None; }
                examined += 1;
                if !self.mempool.admission_verified(key) { continue; }
                let Some(other) = self.mempool.get(&key[..]) else { continue };
                // A funded pair is not judged here: whether it is still
                // backed takes a projected state and a lifecycle validation,
                // which an unauthenticated newcomer must not buy. It is left
                // to `funded_mempool_conflict` after verification, where a
                // refusal is charged to the sender.
                if input_reservation_exempt(other) { continue; }
                // A backed entry is never planned out, so this is the answer
                // the plan would give the newcomer after verification.
                if self.candidate_is_backed(other, key, epoch, &mut funded_context) {
                    return Some(Refusal::StateDependent(INPUT_ALREADY_PENDING));
                }
            }
        }
        None
    }

    /// Callers authenticate `incoming` first: this walks pending entries.
    pub(super) fn plan_mempool_capacity(&self, incoming: &PosTransaction, encoded: usize, epoch: u64) -> Result<CapacityPlan, Refusal> {
        let source = tx_source_hash(incoming);
        let mut count = self.mempool.len();
        let mut bytes = self.mempool.bytes();
        let mut source_count = source.map_or(0, |s| self.mempool.source_count(&s));
        let mut funded_context = None;
        let mut plan = CapacityPlan {
            stale: self.plan_input_conflicts(incoming, epoch, &mut funded_context)?,
            lower_fee: None,
        };
        for key in &plan.stale {
            count = count.saturating_sub(1);
            bytes = bytes.saturating_sub(key.len());
            if source.is_some() && self.mempool.get(key).and_then(tx_source_hash) == source {
                source_count = source_count.saturating_sub(1);
            }
        }
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
                if plan.stale.contains(key) { continue; }
                if self.candidate_is_backed(candidate, key, epoch, &mut funded_context) { continue; }
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
