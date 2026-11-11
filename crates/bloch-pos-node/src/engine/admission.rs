// SPDX-License-Identifier: AGPL-3.0-or-later
//! Node-local admission limits. None of these rules changes block validity.
use super::*;

/// Encoded payload budget. Transaction objects and bookkeeping add bounded
/// overhead; this is not a claim that resident memory equals payload bytes.
pub(super) const MAX_MEMPOOL_BYTES: usize = 16 * 1024 * 1024;
/// Room kept for forced-inclusion envelopes (wire 0x1C) in a full pool. They
/// carry no tip by design (the depth-priced surcharge pays for them), so the
/// lowest-tip rules would drop them first and a pool kept full of cheap
/// entries would censor the one path meant to resist censorship.
///
/// The room is the best `MEMPOOL_FORCED_RESERVED` pooled forced envelopes
/// that are backed ([`check_l2_funding`]) and spend disjoint inputs, ranked by
/// tip and then by age ([`Engine::forced_room`]). Those are never evicted or
/// displaced to make room for another kind, and while the room is not full an
/// arriving forced envelope takes the place of the lowest-tip entry of another
/// kind whatever its tip. Outside the room a forced envelope competes by tip
/// like any entry and the registered DA key may displace it, so forced
/// envelopes cannot be used to hold the pool either (review R308-1, R308-2).
/// Backed includes applicable: an envelope for another network or L2 chain,
/// or of a shape consensus refuses, is refused at admission and holds no
/// room, and a copy re-spending a pooled envelope's output displaces nothing
/// (review R308-2P-2).
/// A DA batch of any other key still never evicts a forced envelope: the
/// sequencer that is being bypassed is the party that sends DA.
/// No forced envelope exists before `L2_FORCED_INCLUSION_EPOCH`, so nothing
/// changes while that gate is inert.
pub(super) const MEMPOOL_FORCED_RESERVED: usize = 64;

fn is_forced_envelope(tx: &PosTransaction) -> bool {
    matches!(tx, PosTransaction::L2ForcedTransaction(_))
}

#[derive(Default)]
pub(super) struct Mempool {
    entries: BTreeMap<Vec<u8>, PosTransaction>,
    identities: BTreeMap<[u8; 32], usize>,
    sources: BTreeMap<[u8; 32], usize>,
    bytes: usize,
    lifecycle_verification_slot: Option<u64>,
    lifecycle_verifications_total: usize,
    lifecycle_verifications: BTreeMap<[u8; 32], usize>,
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
    pub(super) fn reserve_lifecycle_verification(&mut self, source: [u8; 32], wall_slot: u64) -> bool {
        if self.lifecycle_verification_slot != Some(wall_slot) {
            self.lifecycle_verification_slot = Some(wall_slot);
            self.lifecycle_verifications_total = 0;
            self.lifecycle_verifications.clear();
        }
        if self.lifecycle_verifications_total >= LIFECYCLE_VERIFICATIONS_TOTAL_PER_SLOT {
            return false;
        }
        let used = self.lifecycle_verifications.entry(source).or_default();
        if *used >= LIFECYCLE_VERIFICATIONS_PER_SOURCE_PER_SLOT { return false; }
        *used = used.saturating_add(1);
        self.lifecycle_verifications_total = self.lifecycle_verifications_total.saturating_add(1);
        true
    }
    pub(super) fn insert(&mut self, key: Vec<u8>, tx: PosTransaction) -> Option<PosTransaction> {
        let txid = tx.txid();
        self.insert_with_txid(key, tx, txid)
    }
    /// Insert with the identity already derived by the admission path from
    /// this exact transaction. Kept inside the engine module: the supplied
    /// identity drives duplicate accounting and must never come from another
    /// value. The ordinary fixture-facing [`Self::insert`] remains the
    /// self-contained authority for callers without a prepared identity.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_verification_budget_is_per_source_and_renews_each_slot() {
        let mut pool = Mempool::default();
        let first = validator_lifecycle_source(7);
        let second = validator_lifecycle_source(8);
        for _ in 0..LIFECYCLE_VERIFICATIONS_PER_SOURCE_PER_SLOT {
            assert!(pool.reserve_lifecycle_verification(first, 100));
        }
        assert!(!pool.reserve_lifecycle_verification(first, 100));
        assert!(pool.reserve_lifecycle_verification(second, 100));
        assert!(pool.reserve_lifecycle_verification(first, 101));
    }

    #[test]
    fn lifecycle_verification_budget_is_globally_bounded_and_renews_each_slot() {
        let mut pool = Mempool::default();
        for identity in 0..LIFECYCLE_VERIFICATIONS_TOTAL_PER_SLOT {
            let mut source = [0u8; 32];
            source[..8].copy_from_slice(&(identity as u64).to_le_bytes());
            assert!(pool.reserve_lifecycle_verification(source, 200));
        }
        assert!(!pool.reserve_lifecycle_verification([0xff; 32], 200));
        assert_eq!(
            pool.lifecycle_verifications.len(),
            LIFECYCLE_VERIFICATIONS_TOTAL_PER_SLOT,
        );
        assert!(pool.reserve_lifecycle_verification([0xff; 32], 201));
        assert_eq!(pool.lifecycle_verifications_total, 1);
        assert_eq!(pool.lifecycle_verifications.len(), 1);
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
        | PosTransaction::L2WithdrawClaim(_)
        | PosTransaction::L2ForcedTransaction(_) => {
            // A kind this network's L2 does not admit is refused, with its
            // reason, by `l2_admission_refusal`.
            if l2_admission_refusal(tx, state.l2_settlement()).is_some() {
                return Ok(());
            }
            let queue = state.l2_settlement().and_then(|l2| l2.forced_queue());
            return check_l2_funding(state, queue, tx, encoded, epoch);
        }
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

/// Whether an L2 transaction can apply on this network at all (review
/// R308-2P-2): signed for this network's domain, naming this L2's chain id
/// (the kinds that carry one), and of a shape consensus accepts
/// (`validate_shape`). `network` is the committed state's admission domain
/// and `chain` the installed L2 policy's chain id; without an installed L2
/// no kind is admitted (`l2_admission_refusal`), so no chain is compared.
///
/// Node policy, a mirror of the first refusals of `apply_l2_*`. A funded
/// transaction for another network or chain is never included and never
/// spends its inputs, so without this it stayed "backed" for ever.
pub(super) fn check_l2_applicable(network: Option<[u8; 32]>, chain: Option<u64>, tx: &PosTransaction) -> Result<(), Refusal> {
    let (domain, named, shaped) = match tx {
        PosTransaction::L2Deposit(tx) => (tx.network_domain, None, tx.validate_shape().is_ok()),
        PosTransaction::L2DataAvailability(tx) => (tx.network_domain, Some(tx.l2_chain_id), tx.validate_shape().is_ok()),
        PosTransaction::L2WithdrawClaim(tx) => (tx.network_domain, Some(tx.l2_chain_id), tx.validate_shape().is_ok()),
        PosTransaction::L2ForcedTransaction(tx) => (tx.network_domain, Some(tx.l2_chain_id), tx.validate_shape().is_ok()),
        _ => return Ok(()),
    };
    if network != Some(domain) {
        return Err(Refusal::Invalid("L2 transaction is signed for another network"));
    }
    if let (Some(here), Some(named)) = (chain, named) {
        if here != named {
            return Err(Refusal::Invalid("L2 transaction names another L2 chain"));
        }
    }
    if !shaped {
        return Err(Refusal::Invalid("L2 transaction has a shape consensus refuses"));
    }
    Ok(())
}

/// The backing of the L2 kinds that spend funding inputs (deposit 0x14, DA
/// batch 0x15, withdrawal claim, forced envelope 0x1C), checked before the
/// signature like [`check_transfer`] does for transfers (review R308-3).
/// Backed means applicable, not only funded (review R308-2P-2).
///
/// Node policy, a mirror of what `apply_l2_*` checks in consensus: this
/// network, this L2 chain and a valid shape ([`check_l2_applicable`]), the
/// tip and gas ceilings, the funding inputs present in committed state and
/// owned by the funding key, and value conserved at the current base fee. A
/// forced envelope must also offer at least the current entry price of
/// `queue`, a DA batch must be one consensus would record
/// ([`check_da_recordable`]) and a withdrawal claim one consensus would apply
/// on this state ([`check_claim_applicable`], review R308-3P-1).
/// Without it these kinds entered the pool on a signature alone with any
/// claimed tip, and eviction at capacity is by claimed tip. An entry that
/// stops passing is dropped under capacity pressure (`candidate_is_backed`).
pub(super) fn check_l2_funding(
    state: &CommittedState,
    queue: Option<&bloch_pos_committee::l2_settlement::forced::Queue>,
    tx: &PosTransaction,
    encoded: usize,
    epoch: u64,
) -> Result<(), Refusal> {
    use bloch_pos_committee::l2_settlement::forced;
    let l2 = state.l2_settlement();
    check_l2_applicable(state.admission_network_domain(), l2.map(|l2| l2.policy().chain_id), tx)?;
    if let (PosTransaction::L2DataAvailability(batch), Some(l2)) = (tx, l2) {
        check_da_recordable(l2.settled_number(), l2.data_availability(), batch.l2_block_number, || batch.commitment())?;
    }
    // (funding key, inputs, declared bytes, tip, value owed besides the fees)
    let (pubkey, inputs, declared, tip, owed) = match tx {
        PosTransaction::L2Deposit(tx) => (
            &tx.funding_pubkey,
            &tx.inputs,
            tx.tx_bytes,
            tx.tip_millisat_per_gas,
            u128::from(tx.amount_sat)
                + u128::from(tx.change.value)
                + state.l2_deposit_protocol_fee(tx.amount_sat).map_or(0, |(fee, _)| u128::from(fee)),
        ),
        PosTransaction::L2DataAvailability(tx) => {
            (&tx.funding_pubkey, &tx.inputs, tx.tx_bytes, tx.tip_millisat_per_gas, u128::from(tx.change.value))
        }
        PosTransaction::L2WithdrawClaim(tx) => {
            (&tx.funding_pubkey, &tx.inputs, tx.tx_bytes, tx.tip_millisat_per_gas, u128::from(tx.change.value))
        }
        PosTransaction::L2ForcedTransaction(tx) => {
            if !(forced::MIN_GAS..=forced::MAX_GAS).contains(&tx.gas_limit) {
                return Err(Refusal::Invalid("L2 forced transaction declares a gas limit outside the allowed range"));
            }
            if let Some(queue) = queue {
                match queue.surcharge_for(tx.gas_limit) {
                    None => return Err(Refusal::StateDependent("the L2 forced queue is full")),
                    Some(price) if price > tx.max_surcharge_sat => {
                        return Err(Refusal::StateDependent(
                            "L2 forced transaction offers less than the current entry surcharge",
                        ));
                    }
                    Some(_) => {}
                }
            }
            (
                &tx.funding_pubkey,
                &tx.inputs,
                tx.tx_bytes,
                tx.tip_millisat_per_gas,
                u128::from(tx.change.value) + u128::from(tx.max_surcharge_sat),
            )
        }
        _ => return Ok(()),
    };
    if (encoded as u64).max(declared) > fee_market::max_block_tx_bytes(epoch) {
        return Err(Refusal::Invalid("transaction exceeds block byte budget"));
    }
    if declared < encoded as u64 {
        return Err(Refusal::Invalid("transaction underdeclares encoded bytes"));
    }
    let class = fee_market::TxClass::Eutxo { inputs: inputs.len() as u32 };
    if tip > fee_market::MAX_TIP_MILLISAT_PER_GAS {
        return Err(Refusal::Invalid("L2 transaction names a tip above the consensus ceiling"));
    }
    if fee_market::intrinsic_gas(class, declared) > fee_market::MAX_TX_GAS {
        return Err(Refusal::Invalid("L2 transaction declares more gas than a whole block may spend"));
    }
    let owner: [u8; 32] = Sha3_256::digest(pubkey).into();
    let mut seen = BTreeSet::new();
    let mut spent = 0u128;
    for input in inputs {
        if !seen.insert((input.txid, input.vout)) {
            return Err(Refusal::Invalid("L2 transaction repeats a funding input"));
        }
        let entry = state
            .utxo(&input.txid, input.vout)
            .ok_or(Refusal::StateDependent("L2 funding input is absent from committed state"))?;
        if owner != entry.script_hash
            && !(entry.script_hash[20..] == [0; 12] && owner[..20] == entry.script_hash[..20])
        {
            return Err(Refusal::Invalid("L2 funding key does not own its input"));
        }
        spent += u128::from(entry.value);
    }
    let charge = fee_market::charge(class, declared, state.next_base_fee_at(epoch), tip);
    let required = owed
        .checked_add(charge.base_fee_sat)
        .and_then(|total| total.checked_add(charge.priority_fee_sat))
        .ok_or(Refusal::Invalid("L2 transaction value and fee sum overflows"))?;
    if spent != required {
        return Err(Refusal::StateDependent(
            "L2 funding value is not conserved at the current base fee",
        ));
    }
    if let PosTransaction::L2WithdrawClaim(claim) = tx {
        // Last: the funding answers above keep their own reasons.
        check_claim_applicable(state.l2_withdraw_claim_refusal(claim))?;
    }
    Ok(())
}

/// Whether consensus would record a DA batch for L2 block `number` with this
/// commitment (review R308-3P-1): the number and duplicate refusals of
/// `L2State::record_data_availability`, on the committed state's settled
/// mark and DA records. Consensus records DA only for the next
/// [`da::WINDOW`] unsettled blocks and only once per (block, commitment); a
/// funded batch outside that is never included and never spends its output.
/// The window moves with the settled mark (a head reset may lower it), so
/// both number refusals are state dependent. A full record list is not
/// mirrored: `da::MAX_RECORDS` is the per-block cap times the retention plus
/// one block, so expiry keeps the list below it.
///
/// [`da::WINDOW`]: bloch_pos_committee::l2_settlement::da::WINDOW
pub(super) fn check_da_recordable(
    settled: u64,
    records: &[bloch_pos_committee::l2_settlement::da::Record],
    number: u64,
    commitment: impl FnOnce() -> [u8; 32],
) -> Result<(), Refusal> {
    use bloch_pos_committee::l2_settlement::da;
    if number <= settled {
        return Err(Refusal::StateDependent("L2 data availability names a block that is already settled"));
    }
    if number > settled.saturating_add(da::WINDOW) {
        return Err(Refusal::StateDependent("L2 data availability names a block beyond the unsettled window"));
    }
    if records.iter().any(|r| r.l2_number == number) {
        let commitment = commitment();
        if records.iter().any(|r| r.l2_number == number && r.commitment == commitment) {
            return Err(Refusal::StateDependent("L2 data availability repeats a recorded commitment"));
        }
    }
    Ok(())
}

/// A withdrawal claim is backed only if consensus would apply it on the
/// committed state (review R308-3P-1). `refusal` is what
/// `CommittedState::l2_withdraw_claim_refusal` answers: the state checks of
/// `apply_l2_withdraw_claim` up to the signatures (index already claimed,
/// proof against no retained root, root not matured or not final, release
/// window used up, attestation missing, ...). A funded claim that fails one
/// is never included and never spends its inputs. All of them are verdicts
/// against a state, so the refusal is retryable.
///
/// `Conservation` is left to [`check_l2_funding`]: that refusal is priced
/// with the state's own epoch, the funding check with the epoch of the next
/// block, and the two differ on the first block of a byte-target flag day.
pub(super) fn check_claim_applicable(
    refusal: Option<bloch_pos_committee::transition::L2WithdrawClaimReject>,
) -> Result<(), Refusal> {
    use bloch_pos_committee::transition::L2WithdrawClaimReject as R;
    Err(Refusal::StateDependent(match refusal {
        None | Some(R::Conservation) => return Ok(()),
        Some(R::AlreadyClaimed) => "L2 withdrawal claim names a leaf that is already claimed",
        Some(R::Proof) => "L2 withdrawal claim proves against no retained withdrawal root",
        Some(R::Index) => "L2 withdrawal claim names an index its withdrawal root does not hold",
        Some(R::NotMatured) => "L2 withdrawal claim proves against a root younger than the withdrawal delay",
        Some(R::NotFinalized) => "L2 withdrawal claim proves against a settlement that is not final yet",
        Some(R::RateLimited) => "L2 withdrawal claim exceeds what the release window has left",
        Some(R::Escrow) => "L2 withdrawal claim exceeds the escrow",
        Some(R::AttestationRequired) => "L2 withdrawal claim needs the attestors' co-signature",
        Some(R::Attestation) => "L2 withdrawal claim carries an attestation of another set",
        Some(_) => "L2 withdrawal claim is refused by consensus on the committed state",
    }))
}

/// Transactional capacity plan; callers commit it only after authenticating the
/// incoming transaction. Stale entries are not placed in a rejection cache.
pub(super) struct CapacityPlan {
    pub stale: BTreeSet<Vec<u8>>,
    pub lower_fee: Option<Vec<u8>>,
    /// Entries the registered DA key's batch displaces (reserved DA slot).
    pub displaced: Vec<Vec<u8>>,
}

impl Engine {
    pub(super) fn plan_mempool_capacity(&self, incoming: &PosTransaction, encoded: usize, epoch: u64) -> Result<CapacityPlan, Refusal> {
        let source = tx_source_hash(incoming);
        let mut count = self.mempool.len();
        let mut bytes = self.mempool.bytes();
        let mut source_count = source.map_or(0, |s| self.mempool.source_count(&s));
        let mut plan = CapacityPlan { stale: BTreeSet::new(), lower_fee: None, displaced: Vec::new() };
        let mut funded_context = None;
        let incoming_da = matches!(incoming, PosTransaction::L2DataAvailability(_));
        let incoming_forced = is_forced_envelope(incoming);
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
        let fits = |count: usize, bytes: usize| count < MEMPOOL_MAX && bytes.saturating_add(encoded) <= MAX_MEMPOOL_BYTES;
        // The reserved room of forced envelopes, needed only under pressure.
        let room = if fits(count, bytes) { BTreeSet::new() } else { self.forced_room(&plan.stale, epoch) };
        let reserved = da_reserved_key(epoch);
        // The registered DA key's batch (past `L2_DA_RESERVED_SLOT_EPOCH`)
        // displaces the lowest-tip entries that are not its own, whatever
        // their tip, until it fits by count and bytes. Otherwise a pool full
        // of valid tip-0 DA keeps it out of every mempool and the reserved
        // block slot serves nobody. Forced envelopes go last and only those
        // outside the reserved room, lowest tip then youngest first. Its own
        // per-source cap bounds what it can displace; the others lose a place
        // in the queue, never a fee.
        if is_reserved_da(incoming, reserved) && source_count < MEMPOOL_MAX_PER_SOURCE && !fits(count, bytes) {
            let mut victims: Vec<_> = self.mempool.iter()
                .filter(|(key, tx)| !plan.stale.contains(*key) && !is_reserved_da(tx, reserved) && !room.contains(*key))
                .collect();
            victims.sort_by_key(|(key, tx)| {
                let forced = is_forced_envelope(tx);
                let order = if forced { self.mempool_admitted_at.get(*key).copied().unwrap_or(u64::MAX) } else { key.len() as u64 };
                (forced, tx_tip_rate(tx), std::cmp::Reverse(order))
            });
            for (key, _) in victims {
                if fits(count, bytes) { break; }
                plan.displaced.push(key.clone());
                count = count.saturating_sub(1);
                bytes = bytes.saturating_sub(key.len());
            }
        }
        // While the reserved room is not full, an arriving forced envelope
        // takes the place of the lowest-tip entries of another kind whatever
        // their tip (it carries none by design). The caller has checked its
        // backing (`check_transfer`) before planning. The registered DA key's
        // batches are left alone: they would only displace their way back.
        // A copy that re-spends an output a pooled forced envelope already
        // spends displaces nothing (one displacement per funding output,
        // review R308-2P-2): only one of them can ever apply.
        if incoming_forced && source_count < MEMPOOL_MAX_PER_SOURCE && !fits(count, bytes)
            && room.len() < MEMPOOL_FORCED_RESERVED && !self.respends_a_pooled_forced_input(incoming, &plan.stale) {
            let mut victims: Vec<_> = self.mempool.iter()
                .filter(|(key, tx)| !plan.stale.contains(*key) && !is_forced_envelope(tx) && !is_reserved_da(tx, reserved))
                .collect();
            victims.sort_by_key(|(key, tx)| (tx_tip_rate(tx), std::cmp::Reverse(key.len())));
            for (key, _) in victims {
                if fits(count, bytes) { break; }
                plan.displaced.push(key.clone());
                count = count.saturating_sub(1);
                bytes = bytes.saturating_sub(key.len());
            }
        }
        if bytes.saturating_add(encoded) > MAX_MEMPOOL_BYTES { return Err(Refusal::AtCapacity); }
        if source_count >= MEMPOOL_MAX_PER_SOURCE { return Err(Refusal::TooManyFromSource); }
        if count >= MEMPOOL_MAX {
            // By tip. The reserved room does not make way for another kind,
            // no forced envelope makes way for a DA batch, and forced
            // envelopes compete among themselves.
            let protected = |key: &Vec<u8>, tx: &PosTransaction| {
                !incoming_forced && is_forced_envelope(tx) && (incoming_da || room.contains(key))
            };
            let lowest = self.mempool.iter()
                .filter(|(key, tx)| !plan.stale.contains(*key) && !plan.displaced.contains(*key) && !protected(key, tx))
                .min_by_key(|(_, tx)| tx_tip_rate(tx));
            match lowest {
                Some((key, tx)) if tx_tip_rate(incoming) > tx_tip_rate(tx) => plan.lower_fee = Some(key.clone()),
                _ => return Err(Refusal::AtCapacity),
            }
        }
        Ok(plan)
    }

    /// Whether a pooled forced envelope outside `stale` already spends one
    /// of the funding inputs of the forced envelope `incoming`.
    fn respends_a_pooled_forced_input(&self, incoming: &PosTransaction, stale: &BTreeSet<Vec<u8>>) -> bool {
        let PosTransaction::L2ForcedTransaction(incoming) = incoming else { return false };
        let inputs: BTreeSet<_> = incoming.inputs.iter().map(|i| (i.txid, i.vout)).collect();
        self.mempool.iter().any(|(key, tx)| {
            !stale.contains(key)
                && matches!(tx, PosTransaction::L2ForcedTransaction(f) if f.inputs.iter().any(|i| inputs.contains(&(i.txid, i.vout))))
        })
    }

    /// The pooled forced envelopes that hold the reserved room
    /// ([`MEMPOOL_FORCED_RESERVED`]): backed against committed state, not in
    /// `stale`, spending inputs no better-ranked one spends, best first by
    /// tip and then by age. Unbacked envelopes and envelopes that re-spend one
    /// output hold no room, so the room costs real surcharges to occupy.
    pub(super) fn forced_room(&self, stale: &BTreeSet<Vec<u8>>, epoch: u64) -> BTreeSet<Vec<u8>> {
        let queue = self.state.l2_settlement().and_then(|l2| l2.forced_queue());
        let mut ranked: Vec<_> = self.mempool.iter()
            .filter(|(key, tx)| is_forced_envelope(tx) && !stale.contains(*key)
                && check_l2_funding(&self.state, queue, tx, key.len(), epoch).is_ok())
            .collect();
        ranked.sort_by_key(|(key, tx)| {
            (std::cmp::Reverse(tx_tip_rate(tx)), self.mempool_admitted_at.get(*key).copied().unwrap_or(u64::MAX))
        });
        let mut spent = BTreeSet::new();
        let mut room = BTreeSet::new();
        for (key, tx) in ranked {
            if room.len() == MEMPOOL_FORCED_RESERVED { break; }
            let PosTransaction::L2ForcedTransaction(forced) = tx else { continue };
            if forced.inputs.iter().any(|i| spent.contains(&(i.txid, i.vout))) { continue; }
            spent.extend(forced.inputs.iter().map(|i| (i.txid, i.vout)));
            room.insert(key.clone());
        }
        room
    }
}
