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
    /// Outpoints named by pending entries, with how many entries name each.
    spends: BTreeMap<([u8; 32], u32), usize>,
    /// Keys inserted by [`Self::insert`], i.e. not through admission.
    unverified: BTreeSet<Vec<u8>>,
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
    /// Whether any pending entry names `point` as an input.
    pub(super) fn spends_outpoint(&self, point: &([u8; 32], u32)) -> bool {
        self.spends.contains_key(point)
    }
    /// Whether the entry under `key` was inserted by the admission path,
    /// which authenticates a transaction before it inserts it.
    pub(super) fn admission_verified(&self, key: &[u8]) -> bool {
        !self.unverified.contains(key)
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
        for point in Engine::spent_outpoints(&tx).unwrap_or_default() {
            let count = self.spends.entry(point).or_default();
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
        for point in Engine::spent_outpoints(&tx).unwrap_or_default() {
            decrement(&mut self.spends, point);
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
        | PosTransaction::L2WithdrawClaim(_) => {
            // Test builds only: fillers of the pool-mechanics fixtures.
            #[cfg(test)]
            if state.l2_settlement().is_none() && l2_filler_test::is_open() {
                return Ok(());
            }
            return check_l2_funded(state, tx, encoded, epoch);
        }
        PosTransaction::L2ForcedTransaction(_) => {
            // While this network's L2 does not admit forced envelopes the
            // kind is refused, with its reason, by `l2_admission_refusal`.
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
pub(super) fn check_l2_funded(
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

/// The backing of a forced-inclusion envelope (wire 0x1C), checked before
/// the signature like [`check_transfer`] does for transfers (review R308-3).
/// Backed means applicable, not only funded (review R308-2P-2).
///
/// The three released L2 kinds (deposit 0x14, DA batch 0x15, withdrawal
/// claim 0x16) are judged by [`check_l2_funded`], which takes its refusals
/// from the transition's own check functions; given one of them this
/// function answers with that door. The forced envelope has no such shared
/// check function yet, so this is node policy mirroring what
/// `apply_l2_forced_transaction` checks in consensus: this network, this L2
/// chain and a valid shape ([`check_l2_applicable`]), the gas range, an
/// offer of at least the current entry price of `queue`, the tip and gas
/// ceilings, the funding inputs present in committed state and owned by the
/// funding key, and value conserved at the current base fee.
/// Without it the kind entered the pool on a signature alone with any
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
    let PosTransaction::L2ForcedTransaction(forced_tx) = tx else {
        return check_l2_funded(state, tx, encoded, epoch);
    };
    let l2 = state.l2_settlement();
    check_l2_applicable(state.admission_network_domain(), l2.map(|l2| l2.policy().chain_id), tx)?;
    if !(forced::MIN_GAS..=forced::MAX_GAS).contains(&forced_tx.gas_limit) {
        return Err(Refusal::Invalid("L2 forced transaction declares a gas limit outside the allowed range"));
    }
    if let Some(queue) = queue {
        match queue.surcharge_for(forced_tx.gas_limit) {
            None => return Err(Refusal::StateDependent("the L2 forced queue is full")),
            Some(price) if price > forced_tx.max_surcharge_sat => {
                return Err(Refusal::StateDependent(
                    "L2 forced transaction offers less than the current entry surcharge",
                ));
            }
            Some(_) => {}
        }
    }
    // (funding key, inputs, declared bytes, tip, value owed besides the fees)
    let (pubkey, inputs, declared, tip, owed) = (
        &forced_tx.funding_pubkey,
        &forced_tx.inputs,
        forced_tx.tx_bytes,
        forced_tx.tip_millisat_per_gas,
        u128::from(forced_tx.change.value) + u128::from(forced_tx.max_surcharge_sat),
    );
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
    Ok(())
}

/// Transactional capacity plan; callers build it and commit it only after
/// authenticating the incoming transaction. Stale entries are not placed in a
/// rejection cache.
pub(super) struct CapacityPlan {
    pub stale: BTreeSet<Vec<u8>>,
    pub lower_fee: Option<Vec<u8>>,
    /// Entries the registered DA key's batch displaces (reserved DA slot).
    pub displaced: Vec<Vec<u8>>,
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
        let funded = |tx: &PosTransaction| matches!(tx, PosTransaction::FundedDeposit(_) | PosTransaction::FundedDelegate(_));
        let mut stale = BTreeSet::new();
        let points = Self::spent_outpoints(incoming).unwrap_or_default();
        // The common case costs one index lookup per input and no pool walk.
        if funded(incoming) || !points.iter().any(|point| self.mempool.spends_outpoint(point)) {
            return Ok(stale);
        }
        for (key, other) in &self.mempool {
            if funded(other) { continue; }
            let shares_input = Self::spent_outpoints(other)
                .is_some_and(|theirs| theirs.iter().any(|point| points.contains(point)));
            if !shares_input { continue; }
            if self.candidate_is_backed(other, key, epoch, funded_context) {
                return Err(Refusal::StateDependent("transaction spends an input that a pending transaction already spends"));
            }
            stale.insert(key.clone());
        }
        Ok(stale)
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
            displaced: Vec::new(),
        };
        for key in &plan.stale {
            count = count.saturating_sub(1);
            bytes = bytes.saturating_sub(key.len());
            if source.is_some() && self.mempool.get(key).and_then(tx_source_hash) == source {
                source_count = source_count.saturating_sub(1);
            }
        }
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
