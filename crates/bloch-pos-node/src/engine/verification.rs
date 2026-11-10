// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded memoization of cryptographic failures at network/mempool admission.
//!
//! This is not a transaction, validator, or block rejection cache. The exact
//! public key, signing root, and signature determine each entry. Registry,
//! committee, clock, missing-parent, and admission failures never enter it.
//! Consensus execution continues to use its independent, uncached verifier.
use bloch_pos_committee::attestation::{SignaturePolicy, SignatureVerifier};
use sha3::{Digest, Sha3_256};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_FAILURES: usize = 4096;

/// Allowance units one native L2 settlement proof reserves at mempool
/// admission. A unit is one hybrid signature verification; the proof is a
/// Groth16 pairing check, far above the 15 units of an SLH-DSA-suite spend.
/// At 64, one source (128 units per slot) can have two proofs verified per
/// slot and the whole node (1,024 units) sixteen, while an honest prover
/// submits at most one settlement per source anchor.
pub(super) const L2_PROOF_VERIFICATION_UNITS: usize = 64;

#[derive(Default)]
struct Failures {
    known: BTreeSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}

/// Owns one fixed verifier for the lifetime of its cache. Only `false`
/// results are memoized; a successful signature is always checked again.
/// The FIFO and lookup set each retain at most MAX_FAILURES digests, with
/// their usual container overhead. Distinct invalid signatures still cost
/// verification work; this cache does not replace transport rate limits.
pub(super) struct GossipVerifier<V> {
    verifier: V,
    failures: RefCell<Failures>,
    budget: RefCell<SlotBudget>,
    /// Ids of blocks parked only because a slot allowance was spent, with the
    /// wall slot that refused them. Kept beside the budget that produced
    /// them; the engine re-offers them once that slot has passed.
    budget_parked: RefCell<VecDeque<(u64, [u8; 32])>>,
    #[cfg(test)]
    panic_on_verification: Cell<bool>,
}

/// Independent per-slot allowances. Votes and transactions can never spend
/// the units a block needs, and gossiped blocks can never spend the units
/// reserved for directed sync and operator-configured peers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum VerificationLane {
    /// Attestations, transactions and slashing evidence.
    Relay,
    /// Blocks from ordinary gossip.
    GossipBlock,
    /// Blocks from directed sync or an operator-configured peer.
    DirectedBlock,
}

const LANES: usize = 3;
const FAILURE_GROUPS: usize = 2;

impl VerificationLane {
    fn index(self) -> usize {
        match self {
            VerificationLane::Relay => 0,
            VerificationLane::GossipBlock => 1,
            VerificationLane::DirectedBlock => 2,
        }
    }

    /// Failures are counted per source for relay traffic and for blocks
    /// separately, so invalid votes alone never close the block door.
    fn failure_group(self) -> usize {
        match self {
            VerificationLane::Relay => 0,
            VerificationLane::GossipBlock | VerificationLane::DirectedBlock => 1,
        }
    }
}

#[derive(Default)]
struct SlotBudget {
    slot: Option<u64>,
    used: [usize; LANES],
    by_source: BTreeMap<[u8; 32], [usize; LANES]>,
    /// Units of failed verification per source. An entry exists only after a
    /// reserved unit failed, so the map is bounded by the lane ceilings.
    failed_by_source: BTreeMap<[u8; 32], [usize; FAILURE_GROUPS]>,
}

/// One node-local admission view of [`GossipVerifier`]. Exhaustion is exposed
/// separately from an invalid signature so callers can shed with `Ignore`
/// rather than mis-score an honest peer during local overload.
pub(super) struct BudgetedVerifier<'a, V> {
    owner: &'a GossipVerifier<V>,
    slot: u64,
    cap: usize,
    source: Option<[u8; 32]>,
    source_cap: usize,
    lane: VerificationLane,
    failure_cap: usize,
    limited: Cell<bool>,
    failure_limited: Cell<bool>,
}

impl<V> GossipVerifier<V> {
    pub(super) fn new(verifier: V) -> Self {
        Self {
            verifier,
            failures: RefCell::new(Failures::default()),
            budget: RefCell::new(SlotBudget::default()),
            budget_parked: RefCell::new(VecDeque::new()),
            #[cfg(test)]
            panic_on_verification: Cell::new(false),
        }
    }

    /// The policy is part of the key: a signature refused under the strict
    /// relay policy (e.g. a padded Falcon half) may still be valid under the
    /// consensus rule, and must not be remembered as invalid there.
    fn failure_key(
        policy: SignaturePolicy,
        pubkey: &[u8],
        root: &[u8; 32],
        signature: &[u8],
    ) -> [u8; 32] {
        let mut hash = Sha3_256::new();
        hash.update(b"bloch-node-gossip-invalid-signature-v2");
        hash.update([policy.tag()]);
        hash.update((pubkey.len() as u64).to_le_bytes());
        hash.update(pubkey);
        hash.update(root);
        hash.update((signature.len() as u64).to_le_bytes());
        hash.update(signature);
        hash.finalize().into()
    }

    /// The failure-cache root of a KES LEAF check: distinct from the plain
    /// root, because a leaf is verified in the bound (v2) form and a triple
    /// that failed one form says nothing about the other.
    pub(super) fn kes_leaf_cache_root(root: &[u8; 32]) -> [u8; 32] {
        let mut hash = Sha3_256::new();
        hash.update(b"bloch-node-kes-leaf-failure-v1");
        hash.update(root);
        hash.finalize().into()
    }

    pub(super) fn is_known_failure(
        &self,
        policy: SignaturePolicy,
        pubkey: &[u8],
        root: &[u8; 32],
        signature: &[u8],
    ) -> bool {
        let key = Self::failure_key(policy, pubkey, root, signature);
        self.failures.borrow().known.contains(&key)
    }

    /// Failure key for the HF3 spend path once the suite gate is open. A
    /// distinct domain, so a suite-0x0003 witness memoized as invalid by the
    /// context-free path (or before the gate) is never served as a cached
    /// failure after it: the verdict sets differ, so the caches must too.
    fn spend_failure_key(pubkey: &[u8], root: &[u8; 32], signature: &[u8], armed: bool) -> [u8; 32] {
        if !armed {
            return Self::failure_key(SignaturePolicy::Compatible, pubkey, root, signature);
        }
        let mut hash = Sha3_256::new();
        hash.update(b"bloch-node-gossip-invalid-spend-signature-hf3-v1");
        hash.update(Self::failure_key(SignaturePolicy::Compatible, pubkey, root, signature));
        hash.finalize().into()
    }

    fn is_known_spend_failure(&self, pubkey: &[u8], root: &[u8; 32], signature: &[u8], armed: bool) -> bool {
        let key = Self::spend_failure_key(pubkey, root, signature, armed);
        self.failures.borrow().known.contains(&key)
    }

    fn remember_failure(&self, key: [u8; 32]) {
        let mut failures = self.failures.borrow_mut();
        if failures.order.len() >= MAX_FAILURES {
            if let Some(oldest) = failures.order.pop_front() {
                failures.known.remove(&oldest);
            }
        }
        failures.known.insert(key);
        failures.order.push_back(key);
    }

    pub(super) fn budgeted(&self, slot: u64, cap: usize) -> BudgetedVerifier<'_, V> {
        BudgetedVerifier {
            owner: self,
            slot,
            cap,
            source: None,
            source_cap: usize::MAX,
            lane: VerificationLane::Relay,
            failure_cap: usize::MAX,
            limited: Cell::new(false),
            failure_limited: Cell::new(false),
        }
    }

    pub(super) fn budgeted_for_source(
        &self,
        slot: u64,
        cap: usize,
        source: Option<[u8; 32]>,
        source_cap: usize,
    ) -> BudgetedVerifier<'_, V> {
        self.budgeted_lane_for_source(slot, VerificationLane::Relay, cap, source, source_cap)
    }

    /// [`Self::budgeted_for_source`] drawing on `lane`'s own allowance.
    pub(super) fn budgeted_lane_for_source(
        &self,
        slot: u64,
        lane: VerificationLane,
        cap: usize,
        source: Option<[u8; 32]>,
        source_cap: usize,
    ) -> BudgetedVerifier<'_, V> {
        BudgetedVerifier {
            owner: self,
            slot,
            cap,
            source,
            source_cap,
            lane,
            failure_cap: usize::MAX,
            limited: Cell::new(false),
            failure_limited: Cell::new(false),
        }
    }

    /// Reserve `units` of this slot's allowance. A unit is one suite-0x0001
    /// hybrid verification; an SLH-DSA-suite verification costs
    /// `fee_market::verify_cost_units` (15) because it burns ~15x the CPU,
    /// so the per-slot ceiling bounds CPU rather than call count.
    fn reserve_verification(
        &self,
        slot: u64,
        lane: VerificationLane,
        cap: usize,
        source: Option<[u8; 32]>,
        source_cap: usize,
        units: usize,
    ) -> bool {
        let mut budget = self.budget.borrow_mut();
        if budget.slot != Some(slot) {
            budget.slot = Some(slot);
            budget.used = [0; LANES];
            budget.by_source.clear();
            budget.failed_by_source.clear();
        }
        let lane = lane.index();
        let units = units.max(1);
        if source.is_some_and(|key| {
            budget.by_source.get(&key).map_or(0, |used| used[lane]).saturating_add(units) > source_cap
        }) {
            return false;
        }
        if budget.used[lane].saturating_add(units) > cap { return false; }
        budget.used[lane] = budget.used[lane].saturating_add(units);
        if let Some(key) = source {
            let used = budget.by_source.entry(key).or_default();
            used[lane] = used[lane].saturating_add(units);
        }
        true
    }

    /// Whether `source` already failed `failure_cap` units of `lane`'s
    /// failure group in `slot`. Unattributed work has no failure allowance;
    /// it stays bounded by the lane ceiling alone.
    fn source_failures_spent(
        &self,
        slot: u64,
        lane: VerificationLane,
        source: Option<[u8; 32]>,
        failure_cap: usize,
    ) -> bool {
        let Some(key) = source else { return false };
        let budget = self.budget.borrow();
        budget.slot == Some(slot)
            && budget.failed_by_source.get(&key)
                .is_some_and(|failed| failed[lane.failure_group()] >= failure_cap)
    }

    /// Charge a verification that ran and failed to the source that sent it.
    fn note_source_failure(
        &self,
        slot: u64,
        lane: VerificationLane,
        source: Option<[u8; 32]>,
        units: usize,
    ) {
        let Some(key) = source else { return };
        let mut budget = self.budget.borrow_mut();
        if budget.slot != Some(slot) { return; }
        let failed = budget.failed_by_source.entry(key).or_default();
        let group = lane.failure_group();
        failed[group] = failed[group].saturating_add(units.max(1));
    }

    /// Remember that block `id` was parked in `slot` only because an
    /// allowance was spent. At most `cap` ids are kept; the oldest is
    /// forgotten first (that block then waits like any other parked block).
    pub(super) fn note_budget_parked_block(&self, slot: u64, id: [u8; 32], cap: usize) {
        let mut parked = self.budget_parked.borrow_mut();
        if parked.iter().any(|(_, seen)| *seen == id) { return; }
        while parked.len() >= cap.max(1) {
            parked.pop_front();
        }
        parked.push_back((slot, id));
    }

    /// Remove and return the ids parked in a slot before `slot`: their
    /// refusal was a statement about an allowance that has since renewed.
    pub(super) fn take_budget_parked_blocks_before(&self, slot: u64) -> Vec<[u8; 32]> {
        let mut parked = self.budget_parked.borrow_mut();
        if !parked.iter().any(|(at, _)| *at < slot) { return Vec::new(); }
        let mut ready = Vec::new();
        parked.retain(|(at, id)| {
            if *at < slot {
                ready.push(*id);
                false
            } else {
                true
            }
        });
        ready
    }

    /// Units spent in `slot` across every lane.
    #[cfg(test)]
    pub(super) fn budget_used_at(&self, slot: u64) -> usize {
        let budget = self.budget.borrow();
        if budget.slot == Some(slot) {
            budget.used.iter().fold(0usize, |sum, used| sum.saturating_add(*used))
        } else {
            0
        }
    }

    #[cfg(test)]
    pub(super) fn lane_used_at(&self, slot: u64, lane: VerificationLane) -> usize {
        let budget = self.budget.borrow();
        if budget.slot == Some(slot) { budget.used[lane.index()] } else { 0 }
    }

    #[cfg(test)]
    pub(super) fn set_panic_on_verification(&self, enabled: bool) {
        self.panic_on_verification.set(enabled);
    }
}

impl<'a, V> BudgetedVerifier<'a, V> {
    pub(super) fn limited(&self) -> bool { self.limited.get() }

    /// Ignore this source, without verification, once `failure_cap` units of
    /// its verifications have failed in this slot. Honest sources essentially
    /// never relay an invalid signature, so invalid input is charged to its
    /// sender instead of draining the allowance every source shares.
    pub(super) fn with_failure_allowance(mut self, failure_cap: usize) -> BudgetedVerifier<'a, V> {
        self.failure_cap = failure_cap;
        self
    }

    /// Whether a verification was refused because this source spent its
    /// failure allowance (implies [`Self::limited`]), as opposed to a spent
    /// unit allowance.
    pub(super) fn failure_limited(&self) -> bool { self.failure_limited.get() }

    /// Reserve `units` for one real verification, or record why not.
    fn admit(&self, units: usize) -> bool {
        if self.owner.source_failures_spent(self.slot, self.lane, self.source, self.failure_cap) {
            self.limited.set(true);
            self.failure_limited.set(true);
            return false;
        }
        if !self.owner.reserve_verification(
            self.slot, self.lane, self.cap, self.source, self.source_cap, units,
        ) {
            self.limited.set(true);
            return false;
        }
        true
    }

    /// Pass a real verification's result through, charging a failure.
    fn settle(&self, verified: bool, units: usize) -> bool {
        if !verified {
            self.owner.note_source_failure(self.slot, self.lane, self.source, units);
        }
        verified
    }
}

impl<V: SignatureVerifier> SignatureVerifier for BudgetedVerifier<'_, V> {
    /// KES leaves: same cache-before-budget order, forwarded to the owner's
    /// leaf hook (bound form), never to `verify_with_key`. One unit.
    fn verify_kes_leaf(&self, pubkey: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
        let cache_root = GossipVerifier::<V>::kes_leaf_cache_root(root);
        if self.owner.is_known_failure(SignaturePolicy::Compatible, pubkey, &cache_root, signature) {
            return false;
        }
        if !self.admit(1) {
            return false;
        }
        self.settle(self.owner.verify_kes_leaf(pubkey, root, signature), 1)
    }

    fn verify_with_key(&self, pubkey: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
        self.verify_with_key_under(SignaturePolicy::Compatible, pubkey, root, signature)
    }

    fn verify_with_key_under(
        &self,
        policy: SignaturePolicy,
        pubkey: &[u8],
        root: &[u8; 32],
        signature: &[u8],
    ) -> bool {
        // Exact known failures remain cheap and deterministic, and consuming
        // no allowance for them preserves the cache-before-budget ordering.
        if self.owner.is_known_failure(policy, pubkey, root, signature) {
            return false;
        }
        // The context-free path never runs an SLH-DSA verification (suite
        // 0x0003 is refused by its suite arm), so it costs one unit as before.
        if !self.admit(1) {
            return false;
        }
        self.settle(self.owner.verify_with_key_under(policy, pubkey, root, signature), 1)
    }

    /// Native L2 settlement proofs at mempool admission. Not memoized here:
    /// the engine bars the refused transaction bytes, which is the exact
    /// replay. Reserves [`L2_PROOF_VERIFICATION_UNITS`] before the pairing
    /// check and forwards to the fixed inner verifier.
    fn verify_l2_settlement(&self, policy: &[u8; 32], program: &[u8; 32], values: &[u8], proof: &[u8]) -> bool {
        if !self.owner.reserve_verification(
            self.slot,
            self.cap,
            self.source,
            self.source_cap,
            L2_PROOF_VERIFICATION_UNITS,
        ) {
            self.limited.set(true);
            return false;
        }
        self.owner.verifier.verify_l2_settlement(policy, program, values, proof)
    }

    /// Spend witnesses at `epoch`. Below HF3 this is exactly
    /// [`Self::verify_with_key`] (one unit). From HF3 a suite-0x0003 witness
    /// reserves `fee_market::verify_cost_units` (15) units, so the per-slot
    /// and per-source ceilings bound CPU rather than call count.
    fn verify_spend_at_epoch(&self, pubkey: &[u8], root: &[u8; 32], signature: &[u8], epoch: u64) -> bool {
        let armed = bloch_pos_committee::params::hf3_slh_suite_active(epoch);
        self.verify_spend_gated(pubkey, root, signature, epoch, armed)
    }
}

impl<V: SignatureVerifier> BudgetedVerifier<'_, V> {
    /// [`SignatureVerifier::verify_spend_at_epoch`] with the HF3 gate decided
    /// by the caller (so tests can drive the armed branch; the shipped gate is
    /// `u64::MAX`).
    fn verify_spend_gated(&self, pubkey: &[u8], root: &[u8; 32], signature: &[u8], epoch: u64, armed: bool) -> bool {
        if !armed {
            return self.verify_with_key(pubkey, root, signature);
        }
        if self.owner.is_known_spend_failure(pubkey, root, signature, true) {
            return false;
        }
        let units = usize::try_from(bloch_pos_committee::fee_market::verify_cost_units(pubkey))
            .unwrap_or(usize::MAX);
        if !self.admit(units) {
            return false;
        }
        self.settle(self.owner.verify_spend_gated(pubkey, root, signature, epoch, true), units)
    }
}

impl<V: SignatureVerifier> SignatureVerifier for GossipVerifier<V> {
    fn verify_with_key(&self, pubkey: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
        self.verify_with_key_under(SignaturePolicy::Compatible, pubkey, root, signature)
    }

    fn verify_with_key_under(
        &self,
        policy: SignaturePolicy,
        pubkey: &[u8],
        root: &[u8; 32],
        signature: &[u8],
    ) -> bool {
        #[cfg(test)]
        assert!(
            !self.panic_on_verification.get(),
            "deferred authenticated block must not repeat gossip verification"
        );
        let key = Self::failure_key(policy, pubkey, root, signature);
        if self.failures.borrow().known.contains(&key) {
            return false;
        }
        // Release the cache borrow before calling cryptographic code.
        if self.verifier.verify_with_key_under(policy, pubkey, root, signature) {
            return true;
        }
        let mut failures = self.failures.borrow_mut();
        if failures.order.len() >= MAX_FAILURES {
            if let Some(oldest) = failures.order.pop_front() {
                failures.known.remove(&oldest);
            }
        }
        failures.known.insert(key);
        failures.order.push_back(key);
        false
    }

    /// KES leaves: cached under their own root domain and forwarded to the
    /// inner verifier's leaf hook (bound form).
    fn verify_kes_leaf(&self, pubkey: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
        #[cfg(test)]
        assert!(
            !self.panic_on_verification.get(),
            "deferred authenticated block must not repeat gossip verification"
        );
        let key = Self::failure_key(SignaturePolicy::Compatible, pubkey, &Self::kes_leaf_cache_root(root), signature);
        if self.failures.borrow().known.contains(&key) {
            return false;
        }
        if self.verifier.verify_kes_leaf(pubkey, root, signature) {
            return true;
        }
        self.remember_failure(key);
        false
    }

    /// HF3 spend path: below the gate exactly [`Self::verify_with_key`]; from
    /// it the inner verifier's epoch-aware method, memoizing failures under
    /// the gate-specific key ([`Self::spend_failure_key`]).
    fn verify_spend_at_epoch(&self, pubkey: &[u8], root: &[u8; 32], signature: &[u8], epoch: u64) -> bool {
        let armed = bloch_pos_committee::params::hf3_slh_suite_active(epoch);
        self.verify_spend_gated(pubkey, root, signature, epoch, armed)
    }
}

impl<V: SignatureVerifier> GossipVerifier<V> {
    fn verify_spend_gated(&self, pubkey: &[u8], root: &[u8; 32], signature: &[u8], epoch: u64, armed: bool) -> bool {
        if !armed {
            return self.verify_with_key(pubkey, root, signature);
        }
        #[cfg(test)]
        assert!(
            !self.panic_on_verification.get(),
            "deferred authenticated block must not repeat gossip verification"
        );
        let key = Self::spend_failure_key(pubkey, root, signature, true);
        if self.failures.borrow().known.contains(&key) {
            return false;
        }
        if self.verifier.verify_spend_at_epoch(pubkey, root, signature, epoch) {
            return true;
        }
        self.remember_failure(key);
        false
    }
}

#[cfg(test)]
pub(super) struct CountedHybrid(std::rc::Rc<std::cell::Cell<usize>>);

#[cfg(test)]
impl SignatureVerifier for CountedHybrid {
    fn verify_with_key(&self, key: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
        self.0.set(self.0.get().saturating_add(1));
        crate::keys::HybridVerifier::new().verify_with_key(key, root, signature)
    }

    fn verify_with_key_under(
        &self,
        policy: SignaturePolicy,
        key: &[u8],
        root: &[u8; 32],
        signature: &[u8],
    ) -> bool {
        self.0.set(self.0.get().saturating_add(1));
        crate::keys::HybridVerifier::new().verify_with_key_under(policy, key, root, signature)
    }

    fn verify_kes_leaf(&self, key: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
        self.0.set(self.0.get().saturating_add(1));
        crate::keys::HybridVerifier::new().verify_kes_leaf(key, root, signature)
    }
}

#[cfg(test)]
pub(super) fn counted_hybrid() -> (GossipVerifier<CountedHybrid>, std::rc::Rc<std::cell::Cell<usize>>) {
    let calls = std::rc::Rc::new(std::cell::Cell::new(0));
    (GossipVerifier::new(CountedHybrid(calls.clone())), calls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A failure remembered under the strict relay policy must not become a
    /// failure under the consensus rule: the padded form is refused for relay
    /// yet stays consensus-valid until the flag day.
    #[test]
    fn failure_cache_is_keyed_by_signature_policy() {
        use bloch_crypto::crypto::{falcon, MLDSA_SIG_LEN, SUITE_HEADER_LEN};
        let (pk, sk) = bloch_crypto::crypto::generate_keypair();
        let root = [0x6Cu8; 32];
        let padded_len = SUITE_HEADER_LEN + MLDSA_SIG_LEN + falcon::padded_signature_len();
        let mut sig = (0..64)
            .map(|_| bloch_crypto::crypto::sign(&sk, &root).unwrap())
            .find(|s| s.len() < padded_len)
            .unwrap();
        sig.resize(padded_len, 0);
        let (verifier, calls) = counted_hybrid();
        let budget = verifier.budgeted(5, 16);
        assert!(!budget.verify_with_key_under(SignaturePolicy::CanonicalUnbound, &pk, &root, &sig));
        assert!(verifier.is_known_failure(SignaturePolicy::CanonicalUnbound, &pk, &root, &sig));
        assert!(!verifier.is_known_failure(SignaturePolicy::Compatible, &pk, &root, &sig));
        assert!(budget.verify_with_key(&pk, &root, &sig), "compatible verdict is independent");
        assert!(!budget.verify_with_key_under(SignaturePolicy::CanonicalUnbound, &pk, &root, &sig));
        assert_eq!(calls.get(), 2, "the strict failure is served from the cache");
    }

    struct CountingVerifier { calls: Cell<usize> }

    impl SignatureVerifier for CountingVerifier {
        fn verify_with_key(&self, pk: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
            self.calls.set(self.calls.get() + 1);
            pk == b"registered key" && signature == root
        }
    }

    fn fixture() -> GossipVerifier<CountingVerifier> {
        GossipVerifier::new(CountingVerifier { calls: Cell::new(0) })
    }

    #[test]
    fn audit_invalid_signature_repeats_skip_crypto_but_changed_context_retries() {
        let verifier = fixture();
        let root = [1; 32];
        for _ in 0..32 {
            assert!(!verifier.verify_with_key(b"old branch key", &root, &root));
        }
        assert_eq!(verifier.verifier.calls.get(), 1);
        // A newly admitted or branch-corrected key must not inherit another
        // key's failed verification of the exact same root and signature.
        assert!(verifier.verify_with_key(b"registered key", &root, &root));
        assert_eq!(verifier.verifier.calls.get(), 2);
        let other_root = [2; 32];
        assert!(!verifier.verify_with_key(b"registered key", &other_root, &root));
        assert_eq!(verifier.verifier.calls.get(), 3);
        assert!(verifier.verify_with_key(b"registered key", &other_root, &other_root));
        assert_eq!(verifier.verifier.calls.get(), 4);
        // Successes are never memoized, so later state-dependent policy has
        // no cached acceptance to accidentally bypass.
        assert!(verifier.verify_with_key(b"registered key", &other_root, &other_root));
        assert_eq!(verifier.verifier.calls.get(), 5);
    }

    #[test]
    fn audit_invalid_signature_cache_has_deterministic_bounded_fifo_eviction() {
        let verifier = fixture();
        for index in 0..=MAX_FAILURES {
            assert!(!verifier.verify_with_key(b"invalid key", &[0; 32], &index.to_le_bytes()));
        }
        let failures = verifier.failures.borrow();
        assert_eq!(failures.known.len(), MAX_FAILURES);
        assert_eq!(failures.order.len(), MAX_FAILURES);
        drop(failures);
        let calls = verifier.verifier.calls.get();
        assert!(!verifier.verify_with_key(b"invalid key", &[0; 32], &MAX_FAILURES.to_le_bytes()));
        assert_eq!(verifier.verifier.calls.get(), calls);
        assert!(!verifier.verify_with_key(b"invalid key", &[0; 32], &0usize.to_le_bytes()));
        assert_eq!(verifier.verifier.calls.get(), calls + 1);
        assert_eq!(verifier.failures.borrow().known.len(), MAX_FAILURES);
    }

    #[test]
    fn slot_budget_counts_unique_crypto_not_cached_failures_and_renews() {
        let verifier = fixture();
        let bad = [0xA5; 32];
        let bad_signature = [0xCC; 32];
        {
            let bounded = verifier.budgeted(70, 1);
            assert!(!bounded.verify_with_key(b"registered key", &bad, &bad_signature));
            assert!(!bounded.limited(), "the one real call fits the allowance");
        }
        assert_eq!(verifier.verifier.calls.get(), 1);

        // Exact failure is answered by the cache and consumes no new call or
        // allowance. A distinct input in the same slot is locally limited.
        let bounded = verifier.budgeted(70, 1);
        assert!(!bounded.verify_with_key(b"registered key", &bad, &bad_signature));
        assert!(!bounded.limited());
        let other = [0x5A; 32];
        assert!(!bounded.verify_with_key(b"registered key", &other, &bad_signature));
        assert!(bounded.limited());
        assert_eq!(verifier.verifier.calls.get(), 1);
        drop(bounded);

        // The owner's ordinary verifier remains outside relay admission. The
        // node's own proposal path and consensus verifier must not inherit a
        // local gossip-shedding decision.
        let local = [0x11; 32];
        assert!(verifier.verify_with_key(b"registered key", &local, &local));
        assert_eq!(verifier.verifier.calls.get(), 2);

        let renewed = verifier.budgeted(71, 1);
        assert!(renewed.verify_with_key(b"registered key", &other, &other));
        assert!(!renewed.limited());
        assert_eq!(verifier.verifier.calls.get(), 3);
    }

    #[test]
    fn one_source_cannot_spend_another_sources_slot_allowance() {
        let verifier = fixture();
        let noisy = [0x01; 32];
        let honest = [0x02; 32];
        let signature = [0xCC; 32];

        for n in 0u8..2 {
            let root = [n; 32];
            let bounded = verifier.budgeted_for_source(90, 4, Some(noisy), 2);
            assert!(!bounded.verify_with_key(b"registered key", &root, &signature));
            assert!(!bounded.limited());
        }
        let noisy_limited = verifier.budgeted_for_source(90, 4, Some(noisy), 2);
        assert!(!noisy_limited.verify_with_key(b"registered key", &[3; 32], &signature));
        assert!(noisy_limited.limited());
        drop(noisy_limited);

        let honest_admitted = verifier.budgeted_for_source(90, 4, Some(honest), 2);
        assert!(!honest_admitted.verify_with_key(b"registered key", &[4; 32], &signature));
        assert!(!honest_admitted.limited(), "another source retains aggregate headroom");
        assert_eq!(verifier.verifier.calls.get(), 3);
    }

    /// A suite-0x0003-SHAPED key (envelope header, exact length).
    fn slh_key() -> Vec<u8> {
        let mut k = vec![0xB1, 0x0C, 0x03, 0x00];
        k.resize(bloch_pos_committee::fee_market::SLHDSA_FALCON_ENVELOPED_PUBKEY_LEN, 0x42);
        k
    }

    /// The fleet's configuration: HF3 is off, so the spend entry point is the
    /// context-free one — one unit per call, same cache — whatever the key.
    #[test]
    fn spend_path_below_hf3_is_the_context_free_path() {
        assert_eq!(bloch_pos_committee::params::HF3_SLH_SUITE_EPOCH, 7360);
        let verifier = fixture();
        for n in 0u8..3 {
            let bounded = verifier.budgeted_for_source(90, 3, Some([1; 32]), 3);
            assert!(!bounded.verify_spend_at_epoch(&slh_key(), &[n; 32], &[0xCC; 8], 7_359));
            assert!(!bounded.limited());
        }
        assert_eq!(verifier.budget_used_at(90), 3, "one unit per SLH-shaped call below HF3");
        assert_eq!(verifier.verifier.calls.get(), 3);
        let shed = verifier.budgeted_for_source(90, 3, Some([1; 32]), 3);
        assert!(!shed.verify_spend_at_epoch(b"registered key", &[7; 32], &[7; 32], 0));
        assert!(shed.limited());
    }

    #[test]
    fn armed_slh_spend_verification_spends_cpu_weighted_allowance() {
        let verifier = fixture();
        let source = [0x0A; 32];
        let units = bloch_pos_committee::fee_market::verify_cost_units(&slh_key()) as usize;
        assert_eq!(units, 15);
        assert_eq!(bloch_pos_committee::fee_market::verify_cost_units(b"registered key"), 1);
        // Two SLH verifications fit a 30-unit allowance; a third does not,
        // and is shed without reaching the cryptographic verifier.
        for n in 0u8..2 {
            let bounded = verifier.budgeted_for_source(92, 30, Some(source), 30);
            assert!(!bounded.verify_spend_gated(&slh_key(), &[n; 32], &[0xCC; 8], 5, true));
            assert!(!bounded.limited());
        }
        assert_eq!(verifier.budget_used_at(92), 2 * units);
        let shed = verifier.budgeted_for_source(92, 30, Some(source), 30);
        assert!(!shed.verify_spend_gated(&slh_key(), &[9; 32], &[0xCC; 8], 5, true));
        assert!(shed.limited());
        drop(shed);
        assert_eq!(verifier.verifier.calls.get(), 2);
        // A hybrid verification is still one unit and is not starved by the
        // weighting when the aggregate still has room for it.
        let other = verifier.budgeted_for_source(93, 30, Some(source), 30);
        assert!(other.verify_spend_gated(b"registered key", &[7; 32], &[7; 32], 5, true));
        assert!(!other.limited());
        drop(other);
        assert_eq!(verifier.budget_used_at(93), 1);
        // A replayed armed failure is served from the cache at no allowance.
        let replay = verifier.budgeted_for_source(94, 30, Some(source), 30);
        assert!(!replay.verify_spend_gated(&slh_key(), &[0; 32], &[0xCC; 8], 5, true));
        assert_eq!(verifier.budget_used_at(94), 0);
        assert_eq!(verifier.verifier.calls.get(), 3);
    }

    /// A witness memoized as invalid by the context-free path (e.g. a
    /// suite-0x0003 spend seen before HF3) must not be served as a cached
    /// failure on the armed spend path, whose verdict set is larger.
    #[test]
    fn armed_spend_path_does_not_inherit_pre_hf3_failures() {
        struct EpochAware(Cell<usize>);
        impl SignatureVerifier for EpochAware {
            fn verify_with_key(&self, _: &[u8], _: &[u8; 32], _: &[u8]) -> bool { false }
            fn verify_spend_at_epoch(&self, _: &[u8], _: &[u8; 32], _: &[u8], _: u64) -> bool {
                self.0.set(self.0.get() + 1);
                true
            }
        }
        let verifier = GossipVerifier::new(EpochAware(Cell::new(0)));
        let (pk, root, sig) = (slh_key(), [3u8; 32], [4u8; 9]);
        assert!(!verifier.verify_with_key(&pk, &root, &sig));
        assert!(verifier.is_known_failure(SignaturePolicy::Compatible, &pk, &root, &sig));
        assert!(!verifier.verify_spend_gated(&pk, &root, &sig, 9, false), "below HF3: same cache");
        assert!(verifier.verify_spend_gated(&pk, &root, &sig, 9, true), "armed: fresh verdict");
        assert_eq!(verifier.verifier.0.get(), 1);
    }

    /// Votes and transactions draw on the relay lane; spending all of it
    /// leaves both block lanes untouched, and gossiped blocks cannot spend
    /// the lane reserved for directed sync.
    #[test]
    fn lanes_are_independent_allowances() {
        let verifier = fixture();
        let ok = |n: u8| [n; 32];
        for n in 0u8..4 {
            let relay = verifier.budgeted_for_source(95, 4, Some([1; 32]), 4);
            assert!(relay.verify_with_key(b"registered key", &ok(n), &ok(n)));
        }
        let relay = verifier.budgeted_for_source(95, 4, Some([2; 32]), 4);
        assert!(!relay.verify_with_key(b"registered key", &ok(9), &ok(9)));
        assert!(relay.limited() && !relay.failure_limited());
        drop(relay);

        for n in 10u8..12 {
            let gossip = verifier.budgeted_lane_for_source(
                95, VerificationLane::GossipBlock, 2, Some([1; 32]), 2,
            );
            assert!(gossip.verify_with_key(b"registered key", &ok(n), &ok(n)));
            assert!(!gossip.limited(), "the spent relay lane does not limit a block");
        }
        let gossip = verifier.budgeted_lane_for_source(
            95, VerificationLane::GossipBlock, 2, Some([3; 32]), 2,
        );
        assert!(!gossip.verify_with_key(b"registered key", &ok(12), &ok(12)));
        assert!(gossip.limited());
        drop(gossip);

        let directed = verifier.budgeted_lane_for_source(
            95, VerificationLane::DirectedBlock, 2, Some([1; 32]), 2,
        );
        assert!(directed.verify_with_key(b"registered key", &ok(13), &ok(13)));
        assert!(!directed.limited(), "gossiped blocks cannot spend the directed lane");
        drop(directed);
        assert_eq!(verifier.lane_used_at(95, VerificationLane::Relay), 4);
        assert_eq!(verifier.lane_used_at(95, VerificationLane::GossipBlock), 2);
        assert_eq!(verifier.lane_used_at(95, VerificationLane::DirectedBlock), 1);
        assert_eq!(verifier.budget_used_at(95), 7);
    }

    /// A source that exceeds its failure allowance is ignored for the rest of
    /// the slot without reaching the verifier or spending shared units, even
    /// for input that would have verified. Other sources, the other failure
    /// group and the next slot are unaffected.
    #[test]
    fn source_past_its_failure_allowance_is_ignored_without_spending_units() {
        let verifier = fixture();
        let noisy = [0x0B; 32];
        let honest = [0x0C; 32];
        let bad = [0xCC; 32];
        for n in 0u8..2 {
            let relay = verifier.budgeted_for_source(96, 100, Some(noisy), 100)
                .with_failure_allowance(2);
            assert!(!relay.verify_with_key(b"registered key", &[n; 32], &bad));
            assert!(!relay.limited(), "failures inside the allowance are judged");
        }
        assert_eq!(verifier.budget_used_at(96), 2);
        assert_eq!(verifier.verifier.calls.get(), 2);

        for n in 2u8..40 {
            let relay = verifier.budgeted_for_source(96, 100, Some(noisy), 100)
                .with_failure_allowance(2);
            assert!(!relay.verify_with_key(b"registered key", &[n; 32], &bad));
            assert!(relay.limited() && relay.failure_limited());
            // Even a valid signature from this source waits for the next slot.
            assert!(!relay.verify_with_key(b"registered key", &[n; 32], &[n; 32]));
            assert!(!relay.verify_kes_leaf(b"registered key", &[n; 32], &bad));
            assert!(!relay.verify_spend_gated(b"registered key", &[n; 32], &bad, 5, true));
        }
        assert_eq!(verifier.budget_used_at(96), 2, "no shared unit was spent");
        assert_eq!(verifier.verifier.calls.get(), 2, "and no cryptography ran");

        // A remembered failure is still answered as a failure, not as limited.
        let replay = verifier.budgeted_for_source(96, 100, Some(noisy), 100)
            .with_failure_allowance(2);
        assert!(!replay.verify_with_key(b"registered key", &[0; 32], &bad));
        assert!(!replay.limited());
        drop(replay);

        // Relay failures do not close the same source's block lanes.
        let block = verifier.budgeted_lane_for_source(
            96, VerificationLane::GossipBlock, 100, Some(noisy), 100,
        ).with_failure_allowance(2);
        assert!(block.verify_with_key(b"registered key", &[50; 32], &[50; 32]));
        assert!(!block.limited());
        drop(block);
        // Block failures are shared by both block lanes.
        for n in 60u8..62 {
            let block = verifier.budgeted_lane_for_source(
                96, VerificationLane::GossipBlock, 100, Some(noisy), 100,
            ).with_failure_allowance(2);
            assert!(!block.verify_with_key(b"registered key", &[n; 32], &bad));
            assert!(!block.limited());
        }
        let directed = verifier.budgeted_lane_for_source(
            96, VerificationLane::DirectedBlock, 100, Some(noisy), 100,
        ).with_failure_allowance(2);
        assert!(!directed.verify_with_key(b"registered key", &[70; 32], &[70; 32]));
        assert!(directed.failure_limited());
        drop(directed);

        let other = verifier.budgeted_for_source(96, 100, Some(honest), 100)
            .with_failure_allowance(2);
        assert!(other.verify_with_key(b"registered key", &[80; 32], &[80; 32]));
        assert!(!other.limited(), "another source is judged normally");
        drop(other);

        let renewed = verifier.budgeted_for_source(97, 100, Some(noisy), 100)
            .with_failure_allowance(2);
        assert!(renewed.verify_with_key(b"registered key", &[90; 32], &[90; 32]));
        assert!(!renewed.limited(), "the failure allowance renews with the slot");
    }

    #[test]
    fn budget_parked_block_ids_are_bounded_and_released_only_after_their_slot() {
        let verifier = fixture();
        verifier.note_budget_parked_block(10, [1; 32], 2);
        verifier.note_budget_parked_block(10, [1; 32], 2);
        verifier.note_budget_parked_block(11, [2; 32], 2);
        assert!(verifier.take_budget_parked_blocks_before(10).is_empty());
        assert_eq!(verifier.take_budget_parked_blocks_before(11), vec![[1u8; 32]]);
        assert!(verifier.take_budget_parked_blocks_before(11).is_empty());
        verifier.note_budget_parked_block(11, [3; 32], 2);
        verifier.note_budget_parked_block(11, [4; 32], 2);
        assert_eq!(
            verifier.take_budget_parked_blocks_before(12),
            vec![[3u8; 32], [4u8; 32]],
            "the oldest id is forgotten at the cap",
        );
    }

    /// A settlement proof draws on the same per-source and per-slot
    /// allowance as signatures, at its own weight, and a source that has
    /// spent its share is shed before the proof verifier runs.
    #[test]
    fn l2_proof_verification_spends_weighted_source_allowance() {
        struct Proofs(Cell<usize>);
        impl SignatureVerifier for Proofs {
            fn verify_with_key(&self, _: &[u8], _: &[u8; 32], _: &[u8]) -> bool { false }
            fn verify_l2_settlement(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8], proof: &[u8]) -> bool {
                self.0.set(self.0.get() + 1);
                proof == [1]
            }
        }
        let verifier = GossipVerifier::new(Proofs(Cell::new(0)));
        let (noisy, honest) = ([0x0B; 32], [0x0C; 32]);
        let (cap, source_cap) = (4 * L2_PROOF_VERIFICATION_UNITS, 2 * L2_PROOF_VERIFICATION_UNITS);
        for n in 0u8..2 {
            let bounded = verifier.budgeted_for_source(95, cap, Some(noisy), source_cap);
            assert!(!bounded.verify_l2_settlement(&[0; 32], &[0; 32], &[n], &[2]));
            assert!(!bounded.limited(), "an invalid proof within the allowance is invalid, not limited");
        }
        assert_eq!(verifier.budget_used_at(95), 2 * L2_PROOF_VERIFICATION_UNITS);
        let shed = verifier.budgeted_for_source(95, cap, Some(noisy), source_cap);
        assert!(!shed.verify_l2_settlement(&[0; 32], &[0; 32], &[9], &[1]));
        assert!(shed.limited());
        drop(shed);
        assert_eq!(verifier.verifier.0.get(), 2, "the shed proof never reached the verifier");
        // Another source keeps its share, and a valid proof passes.
        let other = verifier.budgeted_for_source(95, cap, Some(honest), source_cap);
        assert!(other.verify_l2_settlement(&[0; 32], &[0; 32], &[9], &[1]));
        assert!(!other.limited());
        drop(other);
        assert_eq!(verifier.budget_used_at(95), 3 * L2_PROOF_VERIFICATION_UNITS);
        // A source with less than one proof of allowance left is shed too.
        let partial = verifier.budgeted_for_source(96, cap, Some(honest), L2_PROOF_VERIFICATION_UNITS - 1);
        assert!(!partial.verify_l2_settlement(&[0; 32], &[0; 32], &[9], &[1]));
        assert!(partial.limited());
        assert!(L2_PROOF_VERIFICATION_UNITS <= super::super::GOSSIP_VERIFICATIONS_PER_SOURCE_PER_SLOT);
    }

    #[test]
    fn cached_failure_does_not_reconsume_source_or_aggregate_allowance() {
        let verifier = fixture();
        let noisy = [0x11; 32];
        let honest = [0x22; 32];
        let bad_root = [0x33; 32];
        let bad_signature = [0x44; 32];

        let first = verifier.budgeted_for_source(91, 2, Some(noisy), 1);
        assert!(!first.verify_with_key(b"registered key", &bad_root, &bad_signature));
        assert!(!first.limited());
        drop(first);

        // The same exact failure is answered before either quota is checked,
        // even though this source has spent its one real verification.
        let cached = verifier.budgeted_for_source(91, 2, Some(noisy), 1);
        assert!(!cached.verify_with_key(b"registered key", &bad_root, &bad_signature));
        assert!(!cached.limited());
        drop(cached);

        let honest_root = [0x55; 32];
        let honest_call = verifier.budgeted_for_source(91, 2, Some(honest), 1);
        assert!(!honest_call.verify_with_key(
            b"registered key",
            &honest_root,
            &bad_signature,
        ));
        assert!(!honest_call.limited());
        assert_eq!(verifier.verifier.calls.get(), 2);
    }
}
