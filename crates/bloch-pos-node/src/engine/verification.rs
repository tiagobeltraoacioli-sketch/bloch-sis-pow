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
    #[cfg(test)]
    panic_on_verification: Cell<bool>,
}

#[derive(Default)]
struct SlotBudget {
    slot: Option<u64>,
    used: usize,
    by_source: BTreeMap<[u8; 32], usize>,
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
    limited: Cell<bool>,
}

impl<V> GossipVerifier<V> {
    pub(super) fn new(verifier: V) -> Self {
        Self {
            verifier,
            failures: RefCell::new(Failures::default()),
            budget: RefCell::new(SlotBudget::default()),
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
            limited: Cell::new(false),
        }
    }

    pub(super) fn budgeted_for_source(
        &self,
        slot: u64,
        cap: usize,
        source: Option<[u8; 32]>,
        source_cap: usize,
    ) -> BudgetedVerifier<'_, V> {
        BudgetedVerifier { owner: self, slot, cap, source, source_cap, limited: Cell::new(false) }
    }

    /// Reserve `units` of this slot's allowance. A unit is one suite-0x0001
    /// hybrid verification; an SLH-DSA-suite verification costs
    /// `fee_market::verify_cost_units` (15) because it burns ~15x the CPU,
    /// so the per-slot ceiling bounds CPU rather than call count.
    fn reserve_verification(
        &self,
        slot: u64,
        cap: usize,
        source: Option<[u8; 32]>,
        source_cap: usize,
        units: usize,
    ) -> bool {
        let mut budget = self.budget.borrow_mut();
        if budget.slot != Some(slot) {
            budget.slot = Some(slot);
            budget.used = 0;
            budget.by_source.clear();
        }
        let units = units.max(1);
        if source.is_some_and(|key| {
            budget.by_source.get(&key).copied().unwrap_or(0).saturating_add(units) > source_cap
        }) {
            return false;
        }
        if budget.used.saturating_add(units) > cap { return false; }
        budget.used = budget.used.saturating_add(units);
        if let Some(key) = source {
            let used = budget.by_source.entry(key).or_default();
            *used = used.saturating_add(units);
        }
        true
    }

    #[cfg(test)]
    pub(super) fn budget_used_at(&self, slot: u64) -> usize {
        let budget = self.budget.borrow();
        if budget.slot == Some(slot) { budget.used } else { 0 }
    }

    #[cfg(test)]
    pub(super) fn set_panic_on_verification(&self, enabled: bool) {
        self.panic_on_verification.set(enabled);
    }
}

impl<V> BudgetedVerifier<'_, V> {
    pub(super) fn limited(&self) -> bool { self.limited.get() }
}

impl<V: SignatureVerifier> SignatureVerifier for BudgetedVerifier<'_, V> {
    /// KES leaves: same cache-before-budget order, forwarded to the owner's
    /// leaf hook (bound form), never to `verify_with_key`. One unit.
    fn verify_kes_leaf(&self, pubkey: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
        let cache_root = GossipVerifier::<V>::kes_leaf_cache_root(root);
        if self.owner.is_known_failure(SignaturePolicy::Compatible, pubkey, &cache_root, signature) {
            return false;
        }
        if !self.owner.reserve_verification(self.slot, self.cap, self.source, self.source_cap, 1) {
            self.limited.set(true);
            return false;
        }
        self.owner.verify_kes_leaf(pubkey, root, signature)
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
        if !self.owner.reserve_verification(self.slot, self.cap, self.source, self.source_cap, 1) {
            self.limited.set(true);
            return false;
        }
        self.owner.verify_with_key_under(policy, pubkey, root, signature)
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
        if !self.owner.reserve_verification(self.slot, self.cap, self.source, self.source_cap, units) {
            self.limited.set(true);
            return false;
        }
        self.owner.verify_spend_gated(pubkey, root, signature, epoch, true)
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
