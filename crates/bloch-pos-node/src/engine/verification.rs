// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded memoization of cryptographic failures at network/mempool admission.
//!
//! This is not a transaction, validator, or block rejection cache. The exact
//! public key, signing root, and signature determine each entry. Registry,
//! committee, clock, missing-parent, and admission failures never enter it.
//! Consensus execution continues to use its independent, uncached verifier.
use bloch_pos_committee::attestation::SignatureVerifier;
use sha3::{Digest, Sha3_256};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, VecDeque};

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
}

#[derive(Default)]
struct SlotBudget {
    slot: Option<u64>,
    used: usize,
}

/// One node-local admission view of [`GossipVerifier`]. Exhaustion is exposed
/// separately from an invalid signature so callers can shed with `Ignore`
/// rather than mis-score an honest peer during local overload.
pub(super) struct BudgetedVerifier<'a, V> {
    owner: &'a GossipVerifier<V>,
    slot: u64,
    cap: usize,
    limited: Cell<bool>,
}

impl<V> GossipVerifier<V> {
    pub(super) fn new(verifier: V) -> Self {
        Self {
            verifier,
            failures: RefCell::new(Failures::default()),
            budget: RefCell::new(SlotBudget::default()),
        }
    }

    fn failure_key(pubkey: &[u8], root: &[u8; 32], signature: &[u8]) -> [u8; 32] {
        let mut hash = Sha3_256::new();
        hash.update(b"bloch-node-gossip-invalid-signature-v1");
        hash.update((pubkey.len() as u64).to_le_bytes());
        hash.update(pubkey);
        hash.update(root);
        hash.update((signature.len() as u64).to_le_bytes());
        hash.update(signature);
        hash.finalize().into()
    }

    pub(super) fn is_known_failure(
        &self,
        pubkey: &[u8],
        root: &[u8; 32],
        signature: &[u8],
    ) -> bool {
        let key = Self::failure_key(pubkey, root, signature);
        self.failures.borrow().known.contains(&key)
    }

    pub(super) fn budgeted(&self, slot: u64, cap: usize) -> BudgetedVerifier<'_, V> {
        BudgetedVerifier { owner: self, slot, cap, limited: Cell::new(false) }
    }

    fn reserve_verification(&self, slot: u64, cap: usize) -> bool {
        let mut budget = self.budget.borrow_mut();
        if budget.slot != Some(slot) {
            budget.slot = Some(slot);
            budget.used = 0;
        }
        if budget.used >= cap { return false; }
        budget.used = budget.used.saturating_add(1);
        true
    }
}

impl<V> BudgetedVerifier<'_, V> {
    pub(super) fn limited(&self) -> bool { self.limited.get() }
}

impl<V: SignatureVerifier> SignatureVerifier for BudgetedVerifier<'_, V> {
    fn verify_with_key(&self, pubkey: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
        // Exact known failures remain cheap and deterministic, and consuming
        // no allowance for them preserves the cache-before-budget ordering.
        if self.owner.is_known_failure(pubkey, root, signature) {
            return false;
        }
        if !self.owner.reserve_verification(self.slot, self.cap) {
            self.limited.set(true);
            return false;
        }
        self.owner.verify_with_key(pubkey, root, signature)
    }
}

impl<V: SignatureVerifier> SignatureVerifier for GossipVerifier<V> {
    fn verify_with_key(&self, pubkey: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
        let key = Self::failure_key(pubkey, root, signature);
        if self.failures.borrow().known.contains(&key) {
            return false;
        }
        // Release the cache borrow before calling cryptographic code.
        if self.verifier.verify_with_key(pubkey, root, signature) {
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
}

#[cfg(test)]
pub(super) struct CountedHybrid(std::rc::Rc<std::cell::Cell<usize>>);

#[cfg(test)]
impl SignatureVerifier for CountedHybrid {
    fn verify_with_key(&self, key: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
        self.0.set(self.0.get().saturating_add(1));
        crate::keys::HybridVerifier::new().verify_with_key(key, root, signature)
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
}
