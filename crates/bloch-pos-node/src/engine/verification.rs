// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded memoization of cryptographic failures at network/mempool admission.
//!
//! This is not a transaction, validator, or block rejection cache. The exact
//! public key, signing root, and signature determine each entry. Registry,
//! committee, clock, missing-parent, and admission failures never enter it.
//! Consensus execution continues to use its independent, uncached verifier.
use bloch_pos_committee::attestation::SignatureVerifier;
use sha3::{Digest, Sha3_256};
use std::cell::RefCell;
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
}

impl<V> GossipVerifier<V> {
    pub(super) fn new(verifier: V) -> Self {
        Self { verifier, failures: RefCell::new(Failures::default()) }
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
}
