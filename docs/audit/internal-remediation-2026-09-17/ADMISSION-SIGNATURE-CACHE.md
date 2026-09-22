# EN-07 / NET-04: repeated invalid transaction signatures (partial)

Date: 2026-09-17. This extends the existing node-local, bounded failed-signature
cache to transaction admission. Consensus execution remains independently
verified and uncached.

The engine supplies its existing `GossipVerifier` to a verifier-parameterized
admission helper for legacy transfers, V2 witness transfers, and funded deposit
authorizations. State-aware lifecycle admission uses the same verifier. The
public stateless `admissible(tx, epoch)` entry point remains available and uses
a fresh `HybridVerifier`.

`HybridVerifier::verify_with_key` invokes the same `bloch_crypto::crypto::verify`
that transfer admission called previously. Signature suite selection, legacy
encoding dispatch, domain roots, gates, and structural checks are unchanged.
Only a cryptographic `false` result for the exact length-delimited public key,
32-byte root, and signature is memoized. Epoch, expiry, missing state, ownership,
committee, and other contextual refusals never become cache entries. Successful
signatures are always verified again.

The existing 4,096-entry FIFO/set bound remains shared across block, attestation,
and transaction verification; no unbounded transaction-identity cache is added.
A corrected signature, changed signing root, or changed public key is a distinct
verification input and remains retryable. Eviction only repeats work; it cannot
turn a failure into acceptance.

Two final real-hybrid regression tests passed in
`/private/tmp/bloch-wave8-admission-negative-cache-final.log`. They exercise
legacy/V2 repeated forgeries with counted underlying verifications, corrected
signatures, different roots/keys, and funded deposits at the actual activation
epoch **2884**. The funded test checks pre-gate/expired refusals do not invoke
cryptography, then validates corrected real candidates (including another
joining key) against the rolled committed state. Existing tests separately pin
bounded eviction and exact cache bindings.

This remains partial mitigation. Unique invalid signatures still consume
verification work; successful prefixes of a transaction are checked again;
capacity/state checks and logging have their own costs. Neither a verification
rate limit nor a protection against many malicious peer identities is claimed.
