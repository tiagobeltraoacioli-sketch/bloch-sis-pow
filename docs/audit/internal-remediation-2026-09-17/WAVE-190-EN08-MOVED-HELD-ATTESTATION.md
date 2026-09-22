# Wave 190 — EN-08 moved held-attestation extraction

Date: 2026-09-19
Comparison base: `49abbbd9`

## Finding

`AttestationPool::take_authenticated_waiting_on_limit` cloned each retained
`Attestation`, including its variable-length hybrid signature, and immediately
evicted the original pending entry. The pending pool is bounded, but draining a
full pool could still copy the signature payload of up to 256 entries over the
drain solely to transfer ownership to the authenticated replay path.

## Correction

Pending removal now has one private authority, `remove_pending`, which removes
all indexes and returns the sole owned `PendingEntry`. Authenticated extraction
moves the attestation, source, and verified-key fingerprint into the opaque
`AuthenticatedPendingAttestation`; ordinary eviction discards the same returned
entry through a thin `evict` wrapper.

This removes the proportional signature clone at the pending-to-replay boundary.
It does not claim an exact heap/RSS reduction.

## Preserved invariants

- the sequence-indexed set remains the FIFO authority, including limited
  extraction and the `remains` signal;
- duty, root, source, source/root, unattributed, and duplicate-key indexes are
  decremented/removed exactly once through the same cleanup body;
- source identity and the verified public-key fingerprint stay bound to the
  moved attestation inside the existing private, non-forgeable replay token;
- capacity eviction, pruning, re-hold behavior, gossip decisions, signature
  verification, and `Ignore` semantics are unchanged;
- no wire, persistence, public API, protocol, consensus, or peer-verdict format
  changes were introduced.

## Adversarial regression

`authenticated_extraction_moves_signature_owners_and_cleans_indexes_in_fifo_order`
parks an attributed entry followed by an unattributed entry under the same
missing root, each with a 4,589-byte signature. It fixes:

- pointer identity of each signature allocation across extraction (a clone
  would change the allocation);
- exact FIFO slicing and tail retention at `limit = 1`;
- byte, source, and verified-key-fingerprint parity;
- cleanup of both attributed and unattributed accounting branches; and
- complete removal of root, duty, source, source/root, duplicate-key, and
  unattributed indexes after the second extraction.

## Validation

- `cargo test -p bloch-pos-committee --lib --offline authenticated_extraction_moves_signature_owners_and_cleans_indexes_in_fifo_order -- --nocapture`
  - 1 passed; 0 failed; 466 filtered out.
- `cargo test -p bloch-pos-committee --lib --offline gossip::tests -- --nocapture`
  - 29 passed; 0 failed; 438 filtered out.
- `cargo test -p bloch-pos-committee --lib --offline`
  - 463 passed; 0 failed; 4 ignored; 98.61s.
- `cargo check -p bloch-pos-node --bin bloch-pos --offline`
  - passed (pre-existing dead-code/unused warnings only).
- `cargo test -p bloch-pos-node --bin bloch-pos --offline`
  - outside the sandbox for localhost fixtures: 610 passed; 0 failed;
    19 ignored; 61.38s.

## Residual boundary

The node replay caller still needs a separate owned attestation after pure
gossip acceptance retains the typed attestation in the accepted/seen state, so
`release_held_turn` still clones the replay token's attestation before handing
one owner to that path. Removing that second-owner requirement would need a
broader ownership/API redesign and is outside this equivalent local change.
Final accepted-pool and slashing-evidence ownership also remains intentional.
