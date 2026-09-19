# Wave 81 — NET-04 / EN-08 authenticated block promotion

Date: 2026-09-19
Starting consolidation: `a47dfe1`

## Residual addressed

Authenticated future blocks and authenticated orphans paid the node's hybrid
gossip verification again on every promotion. A future block whose slot
arrived before its missing parent could therefore pay once on arrival, again
when moving into the orphan pool, and a third time when its parent landed.
The consensus transition correctly performs its own authoritative
parent-state verification and remains unchanged; the duplicate work was only
in node-local gossip admission.

Not every orphan has an authentication proof. An unknown validator index, or
a deposit-added index whose head-state key does not authenticate the block,
is deliberately parked without a verdict because its parent branch may
resolve another legitimate key. Those paths must continue to verify normally
when they become judgeable.

## Hardening

Parked future and orphan entries may now carry a private, move-only
`AuthenticatedBlockAdmission`. It binds:

- the block id;
- the proposal signing root;
- SHA3-256 of the exact proposer signature; and
- SHA3-256 of the registry public key used for authentication.

Construction is private to successful block admission. Promotion removes the
entry from its queue and moves the proof into the admission call. The proof
skips gossip verification only if every binding still matches the queued
envelope and the key currently returned by the registry. If the block must be
parked again, the old proof is consumed and a fresh binding is created only
after that validation succeeds. The proof is not `Clone` or `Copy`.

A missing proof, altered envelope/signature, or different current registry
key takes the ordinary verifier path. Thus branch-ambiguous orphans remain
fail-closed, and a changed key cannot inherit authentication from an earlier
projection.

All mutable checks still run: duplicate/finality refusal, slot horizon,
parent-slot ordering, proposal-variant retention, body commitments, decoding,
future/orphan capacity, parent availability, fork choice and the full
consensus transition. Source attribution remains attached across every queue.
Wire bytes, signature domains, consensus validity, persistence and peer
penalty semantics are unchanged; local overload remains `Ignore`.

## Adversarial coverage

`authenticated_future_to_orphan_to_connected_skips_both_reverifications`
builds a real parent/child chain, delivers the child one slot early, then
releases it first into the orphan pool and later through connected promotion.
A panic-on-gossip-verification sentinel is armed for both releases. Both
promotions succeed, while the budget counter remains unchanged; the fresh
parent still consumes exactly one ordinary gossip verification.

`deferred_block_registry_key_change_reverifies_and_fails_closed` uses two real
proposing fixtures with distinct keys at validator index zero. It parks a
future block under the first fixture's key, synthetically swaps only the local
registry projection to the second fixture's real state, and releases. The key
binding mismatch consumes one fresh gossip verification, rejects the now-bad
genesis-index signature, stores no block and increments the unsigned counter.
This is a controlled projection swap, not a claim that live consensus permits
in-place genesis-key mutation.

Focused validation:

```text
cargo check -p bloch-pos-node --tests --offline
# passed

cargo test -p bloch-pos-node \
  authenticated_future_to_orphan_to_connected_skips_both_reverifications \
  --offline
# 1 passed; 0 failed; 576 filtered out

cargo test -p bloch-pos-node \
  deferred_block_registry_key_change_reverifies_and_fails_closed \
  --offline
# 1 passed; 0 failed; 576 filtered out
```

The focused tests ran outside the sandbox because their real engine fixtures
bind ephemeral loopback listeners. Compiler output contained only existing
unused-code/import warnings.

## Residual risk

- Fresh block admission and the authoritative consensus transition still
  perform their required, independent hybrid verifications.
- Unknown and branch-ambiguous proposer identities carry no reusable proof and
  pay gossip verification once a current key becomes available.
- SHA3-256 fingerprints carry the ordinary collision assumption.
- Deferred block processing remains cooperatively limited to one future or
  orphan block per control turn; this change removes duplicate crypto, not the
  transition cost.
- Multi-identity partitioning, NAT sharing, Sybil resistance and peer-penalty
  policy remain outside this local correction.

External binary release gates are unchanged: independently authenticated
Linux build comparison, hosted CI evidence, signed release/rollback artifacts,
fresh independent WS evidence, scratch-host rollback rehearsal and staged
canary evidence remain required.
