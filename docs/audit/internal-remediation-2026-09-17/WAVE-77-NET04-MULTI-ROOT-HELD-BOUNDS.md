# Wave 77 — NET-04 / EN-08 multi-root held-attestation bounds

Date: 2026-09-19
Starting consolidation: `55d0d67`

## Residual addressed

The pending attestation pool already admitted at most 256 entries globally and
32 entries for one missing root, while replay consumed one entry per selected
control turn. A validator with many valid duties could still distribute those
entries over as many as 256 missing roots. When a sync page made those roots
queryable, every root became separate ready replay work. In addition, the
transport's normalized source identity was used for the first verification but
discarded at hold, so replay fell back to the unattributed aggregate budget.

## Hardening

The ephemeral admission pool now composes four independent bounds:

- 256 authenticated pending attestations globally (existing);
- 32 authenticated waiters per missing root (existing);
- 32 distinct missing roots globally (new);
- for an attributed normalized transport source, 32 pending attestations
  across roots and 8 pending attestations for one root (new).

All checks occur after the initial signature authentication but before an
entry can become later replay work. Capacity pressure returns a typed `Ignore`
reason. It never becomes `Reject`, a peer penalty, or a consensus verdict.
Unattributed input receives no invented identity and remains covered by the
aggregate, root, duty and global-entry limits.

Pending entries retain the optional normalized source. Source-index counts are
removed in the same `evict` path used by FIFO eviction, root release and prune.
The node's one-entry replay path extracts that source with the attestation and
feeds it back to `judge_from`, preserving both the per-source verification
budget and the source if the attestation must be re-held for its other root.

The legacy source-free `process`, `take_waiting_on`, `on_block` and limited
extraction interfaces remain compatible. FIFO order is still the insertion
sequence, and a root tail still drains before the next root advances.

This is node-local volatile relay admission. It changes no attestation validity
rule, committee calculation, fork-choice ordering, signature domain, wire
encoding, persisted state or consensus transition.

## Adversarial coverage

The pool suite now proves:

- 32 distinct roots saturate aggregate root capacity; a 33rd is ignored, and
  releasing one root immediately admits a new root;
- one attributed source saturates its 32-entry share across roots without
  preventing a second source from using existing root headroom;
- release returns the original source identity, retains later-root FIFO, and
  reopens the exact source capacity;
- one source can park only eight entries for one root while another source
  retains headroom for that same root; and
- the existing 256-entry FIFO eviction test still reaches the outer capacity
  using the bounded 32-root set and evicts exactly the oldest entries.

Focused validation:

```text
cargo check -p bloch-pos-committee -p bloch-pos-node --offline
# passed

cargo test -p bloch-pos-committee gossip::tests --offline
# 24 passed; 0 failed

cargo test -p bloch-pos-node \
  held_replay_spends_exactly_one_verification_and_preserves_root_fifo --offline
# 1 passed; 0 failed (outside sandbox for the fixture's loopback listener)

git diff --check
# passed
```

Compiler output contained only existing unused-code warnings.

## Residual risk

- One hybrid signature verification remains non-preemptible.
- A multi-address or multi-peer attacker can partition work across normalized
  source identities; the 32-root and 256-entry aggregate bounds remain the
  outer containment in that case.
- NAT/proxy sharing can make independent honest peers share the source limits.
  Refusal remains `Ignore`, and re-gossip after block arrival can recover it.
- Unattributed/local input cannot receive fair per-source accounting without
  fabricating identity; it remains subject to all source-independent bounds.
- A fully saturated pool still contains 256 authenticated entries and can take
  256 selected replay turns to drain. Existing block/attestation and
  future/orphan schedulers prevent that tail from monopolizing one turn.

The external binary release gates are unchanged: independently authenticated
Linux build comparison, hosted CI evidence, signed release/rollback artifacts,
fresh independent WS evidence, scratch-host rollback rehearsal and staged
canary evidence remain required.
