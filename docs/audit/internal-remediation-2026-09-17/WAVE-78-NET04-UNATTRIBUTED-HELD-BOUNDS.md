# Wave 78 — NET-04 / EN-08 unattributed held-attestation bounds

Date: 2026-09-19
Starting consolidation: `9eebe9d`

## Residual addressed

Wave 77 limited an attributed normalized transport source to 32 pending
attestations across roots and eight for one root. The source-free compatibility
path deliberately did not invent an identity, but consequently bypassed both
limits: embedded or otherwise unattributed callers could occupy all 256 global
entries, or all 32 entries for one missing root.

That remained bounded globally, but it let one less-accountable ingress class
consume capacity reserved for independently attributed traffic and later turn
the entire aggregate pool into replay work.

## Hardening

Source-free ingress now shares one explicit collective bucket:

- 32 authenticated pending attestations across all roots; and
- eight authenticated pending attestations for one missing root.

No peer or source identity is synthesized. The bucket is intentionally shared
by every caller that supplies `None`, accurately representing the absence of a
fairness identity while bounding its aggregate effect. Attributed sources keep
their existing independent 32/eight shares, subject to the existing global,
root, root-set and duty bounds.

Both new counters are incremented only when a verified attestation is actually
held. The single `evict` path decrements them on sliced release, FIFO eviction
and pruning, so capacity reopens exactly when the corresponding entry leaves.
Overflow remains typed `Ignore`, never `Reject`, peer guilt or a consensus
verdict.

This changes only volatile relay admission. Attestation validity, signature
domains, committee selection, fork choice, wire bytes, persisted state and
consensus transitions are unchanged.

## Adversarial coverage

The committee gossip suite proves that:

- source-free input distributed across roots stops at 32 rather than filling
  the 256-entry global pool;
- that saturation does not consume an attributed source's independent share;
- one root accepts at most eight unattributed waiters; and
- extracting one waiter decrements both indexes and immediately admits one
  replacement.

Existing root-release and global-FIFO tests now use explicit synthetic source
identities where they intentionally exercise outer bounds rather than the new
source-free bound.

Focused validation:

```text
cargo test -p bloch-pos-committee gossip::tests --offline
# 26 passed; 0 failed

cargo test -p bloch-pos-node \
  held_replay_spends_exactly_one_verification_and_preserves_root_fifo --offline
# 1 passed; 0 failed (outside sandbox for the fixture's loopback listener)

git diff --check
# passed
```

Compiler output contained only existing unused-code warnings. The node fixture
now supplies explicit synthetic source identities because it deliberately
fills all 32 root-wide slots; using the source-free compatibility path there
would test the new eight-entry bucket instead of the outer replay bound.

## Residual risk

- One hybrid signature verification remains non-preemptible.
- All legitimate source-free callers share one bucket and may contend with
  each other; there is no defensible finer fairness boundary without a real
  caller identity.
- Multi-address and multi-peer attackers can partition work across attributed
  identities; the 32-root and 256-entry aggregate bounds remain the outer
  containment.
- NAT/proxy sharing can make honest peers share attributed limits.
- A fully saturated pool can still contain 256 authenticated entries and take
  256 selected replay turns to drain under the existing cooperative scheduler.

The external binary release gates are unchanged: independently authenticated
Linux build comparison, hosted CI evidence, signed release/rollback artifacts,
fresh independent WS evidence, scratch-host rollback rehearsal and staged
canary evidence remain required.
