# Wave 76 — NET-04 / EN-08 single-attestation held replay

Date: 2026-09-19

## Residual addressed

Wave 75 stopped a deferred block transition and held-attestation replay from
composing before the slot loop regained control. Its held class still consumed
four authenticated entries in one selected turn, so four complete hybrid
signature verifications remained a non-preemptible scheduler slice.

## Hardening

The held-attestation budget is now one entry per selected control turn, the
smallest useful unit the existing verifier can expose: an individual
attestation must complete both halves of its hybrid verification before the
node can know its verdict.

The existing mechanics remain intact:

- the outer scheduler still alternates ready deferred-block and held classes;
- one root stays at the front until its authenticated waiter tail is empty;
- extraction remains FIFO inside that root;
- later roots cannot overtake the front root;
- every extracted entry still traverses the complete committee, key,
  signature, equivocation, doppelganger and relay decision path;
- readiness is returned after every entry, so duties, shutdown and new batch
  admission continue to observe the tail;
- source reporting is unchanged: the original held arrival was already
  reported `Ignore`, while local replay remains silent and only broadcasts an
  accepted frame.

This is volatile node-local scheduling only. It changes no validity rule,
wire message, signature domain, queue content, persistence format or consensus
ordering.

## Adversarial regression

`held_replay_spends_exactly_one_verification_and_preserves_root_fifo` builds a
64-validator deterministic committee, parks the maximum 32 authenticated
waiters accepted for one missing root, and parks another authenticated waiter
for a second root. After both blocks become queryable, the test proves across
32 consecutive turns that:

- exactly one first-root waiter leaves the pending index per turn;
- that exact signed duty is accepted into the live pool;
- the second-root waiter remains untouched throughout the first-root tail;
- the release-root cursor advances only after the first root is empty; and
- one final turn consumes the second root and reports no remaining tail.

Focused validation:

```text
cargo test -p bloch-pos-node --bin bloch-pos \
  held_replay_spends_exactly_one_verification_and_preserves_root_fifo --offline
# 1 passed; 0 failed

cargo test -p bloch-pos-node --bin bloch-pos deferred_ --offline
# 7 passed; 0 failed

cargo test -p bloch-pos-node --bin bloch-pos release --offline
# 21 passed; 0 failed

cargo check -p bloch-pos-node --tests --offline
# passed
```

The integrated fixtures were run outside the restricted sandbox because they
bind an ephemeral loopback port. Compiler output contained only the existing
unused-code warnings.

## Remaining bounds

- One hybrid attestation verification remains non-preemptible; preemption
  inside either cryptographic algorithm is not available through the verifier
  interface.
- One selected block remains a non-preemptible transition.
- A maximally populated root now takes 32 control turns instead of eight, but
  total verification work is unchanged and each turn returns at the smallest
  practical boundary.
- Total drain latency still grows under simultaneous saturation, while the
  outer block/attestation round robin and inner future/orphan round robin
  prevent starvation.

The broader release gates remain unchanged: independently authenticated Linux
build comparison, hosted CI evidence, signed release/rollback artifacts, fresh
independent WS evidence, scratch-host rollback rehearsal, and staged canary
evidence remain external prerequisites for a releasable binary.
