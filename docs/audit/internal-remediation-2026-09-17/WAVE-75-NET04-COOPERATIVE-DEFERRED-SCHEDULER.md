# Wave 75 — NET-04 / EN-08 cooperative deferred-work scheduler

Date: 2026-09-19

## Residual addressed

Wave 74 made ready future blocks and promoted orphans share one aggregate
block-transition slice. The slot loop still invoked the separately bounded
held-attestation replay immediately afterward. Under sustained simultaneous
pressure, one full block transition and four hybrid attestation verifications
could therefore compose before the loop regained its duty/control point.

## Hardening

The slot loop now has a second, outer round-robin scheduler:

- the aggregate deferred-block class and the held-attestation class receive
  separate control turns;
- if both remain ready, turns alternate without starvation;
- if only one is ready, it advances immediately;
- the block class retains its inner future/orphan round robin and one-block
  aggregate limit;
- the attestation class retains its four-entry slice and per-root FIFO;
- readiness is recomputed after the selected work because a landed block can
  make held attestations judgeable;
- all three tail flags still gate validator duties, shutdown completion, and
  admission of another external batch.

The two cursors are volatile node-local scheduling state. No validity rule,
wire message, signature, queue content, source attribution, persistence
format, or consensus ordering changed.

## Adversarial regressions

- `deferred_blocks_and_held_attestations_share_one_fair_slice` holds both
  classes ready for 256 selections and proves strict alternation. It also
  proves a continuously ready attestation tail progresses alone and that a
  block tail receives the next shared turn when dual pressure resumes.
- `deferred_block_and_held_replay_take_separate_control_turns` creates a real
  valid future block through proposal plus reorg, parks a correctly signed
  attestation until its referenced block is queryable, and makes both release
  classes ready together. The first turn applies only the block and leaves the
  exact attestation pending; the second turn replays and accepts it.

Focused validation:

```text
cargo test -p bloch-pos-node --bin bloch-pos deferred_ --offline
# 7 passed; 0 failed

cargo test -p bloch-pos-node --bin bloch-pos release --offline
# 21 passed; 0 failed

cargo check -p bloch-pos-node --tests --offline
# passed
```

The integrated fixture requires loopback socket permission and passed outside
the restricted sandbox. Compiler output retained only pre-existing unused-code
warnings.

## Remaining bounds

- One selected block remains a non-preemptible transition.
- One selected held-attestation turn can still perform four hybrid signature
  verifications; cost-weighted or time-budgeted preemption inside that slice is
  not implemented.
- Readiness checks scan the separately bounded future pool; other readiness
  checks are constant-time.
- Total drain latency grows under simultaneous saturation, but neither outer
  class nor either inner block class can starve.

The broader release gates remain unchanged: independently authenticated Linux
build comparison, hosted CI evidence, signed release/rollback artifacts, fresh
independent WS evidence, scratch-host rollback rehearsal, and staged canary
evidence remain external prerequisites for a releasable binary.
