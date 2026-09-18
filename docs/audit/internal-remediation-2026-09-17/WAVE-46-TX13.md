# Internal audit remediation, forty-sixth wave — epoch recovery headroom

Base: `436c2ef`; implementation commit `cfd120f`; branch
`codex/audit-tx13-epoch-recovery`. This wave adds node-local observability. It
does not change consensus validity, activate a gate, construct recovery blocks
or deploy a binary.

## Recovered boundary

`compute_post_state` derives `block_epoch` from the untrusted header slot and
closes every skipped epoch before checking the proposer signature. An
unbounded gap therefore lets one unauthenticated header request effectively
unbounded work. `MAX_EPOCH_ADVANCE = 4096` is the live consensus backstop; the
transition rejects the first parent-child epoch gap above it before cloning or
rolling state.

The same bound limits ordinary recovery. At 32 30-second slots per epoch,
4,096 epochs are about 45.5 days. The reference producer always targets the
current wall slot and its stale-head duty quarantine prevents signing from an
artificially rolled view. It therefore has no supported way to resume once a
single current-slot block would exceed the bound.

The finding's “only a hard fork” wording is stronger than the bare transition
rule: the limit is per parent-child edge, so a purpose-built and coordinated
producer could theoretically bridge a longer outage with correctly signed
intermediate-slot blocks whose individual gaps stay within 4,096. This tree
has no such producer, ceremony, safety analysis or runbook. Treating that
theoretical path as operational recovery would be unsafe.

## Why no consensus candidate was added

Removing the limit reopens the original remote denial of service. Raising it
only moves the outage cliff while proportionally increasing attacker-controlled
work. A local-clock exception would make block validity depend on clocks that
honest nodes can disagree about. Incremental local precomputation can reduce
latency, but it cannot by itself change whether the eventual parent-child gap
is valid; coupling it to validity would need a specified activation and
mixed-version analysis.

No inactive constant was added merely to defer those choices. A real recovery
candidate needs a bounded intermediate-block protocol or a newly specified
consensus transition, plus replay, signature/watermark, fork-choice and
partition testing.

## Operator-visible headroom

The slot loop now computes:

`MAX_EPOCH_ADVANCE - (wall_epoch - head_epoch)`, saturating at both ends.

It exports the result as
`bloch_pos_epoch_advance_headroom_epochs`. The registry defaults to the full
4,096 rather than zero, so the short interval before the first slot-loop
sample cannot look like an exhausted chain.

The node logs once as severity rises through:

- 512 epochs remaining (about 5.7 days at the mainnet cadence);
- 128 epochs remaining (about 34 hours); and
- zero remaining, when the current epoch is the last one inside the ceiling
  if the gap is exactly 4,096, or the wall epoch is already outside it.

If canonical catch-up lowers severity, the warning latch resets, allowing a
later independent outage to warn again. These values are never read back by
consensus, fork choice, block admission or duty selection.

## Status and residual

TX-13 moves to `PARTIAL`, not `IMPLEMENTED`. Operators now receive actionable
notice before the existing recovery window expires, and the precise
per-edge nature of the bound is documented. There is still no supported
recovery after the reference producer crosses the ceiling. Fleet alert rules,
deployment evidence and a rehearsed intermediate-block or coordinated
consensus recovery procedure remain external work.

The post-wave ledger retains all 200 findings: 71 implemented, 93 partial, 19
open, seven base-changed, four protocol decisions, three unarmed candidates,
two verified positives and one finding refuted by the original audit.

## Validation

- `cargo test -p bloch-pos-node epoch_advance_ -- --nocapture` — 2 passed.
- `cargo test -p bloch-pos-node metrics::tests::counter_increment_changes_render -- --nocapture`
  — 1 passed.
- `cargo test -p bloch-pos-node --bin bloch-pos` — 497 passed, zero failed,
  19 ignored rehearsal/benchmark tests when run with local socket permission.

The first sandboxed full-suite attempt passed 350 tests but denied local
socket creation to 147 tests. Re-running with local socket permission produced
the clean result above. The commands emitted only pre-existing
workspace/compiler warnings.
