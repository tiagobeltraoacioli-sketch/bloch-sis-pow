# Wave 79 — funded-admission rehearsal recovery

Date: 2026-09-19
Starting point: `6a30397`
Scope: isolated validator-lifecycle proof fixture; no production consensus,
wire, persistence, release, or deployment change.

## Known-red reproduced

`scripts/rehearse-validator-admission.py` was intentionally excluded from the
Wave 78 GitLab parity change because its two-node funded-admission rehearsal
failed outside the socket-restricted sandbox. The failure was not hidden or
represented as green.

The complete rerun exposed four fixture assumptions that no longer matched the
hardened admission path:

- a forged funded deposit consumed the exact per-source hybrid-verification
  allowance, while the fixture expected a valid retry from the same funding
  key to pass in the same slot;
- two forged validator exits did the same for the validator identity;
- funding and withdrawal transactions already committed to the canonical
  chain now return `Admitted::Duplicate`, before state validation, instead of
  an error; and
- a payout whose output value is altered now fails the cheap state-dependent
  conservation check before signature verification.

These are intended protections. The correction changes their proof fixture,
not the behavior being proved.

## Fixture correction

The rehearsal now fixes every admission event to an explicit, monotonic test
clock. It proves the exact `LifecycleVerificationLimited` response after the
funded-deposit and exit budgets are consumed, advances one slot, and proves
the authentic transaction is admitted again. The main two-node loop begins at
that new slot instead of travelling backward.

Automatic slashing-evidence submission is also pinned to its own fresh logical
slot. This removes dependence on the host clock and ensures its two signature
checks receive a deterministic per-source budget.

Canonical funding and withdrawal replays must return
`Ok(Admitted::Duplicate)` and must not re-enter the pending pool. The payout
mutations assert the path they actually exercise: destination and signature
mutations fail signature verification, while a value mutation fails
conservation first.

## Full isolated proof

The final unsandboxed run of:

```text
python3 -I scripts/rehearse-validator-admission.py
```

passed all selected phases. The two-node rehearsal proved real hybrid-PQ
funding, activation, proposal and attestation by the joining validator,
authenticated exit, proposer-equivocation slashing, the real 2,048-epoch
withdrawal delay, automatic withdrawal, CLI-built payout spend, payout
finalization, and full-history replay to the same state root. The companion
invalid-state rehearsal passed. The separately compiled short automatic
RANDAO recommit rehearsal passed, and the script verified that the shipping
activation source remained unchanged.

The test requires execution outside the local sandbox because its disposable
nodes bind ephemeral loopback ports. It contacted no external service or
production system.

## Remaining boundary

This recovers a previously known-red executable proof. It does not establish
hosted CI execution, runner integrity, branch protection, Linux release
reproducibility, signed artifacts, rollback rehearsal, weak-subjectivity
freshness, or canary evidence. Those launch gates remain external and open.
