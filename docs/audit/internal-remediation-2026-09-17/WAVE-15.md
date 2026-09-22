# Internal audit remediation, fifteenth wave — 2026-09-17

Base: `ee04184`; documentation reconciliation commit `a27f98b`; CI gate
repair commit `9e74fbb`; branch `fix/internal-audit-20260917`. This is local
source evidence, not hosted-CI or fleet evidence.

## Slashing and lifecycle source truth

ST-10 was confirmed against the current constants. Slashing evidence is
scheduled at epoch 2884, decodes from the wire and is submitted by the node's
observation hook, but comments across the slashing module, transaction decoder,
gate helper, application path, node admission and release tests still described
the older `u64::MAX`/network-unreachable state.

Those comments now distinguish three facts:

- pre-2884 blocks refuse the transaction;
- source at and above 2884 decodes and judges valid evidence;
- source reachability does not prove which binary a fleet runs or that a
  particular chain has economic settlement evidence.

The same reconciliation corrected stale lifecycle comments for authenticated
exit, withdrawal and RANDAO recommit (all epoch 2884), and the leak recovery
boundary (epoch 2880). Two attached limit comments that made the automated
checker associate unrelated numbers with EUVM/network constants were rewritten
without changing their values.

## Blocking prose gates

The comment/constant guard previously reported 14 contradictions; it now checks
430 tracked files, resolves 565 constants and reports zero contradictions.

The trademark/earned-word gate also failed on its own hostile self-test
fixtures, two documentation lines that literally repeated a forbidden mark, a
historical commit-message baseline and two honest-but-pattern-matching claims.
The checker now excludes only its executable fixture source and, for the
earned-word rule, the immutable history-baseline JSON whose verbatim messages
cannot be rewritten without falsifying the evidence. Product prose was
rephrased; the trademark rule still scans the history baseline. The checker
and all five synthetic positive/negative self-tests pass.

This improves INF-03, but it remains partial: local success of the two cited
blocking jobs is not hosted GitLab execution, and the broader inherited CI and
formatting state remains outside this wave.

## Validation and status

The slashing claim suite passed five tests. Focused slashing, RANDAO and
withdrawal schedule regressions each passed. Both blocking prose gates and the
five-case banned-word self-test passed; details are in
`VALIDATION-WAVE-15.txt`.

ST-10 moves from open to implemented. The ledger retains all 200 rows: 55
implemented locally, 75 partial, 57 open, seven base-changed, four protocol
decisions, one unarmed candidate and one refuted by the original audit.
