# Wave 48 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`6edf07f`. This checkpoint combines the four-agent continuation of the local
audit remediation. It is not release approval. No binary was published, no
consensus gate was armed, and no fleet host, validator, credential, signer,
checkpoint, balance or live network was changed.

## Ledger result

All 200 finding rows remain in `FINDINGS.md`. The comparison base contained 71
implemented, 96 partial, 12 unarmed candidates, four protocol decisions and
seven open findings. The integrated ledger contains:

- 71 `IMPLEMENTED`;
- 98 `PARTIAL`;
- 15 `UNARMED CANDIDATE`;
- 5 `PROTOCOL DECISION`;
- 7 `BASE CHANGED`;
- 1 `OPEN`;
- 1 `REFUTED IN AUDIT`; and
- 2 `VERIFIED POSITIVE`.

The six findings removed from `OPEN` split exactly into two partial findings,
three deliberately inactive candidates and one explicit protocol decision.

| Result | Findings |
|---|---|
| Partial | INF-02, LG-01 |
| Unarmed candidate | ST-03, ST-04, ST-16 |
| Protocol decision | FC-07 |

SR-03 is the sole remaining `OPEN` row. The repository now refuses an expired
checkpoint release artifact, but it cannot create the independent signer set
or signed checkpoint envelope required to close the finding.

## Integrated changes and boundaries

The bootnode deep verifier no longer falls back to the fleet administrator
key. It requires a dedicated read-only key and a fixed ForceCommand wrapper.
This is a source-side credential boundary, not evidence that live credentials
were rotated or that host-loss fencing was exercised.

Checkpoint verification now fails closed on expiry whenever a clock is
provided, and release use requires an explicit freshness clock. The change
aligns the release tool with fresh-node boot behavior but does not manufacture
the missing signing ceremony artifacts.

FC-07 now has an executable proof that two disjoint one-third validator sets
can finalize conflicting epoch-18 checkpoints under the live one-half leak
floor without equivocation. Raising the denominator floor enough to guarantee
intersection sacrifices recovery with half or less of stake available, so the
finding is classified as a protocol safety/liveness decision rather than
given an arbitrary candidate.

Three consensus candidates are deliberately inert:

- ST-16 reuses authenticated `ExitV2` after an eight-epoch wait to cancel a
  funded validator that remains queued, preserving withdrawal authorization,
  churn, principal accounting and permanent key/index tombstones;
- ST-03 records and prices correlated slashing exposure in the same effective
  roster units, without reinterpreting pre-activation history; and
- ST-04 aligns a new slash's withdrawal floor with the ordinary exit plus
  withdrawal delay. Cap-free E+1 ejection remains a protocol-policy residual.

`FUNDED_VALIDATOR_CANCELLATION_ACTIVATION_EPOCH` and
`SLASHING_ECONOMICS_V2_ACTIVATION_EPOCH` both remain `u64::MAX`. Production
verdicts and historical replay are unchanged.

LG-01 now has a strict two-archive evidence intake that pins the shipped
carryover digests, root, row count and total, and only distinguishes the two
documented historical hypotheses when independent records agree. It does not
authenticate operator claims or alter the carryover. Signed raw evidence from
both frozen snapshot nodes is still required.

## Validation

- `cargo test -p bloch-pos-committee --offline`: 645 passed, six ignored and
  zero failed across unit, integration and documentation tests.
- `cargo test -p bloch-pos-node --bin bloch-pos ws_tool::tests --offline`: 20
  passed and zero failed.
- Bootnode verifier self-test passed, including administrator-key refusal and
  dedicated read-only-key success; the ForceCommand wrapper rejected an
  arbitrary command with exit status 2.
- LG-01 provenance intake passed all nine adversarial tests and `py_compile`.
- The activation-comment consistency guard, conflict-marker scan and
  `git diff --check` passed in final integration.

Workspace-wide `cargo fmt --all -- --check` remains an inherited red gate over
hundreds of pre-existing files and was not rewritten here. Ignored scale tests
were not counted as passes. Focused and full local tests are implementation
evidence, not authorization to activate, release or deploy.

## Handoff boundary

The remaining `OPEN` item requires external signer material. The five
protocol/candidate results still require owner review, historical replay,
partition and mixed-binary qualification before any activation. INF-02 and
LG-01 remain partial until independent operational evidence is supplied. No
inactive gate should be armed merely because its local regression passes.
