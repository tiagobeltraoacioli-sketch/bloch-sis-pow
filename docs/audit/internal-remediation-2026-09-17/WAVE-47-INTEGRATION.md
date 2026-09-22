# Waves 45–47 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`4e15334`. This checkpoint combines four-agent local remediation and review.
It is not release approval. No binary was published, no activation epoch was
armed, and no fleet host, validator, key, balance, or live network was changed.

## Ledger result

All 200 finding rows remain in `FINDINGS.md`. The comparison base contained 69
implemented, 89 partial, one unarmed candidate and 27 open findings. The
integrated ledger contains:

- 71 `IMPLEMENTED`;
- 96 `PARTIAL`;
- 12 `UNARMED CANDIDATE`;
- 4 `PROTOCOL DECISION`;
- 7 `BASE CHANGED`;
- 7 `OPEN`;
- 1 `REFUTED IN AUDIT`; and
- 2 `VERIFIED POSITIVE`.

The twenty findings removed from `OPEN` split exactly into two implemented,
seven partial and eleven deliberately inactive candidates. Candidate means the
code remains behind an unarmed consensus gate and is not authorized for
production.

| Result | Findings |
|---|---|
| Implemented | ST-12, BV-18 |
| Partial | ST-11, TX-14, INF-20, FC-08, TX-13, ST-15, FC-12 |
| Unarmed candidate | TX-10, ST-06, TX-08, TX-09, FC-04, ST-13, FC-10, ST-07, TX-04, SR-01, FC-05 |

The seven remaining open findings are intentionally not papered over:

- INF-02 needs independently verified credential separation and host-loss
  fencing;
- LG-01 needs source ledger/log evidence to explain the missing historical
  subsidy;
- SR-03 needs a signed checkpoint envelope and signer set;
- FC-07 needs a reviewed finality/leak safety rule;
- ST-03 and ST-04 need reviewed slashing and exit economics; and
- ST-16 needs a specified cancellation/exit path for funded validators whose
  deposit epoch never finalizes.

## Integrated safeguards

The pass added or reconciled inactive candidates for transaction-count
metering, issuance accounting, reward settlement, RANDAO ancestry, activation
queue bounds/order, genesis/network-bound signing, V2 genesis cohort binding,
and fork-choice tie handling. The FC-12 change is observability only: it exposes
the committed permanent-bar history, active intersection and excluded stake;
it does not expire the bar.

An independent activation review compared every `*_ACTIVATION_EPOCH` with the
base. No existing value changed, and all three newly introduced gates remain
`u64::MAX`. A follow-up then made the sentinel semantics uniform: even a direct
synthetic call at epoch `u64::MAX` cannot accidentally open any unarmed PoS
gate. Epochs derived from block slots could not reach that value, so historical
replay and production verdicts are unchanged.

The same review corrected two misleading comments, clarified that
`admission_network_domain` is immutable state context but outside historical
state-root encoding, and strengthened the compile-time distinction between a
slashing ejection at E+1 and a voluntary exit at E+`EXIT_DELAY_EPOCHS`.

## Validation

- The integrated committee suite passed before the sentinel normalization:
  443 passed and four scale tests were intentionally ignored. The normalized
  branch then passed 447 tests with the same four ignored tests; the integrated
  sentinel and voluntary-exit regressions passed again after merge.
- The complete node test run passed outside the socket-restricted sandbox,
  with 500 unit tests passing and 19 rehearsal/benchmark tests ignored; its
  integration-test targets also passed. The initial sandbox run's 147 failures
  were all local-socket `PermissionDenied` errors.
- Genesis tests passed 58/58, published artifact checks 2/2, and fork-choice
  tests 10 passed with one performance test ignored.
- Focused FC-12 committee and metrics regressions passed. Vault and API suites,
  the Rust pin/carryover guards, PQ-claims guard, comment-constant guard and
  local documentation-link check passed in their owning waves or final QA.
- `git diff --check` passed and no conflict markers remain.

`cargo fmt --all -- --check` remains an inherited repository-wide limitation:
it reports differences across hundreds of pre-existing files. This wave did
not apply a workspace-wide formatting rewrite. Existing compiler/clippy
warnings also remain and are not represented as newly introduced failures.

## Handoff boundary

The next work is no longer a safe local audit-patch queue. The seven open items
need external operational evidence or explicit protocol/economic choices,
followed by replay, partition, mixed-binary and release qualification. None of
the inactive candidates should be armed merely because its focused regression
passes.
