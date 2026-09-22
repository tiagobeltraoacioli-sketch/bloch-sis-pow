# Wave 47: ST-15 observer-reward attribution

Date: 2026-09-18. Base: `1711937`. Scope: local node messaging, tests, and
audit ledger only. No slashing rule, reward recipient, consensus state, node,
validator, release, deployment, or live state was changed.

## Finding

The protocol pays the whistleblower credit to the proposer that includes
slashing evidence. The node that first observes, admits, and broadcasts that
evidence receives no protocol reward, and another proposer can include it
first. The previous operator log said only that evidence was “admitted and
broadcast”, which could be read as successful reporter reward submission.

## Remediation and residual

The success message now states both facts explicitly: the observer earns no
protocol reward, and only the including block proposer may receive the credit.
A focused regression checks that the message retains both qualifications.

ST-15 moves from open to partial. This fixes misleading operational feedback,
not the economic rule. Binding rewards to an authenticated reporter, preventing
front-running, or deliberately retaining proposer attribution requires a
protocol decision, a new signed identity/transaction field, replay analysis,
and coordinated activation.

## Validation

`cargo test -p bloch-pos-node --bin bloch-pos evidence_submission_log_does_not_promise_the_observer_a_reward --offline`
passed with one matching test. Existing compiler warnings are inherited.
