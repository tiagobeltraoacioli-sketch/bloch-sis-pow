# Wave 48 ST-16: inactive funded-queue cancellation candidate

Date: 2026-09-18. Branch: `codex/audit-st16-funded-cancel`. Starting point:
`6edf07f`. Scope: committee source, tests and audit evidence only. No gate was
activated, no deployment was performed and no live validator state changed.

## Recovered finding and present invariant

The exact finding was recovered from
`a79c88b:docs/audit/deep-audit-2026-09-16/A3-consensus-staking-lifecycle.md`.
ST-16 observes that a funded registration whose deposit epoch never finalizes
cannot activate, while authenticated exit rejects a record whose activation
epoch is still the `u64::MAX` sentinel. Withdrawal in turn requires a completed
exit. Self-slashing was therefore the only protocol route out of the queue.

The current state makes a safe candidate narrower than a new transaction:

- the funded deposit already commits the validator key and withdrawal script,
  and both the funding authority and validator key sign that destination;
- `ExitV2` authenticates against the registered validator key, binds the
  signed epoch exactly to inclusion, is one-shot and shares a committed
  per-epoch churn ceiling;
- `Withdraw` pays only the registered script and treats funded principal as
  backed, without changing `issued_sat`; and
- validator indices, public-key ownership and deposit history are permanent,
  so cancellation must be a tombstone rather than deletion or index reuse.

## Candidate, deliberately inactive

`FUNDED_VALIDATOR_CANCELLATION_ACTIVATION_EPOCH` is `u64::MAX`. A compile-time
assertion prevents a future finite value from preceding the authenticated-exit
or withdrawal releases. While the gate remains inert, the accepted block set,
historical replay and queue schedule are unchanged.

When explicitly rehearsed, the candidate lets the existing `ExitV2` path
schedule an ordinary delayed withdrawal for a record only when all of these
facts hold:

1. the registration has committed funded provenance;
2. its activation epoch is still the queue sentinel;
3. its unique deposit-history entry has waited the ordinary eight-epoch
   activation delay;
4. it is not slashed and has never exited;
5. the signature is from the registered validator key and names the current
   inclusion epoch; and
6. the shared voluntary-exit churn budget has room.

No wire tag, signing root, state field or state-root format is added. The
normal exit and weak-subjectivity withdrawal delays remain in force. The
withdrawal returns the full remaining funded bond to the withdrawal script
that the funding authority approved in the original deposit. It neither mints
nor writes off principal and does not advance `issued_sat`.

Cancellation leaves the validator record, public-key index, funded-provenance
bit and deposit-history entry committed forever. The activation scan now
requires the exit sentinel as well as the activation sentinel, so later
finality cannot reactivate a cancelled record. This preserves key/index replay
protection and avoids rewriting the historical queue.

## Status and residual risk

ST-16 moves from `OPEN` to `UNARMED CANDIDATE`, not `IMPLEMENTED`. The ledger
delta on this branch is exactly one fewer open finding and one additional
unarmed candidate: 200 findings total, 71 implemented, 96 partial, six open,
13 unarmed candidates, seven base-changed, four protocol decisions, two
verified positives and one refuted in the original audit.

Activation remains a consensus and economic decision. Qualification still
requires full historical replay and mixed-binary tests, a protocol-owner
decision that eight epochs is the correct cancellation floor, analysis of
cancelled registrations sharing the four-per-epoch exit budget, and resource
qualification of permanent tombstones. Cancellation deliberately does not
free ST-13's lifetime registry capacity or permit the same key to re-register.
No activation epoch is proposed by this wave.

## Validation

- `cargo test -p bloch-pos-committee queued_funded_cancellation_is_inert_and_preserves_principal_when_rehearsed -- --nocapture`:
  one focused regression passed. It covers the inert production gate, delay,
  funded provenance, registered-key authorization, one-shot replay refusal,
  later-finality queue exclusion, exact principal return, unchanged issuance
  and permanent registry/history identities.
- `cargo test -p bloch-pos-committee --lib`: 448 passed, four ignored and zero
  failed.
- `cargo clippy -p bloch-pos-committee --lib`: completed with inherited
  warnings and no errors.
- `git diff --check`: passed.

The build emitted inherited unused-import, unused-doc-comment and dead-code
warnings. No test or inactive candidate is deployment evidence.
