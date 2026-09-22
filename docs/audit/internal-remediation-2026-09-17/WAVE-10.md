# Internal audit remediation, tenth wave — 2026-09-17

Base: `3359c01`, branch `fix/internal-audit-20260917`. This is a local source
checkpoint. It does not deploy a node, authenticate a transport peer or alter
consensus validity.

## Lifecycle authorization admission

Lifecycle admission now wraps the existing failure-caching hybrid verifier with
a per-identity, per-wall-slot budget. Consensus' existing cheap-first checks run
before the wrapper is invoked, so nonexistent validators, wrong epochs, inactive
lifecycle states and malformed funded deposits do not spend the allowance. A
registered validator or economically backed funding key may trigger at most two
new hybrid authorization calls in one 30-second slot. Two calls cover the largest
current lifecycle authorization set; each call checks both PQ algorithms.

The wrapper consults the exact immutable-failure cache before reserving budget.
Replaying known bad bytes therefore performs no cryptography and cannot consume
the short allowance. A new slot clears the bounded identity table. Withdrawals
carry no signature and bypass this verifier budget.

Lifecycle transactions also receive stable mempool source identities. Signature
variants of one exit share the same source; withdrawals and RANDAO recommits for
one validator share an index-derived, domain-separated source. This brings these
classes under the existing pending-source accounting instead of returning `None`.

## Residual availability tradeoff

The transport remains unauthenticated. An attacker can spend a known validator's
two-call allowance with distinct, state-plausible signatures and delay a genuine
message until the next slot, or cycle through registered identities. The change
bounds cryptographic work and caps the delay window; it does not provide peer
reputation, global fairness or Sybil resistance. ST-05 is therefore partial, and
the related EN-07/NET-04 residuals remain open in their existing partial rows.

## Validation and status

Three focused regressions pin independent identities, slot renewal, lifecycle
source stability, cache-before-budget order and refusal before a third new crypto
call. The funded-deposit cache regression was moved to the state-aware lifecycle
door, proving that stateless admission performs shape checks without duplicating
two unbounded authorizations. The complete node suite passed 584 tests with 25
ignored. Exact evidence is in `VALIDATION-WAVE-10.txt`.

The ledger retains all 200 rows: 53 implemented locally, 70 partial, 64 open,
seven base-changed, four protocol decisions, one unarmed candidate and one refuted
by the original audit.
