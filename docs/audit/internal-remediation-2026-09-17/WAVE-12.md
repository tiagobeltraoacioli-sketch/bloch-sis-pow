# Internal audit remediation, twelfth wave — 2026-09-17

Base: `9bf8d24`, implementation commit `6eba843`, branch
`fix/internal-audit-20260917`. This is local source evidence, not a fleet
activation or release approval.

## Exact attestation replay suppression

Below the duplicate-attestation flag day, consensus must continue accepting a
repeated `(validator, signing_root)` pair for historical compatibility. The
transition now distinguishes an exact replay from a signature variant. Once an
attestation's validator, signing root and signature bytes have verified, a
byte-identical copy reuses that result and skips the second hybrid verification.
The existing committed-state writes are idempotent, so skipping the duplicate
writes preserves the pre-gate post-state and verdict.

Signature bytes are deliberately part of the cache key. A second randomized or
mutated signature for the same vote still reaches the verifier; a bad variant
therefore remains `Attestation(i)` rather than being accepted from the first
copy's result. The index borrows signature slices from the bounded body and
does not clone multi-kilobyte witnesses.

This mitigates the exact replay form of TX-15 without silently activating a
consensus tightening. The pair-level `DuplicateAttestation` refusal remains
behind `ATTESTATION_DEDUP_ACTIVATION_EPOCH = u64::MAX`; valid signature variants
can still purchase repeated verification, so TX-15 is partial.

## Ledger reconciliation

TX-06 and TX-07 were still recorded as open even though the current tree already
contains live producer/mempool policy, inert consensus rules, activation
tripwires and post-activation regressions:

- TX-06: admission refuses zero/dust and more than 256 outputs; consensus uses
  the same rule only after `DUST_RULE_ACTIVATION_EPOCH`.
- TX-07: admission bounds `tx_bytes` to canonical length plus fixed slack;
  consensus uses the same ceiling only after `TX_BYTES_BOUND_ACTIVATION_EPOCH`.

Both remain exploitable by a hand-built scheduled proposer while those gates
are inert. Their ledger status therefore changes from open to partial, not to
implemented.

## Validation and status

The exact-replay count regression observes two verifier calls: one proposer and
one unique attestation. The variant regression proves a mutated second
signature is still refused. The complete committee suite passed 617 tests with
six ignored, including doctests; details are in `VALIDATION-WAVE-12.txt`.

The ledger retains all 200 rows: 53 implemented locally, 74 partial, 60 open,
seven base-changed, four protocol decisions, one unarmed candidate and one
refuted by the original audit.
