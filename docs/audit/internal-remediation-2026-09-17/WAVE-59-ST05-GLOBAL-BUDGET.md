# Wave 59 ST-05: aggregate lifecycle verification budget

Date: 2026-09-18. Starting point: `9a0dd11`. Scope: node-local lifecycle
transaction admission. Consensus validity, transaction encodings, transports,
release artifacts and deployed nodes are unchanged.

## Local hardening

Lifecycle admission already allowed one economically meaningful identity at
most two new hybrid authorization calls per 30-second wall slot. Exact cached
failures cost no allowance, and committed-state shape checks run before the
budgeted verifier. The remaining local cost nevertheless grew with the number
of registered validator or funded-input identities an unauthenticated sender
could exercise.

The same admission seam now also admits at most 256 new lifecycle hybrid calls
in one wall slot across all identities. The aggregate counter and per-identity
map reset together only when the wall slot changes. A rejected reservation does
not increment either counter. The existing retryable refusal reports the next
slot, and block validation does not consult this node-local state.

The ceiling leaves room for two calls from 128 independent identities in one
30-second slot while converting identity cycling from cost proportional to the
available registry/funding set into a fixed local bound. A regression fills the
aggregate allowance with distinct identities, proves the next identity is
refused, and proves both aggregate and identity accounting renew together.

## Residual boundary

ST-05 remains `PARTIAL`. An unauthenticated sender can spend the shared
allowance first and delay a genuine lifecycle message until the next slot.
Transport identity, fair scheduling, peer penalties and coordinated fleet
qualification remain absent. This change bounds local cryptographic work; it
does not claim Sybil resistance or production rollout evidence.
