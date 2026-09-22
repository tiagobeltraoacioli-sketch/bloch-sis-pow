# Wave 121 integration — streaming persistence and release metadata

Date: 2026-09-19
Integrated head before this report: `c79df04`

## Integrated corrections

- NET-22: one canonical emitter now serves both the public envelope encoder and
  all three block-log persistence paths. Append and synchronous/asynchronous
  rewrites preflight the complete length and stream canonical fields without a
  second envelope-sized aggregate.
- CR-07: create, recover and load render the canonical KDF mnemonic into a
  zeroizing owner; create/recover drop it immediately after Argon2 completes.
- INF-01: candidate packaging rejects malformed/multiline binary digests and
  proves the archived root and node Rust toolchain pins are unique, valid and
  equal before checking rustc or building from the archive.

Integrated commits: `c924874`, `d49136e`, `42c5115`, and `c79df04`.

## Validation

- Node suite: 585 passed, 0 failed, 19 ignored in 62.23 s outside the
  restricted sandbox for loopback socket tests.
- Wallet CLI/full crypto scope: 231 passed, 0 failed, 4 ignored.
- Candidate packager's complete hermetic matrix passed after both digest and
  toolchain-pin additions; shell syntax and diff checks passed.

## Ledger and release decision

The ledger retains 200 rows and 200 unique IDs with unchanged classifications:
71 `IMPLEMENTED`, 98 `PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`,
7 `BASE CHANGED`, 1 `OPEN`, 1 `REFUTED IN AUDIT`, and 2 `VERIFIED POSITIVE`.
SR-03 remains the sole `OPEN` finding.

The MW binary is **NOT READY for launch**. No push, signing, publication,
deployment or release authorization occurred. Independent authenticated Linux
builds/comparison, hosted provenance, real signed artifacts and approval, fresh
WS artifacts and distributed pin, scratch rollback rehearsal, and canary/fleet
`/proc` digest evidence remain mandatory external gates.
