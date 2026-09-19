# Wave 129 integration — fixed sync, protected seeds and packaged-byte binding

Date: 2026-09-19
Integrated head before this report: `07fb959`

## Integrated corrections

- EN-08: the live 13-byte libp2p sync request codec uses a canonical stack
  array for reads and writes, preserving the public vector encoder and exact
  EOF/error behavior without two fixed heap temporaries.
- CR-07: all production HD seed consumers move the BIP39 array immediately
  into zeroizing ownership and retain a protected vector through fallible
  derivation before transferring it to the existing wallet field.
- INF-01: candidate packaging hashes the staged binary before and after its
  two-line version query and refuses synchronous self-mutation, binding the
  published metadata to the same inspected byte set.

Integrated commits: `71a7d262`, `b59b35a0`, and `07fb959`.

## Validation and ledger

- Node suite: 587 passed, 0 failed, 19 ignored in 66.27 s outside the
  restricted sandbox.
- Wallet CLI/full crypto scope: 233 passed, 0 failed, 4 ignored.
- Candidate packager's complete hermetic matrix, shell syntax and diff checks
  pass, including the self-mutating executable fixture.
- The ledger remains 200 rows and 200 unique IDs with unchanged status counts;
  SR-03 remains the sole `OPEN` finding.

## Release decision

The MW binary is **NOT READY for launch**. No push, signing, publication,
deployment or release authorization occurred. Independent authenticated Linux
builds/comparison, hosted provenance, real signed artifacts and approval, fresh
WS artifacts and distributed pin, scratch rollback rehearsal, and canary/fleet
`/proc` digest evidence remain mandatory external gates.
