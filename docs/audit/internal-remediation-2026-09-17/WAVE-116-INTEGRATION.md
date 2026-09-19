# Wave 116 integration — continued safe audit remediation

Date: 2026-09-19
Integrated head before this ledger commit: `25466f3`

## Integrated corrections

- INF-01/INF-09: canonical build metadata is complete and value-bound; candidate
  packaging builds a captured source archive, rejects ambiguous version/target
  metadata, and the legacy integrity guard refuses tracked dirty source. Rollback
  assembly derives all identities from one private binary snapshot.
- NET-22/EN-08: block-log appends, index encoding and the header-only index scan
  now stream through fixed buffers. Directed-sync responses decode from the async
  reader directly into their final bounded envelope vectors.
- BV-09/CR-07: recovery HKDF output, the V3 PQ-seed digest and HD master-key KDF
  output acquire zeroizing owners before their output bytes are written.
- CR-06: the sole production disclosure CLI consumer names its convention
  explicitly.

Integrated commits in ancestry order: `308d6b6`, `21b8e06`, `848ccd3`,
`a1e5663`, `be1ea64`, `e39b7ab`, `e22cdee`, `4a79a4b`, `9121563`,
`7b2895b`, `c3176ea`, `a902859`, `5ba556c`, and `25466f3`.

## Validation

- Node suite after streamed sync decode: 584 passed, 0 failed, 19 ignored
  (61.56 s; outside the restricted sandbox for loopback sockets).
- Wallet CLI/full crypto scope: 230 passed, 0 failed, 4 ignored.
- PQ vault: 51 passed, 0 failed; pq-shield-api: 19 passed, 0 failed.
- Build wrapper, candidate packager, comparator and the 17-case release-integrity
  self-tests passed. Shell syntax and diff checks passed.
- The rollback selftest was not run locally because `minisign` is absent; its
  shell syntax passed and CI remains the blocking disposable-key execution.

## Ledger reconciliation

`FINDINGS.md` retains 200 rows and 200 unique IDs. Counts are unchanged: 71
`IMPLEMENTED`, 98 `PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`,
7 `BASE CHANGED`, 1 `OPEN`, 1 `REFUTED IN AUDIT`, and 2 `VERIFIED POSITIVE`.
SR-03 remains the sole `OPEN` finding.

## Release decision

The MW binary is **NOT READY for launch**. No push, signing, publication,
deployment or release authorization occurred. Required external evidence still
includes two independently authenticated canonical Linux builds and comparison,
hosted CI and builder/image/tool provenance, real signed release and rollback
artifacts with independent approval, a fresh independently signed WS envelope
and authenticated signer arrangement/pin, a scratch-systemd rollback drill, and
staged canary/fleet `/proc` digest verification.
