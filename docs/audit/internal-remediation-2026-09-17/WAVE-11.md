# Internal audit remediation, eleventh wave — 2026-09-17

Base: `51586aa`, branch `fix/internal-audit-20260917`. This is a local source
checkpoint. It does not deploy a node or establish which binary the fleet runs.

## Stale-head duty quarantine

The slot loop now decides whether its committed head is stale before any call
to `attest`, `propose` or `rolled_to`. A head more than one slot behind with no
canonical progress for two slots starts a duty quarantine and requests sync
before local signing. Both duty paths share the same gate, so a stale
attestation cannot consume its epoch watermark and a stale proposal cannot
publish a block from an invented rolled-forward RANDAO/registry view.

The quarantine remembers the wall tip seen when catch-up began. Applying the
first sync page therefore does not reopen duties merely because it refreshed
`last_applied_ms`; canonical progress extends the quiet deadline until the head
reaches the remembered target. Metrics use the same final decision:
`validator_active` is zero and `is_syncing` is one while the quarantine holds.

## Liveness boundary and residual

The legacy devnet wire has neither request IDs nor an end-of-page frame, and
both transports permit genuinely empty slots. A permanent `head >= wall - 1`
requirement would make two missed proposals halt every validator forever. The
quarantine therefore expires after two slots without canonical progress and
uses a two-slot retry cooldown, allowing a sparse chain to recover before the
next sync probe.

That bounded escape is an explicit residual: if a node has no responsive peer
but is genuinely stale, it can resume duties during the cooldown. Closing this
without trading one safety failure for a network-wide liveness failure requires
authenticated sync-completion/tip evidence on both transports. EN-10 therefore
moves from open to partial rather than being overstated as closed.

## Validation and status

Seven regressions pin the normal one-slot gap, freshness threshold, stalled-head
quarantine, boot grace, multi-page progress, quiet sparse-chain escape/retry and
clock regression. The complete node suite passed after the final gate design;
exact commands and counts are in `VALIDATION-WAVE-11.txt`.

The ledger retains all 200 rows: 53 implemented locally, 71 partial, 63 open,
seven base-changed, four protocol decisions, one unarmed candidate and one
refuted by the original audit.
