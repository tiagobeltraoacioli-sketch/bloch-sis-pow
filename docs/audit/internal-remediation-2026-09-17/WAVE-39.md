# Internal audit remediation, thirty-ninth wave — 2026-09-18

Base: `b13a95c`; branch `fix/internal-audit-20260917`. This wave reconciles
LG-02 without rewriting the committed Genesis-4 opening state.

## LG-02: historical compatibility versus canonical vout decoding

Genesis-3 UTXO keys encode `vout` little-endian. The historical snapshot path
decoded those four bytes big-endian, so 38 live outpoints whose real index was
1 were published as 16,777,216. Consensus reads in Genesis-3 were unaffected
because insertion and lookup both used the same little-endian key bytes. The
Genesis-4 loader correctly carried the published TSV literally; consequently,
the wrong numeric indices are now part of the committed opening artifact.

The remediation makes the boundary explicit and executable:

- default snapshot mode retains the historical big-endian misread so the
  published TSV and SHAKE-256 commitment remain reproducible;
- `--canonical-vout` uses `u32::from_le_bytes` for any new export;
- the shared row decoder rejects malformed keys, values and trailing bytes;
- regressions prove historical `1 -> 16,777,216`, canonical `1 -> 1`, the
  canonical round trip across boundary values and the zero-value invariant.

LG-02 remains partial because changing the 38 live Genesis-4 outpoint keys is a
consensus state migration, not an exporter cleanup. Silently changing the old
artifact would break its commitment and replay. Any correction requires an
explicit migration rule, activation and operator coordination.

The ledger retains all 200 rows: 66 implemented, 88 partial, 32 open, seven
base-changed, four protocol decisions, one unarmed candidate, one refuted by
the original audit and one verified positive.
