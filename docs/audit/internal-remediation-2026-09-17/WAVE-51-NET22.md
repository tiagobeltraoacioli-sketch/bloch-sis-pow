# Wave 51: NET-22 bounded block-index failure

Date: 2026-09-18. Base: `2abb416`. Scope: local source, tests and audit
ledger only. No node, peer, public endpoint, consensus rule, activation epoch,
authoritative format or network wire encoding was changed.

## Change

`Store::blocks_after` previously treated a missing, unreadable, malformed,
out-of-range, unsorted or log-disagreeing `blocks.idx` as permission to scan
`blocks.log` from byte zero. A remote sync request could therefore restore an
O(chain length) request cost after local damage to this disposable index.

The serving path now fails boundedly when the derived index is unusable or its
selected record disagrees with the authoritative log. Valid index magic with
no records beside a non-empty log also fails instead of starting a full-history
scan. `Store::open` still rebuilds the index from the log, so restart repairs
these cases without changing authoritative data.

A valid index that merely lags the log remains supported: serving begins at
its covered offset and scans only the unindexed tail. This preserves the crash
window between durable log append and best-effort index append.

## Validation

- Corrupt selected offsets return `InvalidData`, touch at most the attempted
  indexed frame, and work again after the existing open-time rebuild.
- Missing, wrong-magic and valid-magic-only indexes fail before any log-header
  scan and are repaired by `Store::open`.
- A valid lagging index continues to serve every unindexed block.
- All 28 `store::tests` passed.

## Residuals

NET-22 remains **PARTIAL**. A long but valid unindexed tail remains linear to
serve until rebuild. Devnet also completes frame decode before engine-queue
admission. RPC `Host` policy remains a browser/DNS-rebinding control rather
than client authentication; accept-thread overload responses are unchanged.
