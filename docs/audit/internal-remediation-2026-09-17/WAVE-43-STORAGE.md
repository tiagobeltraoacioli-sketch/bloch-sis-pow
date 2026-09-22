# Internal audit remediation, forty-third wave — storage/reorg publication

Base: `45ae11e`; implementation commit `efa5455`; branch
`codex/audit-storage-reorg`. This is local source and regression evidence. It
does not deploy a binary, change consensus rules or alter the persisted frame
format.

## EN-17: dedicated durable reorg writer

`do_reorg` no longer encodes and rewrites the complete canonical block log on
the consensus thread. It transfers an owned canonical envelope list to a named
writer thread. That writer performs the expensive and durable sequence:

1. encode and stream a private, exclusively created replacement;
2. fsync the complete staged file;
3. take the per-directory generation write lock;
4. durably invalidate the derived slot index;
5. atomically rename and directory-fsync the replacement log; and
6. rebuild and fsync the index from the published log.

The event loop polls completion without waiting, so RPC and network work can
continue while the rewrite is staged and published. Validator duties are
blocked while publication is pending: the node cannot spend a signing
watermark or advertise locally produced work from a head it has not made
durable. A later canonical append joins the writer first, then appends after
the replacement generation. A second reorg is similarly serialized.

Writer errors are returned to the event loop and stop the node. Thread-spawn
failure remains immediately fatal. An orderly `--stop-at-slot` waits and
propagates failure before returning; `Store::drop` also joins before releasing
the data-directory lock. The restart cache is written only after successful
writer completion (or after a later append has joined that completion), never
while the replacement log is merely pending.

The publication transaction is shared with the synchronous store test/tool
path. Consequently the existing real read-only-index regression still proves
that failure to invalidate the old index occurs before log replacement for
both callers. Existing restart tests retain the other crash boundary: an empty
or losing-generation index is reconstructed from the authoritative log.

## Regression evidence

- the async call returns while a held generation reader prevents publication,
  proving the caller does not perform or wait for durable publication;
- an append issued before the normal completion poll joins the rewrite and
  produces replacement slots `[100, 200]` followed by appended slot `300`;
- an oversized asynchronous rewrite reports `InvalidInput` without changing
  either the authoritative log or index;
- dropping a store immediately after queuing 300 replacement frames waits for
  the writer, retains the directory lock and permits a clean reopen of all 300
  frames;
- reorg state/root/finality/transaction-index tests pass unchanged, and the
  slot index agrees with the replacement log.

## Residual limits

EN-17 moves to `IMPLEMENTED` as a local source finding. This label does not
claim production deployment or a measured fleet reorg SLA. A rewrite remains
O(canonical chain length) in bytes and allocates an owned envelope vector for
the writer. If a subsequent canonical block, second reorg or orderly shutdown
overtakes the writer, the consensus thread waits for it by design so log order
cannot invert. RPC may observe the already validated in-memory reorg before
the replacement log is durable; signing remains blocked throughout that
window.

EN-23 remains `PARTIAL`: this change does not remove full-log loading, cold
replay, retention growth or qualify peak RSS/recovery time at production
scale. KS-07 also remains `PARTIAL`: no persisted frame checksum or policy for
a consensus-invalid replayed frame was introduced. The persisted frame and
index formats are unchanged.

The post-wave ledger contains 200 rows: 67 implemented, 89 partial, 29 open,
seven base-changed, four protocol decisions, two verified positives, one
unarmed candidate and one finding refuted by the original audit. The
architectural EN-17 boundary recorded in WAVE-42 is superseded by this wave;
the other WAVE-42 boundaries are unchanged.

## Validation

Exact commands and outcomes are recorded in `VALIDATION-WAVE-43-STORAGE.txt`.
