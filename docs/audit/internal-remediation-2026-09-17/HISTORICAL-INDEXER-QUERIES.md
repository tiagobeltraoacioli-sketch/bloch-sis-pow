# Historical explorer query corrections — 2026-09-17

This concerns `tools/bloch-indexer`, the Rust archival-log indexer. It is distinct
from the legacy TypeScript reference indexer corrected in wave 6. No live service
was deployed or declared suitable for exchange settlement by these changes.

## Accuracy and explicit errors

TXID and block-transaction queries now obey the canonical snapshot named by a
cursor. A newer transaction or block returns 404 rather than appearing under an
older snapshot's provenance. Invalid block selectors return 400; a well-formed
selector with no matching transaction returns 404. Repeated staking TXIDs remain
ambiguous (409), but matches are paginated with a total and snapshot cursor.

The legacy `/txid/:id` list now honors `limit`/`offset`, returns `total` and
`next_offset`, and defaults to 100 matches instead of an unbounded list. Consumers
that previously expected every match in one response must follow pagination.
Snapshot-cursor routes are preferable when the chain may change between pages.

Both API families refuse failed or stale local synchronization with 503; previously
legacy balance/status/chart routes could keep returning old data after a sync
failure. Provenance identifies the local archival log rather than a hard-coded
host and distinguishes consensus replay from structure-only indexing. Header
finality fields are not presented as independent proof of network finality.

Numeric query parameters reject duplicates, missing values, malformed numbers and
overflow. Zero limits/steps return 400. Block range calculations and supply-step
advancement cannot wrap; an explicit block range still respects its page limit.

The optional RPC comparison tool caps actual response reads at 1 MiB, applies an
absolute I/O deadline, checks HTTP framing/status and JSON-RPC version/request ID,
and reads only the result object. A remote error cannot masquerade as a balance,
and integer heights cannot truncate. It uses the workspace's already-resolved
`serde_json` package; no new dependency version was introduced. Comparisons refuse
a mismatching initial chain anchor or a changed final anchor and report failed
RPC reads as inconclusive, not as a synthetic zero balance. These checks cannot
make multiple RPC calls atomic or authenticate the historical plaintext endpoints;
the tool is diagnostic, not a settlement or finality verifier.

## Resource and mirror handling

Transaction/history cursor pages iterate the stored index without allocating a
second vector containing the entire matching history. Counting still takes time
proportional to the relevant history; this is not an indexed constant-time query.
Some per-block responses and individual transactions can remain large.

Socket reads and writes share an absolute two-second worker-hold deadline. Sending
another header byte no longer renews the timeout. Overflow 503 writes have a
separate short deadline. Synchronous query CPU, serialization and lock acquisition
cannot be preempted; queued connections can wait longer than the worker deadline.
This is not a complete HTTP server or a service latency guarantee.

Log change hints retain subsecond modification time and, on Unix, change time.
A same-inode, same-size mirror overwrite within one second now triggers a rescan.
These metadata hints are not cryptographic content commitments and do not defend
against an adversary who can manipulate all relevant metadata. Node reorg logs
normally replace the inode atomically.

## Validation

Integration regressions cover extreme numbers, range limits, same-size mirror
replacement, snapshot visibility, duplicate TXID pagination, exact satoshi output,
stale synchronization and existing rollback behavior. Real loopback socket tests
cover trickled reads and a nonreading response client. The sandbox initially
refused loopback binding; the authorized external-sandbox rerun passed. Logs and
hashes are recorded in the wave validation record.
