# Wave 58 NET-22: bounded valid unindexed-tail serving

Date: 2026-09-18. Base: `0c78e38`. Scope: derived block-index fallback,
one focused regression and this evidence note. No endpoint, network protocol,
wire encoding, consensus rule, persisted authoritative format or deployment
changed.

## Correction

The block-serving path already fails boundedly when `blocks.idx` is missing,
corrupt or disagrees with the authoritative log. A valid index may lag the log
by design, however: the log is fsynced before its best-effort index record is
appended. Serving therefore begins at the last covered offset and scans the
valid unindexed tail.

The ordinary crash window is one frame, but after a persistent index-append
failure the live process disables later index appends to preserve a contiguous
prefix. Without a work bound, that valid tail could grow for the rest of the
process lifetime, allowing a remote `get-blocks` request beyond its tip to
parse every tail header before returning an empty page.

Only this unindexed-prefix fallback is now limited to 4,096 complete frames per
request. Crossing the limit returns a bounded `InvalidData` error instructing
the operator to restart, which runs the existing derived-index rebuild. Binary
search hits backed by an index record are unchanged and remain governed by the
existing response-count and response-byte caps. A short crash-window tail is
still served byte-for-byte as before.

At a 30-second slot cadence, 4,096 frames are more than one day of missed index
appends. The allowance is deliberately operational headroom, not a claim that
leaving the derived index degraded that long is healthy.

## Regression

`an_excessive_unindexed_tail_fails_at_the_scan_bound` creates four valid log
frames, truncates the derived index to the first record and invokes the scanner
with a test-only allowance of two. It proves that the third frame returns the
restart/rebuild error before its header is parsed. The same three-frame tail is
then served through the production 4,096-frame allowance, pinning short-tail
compatibility.

Validation on this checkout:

- `cargo test -p bloch-pos-node an_excessive_unindexed_tail_fails_at_the_scan_bound -- --nocapture`:
  passed in both targets that compile the store tests (node unit target: 1
  passed, 540 filtered out; `recovery_fence`: 1 passed, 80 filtered out);
- `git diff --check`: passed.

No workspace-wide formatter or broad suite was run.

## Residual

NET-22 remains **PARTIAL**. A request can still inspect up to 4,096 unindexed
headers, and a tail beyond that point is unavailable until local restart or
repair; this mitigation bounds remote work rather than healing the failed
sidecar online. The index is derived and disposable, while `blocks.log`
remains authoritative and unchanged. Libp2p still allocates its bounded gossip
frame before the application callback, and RPC source/Host controls remain
fairness/browser gates rather than authentication. Fleet deployment and
firewall policy were not inspected or changed.
