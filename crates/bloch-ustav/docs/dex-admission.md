# Signed-operation admission for the local DEX host

The optional `native-dex-host` feature exposes `dex_admission::PendingBatch`.
It accepts signed `pool_wire` operations, allowing a host to assemble a candidate
without asking a wallet to construct the final post-state commitment. It is a
volatile queue for one candidate, not a production mempool or an HTTP endpoint.

## Admission and execution

`PendingBatch::new(&journal, height)` binds the queue to the journal's current
height/root and a later height supplied by the authenticated host. A poisoned
journal cannot start or service admission. Callers cannot provide a different
signature verifier or choose another parent through an operation frame.

`admit(&journal, frame, current_height)` reexecutes the entire ordered prefix
plus the new frame using fixed hybrid PQ verification. This supports deposits or swaps that consume
outputs created by earlier pending operations. It checks resource limits before
copying the new frame and appends bytes only after successful verification. The
returned outcome is a preview; no balances, fees, reserves or journal bytes have
changed and no inputs have been reserved. Invalid signatures, wrong domains,
expiry, dependencies or duplicate requests preserve the previous pending frames.
They do not roll back the trusted height watermark.

`build(&journal, current_height)` revalidates the pending prefix and constructs
an ordinary `BLCHPCAN` candidate without modifying pending frames or persistent
state. Its height watermark can advance.
`commit(&mut journal, current_height)` builds the candidate and submits it through
the journal's own full verification and write/sync/commit boundary. Only success clears and
closes the batch. Any failure preserves pending frames; journal I/O failures
also poison the journal according to its existing recovery contract.

The complete parent checkpoint is checked on every operation. A batch becomes
stale if another candidate changes the journal, including a competing batch from
the same parent. The host must create a new batch and revalidate resubmitted
operations; the API does not silently rebase them or trust an earlier preview.
A successfully committed batch cannot be reused.

## Bounded body reading

`admit_from_reader(&journal, &mut reader, declared_length, current_height)` reads
one request body before invoking the same signed-operation admission. It checks
journal health, parent, monotonic height, operation capacity and remaining byte
quota before reading. A closed/stale batch or an excessive declared length is
rejected without consuming the body. The height watermark still advances after
successful context checks, even if reading or subsequent validation fails.

`declared_length` is optional and untrusted. A nonzero declared size must fit the
remaining quota and exactly match the body. With no declared size, the reader
accepts at most the remaining quota. It consumes at most the applicable limit
plus one byte, using that extra byte to detect an overlong body. Buffer reservation
is bounded by the same value (at most 262,145 bytes); it does not grow according
to an unchecked request header. Empty bodies, premature end-of-body, excess bytes
and I/O errors leave pending frames, confirmed state and journal bytes unchanged.
Interrupted reads are retried; fragmented reads preserve the exact payload.

The reader must delimit a single decoded request body and return EOF at its end.
Do not pass a raw keep-alive TCP connection: an HTTP framework must handle message
framing, conflicting length headers and transfer decoding. After rejection, the
transport must safely discard the remainder or close the request/connection;
the reader deliberately does not drain an arbitrarily long malicious body.
The transport must also impose deadlines and connection/rate limits. This
synchronous method does not establish its own timeout or register an endpoint.
A successful read/admission is still only a preview; commit must obtain a fresh
trusted execution height and revalidate before persistence.

## Current-height validation

Every admission, build and commit now requires a fresh `current_height` from the
host's authenticated chain context. This is the current candidate execution
height, not the journal's last committed height or a wall-clock timestamp.
The initial queue height is no longer reused
implicitly for a delayed commit. The queue remembers the highest height observed
for its parent and rejects smaller values with `HeightRegression`. The watermark
advances after parent/health checks even if subsequent decoding or validation
fails, so a failed expired request cannot be retried at an older height.

For example, a batch admitted at height 4 with signatures valid through height
100 is refused when committed at height 101. It remains buffered but cannot be
committed by supplying height 4 again. An unexpired batch delayed to height 5 is
fully revalidated, encoded and journaled at height 5. This metadata change does
not rewrite signed frames or extend their deadlines.

This is an intentional local API change: `admit`, `build` and `commit` require
an explicit height, and `build` now borrows the queue mutably to retain the
watermark. The host must not obtain this value from an untrusted request body or
reuse a cached admission height. The library cannot independently authenticate a
caller-supplied chain height. `height()` reports this local watermark, not finality.
No wire format or journal migration is required.

## Bounds and trust boundary

The queue retains at most 128 signed frames and 262,144 payload bytes. Count and
actual byte bounds precede allocation of a new payload. The existing batch
preflight also limits aggregate declared bytes and gas before cryptography.
Exact duplicate frames are rejected directly; alternate encodings or witnesses
cannot evade the underlying input-spend, authorization and replay checks.

Each admission revalidates its prefix; across a full queue the verification work
is quadratic in operation count, bounded by the fixed limits. Build and durable
commit revalidate as well. Production ingress still needs authenticated context,
rate and connection limits, scheduling and CPU/memory measurements. This API
does not promise fairness, reserve funds or report a transaction as finalized.

Pending frames are intentionally not durable and are lost if the host exits.
Clients must distinguish a successful preview from a durable commit and from
consensus finality. Only the existing candidate journal persists committed local
results. Neither queue admission nor journal commit authorizes a bridge payout.

## Validation

Real hybrid PQ integration tests enqueue two dependent deposits and a provider
redemption, then commit and reopen the journal. They check invalid signatures,
wrong domains, expiry, out-of-order operations, duplicates, malformed later
frames, stale parents and closed-batch reuse. Delayed-commit tests reject expiry
at the current height, prevent backdating after failure and persist unexpired
batches at the newer height. Preview and rejection preserve the confirmed state
and file bytes; commit matches direct execution, fees and
custody. Capacity tests cover exact byte/count limits and arithmetic overflow.
Body-reading tests cover known/unknown lengths, bounded overlong input, empty
and short bodies, fragmentation, interrupted reads and transport errors. Real PQ
integration exercises body reading through durable commit and journal reopen.

No live node dependency, RPC route, block transaction variant, fee settlement,
wallet connection flow or bridge activation is introduced by this local API.
