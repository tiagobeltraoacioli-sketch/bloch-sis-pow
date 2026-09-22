# Node admission and sync follow-up — 2026-09-17

This patch changes local boot checks, admission classification, and transport peer selection. It does not change block encoding, committed state, protocol activation gates, signatures, or persisted data formats. No deployment or binary release is implied.

## EN-20 — implemented

The production startup path and registry identity tests now use one `check_registry_identity` implementation. Its behavior is the former production implementation: compare the key at the committed index, advance the supplied generation-specific RANDAO chain by the committed consumed-reveal count, compare the current commitment, and distinguish pending activation, active, and exited records. Existing startup behavior is preserved; the obsolete simplified checker is removed. Admission rehearsal callers use the same helper.

Validation: all nine `gate3_` tests passed; log `/private/tmp/bloch-audit-en20-tests.log`. RANDAO generation/recommit rehearsal remains a separately gated rehearsal, not a claim made by these nine tests.

## EN-21 — implemented

The engine stores the actual genesis validator index set from the manifest instead of comparing an index with manifest length. A failed signature for a genesis identity remains rejectable even when that identity has a high sparse index. A signature failure for an identity absent from genesis remains retryable because another branch can hold a different deposited key at that index. This changes local admission/scoring classification only; transition validation remains authoritative.

Validation: all sixteen admission tests passed, including sparse genesis index 91 and existing deposited-key retry behavior; log `/private/tmp/bloch-audit-en21-tests.log`. The first sandbox attempt failed only because the fixture opens a loopback listener; the successful run was outside that restriction.

## NET-15 — shared request scheduler implemented; response accounting remains partial

The engine and periodic timer now use one scheduler for both inbound and outbound devnet connections. At most two five-second request leases are active. Each lease authorizes one request, and each connection can hold only one queued authorization. The writer consumes authorization once, checks expiration immediately before writing, and ignores stale/mismatched queued frames. Reconnection cannot turn a backlog of expired requests into an unbounded request burst.

A FIFO waiting queue rotates lease acquisition. New connections join behind existing waiters but ahead of peers already served in the current round. Failed/full writer queues do not consume a lease. Closed peers are pruned and their lease capacity becomes available. New fetching pauses while either event count or charged wire bytes reaches half of the shared engine queue budget, and resumes automatically when application drains that queue. Existing admission enforces the full 4,096-event / 64-MiB charged-wire-byte caps even for late replies; those caps do not include every allocator/decoder/kernel-buffer allocation.

Outbound readers now answer reverse-direction requests with the same page size, global/IP request budget, per-connection rate limiter, and per-frame writer lock used by inbound serving. Serving runs in at most one worker per connection and four workers globally across both directions and reconnect generations, with no queued pages and a guard retaining the global worker permit and connection/IP capacity until completion; both readers stay free to drain traffic. This prevents simultaneous bidirectional pages from deadlocking TCP send buffers. Without this correction, a scheduler could select an inbound-only connection but the remote dialer's reader would silently ignore its request. Older peers remain wire-compatible, although this reverse-direction recovery path requires a remote implementation that serves it.

**Remaining limitation:** five seconds bounds a request lease, not response completion. Legacy devnet responses are bare block frames without request IDs, page termination, or an explicit empty-page answer. Slow/late replies may overlap across expired leases. The patch does not claim at most two outstanding responses, a bound on total network bandwidth, or authenticated-peer/operator fairness. Exact response-window accounting requires separately qualified protocol framing or connection cancellation; honest connections are deliberately not closed when their lease expires. Serving-side global/IP/per-connection rate limits and receive-queue count/byte admission remain separate defenses.

Validation: the first five `shared_sync` regressions passed in `/private/tmp/bloch-audit-wave4-shared-sync.log`. Final qualification, including two additional regressions exchanging simultaneous 4-MiB pages in both directions and enforcing global serving capacity across disconnected generations with socket closure after response write failure, passed with all 23 transport tests in `/private/tmp/bloch-audit-wave4-net-final-frozen.log` (exit 0). The final tested `net.rs` SHA-256 is `6bc92f5842cde8b372fc6d92f41af1a081024160c76efcc6289e1eeda2d8cbea`. They cover shared engine/timer leases, rotation without applied-head progress, backpressure and resumption, full writer queues, disconnect/reconnect, expired queued requests, two silent outbound peers with a responsive inbound third peer delivering a block over TCP, and reverse-direction serving of a real stored block. The received-block fixture verifies transport delivery, not consensus acceptance or an end-to-end catch-up SLA. Full transport and node qualification are tracked separately.

## NET-07 — partial mitigation

Libp2p retains its existing three-request fanout, but one slot rotates across connected PeerIds independently of claimed height. The other two keep the existing height heuristic. For a stable connected set of N peers, every peer gets an exploratory request within N engine sync requests even when adversaries claim `u64::MAX`.

Height hints are still unvalidated and therefore explicitly documented as hints. This does not provide Sybil resistance, fairness under continual peer churn, proof of useful progress, or a cap on all outstanding requests. It closes the deterministic monopoly of a fixed set of top-height claimants without inventing a consensus validation shortcut.

Regression: `sync_exploration_cannot_be_steered_out_by_forged_heights` checks bounded unique selection, coverage of low/unclaimed peers, and empty/single-peer cases. Qualification log: `/private/tmp/bloch-audit-net07-tests.log`.

## NET-14 — connection-lifetime slot capture corrected

The old dialer-owned lifetime slots are removed. The shared scheduler described above expires and reacquires request leases without requiring an applied-head change, a reconnect, or an engine-triggered request. In a stable connected set with writable queues and a draining engine budget, FIFO rotation eventually gives every connection another request. A slow honest peer stays connected, late blocks remain admissible through the normal queue budget, and fetching resumes after application backpressure clears.

The deterministic lease tests cover repeated reacquisition at an unchanged head. The TCP regression first gives both slots to silent outbound peers, then connects a responsive inbound peer and verifies its requested block reaches the engine channel after rotation. This is a bounded correction to request fairness; peer churn/Sybil resistance, true response-completion attribution, consensus validation, and measured fleet recovery time are separate claims.
