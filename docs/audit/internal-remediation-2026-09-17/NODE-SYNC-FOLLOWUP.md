# Node admission and sync follow-up — 2026-09-17

This patch changes local boot checks, admission classification, and transport peer selection. It does not change block encoding, committed state, protocol activation gates, signatures, or persisted data formats. No deployment or binary release is implied.

## EN-20 — implemented

The production startup path and registry identity tests now use one `check_registry_identity` implementation. Its behavior is the former production implementation: compare the key at the committed index, advance the supplied generation-specific RANDAO chain by the committed consumed-reveal count, compare the current commitment, and distinguish pending activation, active, and exited records. Existing startup behavior is preserved; the obsolete simplified checker is removed. Admission rehearsal callers use the same helper.

Validation: all nine `gate3_` tests passed; log `/private/tmp/bloch-audit-en20-tests.log`. RANDAO generation/recommit rehearsal remains a separately gated rehearsal, not a claim made by these nine tests.

## EN-21 — implemented

The engine stores the actual genesis validator index set from the manifest instead of comparing an index with manifest length. A failed signature for a genesis identity remains rejectable even when that identity has a high sparse index. A signature failure for an identity absent from genesis remains retryable because another branch can hold a different deposited key at that index. This changes local admission/scoring classification only; transition validation remains authoritative.

Validation: all sixteen admission tests passed, including sparse genesis index 91 and existing deposited-key retry behavior; log `/private/tmp/bloch-audit-en21-tests.log`. The first sandbox attempt failed only because the fixture opens a loopback listener; the successful run was outside that restriction.

## NET-15 — bounded mitigation implemented; shared scheduler remains open

Devnet engine-triggered `GET_BLOCKS` no longer broadcasts to every configured/outbound/inbound peer. It selects at most two live connection queues, rotating across both connection directions. Closed connections are pruned, and full queues do not consume the request's fanout budget. Blocks, attestations, and transaction gossip retain their existing broadcast behavior.

The periodic outbound dialer pump remains separately capped at two holders. Consequently an engine request plus periodic requests can address four distinct sources; this patch does **not** claim a shared two-source budget or a bound on all outstanding responses. A peer can also have multiple connections; selection operates on connections, not authenticated operators. The transport is still unauthenticated devnet TCP.

Validation: `engine_sync_requests_are_bounded_and_rotate_past_full_queues` passed, checking fanout and eventual coverage despite a full queue; log `/private/tmp/bloch-audit-net15-tests.log`. Full node/transport integration qualification is tracked by the release coordinator.

## NET-07 — partial mitigation

Libp2p retains its existing three-request fanout, but one slot rotates across connected PeerIds independently of claimed height. The other two keep the existing height heuristic. For a stable connected set of N peers, every peer gets an exploratory request within N engine sync requests even when adversaries claim `u64::MAX`.

Height hints are still unvalidated and therefore explicitly documented as hints. This does not provide Sybil resistance, fairness under continual peer churn, proof of useful progress, or a cap on all outstanding requests. It closes the deterministic monopoly of a fixed set of top-height claimants without inventing a consensus validation shortcut.

Regression: `sync_exploration_cannot_be_steered_out_by_forged_heights` checks bounded unique selection, coverage of low/unclaimed peers, and empty/single-peer cases. Qualification log: `/private/tmp/bloch-audit-net07-tests.log`.

## NET-14 — open

Periodic devnet sync slot ownership still lasts for the connection lifetime. Engine-request rotation offers another recovery route but does not make the periodic slot lease fair. A complete correction needs one scheduler shared by periodic and engine requests, progress/response attribution, finite leases with reacquisition, and bounded in-flight work. Releasing a slot merely because the applied head has not advanced after five seconds is unsafe: applying a valid page may take longer, and the previous implementation had no reacquisition path.

Required rehearsal before closing NET-14: keep two silent peers connected, connect a responsive third peer, verify recovery while retaining the global request/response budget; repeat with slow honest page application, full queues, disconnect/reconnect, and inbound-only topology.
