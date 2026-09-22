# Wave 88 — NET-04 bounded connection-churn diagnostics

Date: 2026-09-19
Starting consolidation: `cc966a8`

## Residual addressed

The libp2p transport already bounded concurrent and pending connections, but a
remote identity could repeatedly complete and close connections over time.
Every `ConnectionEstablished` printed synchronously, and every last
`ConnectionClosed` printed synchronously with its cause. Concurrent ceilings do
not bound that longitudinal event rate, so connection churn could produce an
unbounded stream of stdout writes on the swarm thread. The prominent `NO PEERS`
outgoing-dial diagnostic was likewise outside the existing diagnostic limiter.

This is a logging/availability residual under NET-04, not a consensus or wire
acceptance defect. A peer still has to complete transport work, and connection
limits continue to cap simultaneous occupancy.

## Hardening

A private `connection_diagnostic` helper routes connected, disconnected,
no-peer dial failure and inbound handshake failure messages through the
existing `rejection_log::Class::Connection` window. That window emits at most
eight connection diagnostics per ten seconds, reports the preceding suppressed
count when a new window emits, and increments the existing exact cumulative
`bloch_pos_rejection_logs_suppressed_total` metric.

Only formatting and output live inside the suppressible closure. Peer-count
updates, address bookkeeping, `forget_peer`, in-flight cleanup and
`pump_sync_requests` remain unconditional and outside it. Log suppression
therefore cannot retain a disconnected peer, lose a sync slot or skip recovery
work.

No frame, protocol, consensus rule, verdict, cap, peer score, persistence/API
format or recovery policy changed. This also preserves the diagnostic cause on
the connection messages that are admitted by the log window.

## Adversarial coverage

`connection_log_suppression_never_suppresses_disconnect_state_work`:

- drives 100 connection diagnostics and proves no more than the eight-message
  burst formats, while every denied callback increments the shared suppression
  counter;
- immediately processes a synthetic last-connection close while that class is
  saturated and proves that close itself increments suppression;
- proves peer count decrements, peer head/address/sync-limiter state is
  forgotten, the closed peer's request is removed, and the next queued sync
  request is pumped despite suppressed logging.

The existing deterministic local-logger regression continues to pin exact
burst accounting, window recovery and summary counts independently of global
test state.

## Validation

```text
cargo check -p bloch-pos-node --tests --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos \
  connection_log_suppression_never_suppresses_disconnect_state_work \
  --offline -- --nocapture
# 1 passed; 0 failed; 588 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  rejection_logging_burst_counts_every_suppression_and_recovers \
  --offline -- --nocapture
# 1 passed; 0 failed; 588 filtered out
```

Compiler output contained only existing unused-code/import warnings.

## Residual boundaries

- The limit is global to the connection diagnostic class, not per peer.
  Identity churn can suppress detail from an honest connection event in the
  same window; the summary/counter remains exact and peer-count metrics remain
  authoritative.
- This does not assign peer guilt, ban identities or provide Sybil resistance.
- Startup/listener output and local storage/publish failures are not remote
  connection-lifecycle churn and remain outside this focused change.
- Full node, hosted CI, Linux reproducibility, release signing, rollback and
  fleet qualification remain outside this focused correction.
