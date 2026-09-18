# Wave 53: devnet admission before payload decode

Date: 2026-09-18. Base: `405bfb0`. Scope: local legacy-devnet receive path,
regressions and audit ledger only. No peer or endpoint was contacted, no
deployment changed, and no consensus rule or network encoding changed.

## Correction

The devnet TCP reader previously read a bounded frame, decoded its complete
block, attestation or transaction payload, and only then asked the shared
aggregate and normalized-IP backlog budgets for capacity. A saturated engine
therefore retained bounded memory but an unauthenticated connection could keep
buying decode CPU for frames that were certain to be shed.

The fixed one-byte frame tag now selects the event class and the already
bounded frame length supplies its payload-byte charge. Both per-IP and global
count/byte reservations are acquired before `decode_event` runs. If either
budget is full, the frame is shed without parsing its payload. Malformed or
noncanonical payloads return both reservations, and a successfully decoded
event is admitted only when its canonical encoded size and class exactly match
the pre-decode charge. The existing engine release path then cancels that same
charge.

`FRAME_GET_BLOCKS` keeps its separate serving limiter and never enters this
data-event path. Unknown frame tags remain ignored as before.

## Validation

- `devnet_reserves_before_decode_and_releases_malformed_frames`: passed. A
  malformed attestation-shaped frame is shed against a saturated budget before
  decoding; with capacity available its decode failure restores both global
  and IP reservations.
- `devnet_predecode_charge_matches_the_engine_release_charge`: passed. A valid
  attestation frame reserves exactly its canonical payload size, reaches the
  engine and returns both budgets through the ordinary release/drop path.
- `git diff --check`: passed.

## Residuals

NET-22 remains **PARTIAL**. The frame `Vec` is still allocated and filled under
the existing 8 MiB cap and whole-frame deadline before its type byte can drive
this reservation; this wave removes avoidable decode work, not socket read
work. Libp2p gossipsub still decodes topic payloads before acquiring its peer
backlog reservation, although its message-size limits and scoring remain.
Valid but long unindexed block-log tails and the informational RPC Host/accept
thread observations remain unchanged.
