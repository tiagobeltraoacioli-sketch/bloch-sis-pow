# Wave 54 NET-22: libp2p admission before gossip decode

Date: 2026-09-18. Base: `db7b737`. Scope: production libp2p receive
admission, one focused regression and this evidence note. No endpoint,
deployment setting, consensus rule, activation gate, persisted format or wire
encoding changed.

## Correction

The production gossipsub path previously decoded a block, attestation or
transaction before reserving that peer's bounded first-hop allowance. The
frame itself was capped by gossipsub, and a decoded event could not enter the
engine backlog without a reservation, but a saturated peer could still buy
canonical parsing and decoder allocations for every offered frame.

The receive path now maps the subscribed topic to its event class and charges
the already-bounded `message.data.len()` to the existing per-`PeerId` and
aggregate source registry before invoking any of the three decoders. A refused
reservation reports `Ignore`, because local saturation is not evidence of
peer misconduct. A malformed payload remains `Reject`; dropping its guard
releases the charge automatically.

After a successful canonical decode, the path verifies that re-encoding the
event produces exactly the charged size, attaches the predecode guard to its
`Origin`, and forwards it without taking a second source reservation. Directed
sync blocks, which do not enter through gossip, retain their existing decoded
event admission in `Loop::emit`.

## Regression

`predecode_peer_admission_releases_failures_and_is_not_charged_twice` uses a
one-transaction first-hop allowance. It proves that:

- a reservation taken before decode prevents another frame from using the
  same allowance;
- dropping the guard for a failed decode restores the allowance; and
- an event carrying that guard crosses `Loop::emit`, which would fail if the
  event were charged a second time.

Validation on this checkout:

- predecode release/no-double-charge regression: 1 passed;
- existing first-channel source-admission regression: 1 passed;
- `git diff --check`: passed.

No workspace-wide formatter or test suite was run.

## Residual

NET-22 remains **PARTIAL**. Libp2p has already received and allocated the
bounded gossipsub message before this application callback can reserve it;
this change bounds decoder work and retained first-hop work, not transport
buffer allocation. The shared global engine budget remains a second admission
in the forwarding thread. A valid unindexed block-log tail can still be long,
and RPC `Host` validation remains a browser control rather than client
authentication. Public exposure and fleet firewall policy were not inspected
or changed.
