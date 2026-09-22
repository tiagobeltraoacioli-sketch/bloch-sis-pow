# Wave 69 — NET-04 future-pool byte fairness

Date: 2026-09-18
Requested base: `8e0ebd6`

## Residual addressed

Wave 68 limited one normalized source to eight of the future pool's 32
envelopes. Count fairness did not imply memory fairness: eight near-maximum
envelopes from one source could still consume the entire 16 MiB aggregate byte
budget and leave no retention headroom for another source.

## Change

Future retention now applies a 4 MiB byte ceiling per `Source`, in addition to
the unchanged limits of eight envelopes per source, 32 envelopes globally, and
16 MiB globally. Four independent sources can therefore each reach their byte
share before the aggregate ceiling is exhausted.

The 4 MiB share is intentionally not smaller than the largest locally produced
gossip envelope. A compile-time assertion binds it to
`MAX_PROPOSAL_ENVELOPE_BYTES`, so a future transport-budget increase cannot
silently make one maximum production proposal impossible to retain. One such
proposal always fits an empty source share; additional envelopes fit only
while their combined encoded size remains inside that share.

The existing bounded pool scan now calculates aggregate bytes, per-source
count, and per-source bytes from the same encoded entries. No mutable quota
cache or new lifetime state is introduced. Removing an entry therefore
reopens both its count and byte allowance immediately.

`Gossip(None)` remains a shared source bucket. Exceeding either local ceiling
continues to return `Ignore`: retention pressure is local overload and never
evidence against the forwarding peer. No validity, consensus, wire, fork-choice,
peer-scoring, or persistent-format behavior changes.

## Adversarial coverage

`one_source_cannot_occupy_the_future_byte_budget_and_capacity_reopens` builds
authenticated, commitment-correct envelopes of roughly 3 MiB each and proves:

1. one large envelope from source A fits the 4 MiB share and the production
   gossip envelope ceiling;
2. a second from A exceeds only the source-byte share, receives `Ignore`, and
   is not retained;
3. the same-size envelope from source B is retained while the global budget
   still has room; and
4. releasing A's first envelope immediately allows A to retain another large
   envelope without disturbing B.

The Wave 68 count-fairness regression remains green, proving the byte addition
does not weaken the eight-envelope cap or its lifetime behavior.

## Residual risk

- An adversary with four independently normalized sources can still consume
  the full 16 MiB global budget; the aggregate cap remains the final bound.
- Unattributed honest senders contend in the shared `Gossip(None)` 4 MiB
  bucket. Unlimited missing attribution would recreate the bypass.
- Source attribution is transport-local and can change after reconnects or
  across proxies. It is fairness identity, not cryptographic proposal owner.
- A single near-4 MiB proposal can use almost the whole source share by design;
  refusing it would conflict with the current production transport budget.
- Encoded-size accounting scans at most 32 retained entries and re-encodes
  them on admission. This work is bounded but not cached.
- Per-envelope body hashing and individual release processing remain bounded,
  non-preemptible units addressed only around their scheduling boundaries.
