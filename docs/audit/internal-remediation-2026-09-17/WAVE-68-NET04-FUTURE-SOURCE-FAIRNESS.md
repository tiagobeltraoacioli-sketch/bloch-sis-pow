# Wave 68 — NET-04 future-pool source fairness

Date: 2026-09-18
Requested base: `99287b4`

## Residual addressed

Authenticated near-future blocks were globally bounded to 32 envelopes and
16 MiB, and their signature work already had per-source quotas. Retention was
not partitioned: one normalized transport source could occupy all 32 entries
until their slots arrived, leaving no future-block headroom for an independent
source that had also passed authentication.

## Change

The future pool now retains at most eight envelopes per `Source`, alongside the
unchanged global 32-envelope and 16 MiB ceilings. Four independent sources can
therefore fill the count ceiling; one source can occupy at most one quarter.

`Gossip(None)` is deliberately one shared bucket rather than an exemption. A
transport that cannot attribute a block still receives bounded headroom but
cannot use missing attribution to monopolize the pool. Local proposals never
enter the future-gossip pool and remain unaffected.

The quota is derived directly from current pool entries rather than a separate
cache. Releasing, promoting, or otherwise removing an entry immediately
reopens that source's capacity without a stale lifetime record. Exceeding the
quota retains the existing `Ignore` result: local capacity pressure is never a
reason to blame or penalize the forwarding peer.

This changes only node-local retention. Authentication, block validity, wire
encoding, fork choice, persistence, peer scoring, and consensus are unchanged.

## Adversarial coverage

`one_source_cannot_occupy_the_future_pool_and_capacity_reopens`:

1. fills all eight entries available to one normalized source across valid
   near-future duties;
2. proves its ninth authenticated envelope is `Ignore` and not retained;
3. proves an independent source still obtains an entry;
4. releases one entry through the ordinary future-release path; and
5. proves the first source can immediately use the reopened capacity while the
   independent source's entry remains intact.

`ready_future_block_release_is_sliced_and_gates_duties` remains green and
continues to prove the Wave 67 one-block release slice and final duty gate.

## Residual risk

- Source identity is node-local transport attribution, not a cryptographic
  owner of the proposal. An adversary controlling several peers or normalized
  client addresses can multiply its eight-entry share up to the global cap.
- `Gossip(None)` callers share one bucket, so unattributed honest senders can
  contend with each other. Treating absence as unlimited would restore the
  original monopolization path.
- Eight maximum-size envelopes from one source can still consume substantial
  bounded memory; the unchanged 16 MiB aggregate byte cap is authoritative.
- Per-source counting scans at most the globally bounded 32-entry pool. It
  avoids a second mutable index, but remains linear in that small bound.
- One retained block may still amplify into bounded orphan promotion and fork
  choice work when released; Waves 66–67 bound scheduling around that work,
  not execution inside the individual block path.
