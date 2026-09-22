# Wave 82 — NET-04 / EN-08 orphan-source fairness

Date: 2026-09-19
Starting consolidation: `7176e90`

## Residual addressed

The waiting and ready-to-promote orphan FIFOs shared a hard 256-entry global
cap, but had no source share. One normalized transport source could occupy the
entire pool, evicting every orphan supplied by independent peers and turning
all later honest gaps into replacement churn. Promotion slicing bounded work
per control turn, but did not reserve any retention headroom for another
source.

This was a local fairness gap, not unbounded storage: the aggregate cap and
FIFO eviction were already enforced.

## Hardening

One `Source::Gossip` may now retain at most 32 entries across the combined
`orphans` and `deferred_orphans` queues. Counting both queues is load-bearing:
moving an entry to the ready FIFO must not silently reopen the sender's share
before that entry actually leaves deferred state.

The identity is the existing normalized transport identity carried through
ingestion and promotion. `Source::Gossip(None)` remains one collective
unattributed bucket; the implementation does not fabricate identities for
source-free callers. `Source::Local` is exempt because a transport-fairness
rule must not prevent the node from handling its own proposal path.

The 256-entry global cap and its FIFO policy remain the outer bound. A
source-share refusal drops the new entry, increments the existing internal
`orphans_evicted` counter and remains `Ignore`: capacity pressure is not peer
guilt. Deduplication still runs first, so a repeated envelope neither consumes
another share nor increments the drop counter. The externally published
parked-block gauge remains the existing combined waiting + ready count.

No block validity, signature rule, fork-choice input, wire byte, persistent
format, source normalization or peer penalty changes. Already-retained gaps
continue to drive the existing `needs_sync` path. A new entry refused at its
source share is not retained and does not itself set `needs_sync`; its later
recovery depends on ordinary regossip or a subsequent sync request triggered
by retained chain evidence.

## Adversarial coverage

`one_source_cannot_fill_combined_orphan_queues_and_capacity_reopens` proves:

- one attributed source stops at 32 entries;
- another attributed source retains independent headroom;
- moving one entry from waiting to ready does not reopen the first source's
  combined share;
- removing one ready entry reopens exactly one slot;
- 32 unattributed entries form one collective `Gossip(None)` bucket and the
  next unattributed entry is refused; and
- a local entry remains admissible despite the unattributed transport bucket
  being full.

Exact counter deltas pin all four boundaries: attributed overflow, overflow
while one same-source entry is ready, unattributed overflow, and no increment
for the admitted local control.

The outer-cap fixtures distribute their 256 entries over eight source shares,
so they continue to exercise aggregate FIFO and the shared waiting/ready cap
rather than being shadowed by the new narrower fairness bound.

Focused validation:

```text
cargo check -p bloch-pos-node --tests --offline
# passed

cargo test -p bloch-pos-node \
  one_source_cannot_fill_combined_orphan_queues_and_capacity_reopens \
  --offline
# 1 passed; 0 failed; 577 filtered out

cargo test -p bloch-pos-node deferred_orphan_tail_shares_the_hard_cap_and_deduplication --offline
# 1 passed; 0 failed; 577 filtered out
```

The focused tests require execution outside the sandbox because their engine
fixtures bind ephemeral loopback listeners. Compiler output contained only
existing unused-code/import warnings.

## Residual risk

- Multiple normalized identities can partition the 256-entry aggregate cap;
  this correction is fairness, not Sybil resistance.
- NAT or proxy sharing can make unrelated honest peers contend for one share.
- All source-free callers intentionally contend in the collective bucket.
- The orphan pool is count-bounded rather than byte-bounded; transport frame
  limits bound each envelope, but retained worst-case memory remains a
  separate hardening opportunity.
- One promoted block transition remains non-preemptible and promotion remains
  one block per control turn.

External binary release gates are unchanged: independently authenticated
Linux build comparison, hosted CI evidence, signed release/rollback artifacts,
fresh independent WS evidence, scratch-host rollback rehearsal and staged
canary evidence remain required.
