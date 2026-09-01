<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch Genesis-4 — settlement guidance for integrators

```
Document:  BLOCH-G4-SETTLEMENT-NOTE
Audience:  exchange integration, custody and risk teams
Chain:     Bloch Genesis-4 · BLCH · proof of stake · live mainnet
Describes: the released binary — main @ ad53573
Prepared:  2026-09-01
Delivery:  file, to named contacts. Not published. Not a shared artifact.
Supersedes: §5.1 of BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md, which states the
           settlement guarantee without its conditions and contradicts §5.3–5.5
           of the same document thirty lines later.
```

## 0. The short version

**`finalized` on Genesis-4 today is a strong signal, not a settlement
guarantee.** Two independent defects sit behind it. Neither is a bug in the
finality mathematics; both are in how the node applies it.

1. The quorum denominator can shrink until a small partition reaches two thirds
   of what is left, so **two nodes can report the same finalized epoch under
   different roots**.
2. The node's finalized checkpoint is **not a latch**: a reorg can install a
   state whose finalized epoch is lower than the one the node was reporting a
   moment earlier, so **`finalized: true` can become `justified` or
   `canonical`**, and `finalized_height` can go down.

Defect 1 is mitigated by reading from two nodes. **Defect 2 is not** — both
nodes can rewind, and they can rewind independently. Only a depth margin plus
re-verification addresses it, and neither of those is a proof.

Nothing here requires you to stop integrating. It requires you to credit later
than the protocol's own signal says you may, and to hold rather than retry when
the signals disagree.

## 1. When to credit

| Stage | Signal | Action |
|---|---|---|
| Accepted | `sendrawtransaction` → `accepted: true` | in one node's mempool. Nothing. |
| Included | output visible via `gettxout` / `getutxos` | in a block. Nothing. |
| Finalised | `getchaininfo.finalized.epoch` ≥ the block's epoch | **not yet** — see below |
| **Settled, operationally** | `finalized.epoch` ≥ block's epoch **+ 3**, on **two independent nodes** reporting the **same finalized root at the same epoch**, re-verified immediately before release | **credit** |

### Timing

A transaction included in epoch `E` is first covered by checkpoint `E+1`. That
checkpoint justifies at the first block of `E+2` and finalises at the first
block of `E+3` (Casper k=1). At 32 slots × 30 s = **16 minutes per epoch**:

- protocol finality: **just over 2 epochs, realistically 2–3 — 32 to 48 minutes**
- with the +3 epoch margin below: **5–6 epochs — roughly 80 to 96 minutes**

Under degraded participation both figures are **unbounded**. Do not size a
customer SLA off the floor; size it off your observed distribution and keep a
manual hold path, because a stall does not currently clear itself.

### Where the "+3" comes from, and what it is worth

It is an empirical margin, not a bound, and you should hold it as such.

Fork choice walks from the **justified** root, so the deepest cut it may
legitimately propose — with no invalid block, no misbehaving peer and no rule
broken — is down to the justified checkpoint. The state committed at that block
carries a finalized epoch **two epochs below** the head's. So one such cut
rewinds `finalized` by two epochs, and a margin of three covers it with one
epoch to spare.

Measured on the released code: a node finalising epoch 6 with its justified
root at canonical height 13, cut to that root, finalises epoch 4 — a two-epoch
rewind with nothing broken.

**What it does not cover, and this is the part to plan around.** After a
rewind, the node reads its justified root out of the *rewound* state, so the
next fork-choice walk starts lower than the last one did. Successive rewinds go
progressively deeper and nothing in the current binary bounds the descent. The
same measurement, taken three cuts in a row: walk-root heights 13 → 9 → 5 → 1,
finalized epochs 6 → 4 → 2 → 0. Three legitimate cuts and the node is back at
genesis.

A margin makes the single-reorg case safe. It makes the compound case less
likely, not impossible. **There is no depth at which we can tell you the risk is
zero, and we are not going to publish one.** The margin is one control among
four; the re-verification in §2 and the alerts in §3 are the others, and none of
them is optional.

## 2. What to re-verify, and when

Read `finalized` once and act on it later and you are acting on a fact that may
have been withdrawn in between. The re-verification is the point.

**Immediately before you release funds — not at credit time, not on a schedule:**

1. `getchaininfo` on **node A** and **node B** independently. Require
   `finalized.epoch` equal **and** `finalized.root` equal. Different roots at
   the same epoch is defect 1 in progress: **hold**, do not retry.
2. Require `finalized.epoch` ≥ (deposit block's epoch + 3) on **both**.
3. Require `finalized.epoch` on each node to be **≥ the highest value that node
   has ever reported to you**. You must keep that high-water mark yourself —
   the node does not expose one, and `getchaininfo` reports where finality *is*,
   never where it has *been*. A decrease is defect 2 in progress: **hold**.
4. `gettxout` the specific output on both nodes and require it still present and
   unspent. A deposit that has stopped being visible is a hold, not a retry.
5. `getblockbyslot` for the deposit's block and require `"finality":
   "finalized"` still. A block that has stopped being finalised is a hold.

Note on step 5: the node classifies a block by comparing its slot against the
slot of the finalized checkpoint **on that node's canonical chain**
(`engine.rs:finality_of`). If a reorg drops the finalized root off the canonical
chain, the lookup finds nothing and the block silently reports `justified` or
`canonical` instead. The downgrade is the signal. There is no error field for it.

## 3. Alerts you should run

These are cheap and they are how you find out before your reconciliation does.

- **`finalized.epoch` decreasing on any node.** Should never happen. Does.
- **The finalized root at a given epoch changing.** Should never happen. Does.
- **Two nodes reporting different roots at the same finalized epoch.** This is
  defect 1 and it is the one that has actually been observed on mainnet: on
  2026-08-24 three nodes finalised the same epoch under three different roots.
- **`finalized.epoch` not advancing, tracked independently of height.** Block
  production and finalisation are separate systems here. Heights advance,
  `getblockbyslot` keeps answering, the node looks entirely healthy, and
  deposits quietly stop being creditable.
- **A block that reported `finalized` reporting anything else.**

**One anti-alert.** Do **not** read a rising `finalized` as evidence the network
has reunified. Because the denominator shrinks with absent stake and has no
floor in the shipped binary, a partitioned minority reaching two thirds of what
remains will finalise its own branch and its `finalized.epoch` will climb
steadily and look healthy. Recovery and divergence produce the same graph.

## 4. What we are doing about it

Stated so you can judge the timeline, not as a commitment to a date.

- **Defect 1** — a quorum-denominator floor and a leak-recovery rule are both
  written and both in the shipped binary, inert behind
  `LEAK_RECOVERY_ACTIVATION_EPOCH = u64::MAX`. Arming them changes the committed
  state root, so it is a flag day with a full fleet rebuild, not a
  configuration change. The floor bounds divergence to at most three ways; it
  does not make the finalized root unique, and we would rather say so than let
  you infer otherwise.
- **Defect 2** — a finality latch (a node refuses any head that does not descend
  from its own finalized checkpoint) is written and ships inert behind its own
  flag day, with detection and logging active from the first build that carries
  it, so we can measure how often it would fire before anyone turns it on.

We will tell you when either is armed, because the guidance in §1 changes when
they are.

## 5. What we have not verified

- These figures are from the released binary and its test suite, not from a
  measurement of a live divergence in progress.
- The `+3` margin is reasoned from, and measured against, the depth of a
  *single* legitimate fork-choice cut. It has not been validated against an
  adversary who is trying, and by construction it does not bound the compound
  case.
- We have no production measurement of how often defect 2 fires, because until
  now nothing in the node counted it.
