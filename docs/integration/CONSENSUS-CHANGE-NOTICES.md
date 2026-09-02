<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch Genesis-4 — consensus change notices

Companion to [`CONSENSUS-PARAMETER-REGISTER.md`](CONSENSUS-PARAMETER-REGISTER.md).
Every notice id cited in that register has an entry here, and
`crates/bloch-pos-node/tests/consensus_parameter_register.rs` fails the build
if one does not.

> **Not for the website.** Delivered to integrators directly, as files.

---

## 1. What this channel is

A single low-volume feed that carries exactly one kind of message: **a
Genesis-4 consensus parameter is changing, here is what and when.** No release
notes, no roadmap, no marketing. An integrator subscribes once and can treat
every message as action-required.

### Transports (recommendation — the founder decides)

| Transport | Role |
|---|---|
| `consensus-notices@posternlabs.com` mailing list | primary; one message per notice, plain text |
| This file, in the node repo | the archive of record; a notice exists when it is committed here |
| `getchaininfo` → `pending_activations[]` | machine-readable, so an integrator can alert without reading email |

The third is the one worth building. A notice an operator has to *read* fails
the moment the person who subscribed changes jobs. The RPC field cannot be
missed by a monitoring system that polls `getchaininfo` already — and every
integrator polls it, because it is how they learn `finalized`.

Proposed shape, additive and safe for existing clients:

```json
"pending_activations": [
  {"name": "LEAK_RECOVERY_ACTIVATION_EPOCH", "epoch": 2400,
   "notice": "N-004", "affects": ["finality"]}
]
```

Empty array when nothing is armed. **This requires the founder's approval as
an RPC surface change** and would itself be announced under this policy.

### What a notice contains

Seven fields, all mandatory. The first six are facts; the seventh is the one an
integrator actually acts on.

1. **Parameter** — the exact constant name, as it appears in the source.
2. **Old value → new value.**
3. **Activation epoch** — the authority. Not the date.
4. **Wall-clock estimate** — derived, with the caveat that it is an *earliest*
   bound (see the register, §2).
5. **Scope** — every other parameter that moves in the same switch. The epoch-800
   change moved two constants that are one switch; a notice naming only the cap
   would have been worse than no notice, because it would have been believed.
6. **What breaks if you do nothing** — concretely, in terms of rejected
   transactions or wrong prices, not "may affect compatibility".
7. **What you must do** — a checklist, or the sentence "nothing; this is
   informational".

### Lead time (recommendation)

| Class of change | Minimum lead time | Why |
|---|---|---|
| Anything that changes transaction validity or fee arithmetic | **21 days** | conservation is an equality: a stale integrator is hard-rejected, not delayed, and a custody-side release cycle is measured in weeks |
| Capacity changes (cap/target) | **21 days** | same — the target half changes fee estimation |
| Wire tag additions | **21 days** | a passive indexer's decoder must not choke before it can be updated |
| Finality/leak behaviour, validator economics | **14 days** | affects crediting policy, not transaction construction |
| RPC additions | **7 days** | additive; nothing breaks by ignoring it |
| RPC removals or renames | **90 days** | there is no deprecation mechanism, so the notice *is* the mechanism |
| Emergency security fix | best effort, with a written post-hoc notice within 48 h | stated here so that "emergency" is a named exception rather than an unwritten one |

**What the lead time actually was, measured.** The epoch-800 flag day was armed
at 2026-08-22 02:01 UTC and bound at 18:51 UTC the same day: **under 17 hours**,
and one of the two rules riding it (N-005, the sorted witness table) was
committed at 03:29 UTC, about 15 hours before it became binding. Epoch 1400 was
given roughly five days. Neither was announced. So the recommendation below is
not a tightening of current practice — it is the first practice.

21 days is roughly 1,890 epochs at nominal cadence. Because Genesis-4 does not
produce a block every slot, an epoch target set 1,890 epochs out arrives
*later* than 21 days, never sooner — the lead time is a floor by construction.

**Two constraints the founder should weigh against this.** The flag day already
armed at epoch 1400 was chosen with roughly 491 epochs (5.6 days) of margin
over the measured rollout requirement, which is well under 21 days. And the
current rollout requirement is about 274 epochs, because replay is now minutes
rather than hours. So a 21-day integrator lead time is **not** limited by our
ability to roll the fleet; it is a deliberate choice to let integrators ship,
and it means arming decisions must be made about three weeks before they take
effect rather than one.

### Subscription

An integrator sends one email to `consensus-notices@posternlabs.com`. There is
no self-service portal, no confirmation loop, and deliberately no tiering: the
list is small, the volume is a handful of messages a year, and every recipient
gets every notice.

---

## 2. The notices

### N-000 — Genesis surface, no notice was issued

**Sentinel, not a notice.** Marks every parameter that has held its value since
Genesis-4 launched at slot 0 (2026-08-13 21:31:40 UTC), and every gate still at
`u64::MAX`. Nothing was announced because nothing changed.

`N-000` is rejected by the guard on any row whose gate is armed. It is only
honest for the launch surface and for inert gates.

---

### N-001 — Block payload cap and byte target doubled *(backfilled — never sent)*

| | |
|---|---|
| **Parameters** | `MAX_BLOCK_TX_BYTES` → `MAX_BLOCK_TX_BYTES_V2`, `BLOCK_TX_BYTES_TARGET` → `BLOCK_TX_BYTES_TARGET_V2` |
| **Old → new** | cap `262,144` → `524,288` bytes; target `131,072` → `262,144` bytes |
| **Gate** | `BLOCK_BYTES_V2_ACTIVATION_EPOCH = 800` |
| **Activated** | epoch 800 — **2026-08-22 18:51:40 UTC** |
| **Scope** | both constants; they are one switch and always move together |
| **Status** | **live since epoch 800. This notice was never sent.** |

**What broke for integrators who were not told.** Two things, and the second is
the one that was missed.

The cap alone is benign to under-read: a planner that believes blocks hold
256 KiB simply builds smaller blocks than it could.

The **target** is not benign. The EIP-1559 controller reads utilisation as
`tx_bytes / target`. A planner holding the new cap and the old target reads a
perfectly ordinary 300 KiB block as **2.3× over target**, concludes the chain
is congested, and bids the price up on a block that is at 57% of capacity. It
overpays, and — because conservation is an equality, not a floor — an
overpayment that is not matched by an explicit change output is **rejected**,
not accepted-with-a-tip.

**How it was found.** By an exchange, from chain observation, and dated
2026-08-21 — one day early, because the activation had to be inferred from
block contents. That miss is the strongest argument for this file: the
integrator did the work correctly and still ended up with a wrong number,
because the correct number was never published anywhere.

**Action:** none remaining; already in force. Confirm your fee estimator gates
the target on epoch, not only the cap.

---

### N-002 — Deduplicated-witness transfer format `TransferV2` (`0x06`) *(backfilled — never sent)*

| | |
|---|---|
| **Parameter** | `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH` |
| **Old → new** | `u64::MAX` (inert) → `800` |
| **Activated** | epoch 800 — **2026-08-22 18:51:40 UTC** |
| **Scope** | adds transaction wire tag `0x06`. Tag `0x01` (`Transfer`) stays valid forever and is not deprecated |
| **Status** | **live since epoch 800. This notice was never sent.** |

**What it is.** V1 carries one full witness per input — txid 32 + vout 4 +
pubkey 3,749 + signature 4,775 = 8,560 bytes — so a consolidation spends 30
copies of the same key proving the same statement 30 times. V2 carries a
witness table with one `(pubkey, signature)` per *owner* and 40-byte inputs
that index into it. A 30-input single-owner consolidation goes from ~256,800
bytes to ~9,700, and roughly 6,300 inputs fit in a block instead of 30.

**What breaks if you do nothing.** If you construct transfers: nothing. Keep
emitting `0x01`.

If you **index** the chain: your decoder must not choke on `0x06`. From epoch
800 a block may legally contain a transaction your decoder has never seen, and
a decoder that treats an unknown tag as a fatal parse error stops at that
block. This was the one thing epoch 800 made mandatory for a passive
integrator, and it was announced to nobody.

**Action:** verify your decoder handles `0x06`. Adopt it if you consolidate
UTXOs; ignore it otherwise.

---

### N-003 — Inactivity leak reaches the duty roster *(backfilled — never sent)*

| | |
|---|---|
| **Parameter** | `LEAKED_ROSTER_ACTIVATION_EPOCH` |
| **Old → new** | `u64::MAX` (inert) → `1400` |
| **Activated** | epoch 1400 — **2026-08-29 10:51:40 UTC** |
| **Scope** | `LEAKED_ROSTER_ACTIVATION_EPOCH` only |
| **Status** | **live since epoch 1400. This notice was never sent.** |

**What it is.** Before this, the inactivity leak adjusted the finality quorum
denominator but not `duty_roster_at`, so finality could heal while block
production did not — block rate tracked the share of non-leaked live stake
rather than the surviving validator count. From epoch 1400 the leak reaches
the roster too.

**What breaks if you do nothing.** Nothing constructs differently. Effective
block cadence and therefore *observed confirmation latency* change during a
leak. If you have a hard timeout on "how long a deposit may take to finalize",
recheck it against leak conditions rather than against nominal cadence.

**Action:** informational, unless you alert on block-interval thresholds.

---

### N-004 — F6 seed look-ahead gate removed *(backfilled — never sent; not a value change)*

| | |
|---|---|
| **Parameter** | `ANCESTRY_SEED_ACTIVATION_EPOCH` |
| **Change** | the *gate* was deleted from the code path on 2026-08-24. The constant remains at `u64::MAX` |
| **Status** | the seed rule it once gated is now **unconditional** |

Listed because it is the one change in this file that a value-watching
integrator, or a value-watching guard, cannot see. `ANCESTRY_SEED_ACTIVATION_EPOCH`
still reads `u64::MAX`, and that no longer means "the seed rule is off" — it
means "the constant has no reader". `CommittedState::seed_for_epoch` seeds
epoch `E` from the mix at the close of `E − 1 − MIN_SEED_LOOKAHEAD_EPOCHS`,
always.

**Action:** none. Recorded so that nobody later reads that `u64::MAX` as
evidence of an inert feature. If you maintain your own inventory, mark this
constant as a stub rather than as a disarmed gate.

---

### N-005 — V2 witness tables must be sorted *(backfilled — never sent; **has no constant**)*

| | |
|---|---|
| **Rule** | in a `TransferV2` (`0x06`), the witness table must be **strictly ascending by pubkey** |
| **New rejection** | `WitnessTableNotCanonical` (alongside the existing `DuplicateWitnessKey`) |
| **Commit** | `eec6b7c8`, 2026-08-22 03:29 UTC |
| **Gate** | none of its own — it rides `BLOCK_BYTES_V2_ACTIVATION_EPOCH`/`TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH` = 800 |
| **Status** | **live since epoch 800. This notice was never sent.** |

**This is the most important entry in the backfill, and not because of its
size.** It is a consensus rule that changes which transactions are valid, and
it has **no activation constant of its own** — so it is invisible to any
inventory built by grepping for `ACTIVATION_EPOCH`, including the one an
integrator would build for themselves.

The reasoning for folding it into the existing gate is sound: a second constant
would mean a second flag day for one format. The consequence is not: the
epoch-800 announcement, had it been sent, would have had to cover **two** rule
changes, only one of which is discoverable from the constants.

**What breaks if you do nothing.** If you emit `0x06` transfers with an
unsorted or duplicate witness table, they are rejected — permanently, not
transiently. Sort the table by pubkey before signing.

**Why the register cannot catch the next one of these on its own.** A rule with
no constant leaves no trace in any of the machine tables. Section 3 below
records this as an open gap, and closing it needs a decision, not a test.

---

### N-006 — `gettxout` added *(backfilled — never sent)*

| | |
|---|---|
| **Change** | new RPC method `gettxout [txid, vout]` |
| **Commit** | `eb7874d3`, 2026-08-21 |
| **Status** | live; additive |

Purely additive — nothing breaks by ignoring it. Recorded because the register
now freezes the RPC namespace in both directions, and an addition is exactly
what a one-directional check misses.

---

### N-007 — New RPC error code `TX_REFUSED = -32008` *(backfilled — never sent)*

| | |
|---|---|
| **Change** | new error code `-32008`; a refused transaction is no longer reported as `MEMPOOL_FULL (-32003)` |
| **Commit** | `6a7301ea`, 2026-08-22 01:16 UTC |
| **Status** | live |

**What breaks if you did nothing.** The change is an improvement — `-32003`
means "retry later, the transaction is not invalid", and using it for a
permanent refusal was wrong. But a client that branches on the old code sees an
unknown number and has no rule for it. The two plausible defaults are opposite:
retry forever, or drop a good transaction.

The prose table inside `rpc.rs` still lists only `-32000` through `-32007`.

**Action:** map `-32008` to "refused, do not retry unchanged".

---

### N-008 — `Deposit` and `Delegate` refused at admission unless bonded from the UTXO set *(backfilled — never sent)*

| | |
|---|---|
| **Change** | the node refuses `Deposit` (`0x02`) and `Delegate` (`0x04`) at `sendrawtransaction` unless the bond is funded from the UTXO set |
| **Commit** | `4fd5731c`, 2026-08-14 00:51 UTC — hours after Genesis-4 went live |
| **Scope** | **node-side admission, not a consensus rule.** A block that already carries such a deposit still applies it |
| **Status** | live |

Callers submitting those two transaction types began receiving refusals with
no announcement and no changed constant. Worth stating plainly because it is
the one entry here that is *not* a consensus change: two nodes on different
builds would disagree about what to accept into a mempool while agreeing
completely about every block. If you submit deposits or delegations
programmatically, fund the bond from the UTXO set.

---

### N-009 — Founder vesting schedule changed, and is not enforced *(backfilled — never sent)*

| | |
|---|---|
| **Parameters** | `FOUNDER_CLIFF_SLOTS`, `FOUNDER_VESTING_SLOTS` |
| **Old → new** | cliff `10 × SLOTS_PER_YEAR` → `2 × SLOTS_PER_YEAR`; vesting `40 × SLOTS_PER_YEAR` → `8 × SLOTS_PER_YEAR` |
| **Commit** | `bee1ebdd`, 2026-08-21 — after launch |
| **Status** | live as a published number; **not enforced by any node** |

The announcement question here is not "the cliff moved from 10 years to 2". It
is that **the cliff was never consensus-enforced at all.** `unlock_epoch` is
committed into the allocation txid, so every node agrees on the number, and no
node reads it to authorise a spend. `genesis-mainnet` wrote `0` into all five
buckets. This is pinned by `vesting_is_not_enforced` in
`crates/bloch-pos-node/src/genesis.rs` so that it is a checked fact rather than
a remembered one.

**Action:** if your supply or float model treats founder, VC, team, marketing
or liquidity allocations as locked, it is wrong. They are spendable now.

---

## 2.1 Decisions this needs from the founder

Nothing below has been done. Each is a decision, not an implementation task,
and the register and guard are complete and green without any of them.

1. **Send the backfill.** N-001 through N-009 describe changes that are already
   in force and were never announced. They are written; whether they go out, to
   whom, and with what framing is a founder call. N-001, N-002, N-005 and N-009
   are the four with a concrete action for the recipient.
2. **Approve the lead-time table** in §1, or set different numbers. The
   recommendation of 21 days for validity-affecting changes is roughly 30×
   what epoch 800 actually got.
3. **Approve `pending_activations[]` on `getchaininfo`.** It is the only part
   of this design that touches the node, and it is what makes the channel
   robust to a person changing jobs. It is an RPC surface change and would be
   announced under this policy.
4. **Decide the rule for consensus rules that have no constant** (gap 1 in §3).
   The proposal is that a commit changing `apply_*` acceptance must either
   introduce a gate or cite a notice id. This is a review policy; the guard
   cannot enforce it.
5. **Answer the 2026-08-24 release question** (gap 2 in §3): was a build cut
   between 18:23 and 21:43 UTC? If yes, three consensus rules shipped ungated
   and were withdrawn, and that is a notice.
6. **`LEAK_RECOVERY_ACTIVATION_EPOCH` is still `u64::MAX`** (gap 3 in §3), so
   the quorum floor is not in force. Arming it is a founder decision and is
   deliberately untouched here.

---

## 3. Known gaps in this backfill

Stated rather than glossed, because an inventory that hides its own
incompleteness is worse than none.

**1. A consensus rule with no constant is invisible to the guard.** N-005 is
the proof: a rule that changed transaction validity, folded into an existing
flag day, leaving no new constant to notice. The register freezes constants,
wire tags, RPC methods and error codes — it cannot see a rule that changes the
*meaning* of bytes those tables already list. Closing this needs a policy, not
a test: **every commit that changes `apply_*` acceptance must either introduce
a gate or cite an existing notice id.** That is a founder decision about how
consensus commits are reviewed.

**2. Three consensus rules were ungated in the tree for about three hours on
2026-08-24**, and it is not recorded anywhere whether a build was cut in that
window. Between 18:23 and 21:43 UTC the tree carried an unconditional seed
look-ahead, leak recovery, and the quorum-denominator floor; commit `7b9cb6c6`
re-gated all three at `u64::MAX`. If no release was cut, this is a non-event.
If one was, the fleet ran three unannounced consensus rules and then had them
withdrawn — which is a notice, and a materially different one. **This needs the
release record, which is not in `main`.**

**3. The quorum-denominator ratchet is still live.** `LEAK_RECOVERY_ACTIVATION_EPOCH`
is `u64::MAX`, so the floor at `MIN_QUORUM_DENOMINATOR_NUM/DEN` is **not** in
force. The arithmetic a shipped binary runs today is the one under which
4-of-64 partitions justified three different roots at one epoch on 2026-08-24
(`docs/post-mortems/2026-08-24-finality-divergence.md`). This is not a past
change and so not strictly a notice — but it is the most integrator-relevant
fact in the repository, and any settlement-finality assurance given to an
exchange has to be written against it rather than against the constant.

**4. The 2026-08-24 post-mortem references two divergent mainnet block logs**
(30,578 blocks over epochs 0–1608, and 15,255 over epochs 0–1105). A fork of
the live chain is upstream of every parameter question in this file, and the
register cannot speak to it.

**5. The register was built by reading the tree at `fa4ad9be`.** Pre-genesis
value churn — the supply rescale, the `MIN_DEPOSIT_SAT` moves, the carryover
totals — is deliberately excluded: the chain never ran those values, so they
are not changes to a live network. They are listed in the working notes of this
backfill rather than as notices.

**6. From this commit forward, gaps 1 and 5 are the only ones left.** The guard
fails the build on any change to a registered value, tag, method or error code,
so a future change cannot reach `main` unnoticed whether or not anyone
remembers this file exists.
