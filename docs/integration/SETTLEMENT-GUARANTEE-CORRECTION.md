# Correction — the settlement guarantee in the Bloch Genesis-4 Integration Book

```
Document:   SETTLEMENT-GUARANTEE-CORRECTION
Issued:     2026-09-01
Audience:   Exchange integration, custody and risk teams holding any revision
            of BLOCH-GENESIS4-EXCHANGE-INTEGRATION dated before 2026-08-31
Corrects:   BLOCH-GENESIS4-EXCHANGE-INTEGRATION §5.1
Status:     Partner document. Never published, never a shared artifact.
            Delivered as a file, to named contacts.
Raised by:  us, not by you. This is not a response to a finding.
```

## 1. What we told you, and what we are retracting

The previous revision of the Integration Book said, of crediting a deposit:

> *"Included is not settled: a block that is canonical now can be reorganised,
> and only finalisation is the cryptographic guarantee."*

and set the expected wait at "typically 1–2 epochs (16–32 minutes)".

**Both halves are wrong, and the first is the one that matters.**

- Finalisation on this chain is **not currently a cryptographic settlement
  guarantee.** It is a two-thirds-of-active-stake vote whose denominator we do
  not currently bound, and whose result the node does not currently latch. A
  reader who took that sentence at face value would build a credit rule that
  releases funds on a signal that can be produced by a small partitioned
  minority, and that can subsequently be withdrawn.
- The timing figure was also wrong, in the harmless direction: finality takes
  **2–3 epochs (32–48 minutes)** from inclusion, not 1–2, and is unbounded
  under degraded participation.

We found this by auditing our own document against the released binary after
you reported three unrelated inaccuracies in it. You did not ask about
settlement. We would rather you learned this from us than from your
reconciliation.

## 2. What is actually true

Two defects, and they are **independent**. The mitigation for the first does
not touch the second. Both are properties of the released binary, `main` @
`e4083f9` — not of a branch, not of a plan.

### 2.1 The quorum denominator shrinks, with no floor and no recovery

A checkpoint is justified when attestations reach two thirds of the **active**
stake, and finalised by consecutive justification. That denominator is
leak-adjusted: stake belonging to validators we have not heard from is
subtracted. That much is deliberate and normal — it is what lets a chain keep
finalising when part of the set is offline.

What is not normal is that **nothing bounds the subtraction.** The leak
accumulator has exactly one write path, accrual. There is no decay, no reset
and no removal. The denominator therefore shrinks monotonically and never
recovers. Carried far enough, a handful of validators — one, in the limit —
hold two thirds of what remains and finalise alone.

Two mitigations are compiled into the binary and **neither can execute**: leak
recovery, and a floor holding the denominator at half the unleaked total. Both
sit behind an activation constant set to `u64::MAX`. They are gated for a real
reason — either rule changes which checkpoints justify, justification is
committed into the state root, and applying them to historical epochs makes a
node compute a root the existing headers do not carry, which stops its replay
dead. Arming them is a flag day with a fleet rebuild, not a configuration
change. We are not going to pretend that is imminent.

**This is not hypothetical.** On 2026-08-24, three nodes finalised epoch 986
under three different roots, and no amount of arriving blocks reunified them.

**Consequence for you:** `finalized` is not currently guaranteed to be the same
value on every node. A single node reporting `finalized` may be reporting the
finality of a partition containing only itself.

### 2.2 `finalized` is not a latch — it can move backwards

Inside the finality gadget the finalized checkpoint is monotone: it is only
ever replaced by a strictly higher one. **But the node does not own that gadget
across a reorg.** A reorg replaces the committed state wholesale with an
ancestor's and adopts it unconditionally; nothing on that path compares the
incoming finalized checkpoint against the outgoing one. Fork choice walks from
the *justified* root, not the finalized one, and nothing prunes branches by
finalized checkpoint.

So a reorg down to the justified root installs a state whose finalized epoch
predates the one the node was reporting a moment earlier. Concretely:
`getchaininfo.finalized.epoch` can decrease, and a block that `getblockbyslot`
returned with `"finalized": true` can subsequently come back as `"justified"`
or `"canonical"`.

**Two nodes agreeing does not mitigate this.** Both can rewind, and they can
rewind independently. Agreement protects you against §2.1's divergence and
gives you nothing against §2.2's rewind. Only a depth margin does, which is why
the procedure below has one.

**We cannot yet give you a bound on rewind depth.** We have not measured a
distribution and we are not going to quote you a number we have not measured.
§3 tells you how to choose a margin without one, and how to detect when your
choice was too small.

## 3. What to do instead — exactly

This supersedes §5.1 of any revision you hold. It uses only methods and fields
that exist on the released binary; nothing here is scheduled or branch work.

**Prerequisite: run two independent nodes.** Independent means separate hosts,
separate network paths and separate peer sets — not two processes on one box
and not two connections to the same host. Our own public RPC front end refuses
a read unless two nodes concur, and it was indefensible to hold you to a weaker
standard than we hold ourselves. If you can only run one, credit manually.

Let `N1` and `N2` be those nodes and `M` your depth margin in epochs (see 3.6).

### 3.1 Record the deposit by outpoint, with its epoch

There is no transaction id on this chain and no txid→block index; do not build
around one. Detect the deposit by polling `getbalance [script_hash]`, expand
with `getutxos [script_hash, limit]`, and key your record on the outpoint
(`txid`, `vout`).

`getutxos` does **not** return a slot. Get it from `gettxout [txid, vout]`,
which returns `at_slot`, and derive:

```
deposit_epoch = at_slot / slots_per_epoch     // slots_per_epoch from getchaininfo (32)
```

Read `slots_per_epoch` from the node rather than hard-coding 32.

### 3.2 Require both nodes to agree, on epoch and root

Call `getchaininfo` on `N1` and `N2`. Credit only if **all** of the following
hold:

```
N1.finalized.epoch == N2.finalized.epoch
N1.finalized.root  == N2.finalized.root      // compare the root, not just the epoch
N1.finalized.epoch >= deposit_epoch + M
```

Comparing epochs alone is not sufficient and is the mistake to avoid: §2.1's
failure mode is precisely two nodes at the *same* epoch under *different*
roots. **Disagreement on the root is a hold condition, not a retry.** Stop
crediting against that address, alert an operator, and do not resume
automatically. A retry loop will eventually find a moment when both nodes agree
and will credit against a state you have already been told is inconsistent.

### 3.3 Re-verify immediately before releasing funds

Do not treat a `finalized` reading as durable — that is the whole of §2.2.
Between deciding to credit and releasing value, re-run:

- `gettxout [txid, vout]` on both nodes — the output must still be `unspent`
  and still report the **same `at_slot`**. A changed `at_slot` means the
  transaction was re-included on a different branch and your deposit epoch was
  wrong.
- the §3.2 agreement check again.

If either fails, hold. Do not release on the strength of the earlier reading.

### 3.4 Credit past finality, never at the boundary

`M` is not optional and it is the only mechanism here that absorbs a rewind.
Crediting at `finalized.epoch >= deposit_epoch` — the boundary — gives you no
protection at all, because that is exactly the value that can move backwards.

### 3.5 Alert on all four of these, separately

1. **`finalized.epoch` not advancing, independently of height.** Production and
   finalisation are separate concerns here. Heights advance, `getblockbyslot`
   keeps answering, the node looks healthy, and deposits silently stop being
   creditable. A liveness check on block height will not catch this.
2. **`finalized.epoch` moving backwards**, on either node.
3. **The finalized root at a given epoch changing**, on either node. Neither
   this nor (2) should ever happen; both do.
4. **The two nodes disagreeing** on either field.

Alerts 2 and 3 are your evidence that `M` was too small. Size `M` up from
whatever depth you observe, and tell us what you observe — we want the
measurement as much as you do.

### 3.6 Choosing `M`, absent a measured bound

We cannot give you a distribution yet, so choose defensively and instrument:

- Start well above the finalisation floor of 2–3 epochs. A margin that is a
  small multiple of that is not meaningful protection against a reorg deep
  enough to move a finalized checkpoint.
- Scale it to exposure. A per-deposit ceiling below which you credit at a small
  `M`, with larger amounts held to a much larger `M` and to manual review, is a
  reasonable posture and is what we would do.
- Treat any firing of alert 2 or 3 as a signal to raise `M`, and never lower it
  on the basis of a quiet week — §2.1 means quiet does not imply healthy.

### 3.7 Two things not to do

- **Do not read a rising `finalized` as recovery.** Because the denominator
  shrinks with no floor, a partitioned minority reaching two thirds of what
  remains will finalise its own branch. `finalized` advancing again is not
  evidence the network reunified. It is the specific symptom of §2.1.
- **Do not fall back to a confirmation count.** There is no `confirmations`
  field, depth is not a settlement signal on a PoS chain, and substituting one
  would replace a disclosed weak guarantee with an undisclosed one.

Have a documented manual hold procedure with a human owner. A stall does not
currently clear itself.

## 4. What we are doing, and what would let us withdraw this

We are not asking you to accept this as permanent. The caveat in §2.1 is
withdrawn when leak recovery and the quorum-denominator floor are armed — both
are written and tested, and both need a flag day and a coordinated fleet
rebuild rather than new code. The caveat in §2.2 is withdrawn when the adopt
path compares the incoming finalized checkpoint against the outgoing one and
refuses to move backwards; there is no such comparison on the released binary
today, and no test asserting one.

We will tell you when each lands, as a file, under the same changelog
discipline that produced this correction
([`CONSENSUS-CHANGELOG-DISCIPLINE.md`](CONSENSUS-CHANGELOG-DISCIPLINE.md)).
Neither is armed today, and we will not describe either as imminent.

Until both are done, **the honest statement is that Bloch Genesis-4 offers
economic finality under an assumption of healthy participation, not a
cryptographic settlement guarantee**, and your credit policy should be written
against that sentence rather than against the one we retracted in §1.

## 5. Reference

- Corrected book, §5.1–§5.5 —
  [`BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md`](BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md)
- Claim-by-claim audit behind the revision, findings F and F2 —
  [`INTEGRATION-BOOK-AUDIT-2026-08-31.md`](INTEGRATION-BOOK-AUDIT-2026-08-31.md)
- How a consensus-parameter change reaches you —
  [`CONSENSUS-CHANGELOG-DISCIPLINE.md`](CONSENSUS-CHANGELOG-DISCIPLINE.md)

Code claims verified against `main` @ `e4083f9`.
