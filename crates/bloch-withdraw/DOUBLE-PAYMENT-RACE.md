# The double-payment race, and how this library closes it

**Distribution: partner/integrator delivery only. Do not publish publicly.**

This document is the design argument for `bloch-withdraw`. It states the
race precisely, shows why every habitual fix fails on this chain, and gives
the two rules — with the argument for each — that make paying a withdrawal
twice impossible by construction rather than unlikely by vigilance.

## 1. The chain facts that create the race

All four are Genesis-4 consensus/RPC behaviour, verified in
`bloch-pos-committee` and `bloch-pos-node`:

1. **A transfer commits to exactly one base fee.** A transfer encodes no fee;
   consensus derives it as `gas x price` and requires
   `sum(inputs) == sum(outputs) + fee` **with equality**
   (`transition::apply_transfer`, reject `ValueNotConserved`). The `price` is
   the base fee of the block that includes it. If the base fee moves before
   inclusion — it can move up to 1/8 per block, floor-clamped
   (`fee_market::next_base_fee`) — the equality fails at the new price and
   the bytes are **permanently invalid**. Resubmitting identical bytes never
   succeeds; only a rebuild at the new price can.
2. **A transfer that misses its block is dropped from the mempool without
   notice.** There is no eviction event, and nodes additionally bar
   re-offered bytes their own proposer watched fail (`engine.rs`, the
   rejection cache). Absence from the mempool tells you nothing about
   inclusion.
3. **There is no transaction id at the RPC layer.** `gettransaction` refuses
   by design (`-32005`, no txid index; the `tx_hash` echoed by
   `sendrawtransaction` is explicitly a local correlation handle no block
   commits to). Confirmation is only observable as a change in the eUTXO
   set: `gettxout` / `getbalance` / `listunspent`, keyed by `script_hash`.
4. **Crediting is `finalized`, not head.** Depth is not security under PoS,
   and the public RPC may answer from nodes on different branches. A serious
   integrator reads a node they validate themselves and branches on the
   finality fields.

## 2. The race

Because a rebuilt transaction has different bytes and there is no txid, **the
transaction cannot serve as its own idempotency key**. The naive retry loop —
correct on Bitcoin, correct on Ethereum, muscle memory for every integration
engineer — is:

```
build T1 at base fee B, spending whatever coins the wallet offers
submit T1
wait; T1 does not appear; the fee is now B'
conclude T1 is dead (it missed, the mempool dropped it, fee moved)
build T2 at B', spending whatever coins the wallet offers NOW
submit T2
```

The fatal step is the *conclusion*. "T1 is not in the mempool and the fee
moved" is not proof T1 was never included:

- your node may be behind, or on a different branch than the one that
  included T1;
- the base fee **oscillates** — it can return to exactly B (it is clamped at
  a floor it sits on for long stretches, so B = B' = floor is the common
  case) and a peer that still holds T1's bytes can get them included later;
- a reorg can move T1 from "not included" to "included" between your check
  and your rebuild.

If T1 was, or becomes, included after T2 was built over **different coins**,
both are valid — they conflict on nothing — and both land. The recipient is
paid twice, and there is no txid with which to even *describe* what happened
after the fact. The test
`naive_rebuild_with_fresh_coins_pays_twice` (`tests/race.rs`) demonstrates
this end-to-end against the real consensus arithmetic: two builds, both
included, recipient credited `2 x amount`.

Non-fixes, and why:

- *"Resubmit the same bytes instead of rebuilding."* Dead on fact 1: bytes
  built at B are invalid at B' forever. You must rebuild to make progress, so
  the race is not avoidable by abstinence.
- *"Wait N blocks before rebuilding."* There is no N. Fact 2 means you never
  learn the transaction is gone; fact 3 means you never learn it landed
  except by watching coins; and the fee can return to B after any N.
- *"Check the recipient's balance."* Attribution fails: concurrent
  withdrawals to the same address, or the recipient moving funds, make a
  balance delta unreadable as "my T1 landed".

## 3. The two rules

### Rule 1 — the pinned input set is the payment's identity

The caller supplies a **withdrawal id** (their idempotency key — the library
never invents one). The first build for that id selects coins and **pins**
them to it, durably, before anything is signed. From then on, every attempt
for that id — every fee level, every retry after restart, the cancellation
sweep too — spends **that same pinned set**. The set may *grow* (a fee spike
can outrun it) but never shrinks and is never swapped; growth is append-only
(`withdraw.rs::grow_pins`, and the builder has no code path that spends a
subset).

**Claim: at most one attempt for a withdrawal id can ever be included on any
one chain.** Any two attempts A_i, A_j (i < j) both spend every coin pinned
at time i (A_j spends a superset of A_i's inputs). eUTXO consensus removes an
outpoint on spend and rejects a transaction naming a missing outpoint
(`UnknownInput`); an in-block duplicate is equally rejected. So A_i and A_j
conflict on at least one outpoint, and whichever is included first makes the
other invalid **by consensus**, on that chain, forever. The double-payment is
not made improbable; it is turned into a double-spend, which is the one thing
this chain is built to refuse.

Across a reorg the claim still holds per chain: if A_1 landed on an abandoned
branch and A_2 lands on the surviving one, exactly one payment exists on the
chain that survives — which is the chain the money exists on. (And the
library credits only from finalized history, below, so it never *reports*
the abandoned one.)

Corollaries that fall out for free:

- **Inclusion becomes observable without a txid.** "Was some attempt for
  this id included?" is exactly "is pinned coin #0 spent?" — one `gettxout`
  call. *Which* attempt is answered by probing each attempt's derived txid
  (`PosTransaction::txid` is witness-free and computable offline) at vout 0.
- **Cancellation needs no new mechanism.** A cancel is one more attempt over
  the same pinned set whose outputs pay only the hot wallet back. It races
  the in-flight payment; whichever finalizes is the answer, and it is exactly
  one of them (`cancel_races_the_payment_with_a_sweep`).

What Rule 1 asks of the operator, stated as obligations rather than fine
print:

- **Exclusive key control.** Only this library spends the hot wallet's coins.
  A parallel spender that consumes a pinned coin breaks the identity (the
  library will read that spend as its own attempt landing). The store's
  reservation extends this *between withdrawals*: coins pinned by one id, and
  the outputs an in-flight id's attempts would create, are untouchable by
  other ids until the record is terminal.
- **One ticker per id at a time.** The store contract is load/save, not
  compare-and-swap; serialize `tick` per id (a per-id lock or queue).
- **A durable store.** `save` is write-ahead of `submit` throughout: pins are
  saved before the first build over them, attempts before their bytes are
  sent. A crash therefore never leaves the network knowing bytes the store
  has not recorded (`restart_resumes_instead_of_repaying`).

### Rule 2 — confirm, then rebuild; never rebuild, then confirm

A rebuild happens only after the current tick has observed the pinned
sentinel coin **unspent** in the node's committed state
(`withdraw.rs::tick`: the `gettxout` probe strictly precedes, and gates, the
build path). The naive loop's ordering — decide the old attempt is dead,
then build — is structurally unreachable.

Honesty about what Rule 2 is for: it is **not** what prevents the double
payment. The probe is a TOCTOU — the old attempt can be included in the very
slot after the probe says "unspent", while the rebuild is being signed. When
that happens, Rule 1 makes the fresh attempt a harmless double-spend
(`pinned_rebuild_cannot_double_pay` exercises exactly this schedule: fee
moves, client rebuilds, adversary includes the *old* attempt anyway — one
payment lands, the rebuild is refused). Rule 2's job is discipline and
liveness: rebuilds are decisions made against the chain's observed state and
the fee actually charged next (`next_base_fee_millisat_per_gas`), not
guesses on a timer; and walked-back states (a reorg un-spending the
sentinel) re-enter the submit loop instead of wedging.

## 4. Crediting: the finality gate

`Paid` is declared only when ALL of:

1. the pinned sentinel was observed **spent** at some head slot `S`
   (`gettxout.at_slot`);
2. the finalized boundary — first slot of the finalized checkpoint's epoch,
   from `getchaininfo` — has advanced **past `S`**; and
3. a re-probe at that later time still shows the sentinel spent.

If the spend vanishes between 1 and 3 (reorg), the machine walks back to
`Submitted` and resumes; nothing was credited
(`reorg_walks_back_and_recovers`). The rule is conservative by up to one
epoch and never optimistic: a spend observed at slot `S` was included at
some slot `<= S`, so once the settled line passes `S` and the spend is still
on the canonical chain, the spend is in finalized history.

Residual window, stated: between two polls, a chain could in principle
reorg the spend out *and* have an attempt re-included on the new branch
(inclusion needs a peer still holding the bytes and the base fee matching
again). If the machine's finality check straddles exactly that window, it
may attribute the spend to a slot earlier than its re-inclusion — i.e.,
credit up to one poll early. This affects **when** `Paid` is declared, never
**how many times** the recipient is paid: Rule 1 caps included attempts at
one per chain regardless of any polling schedule. Poll at slot cadence
(30 s) to keep the window one slot wide.

Likewise, a node that violates finality monotonicity (rewinds below its own
finalized checkpoint — a failure mode this network has actually exhibited)
can make the *credit report* wrong; it cannot make the recipient be paid
twice. The at-most-once property is enforced by the eUTXO set itself, on
whatever chain wins; the crediting guarantee is only as good as the finality
of the node you read, which is why you read your own.

## 5. Supporting policies

- **Fee targeting.** Attempts are built against
  `next_base_fee_millisat_per_gas` — the price of the block being aimed at,
  not the price of the block just seen. One attempt is kept per (kind, base
  fee); if the fee returns to a level already built, the stored bytes are
  resubmitted verbatim (fact 1 makes them valid again at that price, and the
  derived txid is unchanged because the declared size is computed from the
  suite's maximum signature length — deterministic in the transfer's terms).
- **Dust is never emitted.** No output below 546 sat (Genesis-3's threshold;
  Genesis-4 consensus would accept less — this client will not, because
  sub-dust outputs have poisoned blocks on this chain's history). Change
  that would fall in `(0, 546)` is burned into the fee **exactly** — the
  conservation equality forbids approximate overpayment, so the builder
  searches the (declared-size, tip) lattice for an exact absorption
  (`build.rs::solve`), and grows the pinned set if none exists.
- **Stale nodes are refused.** A node reporting `behind_by_slots` above the
  configured bound cannot drive any decision: its "unspent" is not evidence.

## 6. What the tests pin

`tests/race.rs`, against a fake chain that re-runs consensus's own
arithmetic (`fee_market::charge`, ownership shape, real hybrid signature
verification, conservation as equality) on the exact bytes the client emits:

| Test | Pins |
|---|---|
| `naive_rebuild_with_fresh_coins_pays_twice` | the hazard is real: the chain includes both naive builds |
| `pinned_rebuild_cannot_double_pay` | the adversarial schedule pays once; `Paid` only after finality |
| `restart_resumes_instead_of_repaying` | crash-restart rebuilds over the same pins; changed terms under an old id are refused |
| `reorg_walks_back_and_recovers` | un-spend after observation walks back and still ends paid once |
| `pinned_set_grows_and_never_swaps` | growth is append-only; old and new attempts still conflict |
| `cancel_races_the_payment_with_a_sweep` | cancellation is a conflicting attempt, terminating in exactly one of Paid/Cancelled |
| `no_attempt_ever_emits_dust` | the dust policy holds through the state machine, not just the builder |
| `stale_node_is_refused` | a self-declared stale node drives nothing |
