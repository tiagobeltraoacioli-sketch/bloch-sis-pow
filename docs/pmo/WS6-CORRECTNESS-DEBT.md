# WS6 — Correctness debt

Written 2026-09-01, PMO. Every claim below was verified by reading the code,
with file:line. None of it is on the 5 September critical path; all of it
outlives the deadline.

**The unifying fact.** Three of the four items are the same defect wearing
different clothes: **the chain holds two value pools — the eUTXO set and the
validator registry's bonded stake — and nothing moves value between them or
reconciles them.** `transition.rs:1252-1262` states it plainly and is worth
quoting in full, because it means none of this was hidden:

> **Bonding is not funded from this set.** `PosTransaction::Deposit` and
> `Delegate` name an `amount_sat` and spend no output; `Exit` and the withdrawal
> delay return no output either. So the chain holds two pools — this one and the
> registry's bonded stake — and coins do not travel between them: a deposit
> creates bonded stake without destroying spendable coins, and fee rewards
> compound into bonds that this set never funded.
>
> Conservation therefore holds **within** the transfer path (the fee is exactly
> what leaves the set, pinned by test) and **not** across the two pools.

That is an accurate, self-authored description of a consensus defect. The debt is
not that we don't know; it is that it is disclosed in a doc comment and nowhere
in the accounting.

---

## 1. The deposit path mints stake from nothing — **live in mainline**

### 1.1 It is not gated, and it is not rejected

The brief and this repo's own registry both described tags `0x02`/`0x03`/`0x04`
as "legacy — decodes, then rejected at transition." **Verified false.** In
`apply_transaction` (`crates/bloch-pos-committee/src/transition.rs:2007-2145`):

- `Deposit` (`:2040`), `Exit` (`:2092`) and `Delegate` (`:2113`) each fall
  through to a complete apply arm and **return success**.
- **The only activation gate in the whole function belongs to `TransferV2`**
  (`:2036-2038` — `self.epoch < TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH →
  FormatNotActive`). No staking arm has an equivalent.
- `SlashingEvidence` is the sole staking-family tag refused here (`:2142`,
  `MisroutedEvidence`), and only because it routes elsewhere.

What is true is narrower and much weaker than "rejected": **the mempool declines
to relay them, as node-local policy.** The audit states the consequence exactly —
*"not a consensus rule: a block that already carries a deposit still applies
it."* Policy in the mempool is not a gate in consensus. Any proposer that
includes one — buggy, patched, or hostile — has it applied by every node on the
network.

*(The registry has been corrected; see `WIRE-NAMESPACE-REGISTRY.md` §1. The
lesson is recorded there too: a `Status` cell must describe consensus, never
mempool policy.)*

### 1.2 The arithmetic

`Deposit`'s arm (`:2040-2085`) inserts a `ValidatorRecord` with
`staked_sat: *amount_sat`, and **spends no eUTXO input and verifies no
signature.** Its complete set of checks:

1. the pubkey is not already registered (`:2050`);
2. `amount_sat >= staking::MIN_DEPOSIT_SAT`;
3. `amount_sat <= max(total_active_sat × MAX_VALIDATOR_STAKE_BPS / 10_000,
   MIN_DEPOSIT_SAT)`.

`MIN_DEPOSIT_SAT = 25_000 * SAT_PER_BLOCH` (`staking.rs:97`). So **each accepted
message conjures 25,000 BLCH of bonded stake**, and because the per-validator cap
is 1% *of active stake*, the ceiling rises as the stake it admits rises. The
floor exists because a naive 1% cap at genesis (active stake ≈ 0) would deadlock
the bootstrap — a sound reason with an unsound consequence.

The audit's measured figure — on the order of **180 messages to control the
chain** — follows from that compounding. **The validator set is held fixed by
policy, not by protocol.**

### 1.3 Is the unmerged `DepositV2` a fix?

**No — and this is the item that most needs a decision.** `DepositV2` (`0x07`)
exists only in worktrees and adds structure, not funding: nothing in it gives the
deposit path an eUTXO input to spend. It reproduces the defect in a newer
encoding. Landing it would make the pool split *more* entrenched, not less.

Closing this means "giving deposits and withdrawals eUTXO inputs" — the
transition module's own words. **That is a consensus change with a flag day, and
it does not belong in a four-day window alongside an exchange integration.**
What belongs in the four-day window is the decision *not* to merge `DepositV2`
until the funding question is answered.

### 1.4 Related: the validators are unreachable by design

`validate_deposit` / `validate_exit` / `validate_withdrawal` have **zero
production callers**, and the trait declaring them has no implementor. The safety
they describe is not merely bypassed — it is not wired at all.

---

## 2. The launch cohort's 1.6M BLCH sits outside `GENESIS_ISSUED_SAT`

**Verified, and it is the same two-pool defect at genesis.**

`Manifest::genesis_issued_sat` (`crates/bloch-pos-node/src/genesis.rs:887-890`):

```rust
self.carryover.as_ref().map_or(0, |c| c.total_sat)
    + self.allocations.iter().map(|a| a.amount_sat).sum::<u128>()
```

**Carryover plus the five allocation buckets. `validators[].stake_sat` is not a
term.** Yet the genesis ceremony seeds exactly that field into each
`ValidatorRecord` at `genesis.rs:964` (`staked_sat: v.stake_sat`).

`check_supply` (`:899-920`) then asserts `issued == GENESIS_ISSUED_SAT`
**exactly**, where `GENESIS_ISSUED_SAT = TOTAL_SUPPLY_SAT −
VALIDATOR_EMISSION_SAT` (`tokenomics_v4.rs:251`). Its comment is precise about
what it is protecting:

> Validator emission is issued by blocks over decades; genesis must leave exactly
> that much unissued, or the emission schedule and the cap disagree and one of
> them silently wins.

**The discrepancy: 64 genesis validators × `MIN_DEPOSIT_SAT` (25,000 BLCH) =
1,600,000 BLCH of bonded stake that exists in committed state from slot 0 and is
counted in no supply total.**

### 2.1 What breaks

- **`TAG_ISSUED_SUPPLY` (state-root tag `0x14`) is short by 1.6M BLCH.** The
  committed cumulative-issuance counter is seeded from `GENESIS_ISSUED_SAT`, so
  the emission-headroom check works against a number that never saw the bond.
- **The hard cap is not enforced over all value.** `TOTAL_SUPPLY_SAT` bounds
  carryover + allocations + emission. Bonded stake is outside the bound, so
  "100 billion fixed" is true of the accounted pool, not of the chain.
- **Any RPC-reported supply understates by 1.6M BLCH** — and this is the one an
  exchange or a listing venue would reconcile against. It is small (0.0016% of
  100B) and therefore exactly the kind of discrepancy that surfaces later, in
  someone else's audit, as evidence we do not know our own supply.
- **`check_supply` passes anyway**, because the bond is not in either side of
  its equality. The check that exists to make the manifest *"a claim rather than
  an assertion"* cannot see the term.

### 2.2 PMO position

This is **an accounting defect, not a solvency defect** — the 1.6M is real,
intended, and published in the genesis manifest. Nobody minted it secretly.
**But do not let a partner discover it in reconciliation.** The cheap, honest fix
is not a consensus change: **state the bond explicitly in the supply
documentation and in whatever `getsupply`-shaped surface we publish**, as a
distinct pool alongside issued supply. The consensus-level fix (bonded stake
funded from and returned to the eUTXO set) is item 1.3 and shares its flag day.

---

## 3. The fleet runs a binary without the catch-up fix

**Confirmed, and it is worse than "the fleet is behind" — no release has it.**

The fix is `fix(catch-up): share the eUTXO map so an epoch roll stops paying the
ledger` (an `Arc<BTreeMap>` copy-on-write, so an epoch boundary stops doing work
proportional to the whole ledger). It lives on **`integ/ws-checkpoint-tooling`**
and is merged nowhere.

Its absence is why cold sync decelerates by more than an order of magnitude
within the first 20 epochs. The 26-hour cold-sync figure published in
`THIRD-PARTY-QUICKSTART.md` was measured **with the fix applied** — so **the
published sync time describes a binary no third party can obtain.** A build
without it took roughly twice as long in the same run, though that comparison was
CPU-contaminated and should not be quoted as the fix's effect.

This compounds with the release situation (WS5 §6): `genesis4-node-20260814` is
**consensus-dead since epoch 800** and silently forks onto a dead branch, and the
R2 paths older docs point at return 404. **There is currently no binary we can
hand anyone.** That is a Phase 1 item, not a debt item, and it is tracked as
plan 1.4.

---

## 4. The two explanations of 2026-08-24

### 4.1 Both, stated

**Explanation A — the length-dependent shuffle.** The committee-partition
routine's shuffle depended on the length of the validator list it was given.
Nodes that had filtered zero-stake validators differently held lists of different
lengths, so the same seed produced *different partitions*, and the roster split.

**Explanation B — the quorum-denominator ratchet.** The finality denominator is
leak-adjusted with its protective floor gated off
(`LEAK_RECOVERY_ACTIVATION_EPOCH = u64::MAX`), so it shrinks toward whatever
minority a partitioned node can still hear, and that minority finalizes its own
branch. On 2026-08-24, three nodes finalized epoch 986 under three different
roots.

### 4.2 The tests encoding A are red, and they refute themselves

`cargo test -p bloch-pos-committee --lib` on `main` is **285 passed, 5 failed**,
all in `prova::tests` (`s1`, `s2_mutation`, `s3_mutation`, `s4`,
`s4_mutation`). Their assertion text argues against their own thesis:

- s1 — *"different zero-sets produced the SAME step-8 partition — the
  length-dependent shuffle is not the mechanism and **this analysis is wrong**"*
- s4 — *"34 honest validators holding 100% of live stake justified anyway — then
  the roster split does not block finality and **this finding is refuted**"*
- s3 mutation — *"the comparator saw a difference in only 0 of 8 epochs after
  planting a zero-stake validator; **it is blind to the defect it exists to
  catch**"*

### 4.3 What the evidence actually supports

**The red tests are not evidence against Explanation A.** They are evidence that
**the test harness stopped reaching the code it was written to exercise.**

Verified: the `PRE_FIX_FILTER` branch used to call `committees::epoch_committees`,
and *that call was the broken code*. The 2026-08-24 change removed the pre-shuffle
filter from production and left it only behind
`params::rehearsal::RESTORE_ZERO_STAKE_FILTER` — so from that point the mutation
hooks were pointing at code that had moved out from under them. **Static
reference rot**, the same class of failure that has now hit four systems in this
repo. The self-refuting messages are the harness reporting, accurately, that it
can no longer reproduce a defect it is no longer able to reach.

**Conclusion: the two explanations are not competitors, and the framing is the
problem.** A is a historical account of *how the roster split*; B is a live,
code-verified account of *why a split becomes a finality failure instead of a
stall*. A has been fixed and its regression harness has rotted. **B is not fixed
and is not tested at all** — `params.rs:597` still reads `u64::MAX`.

**B is the one that matters, and B does not depend on `prova.rs`.** It rests on
direct reading of `finality.rs:342-364` plus the crate's own passing test
`a_partitioned_minority_finalizes_because_the_leak_shrinks_the_denominator`
(`finality.rs:976`), which demonstrates 4 of 64 validators — 6.25% — reaching a
false quorum. Nothing in §4.2 weakens it.

### 4.4 The repair already exists, on the branch we are merging anyway

`020771ad` (*"test(prova): restaura o filtro pre-fix pela chave de ensaio"*) is on
**`integ/validator-opening`** — the same branch recommended for merge as plan
item 1.2. It reconnects the pre-fix filter through the rehearsal key, and all
five tests pass there. Its own message confirms the failures are pre-existing:
they reproduce on untouched `e4083f96`. **These are base failures, not
integration failures, and merging 1.2 clears them.**

### 4.5 What still needs an owner

A consensus owner must **write down which explanation the next post-mortem
cites**, because the repo currently supports citing either. The PMO's reading is
§4.3, but the PMO does not own consensus. Two concrete asks:

1. **Retire or re-scope `prova.rs`** so it stops asserting a refutation it no
   longer has standing to make. A rotted harness that argues is worse than one
   that fails.
2. **Give Explanation B a test that is not `prova.rs`** — specifically a
   ratchet-shaped test that fails if a node's finalized checkpoint moves
   backwards. WS5 §1.4 shows `do_reorg` (`engine.rs:1609`) adopts state
   unconditionally with **zero occurrences of `finaliz`** in the function, that
   `forkchoice.rs` never mentions `finalized`, and that a downward move is not
   even logged. **No such test exists in either crate.** It is the cheapest
   durable protection against the failure that actually cost us a chain.

---

## Ordering

Nothing here is on the 5 September path. Suggested order after it:

1. **§4.5's ratchet test** — smallest, and it guards the live defect.
2. **§2.2's documentation fix** — hours, and it removes a reconciliation
   surprise before any listing conversation.
3. **The decision not to merge `DepositV2`** until §1.3 is answered — free, and
   it stops the debt growing.
4. **§1's consensus fix and the `LEAK_RECOVERY` arming** — one flag day, founder
   only, properly scoped and rehearsed. Not before the exchange is synced.
