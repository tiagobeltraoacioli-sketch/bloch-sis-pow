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

Measured exposure, recorded in the node's own source
(`bloch-pos-node/src/engine.rs:2731-2735`): **25,000 BLCH per unauthenticated
request, ~46 requests to reach a third of active stake.** **The validator set is
held fixed by policy, not by protocol.**

`Delegate` (`0x04`, `transition.rs:2050-2072`) is the same shape, and adds its
own defect: **no ownership check on the `delegator` field at all.**

`staking::validate_deposit` (`staking.rs:285-318`) *does* demand transparent
inputs — and has **no production call site**, a fact pinned by
`tests/integration_book_claims.rs:484-489`.

### 1.3 Is the unmerged `DepositV2` a fix?

**It splits — and picking the wrong worktree ships the defect in a new
encoding.** My earlier blanket "DepositV2 reproduces it" was wrong. Measured:

- **`agent-a5a0a10bb332b59ca`** (and `wt/signed-exit-wire`,
  `wt/exit-churn-limit`, `wt/withdraw-refusals`) — **FIXES it.** Real
  conservation (`if spent_value != *amount_sat + change_sat + fee {
  ValueNotConserved }`, `:3433`), a real burn
  (`self.eutxos.remove(&(i.txid, i.vout))`, `:3476-3478`), proof-of-possession,
  and per-input witnesses. Critically it **also rejects `0x02` unconditionally at
  every epoch** (`:2472-2494`) — it closes the live hole, not just the new path.
  The new `0x07` is inert (`FUNDED_STAKING_ACTIVATION_EPOCH = u64::MAX`).
- **`agent-a087ea83a391a7f0a`** — **REPRODUCES it.** `apply_deposit_v2` is
  correct in isolation, but the legacy arm only returns early
  `if deposit_funding_active(self.epoch)`, and
  `DEPOSIT_FUNDING_ACTIVATION_EPOCH = u64::MAX` — so the minting arm still runs
  at every epoch. **Merging this fixes nothing** while looking like a fix.

**This is the decision that matters: merge the first lineage, not the second.**
The two are easy to confuse — both add a correct `0x07` — and only one closes
`0x02`.

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
exactly 160,000,000,000,000 sat = 1,600,000 BLCH**, bonded in committed state
from slot 0 and counted in no supply total. `GENESIS_ISSUED_SAT` itself is
5,714,640,000,000,000,000 sat. **Real ultimate supply is 100,001,600,000 BLCH —
1.6M *above* the "hard cap"** (0.0016%).

### 2.0 Root cause: two genesis builders disagree, and we shipped the wrong one

This is not an oversight in the accounting; it is a fork in the tooling.

- **The ceremony tool deducts.** `tools/genesis4-ceremony/src/lib.rs:684-703` —
  *"the genesis liquidity output is reduced by exactly the bonded amount."*
  Under this path the books balance.
- **The node builder does not.** `bloch-pos-node/src/main.rs:605-621` allocates
  the full `LIQUIDITY_BLOCH` and bonds the validators on top.

**The shipped `genesis/mainnet.manifest` matches the non-deducting path** — 64
validators × 25,000 BLCH bonded *and* the full 5B BLCH liquidity. The correct
builder existed and was not the one used.

*(Inferred, not proven: that the manifest came from `bloch-pos genesis-mainnet`
rather than the ceremony tool. Strongly supported by the un-deducted value; no
build log was found.)*

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
  its equality — it sums only carryover + allocations, reports diff 0, and **is
  never re-run at node start.** The check that exists to make the manifest
  *"a claim rather than an assertion"* cannot see the term.
- **The cap check can never fire on this gap.** `transition.rs:3219` compares a
  counter seeded 1.6M short of reality, so `SupplyCapExceeded` is unreachable
  for it.
- **No test anywhere sums eUTXOs + registry stake against `issued_sat`.**
- **No RPC contradicts it**: `getsupply`, `getsupplyinfo` and `getissuance` are
  all in `RPC_ABSENT` (`rpc.rs:867-875`).
- **The gap widens without bound** with every post-genesis deposit (§1).

### 2.2 PMO position

This is **an accounting defect, not a solvency defect** — the 1.6M is real,
intended, and published in the genesis manifest. Nobody minted it secretly.
**But do not let a partner discover it in reconciliation.** The cheap, honest fix
is not a consensus change: **state the bond explicitly in the supply
documentation and in whatever `getsupply`-shaped surface we publish**, as a
distinct pool alongside issued supply. The consensus-level fix (bonded stake
funded from and returned to the eUTXO set) is item 1.3 and shares its flag day.

**And be honest about the cost of a true fix:** correcting the genesis books is a
**genesis-state-root change. It moves `genesis_id()`, so it requires a
relaunch.** That is not a flag day; it is a new chain. Which is precisely why the
documentation fix is the right answer for now, and why nobody should promise a
partner that the 1.6M will be reconciled away.

---

## 3. "The fleet runs a binary without the catch-up fix" — **the premise is inverted**

**CORRECTION, 2026-09-01. This section originally asserted the brief's premise as
confirmed. Measurement reverses it, and the reversal changes who is behind.**

There are **two different fixes** that both get called "the catch-up fix", and
conflating them is what produced the error. Separated:

### 3a. The consensus catch-up fix (`47f7644b`) — **the fleet HAS it; `main` does not**

Read-only probes (`--version`, `readlink /proc/PID/exe`, RPC) across all **7 big
boxes × 9 processes = 63 validators**: every one runs `bloch-pos-cinco`,
`0.1.0-mainnet (46133196-varredura)`, and **`46133196` descends from
`47f7644b`.**

`git merge-base --is-ancestor 47f7644b main` → **not an ancestor.** Same for
`0a3a436a`, and same for `validator-ops`. `docs/ATRIBUICAO-2026-08-24.md:30`
shows `0e609f19` ("o codigo que a frota roda passa a ser o main") landed 02:33;
`47f7644b` (05:50) and `0a3a436a` (06:13) landed *after* and were never brought
back.

**So the fleet is ahead and the repository is behind** — the inverse of the
brief. The only stragglers are `main`/`validator-ops` and **one stale public-RPC
observer** (`136.244.90.238`, `2701feab`, **epoch 800 against the fleet's
1666**). That observer is one of the two nodes WS5 §1.5 says the exchange would
be told to corroborate against.

**The four corrections in `47f7644b`, and whether merging arms anything:**

| # | correction | gate | effect |
| --- | --- | --- | --- |
| 1 | producer inclusion filter uses `committee_for_slot`, not `slot_subcommittee` (`derive.rs:499`) | **none, deliberately** | producer-side only; replay byte-identical |
| 2 | node seed look-ahead reads the same gate as the committed rule (`engine.rs:929`) | `ANCESTRY_SEED_ACTIVATION_EPOCH` = `u64::MAX` **(OFF)** | **this is the flood fix**; below the flag day it uses lookahead 0, matching `seed_for_epoch` |
| 3 | `release_held` anchors to the arriving block, not this node's head (`engine.rs:2380`) | none needed | node-local |
| 4 | unjudgeable-but-parkable: "target not yet received" parks, "ancestry unreachable" ignores (`engine.rs:2232-2262`) | none needed | node-local |

**Does merging arm anything? No.** No constant changes value on any ref;
`ANCESTRY_SEED_ACTIVATION_EPOCH` and `LEAK_RECOVERY_ACTIVATION_EPOCH` are
`u64::MAX` on `validator-ops`, `main` and this branch alike, and this branch adds
only one *more* inert gate. **But it is not behaviourally inert** — corrections
1–4 take effect the moment a merged binary runs, which is exactly how the repo
converges onto the fleet.

**Minimal carrier.** If the goal is only to close the consensus gap,
`origin/relanca/e1400-quatro-portoes` already publishes these commits. Note that
**`pmo/wire-namespace-registry` — the branch carrying this analysis — is
local-only and has never been pushed.**

**Standing hazard, and it constrains the founder's arming decision**
(`engine.rs:912-928`): `derive::sortition_seed` is a **third** seed definition,
reading E−1 with **no gate at all**. All three agree below the flag day, so
nothing is wrong today — but **arming `ANCESTRY_SEED_ACTIVATION_EPOCH` is unsafe
until that third definition is closed.**

### 3b. The cold-sync catch-up fix — **unmerged, and in no release. This part stands.**

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

**Conclusion — and this goes further than "not competitors". E1 is arithmetically
incapable of having caused the incident.**

`transition.rs:1664-1669`:

```rust
fn consensus_roster_at(&self, epoch: u64) -> Vec<Validator> {
    let roster = self.duty_roster_at(epoch);
    if epoch < crate::params::LEAKED_ROSTER_ACTIVATION_EPOCH {
        return roster;                      // <-- the identical object
    }
    with_leak_applied(roster, |index| self.finality_engine.leaked_of(index))
}
```

`LEAKED_ROSTER_ACTIVATION_EPOCH = 1400` (`params.rs:244`). **The incident was at
epoch 986.** Below 1400, step 8 and `close_epoch` receive the *same roster*, so
the two partitions are identical **whether or not the pre-shuffle filter
exists**. E1's mechanism could not operate at epoch 986. The repo says so itself
at `docs/RELANCA-G4-DECISOES.md:148-152`: *"`consensus_roster_at` returns the
unleaked roster while `epoch < 1400`, so the roster split never operates
there."*

So E1 was a **real latent defect that would have fired at epoch 1400** and was
pre-emptively fixed. It was never the incident's mechanism. **E2 is unconditional
code and matches the observed signature** — three nodes, one epoch, three roots.

### 4.3.1 The corollary, and it is the worst finding on this page

**The fix for the mechanism that was *not* responsible is armed and already
bound; the fix for the mechanism that *was* responsible is switched off.**

In production (`gates_forced_open()` is `false` outside `cfg(test)`,
`finality.rs:290-297`):

- **Denominator floor** — `finality.rs:353-360`: `votes.epoch <
  LEAK_RECOVERY_ACTIVATION_EPOCH` is always true (`u64::MAX`, `params.rs:597`),
  so `total_active = leak_adjusted`. **No floor.**
- **Leak recovery** — `finality.rs:497-499`: `votes.epoch >= u64::MAX` is always
  false. **The accumulator never comes back down.**

Meanwhile `LEAKED_ROSTER_ACTIVATION_EPOCH = 1400` is armed and the chain is at
epoch 1666.

**The monotonic ratchet that caused 2026-08-24 is live and unmitigated on all 63
validators today.** The founder's `1/2` floor (`params.rs:147-149`, authored
2026-08-24) is the correct mitigation and it is gated off. **Arming
`LEAK_RECOVERY_ACTIVATION_EPOCH` is the highest-value consensus action available
— and it is not on the 5 September path, so it can be scoped and rehearsed
properly.**

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

1. **Arm `LEAK_RECOVERY_ACTIVATION_EPOCH`** (§4.3.1). The ratchet that caused
   2026-08-24 is live on all 63 validators, and the founder's `1/2` floor —
   already written, already correct — is sitting behind an off switch. This is
   the highest-value consensus action available. Founder-only, one flag day, and
   it should be scoped and rehearsed *after* 5 September precisely because it
   deserves that care.
2. **Pick the right `DepositV2` lineage** (§1.3) — merge `a5a0a10bb332b59ca`,
   which also closes `0x02`; do **not** merge `a087ea83a391a7f0a`, which
   reproduces the mint while appearing to fix it. Free, and it stops the debt
   growing.
3. **§4.5's ratchet test** — small, and it guards the live defect directly.
4. **§2.2's documentation fix** — hours, and it removes a reconciliation surprise
   before any listing conversation. Note the true fix needs a relaunch, so the
   documentation *is* the answer for this chain.
5. **Bring `main` up to the fleet** (§3a) — the repository is behind the
   validators, not ahead of them. `origin/relanca/e1400-quatro-portoes` is the
   minimal published carrier.
6. **Retire the stale public-RPC observer** (§3a) — epoch 800 against the fleet's
   1666, and it is one of the two nodes we would tell an exchange to corroborate
   against. This one is cheap and belongs before the exchange handover, not
   after.

**Do not arm `ANCESTRY_SEED_ACTIVATION_EPOCH`** until the third, ungated seed
definition at `engine.rs:912-928` is closed (§3a).
