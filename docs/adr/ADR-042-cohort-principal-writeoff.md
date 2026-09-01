# ADR-042 — The launch cohort's principal: what a withdrawal may pay

**Status:** proposed, implementation INERT (`WITHDRAWAL_ACTIVATION_EPOCH = u64::MAX`).
**Decision owner:** the founder. This ADR presents the options and recommends one; it does not decide.
**Date:** 2026-09-01.

---

## 1. The measurement

Taken from `genesis/mainnet.manifest` — the file the fleet decodes, 247,514 bytes,
SHA-256 `7eef82a7…b2dd` — and re-derived independently a second time before it
was written down.

| | sat | BLCH |
|---|---:|---:|
| `carryover.total_sat` | 1,814,640,000,000,000,000 | 18,146,400,000 |
| Σ allocations (5 buckets) | 3,900,000,000,000,000,000 | 39,000,000,000 |
| `Manifest::genesis_issued_sat()` | **5,714,640,000,000,000,000** | 57,146,400,000 |
| `tokenomics_v4::GENESIS_ISSUED_SAT` | **5,714,640,000,000,000,000** | 57,146,400,000 |
| difference — `check_supply()` passes | **0** | 0 |
| Σ `ManifestValidator::stake_sat`, 64 validators | **160,000,000,000,000** | 1,600,000 |

**The zero is the proof.** A sum that balances without a term is a sum the term
is not in. `genesis_issued_sat()` adds the carryover to the allocations and
nothing else; `CommittedState::genesis` seeds `issued_sat` from the constant
rather than deriving it from the ledger it was handed. So at slot 0 the chain
holds 1,600,000 BLCH of bonded stake that no output funded, no counter records,
and no rule can see.

Two further facts, both checked by test (`genesis.rs::launch_bond_backing`):

* Every one of the 64 bonds is exactly 25,000 BLCH — `staking::MIN_DEPOSIT_SAT`.
* All 64 withdrawal credentials are the **same address**. The write-off has
  exactly one economic counterparty.

And one qualification that matters for how much weight the "difference 0" can
carry: `GENESIS_ISSUED_SAT` is *defined* as `TOTAL_SUPPLY_SAT −
VALIDATOR_EMISSION_SAT`, and `VALIDATOR_EMISSION_BLOCH` is *defined* as the
total minus the carryover minus the five buckets. Substituting, the constant is
identically `(carryover + buckets) × SAT_PER_BLOCH`. `check_supply()` is
therefore a manifest↔constant typing check, not a supply audit. It could never
have caught this, because no term in it has ever been a bond.

## 2. What is payable, and what is not

Not all of a launch bond is unbacked. Reward compounding advances `issued_sat`
and `staked_sat` on the same line, inside the same `if let`, in
`close_epoch` — the counter cannot move without the bond. So every satoshi a
launch validator has EARNED is real, counted and legitimately owed. Only the
25,000 BLCH each was handed at genesis is unbacked.

Reported accrued emission across the cohort at the time of writing is ~123.7M
BLCH — roughly 77× the principal. **This figure could not be verified from the
repository** and is carried as reported, not as measured; it comes from the live
chain, not from these bytes. The mechanism behind it is verified, and it is what
makes "pay the emission, write off the principal" a real payout rather than a
polite refusal.

## 3. The options

### Option A — count the principal into issued supply

Raise `issued_sat` by 160,000,000,000,000 sat so the books balance with the bond
inside them, and leave the emission schedule alone.

**Rejected on arithmetic, not on taste — and the arithmetic is worse than it
first looks, because it does not fail loudly.** `TOTAL_SUPPLY_SAT ==
GENESIS_ISSUED_SAT + VALIDATOR_EMISSION_SAT` **exactly**: there is no headroom
anywhere in the schedule, so every satoshi added to genesis issuance is a
satoshi taken out of the emission budget. Counting the bond does not push
`issued_sat` over the cap on day one — the counter would sit at 57,148,000,000
BLCH against a cap of 100,000,000,000 — it leaves the 40-year emission schedule
promising 1,600,000 BLCH more than the cap will ever let it pay.

And `close_epoch` clamps issuance to the remaining headroom rather than
refusing, so nothing goes red. The schedule and the cap would simply disagree,
and the clamp would win, silently, decades from now, taking the shortfall out of
whoever happened to be validating at the end. That is precisely the failure mode
`Manifest::check_supply`'s own comment names: *"genesis must leave exactly that
much unissued, or the emission schedule and the cap disagree and one of them
silently wins."*

The identity is now a compile-time assertion in `tokenomics_v4.rs` — not because
it stops anyone counting the bond, but so that an edit which opens a gap between
the cap and its two halves cannot take this reasoning out from under the
write-off without going red.

Note that Option A and Option B are the same transfer, differing only in whether
it is written down. A takes 1,600,000 BLCH from the emission budget and leaves
the constant claiming otherwise; B takes it and says so.

### Option B — absorb it from the validator emission budget

Lower `VALIDATOR_EMISSION_BLOCH` by 1,600,000 and raise the genesis issuance by
the same. The cap holds, the schedule is honest about what it can pay, the bond
becomes backed, and the withdrawal pays in full with no new rule at all. This is
Option A with the books corrected to match.

**Preserves the cap. Transfers unbacked coin.** Stated plainly: it funds the
founder's launch bond out of the emission that every future validator — most of
them not yet on the chain — would otherwise have earned. It is 0.0037% of the
emission budget, which is small, and it is a transfer from a group that cannot
be consulted to a party that is one address, which is the part that is not about
size.

It is also more invasive than it looks. `VALIDATOR_EMISSION_BLOCH` is the base
of the whole 40-year emission curve; changing it changes every per-slot payout
the schedule has already produced, so this is a hard fork of the reward curve
and a re-derivation of the emission accumulators, not an edit to a constant.

### Option C — never pay the principal (implemented here, inert)

The withdrawal pays `staked_sat` **minus** the unbacked genesis principal.
The cap is untouched, no coin moves from anyone to anyone, the emission is paid
in full, and the founder simply does not receive coin that was never issued.

Cost, stated honestly: the founder forgoes 1,600,000 BLCH of nominal position it
has held on the books since launch. Since that position was never backed, the
loss is of a number, not of coin — but it is a real reduction in what the launch
ceremony appeared to grant, and the founder is the only party it falls on.

## 4. Recommendation

**Option C.** It is the only one of the three in which no party receives coin
that was never issued and no party pays for someone else's. A and B both settle
the discrepancy by moving value; C settles it by declining to.

The decision is the founder's, and it is a decision about the founder's own
position, which is the one circumstance in which this document should not be the
thing that settles it.

## 5. What is implemented

`CommittedState::unbacked_principal_sat(index)` — derived, never materialised.
It reads only fields the state root already commits (cohort membership,
`staked_sat`), so there is no second encoding of the fact to drift from the
first and no state-root schema change.

```
in the genesis cohort?        no  → Known(0)          // funded, or issued
slashed?                      yes → Indeterminate     // refuse; see below
otherwise                         → Known(min(25,000 BLCH, staked_sat))
```

The `Withdraw` arm subtracts it last, after the inactivity leak and the
slashing re-price, so those two continue to price the whole bond exactly as they
did before this rule existed.

### The case it refuses to answer

A **slashed** launch bond is `Indeterminate`, and the withdrawal is refused
rather than paid. Slashing burns from `staked_sat`; reward compounding adds to
it; committed state records neither history. A bond slashed below its principal
and then regrown by rewards is therefore indistinguishable from one never
slashed, and `min(principal, staked_sat)` would charge the burn twice — the
second time against real emitted coin, which is exactly the confiscation this
rule must not perform. Refusing is the only answer that is not a guess.

Unreachable today: 64 of 64 launch validators carry no applied slash. It is a
refusal and not a `debug_assert` because "today" is not a consensus rule.

**The fix that would let it answer** is a committed low-water mark per record —
`min(principal, stake_low_water)`, where the low-water is recorded ungated from
the rebuild, since a gate cannot record what the gate must read. That is a
state-root column (a new tag, a leaf, the mutation harness) and therefore its own
decision and its own flag day. Prior art exists on `pmo10/lastro-sobre-armado`
(2026-08-23) and should be the starting point if it is taken up.

## 6. Fork safety

**No block changes acceptance.** The entire `Withdraw` arm is behind
`withdrawal_rules_active(self.epoch)`, read from the COMMITTED epoch, with
`WITHDRAWAL_ACTIVATION_EPOCH = u64::MAX`. The write-off is reachable only from
inside a code path that no epoch reaches. An old binary and a new one return the
identical verdict — `TxReject::StakingRule` — on every block that exists or can
be produced before the flag day.

Everything else added here is read-only: `supply_audit`,
`unbacked_principal_sat`, `total_bonded_sat`, `pending_fee_total_sat`,
`delegator_fee_total_sat` compute values from committed state and write nothing.
`Manifest::check_bond_backing` runs at manifest-build time, not in block
acceptance.

**Ordering, enforced at compile time.** `FUNDED_STAKING_ACTIVATION_EPOCH` must
arm before `WITHDRAWAL_ACTIVATION_EPOCH`, or a bond nothing funded becomes
withdrawable coin. Both assertions were verified to break the build (§7 of the
delivery report); they are not decorative.

## 7. The invariant this all hangs from

```
issued_sat + unbacked_principal  ==  eUTXO set + bonded stake
                                     + producer-fee float + delegator-fee credits
                                     + everything ever burned
```

The chain burns — half the base fee during the emission era, 31/32 of every
slashing penalty, the inactivity leak at the withdrawal door — and **no counter
records a burn** (`state_root.rs`: "gross and monotone … the cap invariant is
one-sided"). So the invariant is carried as `SupplyAudit::slack()`, which is the
left side minus the right side without the burn term:

* **zero** at a launch-shaped genesis,
* **`>= 0`** in every reachable state (`None` when it would go negative), and
* **monotone non-decreasing** across every transition — it grows by exactly what
  was burned and by nothing else.

**A mint is precisely a transition that makes `slack` fall.** That is the whole
detector, and it is what was missing: nothing in this codebase computed "how
much coin is there" before now, which is why 1,600,000 BLCH could sit outside
every counter for eighteen days without anything going red.
