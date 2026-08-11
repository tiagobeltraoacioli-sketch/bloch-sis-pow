<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Bloch — Tokenomics V4 (Genesis-4 relaunch with carryover)

```
Document:   BLOCH-TOKENOMICS-V4
Status:     DRAFT — founder decision recorded, parameters not frozen
Created:    2026-08-10
Supersedes: tokenomics_v2.rs (21 B nominal, uncapped tail) and ADR-035 emission V3
Relates to: BLOCH-POS-SHA3-LATTICE-MIGRATION.md (§4 distribution gates)
```

---

## 1. Decision

Relaunch from a fresh genesis with a **fixed 100,000,000,000 BLCH** supply.
Balances held today by parties other than the founder are carried over in
**absolute** terms, capped at 300,000,000 BLCH. The founder's current holding is
not carried over; it is replaced by a new, vested 17% allocation.

| Destination | BLCH | Share | Unlock |
|---|---:|---:|---|
| Founder | 17,000,000,000 | 17.00% | **2-year cliff, then 10-year linear vesting** |
| VC / crypto hedge funds | 10,000,000,000 | 10.00% | **unspecified — §7** |
| Development team | 10,000,000,000 | 10.00% | **unspecified — §7** |
| Marketing | 4,000,000,000 | 4.00% | **unspecified — §7** |
| Liquidity | 5,000,000,000 | 5.00% | **unspecified — §7** |
| Carryover holders | ≤ 300,000,000 | ≤ 0.30% | liquid at genesis |
| **Validators** | **53,700,000,000** | **53.70%** | emitted over 40 years |
| **Total** | **100,000,000,000** | **100.00%** | |

Validator emission runs for 40 years and is supplemented by transaction fees.
**After the 100 B is fully emitted, validators are paid 100% from fees.**

---

## 2. What the carryover actually contains — measured

From `carryover.tsv.gz` (413,743 UTXOs, SHA-256 pinned in-repo), aggregated by
address hash. The set has exactly **five** addresses:

| Address hash | BLCH | Share of carryover | UTXOs |
|---|---:|---:|---:|
| `e986db51…` (founder) | 3,294,337,200 | 94.79% | 392,183 |
| `be7c81e1…` | 177,063,600 | 5.10% | 21,079 |
| `5b4a5303…` | 3,158,400 | 0.09% | 376 |
| `5b00d538…` | 470,400 | 0.01% | 56 |
| `5d493bc4…` | 411,600 | 0.01% | 49 |
| **Total** | **3,475,441,200** | 100% | 413,743 |

**Non-founder total: 181,104,000 BLCH — 5.21%.** The founder's "the 5% others
hold" is accurate to two significant figures.

That figure is the **floor**, not the final number: it covers only the
Genesis-1 carryover. Coins mined since Genesis-3 by third parties must be added
at snapshot time. The chain stands at height **40,144**, so 337,209,600 BLCH
have been emitted since Genesis-3 (40,144 × 8,400).

---

## 3. The 300 M cap is close to binding — and moving

Headroom against the measured carryover floor is 118,896,000 BLCH. But
third-party miners accrue continuously.

A measurement recorded at height 18,809 had non-founder holdings at ≈ 207 M
against a carryover floor of 181.1 M, implying roughly **16% of emission has
been going to third parties**. Carrying that rate forward:

| | |
|---|---|
| Estimated non-founder holdings at h40,144 | ≈ 236 M BLCH |
| Remaining headroom under the cap | ≈ 64 M BLCH |
| Third-party accrual at 8,400 BLCH/block, 2,880 blocks/day, ~16% share | ≈ 4.0 M BLCH/day |
| **Estimated time until the cap binds** | **≈ 2 weeks** |

The 16% figure is an estimate derived from a single prior measurement, not a
fresh audit — it should be re-measured against live balances before anything is
frozen. But the order of magnitude is the point: **the cap is not comfortable
headroom, it is a deadline.**

Two consequences that need a decision now:

1. **The snapshot height must be announced in advance and fixed.** Otherwise the
   cap creates an incentive to mine hard right before an unannounced snapshot,
   and the choice of height becomes a discretionary act that redistributes value
   between third parties.
2. **A rule is needed for the over-cap case.** The proposal here is
   **pro-rata scale-down**: if measured non-founder holdings exceed 300 M, every
   non-founder balance is multiplied by `300_000_000 / total_non_founder`. It is
   neutral, needs no discretion, and it is the only rule that treats a holder's
   position the same regardless of when they acquired it. A first-come or
   by-address cut would not.

---

## 4. What this does to existing holders

Stated plainly, because it affects parties who are not in the room:

| | Today | After V4 |
|---|---:|---:|
| Non-founder coins | 181.1 M (carryover) | ≤ 300 M |
| Non-founder **share of network** | 5.21% | **≤ 0.30%** |

Holders keep their coins in absolute terms and lose roughly **17×** of their
relative position. That is the arithmetic consequence of preserving absolute
balances while multiplying total supply by ~27× (3.475 B → 100 B). It is a
legitimate choice — it is what "preserved in absolute terms" means — but it
should be published in exactly these terms rather than as "your balance is
preserved", which is true and misleading at the same time.

---

## 5. What this does to the concentration problem

This is the strongest argument for the relaunch, and it is worth stating.

The PoS migration design opens (§0.1) with the objection that ~94% of supply
sits at one address, so stake-weighted consensus would hand the chain to the
founder. V4 changes that materially:

| | Today | V4 at genesis | V4 after founder vesting completes |
|---|---:|---:|---:|
| Founder | 94.3% | **0%** (2-year cliff) | 17% |
| Insiders total (founder + VC + team + marketing) | 94.3% | depends on §7 | 41% |
| Validators (earned) | — | grows to 53.7% | 53.7% |

With a 2-year cliff, the founder holds **no spendable stake at genesis**. That
is a genuine, consensus-enforceable answer to §0.1 — far stronger than the
taint-propagation machinery in §4.1 of the migration design, which exists
precisely because the current distribution could not be fixed any other way.

**But it depends entirely on §7.** If VC, team and marketing (24% combined)
unlock at or near genesis, the concentration problem returns in a different
costume: a 24% bloc against a validator allocation that starts at zero and
takes years to accumulate. The gates G1–G4 would fail on day one.

---

## 6. Emission

- Validator allocation: **53,700,000,000 BLCH** over **40 years**.
- At 30 s slots: 42,076,800 slots in 40 years.
- **Average 1,276 BLCH per block.**

The curve itself is not specified by this decision. Three candidates:

| Curve | Behaviour | Note |
|---|---|---|
| Flat | 1,276 BLCH/block for 40 years | Simplest; no early-adopter premium |
| Halving | Higher early, halving every N years | Familiar; front-loads to early validators |
| Smooth decay | Continuous exponential to a floor | Avoids halving cliffs entirely |

**Hard cap — a reversal worth recording.** The current design is explicitly
*not* hard-capped: `tokenomics_v2.rs` runs a perpetual 100 BLCH tail
(Monero-style), and ADR-035 lowered that floor to 60. V4 replaces it with a
fixed cap and a fee-only end state. That is a deliberate and defensible choice,
but it inherits the fee-only security-budget question: after year 40, the
entire cost of consensus must be covered by fee revenue, and if fees are thin
the validator set shrinks to whatever fees sustain. The tail existed to avoid
exactly that. The reversal should be recorded in an ADR that retracts the tail
rationale rather than silently superseding it.

---

## 7. Unspecified — blocking

Vesting for **VC (10%), team (10%), marketing (4%) and liquidity (5%)** was not
specified. This is not a detail: per §5 it decides whether the relaunch fixes
the concentration problem or reproduces it. It also decides whether the PoS
activation gates G1–G4 can ever be met.

Liquidity is the one allocation with a genuine argument for being liquid at
genesis — that is its function. The other three are not obviously so.

---

## 8. Engineering hazards

### 8.1 u64 headroom — must be addressed before any code lands

At 8 decimal places, 100 B BLCH is **10^19 satoshis, which is 54.21% of
`u64::MAX`**. Today's 21 B nominal is 11.38%.

The supply itself fits. The danger is that **any addition of two large values
overflows**: a supply-accounting check, a treasury-plus-allocation comparison,
a sum over a large UTXO set. In debug builds that panics; in release builds it
wraps silently, and a silently wrapped consensus value is a chain split.

Options:

| Option | Effect | Cost |
|---|---|---|
| **Keep 8 decimals, move all accumulators to `u128`** (recommended) | Divisibility unchanged; overflow impossible in accounting paths | Audit of every summation over balances; `u64` stays for individual values |
| Reduce to 6 decimals | Supply becomes 0.54% of `u64::MAX` | Loses two orders of divisibility; changes every address/amount format |

Recommended: keep 8 decimals, `u128` for every accumulator, plus a
`const _: () = assert!(...)` pinning the invariant so a future supply change
cannot quietly re-enter the danger zone. This is the same discipline already
applied in `crates/bloch-pos-committee/src/sample.rs`, where cumulative stake is
`u128` for exactly this reason.

### 8.2 Genesis allocation outputs

Six allocations must appear in the genesis block as consensus-recognised
outputs with their unlock schedules enforced by consensus, not by promise —
the same standard §4.1 of the migration design applies to the old premine. A
vesting schedule that lives in a spreadsheet is not a vesting schedule.

---

## 9. Open decisions

1. Vesting for VC, team, marketing, liquidity (§7) — **blocking**.
2. Emission curve: flat, halving, or smooth decay (§6).
3. Snapshot height, announced in advance (§3).
4. Confirmation of pro-rata scale-down for the over-cap case (§3).
5. Decimal places and the `u128` accumulator audit (§8.1).
6. ADR retracting the perpetual-tail rationale (§6).
7. **The VC allocation against the ownerless thesis.** ADR-033 restored an
   ownerless position; ADR-034 records a founder anonymisation/relinquishment
   pact; the public posture is a civic node movement, "coins don't vote", not a
   security. A 10% allocation sold to funds introduces investors with a return
   expectation and, in practice, an issuer. That is a coherent thing to want,
   but it cannot coexist unstated with the current public documents — one of the
   two has to be retracted, in writing, before either is published.
