# BLOCH Tokenomics V1 — Specification (SUPERSEDED)

> ⚠️ **THIS DOCUMENT IS SUPERSEDED.**
>
> V1 has been replaced by V2. See:
> - `docs/specs/TOKENOMICS_V2.md` — the active specification
> - `docs/MIGRATION-TOKENOMICS-V1-TO-V2.md` — engineering migration checklist
> - `docs/adr/ADR-028-tokenomics-v2-activation.md` — architectural decision recording the transition
>
> **What V1 specified that V2 changed:**
> - V1: 4% founder premine = 40,000,800 BLOCH, single coinbase output at genesis, no on-chain vesting
> - V2: 17% founder premine = 170,000,000 BLOCH, per-block coinbase outputs over 348 months with 207,260-block cliff
> - V1: 1,000,020,000 BLOCH mining cap (overshoots 1B by 20k due to integer rounding)
> - V2: 1,000,000,000 BLOCH nominal supply with separate accounting for premine, pool, and mining
> - V1: 93/5/2 reward split (miner / oracle / treasury)
> - V2: 70/25/5 reward split (miner / validator / oracle) with no on-chain treasury
> - V1: 10-second block time (assumed in halving math)
> - V2: 150-second block time (consistent with ADR-006)
>
> V1 was never deployed. Mainnet has not activated. V2 is the genesis configuration that will be used for mainnet activation per ADR-023 Phase 1.
>
> This document is preserved as historical record only. **Do not** treat any constant or rule herein as binding.
>
> **Date of supersession:** 2026-05-01
> **Superseding document:** `docs/specs/TOKENOMICS_V2.md` v2.0

---

# BLOCH Tokenomics V1 — Specification

**Status**: SUPERSEDED (was: Genesis-locked, pre-commitment doctrine)
**Version**: 1.2 (final V1 revision)
**Date**: April 2026
**Author**: BLOCH Founder

> *"Tudo o que pode ser parametrizado por governance pode ser corrompido por governance."*
>
> — Doutrina BLOCH, *Ensaio 2 — Pre-Commitment Doctrine*

---

## 1. Preamble

This document specifies the complete economic model of the Bloch-SIS Protocol (BLOCH) blockchain. Every parameter herein is **genesis-locked** — meaning the values are compiled into the Rust source code as `pub const` constants, become consensus rules at genesis block production, and can only be changed by hard fork. There is no on-chain governance mechanism that can alter these parameters. There is no voting. There is no DAO.

This is not a limitation. It is the design.

The reasoning is developed at length in *The Cryptographic Constitution* (2026, SSRN) and in *Ensaio 2 — Pre-Commitment Doctrine*. The short version: any parameter that the protocol allows to be changed by some procedure becomes the focal point of capture by whoever controls that procedure. The only way to make a parameter genuinely credible as a long-term commitment is to remove the mechanism of its alteration. Hard fork remains as the final escape valve, but it requires social consensus across miners, oracles, and users — exactly the high-cost, high-visibility procedure that pre-commitment theory (Elster 1979, 2000) identifies as the proper substrate for constitutional rules.

Therefore: **the numbers in this document are not proposals. They are commitments.**

---

## 2. Total Supply

```
MINING_EMISSION_CAP    = 1,000,020,000 BLOCH  (Σ subsidy as halvings → ∞)
FOUNDER_PREMINE        =     40,000,800 BLOCH  (4% of MINING_EMISSION_CAP)
TOTAL_ABSOLUTE_SUPPLY  = 1,040,020,800 BLOCH  (mining cap + premine)
DECIMALS               = 8
ATOMIC_UNIT            = 1 BLOCH × 10⁻⁸ = 1 satoshi
```

Distribution at completion (after all halvings asymptotically reach the supply cap):

```
Genesis pre-allocation (founder)              40,000,800 BLOCH  ( 3.846%)
Block subsidy emission (miners,      93%)    930,018,600 BLOCH  (89.423%)
Block subsidy emission (oracle pool,  5%)     50,001,000 BLOCH  ( 4.808%)
Block subsidy emission (treasury,     2%)     20,000,400 BLOCH  ( 1.923%)
                                           ───────────────
                                            1,040,020,800 BLOCH  (100.000%)
```

The 4% founder pre-allocation is fixed at genesis as a single coinbase output, with **no on-chain vesting schedule** (see §7 for the off-chain lockup pledge that complements this). It is the only deviation from a pure 0%-premine fair launch, and it exists for a single reason: it grants the founder long-term economic alignment with the project's success without requiring external venture capital. The deviation is publicly disclosed, mathematically bounded, and constitutionally locked at the protocol level — exactly the conditions that make pre-commitment legitimate.

**Note on percentages.** Two related but distinct percentages appear in this document. The **per-block split** (93/5/2) describes how every block's subsidy is divided among miner, oracle pool, and treasury. The **share of total absolute supply** describes how the same parameters distribute across the chain's full lifetime. The miner per-block share is 93%, but the miner share of total absolute supply is ~89.42% — the difference is the founder's 40,000,800 BLOCH premine, minted at genesis and outside the per-block split. Both numbers are correct; they describe different cuts of the same accounting.

---

## 3. Block Subsidy

```
GENESIS_BLOCK_REWARD     = 2,381 BLOCH per block
HALVING_INTERVAL         = 210,000 blocks
EMISSION_CURVE           = geometric (each halving cuts reward in half)
ASYMPTOTIC_BEHAVIOR      = subsidy → 0 as blocks → ∞
```

The 210,000-block halving interval and the geometric emission curve are direct lineage inheritance from Bitcoin (Nakamoto 2008). The genesis reward of 2,381 was calibrated to land the total mining emission at exactly:

```
Σ subsidy = 2381 × 210,000 × (1 + 1/2 + 1/4 + ...) = 2381 × 210,000 × 2 = 1,000,020,000 BLOCH
```

The 20,000 BLOCH above a clean 1B is the unavoidable rounding consequence of integer reward × integer halving interval; the alternative (a non-integer reward) would introduce floating-point determinism risks across heterogeneous node implementations and is rejected on consensus-safety grounds.

At 10-second target block time, the halving interval corresponds to approximately 24.3 days of wall-clock time (210,000 × 10s = 2,100,000 seconds). The full mining emission curve reaches:

- 50% of mining cap at halving 1 (~24 days)
- 99% at halving ~7 (~5.6 months)
- 99.99% at halving ~14 (~11 months, at which point subsidy drops below 1 satoshi)

After approximately one year of mainnet operation, the chain transitions from subsidy-funded to fee-funded miner economics. Halving epochs continue beyond this asymptotic regime as a numerical formality.

---

> **NOTE TO READERS:** The above is the V1 spec preserved verbatim. V1 had additional sections on block reward split (93/5/2), fee distribution, oracle pool mechanics, treasury, and genesis transaction structure. Those sections are not reproduced in full here because they are wholly superseded by V2. The complete V1 file as committed at hash `1306979` is available in git history if needed for archival reference.
>
> The substantive change between V1 and V2 is documented in `docs/adr/ADR-028-tokenomics-v2-activation.md`.

---

## End of superseded specification

V1 is preserved here as historical record. All future references to BLOCH tokenomics should cite `docs/specs/TOKENOMICS_V2.md`.

If you arrived here because of an external link, please update your reference to V2.
