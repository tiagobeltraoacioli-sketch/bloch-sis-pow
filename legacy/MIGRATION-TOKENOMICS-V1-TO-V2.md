# Migration: Tokenomics V1 → V2

> ## ⚠️ HISTORICAL — completed migration; numbers below are twice superseded
> This checklist migrated the code off V1 in 2026-05. The "V2" numbers it
> targets (1B nominal, 1,905 reward, 150 s blocks, 70/25/5) were later
> re-based by the Bloch-SIS B3b revision (21B nominal, 8,400 reward, 30 s
> blocks, 100% miner — `crates/bloch-crypto/src/core/tokenomics_v2.rs`),
> and the emission curve is superseded by **Emission V3** (2,600 BLOCH
> initial, 1.5-year halvings) from emission height 453,743 / local height
> 40,000 — see [`legacy/specs/TOKENOMICS_V3.md`](./specs/TOKENOMICS_V3.md)
> and ADR-035. There is no V2 → V3 migration checklist: V3 is a single
> height-gated flag-day fork, deployed by upgrading the node binary before
> local height 40,000.

| Field | Value |
|---|---|
| **Status** | Historical (completed; superseded — see banner) |
| **Date** | 2026-05-01 |
| **Companion docs** | `legacy/specs/TOKENOMICS_V2.md`, `docs/adr/ADR-028-tokenomics-v2-activation.md`, `legacy/specs/historical/TOKENOMICS_V1_SUPERSEDED.md` |
| **Estimated effort** | 4–6 days focused engineering |

---

## 1. Why this migration exists

The codebase shipped V1 tokenomics (commits `ac14295` and `825e0a1` rebuild the consensus layer to 93/5/2 with a 4% genesis-output premine). Subsequently, ADRs 010, 010-A, and 010-Addendum-1 (committed at `5445935`) specified a different model — 70/25/5 with 17% founder premine and 30-year linear vesting — without back-applying the changes to code.

This migration brings code into agreement with ADRs. Because mainnet has not activated, no backward-compatibility guarantees exist. The migration is a clean replacement.

---

## 2. State before migration

```
src/core/mod.rs:
  MAX_SUPPLY            = 1_000_020_000 * 100_000_000  (V1)
  FOUNDER_PERCENT       = 4                              (V1)
  BLOCK_REWARD          = 2_381 * 100_000_000           (V1)
  HALVING_INTERVAL      = 210_000                        (unchanged)
  TARGET_BLOCK_TIME     = 10                             (V1)

  No constants for: MINER_SHARE_BPS, VALIDATOR_SHARE_BPS, ORACLE_SHARE_BPS,
                     TAIL_FLOOR_SAT, FOUNDER_VESTING_*

src/consensus/:
  Reward calculation hardcodes 93/5/2 split (V1, per commit 825e0a1)

src/bin/bloch-mine-genesis.rs:
  Computes founder_reward = MAX_SUPPLY * FOUNDER_PERCENT / 100  (V1 — single output)

docs/specs/TOKENOMICS_V1.md exists.
docs/specs/TOKENOMICS_V2.md does not exist.
ROADMAP.md references V1 numbers (4%, 1.00002B, 40M).
```

## 3. State after migration

```
src/core/mod.rs:
  NOMINAL_TOTAL_SUPPLY        = 1_000_000_000 * 100_000_000
  FOUNDER_PREMINE_TOTAL_SAT   =   170_000_000 * 100_000_000
  VALIDATOR_ORACLE_POOL_SAT   =    30_000_000 * 100_000_000
  MINING_EMISSION_NOMINAL_SAT =   800_000_000 * 100_000_000
  INITIAL_BLOCK_REWARD_SAT    =       1_905   * 100_000_000
  HALVING_INTERVAL            = 210_000
  TARGET_BLOCK_TIME_SECS      = 150
  TAIL_FLOOR_SAT              =          25   * 100_000_000

  MINER_SHARE_BPS             = 7_000
  VALIDATOR_SHARE_BPS         = 2_500
  ORACLE_SHARE_BPS            =   500
  ENDOW_FEE_SHARE_BPS         = 1_000

  OUTBOUND_QUERY_BURN_BPS           = 5_000
  OUTBOUND_QUERY_ENDOW_BPS          = 3_000
  OUTBOUND_QUERY_ORACLE_REBATE_BPS  = 2_000

  FOUNDER_VESTING_CLIFF       =   207_260
  FOUNDER_VESTING_LINEAR      = 6_013_440
  FOUNDER_VESTING_END         = 6_220_700

  FOUNDER_ADDRESS_HASH        = [u8; 20] (set at genesis ceremony)

  Removed: MAX_SUPPLY, FOUNDER_PERCENT, BLOCK_REWARD

src/consensus/:
  block_subsidy(height) returns u64 with tail-floor logic
  split_block_subsidy(subsidy) returns (miner, validator, oracle)
  Per-block founder vesting output enforced for h ∈ [207260, 6220700)

src/bin/bloch-mine-genesis.rs:
  No founder output at genesis (vesting cliff enforces this)

docs/specs/TOKENOMICS_V2.md replaces V1.
docs/specs/historical/TOKENOMICS_V1_SUPERSEDED.md preserves V1.
ROADMAP.md updated to reflect V2 numbers.
```

---

## 4. Refactor steps (in execution order)

### Step 1 — Documentation flip (no code changes)

```bash
# In repo root
mkdir -p docs/specs/historical
git mv docs/specs/TOKENOMICS_V1.md docs/specs/historical/TOKENOMICS_V1_SUPERSEDED.md
# Add the SUPERSEDED header at the top per the SUPERSEDED.md template.
# Place the new V2 spec.
cp /path/to/new/TOKENOMICS_V2.md docs/specs/TOKENOMICS_V2.md
# Place the new ADR.
cp /path/to/new/ADR-028-tokenomics-v2-activation.md docs/adr/
```

Commit boundary: `docs(specs): supersede V1 tokenomics, add V2`

### Step 2 — Constants in src/core/mod.rs

Replace the constants block (lines 14–32 currently):

- Remove: `MAX_SUPPLY`, `FOUNDER_PERCENT`, `BLOCK_REWARD`
- Add: `NOMINAL_TOTAL_SUPPLY`, `FOUNDER_PREMINE_TOTAL_SAT`, `VALIDATOR_ORACLE_POOL_SAT`, `MINING_EMISSION_NOMINAL_SAT`, `INITIAL_BLOCK_REWARD_SAT`, `TAIL_FLOOR_SAT`
- Update: `TARGET_BLOCK_TIME` → `TARGET_BLOCK_TIME_SECS = 150` (was 10)
- Add reward split BPS constants: `MINER_SHARE_BPS`, `VALIDATOR_SHARE_BPS`, `ORACLE_SHARE_BPS`
- Add fee distribution: `ENDOW_FEE_SHARE_BPS`, three `OUTBOUND_QUERY_*` constants
- Add vesting: `FOUNDER_VESTING_CLIFF`, `FOUNDER_VESTING_LINEAR`, `FOUNDER_VESTING_END`
- Add `FOUNDER_ADDRESS_HASH = [0u8; 20]` placeholder (set at genesis)

After the const block, update the documentation comments to reference V2 instead of V1.

Commit boundary: `feat(core): V2 tokenomics constants`

### Step 3 — Update reward computation

Locate `block_subsidy(height)` (currently around `src/core/mod.rs:1209`). Replace:

```rust
fn block_subsidy(height: u64) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    if halvings >= 64 { 0 } else { BLOCK_REWARD >> halvings }
}
```

with:

```rust
pub fn block_subsidy(height: u64) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    let geometric = if halvings >= 64 {
        0
    } else {
        INITIAL_BLOCK_REWARD_SAT >> halvings
    };
    geometric.max(TAIL_FLOOR_SAT)
}
```

Add new function `split_block_subsidy`:

```rust
pub fn split_block_subsidy(subsidy: u64) -> (u64, u64, u64) {
    let validator = subsidy * VALIDATOR_SHARE_BPS / 10_000;
    let oracle    = subsidy * ORACLE_SHARE_BPS    / 10_000;
    let miner     = subsidy - validator - oracle;
    (miner, validator, oracle)
}
```

Update existing 93/5/2 reward split logic in `src/consensus/` (find with `grep -rn "93\|7000\|9_300" src/consensus/`) to use `split_block_subsidy`.

Commit boundary: `feat(consensus): V2 70/25/5 reward split + tail floor`

### Step 4 — Implement founder vesting

This is **new code** not present in V1. Add to `src/core/mod.rs` (or new `src/core/vesting.rs` module):

```rust
pub fn founder_vested_amount_sat(h: u64) -> u64 {
    if h < FOUNDER_VESTING_CLIFF {
        0
    } else if h >= FOUNDER_VESTING_END {
        FOUNDER_PREMINE_TOTAL_SAT
    } else {
        let blocks_post_cliff = h - FOUNDER_VESTING_CLIFF;
        FOUNDER_PREMINE_TOTAL_SAT * blocks_post_cliff / FOUNDER_VESTING_LINEAR
    }
}

pub fn founder_vesting_for_block(h: u64) -> u64 {
    if h == 0 { return 0; }
    founder_vested_amount_sat(h) - founder_vested_amount_sat(h - 1)
}
```

In `accept_block` consensus validation, enforce:

- For block at height `h ∈ [FOUNDER_VESTING_CLIFF, FOUNDER_VESTING_END)`: coinbase MUST contain an output of exactly `founder_vesting_for_block(h)` to `FOUNDER_ADDRESS_HASH`.
- For block at height `h < FOUNDER_VESTING_CLIFF`: coinbase MUST NOT contain any output to `FOUNDER_ADDRESS_HASH`.
- For block at height `h ≥ FOUNDER_VESTING_END`: coinbase MUST NOT contain any output to `FOUNDER_ADDRESS_HASH`.

Commit boundary: `feat(consensus): per-block founder vesting (V2 §5)`

### Step 5 — Block time cascade

Update all references to 10s block time:

- `TARGET_BLOCK_TIME = 10` → `TARGET_BLOCK_TIME_SECS = 150`
- Difficulty retargeting comment: "5.6 hours" → "84 hours"
- `src/ffg/mod.rs:91` comment about 10min block_time — update or remove (FFG epoch math has its own scale)
- `src/bin/bloch-calibrate.rs:343-344` — block time bounds 5..20s → 50..300s (or recalibrate per measured hashrate)
- Any tests with hardcoded 10s assumptions

Run `cargo test` and fix all assertion failures resulting from changed timing.

Commit boundary: `feat(consensus): block time 10s → 150s (V2 §3)`

### Step 6 — Genesis tools

`src/bin/bloch-mine-genesis.rs` (line 98 currently):

```rust
let founder_reward = MAX_SUPPLY * FOUNDER_PERCENT / 100;  // REMOVE
```

Genesis block has 0 founder output. The first founder output appears at block 207,260.

`src/bin/bloch-calibrate.rs`:

- Update difficulty calibration to target 150s blocks at expected initial hashrate
- Block-time validation bounds widen to accommodate longer interval

Commit boundary: `chore(tools): genesis tools updated for V2`

### Step 7 — Test refactor

All tests with V1 assumptions need updating. Find them:

```bash
grep -rn "2_381\|2381\|FOUNDER_PERCENT\|1_000_020_000\|1000020000\|MAX_SUPPLY" tests/ src/
```

Replace V1 numbers with V2:
- `BLOCK_REWARD` (`238_100_000_000`) → `INITIAL_BLOCK_REWARD_SAT` (`190_500_000_000`)
- Reward split tests (93/5/2) → 70/25/5
- Total emission tests: 1,000,020,000 BLOCH → 798,630,000 BLOCH pre-tail (or 800M nominal)
- Founder reward at genesis: 40,000,800 BLOCH → 0 BLOCH
- Halving timing (24.3 days) → 365 days

Add new tests:

```rust
#[test]
fn vesting_zero_pre_cliff() {
    assert_eq!(founder_vested_amount_sat(0), 0);
    assert_eq!(founder_vested_amount_sat(207_259), 0);
}

#[test]
fn vesting_starts_at_cliff() {
    assert_eq!(founder_vesting_for_block(207_259), 0);
    assert!(founder_vesting_for_block(207_260) > 0);
}

#[test]
fn vesting_complete_at_end() {
    assert_eq!(founder_vested_amount_sat(6_220_700), FOUNDER_PREMINE_TOTAL_SAT);
    assert_eq!(founder_vested_amount_sat(7_000_000), FOUNDER_PREMINE_TOTAL_SAT);
}

#[test]
fn vesting_total_matches_premine() {
    let mut sum = 0u64;
    for h in FOUNDER_VESTING_CLIFF..FOUNDER_VESTING_END {
        sum += founder_vesting_for_block(h);
    }
    // Truncation loss ≈ 0.026 BLOCH = 2_562_560 sat
    let loss = FOUNDER_PREMINE_TOTAL_SAT - sum;
    assert!(loss < 10_000_000, "vesting truncation loss too high: {loss}");
}

#[test]
fn split_sums_correctly() {
    let s = INITIAL_BLOCK_REWARD_SAT;
    let (m, v, o) = split_block_subsidy(s);
    assert_eq!(m + v + o, s);
}

#[test]
fn split_proportions_correct() {
    let s = 10_000_000_000u64;  // 100 BLOCH exact
    let (m, v, o) = split_block_subsidy(s);
    assert_eq!(v, 2_500_000_000);  // 25%
    assert_eq!(o,   500_000_000);  //  5%
    assert_eq!(m, 7_000_000_000);  // 70%
}

#[test]
fn tail_floor_activates() {
    let height_before_tail = 6 * HALVING_INTERVAL + 1;  // halving 6: reward 29 BLOCH
    assert!(block_subsidy(height_before_tail) > TAIL_FLOOR_SAT);
    let height_at_tail = 7 * HALVING_INTERVAL + 1;  // halving 7: geometric 14, tail 25
    assert_eq!(block_subsidy(height_at_tail), TAIL_FLOOR_SAT);
    let height_far_future = 100 * HALVING_INTERVAL;
    assert_eq!(block_subsidy(height_far_future), TAIL_FLOOR_SAT);
}

#[test]
fn pre_tail_emission_close_to_target() {
    let mut sum = 0u64;
    for h in 0..(11 * HALVING_INTERVAL) {  // halvings 0–10 inclusive
        let r = INITIAL_BLOCK_REWARD_SAT >> (h / HALVING_INTERVAL);
        if r >= TAIL_FLOOR_SAT { sum += r; } else { break; }
    }
    let pre_tail_bloch = sum / 100_000_000;
    assert!(pre_tail_bloch >= 798_000_000 && pre_tail_bloch <= 800_000_000,
        "pre-tail emission off target: {pre_tail_bloch}");
}
```

Commit boundary: `test(consensus): V2 tokenomics test suite`

### Step 8 — ROADMAP and README

`ROADMAP.md`:
- Update §1 and §6.0 references to "1,000,020,000 BLOCH" → "1,000,000,000 BLOCH nominal"
- Update §6.0 references to "40,000,800 BLOCH premine" → "170,000,000 BLOCH premine, 30-year vesting"
- Update tokenomics rebuild references from "ac14295 / 825e0a1" to "ADR-028"

`README.md`:
- Find any tokenomics summaries (`grep -n "premine\|2381\|FOUNDER_PERCENT" README.md`)
- Update to V2 numbers

Commit boundary: `docs: ROADMAP + README aligned with V2`

### Step 9 — ADR closure

Add or update:
- `docs/adr/ADR-010-tokenomics-emission.md` — change Status from "Proposed" to "Accepted (V2 activated by ADR-028)"
- `docs/adr/ADR-010-A-founder-premine.md` — change Status from "Proposed" to "Accepted (V2 activated by ADR-028)"
- `docs/adr/ADR-010-Addendum-1-oracle-pool.md` — change Status to "Accepted"
- `docs/adr/ADR-028-tokenomics-v2-activation.md` — Status "Accepted" with date

Commit boundary: `docs(adr): close 010-* sequence; ADR-028 accepted`

### Step 10 — Final sanity checks

```bash
cargo build --all-targets
cargo test --release
cargo clippy --all-targets -- -D warnings
grep -rn "FOUNDER_PERCENT\|MAX_SUPPLY\|2_381\|2381" src/ tests/  # should be empty
grep -rn "93/5/2\|9300\|7_000_000\|7000_BPS" src/  # should be empty (V1 split removed)
```

If all green, tag:

```bash
git tag v0.2.2-tokenomics-v2
```

---

## 5. Genesis ceremony — separate workflow

After this migration, a separate workflow regenerates the genesis block:

1. Founder address generation (ML-DSA-65 keypair, 3-2-1 backup per memory entry of 2026-04-26)
2. Treasury and oracle pool address generation, multi-sig setup
3. `FOUNDER_ADDRESS_HASH` constant set in src/core/mod.rs
4. Genesis difficulty calibrated against measured seed hashrate
5. `bloch-mine-genesis` runs with V2 constants
6. Genesis block hash committed and tagged
7. Sanity verification: clean fresh node sync past block 0, then 207,260, then 1,470,000

This is **not** part of the V1 → V2 migration. Genesis ceremony is post-mainnet-dev-checklist work per `legacy/MAINNET-DEV-CHECKLIST.md` §9.

---

## 6. Rollback strategy

If V2 migration breaks something post-merge but pre-genesis ceremony, simply revert the merge commits in reverse order. Branch protection should require these commits land in atomic groups so revert is clean.

If V2 migration breaks something post-genesis, this is a hard fork situation. The chance of this is low because all V2 logic is exercised by tests before genesis ceremony.

---

## 7. Document control

- **Version:** 1.0 — initial
- **Date:** 2026-05-01
- **Owner:** Founder (custodial) until Phase 3
- **License:** Same as repository
