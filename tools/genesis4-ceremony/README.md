<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Genesis-4 ceremony

Assembles the Genesis-4 genesis block from the signed carryover artifact and
the published genesis validator cohort: the canonical allocation document
(every opening output with its unlock schedule, plus the cohort), the
`BlockHeaderV4` for slot 0, and the `block_id`.

Spec: `docs/specs/BLOCH-TOKENOMICS-V4.md` (§1 allocations, §2–§3 carryover and
the retired cap, §3.2.2 artifact-is-canonical, §3.3 genesis validator set,
§3.3.1 the one-year rule, §7 vesting, §8.2 consensus-enforced locks) and
`docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §5.3–§5.5.

Key custody for the ceremony — what must exist before this tool can run, and
under whose control — is `docs/specs/BLOCH-GENESIS-KEYS.md`.

## Why Rust, when `build_carryover.py` is Python

The carryover builder *filters an external snapshot* — Python was the right
tool, and restating `SAT_PER_BLOCH` there is a tolerable duplication for a
filter. The ceremony *constructs the consensus object itself*, and that
changes the calculus:

1. **No restated numbers.** This crate imports every constant and every
   vesting curve from `crates/bloch-pos-committee` — the tokenomics from
   `tokenomics_v4.rs` (whose compile-time assertions pin the 21 B total and
   the 9,036,115,200 validator remainder), the key and deposit parameters from
   `staking.rs`, the cohort-floor inputs from `params.rs`. A Python ceremony
   would be a second copy of the tokenomics that could drift from the one
   consensus compiles in.
2. **Slot-exact arithmetic.** Unlock schedules use truncating integer
   division. The tests assert the schedule carried in the genesis agrees with
   `founder_vested_sat` & co. at every boundary slot — provable only when both
   sides run the same `u128` arithmetic.
3. **Same hashing conventions.** SHA3-256/SHAKE-256 with the 16-byte
   `BLCH4:` domain tags from `params.rs`, the same crate the node-side
   verifier will use — and the cohort fixture in the tests commits real
   8,192-step `beacon::RandaoChain` heads, not mocks.

Cross-language continuity is pinned, not assumed: a known-answer test asserts
the Rust SHAKE-256 of a carryover file equals what CPython's
`hashlib.shake_256` (i.e. `build_carryover.py`) publishes.

Workspace posture: standalone crate with its own `[workspace]`, exactly like
`bloch-pos-committee` — not a member of the node workspace, cannot touch the
live validation path.

## What the genesis contains

| Output | BLCH | Schedule (consensus-enforced) |
|---|---:|---|
| Carryover holders | 3,773,884,800 — the whole measured ledger, founder included | fully liquid, from the signed artifact |
| Founder (new grant) | 2,100,000,000 | 10-year cliff, 40-year linear |
| VC | 2,100,000,000 | 12-month cliff, 24-month linear |
| Team | 2,100,000,000 | 18-month cliff, 36-month linear |
| Marketing | 840,000,000 | 25% at genesis, 24-month linear |
| Liquidity | 1,050,000,000 − cohort stake | fully liquid |
| Genesis cohort (bonded stake) | ≥ 64 × 100,000 minimum, out of liquidity | staked from slot 0, exit via the ordinary path |

Plus the validator emission (9,036,115,200 over 40 years), so the accounting
closes to **exactly** 21,000,000,000 BLCH — outputs + bonded cohort stake +
emission, not "at most". Each output's schedule is part of its leaf hash, so
`state_root` — and therefore `block_id` — commits to the locks: a genesis
without them is a visibly different chain, not a broken promise (§8.2's
standard).

The **carryover cap is retired** (§3): the artifact must total exactly
3,773,884,800 BLCH — the measured ledger the constants were balanced around.
The ceremony never scales, pads, or truncates; any other total stops it.

## The genesis validator cohort — §3.3

A fresh genesis has no PoW to seed it and deposits need blocks that need
validators, so the chain launches with a founder-funded, founder-operated
validator set — published **in the genesis block** as consensus data, active
from slot 0, no deposit transaction. The tool takes the cohort as a TSV
(one line per validator):

```
index<TAB>pubkey_hex<TAB>randao_c0_hex<TAB>stake_sat<TAB>withdrawal_hex
```

- `index`: contiguous from 0 — the registry indices
  `genesis_cohort::apply_cohort_cap` consumes.
- `pubkey`: the **raw** 3,745-byte hybrid key, ML-DSA-65 ‖ Falcon-1024
  (`staking.rs` convention; strip the 4-byte `bloch-crypto` suite envelope —
  the parser tells you if you forgot).
- `randao_c0`: the head of the validator's 8,192-step SHAKE-256 RANDAO chain
  (`beacon.rs`), committed here because a validator without one can never
  propose.
- `stake_sat`: ≥ `MIN_DEPOSIT_SAT` (100,000 BLCH), funded **from the
  liquidity bucket** (§3.3.1) — the genesis liquidity output is reduced by
  the total bonded stake, so nothing is minted for the cohort.
- `withdrawal`: 32-byte return address, fixed at genesis so a hot validator
  key cannot redirect the principal.

At least **64 members** (two attesters per slot across the 32-slot epoch
partition; derived as `2 × SLOTS_PER_EPOCH`, not restated). Duplicate pubkeys
or duplicate RANDAO commitments are refused — a shared `c_0` means a
copy-pasted seed.

**Why the cohort is inside the block:** the one-year commitment — founder
weight below one third within a year — is enforced by
`crates/bloch-pos-committee/src/genesis_cohort.rs` as a declining cap on
exactly this set. The set must therefore be published once, in the genesis,
shrink-only; the cohort Merkle root is a leaf of `state_root`, so editing the
set (or its count) changes the `block_id`. A genesis without the cohort would
give the cap nothing to bind, which is why this tool refuses to build one.

## The carryover digest is inside the block — §3.2.2

After the Genesis-3 chain halts at 80,000, nobody is paying hashrate to
defend it and rewriting its history costs almost nothing. **The signed
artifact is the record, not the chain.** The artifact's SHAKE-256 digest is a
leaf of the genesis `state_root`, so replacing the artifact silently is
impossible — it changes the genesis `block_id`, i.e. it launches a different
chain in public. The tool is fail-closed in both directions: it recomputes
the digest from the artifact bytes and refuses to build unless it matches the
digest passed in from the published record.

## Runbook

```bash
# 0. inputs: the artifact from tools/genesis4-carryover and its PUBLISHED
#    digest (from the halt announcement — not recomputed from the same file),
#    plus the cohort file assembled per docs/specs/BLOCH-GENESIS-KEYS.md.
gunzip -k genesis4-carryover.tsv.gz   # ceremony reads plain bytes only

# 1. assemble
cargo run --release -- \
    --carryover genesis4-carryover.tsv \
    --carryover-shake256 <published 64-hex digest> \
    --cohort genesis4-cohort.tsv \
    --founder <addr40> --vc <addr40> --team <addr40> \
    --marketing <addr40> --liquidity <addr40> \
    --out genesis4

# outputs:
#   genesis4.tsv           canonical allocation document (incl. cohort)
#   genesis4.tsv.shake256  its SHAKE-256
#   genesis4.header.bin    canonical BlockHeaderV4 (304 B, little-endian)
# printed: state_root, cohort_root and block_id

# 2. several operators run steps 0–1 independently and compare block_ids.
#    Agreement between independent parties is the evidence — one party's
#    output is only a commitment. Then publish document + digest + block_id
#    alongside the carryover artifact.
```

The Genesis-4 node's genesis loader must rebuild `state_root` from the
allocation document and refuse to start on mismatch — the same fail-closed
posture `chain_requires_carryover` gives Genesis-3.

## Header choices worth recording

- `proposer_index = u32::MAX`: genesis has no proposer and no proposer
  signature; the sentinel can never be a real validator index.
- `randao_mix = SHA3-256(DS_RANDAO ‖ 0³² ‖ carryover_digest)`: one §6 mixing
  step seeds the beacon from the artifact, so even the RANDAO chain's origin
  entropy is pinned to the record. The cohort's own chains take over from
  slot 1 — each member's `c_0` is in its cohort leaf, already inside
  `state_root`.
- Checkpoint roots, `body_root`, `attestation_root`, `coherence_root` are
  all-zeros: genesis is its own finalized checkpoint, the body is empty, the
  shielded pool starts empty.

## Tests

```bash
cargo test
```

Twenty tests covering: the sum of allocations + bonded stake + emission is
exactly 21,000,000,000 BLCH; the bucket values and schedules match the §1
table (founder 10-year cliff / 40-year linear); no lock absent; slot-exact
agreement between the carried schedules and the `tokenomics_v4` closed forms;
the carryover digest KAT against CPython; refusal on digest mismatch,
tampered artifacts, wrong-total artifacts, non-canonical encodings and
bucket-address collisions; the cohort — floor of 64 enforced, funded from
liquidity with the accounting still closing, inside the block identity
(stake, commitment, and count all move `block_id`), indices consumable by
`apply_cohort_cap` end-to-end, malformed cohorts refused, parser strict; and
that digest, locks and cohort are all bound into `block_id`.
