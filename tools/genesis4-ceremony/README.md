<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Genesis-4 ceremony

Assembles the Genesis-4 genesis block from the signed carryover artifact:
the canonical allocation document (every opening output with its unlock
schedule), the `BlockHeaderV4` for slot 0, and the `block_id`.

Spec: `docs/specs/BLOCH-TOKENOMICS-V4.md` (§1 allocations, §3 cap, §3.2.2
artifact-is-canonical, §7 vesting, §8.2 consensus-enforced locks) and
`docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §5.3–§5.5.

## Why Rust, when `build_carryover.py` is Python

The carryover builder *filters an external snapshot* — Python was the right
tool, and restating `SAT_PER_BLOCH` and the cap there is a tolerable
duplication for a filter. The ceremony *constructs the consensus object
itself*, and that changes the calculus:

1. **No restated numbers.** This crate imports every constant and every
   vesting curve from `crates/bloch-pos-committee/src/tokenomics_v4.rs` — the
   crate whose compile-time assertions pin the 100 B total and the §8.1 u64
   hazard. A Python ceremony would be a second copy of the tokenomics that
   could drift from the one consensus compiles in.
2. **Slot-exact arithmetic.** Unlock schedules use truncating integer
   division. The tests assert the schedule carried in the genesis agrees with
   `founder_vested_sat` & co. at every boundary slot — provable only when both
   sides run the same `u128` arithmetic.
3. **Same hashing conventions.** SHA3-256/SHAKE-256 with the 16-byte
   `BLCH4:` domain tags from `params.rs`, the same crate the node-side
   verifier will use.

Cross-language continuity is pinned, not assumed: a known-answer test asserts
the Rust SHAKE-256 of a carryover file equals what CPython's
`hashlib.shake_256` (i.e. `build_carryover.py`) publishes.

Workspace posture: standalone crate with its own `[workspace]`, exactly like
`bloch-pos-committee` — not a member of the node workspace, cannot touch the
live validation path.

## What the genesis contains

| Output | BLCH | Schedule (consensus-enforced) |
|---|---:|---|
| Founder | 17,000,000,000 | 24-month cliff, 120-month linear |
| VC | 10,000,000,000 | 12-month cliff, 24-month linear |
| Team | 10,000,000,000 | 18-month cliff, 36-month linear |
| Marketing | 4,000,000,000 | 25% at genesis, 24-month linear |
| Liquidity | 5,000,000,000 | fully liquid |
| Carryover holders | ≤ 300,000,000 | fully liquid, from the signed artifact |

Plus, recorded so the accounting closes to **exactly** 100,000,000,000 BLCH:
the validator emission (53.7 B over 40 years) and the unissued remainder of
the 300 M cap (issued to nobody). Each output's schedule is part of its leaf
hash, so `state_root` — and therefore `block_id` — commits to the locks: a
genesis without them is a visibly different chain, not a broken promise
(§8.2's standard).

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
#    digest (from the halt announcement — not recomputed from the same file).
gunzip -k genesis4-carryover.tsv.gz   # ceremony reads plain bytes only

# 1. assemble
cargo run --release -- \
    --carryover genesis4-carryover.tsv \
    --carryover-shake256 <published 64-hex digest> \
    --founder <addr40> --vc <addr40> --team <addr40> \
    --marketing <addr40> --liquidity <addr40> \
    --out genesis4

# outputs:
#   genesis4.tsv           canonical allocation document
#   genesis4.tsv.shake256  its SHAKE-256
#   genesis4.header.bin    canonical BlockHeaderV4 (304 B, little-endian)
# printed: state_root and block_id

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
  entropy is pinned to the record.
- Checkpoint roots, `body_root`, `attestation_root`, `coherence_root` are
  all-zeros: genesis is its own finalized checkpoint, the body is empty, the
  shielded pool starts empty.

## Tests

```bash
cargo test
```

Seventeen tests covering: the sum of allocations is exactly
100,000,000,000 BLCH (under-cap and at-cap); no lock absent (founder/VC/team
have cliff + linear and nothing liquid at genesis, marketing exactly 25% TGE,
liquidity and holders liquid); slot-exact agreement between the carried
schedules and the `tokenomics_v4` closed forms; the carryover digest KAT
against CPython; refusal on digest mismatch, tampered artifacts, over-cap
artifacts, non-canonical encodings, and bucket-address collisions; and that
both the digest and the locks are bound into `block_id`.
