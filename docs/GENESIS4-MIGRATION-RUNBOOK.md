<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Genesis-4 migration — the ceremony

The ordered steps that turn a halted Genesis-3 into a running Genesis-4, with
what must be verified at each one and who performs it. Written 2026-08-13
against measured state, not against a plan.

## What "migration" means here, precisely

Three things happen, and confusing them is how a migration goes wrong:

1. **The halt.** Genesis-3 stops at a height every node agrees on. Consensus
   does this; nobody has to be trusted.
2. **The snapshot.** The balance set at that height becomes a signed artifact.
   This is the record of who holds what, and it survives independently of any
   chain running.
3. **The launch.** Genesis-4 starts from a manifest that *carries* that
   snapshot. Without this step the snapshot is a file nobody reads.

Steps 1 and 2 are done or nearly done. Step 3 is the one with code missing.

## The allocation table, verified

Computed from the measured ledger, not restated from a draft. Every figure
derives from `crates/bloch-pos-committee/src/tokenomics_v4.rs`.

| bucket | BLOCH | % of supply | at genesis |
|---|---:|---:|---|
| carryover (holders) | 18,146,400,000 | 18.15% | liquid, ordinary balance |
| founder | 10,000,000,000 | 10.00% | vested |
| VC | 10,000,000,000 | 10.00% | 12-month cliff, 24-month linear |
| team | 10,000,000,000 | 10.00% | 18-month cliff, 36-month linear |
| marketing | 4,000,000,000 | 4.00% | 25% liquid, rest over 24 months |
| liquidity | 5,000,000,000 | 5.00% | fully liquid |
| validator emission | 42,853,600,000 | 42.85% | **not** a genesis output — issued over 40 years |
| **total** | **100,000,000,000** | **100.00%** | |

Genesis issues **57,146,400,000 BLOCH** (`GENESIS_ISSUED_SAT` =
5,714,640,000,000,000,000 sat). The remainder is the emission headroom the
cap check works against. `Manifest::check_supply()` refuses a manifest whose
carryover plus allocations does not equal exactly that figure.

The carryover figure is **final**. Genesis-3 stopped at height 39,918 on
2026-08-13 and the terminal snapshot was taken there — 452,726 outputs across
16 addresses, 3,810,744,000 BLOCH, set root `7c756ee8…`, file SHA-256
`84ddbbac…`, produced independently on two nodes with byte-identical results.
The constants are re-pinned to it: `INITIAL_ANNUAL_SAT` re-derived by binary
search, year-one inflation 434 bps, concentration 93.94%.

The chain never reached 50,000. The coins between 39,918 and that ceiling were
never minted, so there is nothing to burn: validator emission is the remainder
of a fixed cap, and a smaller carryover simply leaves more of it unissued.

## What must exist before the ceremony can run

None of these is optional, and each is verifiable rather than a matter of
judgement:

| # | piece | how to know it is done |
|---|---|---|
| 1 | Carryover ingestion | a genesis built from the snapshot commits a state root that differs from one built without it, and the ingested total equals the commitment |
| 2 | `Transfer` moving value | a signed transfer moves an output; an unsigned or wrongly-signed one is refused; a double-spend is refused |
| 3 | RPC | `getbalance` on a carried address returns the carried amount |
| 4 | Production network | two nodes on different hosts form a gossipsub mesh and finalise |

Items 1–4 are in flight. Until 1 and 2 land, a launched Genesis-4 has balances
that exist in the state root but that nobody can move — and until 1 lands, it
has no balances at all.

## The ceremony, in order

### T−2 weeks — keys

**Performed by the founder, air-gapped. Not by an agent, not on a networked
machine.** `docs/specs/BLOCH-GENESIS-KEYS.md` rule zero.

- 64 validator keypairs (hybrid ML-DSA-65 ‖ Falcon-1024, 3,745-byte public
  key) and 64 RANDAO seeds.
- Only the **public halves** leave the machine: index, `stake_sat` (≥ 25,000
  BLOCH), 32-byte RANDAO commitment `c_0`, public key, withdrawal
  credentials, `commission_bps`.
- Timing is not ceremony: validator keys sign every slot, so they cannot be
  cold, and every week they exist before launch is a week of exposure.

Rehearse the whole ceremony first with throwaway keys. Throwaway keys are
worth nothing, so nothing is lost if the rehearsal leaks.

### T−0 — the halt

Genesis-3 reaches its terminal height and stops. Every node refuses blocks
above it; no coordination is required at the moment itself.

**Verify:** three independent nodes report the same tip at the terminal
height. Not one node — agreement is the evidence.

### T+0 — the snapshot

Run `bloch-snapshot-utxo --data-dir <datadir>/db --out balances.tsv` on an
archival node. It opens read-only.

**Verify — and this is the step most likely to be done badly:** at least two
independently operated nodes produce a snapshot at the same height and their
SHAKE-256 roots match. A snapshot is a trust anchor, not a proof; one tool's
output agreeing with itself proves nothing.

Record: height, block_count, UTXO count, total satoshis, SHAKE-256 root,
SHA-256 of the file. All six. The height and the block_count are different
numbers in a DAG and confusing them has already cost one wrong measurement
(the tokenomics doc said "height 43,172" for what was a block_count).

### T+0 — re-pin the tokenomics

Update `CARRYOVER_TOTAL_BLOCH` to the measured total, re-derive
`INITIAL_ANNUAL_SAT` by binary search against the new remainder, and re-measure
`LARGEST_CARRYOVER_ADDRESS_BLOCH` **from the same snapshot**.

Both figures from one snapshot, always. Updating the total while leaving the
largest-address figure at an older reading reports a concentration change that
is an artifact of mixing measurements, not a change in who holds what.

**Verify:** `cargo test -p bloch-pos-committee` passes. Four compile-time
assertions guard this; if any fires, the arithmetic moved and someone must
decide, not silence it.

### T+0 — assemble the manifest

    bloch-pos genesis-mainnet --cohort out/cohort.tsv --out mainnet.manifest

Reads the ceremony's **public halves only** — the devnet `genesis` command
reads keystores, which is exactly what must never leave the air-gapped
machine. Every column is refused rather than defaulted: a blank `stake_sat`
stops the assembly, because a validator set is the one artifact nobody can
correct after a chain runs from it.


Inputs: the snapshot commitment (digest, count, total), the 64 validators'
public halves, the allocation table above, `genesis_time_ms`, `slot_ms` =
30,000, the genesis cohort indices.

**Verify:** `Manifest::check_supply()` passes; the manifest digest is recorded
and published; two independent builds of the manifest from the same inputs
produce byte-identical files.

### T+0 — launch

Every validator boots with the same manifest digest pinned in its data
directory. A node whose manifest digest differs refuses to start — that is the
mechanism working, not a fault.

**Verify:** first block produced; first epoch justified; first epoch finalised;
all nodes agreeing on one state root at a settled slot. Finality is the
acceptance test, not block production — a chain that produces and never
finalises is not running.

## What the migration does not fix

Stated here because a runbook that only lists successes is a sales document.

- **Concentration.** 93.93% of the carryover is one address. The
  genesis-cohort cap tapers the founder's *consensus weight* to one third over
  a year (`genesis_cohort.rs`), which is a real commitment expressed as a
  consensus rule. It does nothing to the holdings.
- **Custody.** No HSM signs ML-DSA-65 ‖ Falcon-1024. Any exchange or custodian
  integrating BLCH holds keys in software or does not hold them. This is a
  consequence of being genuinely post-quantum and it does not go away with a
  new chain.
- **Validator independence.** 64 keys operated by one entity is one operator.
  The Nakamoto coefficient is 1 until third parties run validators, and no
  amount of key-splitting changes that.
