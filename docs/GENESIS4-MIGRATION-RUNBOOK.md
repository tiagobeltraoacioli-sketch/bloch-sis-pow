<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Genesis-4 migration — the ceremony

> **Completed. This is now a record, not a plan.** Genesis-3 stopped
> permanently at height 39,918 on 2026-08-13 (terminal DAG block count 50,690
> — height and block count are different measurements in a DAG). **Genesis-4
> has been live under proof of stake since 21:31:19 UTC on 2026-08-13**: 30 s
> slots, 32 slots per epoch, `COMMITTEE_SIZE` 128, `SLOT_SUBCOMMITTEE_SIZE` 8,
> 64 genesis validators, hybrid ML-DSA-65 ‖ Falcon-1024, Casper justification
> and finalisation **by epoch** (~32 min typical, ~48 min worst case).
> Finality, not confirmation depth, is the settlement rule. Public read RPC:
> <https://posternlabs.com/g4rpc>, version `0.1.0-mainnet`.
>
> The steps below are written in the order they were performed. Where this
> page originally said something was still missing, it now says what is
> actually true today — see "What had to exist before the ceremony could run".

The ordered steps that turned a halted Genesis-3 into a running Genesis-4, with
what was verified at each one and who performed it. Written 2026-08-13 against
measured state, not against a plan; annotated after the launch.

## What "migration" means here, precisely

Three things happen, and confusing them is how a migration goes wrong:

1. **The halt.** Genesis-3 stops at a height every node agrees on. Consensus
   does this; nobody has to be trusted.
2. **The snapshot.** The balance set at that height becomes a signed artifact.
   This is the record of who holds what, and it survives independently of any
   chain running.
3. **The launch.** Genesis-4 starts from a manifest that *carries* that
   snapshot. Without this step the snapshot is a file nobody reads.

All three are done. The halt landed at height 39,918 on 2026-08-13; the
terminal snapshot was taken there; Genesis-4 launched from a manifest carrying
it at 21:31:19 UTC the same day and has been producing and finalising since.

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
2026-08-13 (terminal DAG block count 50,690) and the terminal snapshot was
taken there — 452,726 outputs across 16 addresses, **3,810,744,000 BLOCH
measured on the Genesis-3 side**, set root `7c756ee8…`, file SHA-256
`84ddbbac…`, produced independently on two nodes with byte-identical results.
The constants are re-pinned to it: `INITIAL_ANNUAL_SAT` re-derived by binary
search, year-one inflation 434 bps, concentration 93.94%.

**3,810,744,000 and 18,146,400,000 are the same coins, not two measurements.**
They are the two sides of the ×100/21 redenomination that took total supply
from 21 B to 100 B: 3,810,744,000 × 100 / 21 = 18,146,400,000 exactly, with no
aggregate dust (`SPLIT_NUMERATOR` / `SPLIT_DENOMINATOR`, asserted at compile
time in `tokenomics_v4.rs`). The table above states Genesis-4 units; this
paragraph states the Genesis-3 side of the same set. Nobody was diluted and no
coin was created by the split.

The chain never reached 50,000 — the ceiling planned at the time, later
lowered from 80,000 and never met. This is load-bearing for supply: the coins
between 39,918 and that ceiling were never minted, so there is nothing to burn.
Validator emission is the remainder of a fixed cap, so a smaller carryover
simply leaves more of it unissued.

## What had to exist before the ceremony could run

None of these was optional, and each is verifiable rather than a matter of
judgement. Status as of 2026-08-14, after launch:

| # | piece | how to know it is done | status |
|---|---|---|---|
| 1 | Carryover ingestion | a genesis built from the snapshot commits a state root that differs from one built without it, and the ingested total equals the commitment | **exists** — `Manifest::ingest_carryover`, `crates/bloch-pos-node/src/genesis.rs`; it ran at genesis |
| 2 | `Transfer` moving value | a signed transfer moves an output; an unsigned or wrongly-signed one is refused; a double-spend is refused | **exists** — a real transaction format with inputs and outputs, `crates/bloch-pos-committee/src/transition.rs:242-262` |
| 3 | RPC | `getbalance` on a carried address returns the carried amount | **exists** — JSON-RPC server in `crates/bloch-pos-node/src/rpc.rs`; public read endpoint <https://posternlabs.com/g4rpc>, version `0.1.0-mainnet` |
| 4 | A network a third party can join | a node not operated by the founder can connect, follow and finalise | **does not exist** — see below |

Items 1–3 landed and the chain launched on them. Item 4 did not, and the
reason is specific rather than general.

**The live transport is still `Transport::Devnet`**: a point-to-point TCP full
mesh with a fixed peer list, no discovery and no authentication, which is why a
third party cannot yet join the network (`crates/bloch-pos-node/src/net.rs`,
selected in `main.rs`). This page previously described item 4 as "two nodes on
different hosts form a gossipsub mesh"; **there is no gossipsub mesh and no
libp2p layer on the live chain** — do not describe one as running.

Compounding it, **`Deposit` and `Delegate` are refused at every node's
mempool** (`crates/bloch-pos-node/src/engine.rs:1900-1906`) because bonding is
not yet funded from the UTXO set. So even a third party who could reach the
network could not bond stake and become a validator. All 64 genesis validators
are run by one entity, and until both of those change, that cannot be diluted
by anyone joining.

Also absent, and worth stating rather than discovering: there is **no RocksDB**
(persistence is append-only with deterministic replay), **no slashing-evidence
pipeline**, and **no checkpoint-sync state download**.

## The ceremony, in the order it was performed

Kept in the original T-minus form because that is the order it happened in and
the order a rehearsal would follow. It has already run: T+0 was 2026-08-13,
and the chain has been live since 21:31:19 UTC that day.

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

Genesis-3 reached its terminal height — **39,918**, block count 50,690 — and
stopped, permanently, on 2026-08-13. Every node refused blocks above it; no
coordination was required at the moment itself.

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

Reads the ceremony's **public halves only** — the shipped binary's other
`genesis` command reads keystores, which is exactly what must never leave the
air-gapped machine. (That command is named for the devnet *transport*, not for
the chain: `Transport::Devnet` is what the live mainnet runs on today. The
transport is devnet; the chain is not.) Every column is refused rather than
defaulted: a blank `stake_sat` stops the assembly, because a validator set is
the one artifact nobody can correct after a chain runs from it.

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

This step completed at **21:31:19 UTC on 2026-08-13**, and Genesis-4 has run
since. Justification and finalisation are **by epoch** — 32 slots of 30 s —
so settlement is ~32 minutes typically and ~48 minutes worst case. Anyone
integrating BLOCH waits for finality, not for a confirmation count.

## What the migration does not fix

Stated here because a runbook that only lists successes is a sales document.

- **Concentration.** 93.94% of the carryover is one address —
  17,046,829,380 BLOCH of 18,146,400,000. With the founder allocation that is
  27,046,829,380, or 27.04% of the 100 B cap; the foundation buckets are a
  further 29.00%. Together 56,046,829,380 of the 57,146,400,000 issued at slot
  0, leaving 1,099,570,620 BLOCH — **1.92%** — in third-party hands. The
  genesis-cohort cap tapers the founder's *consensus weight* to one third over
  a year (`genesis_cohort.rs`), which is a real commitment expressed as a
  consensus rule. It does nothing to the holdings.
- **Custody.** No HSM signs ML-DSA-65 ‖ Falcon-1024. Any exchange or custodian
  integrating BLCH holds keys in software or does not hold them. This is a
  consequence of being genuinely post-quantum and it does not go away with a
  new chain.
- **Validator independence.** 64 keys operated by one entity is one operator.
  The Nakamoto coefficient is 1 until third parties run validators, and no
  amount of key-splitting changes that. Today they *cannot*: the live
  transport is a point-to-point TCP full mesh with a fixed peer list, no
  discovery and no authentication, and `Deposit`/`Delegate` are refused at
  every node's mempool. Both must change before this number can move at all.
- **Audit.** No external audit has been completed.
