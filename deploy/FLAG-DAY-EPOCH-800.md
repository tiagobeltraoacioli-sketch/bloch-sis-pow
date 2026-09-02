<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Flag day — epoch 800

**If you run a Genesis-4 node, you must be on `8e0cb15f` (or later) before the
chain reaches epoch 800.** A node below that commit refuses the blocks the rest
of the network accepts from that epoch on, and forks. This is not advisory.

## What activates

Two consensus switches, armed at the **same** epoch on purpose:

| constant | value | effect from epoch 800 |
|---|---|---|
| `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH` | 800 | `TransferV2` (wire tag `0x06`) becomes valid: one `(pubkey, signature)` per **owner** instead of per input, 40-byte inputs, witness table in strictly increasing pubkey order |
| `BLOCK_BYTES_V2_ACTIVATION_EPOCH` | 800 | block payload cap 262,144 → **524,288**, and the EIP-1559 byte target 131,072 → **262,144** with it |

They are one switch, not two. A fleet running two rule sets is a partition, so
`raising_the_block_cap_is_a_flag_day` asserts the two constants are **equal**
rather than asserting either is `u64::MAX` — arming is allowed, arming them
apart is not.

The cap and its EIP-1559 target move together for the same reason: gating the
cap alone would leave the controller reading utilisation as `tx_bytes / 131,072`
under a 524,288 cap, so a 256 KiB block — exactly half full — would read as 2×
over target and push the base fee up forever.

## What it buys

The carryover holds 452,726 outputs of 8,400 BLCH each. Moving a large position
is not one big transaction, it is hundreds of thousands of inputs:

| | inputs/block | BLCH/block |
|---|---|---|
| before (V1, 262 KiB) | 30 | ~1.2 M |
| after, many owners | 30 | ~1.2 M |
| after, **single owner** | **12,880** | **~516 M** |

The entire gain is on single-owner consolidation, because that is the only case
where the witnesses were redundant copies. With distinct owners there is nothing
to deduplicate and the number does not move.

## What is deployed

```
commit   8e0cb15f  (main)  ← merge of the branch the fleet runs, 6a7301ea
image    registry.fly.io/bloch-g4:g4-flagday-6a7301ea
digest   sha256:e29a51487046faa8ccd41773b1749e1f60566adef59cddbc8dd0e6f96bcbbcf5
binary   ELF 64-bit x86-64, built in rust:1-bookworm
tests    504 green
```

The image inherits the previous fleet image and replaces exactly one file, the
node binary — `carryover.tsv`, `mainnet.manifest`, `start.sh`, the base OS and
its libraries are untouched, so the build cannot introduce a difference it did
not intend.

### Fleet, as rolled on 2026-08-22

| where | count | how |
|---|---|---|
| Fly (`bloch-g4`) | 49 | image update, batches of 8 |
| classic boxes | 15 | binary swap, argv preserved from `/proc/PID/cmdline` |
| **total** | **64 of 64** | every registered index alive |

Two lessons are baked into the rollout scripts and should stay there:

- **Never rebuild argv.** `V_INDEX` values are `'2'`, `'03'`, `'04'`, `'5'` —
  inconsistent padding — and a classic node's `--peers` is 64 endpoints on one
  line. Two Fly machines lost `blocks.log` and `validator.key` on 2026-08-21 to
  a reconstructed `V_INDEX`. Read it literally or do not touch it.
- **Do not trust a rollout's own report.** The first pass matched
  `pgrep -x bloch-pos-fixed` and silently skipped two validators running as
  `bloch-pos-new` and `bloch-pos-linux`. They reported "nothing to do" and stayed
  on the old binary. Audit for *any* node process afterwards, by binary hash.

## Fixed during this rollout

- **Key equivocation on two indices.** Validators 16 and 35 were each running on
  two nodes with the **same private key** (`faa75086…`, `90a2d3c9…`, verified by
  hash on both sides), on different heads. That is the exact condition that
  produces conflicting attestations, and it is slashable. The classic copies
  were stopped and their data directories renamed
  `nNN.desativado-equivocacao`.
- **Validator 0 was not running at all.** Its key and chain data were intact;
  it was simply never started.

## Known gaps at the time of writing

- **77% of the validator set is reachable in one direction only.** The Fly app
  has no public IP (`flyctl ips list` is empty), so the 49 machines can dial out
  but nothing outside Fly can dial in. Classic nodes dial 64 endpoints, all
  classic, **zero** Fly. Every Fly↔classic link is Fly-initiated.
- **Classic peer lists are ~80% dead.** They name 5–6 ports per box where 1–2
  processes run.
- **A late node's attestation is `Reject`, not `Ignore`.** A node behind derives
  the committee from its own head, so it attests against a committee its peers
  compute differently and the attestation is discarded rather than held. Every
  restart therefore costs the fleet a window in which most of it cannot
  contribute to finality — and a restart costs ~2 h of replay per node today.
- **Replay is single-threaded.** Measured `loadavg 1.00` on 2 vCPU and 745 MB
  RSS of 8 GB: neither more cores nor more RAM helps. The cost is the state
  root, O(n) over 452,726 eUTXO entries at ~0.8 s/block. `feat/state-snapshot`
  is the branch that removes replay entirely.
