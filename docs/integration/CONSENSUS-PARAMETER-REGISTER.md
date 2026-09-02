<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch Genesis-4 — consensus parameter register

**Status:** authoritative. **Enforced by:** `crates/bloch-pos-node/tests/consensus_parameter_register.rs`.
**Audience:** exchanges, custodians, block explorers, wallet and bridge integrators.

> **Not for the website.** This file and `CONSENSUS-CHANGE-NOTICES.md` are
> delivered to integrators directly, as files. They are not published to
> posternlabs.com, blochprotocol.io, or as a shared artifact.

---

## 0. Why this file exists

On 2026-08-22 the block payload cap doubled from 262,144 to 524,288 bytes at
epoch 800. Nobody was told. An exchange discovered it by observing the chain,
and dated it 21 August — a day early, because the only way to find the
activation was to reverse-engineer it from block contents.

They also got the mechanism right, and it is the reason this is not a
cosmetic problem:

> *Conservation is an equality, so a stale fee assumption is a hard rejection
> rather than a slow confirm.*

`Transition::apply_transfer` requires `sum(inputs) == sum(outputs) + fee`
exactly. An integrator holding a stale parameter does not get a degraded
experience — slower confirmations, a retry that eventually lands. They get a
transaction that **can never be valid at any point in the future**, and no
amount of waiting or rebroadcasting fixes it. That is why the lead time on a
notice has to be measured in days, not hours.

And at epoch 800 **both halves moved**. The cap went 262,144 → 524,288 and the
EIP-1559 byte target went 131,072 → 262,144, because they are one switch.
A planner that learned the new cap and kept the old target prices a legal
300 KiB block as 2.3× over target and pushes its own bid up on a block that is
not congested at all.

## 1. The three states, and why two is not enough

A parameter is not simply "on" or "off". Reading only the value is how the
2.3× misprice happens one layer down.

| State | How it looks in source | What it means to you |
|---|---|---|
| **LIVE** | finite value, no gate, or gate ≤ current epoch | in force now |
| **ARMED** | finite gate epoch, in the future | in force on a known date |
| **INERT (by value)** | the gate constant is `u64::MAX` | shipped in every binary, changes nothing |
| **INERT (by gate)** | finite, ordinary-looking value — but the rule that reads it is behind a gate at `u64::MAX` | **the trap.** The constant reads as live and is not. |

`INACTIVITY_LEAK_RECOVERY_QUOTIENT = 16` and `MIN_QUORUM_DENOMINATOR_NUM/DEN
= 1/2` are the standing examples of INERT (by gate): three perfectly ordinary
finite numbers, none of which affect a single block today, because
`LEAK_RECOVERY_ACTIVATION_EPOCH` is `u64::MAX`. Do not read a value without
reading its gate.

**The current epoch as of this revision: 1726** (height 34,359, slot 55,255;
read from both archival nodes, 2026-09-01).

## 2. Epoch ↔ wall clock

Genesis-4 slot 0 is **2026-08-13 21:31:40 UTC**. Slots are 30 s, epochs are
32 slots (16 min). So:

```
unix(epoch E) = 1786656700 + E * 32 * 30
```

| Epoch | UTC |
|---|---|
| 800 | 2026-08-22 18:51:40 |
| 1400 | 2026-08-29 10:51:40 |
| 1726 (now) | 2026-09-01 05:39:40 |

This is an *estimate* for any future epoch: it assumes every slot produces a
block, and Genesis-4 does not. Measured cadence has run well below one block
per slot. **A future epoch arrives later than this formula says, never
earlier** — treat it as the earliest possible moment, and take the activation
epoch, not the date, as the authority.

---

## 3. Consensus constants — `bloch-pos-committee/src/params.rs`

<!-- MACHINE-TABLE: params -->

| Constant | Source expression | Value | Gate | State | Notice |
|---|---|---|---|---|---|
| `COMMITTEE_SIZE` | `128` | `128` | — | LIVE | N-000 |
| `SLOT_SUBCOMMITTEE_SIZE` | `8` | `8` | — | LIVE | N-000 |
| `SLOTS_PER_EPOCH` | `32` | `32` | — | LIVE | N-000 |
| `SLOT_DURATION_SECS` | `30` | `30` | — | LIVE | N-000 |
| `MAX_DRAWS_PER_SLOT` | `4096` | `4096` | — | LIVE | N-000 |
| `RANDAO_CHAIN_LENGTH` | `8_192` | `8192` | — | LIVE | N-000 |
| `INACTIVITY_LEAK_THRESHOLD_EPOCHS` | `4` | `4` | — | LIVE | N-000 |
| `INACTIVITY_LEAK_QUOTIENT` | `64` | `64` | — | LIVE | N-000 |
| `INACTIVITY_LEAK_RECOVERY_QUOTIENT` | `16` | `16` | `LEAK_RECOVERY_ACTIVATION_EPOCH` | INERT-BY-GATE | N-000 |
| `MIN_QUORUM_DENOMINATOR_NUM` | `1` | `1` | `LEAK_RECOVERY_ACTIVATION_EPOCH` | INERT-BY-GATE | N-000 |
| `MIN_QUORUM_DENOMINATOR_DEN` | `2` | `2` | `LEAK_RECOVERY_ACTIVATION_EPOCH` | INERT-BY-GATE | N-000 |
| `LEAKED_ROSTER_ACTIVATION_EPOCH` | `1400` | `1400` | self | LIVE | N-003 |
| `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH` | `800` | `800` | self | LIVE | N-002 |
| `BLOCK_BYTES_V2_ACTIVATION_EPOCH` | `800` | `800` | self | LIVE | N-001 |
| `ANCESTRY_SEED_ACTIVATION_EPOCH` | `u64::MAX` | `18446744073709551615` | self | INERT | N-000 |
| `LEAK_RECOVERY_ACTIVATION_EPOCH` | `u64::MAX` | `18446744073709551615` | self | INERT | N-000 |

<!-- END-MACHINE-TABLE -->

**What binds you.** `SLOT_DURATION_SECS` and `SLOTS_PER_EPOCH` set the
wall-clock formula above. `COMMITTEE_SIZE` and `SLOT_SUBCOMMITTEE_SIZE` bound
attestation volume, which is budgeted *outside* the payload cap — a full
block is payload + attestations, and only the payload half is capped by
`MAX_BLOCK_TX_BYTES`. The three `INERT-BY-GATE` rows change nothing today and
will change finality behaviour the day `LEAK_RECOVERY_ACTIVATION_EPOCH` is
armed; that is a notice you will receive.

---

## 4. Capacity and fee market — `bloch-pos-committee/src/fee_market.rs`

<!-- MACHINE-TABLE: fee_market -->

| Constant | Source expression | Value | Gate | State | Notice |
|---|---|---|---|---|---|
| `MAX_BLOCK_TX_BYTES` | `262_144` | `262144` | `BLOCK_BYTES_V2_ACTIVATION_EPOCH` | SUPERSEDED | N-001 |
| `BLOCK_TX_BYTES_TARGET` | `MAX_BLOCK_TX_BYTES / 2` | `131072` | `BLOCK_BYTES_V2_ACTIVATION_EPOCH` | SUPERSEDED | N-001 |
| `MAX_BLOCK_TX_BYTES_V2` | `524_288` | `524288` | `BLOCK_BYTES_V2_ACTIVATION_EPOCH` | LIVE | N-001 |
| `BLOCK_TX_BYTES_TARGET_V2` | `MAX_BLOCK_TX_BYTES_V2 / 2` | `262144` | `BLOCK_BYTES_V2_ACTIVATION_EPOCH` | LIVE | N-001 |
| `BLOCK_GAS_LIMIT` | `60_000_000` | `60000000` | — | LIVE | N-000 |
| `BLOCK_GAS_TARGET` | `BLOCK_GAS_LIMIT / 2` | `30000000` | — | LIVE | N-000 |
| `GAS_PER_BYTE` | `16` | `16` | — | LIVE | N-000 |
| `TX_FLAT_GAS` | `5_000` | `5000` | — | LIVE | N-000 |
| `HYBRID_SIG_BYTES` | `4_589` | `4589` | — | LIVE | N-000 |
| `HYBRID_VERIFY_INSTRUCTIONS` | `7_274_849` | `7274849` | — | LIVE | N-000 |
| `INSTRUCTIONS_PER_GAS` | `100` | `100` | — | LIVE | N-000 |
| `HYBRID_VERIFY_GAS` | `HYBRID_VERIFY_INSTRUCTIONS / INSTRUCTIONS_PER_GAS` | `72748` | — | LIVE | N-000 |
| `SECP256K1_VERIFY_GAS` | `3_000` | `3000` | — | LIVE | N-000 |
| `SHIELDED_VERIFY_GAS_PROVISIONAL` | `25 * HYBRID_VERIFY_GAS` | `1818700` | — | INERT | N-000 |
| `MILLISAT_PER_SAT` | `1_000` | `1000` | — | LIVE | N-000 |
| `MIN_BASE_FEE_MILLISAT_PER_GAS` | `10` | `10` | — | LIVE | N-000 |
| `MAX_BASE_FEE_MILLISAT_PER_GAS` | `TOTAL_SUPPLY_SAT * MILLISAT_PER_SAT` | `10000000000000000000000` | — | LIVE | N-000 |
| `BASE_FEE_CHANGE_DENOMINATOR` | `8` | `8` | — | LIVE | N-000 |

<!-- END-MACHINE-TABLE -->

### 4.1 How to price a transfer, and what breaks if you get it wrong

```
intrinsic_gas = TX_FLAT_GAS + tx_bytes * GAS_PER_BYTE + verify_gas(class)
fee_sat       = ceil(intrinsic_gas * (base_fee + tip) / MILLISAT_PER_SAT)
```

and then, **as an exact equality**:

```
sum(input values) == sum(output values) + fee_sat
```

Underpay and the transfer is rejected. Overpay and it is *also* rejected —
conservation is an equality, not a floor. There is no "leave the change as a
tip" path: the difference must be an explicit output.

Read `base_fee` from `getchaininfo` per block. Do not cache it, and do not
compute it yourself from the previous block unless you also gate
`block_tx_bytes_target` on the epoch — that is exactly the 2.3× error.

**The base fee is currently pinned at the floor** (`10` msat/gas, both
archival nodes, 2026-09-01) and has been since genesis: mempool depth has not
approached target. It will not stay there, and code that has only ever been
exercised against a floor value is code that has never been tested.

### 4.2 The pairing rule

`MAX_BLOCK_TX_BYTES_V2` and `BLOCK_TX_BYTES_TARGET_V2` are **one switch**.
They activate at the same epoch, from the same constant, and
`fee_market::tests::the_cap_and_the_target_are_one_switch_not_two` fails if
they are ever separated. Any notice that moves one moves the other; if you
receive a notice that appears to move only the cap, it is wrong — ask.

---

## 5. Validator economics — `staking.rs`, `slashing.rs`, `rewards.rs`

These bind anyone who stakes, delegates, or credits a customer's staking
rewards. They are consensus constants, not policy: a deposit below
`MIN_DEPOSIT_SAT` is rejected, not queued.

<!-- MACHINE-TABLE: staking -->

| Constant | Module | Source expression | Value | State | Notice |
|---|---|---|---|---|---|
| `SUITE_MLDSA65_FALCON1024` | `staking` | `0x0001` | `1` | LIVE | N-000 |
| `MLDSA65_PK_BYTES` | `staking` | `1952` | `1952` | LIVE | N-000 |
| `FALCON1024_PK_BYTES` | `staking` | `1793` | `1793` | LIVE | N-000 |
| `HYBRID_PK_BYTES` | `staking` | `MLDSA65_PK_BYTES + FALCON1024_PK_BYTES` | `3745` | LIVE | N-000 |
| `MLDSA65_SIG_BYTES` | `staking` | `3309` | `3309` | LIVE | N-000 |
| `MIN_DEPOSIT_SAT` | `staking` | `25_000 * SAT_PER_BLOCH` | `2500000000000` | LIVE | N-000 |
| `ACTIVATION_DELAY_EPOCHS` | `staking` | `8` | `8` | LIVE | N-000 |
| `MAX_ACTIVATIONS_PER_EPOCH` | `staking` | `4` | `4` | LIVE | N-000 |
| `EXIT_DELAY_EPOCHS` | `staking` | `32` | `32` | UNREACHABLE | N-000 |
| `WITHDRAWAL_DELAY_EPOCHS` | `staking` | `2048` | `2048` | UNREACHABLE | N-000 |
| `SLASH_PROPOSER_EQUIV_BPS` | `slashing` | `500` | `500` | LIVE | N-000 |
| `SLASH_SURROUND_VOTE_BPS` | `slashing` | `500` | `500` | LIVE | N-000 |
| `WHISTLEBLOWER_QUOTIENT` | `slashing` | `32` | `32` | LIVE | N-000 |
| `CORRELATION_MULTIPLIER` | `slashing` | `3` | `3` | LIVE | N-000 |
| `CORRELATION_WINDOW_EPOCHS` | `slashing` | `4_096` | `4096` | LIVE | N-000 |
| `BPS` | `rewards` | `10_000` | `10000` | LIVE | N-000 |
| `BASE_FEE_BURN_BPS` | `rewards` | `5_000` | `5000` | LIVE | N-000 |
| `PRIORITY_FEE_PRODUCER_BPS` | `rewards` | `10_000` | `10000` | LIVE | N-000 |
| `MAX_COMMISSION_BPS` | `rewards` | `10_000` | `10000` | LIVE | N-000 |
| `MIN_DELEGATION_SAT` | `rewards` | `10 * SAT_PER_BLOCH` | `1000000000` | LIVE | N-000 |

<!-- END-MACHINE-TABLE -->

**`EXIT_DELAY_EPOCHS` and `WITHDRAWAL_DELAY_EPOCHS` are marked UNREACHABLE and
this is the single most important row in this file for a custodian.** Both
constants exist, both have sensible finite values, and **neither is reachable
by any production code path.** `apply_exit` has no production caller; the only
writer of `exit_epoch` is the slashing path. A deposit enters the validator set
and cannot voluntarily leave it — not after 32 epochs, not after 2048, not
ever, in this build.

This is not a gated future feature waiting on an activation epoch. There is no
`SIGNED_EXIT` or `EXIT_CHURN` constant to arm, because there is no exit
mechanism behind one. **If you are modelling staked BLCH as withdrawable on a
2048-epoch (≈22.8 day) horizon, that model is wrong.** It will not become right
by waiting.

`BASE_FEE_BURN_BPS = 5000` means half the base fee is burned and half accrues
to the producer; `PRIORITY_FEE_PRODUCER_BPS = 10000` means the entire tip goes
to the producer. Both matter for supply accounting.

---

## 6. Domain-separation tags — `params.rs`

Fixed 16 bytes, right-padded with `\0`, so no tag is a prefix of another.
These enter signing roots. A change here invalidates every signature you can
produce.

<!-- MACHINE-TABLE: ds_tags -->

| Constant | Source expression | Notice |
|---|---|---|
| `DS_SORTITION` | `*b"BLCH4:SORTIT\0\0\0\0"` | N-000 |
| `DS_ATTEST` | `*b"BLCH4:ATTEST\0\0\0\0"` | N-000 |
| `DS_BLOCK` | `*b"BLCH4:BLOCK\0\0\0\0\0"` | N-000 |
| `DS_BODY` | `*b"BLCH4:BODY\0\0\0\0\0\0"` | N-000 |
| `DS_STATE` | `*b"BLCH4:STATE\0\0\0\0\0"` | N-000 |
| `DS_RANDAO` | `*b"BLCH4:RANDAO\0\0\0\0"` | N-000 |
| `DS_DEPOSIT` | `*b"BLCH4:DEPOSIT\0\0\0"` | N-000 |
| `DS_SPEND` | `*b"BLCH4:SPEND\0\0\0\0\0"` | N-000 |
| `DS_TXID` | `*b"BLCH4:TXID\0\0\0\0\0\0"` | N-000 |
| `DS_SLASH` | `*b"BLCH4:SLASH\0\0\0\0\0"` | N-000 |
| `DS_PROPOSE` | `*b"BLCH4:PROPOSE\0\0\0"` | N-000 |
| `DS_EXIT` | `*b"BLCH4:EXIT\0\0\0\0\0\0"` | N-000 |
| `DS_WSCKPT` | `*b"BLCH4:WSCKPT\0\0\0\0"` | N-000 |
| `DS_COHERENCE` | `*b"BLCH4:COHERE\0\0\0\0"` | N-000 |

<!-- END-MACHINE-TABLE -->

`DS_SPEND` is the one an integrator signs against: it is the transfer signing
root. `DS_TXID` determines the txid you index by.

---

## 7. Transaction wire tags — `bloch-pos-committee/src/transition.rs`

The first byte of `PosTransaction::canonical_bytes`. Unknown tags are a decode
failure (`TxDecodeError::UnknownTag`), never a skip.

<!-- MACHINE-TABLE: wire_tags -->

| Tag | Variant | Decodes | Notice |
|---|---|---|---|
| `0x01` | `Transfer` | yes | N-000 |
| `0x02` | `Deposit` | yes | N-000 |
| `0x03` | `Exit` | yes | N-000 |
| `0x04` | `Delegate` | yes | N-000 |
| `0x05` | `Evidence` | no | N-000 |
| `0x06` | `TransferV2` | yes | N-002 |

<!-- END-MACHINE-TABLE -->

**`0x05` is asymmetric and this is deliberate.** `canonical_bytes` emits it;
`decode` returns `TxDecodeError::EvidenceNotDecodable` rather than a
transaction. Do not build a round-trip test that assumes encode/decode are
inverse across all six tags — five of six is the actual contract.

**`0x06` has been live since epoch 800.** It is not a replacement: `0x01`
stays valid forever and you may keep emitting it. `0x06` deduplicates
witnesses — one `(pubkey, signature)` per *owner* rather than per *input*, and
40-byte inputs that index into that table. A 30-input single-owner
consolidation goes from ~256,800 B to ~9,700 B. If you consolidate, this is
worth adopting; if you do not, you may ignore it, but **your decoder must not
choke on `0x06` in a block you are indexing.** That is the one thing epoch 800
made mandatory for a passive integrator, and it was never announced.

---

## 8. Network frame tags — `bloch-pos-node/src/net.rs`

Only relevant if you run a node and speak the devnet TCP transport directly.
Wire: `u32 LE frame length ‖ type byte ‖ payload`.

<!-- MACHINE-TABLE: frame_tags -->

| Constant | Value | Notice |
|---|---|---|
| `FRAME_BLOCK` | `0x01` | N-000 |
| `FRAME_ATT` | `0x02` | N-000 |
| `FRAME_GET_BLOCKS` | `0x03` | N-000 |
| `FRAME_TX` | `0x04` | N-000 |

<!-- END-MACHINE-TABLE -->

Two defects here are worth stating because they are the reason this table is
machine-checked rather than described:

- The module doc in `net.rs` lists only `0x01`, `0x02` and `0x03`. **`FRAME_TX
  = 0x04` has been missing from that prose since it was added.** The register
  is now the authority; the prose is not.
- Every dispatch on these bytes is a `match` on a plain `u8` with a `_ =>`
  catch-all, so the compiler cannot detect a tag that is defined and never
  routed, nor two constants given the same value. It is not an enum, and the
  exhaustiveness that an enum would buy is not present. `SYNC_TAG_GET_BLOCKS`
  and `SYNC_TAG_BLOCKS` in `p2p.rs` are **both `0x01`** today — benign, because
  they are decoded in two disjoint namespaces, but it is benign by accident
  and nothing checks it.

---

## 9. RPC surface — `bloch-pos-node/src/rpc.rs`

JSON-RPC 2.0, HTTP POST, positional array params. Anything not listed returns
`method not found`.

<!-- MACHINE-TABLE: rpc -->

| Method | Behaviour | Notice |
|---|---|---|
| `getchaininfo` | serves | N-000 |
| `getblockcount` | serves | N-000 |
| `getblockbyslot` | serves | N-000 |
| `getblockbyid` | serves | N-000 |
| `getvalidator` | serves | N-000 |
| `getvalidatorcount` | serves | N-000 |
| `getbalance` | serves | N-000 |
| `gettransaction` | refuses | N-000 |
| `getnewaddress` | refuses | N-000 |
| `gettxout` | serves | N-000 |
| `getutxos` | serves | N-000 |
| `listunspent` | serves | N-000 |
| `sendrawtransaction` | serves | N-000 |
| `getmempoolinfo` | serves | N-000 |

<!-- END-MACHINE-TABLE -->

`getutxos` and `listunspent` are the same handler under two names.

**The two refusals are load-bearing.** `gettransaction` and `getnewaddress`
exist, answer, and explain why they cannot serve — rather than falling through
to `method not found`, which would send you looking for a newer build that
does not exist. There is **no transaction index** on this chain: you cannot
look a transfer up by id. Track outputs by `(txid, vout)` through `gettxout`
and `listunspent`, and reconcile balances with `getbalance` against a
`script_hash` (the 20 bytes after `bloch1q`, zero-padded to 32).

There is no notification/subscription transport — no WebSocket, no long poll.
Poll `getchaininfo` and compare `finalized`.

---

## 9.1 RPC error codes — `bloch-pos-node/src/rpc.rs`

An error code is part of the contract. A client that branches on `-32003`
("retry later, not invalid") and receives a code it does not know has to guess.

<!-- MACHINE-TABLE: rpc_errors -->

| Constant | Code | Notice |
|---|---|---|
| `BLOCK_NOT_FOUND` | `-32000` | N-000 |
| `VALIDATOR_NOT_FOUND` | `-32001` | N-000 |
| `TX_DECODE_FAILED` | `-32002` | N-000 |
| `MEMPOOL_FULL` | `-32003` | N-000 |
| `NODE_UNAVAILABLE` | `-32004` | N-000 |
| `NO_TRANSACTION_INDEX` | `-32005` | N-000 |
| `NO_WALLET` | `-32006` | N-000 |
| `SLOT_EMPTY` | `-32007` | N-000 |
| `TX_REFUSED` | `-32008` | N-007 |

<!-- END-MACHINE-TABLE -->

`-32008` was added on 2026-08-22 and never announced — see notice N-007. The
prose table in `rpc.rs` itself still documents only `-32000` through `-32007`,
which is the same rot as the missing `FRAME_TX` above and the reason this
register is machine-checked.

`SLOT_EMPTY` is normal under PoS, not an error condition: Genesis-4 does not
produce a block in every slot. Treat it as "advance to the next slot", never as
a node fault.

---

## 10. What does NOT exist

A negative inventory, because "not found" and "not armed" are different
answers and only one of them is safe to plan around.

| Identifier | Status |
|---|---|
| `SLASHING_EVIDENCE_ACTIVATION_EPOCH` | **does not exist anywhere in the tree** |
| `WITHDRAWAL_*` activation constant | does not exist |
| `FUNDED_STAKING_*` activation constant | does not exist |
| `SIGNED_EXIT_*` activation constant | does not exist |
| `FINALITY_LATCH_*` activation constant | does not exist |
| `FORKCHOICE_SET_DETERMINED_*` activation constant | does not exist |
| `EXIT_CHURN_*` activation constant | does not exist |
| `VESTING_LOCK_*` activation constant | does not exist |
| `ANCESTRY_SEED_ACTIVATION_EPOCH` | exists, `u64::MAX`, INERT |
| `LEAK_RECOVERY_ACTIVATION_EPOCH` | exists, `u64::MAX`, INERT |

A searched-for constant that turns up nothing means the feature has **no gate
at all** — so it either does not exist, or it is unconditional, and those
demand opposite responses. Two cases in this tree matter to an integrator:

- **Vesting is not enforced.** `crates/bloch-pos-node/src/genesis.rs` has no
  vesting lock in the spend path; `vesting_is_not_enforced` (same file) pins
  that as a fact rather than leaving it as an assumption. Genesis allocations
  described as vested are spendable. There is no `VESTING_LOCK` constant to
  arm because there is no mechanism behind it.
- **Voluntary exit does not exist.** A deposit enters and cannot leave:
  `apply_exit` has no production caller, and the only writer of `exit_epoch`
  is slashing. There is no `SIGNED_EXIT` or `EXIT_CHURN` gate because there is
  no exit path to gate.

Both are honest limitations of the current build, not scheduled features.
Neither will produce an activation notice, because neither has anything to
activate. If you are modelling stake as withdrawable, it is not.

`ANCESTRY_SEED_ACTIVATION_EPOCH` deserves one more line: the F6 seed
look-ahead it once gated is now **unconditional** — the gate was removed from
the code path on 2026-08-24, and the constant that remains is a stub with no
reader. Its `u64::MAX` does not mean "the seed rule is off".

---

## 11. How this file is enforced

`crates/bloch-pos-node/tests/consensus_parameter_register.rs` reads the source
of `params.rs`, `fee_market.rs`, `staking.rs`, `slashing.rs`, `rewards.rs`,
`transition.rs`, `net.rs` and `rpc.rs`, extracts every constant, wire tag, RPC
method and error code, and compares against the tables above **in both
directions**:

- a name in the source with no row here → **red**, naming the constant
- a row here with no name in the source → **red**, naming the row
- a value that differs from the linked constant → **red**, printing old and new
- a state of `LIVE` or `ARMED` whose `Notice` column is `N-000` → **red**
- a `Notice` id with no entry in `CONSENSUS-CHANGE-NOTICES.md` → **red**

`N-000` is the sentinel for "pre-dates the register, no notice was issued". It
is accepted only on rows that are INERT, SUPERSEDED, or part of the genesis
surface. **Arming a gate forces a notice id**, and that id must resolve to a
real notice — which is the mechanism that makes an unannounced parameter
change fail the build rather than merely violate a convention.

This follows the rule already written into
`crates/bloch-pos-node/tests/published_checksums.rs`: *a fact the build system
can check must never live only in a file nobody executes.* That test exists
because a published checksum rotted into prose and prose cannot go red. This
one exists for the same reason, one layer up.

**The RPC namespace was not frozen before this.** The nearest existing check,
`rpc/tests.rs::every_method_routes_to_its_request`, drives ten methods through
`call()` and asserts the resulting request — it proves nothing was *removed*
and says nothing about additions, which is the direction `gettxout` and
`TX_REFUSED` went unannounced through. The bidirectional check here is new.

The guard was verified by violating it: a constant was added to `fee_market.rs`
and `LEAK_RECOVERY_ACTIVATION_EPOCH` was moved off `u64::MAX` in a scratch
edit. Four tests went red naming exactly what changed, including
`INACTIVITY_LEAK_RECOVERY_QUOTIENT` — a constant nobody had touched, caught
because its *gate* had moved. Repairing the register to match the source
silenced the text and value checks and left the notice requirement standing.
The edits were reverted; both gates remain at `u64::MAX`.

**Last verified against the live chain:** 2026-09-01, epoch 1726, from
archival nodes `139.180.166.5:8080` and `139.180.173.231:8080` (both agreeing).
