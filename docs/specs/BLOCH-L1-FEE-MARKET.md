<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# BLOCH-L1-FEE-MARKET — one market, one unit, one price

**Status:** proposed 2026-08-11; **wired into consensus 2026-08-12** (§6.1
and §4.4 are no longer integration seams — see §8). Code authority:
`crates/bloch-pos-committee/src/fee_market.rs` (constants and arithmetic),
`crates/bloch-pos-committee/src/rewards.rs` (the fee split, decided
2026-08-11, `BLOCH-TOKENOMICS-V4.md` §6.3.2), and
`crates/bloch-pos-committee/src/tokenomics_v4.rs` (emission). **Every figure
in this document is the value of a named constant or function in those files;
none is normative here.** Where a decision belongs to the founder it is
labelled GATED.

Companion context: `docs/FLEET-BRIEF-2026-08-11.md` (EVM at L1; the
dual-authorisation question), `BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §6.5 and
gate G10 (byte budgets), `COHERENCE-C1.md` (shielded pool).

---

## 1. What a block carries, and what each thing actually costs

A Genesis-4 block can carry three transaction classes, and they consume
three different resources:

| Class | Dominant real cost | Where measured |
|---|---|---|
| eUTXO transfer | One hybrid ML-DSA-65 ‖ Falcon-1024 verification **per input** — `HYBRID_VERIFY_INSTRUCTIONS` = 7,274,849 RV32IM instructions — plus `HYBRID_SIG_BYTES` = 4,589 B of signature on the wire | `spikes/prover-cost/RESULTS.md`; migration spec §6.5 |
| EVM transaction | Computation and state growth, metered per opcode; envelope bytes; one authorisation verify | EVM schedule (adopted, §3.2) |
| Coherence shielded | One FRI-STARK proof verification, and the proof's bytes — "tens to hundreds of KB" | `COHERENCE-C1.md` |

Three costs, and the classical menu is one fee market per class (three
prices), a multidimensional market (one market, several prices), or one
market with one unit.

## 2. Decision: one market, unit = gas

**One fee market. The common unit is gas (`u64`), and every class buys it
through a class-specific cost function** (§3). One price — the base fee —
clears the whole block.

### 2.1 Why one unit, and why that unit is gas and not bytes

The honest observation is that the three classes *mostly contend for the
same resource*: **block bytes under the gossip budget**. The G10 capacity
gate is denominated in bytes; the PQ signature is the largest object in an
eUTXO transaction; the FRI proof is the largest object in a shielded one.
Bytes-as-the-unit was therefore seriously considered — it is the simpler
market and it prices the true bottleneck directly.

It loses to gas on one fact: **EVM at L1 makes computation a first-class
resource that bytes cannot see.** A 200-byte transaction that runs a
10 M-step contract loop costs every validator CPU that a byte price would
give away for free; a byte-only market is an invitation to buy cheap bytes
and spend expensive cycles. Gas is the unit that can express *both* "you
made every node carry 4,589 bytes" (`GAS_PER_BYTE` per byte) and "you made
every node execute this" (opcode/verify charges) in one scalar. Bytes remain
priced — dominantly so (§3.1) — but as a term inside gas, not as the unit.

### 2.2 Why one price and not three markets

- Three class-markets re-price the *same* scarce bytes three ways, and the
  arbitrage lands on the proposer: it would pick whichever class pays more
  per byte, which is a single market with extra steps and worse UX.
- A block is one propagation event. Its scarcity is joint; a price per class
  pretends it is separable.
- The committee crate treats transactions as opaque bytes (`derive.rs` §1.2);
  one market keeps the consensus surface to two caps and one controller
  instead of per-class quota machinery.

### 2.3 The cost of the choice, stated

One price for three cost profiles means **cross-subsidised congestion**: a
surge of EVM demand raises the base fee that a shielded spender pays, even
though the shielded transaction consumes no EVM compute. That is a real
distortion and it is accepted, for now, on three grounds: (a) the shared
byte term *is* most of every class's cost, so the price they share mostly
reflects a resource they genuinely share; (b) the controller (§4.2) already
measures gas and bytes separately, so promoting bytes to an independently
priced dimension later (the EIP-4844 move) is an additive change, not a
redesign; (c) three markets at launch means three thin, manipulable markets
on a chain that will open with modest traffic.

## 3. Costing the three classes

### 3.1 The common terms

Intrinsic gas — owed on inclusion, before any execution, and not refunded on
failed execution (`fee_market::intrinsic_gas`):

```
intrinsic = TX_FLAT_GAS + tx_bytes · GAS_PER_BYTE + verify_gas(class)
```

- `GAS_PER_BYTE` = 16 — Ethereum's non-zero-calldata price, kept because the
  entire EVM ecosystem has internalised it, and because it makes the byte
  term dominate exactly the transactions whose bytes dominate the network: a
  hybrid signature alone prices at `HYBRID_SIG_BYTES · GAS_PER_BYTE` =
  73,424 gas.
- `verify_gas` is anchored to **measured instruction counts** through one
  calibration ratio, `INSTRUCTIONS_PER_GAS` = 100: a hybrid PQ verification
  is `HYBRID_VERIFY_GAS` = 72,748 gas (from the measured 7,274,849
  instructions). One measured number, one ratio, no hand-tuned magic
  constants; recalibrating the whole native schedule is a one-line edit.

### 3.2 Per class

| Class | verify_gas | Execution gas | Notes |
|---|---|---|---|
| eUTXO, n inputs | n · `HYBRID_VERIFY_GAS` | none (transfers) | Bytes + verify are the whole cost |
| EVM from PQ account | `HYBRID_VERIFY_GAS` | **Ethereum's live opcode schedule, adopted 1:1** (1 EVM gas = 1 Bloch gas), with the intrinsic 21,000 and the per-byte calldata terms **zeroed** — flat, bytes and authorisation are already charged by §3.1, and double-charging bytes would silently re-price every deployed contract's calldata assumptions | Contracts and tooling port with familiar economics |
| EVM from secp256k1 account — **GATED** | `SECP256K1_VERIFY_GAS` = 3,000 (the ECRECOVER precedent) | same as above | Priced so the founder's dual-auth options are comparable; existence is not decided here |
| Shielded (C1) | `SHIELDED_VERIFY_GAS_PROVISIONAL` | none | **PROVISIONAL** — see below |

The fee-market face of the dual-authorisation decision, made explicit as the
fleet brief requires: a PQ-account EVM transaction pays `HYBRID_VERIFY_GAS`
vs 3,000 for verification **and** ~4.6 KB vs ~65 B of signature bytes —
authorisation-cost gap ≈ 36×, whole-transaction intrinsic gap ≈ 12×
(pinned by the `intrinsic_gas_prices_the_pq_byte_reality` test). If both
account types are admitted, PQ users pay roughly an order of magnitude more
per transaction *for the security property the chain exists to provide*.
Any subsidy to close that gap (e.g. discounting `GAS_PER_BYTE` for PQ
signatures) is a founder-level economics decision; this design charges true
cost and states the gap rather than hiding it in the schedule.

**Shielded calibration is not done.** `SHIELDED_VERIFY_GAS_PROVISIONAL` is a
placeholder (25 · `HYBRID_VERIFY_GAS`) pending a measurement of the C1
FRI-STARK *verifier* with the same harness that measured the signature
verifiers (`coherence-prover` has it). Activation with this number
unmeasured is forbidden by this spec. Separately, `COHERENCE-C1.md` bounds
proofs only as "tens to hundreds of KB": **if the measured worst-case proof
exceeds `MAX_BLOCK_TX_BYTES` (§5), shielded transactions cannot be included
at all** — the byte cap was sized to make that unlikely (256 KiB), but the
proof-size measurement is a blocking prerequisite, and a conflict is a
founder decision (bigger blocks vs proof recursion), not a silent constant
bump.

## 4. EIP-1559: yes — base fee, tip, and the two eras

### 4.1 Why 1559-shaped

`rewards.rs` already *is* 1559-shaped: the decided fee split
(`BASE_FEE_BURN_BPS`, `PRIORITY_FEE_PRODUCER_BPS`, `split_fees_at`) is
defined over a base fee and a priority fee, so the only open question was
whether the base fee is a protocol-computed price or a first-price auction.
Protocol-computed wins on a 30 s-slot chain: auctions clear by overbidding
and replacement spam, and at 30 s per block the bid-escalation window is an
order of magnitude longer — more wasted bids, worse inclusion estimates,
and a mempool DoS surface priced at zero. A posted price with a ±1/8
per-block controller gives wallets a quotable number and burns the spam
margin instead of gifting it.

### 4.2 The controller — one price over the max of two utilisations

`fee_market::next_base_fee` is EIP-1559's controller with one change:
utilisation is **max(gas axis, byte axis)**, each measured against half its
cap (`BLOCK_GAS_TARGET`, `BLOCK_TX_BYTES_TARGET`), compared by
cross-multiplication in `u128`.

Plain gas-only 1559 mis-prices this chain, and not as a corner case: a block
packed with minimal eUTXO transfers **saturates the byte cap while using
under a sixth of the gas cap** (pinned by `bytes_bind_before_gas_for_eutxo_blocks`).
A gas-only controller reads that byte-saturated block as slack and *lowers*
the price of the exhausted resource. Max-utilisation tracks whichever
resource is scarce; what it gives up — pricing the two axes independently —
is exactly the §2.3 trade, with the same escape path.

Mechanics: ±1/8 max step (`BASE_FEE_CHANGE_DENOMINATOR`), congested blocks
always move the price by ≥ 1, floor `MIN_BASE_FEE_MILLISAT_PER_GAS`
(spam floor, also the genesis value), ceiling
`MAX_BASE_FEE_MILLISAT_PER_GAS` (a non-economic bound that turns the
overflow assertions into proofs). Skipped slots produce no update — the base
fee is a function of parent-committed values only (§5.5 of the migration
spec: no clocks, no node-local state).

The tip (priority fee, millisat/gas, user-set, unbounded) is the ordering
market on top; it is what `split_fees_at` sees as `priority_fee`.

### 4.3 Units and arithmetic

- **Gas:** `u64` per transaction and per block. `BLOCK_GAS_LIMIT` is ~10⁷·6,
  so per-block totals sit 11 orders of magnitude under `u64::MAX`.
- **Price:** `u128`, in **millisatoshi per gas** (10⁻³ sat = 10⁻¹¹ BLCH).
  Why not sat/gas: with `SAT_PER_BLOCH` = 10⁸, a whole-satoshi price near
  the floor cannot express a ±1/8 step — 1 → 2 sat/gas is a 100% jump. Why
  not a finer unit: msat already gives the controller three decimal digits
  below the settlement quantum, and §4.2's ≥ 1 msat step rule keeps every
  step representable.
- **Settlement:** whole satoshis, `fee_parts_sat`, rounded **up** per part —
  truncation would make sub-1000-msat gas free, and free gas at
  attacker-chosen granularity is a DoS gift. The satoshi stays the only
  on-ledger quantum; msat exists in the price, never in a balance.
- **Overflow:** all fee arithmetic `u128`, per the crate rule (the products
  overflow, not the totals). Compile-time assertions in `fee_market.rs` pin:
  byte-cap gas ≤ gas cap; targets are exact halves; `BLOCK_GAS_LIMIT ×
  MAX_BASE_FEE` and the controller's cross-multiplications fit `u128` with
  the supply (`TOTAL_SUPPLY_SAT`, 54.21% of `u64::MAX`) as the anchor; the
  floor ≥ the change denominator.

### 4.4 Where the base fee lives — committed state, not the header

`BlockHeaderV4` (frozen by the single-derivation-path property test) does
not carry a base fee, and this design does not add one. The base fee is
**committed consensus state**: a leaf in the `state_root.rs` SMT under
component tag `TAG_BASE_FEE` (`state_root::BaseFeeRecord`), holding
`(base_fee_millisat_per_gas, gas_used, tx_bytes)` for the block that
committed it. The child block's price is
`CommittedState::next_base_fee()` — one call into `next_base_fee` over the
parent's leaf, used by the producer to price its mempool and by the validator
to charge every included transaction, so there is one expression of the rule.
This keeps the header untouched and satisfies §5.5 derivability.

**Wired 2026-08-12.** The tag is `0x15`, not the `0x09` this document
originally reserved: tags are append-only and the S5.5 bookkeeping extension
had claimed `0x09`–`0x0F` in the meantime.

### 4.5 The burn, and exactly what happens at the era boundary

Nothing new is decided here — the split is `rewards::split_fees_at`, decided
2026-08-11 (`BLOCH-TOKENOMICS-V4.md` §6.3.2):

| Era | Base fee | Priority fee |
|---|---|---|
| `slot < EMISSION_SLOTS` | `BASE_FEE_BURN_BPS` = 5,000 → **half burned**, half to producer | `PRIORITY_FEE_PRODUCER_BPS` = 10,000 → all to producer |
| `slot ≥ EMISSION_SLOTS` | **no burn**, all to producer | all to producer |

One precision against the shorthand "fees burn during emission" in the fleet
brief: the decided rule burns **half of the base fee**, not all fees — the
producer keeps half the base fee plus the whole tip in era 1. This document
follows the code and §6.3.2, and says so rather than silently disagreeing.

So, answering the question as posed: **yes, the base fee stops burning in
era 2 — but the base fee itself does not stop existing.** Congestion control
is needed forever; only the burn destination changes, at exactly
`EMISSION_SLOTS`, the same boundary at which every emission function in
`tokenomics_v4.rs` returns 0. There is never a slot with both issuance and a
burn, nor one with neither revenue source.

### 4.6 Net inflation, with the arithmetic

Measured against total supply, the way the tokenomics measures it
(`annual_inflation_bps`):

- **Era 1 gross:** the recommended decay curve peaks in year 1 at
  `annual_inflation_bps(0)` = **436 bps = 4.36%** (4,367,467,014 BLCH =
  `INITIAL_ANNUAL_SAT`), then 286 bps in year 5, 169 bps in year 10.
- **Era 1 net:** net = gross − burned, and burned ≥ 0 every slot, so
  **net ≤ 4.36% < the 7% target in every year, with 264 bps of margin
  before any burn is even counted**. The target is met by the emission
  curve alone; the burn only widens the margin, and with heavy fee traffic
  net issuance can go negative (deflation) — consistent with the hard cap,
  since burns destroy, never mint.
- **Era 2:** issuance 0, burn 0 → **net inflation exactly 0%** forever.
  Total supply ends at `TOTAL_SUPPLY_BLOCH` minus everything burned in
  era 1 (the cap is a ceiling, not a landing point — §6.3.2's note).

The `net_inflation_stays_under_the_7_percent_target` test pins the three bps
figures and both era properties. (The doc comment in `tokenomics_v4.rs`
carried year-1 figures from the superseded 100 B draft; corrected this wave
and added to `check_stale.py`.)

## 5. DoS: the two caps and the G10 gate — which one commands

Consensus enforces **two independent per-block caps**, and a block is
invalid if it exceeds *either*:

1. `MAX_BLOCK_TX_BYTES` = 262,144 (256 KiB) on transaction payload bytes —
   sized to admit one worst-case C1 proof (§3.2) and ~54 minimal eUTXO
   transfers (~1.8 tx/s; the honest throughput of 4.6 KB signatures on 30 s
   slots).
2. `BLOCK_GAS_LIMIT` = 60,000,000 — 2 M gas/s, the CPU/state backstop, the
   same order as Ethereum's 3 M gas/s.

**When they disagree, the byte cap commands.** It is the cap G10's fleet
measurement stands behind, and the compile-time assertion
`MAX_BLOCK_TX_BYTES · GAS_PER_BYTE ≤ BLOCK_GAS_LIMIT` guarantees the gas
cap can never make the byte cap unreachable — bytes can bind first (and for
signature-heavy traffic always do), gas cannot forbid a byte-legal block on
byte grounds. Attestation bytes are outside both caps: the protocol itself
bounds them (committee sizes, §6.5.3 of the migration spec), and a proposer
neither profits from nor pays for them.

**G10 must be restated before activation.** As written
("54 KB/block average, ≈ 588 KB epoch-boundary burst") G10 covers only the
attestation traffic of §6.5 — the tx payload this fee market admits comes
*on top*. The gate that actually validates this design is:

- worst block ≈ 588 KB + `MAX_BLOCK_TX_BYTES` (256 KiB) ≈ **850 KB**,
  p99 propagation < 5 s;
- sustained average ≈ 54 KB + `BLOCK_TX_BYTES_TARGET` (128 KiB) ≈
  **182 KB/block** for ≥ 14 days, no mesh degradation, no yamux
  stream-limit failures.

Direction of resolution is fixed: **if the fleet cannot sustain that,
`MAX_BLOCK_TX_BYTES` comes down; the gate's pass bar never comes down to
meet the constant.** The launch gate commands the constant, the constant
commands block validity.

Below the caps, admission economics carry the rest: intrinsic gas is owed on
inclusion even when execution fails (§3.1) — you cannot make every node
verify a 72,748-gas signature for free by failing afterwards; mempool
admission requires balance ≥ max fee at the current base fee; and the price
floor keeps zero-cost spam impossible even on an idle chain.

## 6. Proposer revenue, the operator/delegator split, and MEV

### 6.1 Fees flow through the same split as issuance — because of year 40

Does EVM fee revenue change the proposer reward and the operator/delegator
split? **Yes — this design routes the producer's fee share through the same
stake-origin + commission split as issuance**
(`fee_market::distribute_producer_fees`, mirroring `rewards::distribute`
minus the credits scaling: producing the block *is* the performance).

The forcing argument is the era boundary. `rewards::distribute` pays
delegators out of `epoch_issuance`, which is 0 after `EMISSION_SLOTS` —
at which point fees are validators' *entire* revenue. Under the current
`transition.rs` step 11, `FeeSplit::to_producer` is credited raw to the
proposer's own record: delegator revenue would go to exactly **zero at the
moment fees become everything**, and delegation — the mechanism that lets
stake exist without running hardware — would collapse at the fee-only
boundary, forty years into an immutable schedule. Routing fees through the
commission split keeps delegator economics alive in both eras
(`delegation_survives_fee_only_era` pins it).

**Wired 2026-08-12.** `transition.rs`'s epoch boundary applies
`distribute_producer_fees` over the producer's committed stake position:
`self_stake` is the bond, `delegated_stake` comes from
`delegation::Registry::resolve`, and `commission_bps` is a new **committed
registry column** (`state_root::ValidatorRecord::commission_bps`, declared at
deposit and published for the genesis cohort) — a rate read from anywhere but
committed state would make two nodes compound different bonds from the same
block. The delegators' side is split pro-rata by *activated* satoshis
(`fee_market::split_delegator_fees`) into a committed ledger,
`TAG_DELEGATOR_FEE_REWARD` — the earning mirror of the slash-loss ledger, and
a ledger for the same reason: editing delegation records would reshuffle
warm-up history. Truncation dust goes to the operator. Pinned end-to-end by
`transition::tests::producer_fees_reach_delegators_through_the_commission_split`.

### 6.2 MEV: what the design does, and the honest bill for it

A proposer chooses and orders transactions, so a proposer that picks
expensive transactions earns more — and with EVM at L1 this stops being
theoretical: DEX arbitrage, liquidations and sandwiching arrive with the
first AMM deployment. What this design does:

- **Structurally removes the auction component.** The protocol base fee
  eliminates first-price overbidding spam; the burn (era 1) takes half the
  congestion revenue out of the proposer's incentive entirely; tips remain
  the one open bribery channel and are visible on-chain.
- **Spreads the proceeds.** §6.1 means MEV captured as fees/tips is shared
  with delegators pro-rata, not concentrated on operators — which does not
  reduce MEV, but stops it from being a centralising operator-only revenue
  stream, the second-order harm that actually threatens gate G2.
- **Nothing else — stated as a cost, not an oversight.** No PBS, no
  encrypted mempool, no inclusion lists, no order-fairness protocol. The
  bill: proposers can reorder, insert, and censor within their slot;
  off-protocol side-payment markets (the Jito shape) can form; and §6.4 of
  the migration spec makes it worse than on Ethereum in one specific way —
  **sortition is public one epoch ahead**, so searchers know exactly whom
  to bribe (or DoS) minutes in advance. Two mitigations already bound the
  damage: slot-subcommittee attestation weight makes intra-epoch reorgs
  (time-bandit MEV) expensive, and 30 s slots leave finality ~16 min behind
  the tip at worst, bounding multi-block MEV games against finalised state.
  PBS-style separation is future work that this single-market design
  neither blocks nor requires.

## 7. Decisions asked of the founder (GATED)

1. **secp256k1 accounts at L1** — priced here (§3.2), not decided. The fee
   market is indifferent; the security note in the fleet brief is not.
2. **PQ fee subsidy** — whether to discount the ~12× PQ-vs-secp intrinsic
   gap if dual-auth is adopted, or let true cost stand (§3.2).
3. **Shielded proof size vs `MAX_BLOCK_TX_BYTES`** — if measurement shows a
   worst-case C1 proof above 256 KiB (§3.2): bigger blocks or recursion.

## 8. Not done this wave

- No transaction parsing/serialisation, no EVM engine, no mempool: this
  crate treats transactions as opaque bytes; the module is the arithmetic
  and the constants, as `rewards.rs` is for the split.
- The base-fee state leaf (tag `0x09`) is specified (§4.4), not added —
  the SMT component list is a closed list owned by the state-root design.
- ~~`transition.rs` step 11 not rewired~~ / ~~`Transfer` carries declared
  fees~~ — **both done 2026-08-12** (§6.1, §4.4). `PosTransaction::Transfer`
  is now `{ inputs, tx_bytes, tip_millisat_per_gas }`: gas is derived by
  `intrinsic_gas` and priced at the committed base fee, so a transaction can
  no longer name the satoshis it pays. That changed `canonical_bytes`, hence
  `body_root`, hence block identity — a consensus change, pinned by
  `transfer_encoding_is_gas_priced_not_declared`. The two per-block caps (§5)
  are enforced with their own errors (`BlockGasLimitExceeded`,
  `BlockByteLimitExceeded`).
- **Still not wired:** issuance (`rewards::distribute` at the epoch boundary)
  still credits the whole payout into the operator's bond with
  `commission_bps: 0` and `delegated_stake: 0`. The forcing argument of §6.1
  is about *fees*, and only fees were routed; issuance now has a committed
  commission column available to it and does not read it. Deliberate scope,
  recorded here rather than left to be discovered.
- The class of `PosTransaction::Transfer` is fixed to `TxClass::Eutxo`. The
  `EvmPq` / `EvmSecp256k1` / `Shielded` classes are priced (§3.2) but no
  transaction variant carries them, because no such variant exists yet.
- `SHIELDED_VERIFY_GAS_PROVISIONAL` unmeasured; activation-blocking (§3.2).
- G10 restatement (§5) is stated here, not edited into the migration spec.
