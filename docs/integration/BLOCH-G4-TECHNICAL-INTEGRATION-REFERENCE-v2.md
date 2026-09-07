# Bloch Genesis-4 — Technical Integration Reference

**Edition 2 · 2026-09-07 · Code revision `72e5525` (branch `main`)**

Postern Labs · Bloch Genesis-4, a post-quantum proof-of-stake Layer-1 with an
extended-UTXO ledger and explicit Casper-FFG finality.

## Scope statement

This edition is **code-verified**: every technical statement below was checked
directly against the source tree at commit `72e5525` (branch `main`) on
2026-09-07, by reading the relevant Rust source and its test suite. Two
internal, tool-assisted audit reports (`round3-report.md`, `round4-report.md`,
both dated 2026-09-06) informed §14's narrative and are cited by name where
they add commit-count/finding-count detail beyond what the source tree states
on its own. **Neither report is a file inside the `72e5525` source tree** — a
reader working only from this repository cannot independently re-open them.
Every substantive fact this document draws from them is separately
cross-checked directly against the cited source file wherever the source
carries the same finding (most consensus-history comments in `committees.rs`,
`derive.rs`, `finality.rs`, and `lib.rs` name their own finding IDs — e.g.
`R1 M8`, `R1 H3`, `F1` — independent of either report); where a figure (a
specific commit count, a finding-group total) is sourced only to a report and
has no independent in-tree artifact, §14 says so explicitly.
**This edition is NOT live-verified.** The environment that produced it has no
network path to `posternlabs.com`, to the two direct nodes, or to any other
running Genesis-4 endpoint. Edition 1 stated "verified live at height 42497"
and "endpoints and field lists verified live against the network" — this
edition makes no such claim, about any height, anywhere, and none of the
sample RPC responses below are live captures. Where a fact is about
infrastructure this repository does not contain (a public URL, an IP address, a
proxy's cache behaviour, the WASM wallet library), it is marked
**OPERATOR-ASSERTED** and is *not* verified by this edition either — it is
carried forward from edition 1 or from operator-facing internal documents,
unchanged in kind from before.

## How to read the evidence classes used throughout this document

- **VERIFIED-IN-CODE** — read directly from the source tree at `72e5525`, cited
  as `file:line`. This is the strongest class in this document and is as far
  as static review can go: it does not mean the deployed fleet is running this
  exact commit (see §13.5 and §14), only that the cited behaviour is what a
  binary built from this tree does.
- **OPERATOR-ASSERTED** — an infrastructure fact this repository cannot prove
  or disprove: a public URL, an IP address, DNS status, a proxy's cache TTL or
  quorum policy, the existence and behaviour of the closed-source WASM signing
  library, or the current status of an operational ceremony. Carried forward
  from edition 1 or an internal operator document, and flagged as such
  wherever it appears.
- **CONTRADICTED** — edition 1 (or another in-repo document) stated something
  the code does not do. Both the old claim and the current fact are given,
  with evidence, and the change is logged in Appendix A.

<div class="warn">

**The single fact that determines which integration path is open to you today.**
A **brand-new** node — a fresh clone, empty data directory, no
`--ws-checkpoint` — **cannot join Genesis-4 from scratch right now.** The
2016-epoch (≈22.4-day) "weak subjectivity" trust window that lets a fresh node take
the genesis manifest on faith closed on **2026-09-05 07:07:19.962 UTC**, and no
signed checkpoint that would let a fresh node join after that date has been
produced: the Phase-A signing ceremony has not been held, and no checkpoint
envelope exists anywhere in this repository or (per the most recent in-repo
note, dated 2026-09-06) outside it. A node that already completed its first
sync before that date is unaffected and needs nothing further. A node started
fresh today refuses to sync, loudly, by design, and tells the operator so. This
is covered in full, with the exact code path and constants, in §2.6 and §13.4
— read it before deciding whether "run your own node" is a path you can take
this week. It determines whether §13 (self-hosted observer node) or §10/§11
(the public endpoint / a fleet-operated direct node) is the integration path
available to you **today**.

</div>

---

## Contents

1. Network parameters
2. Architecture and consensus
3. Activation gates and what they mean for an integrator
4. Cryptographic standards
5. Addresses and script hashes
6. Keys and wallets
7. Block format
8. Transactions
9. Mempool and broadcast
10. JSON-RPC API
11. Deposits
12. Withdrawals
13. Running a node
14. Operational security notes for integrators
15. Appendix A — Changed since edition 1
16. Appendix B — Evidence index
17. Appendix C — Glossary

---

## 1. Network parameters

| Parameter | Value | Class | Evidence |
|---|---|---|---|
| Chain | Bloch Genesis-4 — post-quantum proof-of-stake L1. Predecessor **Genesis-3** (proof-of-work, SHA-256d/AuxPoW) is closed; it stopped at height 39,918 and is kept buildable only so the carried-over ledger can be re-derived. | VERIFIED-IN-CODE | `SECURITY.md:9-27`, `legacy/genesis3-node/` |
| Ticker | **BLCH** — canonical, public/prose spelling everywhere outside Rust identifiers. "BLOCH" is *only* a naming convention inside `SCREAMING_SNAKE_CASE` Rust constants (`TOTAL_SUPPLY_BLOCH`, `CARRYOVER_TOTAL_BLOCH`, …) and every rendered public page label reads "BLCH". Treat a visible "BLOCH" as a rendering artefact (a constant-name comment leaking into rendered text), never a second ticker. | VERIFIED-IN-CODE | `tokenomics_v4.rs:89-117`; `docs/integration/BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md:43` ("Ticker \| BLCH"); `apps/site/supply.html:112` |
| Token contract | None — BLCH is the native L1 asset, no ERC-style contract | VERIFIED-IN-CODE | absence confirmed (no token-contract crate) |
| Total supply | **100,000,000,000 BLCH**, fixed hard cap; enforced as a `const` with no setter, checked on every block (`SupplyCapExceeded`) | VERIFIED-IN-CODE | `tokenomics_v4.rs:89` (`TOTAL_SUPPLY_BLOCH`), `:84-88` (cap enforcement) |
| Carryover total | **18,146,400,000 BLCH** (`CARRYOVER_TOTAL_BLOCH`) across the measured **452,726** opening outputs (`CARRYOVER_MEASURED_UTXOS`) carried over from Genesis-3's terminal height 39,918. The single largest carried-over address holds **17,046,829,380 BLCH** (`LARGEST_CARRYOVER_ADDRESS_BLOCH`) — **93.94%** of the carryover total, the concentration figure §14.3 cites. | VERIFIED-IN-CODE | `tokenomics_v4.rs:200` (`CARRYOVER_TOTAL_BLOCH`), `:236` (`CARRYOVER_MEASURED_UTXOS`), `:479` (`LARGEST_CARRYOVER_ADDRESS_BLOCH`); `CARRYOVER-SNAPSHOT.md` |
| Decimals / sat | 8 decimals; 1 BLCH = 100,000,000 sat; `SAT_PER_BLOCH = 100_000_000`; `TOTAL_SUPPLY_SAT = 10^19` | VERIFIED-IN-CODE | `tokenomics_v4.rs:46,89-90` |
| Slot time | 30 seconds (`SLOT_DURATION_SECS`) | VERIFIED-IN-CODE | `bloch-pos-committee/src/params.rs:82` |
| Epoch | 32 slots (`SLOTS_PER_EPOCH`) = 16 minutes | VERIFIED-IN-CODE | `params.rs:43` |
| Genesis time | **2026-08-13 21:31:19.962 UTC**, decoded from `genesis/mainnet.manifest`'s `genesis_time_ms` field (`1786656679962`), 64 genesis validators | VERIFIED-IN-CODE | `crates/bloch-pos-node/src/genesis.rs:109,816-864`; cross-checked against `genesis/README.md:8-11` |
| Current epoch (this edition) | **≈2,232** at 2026-09-07 (derived from genesis time + elapsed 30 s slots; this document does not and cannot confirm the live fleet's actual head — see the scope statement above) | derived arithmetic, not a live read | genesis time above + `params.rs` constants |
| Finality model | Casper-FFG: justification at ≥⅔ attesting stake, finalization on two consecutive justified checkpoints, computed **per node** from the chain it validated itself. **Not backed by any slashing cost today** — see §2.4/§2.7 and §14. | VERIFIED-IN-CODE | `bloch-pos-committee/src/finality.rs`; `rpc.rs:1684-1814` (`Finality` doc) |
| Ledger model | Extended UTXO (eUTXO); outputs keyed `(txid, vout)`, committed value `EutxoEntry{txid,vout,value,script_hash}` | VERIFIED-IN-CODE | `bloch-pos-committee/src/state_root.rs:1030-1042` |
| Custody model | Non-custodial by construction: the node holds no spending key anywhere in its process, generates no address, and signs nothing on a user's behalf. All signing is client-side. | VERIFIED-IN-CODE | `crates/bloch-pos-node/src/main.rs:202-203` ("never holds a spending key"); `rpc.rs:1068-1069` (`getnewaddress` refusal doc) |
| Transports | `devnet` (default), `libp2p`, `dual` — selected by `--transport`; default is `devnet` with a loopback P2P listen address | VERIFIED-IN-CODE | `main.rs:1119` (`None \| Some("devnet") => Transport::Devnet`), `main.rs:1044` (`DEFAULT_P2P_LISTEN = "/ip4/127.0.0.1/tcp/16400"`) |
| RPC default bind/port | **`127.0.0.1:16310`** (`--rpc-bind` default `127.0.0.1`, `--rpc-port` default `16310` = `DEFAULT_RPC_PORT`). **Not `8080`** — see §10.1 and Appendix A. | VERIFIED-IN-CODE | `main.rs:81` (`DEFAULT_RPC_PORT: u16 = 16310`), `main.rs:1338-1339,1390` |
| Metrics/health | `--metrics-bind 127.0.0.1` default, `--metrics-port` **off unless explicitly set** — no default listener | VERIFIED-IN-CODE | `main.rs:1355-1365,1395` |
| L2 status | **No EVM-compatible L2 exists in this repository, and none runs code driven by it.** "Chain id 8400" is a reference to a separate, already-being-replaced external service the founder has framed as being retired, not extended; the successor "EVM at L1" plan is an explicit `Status: DRAFT` document with **no code for either track**. Do not present chain id 8400 as a current, operating feature. | VERIFIED-IN-CODE (absence) | `docs/FLEET-BRIEF-2026-08-11.md:51`; `docs/specs/BLOCH-L1-EXECUTION-PLAN.md:7` (`DRAFT — milestone plan for review; no code exists for either track`) |
| Testnet | **No Genesis-4 testnet exists in this repository or is referenced by the PoS node/consensus crates at all** (zero occurrences of "testnet" in `bloch-pos-node`/`bloch-pos-committee`). The `bloch1t` "testnet" address prefix belongs only to the legacy Genesis-3 address module (`bloch-crypto::address`), which `bloch-pos-node` never imports. If you are told a Genesis-4 testnet exists, that is an infrastructure claim this repository does not support and cannot verify — treat as OPERATOR-ASSERTED and confirm independently. | VERIFIED-IN-CODE (absence) / OPERATOR-ASSERTED (any claimed live testnet) | `bloch-crypto/src/address.rs` (prefix table); `bloch-pos-node`/`bloch-pos-committee` grep, zero hits |
| Weak-subjectivity status | **A fresh third-party node cannot join today** — see the boxed warning above and §2.6/§13.4. | VERIFIED-IN-CODE | `crates/bloch-pos-node/src/ws_boot.rs`, `crates/bloch-pos-committee/src/ws.rs` |

<div class="note">

**Reading `total_active_stake_sat`, `balance_sat`, and every other satoshi
amount.** Every satoshi-denominated field on the RPC surface is encoded as a
**decimal string**, never a JSON number (`Json::sat`, `rpc.rs:392-401`) — a
10^19-satoshi total supply exceeds a JS/JSON double's exact-integer range
(2^53), so a client that parses these fields with `JSON.parse` and ordinary
floating-point arithmetic will silently lose precision on values above
roughly 9×10^15 sat. Parse every `*_sat` field as a big integer (`BigInt` in
JavaScript, `u128`/arbitrary-precision decimal elsewhere), never as a native
number. Plain counts, slots, epochs and indices (`height`, `slot`, `epoch`,
`index`, `utxo_count`, …) are ordinary JSON numbers (`Json::u`) and do not need
this treatment. Readers must additionally tolerate a legacy bare-integer form
on input per `docs/specs/BLOCH-SATOSHI-ENCODING.md:10-33`, but every response
this node emits uses the string form.

</div>

---

## 2. Architecture and consensus

### 2.1 Slots, epochs, proposer and committee

Time is divided into fixed 30-second slots (`SLOT_DURATION_SECS = 30`) grouped
into 32-slot epochs (`SLOTS_PER_EPOCH = 32`, `params.rs:43,82`). For each slot,
one proposer is drawn from the active validator set by a weighted schedule; the
**finality committee is the entire active validator set** (64 today), not a
fixed-size sample of it. `committees::epoch_committees` partitions the active
set deterministically (Fisher-Yates over an epoch-scoped seed) into
`SLOTS_PER_EPOCH` (32) per-slot groups — every active validator lands in
exactly one slot's group and votes exactly once per epoch, so the union of an
epoch's groups **is** the active set, and the Casper-FFG quorum denominator is
total active stake with no sampling variance
(`bloch-pos-committee/src/committees.rs`, `schedule.rs`). At today's 64 active
validators that is **≈2 validators per slot-group**.

<div class="warn">

**`COMMITTEE_SIZE = 128` and `SLOT_SUBCOMMITTEE_SIZE = 8` (`params.rs:30,40`)
size a different, superseded sampled-draw mechanism that is not wired into
consensus — do not read "committee of 128" off these two constants.** The
crate's own `lib.rs` states plainly that "the live committee mechanism is the
partition (`committees.rs`, called from `transition.rs`), never the sampled
draw these two constants size," and `finality.rs`'s own in-body correction
records that the earlier 128-member *sampled* reading made the quorum two
thirds of a *sample's* stake, not the network's — finding F1, which the
partition above replaced (a ~30% adversary could exceed one third of a
128-member sample often enough to stall finality roughly one epoch in five).
See Appendix A.

</div>

A block body may carry up to **`MAX_ATTESTATIONS_PER_BLOCK` = 4,096** per-slot
fork-choice attestations (`params.rs:78`) — a ceiling far above what the
current 64-validator active set can produce in one slot (≈2, above), so it is
not binding today; it bounds a much larger future validator set instead.

This partition and proposer draw are memoised once per epoch (a Round-3/4 fix,
R1 M8) rather than recomputed on every one of an epoch's 32 blocks, with a
differential test proving the cached and uncached results are byte-identical
(`committees.rs:799-830`, `repeated_calls_with_the_same_key_recompute_only_once`).

### 2.2 RANDAO

Validator selection draws on a RANDAO-style beacon: each validator commits to a
`randao_commitment` at registration and reveals it per block
(`randao_reveal`/`randao_mix` header fields, §7). The seed-selection code has
one intentionally ungated anti-grinding improvement
(`ANCESTRY_SEED_ACTIVATION_EPOCH`, inert, §3) still pending, and a formerly
divergent, dead-code fourth definition of the seed function
(`derive::sortition_seed`) was deleted outright rather than gated, since it had
zero non-test callers (`derive.rs:6-24`, module doc "deleted 2026-09-06, R1
H3"; `round4-report.md` discusses the same finding but is not needed to verify
it — the deletion and its rationale are recorded in the source itself).

### 2.3 Fork choice — LMD-GHOST

Fork choice is **LMD-GHOST** (latest-message-driven, greatest-weight subtree):
the head is the leaf of the heaviest chain by *attested weight*, not by chain
length (`engine.rs:33-35`, `lmd_ghost_head`/`forkchoice_store`,
`engine.rs:5179-5260`). This is deliberately not "longest chain" — a Round-3
regression test exists specifically pinning that fork choice follows attested
weight, not length (`engine.rs:5937-5979`). `advance()` recomputes the head on
every iteration and converges in a bounded number of steps.

There is **no fixed maximum reorg depth** above a node's own finalized
checkpoint; the only structural limit is the finality latch (§2.5). Reorgs are
replayed only from the fork point forward, not from genesis, since a 2026
performance fix (`engine.rs:3420-3435`).

### 2.4 Casper-FFG — the exact justification and finalization rule

One checkpoint vote per epoch, by the whole active validator set — partitioned
into the 32 per-slot groups of §2.1, whose union is the epoch's voting body —
(`bloch-pos-committee/src/finality.rs`):

- **Justification** (`finality.rs:15-20,405-478`): a checkpoint is justified
  when the sum of attesting stake, for attestations whose `source ==
  current_justified` and `target_epoch == this epoch`, satisfies
  `3 × attesting ≥ 2 × total` in exact `u128` integer arithmetic — no
  rounding. A test pins that exactly two-thirds justifies and "two-thirds
  minus one satoshi" does not (`finality.rs:678-716`).
- **Finalization** (`finality.rs:21-24,479-497`): Casper *k=1* — if a
  checkpoint at `epoch` justifies with `source == current_justified` **and**
  `cp.epoch == source.epoch + 1` (strictly consecutive), then `source`
  becomes finalized. A justified checkpoint that is *not* built consecutively
  (e.g. after a skipped epoch) is justified but never finalized on its own
  (`finality.rs:744-761`).
- **Equivocation**: a validator signing two different `AttestationData` for
  the same target epoch counts for neither side of the tally
  (`finality.rs:424-442`).

### 2.5 The finality latch — what "finalized_height is monotonic" actually rests on

`finalized_height` is **not** an independently tracked counter. It is computed
by looking up the height of whatever block currently holds the finalized
checkpoint's *root* on this node's own canonical chain:
`self.height_of(&self.state.finality().finalized.root)` (`engine.rs:3862-3866`).
Finality is fundamentally a **(epoch, root) checkpoint** fact; `finalized_height`
is a height-shaped projection of it for RPC convenience.

The pure Casper-FFG replay of a `FinalityState` can, by itself, legitimately
have its finalized checkpoint **descend** across reorgs that break no protocol
rule — this was measured on the live chain (finalized epoch 6 → 4 → 2 → 0 in
three in-rules cuts). Since 2026-09-05 (finding F-03), an engine-level
**finality latch** makes this untrue *for any single node*:

- `ratchet_finalized()` moves `Engine.finalized_latch` **up only**
  (`engine.rs:3325-3339`).
- `cut_below_finalized_latch(ancestor)` refuses any reorg whose common
  ancestor is strictly below the latch (`engine.rs:3352-3371`).
- A refused branch is **parked**, not deleted, in a bounded FIFO
  (`Engine.parked_refused_finality`, cap 512, `engine.rs:379`) — a re-offered
  identical branch is recognized and refused at the door before any signature
  work, so this is not a silent, ever-growing partition.
- The refusal count is exported as the Prometheus counter
  `bloch_pos_finality_rewinds_refused_total` (§14.2).
- **Operator override**: `--allow-finality-rewind` /
  `BLOCH_ALLOW_FINALITY_REWIND=1` lifts the latch, loudly logging every
  instance by name (`engine.rs:3357-3369,4626-4638`). Not recommended for an
  exchange's own observer node.

<div class="warn">

**This is a per-node guarantee, not a network guarantee.** Two nodes can each
have a monotonic, never-rewinding `finalized_height` of their own and still
disagree with each other about what root that height holds, if they were on
opposite sides of a leak-driven partition (§2.7). "Two nodes agree" mitigates
*divergence* — it does not mitigate either node's own rewind, because both
rewind independently. See §11.3 for the crediting rule this implies.

</div>

### 2.6 Weak subjectivity — how a fresh node bootstraps, and why it cannot today

Genesis-4 is proof-of-stake: a validator that exits and withdraws its bond can,
after the withdrawal delay passes, sign a complete alternate history at zero
ongoing cost (the "long-range attack"). The protocol's defence is a
**weak-subjectivity window**: a node's own finality is only a valid trust
anchor for a syncing peer while it is recent enough that the validators who
signed it could not all have withdrawn yet.

- **The window, exact** (`crates/bloch-pos-committee/src/ws.rs:133-167`):
  `WS_PERIOD_EPOCHS = WITHDRAWAL_DELAY_EPOCHS (2048) − EXIT_DELAY_EPOCHS (32) =
  2016` epochs ≈ 22.4 days. `WS_FRESH_EPOCHS = WS_PERIOD_EPOCHS / 2 = 1008`
  epochs ≈ 11.2 days (soft/warn threshold).
- **The window closed at 2026-09-05 07:07:19.962 UTC** — genesis time
  (2026-08-13 21:31:19.962 UTC) plus 2016 epochs. This is arithmetic over
  values read directly from the manifest and `params.rs`, not an assertion.
- **Boot decision** (`ws.rs:637-647`, `boot_decision`):

  ```rust
  pub fn boot_decision(has_local_finality: bool, age_epochs: u64) -> BootDecision {
      if !has_local_finality { BootDecision::RequireCheckpoint }
      else if age_epochs < WS_FRESH_EPOCHS { BootDecision::Resume }
      else if age_epochs < WS_PERIOD_EPOCHS { BootDecision::ResumeStaleWarn }
      else { BootDecision::RefuseStale }
  }
  ```

  A node with **no finality of its own** (an empty data directory — the case
  for any new node standing up today) always lands in `RequireCheckpoint`. If
  no `--ws-checkpoint` was supplied, its only candidate anchor is the genesis
  checkpoint (epoch 0), and `RequireCheckpoint`'s own logic refuses to sync
  once that anchor's age exceeds `WS_PERIOD_EPOCHS` — which it now does, by
  about two days as of this edition's date, and will keep doing indefinitely
  until a signed checkpoint is supplied.
- **The refusal, verbatim** (`crates/bloch-pos-node/src/ws_boot.rs:590-609`,
  `ERR_WS_REQUIRE_CHECKPOINT`): *"This node has no finalized history of its
  own, and its only trust anchor (the genesis anchor) is `{anchor_age}` epochs
  old — at or beyond the weak-subjectivity window of `{WS_PERIOD_EPOCHS}`
  epochs (≈22 days at the mainnet slot cadence). Under proof of stake,
  validators who exited and withdrew long ago can sign a complete forged
  history at zero cost; beyond the window, nothing inside the protocol lets a
  syncing node tell that forgery from the chain the network actually lived. A
  recent checkpoint obtained OUT OF BAND is the only sound way in."* The
  message then names the recovery path: fetch a signed checkpoint envelope
  from a trusted channel, compare its digest across at least two independent
  channels, and restart with `--ws-checkpoint <file> --ws-signer-set <file>`.
- **No such checkpoint exists in this repository.** `genesis/` contains only
  `mainnet.manifest` and `README.md` — no `ws_latest.bin`, no checkpoint
  envelope, no signer-set file. The signing ceremony that would produce one
  (Phase A: 2-of-3 signers, ≥1 external; Phase B: 3-of-5, ≥2 external —
  `ws.rs:298-310`) **has not been held**, per the most recently dated in-repo
  note (2026-09-06): *"The signing keys have not been generated — the
  ceremony … has not happened … a third party attempting a first sync today
  (or any day after 2026-09-05 07:07:19 UTC) cannot independently join
  Genesis-4."* This edition cannot confirm or deny whether the ceremony has
  been held since that note was written — that is an operational fact outside
  this repository — but as of `72e5525`, the code, the tests, and every dated
  operator note agree that it had not been.
- **What is unaffected**: a node that completed its **first** sync before
  2026-09-05 07:07 UTC keeps its own finality as its anchor from then on, and
  needs no checkpoint. This is the case for the existing fleet nodes. It is
  not the case for any node an exchange stands up from scratch from this point
  forward, until a checkpoint is published and supplied.

<div class="warn">

**Practical consequence.** As of this edition, an exchange **cannot** bring up
its own fresh, independently-syncing Genesis-4 observer node and have it reach
the live chain unassisted. The "recommended posture" of §13 (an
independently-validating observer node) is the right target architecture, but
it is **blocked today** on an operational ceremony this repository's code
cannot perform for you. Until a checkpoint is published, or your node's data
directory is seeded from an already-synced node's `blocks.log` + `meta.bin` +
`ws_latest.bin` (§13.3 — which shifts, but does not remove, the trust
question: you are then trusting whoever gave you the seed), the only
integration paths available today are the public proxy endpoint and/or a
fleet-operated direct node (§10, §14) — both OPERATOR-ASSERTED, not something
this repository verifies.

</div>

### 2.7 Inactivity leak, the quorum-denominator floor, and the 2026-08-24 partition finding

After `INACTIVITY_LEAK_THRESHOLD_EPOCHS` (4) consecutive epochs without
finality, every committee member who did not vote that epoch loses
`max(remaining × t / INACTIVITY_LEAK_QUOTIENT, 1)` satoshis of *effective
stake as tracked by this leak ledger* (`t` = epochs beyond the threshold;
`INACTIVITY_LEAK_QUOTIENT = 64`, `finality.rs:499-526`, `params.rs:159,167`).
This is separate storage from `CommittedState`'s own `effective_stake`, but it
feeds the Casper-FFG quorum denominator.

**The load-bearing caveat, in the code's own words** (`finality.rs:63-81`):
*"the safety argument [only one root can justify per epoch] is true of ONE
`FinalityState` and false of the network"* — because the quorum denominator is
the **leak-adjusted** total, and the leak is a function of what *this node*
heard. Two nodes that heard different subsets hold different denominators, so
two disjoint partitions can each independently reach ⅔ of their own (different,
shrunken) totals and each finalize a different root for the same epoch. **This
is not hypothetical**: it is the reproduced 2026-08-24 incident — a test
measures a 4-of-64 partition (6.25% of stake) self-finalizing once the absent
93.75% has leaked away (`finality.rs:1010-1030`), and `genesis/README.md:83-89`
independently records "three disjoint partitions of four validators each
finalized epoch 25 under three different roots" as a real, past event on this
chain.

**The fix and its flag day**: `LEAK_RECOVERY_ACTIVATION_EPOCH = 2_700`
(`params.rs:1183`) — **armed**, firing **2026-09-12 21:31:19.962 UTC** — adds a
floor to the quorum denominator (`max(leak_adjusted, unleaked_total × ½)`) so a
partition holding under ⅓ of the *original* stake can never self-justify, and
enables leak **recovery** at `INACTIVITY_LEAK_RECOVERY_QUOTIENT = 16`
(`params.rs:223`): a participating validator's leaked balance decays back
toward zero at 1/16 per epoch (the accumulator roughly halves every ~11
epochs, floor-guarded so it terminates) instead of only ever growing —
deliberately slower than the 1/64-per-epoch accrual rate the leak itself uses,
so recovery cannot instantly undo the leak that funded it. Below epoch 2700,
the pre-fix, unfloored arithmetic is exactly what is in force — **as of this
edition's current epoch (~2,232), that is still the live rule.** See §3 for
the full flag-day table and what changes for an integrator.

### 2.8 Slashing — exists in code, structurally inert today

`SLASHING_EVIDENCE_ACTIVATION_EPOCH = u64::MAX` — **inert**. Genesis-4's own
RPC source states plainly, in the single most consequential doc comment in
this tree for an exchange: **"No stake on Genesis-4 can be slashed at all"**,
for four independent reasons, any one of which is alone sufficient
(`rpc.rs:1695-1736`):

1. Slashing evidence (wire tag `0x05`) now *decodes* (fixed 2026-09-05,
   closing a prior defect where the codec could not even recover the
   evidence) — but every ingress path (block body, gossip,
   `sendrawtransaction`) refuses the resulting transaction below the unarmed
   activation epoch.
2. That refusal is the only one on **every** ingress path — a proposer that
   included evidence today would produce a block its own peers refuse.
3. Nothing in this codebase constructs the transaction outside tests; the
   node only **logs** a detected equivocation — the log line itself says the
   pipeline is "NOT wired".
4. The activation constant is defined and is exactly `u64::MAX` — no epoch
   any chain reaches will ever activate it without a founder decision to move
   it, and moving it has a stated fleet-rollout precondition that has not been
   met.

The same doc comment records a forensic replay finding a **majority of the
64-validator genesis set** with provable double-signing on the live chain,
derived seven independent ways, none of it ever slashed, none of it visible
over any RPC method — `slashed: false` is what every one of them reads,
because no method exposes equivocation evidence. **Read `slashed: false` as
the expected value, not as a clean bill of health.** **The code's own doc
comment explicitly instructs against putting the exact count in
integrator-facing material, because no RPC method lets a reader verify it
themselves — a figure the recipient cannot check does not belong in a
document they are meant to act on.** This document complies with that
instruction: it states the fact of undetected, unprosecuted, non-verifiable
equivocation at scale, and deliberately withholds the count itself.

**Net for an exchange**: Genesis-4 finality today is, in the source's own
words, *"economic by intent and cryptographic by nothing"* — reverting a
finalized checkpoint costs an attacker no bonded stake, only the coordination
of whichever validators would have to do it. See §14 for the crediting rule
this drives.

### 2.9 What "finalized" guarantees, and what it does not

Summarizing §2.4–2.8 into one statement, matching the node's own `Finality`
enum doc comment (`rpc.rs:1684-1814`) and `SECURITY.md`'s integrator guidance:

**What it guarantees:**
- It is *this node's own judgement*, computed from the chain it validated
  itself — it does not depend on trusting whoever produced the block.
- Since the 2026-09-05 finality latch, it is a genuine per-node **latch**: a
  block this node once reported `finalized` never later leaves *this node's*
  canonical chain (absent the explicit `--allow-finality-rewind` override).
- It is strictly stronger than `justified` or `canonical`.

**What it does NOT guarantee:**
- **No slashing cost backs it** (§2.8) — reverting it costs an attacker
  nothing bonded.
- **It is not a cross-node latch.** Two independently-run nodes can each have
  a monotonic `finalized_height` and disagree on its root, if they were on
  opposite sides of a leak-driven partition (§2.7).
- **The quorum denominator has no floor before epoch 2700** — a partition
  holding as little as 6.25% of stake has been shown, in this exact codebase's
  own history, to self-finalize.
- The pure Casper-FFG rule underneath can, by itself, propose a legitimate
  downward cut of the finalized checkpoint; only the per-node engine latch
  stops that node individually from acting on it.

See §11.3 for the single, explicit crediting rule this document recommends as
a consequence.

---

## 3. Activation gates and what they mean for an integrator

All gates read `self.epoch`/the block's own committed epoch — never a clock —
so a mixed fleet of old/new binaries agrees on every block before its own gate,
and every gate is designed so that "inert" reproduces today's live behaviour
byte-for-byte (`params.rs`, repeated doc pattern across every constant below).
`u64::MAX` means "no epoch will ever reach it without a founder decision to
change the constant and rebuild the fleet".

| Gate constant | Value | Status at epoch ≈2,232 (2026-09-07) | Integrator impact |
|---|---|---|---|
| `LEAKED_ROSTER_ACTIVATION_EPOCH` | `1_400` | **Active** (armed 2026-08-29, long past) | Inactivity leak now reaches the proposer/committee duty roster, not only the quorum denominator. No direct RPC-visible change; validator-registry internal. |
| `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH` | `800` | **Active**, long past | `TransferV2` (wire `0x06`) is a valid, live block-inclusion format; see §8.2. A wallet may emit either V1 or V2 — both settle to the identical `txid`. |
| `BLOCK_BYTES_V2_ACTIVATION_EPOCH` | `800` | **Active**, long past (paired with the gate above by a compile-time-adjacent test) | Block payload cap 262,144→524,288 bytes; EIP-1559 byte target 131,072→262,144. Affects how many transfers fit per block and the fee-market's byte axis (§8.6/§9). |
| `LEAK_RECOVERY_ACTIVATION_EPOCH` | **`2_700`** | **Armed, not yet reached** — fires **2026-09-12 21:31:19.962 UTC** | See §3.1 — the epoch-2700 flag day. |
| `ANCESTRY_SEED_ACTIVATION_EPOCH` | `u64::MAX` | Inert | RANDAO seed anti-grinding look-ahead. Not integrator-visible. |
| `DEPOSIT_ACTIVATION_EPOCH` | `u64::MAX` | **Inert, and this inertness is the live rule, permanently by design** | Legacy `Deposit`/`Delegate` (wire `0x02`/`0x04`) are refused by *consensus*, on every node, at every epoch. The constant's own doc comment states arming it is explicitly **not** how funded deposits open — doing so would make stake-minted-from-nothing a consensus-valid transaction — and recommends this number **never move**. **An exchange cannot stake customer funds on-chain today, under any circumstance** — see §8.7 and §12. |
| `EXIT_AUTH_ACTIVATION_EPOCH` | `u64::MAX` | Inert; **arming precondition unmet** | Below it, the legacy, unauthenticated `Exit` (`0x03` — a bare registry index, no signature, cannot be revoked) remains the only voluntary-exit path and is a live, zero-signature attack surface against the 64-validator genesis committee: 64 such messages in one block would retire the entire roster. This affects **validator bonds, not user eUTXO funds/balances**. Arming needs the contested wire byte `0x08` (claimed by `ExitV2` here and by rival messages on other lineages) settled first — arming without that "retires legacy Exit and puts nothing in its place" per the constant's own doc comment. |
| `FEE_STAKE_DECOUPLE_ACTIVATION_EPOCH` | `u64::MAX` | Inert | Closes a fee-to-stake compounding path that today lets one proposer convert liquid coin into a ⅔ supermajority in a single block for roughly 1,080 sat of fees. Validator-registry/consensus-security impact, not directly RPC-visible. |
| `SLASHING_EVIDENCE_ACTIVATION_EPOCH` | `u64::MAX` | Inert | See §2.8. Nothing on Genesis-4 can be slashed today. |
| `DUST_RULE_ACTIVATION_EPOCH` | `u64::MAX` | Inert at consensus | A block **may** legally carry a zero-value output today; the node's own mempool already refuses dust unconditionally as local policy (not consensus), so well-behaved public nodes will not relay one, but a non-conforming proposer's block including one is still valid on-chain. |
| `RANDAO_RECOMMIT_ACTIVATION_EPOCH` | `u64::MAX` | Inert; soft deadline **≈2027-02-11** (RANDAO commitment-chain exhaustion) if not armed by then | Validator-liveness concern, not directly integrator-visible; a wire tag (`0x0A`) is likewise undecoded pending a founder ruling. |
| `TX_BYTES_BOUND_ACTIVATION_EPOCH` | `u64::MAX` | Inert at consensus | A transaction may legally over-declare its `tx_bytes` today; the node's mempool already bounds this as local policy (`TX_BYTES_DECLARE_SLACK`), so a well-behaved public node still enforces the practical bound described in §8.6. |
| `ATTESTATION_DEDUP_ACTIVATION_EPOCH` | `u64::MAX` | Inert (new this wave) | Consensus-internal; not integrator-visible. |
| `REWARDS_V2_ACTIVATION_EPOCH` | `u64::MAX` | Inert (new this wave) | Validator issuance/participation-credit accounting only; does not change a depositor's/holder's eUTXO balance. |
| `STAKING_TX_METERING_ACTIVATION_EPOCH` | `u64::MAX` | Inert (new this wave) | Gas/byte metering for staking transactions; not relevant while `DEPOSIT_ACTIVATION_EPOCH` keeps staking closed. |
| `WITHDRAWAL_ACTIVATION_EPOCH` | `u64::MAX` | Inert **and unwired** | **There is no `PosTransaction::Withdraw` variant at all** in this tree — the transaction-type space is frozen by an exhaustive match with no wildcard arm, and no wire tag is assigned to it (`0x0B` is *not* found assigned anywhere in the current tree's wire-tag registry, despite an internal report describing it as "provisional" — treat that as unconfirmed). See §8.7/§12 — **there is no stake-withdrawal transaction today, at any wire tag.** |
| `SIGHASH_NETWORK_BINDING_ACTIVATION_EPOCH` | `u64::MAX` | Inert | See below — this is the one gate whose future arming needs advance wallet-side coordination, not just fleet coordination. |

### 3.1 The epoch-2700 flag day (2026-09-12 21:31:19.962 UTC)

`LEAK_RECOVERY_ACTIVATION_EPOCH = 2_700` is the **only** consensus gate armed
for a future flag day in this tree beyond the two long-past epoch-800 gates.
Two facts an integrator should hold at once:

- **It does not change transaction validity, wire formats, or eUTXO
  balances.** Nothing in the transaction-acceptance path (`transition.rs`)
  reads this constant; every use is confined to the epoch-boundary
  justification/finality fold in `finality.rs`. No address, no balance, no
  withdrawal or deposit rule changes because of this flag day.
- **`state_root` will take a different value across the boundary, on
  schedule, and this is expected — not a fork.** `state_root.rs` commits the
  inactivity-leak bookkeeping into the same Merkle tree as everything else;
  the moment leak entries begin decaying (post-2700, for any validator that
  had accrued leak and is now participating), the committed bytes for that
  subtree differ from the pre-2700 rule. Every upgraded node computes the
  identical new root; a node running a binary that predates the
  `LEAK_RECOVERY_ACTIVATION_EPOCH = 2_700` constant would compute a
  **different** post-2700 root and silently stop agreeing with the network.
  If you self-host a node (§13), confirm before 2026-09-12 21:31 UTC that its
  binary was built from a commit at or after the one that armed this constant
  — `72e5525` qualifies.

Positive effect for an integrator: post-2700, a small partition of validators
can no longer self-finalize a rogue checkpoint of the 2026-08-24 class,
making `finalized` a somewhat more trustworthy signal against the
partition-based false-finality risk of §2.7 — it does not, on its own, restore
a slashing cost, and the crediting recommendation in §11.3/§14 does not change
because of it.

### 3.2 `SIGHASH_NETWORK_BINDING_ACTIVATION_EPOCH` — the one gate that needs wallet coordination

Currently `u64::MAX` (inert). Once armed, a signature is checked against
`SHA3-256(DS_SPEND2 ‖ network_binding() ‖ spend_signing_root())` instead of
`spend_signing_root()` alone (`network_binding()` a fixed 32-byte label,
`b"BLCH4:GENESIS-4:MAINNET"`) — `spend_signing_root()` itself, and therefore
every `txid`, is untouched. The code states the consequence for wallets
explicitly: **"arming with no wallet-side change simply makes every existing
signature invalid (fail-closed, not fail-open)"** — every outstanding
signed-but-unconfirmed transaction becomes permanently `BadSignature` the
instant this gate's epoch is reached, with **no coded grace period**. If this
is ever armed, it requires advance, published coordination with every wallet
implementation (including the WASM library, OPERATOR-ASSERTED, §6), not only a
node-fleet rebuild.

---

## 4. Cryptographic standards

Post-quantum by construction — no secp256k1/ECDSA anywhere on a Genesis-4
consensus path.

| Item | Value | Evidence |
|---|---|---|
| Signature scheme | **Hybrid: ML-DSA-65 ‖ Falcon-1024 — both must verify.** The two rest on different lattice problems (Module-LWE vs. NTRU), so a break in one does not forge the other. | `bloch-crypto/src/crypto/mod.rs` |
| ML-DSA-65 | NIST FIPS 204 (Dilithium), Module-LWE. Public key **1,952 B**, secret key **4,032 B**, signature **3,309 B** (fixed-length). | `crypto/mod.rs:20-22` |
| Falcon-1024 | NTRU-lattice, hedged. Public key **1,793 B** (fixed), secret key **2,305 B**, signature **variable-length**, max declared size **1,462 B** (the theoretical ceiling; see the re-sign note below for why the *actual* size varies transaction to transaction). | `pqcrypto-falcon-0.4.1/src/ffi.rs:54-56`, cross-checked `crypto/mod.rs:723,734,748-749` |
| Key envelope | 4-byte header: `0xB1 0x0C` magic + `suite_id: u16` little-endian + body. `SUITE_MLDSA65_FALCON1024 = 0x0001` (today's hybrid); `SUITE_MLDSA65_ONLY = 0x0002` exists only as a proof-of-removability, unused in production. A legacy (pre-envelope) raw hybrid object of exactly `MLDSA_PUBKEY_LEN + Falcon-pubkey-length` bytes is also accepted and treated as suite `0x0001` — length alone disambiguates the two, and a legacy pubkey happening to start with the magic bytes cannot be misclassified (regression-tested). | `crypto/mod.rs:24-53,201-244` |
| Enveloped hybrid sizes | Pubkey 4+1952+1793 = **3,749 B**; secret key 4+4032+2305 = **6,341 B**; signature (max) 4+3309+1462 = **4,775 B** | `transition.rs:207` (`WitnessKey` doc, "3,749 B key" / "4,775 B proofs") |
| "Measured" gas-pricing signature size | **`HYBRID_SIG_BYTES = 4,589` bytes** — a *measured* figure (3,309 + a Falcon component priced at 1,280, not the 1,462 theoretical ceiling), used only to budget mempool declared-size slack, not a hard maximum. | `bloch-pos-committee/src/fee_market.rs:135-137` |
| Hashing | SHA3-256 / SHAKE-256, domain-separated | throughout `bloch-crypto`, `bloch-pos-committee` |
| Domain separation tags (16 bytes each, exact) | `DS_BLOCK = b"BLCH4:BLOCK\0\0\0\0\0"` (`params.rs:1820`); `DS_SPEND = b"BLCH4:SPEND\0\0\0\0\0"` (`:1838`); `DS_SPEND2 = b"BLCH4:SPEND2\0\0\0\0"` (`:1848`, inert, §3.2); `DS_TXID = b"BLCH4:TXID\0\0\0\0\0\0"` (`:1857`); `DS_PROPOSE = b"BLCH4:PROPOSE\0\0\0"` (`:1869`); `DS_EXIT = b"BLCH4:EXIT\0\0\0\0\0\0"` (`:1876`); `DS_WSCKPT = b"BLCH4:WSCKPT\0\0\0\0"` (`:1881`) | `bloch-pos-committee/src/params.rs`, per-tag line numbers given inline (file order: `DS_BLOCK`, `DS_SPEND`, `DS_SPEND2`, `DS_TXID`, `DS_PROPOSE`, `DS_EXIT`, `DS_WSCKPT`) |
| Constant-time / fail-closed properties | `crypto::verify` auto-detects enveloped vs. legacy-raw form by exact byte length and returns `false` (never panics) on a suite mismatch between pubkey and signature — a documented consensus rule, not merely a library nicety. OS-RNG failure fails **closed** (aborts) rather than silently falling back to a weaker source (a fixed Round-3 defect, K-H1). | `crypto/mod.rs:239-262` |

<div class="note">

**Falcon-1024's variable length is why a signer sometimes re-signs.** A
transaction's `tx_bytes` field sits *inside* the spend-signing root (§8.3), so
a wallet must fix it **before** the signature exists — but Falcon-1024's
signature length varies transaction to transaction. The reference in-repo CLI
budgets `HYBRID_SIG_BYTES` (4,589 B, above) worth of slack per input and, if
the actual encoded size still exceeds what was declared after signing, refuses
to send and requires re-signing at a larger declared size (same message, new
nonce → new Falcon signature bytes, **identical** `txid`/signing root). The
re-sign *loop itself* — "sign, check size, retry up to a few times, no network
round trip" — is a property of the (out-of-repository) WASM wallet's
higher-level flow: nothing in `bloch-crypto::crypto::sign()` itself checks or
retries. **VERIFIED-IN-CODE**: why the phenomenon exists (variable Falcon
length, `tx_bytes` fixed pre-signature, `UnderdeclaredSize` refusal on any
shortfall) and that this repository's own reference CLI hits the identical
problem and instructs the operator to re-sign manually. **OPERATOR-ASSERTED**:
the specific "re-signs itself, a few times, no round trip" mechanics of the
production wallet, since that wallet is not in this repository.

</div>

---

## 5. Addresses and script hashes

<div class="warn">

**The node reads and writes `script_hash` (32 bytes), never an address
string.** No method on the Genesis-4 RPC surface generates, validates, or
converts a `bloch1q…` address. All address-string handling — generation,
parsing, checksum computation, and the address→`script_hash` mapping below —
must be reimplemented client-side; it is not something the node will do for
you. `getnewaddress` exists as a routed method and returns a dedicated error
(§10.5) precisely because the node has, in its own words, **"no frozen address
format"** of its own.

</div>

### 5.1 Address format (VERIFIED-IN-CODE — `bloch-crypto::address::Address`)

| Fact | Value | Evidence |
|---|---|---|
| Mainnet prefix | `bloch1q` | `bloch-crypto/src/core/mod.rs:141` |
| "Testnet" prefix | `bloch1t` — belongs to the legacy Genesis-3 address module only; no Genesis-4 network uses it (§1) | `core/mod.rs:142` |
| Body | 20-byte hash ‖ 4-byte checksum = 24 bytes = 48 hex chars | `bloch-crypto/src/address.rs:74-82` |
| Total length | 7 + 48 = **55 characters** | `address.rs:75-77` |
| Hash algorithm | `SHA3-256(pubkey)`, **first 20 bytes** — **this is not Bitcoin's hash160** (RIPEMD160(SHA256(·))); no RIPEMD160 implementation exists anywhere in this codebase. Any in-repo comment calling this "hash160" is using the term informally, as a synonym for "20-byte pubkey hash", not literally. | `address.rs:56-60`; repo-wide grep for `ripemd`, zero hits |
| Checksum | `SHA3-256(SHA3-256(hash))[0..4]`, appended (not prepended) after the hash | `address.rs:88-95,130-138` |
| Case sensitivity — prefix | Case-sensitive exact match | `address.rs:66-72` |
| Case sensitivity — hex body | **Case-insensitive** on parse (accepts mixed-case hex); always emitted lowercase | `address.rs:79,137` (uses the `hex` crate, which accepts `A-F`/`a-f` interchangeably) |
| Validation regex | `^bloch1q[0-9a-fA-F]{48}$` for the **body**, if you want to accept everything the reference parser accepts. **A lowercase-only regex (`^bloch1q[0-9a-f]{48}$`, as edition 1 recommended) is stricter than what the network itself accepts** and will wrongly reject a technically valid, hand-typed or case-mangled address — see Appendix A. Every address this network itself emits is already lowercase, so this only matters for input validation, not for anything you generate yourself. | `address.rs:79` + `hex` crate behaviour |
| No version/type byte | Confirmed — the 24-byte payload is exactly `hash(20) ‖ checksum(4)`, nothing else | `address.rs:39-42,74-98` |

A pinned worked example from this repository's own test suite (regression-only,
**not** asserted to correspond to any real, currently-funded key):
`bloch1q89747fe8bda0f0fbad1f107d9852bb5523d446e0db89ce31` (`address.rs:213-220`,
`treasury_address_parses`).

### 5.2 Address → `script_hash` derivation — the exact rule, and where it is incomplete

The eUTXO ledger's ownership check, `owns(key_hash, script_hash)`
(`bloch-pos-committee/src/transition.rs:2061-2103`), accepts **two** distinct
32-byte `script_hash` shapes, with **no epoch gate** on either — this rule is
identical either side of every activation gate in §3:

```rust
fn owns(key_hash: &[u8; 32], script_hash: &[u8; 32]) -> bool {
    if key_hash == script_hash { return true; }              // "Native"
    script_hash[20..] == [0u8; 12] && key_hash[..20] == script_hash[..20]  // "Carried"
}
```

- **Native (primary rule)**: `script_hash` is the **full, untruncated 32-byte**
  `SHA3-256(spender's public key)` — exact 32-byte equality. This is what a
  genuinely new Genesis-4 output uses when the payer knows the recipient's
  full public key. **An address string alone cannot express this form** — it
  only ever carries the 20-byte truncated hash, never the other 12 bytes a
  Native `script_hash` would need.
- **Carried (legacy-compatible form)**: the first 20 bytes of `script_hash`
  equal the first 20 bytes of `SHA3-256(pubkey)` (exactly the address hash of
  §5.1), and the last 12 bytes are zero — **right-padding**, zeros appended
  after the hash. This is the form a payer constructs when they only have a
  `bloch1q…` address string.
- **Both are accepted, unconditionally, by both wire formats (V1 and V2, §8.1–8.2).**
  The Carried form gives an output **160 bits of preimage resistance rather
  than 256**, stated explicitly in-code as the accepted cost of carrying a
  Genesis-3 balance across, not a defect introduced by carrying it.

**Worked example**, using the address above
(`bloch1q89747fe8bda0f0fbad1f107d9852bb5523d446e0db89ce31`):

```
address body (48 hex) = 89747fe8bda0f0fbad1f107d9852bb5523d446e0 db89ce31
                          \_______________ hash (40 hex / 20 B) ______/ \checksum(8 hex)/

script_hash (Carried form, 64 hex / 32 B) =
  89747fe8bda0f0fbad1f107d9852bb5523d446e0            <- the 20-byte hash, unchanged
  000000000000000000000000                            <- 24 zero hex chars = 12 zero bytes

  = 89747fe8bda0f0fbad1f107d9852bb5523d446e0000000000000000000000000
```

```js
// address (55 chars) -> script_hash (64 hex), Carried/legacy form
const scriptHash = addr.slice(7, 47) + "0".repeat(24);
```

<div class="warn">

**This derivation is correct only for the Carried form — it is not "the"
general Genesis-4 `script_hash` rule.** A Native, full-32-byte `script_hash`
exists, is equally spendable, and **cannot be derived from an address string at
all** — it can only be constructed by whoever holds (or was given) the raw
public key. If your exchange ever receives funds paid to a Native `script_hash`
rather than the address-derived Carried form, no address string will exist to
represent it; you must record and reconcile against the `script_hash` itself.
Whether the production WASM wallet defaults new Genesis-4 receive addresses to
the Carried or Native form is **OPERATOR-ASSERTED** — this repository does not
contain that wallet's code (§6).

</div>

### 5.3 Node key-on and self-check

Every balance/UTXO-reading RPC method (`getbalance`, `getutxos`/`listunspent`,
`gettxout`) takes a 32-byte `script_hash`, never an address, and **every
response echoes the `script_hash` it used** — compare it against what you sent
as a one-line integration self-check (`rpc.rs:1089,1109-1120,2126-2193`).

---

## 6. Keys and wallets

**The node holds no keys.** `bloch-pos-node`'s only cryptographic calls are
signature *verification* and validator-keystore generation for its own
(optional) consensus duties — never a wallet spending key
(`crates/bloch-pos-node/src/main.rs:202-203`, `keys.rs`). All wallet signing is
client-side.

### 6.1 BIP39 seed derivation — two versions, and the rule for new vs. existing wallets

`bloch-crypto::wallet::seed::SeedPhrase` (`crates/bloch-crypto/src/wallet/seed.rs`):

| Version | KDF | Status |
|---|---|---|
| `V1LegacyPbkdf2Sha256` | PBKDF2-HMAC-**SHA-256**, 2048 rounds | **Not standard BIP39.** Kept only so a wallet created before the fix (K-M3) still opens under the same keys. **No automatic migration exists, ever** — a V1 wallet keeps deriving under V1 forever (a stated founder decision: "there is no automatic migration or sweep"). |
| `V2Bip39Sha512` | PBKDF2-HMAC-**SHA-512**, 2048 rounds | The correct, standard BIP39 derivation. **Default for every newly generated wallet.** |

Both versions are pinned against the official BIP39 (Trezor) test vectors; the
legacy SHA-256 path is separately pinned so it cannot silently drift and
strand V1 wallets. 24-word (256-bit entropy) is the default mnemonic length;
12-word (128-bit) is also accepted. Only the first 32 bytes of the 64-byte
BIP39 seed feed key generation.

<div class="warn">

**Recovering an unlabeled mnemonic must derive BOTH candidates and
disambiguate — never guess one.** Because there is no automatic migration and
no way to tell which version produced a given address without trying both, the
reference recovery path (`Wallet::recover_ambiguous` /
`Wallet::recover_resolved`) derives under both `V1` and `V2` and picks the
correct one only by matching a known address string or on-chain history.
**What an exchange must record when generating a cold wallet from a mnemonic**:
the mnemonic phrase itself (and BIP39 passphrase, if any — see below), **which
`SeedVersion` was used**, and the network (mainnet — affects only the address
string prefix, not the key). Losing the version record turns a mnemonic into
an ambiguous recovery problem.

</div>

The optional 25th-word BIP39 passphrase **is implemented and tested**
(`to_seed_bytes_versioned`) — this contradicts a stale top-of-file doc comment
in the same module that still claims it is "not implemented"; the code and its
test vectors are the authority, and passphrase-protected mnemonics are
supported.

### 6.2 A separate HD-wallet path exists — different pipeline, no BIP-32 path strings

`bloch-crypto::hd_wallet::HdWallet` (`crates/bloch-crypto/src/hd_wallet/mod.rs`)
does **not** go through the versioned `SeedPhrase` module above at all — it
calls the standard `bip39` crate's own `Mnemonic::to_seed(passphrase)`
directly, which is always the standard BIP39-HMAC-SHA512 construction (the
V1/V2 ambiguity of §6.1 does not apply here). Per-address keys are **not** a
standard BIP-32 hierarchical path — there is no `m/44'/…'/…'/0/i` string
anywhere in this crate. Instead: `diversified_seed(master_seed, index) =
SHA3-256("bloch:diversifier:v1" ‖ master_seed ‖ index_u32_LE)`, then key
generation on that 32-byte result. Each address is independent and unlinkable
from any other except via the master seed; there is no parent/child chain code
and no hardened/non-hardened distinction. **If your exchange's cold-wallet
tooling assumes a BIP-32-style derivation path string, this repository's HD
wallet implementation does not use one — confirm which derivation convention
the production wallet library actually implements (OPERATOR-ASSERTED, see
below) before building around an assumed path scheme.**

### 6.3 Secret-key envelope

Secret keys use the identical suite-envelope scheme as public keys and
signatures (§4): prefix `b10c0100` (`0xB1 0x0C` magic + suite `0001` LE) before
the secret-key body (`wrap_envelope(SUITE_MLDSA65_FALCON1024, &sk)`,
`crypto/mod.rs:73`). **VERIFIED-IN-CODE**, applies uniformly to public keys,
secret keys, and signatures.

### 6.4 The WASM signing library — OPERATOR-ASSERTED

<div class="warn">

**This repository does not contain the production wallet-signing library.** An
exhaustive, repository-wide search for the exact symbol names edition 1 names
— `bw_call`, `new_mnemonic`, `wallet_from_mnemonic`, `g4_transfer_preview`,
`g4_build_and_sign_transfer` — finds **zero occurrences**, in any language, in
this tree. `bloch-crypto`'s `Cargo.toml` does describe compiling a "pure
wallet/crypto subset … used by the WASM mobile wallet", so the library
plausibly shares primitives with the crate this document cites throughout §4
and §6.1–6.2, but this cannot be confirmed here. Everything about that
library's behaviour — its exact dispatcher shape, whether it emits Transfer V1
or V2 (§8.2), whether it defaults to a Native or Carried `script_hash` (§5.2),
which `SeedVersion` it selects, and the specific "re-sign on Falcon overshoot"
retry mechanics (§4) — is **OPERATOR-ASSERTED**, carried forward from edition
1's naming, with the caveat that it is not in the audited repository and this
edition neither confirms nor updates any fact about it.

</div>

---

## 7. Block format

Header fields returned by `getblockbyslot` / `getblockbyid`, distinguishing the
**304-byte consensus header** (`crates/bloch-pos-committee/src/header.rs`,
`BlockHeaderV4`) from the fields the RPC layer *derives* at serve time.

### 7.1 Consensus header (`BlockHeaderV4`, exactly 304 bytes, 12 fields)

| Field | Type | Byte offset | Notes |
|---|---|---|---|
| `version` | `u32` LE | 0 | Fixed magic `0xB10C_0005` (decimal 2,970,353,669). **Never "fix" this to a friendly `4`** — a client recomputing `block_id` hashes these exact bytes. |
| `parent` | `[u8;32]` | 4 | Parent `block_id` |
| `state_root` | `[u8;32]` | 36 | Committed state root after this block |
| `body_root` | `[u8;32]` | 68 | Root over the block's **transactions only** (`derive::body_root`, `derive.rs:141-153`) — **attestations are a separate tree, committed by `attestation_root` below, not by this field.** |
| `slot` | `u64` LE | 100 | Slot index; may exceed height (slots can be missed) |
| `proposer_index` | `u32` LE | 108 | Validator index of the proposer |
| `randao_reveal` | `[u8;32]` | 112 | This block's RANDAO reveal |
| `randao_mix` | `[u8;32]` | 144 | Chain RANDAO mix after this reveal |
| `justified_root` | `[u8;32]` | 176 | **The block producer's own** justified checkpoint root as of build time |
| `finalized_root` | `[u8;32]` | 208 | **The block producer's own** finalized checkpoint root as of build time |
| `attestation_root` | `[u8;32]` | 240 | Root over the block's attestations (`derive::attestation_root`, `derive.rs:172-178`) — a distinct tree from `body_root` above, with its own leaf tag |
| `coherence_root` | `[u8;32]` | 272 | Root over the Coherence privacy-layer tree |

**The header carries no `height`, `tx_count`, `attestation_count`, or
`timestamp` field** — the old PoW/DAG fields (`bits`, `nonce`, `parents:
Vec<_>`) are removed relative to the predecessor format. `block_id =
SHA3-256(DS_BLOCK ‖ canonical_serialize(header))` — the sole derivation path,
structurally enforced. The proposer's signature is over a **separately**
domain-tagged digest (`DS_PROPOSE`), specifically so a signature can never be
confused with, or replayed as, a block identity.

### 7.2 Fields the RPC layer adds (present in every `getblockbyslot`/`getblockbyid` response, not in the header)

| Field | Type | Source / meaning |
|---|---|---|
| `block_id` | 64-hex | Derived, §7.1 |
| `height` | `u64` or `null` | Block height (settlement key, §2.5). `null` when this node cannot place the block on its own canonical chain. **Height ≠ slot**: `height` is strictly monotonic per canonical block; `slot` can skip. |
| `epoch` | `u64` | Computed `slot / 32` — not a header field |
| `timestamp` | `u64` unix seconds | **Derived from `slot` for display only — not a consensus field.** `BlockHeaderV4` carries no time at all. |
| `finality` | string: `"finalized"\|"justified"\|"canonical"\|"not_canonical"` | This *node's own* current classification of the block (§2.9), not the producer's committed roots above |
| `finalized` | **boolean** | `true` only if `finality == "finalized"`. **See the warning below.** |
| `tx_count` | `u64` | `body.transactions.len()` — a count only; **the header/body carries no way to enumerate which txids a block contains via this RPC surface.** |
| `attestation_count` | `u64` | Count of attestations in the body |

<div class="warn">

**Edition 1's block-format table is wrong about `finalized`'s type — this is
the single highest-severity field-shape correction in this edition.** Edition
1 (§5) lists a per-block `finalized` field as an **object**, `{epoch, root}`
"finalized checkpoint". On the actual `getblockbyslot`/`getblockbyid`
response, **`finalized` is a plain boolean** (`Json::Bool(finality.is_final())`,
`rpc.rs:1893`). The `{epoch, root}` object shape does exist — but only as a
field of the **different** `getchaininfo` response (§10.3), describing this
node's *current* finality state, not any one block's. A client written against
edition 1's table that tries to read `.epoch`/`.root` off a block response's
`finalized` field will get a type error or silently mis-parse a boolean as
truthy/falsy. **The field to compare against `finalized_height` for crediting
is `getchaininfo`'s (or `getblockcount`'s) `finalized_height` integer (§11),
never this per-block boolean, and never the per-block `finalized_root` header
field either** (that one is the *producer's* view at build time, already stale
by the time you read it).

</div>

---

## 8. Transactions

eUTXO transactions with deterministic, non-malleable identifiers. A
transaction consumes explicit unspent outputs and creates new ones.
Conservation is a **strict equality**: `sum(inputs) = sum(outputs) + fee`.

### 8.1 Transfer V1 (wire tag `0x01`)

```rust
Transfer {
    inputs: Vec<TransferInput>,     // { txid: [u8;32], vout: u32, pubkey: Vec<u8>, signature: Vec<u8> }
    outputs: Vec<TransferOutput>,   // { value: u64, script_hash: [u8;32] }
    tx_bytes: u64,                  // declared payload size — see §8.6
    tip_millisat_per_gas: u128,     // the ONLY sender-set price term — see §8.5
}
```

Canonical encoding, tag `0x01`: `u32 n_inputs ‖ {txid(32) ‖ vout(4 LE) ‖
len‖pubkey ‖ len‖signature}* ‖ u32 n_outputs ‖ {value(8 LE) ‖ script_hash(32)}*
‖ tx_bytes(8 LE) ‖ tip_millisat_per_gas(16 LE)`. Every variable-length field is
`u32`-length-prefixed; every fixed field is little-endian. Trailing bytes
after a full parse are a decode error — no two byte strings decode to one
transaction. This is the exact byte string the header's `body_root` Merkles
over per transaction.

### 8.2 Transfer V2 — deduplicated witness table (wire tag `0x06`)

```rust
TransferV2 {
    keys: Vec<WitnessKey>,          // one (pubkey, signature) per OWNER, not per input
    inputs: Vec<TransferInputV2>,   // { txid: [u8;32], vout: u32, key_index: u32 } — 40 bytes fixed, no per-input witness
    outputs: Vec<TransferOutput>,
    tx_bytes: u64,
    tip_millisat_per_gas: u128,
}
```

**Live and active since epoch 800** (`TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH`,
§3), i.e. active for essentially this entire chain's operating history —
**edition 1's transaction-type table omits it entirely.** What it changes:

1. Each owner's `(pubkey, signature)` appears once in `keys`; each input
   references it by `key_index`. Gas is charged per **owner** in the table,
   not per input — cheaper for a multi-input, single-owner sweep.
2. Two consensus-level table disciplines with no V1 analogue: `keys` must be
   **strictly ascending by pubkey bytes** (an inversion or duplicate is a
   reject), and every table entry must be referenced by at least one input
   (an unreferenced entry is unpaid, relay-stuffable padding). Both close a
   malleability class that would otherwise exist because the table sits
   **outside** the signing root (§8.3).
3. `spend_signing_root` — and therefore `txid` — is **byte-identical** between
   the V1 and V2 encoding of the same logical transfer. A wallet's signature is
   valid under either wire shape; only the encoding and admission rules
   differ.
4. Same `owns()`-before-signature ownership check as V1 (§5.2), applied per
   input against the indexed key.

**This repository's own reference CLI (`bloch-pos submit-tx`) emits only V1**
— by explicit doc comment, "the only variant this emits on purpose." Whether
the production wallet library emits V1 or V2 is **OPERATOR-ASSERTED** — not
verifiable from this tree.

<div class="note">

**Practical consolidation-sizing guidance, for a UTXO-sweep design.** V1's
per-input witness duplication has a measured (2026-08-21) real limit: N inputs
owned by one key each carry their own 3,749 B key and up to 4,775 B proof, and
that caps a 262,144 B block at **~30 inputs** sharing one owner
(`transition.rs:207-212`). Since `BLOCK_BYTES_V2_ACTIVATION_EPOCH` is active
(§3, the live cap is 524,288 B), the equivalent V1 figure today is roughly
double that, **~60 inputs** per block for a single-owner sweep encoded as V1.
TransferV2 (above) removes this bound for a single-owner sweep entirely — one
key and one signature are charged regardless of how many inputs reference
them — so an exchange consolidating many small deposits under one key should
prefer V2 once its wallet tooling supports it, rather than sizing sweeps
around the V1 ~30/~60-input ceiling.

</div>

### 8.3 Signing root, `txid`, and the non-consensus `tx_hash`

- **`spend_signing_root()`** (one shared fold, called identically by both V1
  and V2): `DS_SPEND ‖ n_spends ‖ each (txid,vout) ‖ n_outputs ‖ each
  (value,script_hash) ‖ tx_bytes ‖ tip_millisat_per_gas`. **Witnesses
  (signatures, pubkeys, the V2 table, `key_index`) are explicitly OUTSIDE this
  root** — the code's own doc: "excluding them is the only construction that
  terminates."
- **`txid = SHA3-256(DS_TXID ‖ spend_signing_root())`** — deterministic and
  known **before broadcast**; it is the key of every `(txid, vout)` output the
  transfer creates in the committed eUTXO set. **Track deposits and
  withdrawals by this value.**
- **`checked_signing_root(epoch)`** is what a signature is actually verified
  against; below the inert `SIGHASH_NETWORK_BINDING_ACTIVATION_EPOCH` (§3.2)
  this equals `spend_signing_root()` unchanged.
- **`tx_hash`** (a **different**, node-local, non-consensus quantity, echoed
  only by `sendrawtransaction`'s response): `SHA3-256(canonical_bytes())` —
  this **includes** the witnesses, so it is malleable (different witness bytes
  for the same logical spend produce a different `tx_hash`), and **no block
  ever commits to it**. `sendrawtransaction`'s response does **not** carry the
  real `txid` at all (§10.5) — compute it client-side or read it back off the
  eUTXO set once included.

### 8.4 Conservation — exact equality, valid at exactly one base fee

```rust
let created: u128 = outputs.iter().map(|o| o.value as u128).sum();
let fee = charge.base_fee_sat + charge.priority_fee_sat;
if spent_value != created + fee { return Err(TransferReject::ValueNotConserved); }
```

`!=`, not `<` or a tolerance band — **there is no way to overpay and have the
excess simply forfeited**; any mismatch in either direction refuses the whole
transaction. The **base-fee** term is entirely protocol-set from the
including block's committed `base_fee_millisat_per_gas` and is not something a
transaction declares; the **tip** term (`tip_millisat_per_gas`) is the only
sender-controlled price lever, and it is fixed at signing time (folded into
`spend_signing_root`). Because `outputs`, `tip`, and `gas` (a pure function of
transaction shape) are all fixed at signing, the **only** variable in the
equality that can move between signing and inclusion is the including block's
base fee. **A transfer built against base fee `B` satisfies the equality only
in a block whose committed base fee is exactly `B`.** If the base fee has
moved by the time a proposer tries to include it, the identical bytes fail
`ValueNotConserved` — there is no retry-with-slack; the transaction must be
rebuilt against whatever the current base fee is.

<div class="note">

**The full `TransferReject` taxonomy that `-32008`'s free-text message
collapses into.** §10.6 already warns not to parse a `-32008` message's text;
this is the underlying reason taxonomy to build structured client-side
diagnostics against instead (`bloch-pos-committee::interfaces::TransferReject`,
`interfaces.rs:467-600`, checked in the order listed — cheapest first,
signature verification last):

`NoInputs` (spends nothing) · `UnderdeclaredSize` (`tx_bytes` below the real
encoding) · `OverdeclaredSize` (above it by more than the mempool slack, inert
at consensus, §3) · `TipAboveCeiling` (`tip_millisat_per_gas` over
`MAX_TIP_MILLISAT_PER_GAS`) · `TxGasCeilingExceeded` (intrinsic gas over
`MAX_TX_GAS`) · `DuplicateInput` (same outpoint spent twice in one transfer) ·
`UnknownInput` (outpoint absent from the unspent set) · `ScriptMismatch`
(supplied key does not match the output's `script_hash`) · `BadSignature` ·
`ValueNotConserved` (§8.4, above) · `OutputExists` (a `(txid,vout)` collision —
unreachable without a SHA3-256 break) · `FormatNotActive` (a `TransferV2`
arriving before its activation epoch) · `BadKeyIndex` (V2 input references a
witness-table slot that does not exist) · `DuplicateWitnessKey` /
`WitnessKeyUnused` / `WitnessTableNotCanonical` (the three V2 witness-table
disciplines of §8.2) · `DustOutput` / `TooManyOutputs` (§8.7 below, inert at
consensus today, enforced as mempool policy).

</div>

### 8.5 Fee model — formula, bounds, and how many blocks a wallet realistically has

EIP-1559 with one change: utilisation is the **max of two resources** (gas axis
vs. byte axis, compared by cross-multiplication) — an eUTXO-heavy block
saturates bytes well under a tenth of the gas cap, so a gas-only controller
would misread a byte-saturated, gas-light block as slack.

```
gas_cross   = parent.gas_used   * byte_target
bytes_cross = parent.tx_bytes   * BLOCK_GAS_TARGET
(used, target) = gas_cross >= bytes_cross
    ? (parent.gas_used,  BLOCK_GAS_TARGET)
    : (parent.tx_bytes,  byte_target)
if used == target:  base unchanged
if used >  target:  base += max(1, base*(used-target)/target/8)   // congested: ALWAYS moves by >=1
if used <  target:  base -= base*(target-used)/target/8
clamp to [MIN_BASE_FEE_MILLISAT_PER_GAS, MAX_BASE_FEE_MILLISAT_PER_GAS]
```

| Bound | Value |
|---|---|
| `MIN_BASE_FEE_MILLISAT_PER_GAS` | `10` msat/gas (genesis price and floor) |
| `MAX_BASE_FEE_MILLISAT_PER_GAS` | `TOTAL_SUPPLY_SAT × 1,000` = `10^22` msat/gas |
| `BASE_FEE_CHANGE_DENOMINATOR` | `8` — max ±⅛ per block |
| `MAX_TIP_MILLISAT_PER_GAS` | same ceiling as the base-fee max, enforced as `TipAboveCeiling` |
| Congestion floor | a congested block's step is floored at `1` — "a congested block must always move the price" |
| Skipped slots | produce no update at all — base fee carries over unchanged |
| Byte target/cap | epoch-gated together with V2 witness dedup (`BLOCK_BYTES_V2_ACTIVATION_EPOCH = 800`, active): cap 262,144→524,288 bytes, target 131,072→262,144 |

<div class="note">

**The exact per-transaction gas formula — needed to compute the fee a
transaction shape actually owes, since §8.4's conservation check refuses any
mismatch with no tolerance, and no RPC method computes this for you:**

```
gas = TX_FLAT_GAS (5,000)
    + tx_bytes * GAS_PER_BYTE (16)
    + n * HYBRID_VERIFY_GAS (72,748)
```

where `n` is the input count for Transfer V1 (`inputs.len()`, §8.1) or the
distinct owner-key count for TransferV2 (`keys.len()`, §8.2) — one hybrid
verification per input in V1, one per witness-table entry in V2. Then:

```
base_fee_sat     = ceil(gas * base_fee_millisat_per_gas / 1000)
priority_fee_sat = ceil(gas * tip_millisat_per_gas     / 1000)
fee              = base_fee_sat + priority_fee_sat
```

(`fee_market.rs:129,133,175` [`HYBRID_VERIFY_GAS`, asserted `== 72_748` at
`fee_market.rs:566`]`,212-229,373-393,495-505`; the V1-vs-V2 class derivation
is at `transition.rs:3713` [V1, `inputs.len()`] and `:3912` [V2, `keys.len()`]).
**There is no fee-estimation RPC method** — `sendrawtransaction` either
accepts or refuses the fully-built transaction, and the frozen method registry
(§10.2) has no call that returns this number. A wallet must derive `gas` from
its own transaction shape and compute `base_fee_sat`/`priority_fee_sat` itself,
before signing.

</div>

**How many blocks does a wallet realistically have?** There is no named
constant for this — it is a derived consequence of §8.4 plus the controller
above: if a transaction is not included in the very next block whose base fee
equals what was assumed, and that block's usage was not exactly at target, the
base fee moves and the transaction fails `ValueNotConserved` in every
subsequent block whose base fee differs. **Practically: one block.** The only
forward-looking signal is `next_base_fee_millisat_per_gas`, present on both
`getchaininfo` and `getmempoolinfo` — the price the *immediately next* block
would charge, computed from the head's own committed usage. There is no way to
predict the base fee two or more blocks out.

### 8.6 Size declaration and the Falcon re-sign phenomenon

See §4's note. In brief: `tx_bytes` must be fixed before the Falcon signature
exists (Falcon's true length is unknowable at signing time); `TX_BYTES_DECLARE_SLACK
= HYBRID_SIG_BYTES` (4,589 B) budgets one signature's worth of overshoot at the
mempool door (node-local policy today; the consensus-level bound
`TX_BYTES_BOUND_ACTIVATION_EPOCH` is inert, §3). An `UnderdeclaredSize` refusal
after signing means: re-sign at a larger declared size (same message, same
`txid`).

### 8.7 Output limits, dust, and the full wire-tag table

| Consensus bound | Value | Gated? |
|---|---|---|
| `MIN_TRANSFER_OUTPUT_SAT` (dust floor) | `1,000` sat | Consensus-inert (`DUST_RULE_ACTIVATION_EPOCH = u64::MAX`) — enforced unconditionally as **mempool** policy today |
| `MAX_TRANSFER_OUTPUTS` | `256` | Consensus-inert, same mempool-policy enforcement today |
| `MAX_BLOCK_TX_BYTES_V2` | `524,288` | Active (epoch 800) |
| `BLOCK_GAS_LIMIT` / `MAX_TX_GAS` | `60,000,000` | Active — one transaction could in principle claim a whole block's gas; bytes bind first in practice |
| `MAX_TXS_PER_BLOCK` | `256` | **Node-local proposer policy, not a consensus count cap** |

**Full wire-tag table**, `PosTransaction` variant space (frozen by an
exhaustive match with no wildcard arm, `tests/wire_tag_registry.rs`):

| Tag | Name | Status |
|---|---|---|
| `0x01` | `Transfer` (V1) | **Live.** Value transfer between script hashes. |
| `0x02` | `Deposit` | **Refused at every epoch, by consensus, on every node — not "not yet armed", structurally and permanently refused by design.** The gating constant's own doc comment states arming it is explicitly *not* how deposits open, and recommends the constant never move. |
| `0x03` | `Exit` | **Live and consensus-valid.** Legacy, unauthenticated (bare registry index, no signature, cannot be revoked); remains the only voluntary-exit path until `EXIT_AUTH_ACTIVATION_EPOCH` arms (inert, §3). Validator-bond impact only, not user funds. |
| `0x04` | `Delegate` | **Refused at every epoch, by consensus, on every node** — same permanent-refusal design as `Deposit`. |
| `0x05` | `SlashingEvidence` | Decodes since 2026-09-05, but the transition refuses the resulting transaction below `SLASHING_EVIDENCE_ACTIVATION_EPOCH` (inert, §2.8/§3). Nothing constructs this transaction outside tests today. |
| `0x06` | `TransferV2` | **Live and active since epoch 800** — see §8.2. **Missing from edition 1's table entirely.** |
| `0x07` | *(contested)* | Five rival claims across branches (`FundedDeposit`, `DepositV2`, `DepositFunded`, `Withdraw`, `SignedExit`) — none live on this lineage. Assignment is a founder decision. |
| `0x08` | *(contested)* | Four rival claims; this tree's own `ExitV2` encodes to it but its decoder deliberately **refuses to decode `0x08`** — the byte `EXIT_AUTH_ACTIVATION_EPOCH` needs settled first. |
| `0x09` | *(contested)* | Two rival claims (`Withdraw`, `ExitV2`); not used by this tree at all. |
| `0x0A` | `RandaoRecommit` (this tree's own, uncontested — the lowest byte with no claimant elsewhere as of the 2026-09-02 sweep) | Encodes but is **deliberately not decodable** pending `RANDAO_RECOMMIT_ACTIVATION_EPOCH` (inert, §3). |
| `0x0B` | *(unassigned in this tree)* | An internal audit report describes a "provisional `0x0B`" for `Withdraw`; **this could not be confirmed anywhere in the current tree's wire-tag registry** — no `PosTransaction` variant encodes to it and the registry's own table has no `0x0B` row. Do not treat `0x0B` as assigned without separate confirmation from the project. |

<div class="note">

**What `sendrawtransaction` actually returns for a `Deposit`/`Delegate` payload
(`0x02`/`0x04`).** Both are refused immediately at the mempool door by
`admissible()` (`engine.rs:5362-5410`) as `Refusal::Invalid`, which the RPC
layer surfaces as **`-32008 TX_REFUSED`** (`engine.rs:4069-4074`) — the same
terminal, do-not-retry code any other structurally-invalid transaction gets,
not a distinct code and not deferred to block-proposal time. A wallet that
ever emits one of these by mistake (e.g. a library bug picking the wrong wire
tag) gets an immediate, terminal answer at broadcast time, not a delayed one.

</div>

<div class="warn">

**There is no stake-withdrawal transaction on Genesis-4 today, at any wire
tag.** `WITHDRAWAL_ACTIVATION_EPOCH` is inert **and unwired** — its own doc
comment states it "gates NOTHING today": no `PosTransaction::Withdraw` variant
exists in the frozen variant space, and even the committed validator-record
type has no field to mark a bond as paid out. Combined with `Deposit`/`Delegate`
being structurally, permanently refused (`0x02`/`0x04` above): **an exchange
cannot stake customer funds on-chain today, under any circumstance, and cannot
withdraw a stake even if one somehow existed.** The 64 genesis validators are
the entire committee and it cannot currently grow.

</div>

---

## 9. Mempool and broadcast

**Admission pipeline** (`on_transaction`, node-local policy, checked in this
exact order):

1. Byte-identical to something already pending → `Admitted::Duplicate` (a
   success, not an error).
2. Currently barred against state (see below) → `TX_REFUSED_RETRYABLE`
   (`-32009`) — checked **before** capacity so a mempool full of barred
   transactions never wrongly reports "at capacity" as the reason.
3. **Per-source cap**: `MEMPOOL_MAX_PER_SOURCE = 64` — one spend-authority
   source (identified by the first input's/table entry's pubkey hash) may have
   at most 64 pending transactions; a 65th is refused with `-32010`
   (`TX_REFUSED_SOURCE_CAP`) unless it outbids that source's own lowest-tip
   pending entry, which is evicted to make room.
4. **Overall capacity**: `MEMPOOL_MAX = 4,096`. At capacity, the lowest-tip
   entry is evicted **only if** the incoming transaction's tip rate is
   strictly greater (ties do not evict); eviction is decided here but
   committed only after the next check passes, so a garbage-signature flood
   cannot evict a real payer for free.
5. **Stateless admissibility**: non-empty structure, dust/count bounds (§8.7),
   price bounds, declared-size bound (§8.6), V2 table discipline, and
   **finally** the spend signature(s) — cheapest checks first, signature
   verification last. What this stateless check does **not** verify: whether
   the spent outpoints exist or are unspent, whether the fee matches the
   *current* base fee, or (V2) the script match — those need committed state
   and are only caught later, at proposal time.
6. New entry inserted keyed by canonical bytes; re-broadcast on first sight
   only.

**Retention and eviction** — three independent mechanisms:

- `MEMPOOL_TTL_SLOTS = 100` (node-local, not consensus): unincluded for more
  than 100 slots of head progress → dropped, no bar applied. Counted in
  `getmempoolinfo.expired`.
- A per-epoch sweep marks a transaction "suspect" if its spent outpoints are
  missing from the committed state; if **still** missing on the *next*
  epoch's sweep, it is evicted **and** barred (a two-strikes design, so a
  transaction merely waiting on an unconfirmed parent is not punished on
  first look).
- The proposer's own probe-drop loop: while building a candidate block, on
  any transition error the culprit transaction is popped, removed from the
  mempool, barred, and the proposer retries with the rest.

**The rejection bar — `REJECTION_TTL_SLOTS = 128` slots (≈64 minutes) — lapses,
it is never permanent.** `is_rejected` returns a bar only while `until_slot >
current_slot`; the doc header on the constant is explicit about **why a ban
expires instead of being permanent**: a transaction refused for a missing
input today may be a perfectly legitimate chained spend whose parent simply
hasn't landed yet, and a permanent bar would make that coin permanently
unmovable. The bar cache itself is capped at 4,096 entries, evicting the
soonest-to-lapse when full.

<div class="warn">

**Resubmitting identical bytes is NOT permanently invalid — do not build
integration logic that assumes it is.** Three cases: (A) still pending →
silently deduplicated (`Admitted::Duplicate`); (B) already dropped and
currently barred → `-32009` `TX_REFUSED_RETRYABLE`, **temporary**, lifts after
`error.data.until_slot`; (C) already dropped and the bar has since lapsed →
freshly re-admitted as new, and will be dropped and barred again for the same
underlying reason if it hasn't changed. The node's own source contains a named
admission that treating a `-32008`/`-32009`-class refusal as uniformly
permanent is a **real, previously-published integration mistake on this
project**: "our own published integration guidance says never to resubmit
after -32008, so an exchange following it permanently abandoned transactions
the node would have taken an hour later." Only `-32008` (`TX_REFUSED`) is
genuinely terminal — a verdict on the bytes themselves (bad signature, empty
witness table, structural shape); `-32009` (`TX_REFUSED_RETRYABLE`) is
state-dependent and self-expiring. See §10.6 for the full retry policy.

</div>

**Ordering**: candidate-block packing is sorted by `tip_millisat_per_gas`
**descending**, ties broken by canonical-bytes ascending (replacing a prior,
gameable pure-lexicographic order). Packing is budgeted by the *larger* of
wire length and declared `tx_bytes`, so consensus's own byte-cap accounting
(which sums declared sizes) is never under-counted by the packer.

**On a base-fee change**: rebuild the transaction against the new
`next_base_fee_millisat_per_gas` (§8.4/§8.5) — do not resubmit the same bytes
expecting them to eventually clear at the old fee.

**Broadcast acknowledgement semantics**: `sendrawtransaction`'s success
response (`accepted: true`) means the node took the bytes into its mempool —
**it is a queue acknowledgement, not a receipt, and it is not the presence of
the transaction in a block.** See §10.5 for its exact field shape (notably: no
`txid`).

---

## 10. JSON-RPC API

### 10.1 Transport

| Property | Value |
|---|---|
| Protocol | JSON-RPC 2.0 over HTTP POST, one call per connection |
| Verb | **POST only** — any other verb, **including `OPTIONS`**, is refused with HTTP `405` before any other header is even checked. **There is no CORS preflight support on the node's own RPC** — no `Access-Control-*` header is ever sent, on success or refusal, on any path. |
| `Content-Type` | Must be `application/json` (case-insensitive; `;`-parameters after it, e.g. `; charset=utf-8`, are ignored) — else HTTP `415`. |
| `Origin` | **If present at all, regardless of value** (including the server's own origin or the literal string `"null"`) → HTTP `403`. No allowlist, no wildcard-for-reads split. This defeats a forged cross-origin submit to the state-changing `sendrawtransaction` method, and it means **a browser cannot call a Genesis-4 node's raw RPC directly** — every modern browser attaches `Origin` even to a same-origin fetch. |
| `Host` | Must equal (ignoring a `:port` suffix): `127.0.0.1`, `localhost`, `::1` (always allowed), the node's own literal `--rpc-bind` address (unless it is the wildcard `0.0.0.0`/`::`), or an entry in the comma-separated **`BLOCH_RPC_HOST_ALLOWLIST`** environment variable (read once at process start, not per request) — else HTTP `403`. Defeats DNS rebinding. |
| Body size | `Content-Length` required (else `411`); refused with `413` above `MAX_BODY_BYTES = 1,048,576` bytes (1 MiB), before a single body byte is read. Header block capped at `MAX_HEADER_BYTES = 16,384` bytes (`431` if exceeded). |
| Connections | `MAX_CONNECTIONS = 64`, a **global** cap (not per-IP) — past it, `503 {"error":"too many connections"}`, connection closed without spawning a handler. **There is no per-IP rate limit anywhere on this surface** — stated explicitly in-code as an anti-exhaustion, not an authorisation, bound. |
| Keep-alive | **None.** Every response includes `Connection: close` — one request per TCP connection. A client library that pools connections will find them closed after each reply. |
| Batching | **Explicitly refused, not silently answered per-item.** A top-level JSON array → `-32600 invalid request`, `"batch requests are not supported; send one call per request"`. |
| Params | **Both a positional JSON array and a named JSON object are accepted, for every parameterized method** — `pick(params, pos, name)` reads either form. Edition 1 said "named object"; the in-repo integration guide said "positional array"; **both are individually correct and incomplete** — the code supports both, and the repository's own explorer client (`apps/explorer/src/lib/g4.ts`) uses the positional-array form against this exact endpoint family. |
| Timeouts | `IO_TIMEOUT = 30s` per connection; `ENGINE_TIMEOUT = 10s` for a call to wait on the consensus thread before `-32004 NODE_UNAVAILABLE` (`getbalance`/`getutxos` are exempt — served directly off a published snapshot, not round-tripped through the consensus thread). |
| Chunked transfer-encoding | Not implemented — `411`. |
| TLS | **None, at the node — plaintext HTTP only.** The RPC module's own doc comment states this outright ("no TLS, no compression"): there is no certificate, no negotiation, and no encrypted-transport option of any kind on this port. Terminate TLS yourself (an SSH tunnel, or your own reverse proxy — §13.5) before this port is reachable beyond a trusted network. |

<div class="warn">

**"CORS enabled; OPTIONS preflight answered (204)" (edition 1's transport
table) is false for the node itself.** At the node directly, there is no CORS
support of any kind and any non-POST verb, OPTIONS included, gets `405`, not
`204`. This may be accurate for the public proxy in front of the fleet (a
Cloudflare Worker, OPERATOR-ASSERTED, not in this repository) — but it is not
what a self-hosted, directly-connected node answers, and this document's own
§13 recommends exactly that deployment. A browser-based tool or an SDK that
always attaches `Origin` will be unconditionally refused against a direct
node.

</div>

<div class="warn" markdown="1">

**HTTP heads are parsed strictly since the 2026-09-07 security-audit merge (F03/F04, `rpc.rs`).** A request is refused with `400` if it carries a duplicate `Content-Length`, `Host` or `Content-Type` field, a field name that is not an HTTP token, a control byte in a field value, a malformed request line (missing target, unknown HTTP version, extra tokens), or a non-decimal / overflowing `Content-Length`; the 16 KiB head cap now counts the terminating `CRLFCRLF` and is enforced while reading (`431`). The whole request — head and body — must arrive within one monotonic deadline: a client that trickles bytes to renew a per-read timeout is disconnected (`408`). Well-formed clients see no change.

</div>

### 10.2 Full method reference

Every method in the frozen registry (`method_registry.rs`, `tests/rpc_method_registry.rs`):

| Method | Params (name, type; position) | Returns | Notes |
|---|---|---|---|
| `getchaininfo` | none | See §10.3 | |
| `getbuildinfo` | none | `build_version, package_version, commit, commit_source (git\|asserted\|none), tree_state (clean\|modified\|unverified\|unknown), source_digest (sha3-256 hex), source_digest_alg, source_digest_scope, source_files, source_bytes, rustc, profile, target, digest_note` | Constant cost, no chain-state read. Compare `source_digest` across nodes you trust — identical digests mean identical *source*, not identical binary behaviour (see the warning below). |
| `getblockcount` | none | `height, slot, epoch, finalized_height (u64\|null), justified_epoch, finalized_epoch` | |
| `getblockbyslot` | `slot` (u64; pos 0) | Block object, §7.2 | `-32007 SLOT_EMPTY` if no canonical block at that slot (message names the current head) |
| `getblockbyid` | `block_id` (64-hex; pos 0) | Block object, §7.2 | `-32000 BLOCK_NOT_FOUND` if unknown |
| `getvalidator` | `index` (u32; pos 0) | `index, pubkey_hash (64-hex, SHA3-256 of the raw pubkey — NOT the pubkey itself), pubkey_bytes (u64, LENGTH of the stored pubkey, not the key material), state (slashed\|exited\|exiting\|queued\|active), own_stake_sat (string), effective_stake_sat (string\|null — null means "not in the sampled set this epoch", distinct from zero), commission_bps (STRING), randao_commitment (64-hex), slashed (bool), activation_epoch/exit_epoch/withdrawable_epoch (u64\|null, null = "never")` | `-32001 VALIDATOR_NOT_FOUND` if index unknown |
| `getvalidatorcount` | none | `total, active, total_active_stake_sat (string)` | |
| `getvalidators` | none | Array, one entry per registered index: `index, pubkey_hash, status, effective_stake_sat (string\|null), commission_bps` — **a PLAIN JSON NUMBER here**, not the string `getvalidator` uses for the same-named field | **Missing from edition 1 entirely.** Whole registry in one call, no pagination (bounded in practice by the 64-validator ceiling). |
| `getbalance` | `script_hash` (64-hex; pos 0) | `script_hash, balance_sat (string), utxo_count (u64)` | |
| `gettxout` | `txid` (64-hex; pos 0), `vout` (u32; pos 1, **optional, defaults to 0**) | `txid, vout, unspent (bool), utxo (object\|null — the IDENTICAL 4-field object one `getutxos` entry is: `txid, vout, value_sat, script_hash` — see the note below), at_slot (u64 — the HEAD SLOT THIS NODE ANSWERED FROM, not the output's creation slot — see §11)` | |
| `getutxos` / `listunspent` (aliases, one implementation) | `script_hash` (64-hex; pos 0), `limit` (u32; pos 1, **not** "page" or "offset" — optional, default 100, **clamped** 1..=1,000) | `script_hash, total (u64), returned (u64), truncated (bool), utxos[{txid, vout, value_sat (string), script_hash}]` | **No third parameter of any kind is read** — see §10.4. |
| `sendrawtransaction` | `hex` (string, canonical tx bytes; pos 0) | See §10.5 | The only write method |
| `getmempoolinfo` | none | `size, max (=4096), bytes, next_base_fee_millisat_per_gas (string), barred, barred_hits, expired, evicted_low_fee` | **8 fields, not 4** — see the warning below |
| `gettxstatus` | `txid` (64-hex; pos 0) | `{"status": "pending"\|"included"\|"justified"\|"finalized"\|"unknown"}` | **Missing from edition 1 entirely; see the caveat in §10.6 before using its `"finalized"` value for crediting.** |

**Not exposed by design** (routed, dedicated error codes — see §10.6):
`gettransaction` (by hash — the chain is indexed by output, not by account, and
the node has no txid→block index) and `getnewaddress` (the node holds and
mints no wallet). `getblocktemplate`, `submitblock`, `getcapabilities`,
`getnodeversion`, `getversion`, `getidentity`, `getbuild`, `getnodeinfo` are
**not routed at all** → generic `-32601`. **`getcapabilities` not existing is
itself load-bearing**: there is no machine-readable way for a client to ask
this node what it currently guarantees about finality/slashing — that
information is prose-only (§2.8/§2.9), and this document, `SECURITY.md`, and
the in-repo integration guide are where it lives.

<div class="note">

**`gettxout`'s `utxo` object is byte-for-byte the same 4-field shape a
`getutxos` entry is** — `{txid, vout, value_sat, script_hash}`, built by the
identical `eutxo_json` helper in both cases (`rpc.rs:2110-2117`, called from
`rpc.rs:2176-2193`). It is **not** missing `script_hash`; the sample response
in §10.8 already shows it present. Do not build a client that special-cases
`gettxout`'s `utxo` field as a 3-field, `script_hash`-less shape.

**No RPC method on this surface reconstructs a settled transaction's history**
— its actual inputs, the fee/tip it actually paid, or its `kind` — once it is
included in a block. `gettxout`/`getutxos` expose only a live *output*'s
existence/value/script_hash, never the transaction that created it;
`getblockbyslot`/`getblockbyid` expose only `tx_count` (§7.2), a count with no
txid list. Plan any fee-reconciliation or incident-postmortem tooling around
this limit: correlate by the `txid` you already computed client-side before
broadcast (§8.3), never by asking the chain to enumerate or explain a
transaction after the fact — there is no RPC primitive that does either.

</div>

<div class="warn">

**`getmempoolinfo` returns 8 fields today, not the 4 edition 1's method table
and sample response show.** `barred` (currently barred transactions),
`barred_hits` (re-offers actually turned away), `expired` (dropped for age),
`evicted_low_fee` (evicted for a higher-fee arrival) are all live. This gap is
not hypothetical: the node's own `getbuildinfo` doc comment cites, as the
reason that method exists, an incident where "on 2026-09-02 both public
archivals answered `getmempoolinfo` with four fields where this build emits
six" — the count has since grown again, to eight, with no version signal on
either side to show the drift. Do not assume a fixed field count for this
method; compare `getbuildinfo.source_digest` across nodes if the exact shape
matters to your integration.

</div>

### 10.3 `getchaininfo` — full field list

`block_id` (64-hex), `slot` (u64), `height` (u64), `finalized_height` (u64 or
null), `epoch` (u64), `slot_in_epoch` (u64), `slots_per_epoch` (u64, `=32`),
`state_root` (64-hex), `justified` / `finalized` / `previous_justified` (each
`{epoch: u64, root: 64-hex}`), `validators` (`{total, active}`),
`total_active_stake_sat` / `base_fee_millisat_per_gas` /
`next_base_fee_millisat_per_gas` (decimal strings), `mempool` (u64),
`blocks_known` (u64), `wall_slot` (u64), `behind_by_slots` (u64),
`transport` (`{name: "devnet"|"libp2p"|"dual", peers: {devnet: u64|null,
libp2p: u64|null}}`). The last four fields (`blocks_known`, `wall_slot`,
`transport.*`) are **not in edition 1's field list** — `transport` in
particular exists specifically because a node alone on the wrong network layer
does not fail visibly: it finds no peers, builds its own fork, and still
answers `getchaininfo` with a plausible height and a moving, `"finalized"`
epoch. **Poll `transport.peers`, not just `behind_by_slots`, to detect "alone
on my own fork."**

### 10.4 `getutxos`/`listunspent` — the correct enumeration pattern (edition 1's is wrong)

<div class="warn">

**There is no pagination cursor and no `offset` parameter — the RPC signature
is `[script_hash, limit]`, exactly two parameters, full stop.** Edition 1
described this method as "page-based (100 per page, no cursor); the reply
states total, returned, truncated — page until truncated is false." **That
workflow cannot converge.** `limit` (default 100, clamped 1..=1,000) is a
*count*, not a page index; the node's own doc comment on this handler states
plainly that a script hash with more outputs than the `limit` used has *no*
way to reach the outputs past the first page through this method — calling it
again with the same arguments returns the identical first page, every time,
from a lazy iterator that always starts at position zero.

An in-repo integration guide independently invents a third parameter,
`offset`, for this method — **it does not exist in the code**; the handler
reads exactly two positions.

**The correct pattern**:
- Use `getbalance.utxo_count` as the reference total for a script hash.
- Keep any address you want to fully enumerate via `getutxos` under 1,000
  outputs (`UTXO_PAGE_MAX`) — then a single call with `limit: 1000` is always
  complete.
- For an address that already exceeds 1,000 outputs (this chain has at least
  one, from carryover — see §13), **`gettxout(txid, vout)` is the only exact,
  single-output check this node offers past the first page.** It was added
  specifically to give a way to confirm one specific outpoint's status without
  a working pagination path.

</div>

### 10.5 `sendrawtransaction` — response shape, and the missing `txid`

Request: `{"method":"sendrawtransaction","params":{"hex":"<signed-tx-hex>"}}`
(parameter name is `hex`, not `raw_hex` — matches edition 1).

Response fields, on success: `accepted` (bool, always `true` on success —
failures are JSON-RPC error objects instead), `status`
(`"accepted"|"duplicate"`), `kind`
(`transfer|transfer_v2|deposit|exit|exit_v2|delegate|slashing_evidence|randao_recommit`),
`bytes` (u64, canonical byte length), `tx_hash` (64-hex — **not** the consensus
`txid`; see §8.3), `tx_hash_note` (explicit disclaimer string), `confirmation`
(explains that this transport confirms nothing and that `finalized: true` is
the strongest signal but not a settlement guarantee).

<div class="warn">

**There is no `txid` field anywhere in this response.** The consensus `txid`
is deterministic and known to the wallet before broadcast — compute it
client-side and never expect `sendrawtransaction` to echo it. An in-repo
integration document's own sample response (`{"accepted":true,"txid":"…"}`)
is itself wrong on this point; the actual response shape has no `txid` key.

</div>

### 10.6 Error codes — two tables, deliberately separated, and a warning about one collision

**Node-level** (VERIFIED-IN-CODE, complete — every code the node itself defines, `rpc.rs:118-215`):

| Code | Name | Meaning at the node | Retryable? |
|---|---|---|---|
| `-32700` | Parse error | Body was not JSON | No — fix the client |
| `-32600` | Invalid request | JSON but not a JSON-RPC 2.0 object; also used for a top-level batch array | No |
| `-32601` | Method not found | No such method in this build | No |
| `-32602` | Invalid params | Arguments don't fit (bad hex, missing field, out of range) | No |
| `-32603` | Internal error | A bug in the node | Report it |
| `-32000` | `BLOCK_NOT_FOUND` | No block with that id is known | Retry after sync, or it never existed |
| `-32001` | `VALIDATOR_NOT_FOUND` | Index not in the committed registry | No |
| `-32002` | `TX_DECODE_FAILED` | Valid hex, not a canonical transaction | Do not retry unchanged |
| `-32003` | `MEMPOOL_FULL` | Admission refused for capacity — the transaction itself was not judged invalid | **Yes** |
| `-32004` | `NODE_UNAVAILABLE` | Consensus thread unreachable/shutting down | Yes |
| `-32005` | `NO_TRANSACTION_INDEX` | `gettransaction` — no txid→block index exists | No, permanent for this build |
| `-32006` | `NO_WALLET` | `getnewaddress` — no wallet, no frozen address format | No, permanent for this build |
| `-32007` | `SLOT_EMPTY` | Slot exists, carries no canonical block (missed proposal) | Normal under PoS — advance |
| `-32008` | `TX_REFUSED` | The node judged these **bytes** invalid on their merits | **Terminal — never resubmit these bytes** |
| `-32009` | `TX_REFUSED_RETRYABLE` | Barred against a **state** (e.g. spends an output this branch lacks yet); `error.data.until_slot` names when it lifts | **Yes, after `until_slot`** (~64 minutes, `REJECTION_TTL_SLOTS = 128` slots) |
| `-32010` | `TX_REFUSED_SOURCE_CAP` | This spend-authority source already has 64 (`MEMPOOL_MAX_PER_SOURCE`) pending transactions | Wait for one of that source's own pending transactions to clear |

`error.data` exists **only** on `-32009`, shaped exactly `{"retryable": true,
"until_slot": <number>}` — omitted from the wire entirely on every other code
(never emitted as `null`).

<div class="warn">

**`gettransaction`/`getnewaddress` do NOT return `-32601` at the node** —
edition 1 and the in-repo integration guide both state they do. At the node,
they are routed methods with dedicated codes, `-32005`/`-32006`, each carrying
an explanatory reason and never reaching the backend. This is plausibly a
**proxy-level normalisation** (the public endpoint's read-method allowlist
could map every disallowed method to the generic `-32601`) — but that is a
proxy fact this repository cannot verify (§10.7), and the two documents
present it as a blanket node fact without making the distinction.

**`-32010` means two unrelated things depending on which layer answers you —
the single most important error-code fact in this document.** At the **node**,
`-32010` is `TX_REFUSED_SOURCE_CAP` — a mempool per-source admission cap, only
ever returned from `sendrawtransaction`. At the **public proxy** (per edition
1 and per an internal operational document, both OPERATOR-ASSERTED, not in
this repository), `-32010` means "no read quorum: the sampled upstream nodes
disagreed" — an entirely different failure class, on a different family of
methods (reads, not writes). **An exchange integrating directly against a
self-hosted node (§13's own recommended posture) and reusing the published
"no quorum" meaning for `-32010` will misinterpret a mempool-capacity refusal
on a broadcast as a transient proxy read-corroboration hiccup.** Know which
endpoint answered before you interpret this code.

**`-32008` (terminal) vs. `-32009` (retryable) is the split edition 1 never
discusses at all, and the node's own source names this exact omission as a
real, previously-committed integration mistake on this project** — see the
warning in §9. Seven of the node's eleven own error codes
(`-32000,-32001,-32003,-32004,-32005,-32006,-32008,-32009`) are undocumented
in edition 1, whose error table lists only five codes and misassigns one of
them.

</div>

**Proxy-level** (`posternlabs.com/g4rpc` — **entirely OPERATOR-ASSERTED**;
this repository contains no proxy source code, worker, or configuration; a
repository-wide search for the proxy's own URL path finds only two
*consumers* of it, never a server implementation):

| Code (as documented by edition 1 / operator notes) | Meaning at the proxy |
|---|---|
| `-32601` | Method not on the read-method allowlist |
| `-32602` | Invalid params |
| `-32002` | Not a canonical transaction |
| `-32007` | No canonical block at that slot |
| `-32010` | **No quorum — sampled upstream nodes disagreed on a read** (see the collision warning above) |

### 10.7 Proxy-level facts, all OPERATOR-ASSERTED

Everything below is carried forward from edition 1 or an internal operational
note, and **none of it is verified by this edition** — this repository
contains no proxy source:

- Public endpoint `https://posternlabs.com/g4rpc`; direct nodes at
  `139.180.166.5:8080` and `139.180.173.231:8080`.
- A read-method allowlist, a same-origin/CORS layer distinct from the node's
  own (§10.1), and a cache with per-method TTLs (`getchaininfo` 3s,
  `getblockcount` 3s, `getvalidatorcount` 5s, `getblockbyslot` 10s,
  `getblockbyid` 300s).
- **Quorum ≥ 2**: the proxy samples multiple upstream nodes and requires
  agreement before answering certain "branch-sensitive" read methods; an
  internal operational note additionally states that `getchaininfo`
  specifically is corroborated only "softly" (a highest-agreeing-height
  projection) and can silently return a **single, uncorroborated** node's
  answer if nobody agrees — a caveat edition 1 does not state.
- Dedicated RPC nodes for exchange use "can be provisioned on request."

<div class="warn">

**Unresolved before this edition can confirm the "Direct nodes (by IP)"
section**: this repository's own bootnode-verification tooling and an
operational runbook both state, independently, that the fleet's node RPC
binds `127.0.0.1` **fleet-wide, including these exact two hosts** — i.e. that
`139.180.166.5:8080`/`139.180.173.231:8080` should **not** be reachable as
written, absent an explicit public-forwarding bridge (the pattern used
elsewhere in this project's deploy tooling for a *different* archival node).
This repository cannot confirm whether such a bridge exists on these two
specific hosts. Confirm directly with the endpoint operator before an
integration is built to depend on either address being reachable — see the
companion operator memo, `CHANGES-for-the-endpoint-operator.md`.

</div>

### 10.8 Sample responses — shape reconstructed from the code's JSON builders, NOT live values

<div class="note">

**Every value below is illustrative.** None of these are live captures — this
environment has no network path to any running node (see the scope
statement). Field names, types, and nesting are reconstructed directly from
the `Json::obj(...)` builders cited in §10.2–§10.3 and §7; only the numbers,
hex strings, and hashes are placeholders chosen to show the *shape* (length,
whether a field is a string vs. a number, where `null` can appear).

</div>

`getchaininfo`:

```json
{
  "block_id": "e3a1...c02f",
  "slot": 70432, "height": 70401, "finalized_height": 70369,
  "epoch": 2201, "slot_in_epoch": 0, "slots_per_epoch": 32,
  "state_root": "9b7c...11a0",
  "justified": {"epoch": 2200, "root": "4f6d...88ee"},
  "finalized": {"epoch": 2199, "root": "0a1b...ffd2"},
  "previous_justified": {"epoch": 2199, "root": "0a1b...ffd2"},
  "validators": {"total": 64, "active": 64},
  "total_active_stake_sat": "6177107126034566",
  "base_fee_millisat_per_gas": "10",
  "next_base_fee_millisat_per_gas": "10",
  "mempool": 3, "blocks_known": 70401,
  "wall_slot": 70432, "behind_by_slots": 0,
  "transport": {"name": "devnet", "peers": {"devnet": 2, "libp2p": null}}
}
```

`getblockbyslot [70430]` / `getblockbyid`:

```json
{
  "block_id": "e3a1...c02f", "version": 2970353669,
  "parent": "d0c2...5511", "slot": 70430, "epoch": 2200, "height": 70399,
  "proposer_index": 41, "timestamp": 1788269679,
  "state_root": "9b7c...11a0", "body_root": "77aa...002c",
  "randao_reveal": "aa11...9900", "randao_mix": "bb22...8800",
  "justified_root": "4f6d...88ee", "finalized_root": "0a1b...ffd2",
  "attestation_root": "cc33...7700", "coherence_root": "dd44...6600",
  "finality": "justified", "finalized": false,
  "tx_count": 2, "attestation_count": 61
}
```

`getbalance`:

```json
{"script_hash": "e986...0000", "balance_sat": "3791846123578561665", "utxo_count": 425599}
```

`getutxos [script_hash, 2]`:

```json
{
  "script_hash": "e986...0000", "total": 425599, "returned": 2, "truncated": true,
  "utxos": [
    {"txid": "0d01...a376", "vout": 1, "value_sat": "3999999992712", "script_hash": "e986...0000"},
    {"txid": "1a22...b487", "vout": 0, "value_sat": "1250000000", "script_hash": "e986...0000"}
  ]
}
```

`gettxout [txid, 1]`:

```json
{
  "txid": "0d01...a376", "vout": 1, "unspent": true,
  "utxo": {"txid": "0d01...a376", "vout": 1, "value_sat": "3999999992712", "script_hash": "e986...0000"},
  "at_slot": 70432
}
```

`sendrawtransaction [hex]` (success — note: no `txid`):

```json
{
  "accepted": true, "status": "accepted", "kind": "transfer",
  "bytes": 4931, "tx_hash": "7f0e...aa19",
  "tx_hash_note": "local correlation handle only (SHA3-256 of the canonical bytes); not a consensus transaction id — no block commits to it",
  "confirmation": "this transport does not confirm: watch for the transaction in a block via `getblockbyslot`. `finalized: true` on that block is the strongest signal this chain offers, but it is NOT a settlement guarantee..."
}
```

`sendrawtransaction` error (retryable barred transaction):

```json
{"jsonrpc": "2.0", "id": 1, "error": {"code": -32009, "message": "barred: spends an output this branch does not have yet", "data": {"retryable": true, "until_slot": 70560}}}
```

`getmempoolinfo`:

```json
{"size": 3, "max": 4096, "bytes": 12904, "next_base_fee_millisat_per_gas": "10", "barred": 1, "barred_hits": 4, "expired": 0, "evicted_low_fee": 0}
```

`getvalidatorcount`:

```json
{"total": 64, "active": 64, "total_active_stake_sat": "6177107126034566"}
```

`getvalidators` (one entry of 64 shown — note `commission_bps` is a plain number here, a string on `getvalidator`):

```json
[{"index": 0, "pubkey_hash": "a1b2...ef00", "status": "active", "effective_stake_sat": "96517299000000", "commission_bps": 500}]
```

`gettxstatus [txid]`:

```json
{"status": "finalized"}
```

`getbuildinfo` / `bloch-pos buildinfo`:

```json
{
  "build_version": "0.4.0-genesis4", "package_version": "0.4.0",
  "commit": "72e5525...", "commit_source": "git", "tree_state": "clean",
  "source_digest": "3d67...b308", "source_digest_alg": "sha3-256",
  "source_digest_scope": "workspace crates dir: rs, toml, c, h, S, s; plus workspace Cargo.toml and Cargo.lock; relative paths, sorted, length-prefixed",
  "source_files": "812", "source_bytes": "9134221",
  "rustc": "1.94.1", "profile": "release", "target": "x86_64-unknown-linux-gnu",
  "digest_note": "different digests prove different source trees; equal digests are evidence of the same source, not proof — whoever can edit the source can edit the build script that hashes it"
}
```

---

## 11. Deposits

### 11.1 Detection strategies

1. **Poll `getbalance(script_hash)`** — cheap, exact, gives a true `utxo_count`
   without walking the output set.
2. When it moves, **`getutxos(script_hash, limit)`** to see which outputs
   arrived (`txid`, `vout`, `value_sat`) — subject to the 1,000-output cap of
   §10.4.
3. **`gettxout(txid, vout)`** to confirm one specific output exists and is
   unspent — the exact primitive for confirming an individual payment, and the
   only one that works past 1,000 outputs on one script hash.
4. **Block scanning by slot** (`getblockbyslot`), if you need to observe
   inclusion directly rather than only the resulting UTXO set. A slot with no
   canonical block returns `-32007` **naming the current head** — a scanner
   must stop at the head, not treat a future slot as merely empty. The header
   response carries no transaction list, only `tx_count` — you cannot learn
   *which* txids a block contains through this RPC surface; correlate by
   `gettxout`/`getutxos` against txids you already expect, not by scanning
   block bodies for unknown ones.

### 11.2 What `gettxout`'s `at_slot` actually is — a correction to edition 1's mechanism

<div class="warn">

**`at_slot` on a `gettxout` response is this node's current head slot at the
moment it answered — it is NOT the funding output's creation/inclusion
slot.** Nothing in the committed eUTXO entry (`EutxoEntry{txid, vout, value,
script_hash}`) carries a creation height or slot, and **no RPC method in this
tree answers "what block/height contains txid X" by txid alone.** Edition 1's
deposit-crediting recipe — "read the output's block height … compare to
`finalized_height`" — is not directly executable as literally written: there
is no height field to read off the output. The safe, executable pattern is an
**observed-height cross-reference**, built by the integrator:

1. Poll `gettxout(txid, vout)` until `unspent: true`.
2. In the same round-trip (or immediately after), read `height` from
   `getblockcount`/`getchaininfo`. Record this observed height `H` — the
   output already existed at or before `H` (a conservative upper bound; it may
   have landed earlier).
3. Credit once `finalized_height ≥ H`, per the crediting rule in §11.3.

This never credits early (it can only overstate how long you waited), and it
is the same conclusion the audited research behind this edition reached
independently: the *policy* half of edition 1's §10 ("settle on
`finalized_height`, never on acknowledgement, never on epoch") is sound and
matches the node's own guidance; the *mechanism* half (reading a height field
that does not exist) does not work as written.

</div>

**Exact-integer parsing**: `balance_sat`, `value_sat`, and every other
`*_sat` field is a decimal string — parse as a big integer (§1's note).
**Address validation and `script_hash` derivation**: §5. **Minimum
confirmations**: this document deliberately does not restate "N confirmations"
— see §11.3, which gives the actual crediting rule in epochs, with reasoning.

### 11.3 The deposit-crediting rule — one explicit recommendation, with the reasoning

<div class="warn">

Do **not** simply carry forward edition 1's "`finalized_height ≥ height ⇒
irreversible" as an unqualified rule. §2 already established what `finalized`
does and does not buy; here is the single, explicit rule this edition
recommends, and why.

**Three sources of guidance exist in this project, and they disagree on the
margin — resolve them explicitly rather than silently picking one:**

| Source | Dated | Margin recommended |
|---|---|---|
| `rpc.rs`'s own `Finality` doc comment | comment content dated 2026-09-01/09-05 | `finalized` + **3 epochs** (~48 minutes) |
| `docs/integration/BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md` §5 | 2026-08-26/09-05, pre-dates the round-3/4 arming | `finalized` + **3 epochs** (~48 minutes) — same figure, same reasoning, and **also** still describes `LEAK_RECOVERY_ACTIVATION_EPOCH` as unarmed (`u64::MAX`), which is stale (§3) |
| `SECURITY.md` §"Guidance for integrators" | **2026-09-06 — the newest of the three** | `finalized` + **~30 epochs** (~8 hours) |

**This document recommends `SECURITY.md`'s ~30-epoch margin as the current,
authoritative figure**, for two reasons: it is the most recently updated of
the three, and its own stated rationale is explicit and still applies — the
finality-latch fix (§2.5) is new (2026-09-05) and its edge cases are still
being found in audit; 30 epochs of continued, uninterrupted cross-node
agreement is meant to be well past the window in which that class of defect
would surface as a visible disagreement. The 3-epoch figure bounds only a
*single* legal downward cut (§2.7/§2.9) with one epoch to spare — it does
**not** bound a repeated ratchet, and both places that state it say so
themselves ("no depth is provably safe today"). Neither older document's
`LEAK_RECOVERY` claim should be trusted over §3's current fact.

**The recommended rule, stated once, in full:**

1. Wait for the transaction's block to reach `finalized` — read
   `finalized_height` from `getchaininfo`/`getblockcount`, and confirm your
   observed height `H` (§11.2) satisfies `finalized_height ≥ H`.
2. Then wait a further **~30 epochs (~8 hours: 30 × 32 slots × 30 s)** of continued, uninterrupted
   chain progress before treating a large or irreversible credit as final.
3. Throughout, **query at least two independently operated nodes** — no
   shared operator, keystore, or (ideally) network path — and require them to
   agree on the **same finalized root at the same finalized epoch**, not the
   epoch alone. **Two nodes agreeing does not mitigate either node's own
   rewind** (§2.5/§2.9) — it catches *divergence* between them, which is a
   different failure than either one individually reporting a false
   finalization.
4. Re-verify immediately before actually releasing funds, rather than trusting
   a check performed earlier in the flow.

This rule is more conservative than either older document's 3-epoch figure by
roughly 10×. Apply proportional judgement for low-value/high-frequency credits
where a shorter margin is an acceptable business risk — but do so as a
deliberate, documented risk decision, not because this document's default is
unclear.

</div>

### 11.4 Reorg handling before finality

Above its own finalized checkpoint, a node's canonical chain can reorg to
arbitrary depth via ordinary LMD-GHOST re-weighing (no cap) — this is normal
and expected for an included-but-not-yet-finalized transaction. `gettxstatus`
(§10.2) reflects this: a transaction that gets reorg'd out and is not
re-included elsewhere moves from `included`/`justified` back to `unknown` (or
`pending` if it re-enters the mempool) — it does not remain falsely
`included`.

<div class="note">

`gettxstatus`'s own `"finalized"` value is computed by an **epoch** comparison
internally (it looks up the transaction's recorded slot, converts to an
epoch, and compares that epoch against the node's finalized epoch) — this is
exactly the "epoch comparison" this document, edition 1, and the node's own
RPC doc all say never to credit on. `gettxstatus` is a genuinely useful,
txid-keyed convenience for **tracking** a submission (and is missing from
edition 1 entirely), but do **not** use its `"finalized"` string as the
crediting signal in place of the `gettxout` + `finalized_height` rule of
§11.2–11.3. It also cannot distinguish "never submitted" from "submitted,
admitted, and later dropped by a proposer" — both read `"unknown"`.

</div>

---

## 12. Withdrawals

### 12.1 Building and signing

1. Select unspent inputs owned by the withdrawing key (`getutxos`/`gettxout`,
   §10.2/§10.4) sufficient to cover the payout plus the fee.
2. Read `next_base_fee_millisat_per_gas` from `getchaininfo` or
   `getmempoolinfo` **immediately before building** — this is your one-block
   look-ahead (§8.5).
3. Choose `tip_millisat_per_gas` (the only sender-set price lever) and
   `outputs` (payout + change).
4. Fix `tx_bytes` — budget for Falcon's variable signature length (§4, §8.6);
   under-declaring forces a re-sign.
5. Sign (client-side; the node never sees a spending key). `spend_signing_root`
   and therefore `txid` are fixed the moment `outputs`/`tip`/`tx_bytes` are
   chosen and the inputs are named — before the signature exists.
6. `sendrawtransaction({"hex": "<signed bytes>"})`.

### 12.2 Fee selection and the base-fee window

A transfer is valid at **exactly one** base fee — the one committed by the
including block (§8.4). There is no slack window beyond, in practice, the
single next block. If the base fee moves before inclusion, the identical
signed bytes will fail `ValueNotConserved` in every subsequent block whose
base fee differs — **rebuild, do not resubmit**, against the new
`next_base_fee_millisat_per_gas`.

### 12.3 Tracking to finality

Same mechanism as deposits (§11): track by the client-computed `txid`, confirm
inclusion via `gettxout`, and apply the crediting-margin rule of §11.3 before
treating the withdrawal as irreversibly settled from the exchange's own books'
perspective (i.e., before you stop being able to safely reissue/cancel
internally) — note this is a different question from when the *recipient*
should trust the payment, which follows the same §11.3 rule from their side.

### 12.4 Failure modes and retries — rebuild vs. resubmit

| Symptom | Cause | Correct action |
|---|---|---|
| `-32008 TX_REFUSED` | Bytes invalid on their merits (bad signature, malformed structure) | **Never resubmit these bytes.** Diagnose and rebuild from scratch. |
| `-32009 TX_REFUSED_RETRYABLE`, with `error.data.until_slot` | Barred against current state (commonly: a stale base-fee assumption after `ValueNotConserved`, or a spent input that hasn't landed on this branch yet) | **Retryable after `until_slot`.** If the underlying cause was a stale base fee, rebuild against the current one rather than waiting out the bar and resubmitting unchanged bytes — resubmitting unchanged will simply fail and be barred again for the same reason. |
| `-32003 MEMPOOL_FULL` | Node-wide capacity | Retry later; the transaction was not judged invalid. |
| `-32010 TX_REFUSED_SOURCE_CAP` (at a **direct node**) | This spend-authority source already has 64 pending transactions | Wait for one of that source's own pending transactions to clear, or consolidate outstanding withdrawals from the same source before issuing more. **Do not interpret this as a quorum failure if you are talking to a fleet-operated proxy that also uses `-32010` for a different meaning (§10.6).** |
| `Admitted::Duplicate` (success, not an error) | Identical bytes already pending | No action — it is already in the mempool. |

### 12.5 Batching constraints

The per-source cap (`MEMPOOL_MAX_PER_SOURCE = 64`, §9) bounds how many
withdrawals from one spend-authority key can be outstanding simultaneously.
Coin selection reads the current UTXO set at build time; a batch built from
one snapshot can select the same input twice across two withdrawals built
close together. Serialize: send one transfer, wait for inclusion (~30
seconds), then build the next — or track your own already-committed outpoints
locally and exclude them from selection before the chain confirms them. There
is no withdrawal-batching RPC primitive; each withdrawal is one
`sendrawtransaction` call.

---

## 13. Running a node

### 13.1 Recommended posture

**An independently-validating observer node — no keystore.** A data directory
with no `validator.key` boots in observer mode: it applies every block and
serves the full RPC surface, but signs nothing and takes on no consensus
duties (`engine.rs:4416-4429`). This is the correct posture for an exchange —
you get a `finalized_height` computed from a chain **you** validated, not one
you are trusting a shared endpoint to report honestly. **This is the posture
blocked by the weak-subjectivity gap described in §2.6 for any node started
fresh today** — read that section before planning around this section.

### 13.2 Exact command line for the current binary

```bash
./target/release/bloch-pos run \
  --data-dir   /var/lib/bloch/data \
  --genesis    /var/lib/bloch/mainnet.manifest \
  --carryover  /var/lib/bloch/carryover.tsv \
  --transport  devnet \
  --listen 19100 --listen-addr 127.0.0.1 \
  --peers 139.180.166.5:19100,139.180.173.231:19100 \
  --rpc-port 16310 --rpc-bind 127.0.0.1
```

<div class="warn">

**Edition 1's node command line will not run as written.** It reads
`bloch-pos run --transport dual --peer 139.180.166.5:19100 --peer
139.180.173.231:19100`. Checked against the current binary's argument parser:

- **`--peer` (singular) is not a flag.** Only `--peers` (devnet, comma-separated)
  and `--p2p-peer` (libp2p, comma-separated) exist. Passing `--peer X --peer
  Y` is **silently absorbed as unrecognized text — no peer is configured at
  all**, which is not a refusal, and arguably worse than one.
- **`--transport dual` requires `--listen <port>`**, which the old command
  never supplies — the real binary would exit 2, `--listen <port> is required
  for the 'dual' transport`.
- **`--data-dir` and `--genesis` are both hard-required** and absent from the
  old command entirely.
- **`--p2p-advertise <multiaddr>`, which edition 1 describes for a node behind
  NAT/LB, does not exist anywhere in this repository** (zero occurrences).
- **`dual` is the wrong transport for these specific bootnodes anyway** — an
  in-repo operational note states plainly that these two hosts run
  `--transport devnet`, not libp2p, and that `--transport libp2p` against them
  "exchanges zero frames and leaves you alone on your own fork" while still
  printing plausible-looking `applied`/`finalized` log lines.

</div>

**Flags, defaults, and what each transport requires** (`main.rs`):

| Flag | Default | Notes |
|---|---|---|
| `--data-dir <dir>` | none — **required** | |
| `--genesis <file>` | none — **required** | |
| `--carryover <snapshot.tsv>` | required **iff** the genesis manifest carries a carryover commitment (it does, for mainnet) | Checked against four manifest-committed fields (digest, set root, count, total) before a single balance is admitted; the node refuses to start on a mismatch. |
| `--transport devnet\|libp2p\|dual` | **`devnet`** (both unnamed and named) | `None \| Some("devnet") => Transport::Devnet` — confirmed the current, tested, documented default; a prior revision briefly flipped this to `dual` and has been reverted. `devnet` requires `--listen <port>` (1–65535); refuses `--p2p-listen`/`--p2p-peer`. `dual` accepts every flag of both halves and also requires `--listen`. |
| `--listen <port>` | none for `devnet`/`dual` — required when that transport is selected | |
| `--listen-addr <ip>` | `127.0.0.1` | A wider bind is an explicit operator choice. |
| `--peers <host:port,…>` | none | Devnet mesh peers, comma-separated. **Plural — no singular `--peer`.** |
| `--p2p-listen <multiaddr>` | `/ip4/127.0.0.1/tcp/16400` | Loopback by default; applied only when a swarm runs and none was named. |
| `--p2p-peer <multiaddr,…>` | none | libp2p peers, comma-separated. |
| `--rpc-bind <ip>` | `127.0.0.1` | |
| `--rpc-port <n>\|off` | **`16310`** | `off`/`0` disables RPC entirely. **Not 8080** — see §1 and Appendix A for where that number actually comes from. |
| `--metrics-bind <ip>` | `127.0.0.1` | |
| `--metrics-port <n>\|off` | **off — no default listener** | |
| `--max-peers <n>` | 64 | libp2p/dual only |
| `--behind-proxy` | off | libp2p/dual only — zeroes an IP-colocation peer-scoring penalty |
| `--ws-checkpoint <file>` + `--ws-signer-set <file>` | none | Must be given together. See §2.6/§13.4. |
| `--stop-at-slot <n>` | none | test/ops convenience |
| `--allow-finality-rewind` (env: `BLOCH_ALLOW_FINALITY_REWIND=1`) | off | Not recommended for an observer node. |
| `--no-doppelganger-check` (env: `BLOCH_NO_DOPPELGANGER=1`) | off | Meaningless for an observer (no keystore, no duties). |

Env var **`BLOCH_RPC_HOST_ALLOWLIST`** (comma-separated extra `Host` values,
read once at process start) is the only way to widen the Host allowlist — there
is no equivalent CLI flag.

### 13.3 Data directory, `LOCK`, and replay cost

Files in `<data-dir>`: `LOCK` (`O_EXCL` + `flock`; never unlinked on clean
shutdown by design — a prior revision that unlinked it on `Drop` opened a
two-process race that could double-sign; the current design detects and
reclaims an orphaned lock from a dead process, but a live one is never
preempted), `meta.bin`, `blocks.log` (append-only, one `fsync`-flushed frame
per block; a crash leaves at most one truncated trailing frame, detected and
dropped on replay), `blocks.idx` (rebuilt/repaired on open),
`validator.key` (validator only — absent for an observer), `ws_latest.bin`
(the weak-subjectivity checkpoint this node has itself verified — one of the
three files to copy when seeding a new node from an existing one, alongside
`blocks.log` and `meta.bin`).

**Replay cost is `O(chain length)` by design — there is no state-snapshot or
RocksDB layer, and no checkpoint-sync state download.** A measured full cold
sync from genesis (2 vCPU / 7.9 GB box, dated 2026-09-01) took **21.2
minutes** at height 33,602, peak RSS 934 MB; seeding the same three files from
a donor node and replaying locally took **22.1 minutes** — seeding still
validates every block; it only saves the time of fetching them over the
network, and is not a weaker validation than a full network sync
(OPERATOR-MEASURED figures, not something the code enforces).

### 13.4 Weak-subjectivity checkpoint — required today for any fresh node

See §2.6 in full. In summary for this section: a node with no local finality
of its own (any fresh node started from now on) requires a signed
weak-subjectivity checkpoint envelope once the genesis anchor exceeds the
2016-epoch trust-once window — which it has, since 2026-09-05 07:07:19.962
UTC. **No such checkpoint exists in this repository, and the signing ceremony
that would produce one has not been held as of the most recent dated
operator note (2026-09-06).** A node run exactly as in §13.2, today, will sync
from genesis and then **refuse to complete**, loudly, with the
`ERR_WS_REQUIRE_CHECKPOINT` message quoted in full in §2.6 — this is the
mechanism working as designed, not a bug to work around. If a checkpoint has
since been published, obtain it from a channel you trust, verify its digest
across at least two independent channels, and supply it via
`--ws-checkpoint <file> --ws-signer-set <file>`.

### 13.5 RPC exposure

Loopback by default (`127.0.0.1:16310`). To reach it from another host
safely: **do not** widen `--rpc-bind` to a public interface without your own
authenticating reverse proxy in front of it — the node's own RPC has no API
key and no per-method authorisation by design (only anti-exhaustion bounds,
§10.1). Reach it via an SSH tunnel or your own proxy that terminates TLS and
enforces access control; if you must widen the `Host` allowlist for a
legitimate proxy hostname, use `BLOCH_RPC_HOST_ALLOWLIST`, not a wildcard
bind.

### 13.6 `/health` and `/metrics`

Opt-in only (`--metrics-port`, off unless set), separate server from the RPC
port, GET-only.

`GET /health`:

| Status | Body | Meaning | Alert as |
|---|---|---|---|
| `503` | `{"status":"starting",…}` | Slot loop never ran a turn (booting/replaying) | Expected during boot/replay only |
| `503` | `{"status":"stalled",…}` | **Both** a live-computed slot lag > 4 slots **and** no real canonical-state change in 30s | Page — the node is genuinely stuck |
| `200` | `{"status":"syncing",…}` | Alive, catching up — do not route reads here, don't restart | Informational |
| `200` | `{"status":"ok",…}` | Healthy | — |

Body always includes: `head_slot, behind_by_slots, finalized_epoch,
peer_count, is_syncing, validator_active, heartbeat_age_secs`. The two-signal
`stalled` design (both slot lag *and* stale last-applied timestamp) is a fixed
prior false-positive: a node merely busy answering a heavy RPC burst used to
report `stalled` after 30 seconds even though it was current — an
orchestrator restarting on a bare `503` would have restarted a healthy node.

`GET /metrics` — Prometheus text, prefix `bloch_pos_*`. Names to alert on for
an exchange:

| Metric | Alert condition |
|---|---|
| `bloch_pos_behind_by_slots` | > 64 for 5m (>32 minutes behind) |
| `bloch_pos_finalized_epoch` | no advance for an extended period (pair with `bloch_pos_last_finality_advance_unix`) |
| `bloch_pos_peer_count` | < 2 for 10m |
| `bloch_pos_finality_rewinds_refused_total` | any increase — this is the ONLY place this counter is exposed (not a `getchaininfo` field) |
| `bloch_pos_equivocations_observed_total` | any increase — detected equivocation, not itself actionable (§2.8) but worth knowing |
| `bloch_pos_data_dir_fs_free_bytes` | falling toward zero — **exports free bytes only, no size series**; pair with a filesystem-percentage collector for a usable disk-full alert |
| `bloch_pos_store_append_failures_total` | any increase — an ENOSPC signal, treated as fatal by design |
| `bloch_pos_blocks_parked` | sustained growth — sync trouble |
| `bloch_pos_process_starts_total` | resets to 1 on every restart — a `resets(...[1h])` query is an OOM/restart-loop alarm |

<div class="note">

A shipped example alert-rules file in this repository marks exactly the three
most security-relevant alerts (`finality_rewinds_refused`,
`equivocations_observed`, `keystore_sealed`) as "DISABLED — metric does not
exist yet" — as of `72e5525` **all three metrics exist and are exported**; the
monitoring file simply predates the commit that added them. Do not copy that
file's disabled status without checking `metrics.rs` directly, or wire your
own alert rules from the table above instead.

</div>

### 13.7 Release integrity — `--version` and `getbuildinfo`

```
$ bloch-pos --version
bloch-pos-node <pkg-version> (Genesis-4, block version 0xb10c0005)
source-digest sha3-256:<hex> (<N> files, <M> bytes) commit-source:<git|asserted|none> tree:<clean|modified|unverified|unknown>
```

`getbuildinfo` (RPC) and `bloch-pos buildinfo` (CLI) return the identical
object: `build_version, package_version, commit, commit_source,
tree_state, source_digest (SHA3-256 over every `crates/**/*.{rs,toml,c,h,S,s}`
file plus the workspace `Cargo.toml`/`Cargo.lock`, computed at build time),
source_digest_alg, source_digest_scope, source_files, source_bytes, rustc,
profile, target, digest_note`.

<div class="warn">

**What `source_digest` can and cannot prove, in the code's own stated terms.**
Two nodes reporting a **different** `source_digest` were built from different
source trees, full stop — no interpretation needed. It does **not** prove a
node is running the exact tag it claims: `commit`/`commit_source` can be
independently asserted at build time via a build-time-only environment
variable, and equal digests mean the hashed file set matched, not that the
compiled artefact wasn't altered after the fact. It also says nothing about
behaviour — identical source and toolchain have, in this project's own
history, still diverged at runtime on local state. Treat this as tamper-evident
against drift and accident, not tamper-proof against a deliberately dishonest
operator.

**Raw binary `sha256sum` is not a reliable cross-machine comparison for this
project as it stands.** An internal measurement found that building the
identical source at a different absolute filesystem path produces a
**different** compiled-binary sha256 (Cargo's build metadata hashes the
absolute manifest path, which seeds every symbol hash) — `--remap-path-prefix`
does not fix this. **No canonical containerized build exists yet for the
`bloch-pos` binary**, so the only publishable, path-independent comparison
available today is the `source_digest` line above, not the raw binary hash.
</div>

### 13.8 Hardware/disk guidance (OPERATOR-MEASURED, not enforced by code)

Linux x86-64, 2+ vCPU, 8 GB RAM, 80 GB SSD. Replay is single-threaded and pins
one core — extra cores let you run more independent nodes, not one faster
node. Peak resident memory measured at 934 MB for a full cold sync on a 2
vCPU / 7.9 GB box; "8 GB is comfortable, untested below it."
`mainnet.manifest` ≈247 KB; `carryover.tsv` ≈55 MB uncompressed, 452,726
opening outputs (see the note on this figure in Appendix A).

### 13.9 Docker/Nix — what does and does not exist

**There is no Genesis-4 (`bloch-pos`) container image and no working
Genesis-4 Nix package anywhere in this repository.** Every `Dockerfile` and
every pinned image under `deploy/akash/*.yaml` in this tree builds or
references the **legacy Genesis-3** `bloch` binary — none is `bloch-pos`.
`os/bloch-pos-node.nix` is a NixOS module written for the live node, but its
`package` option has no real default (no `bloch-pos-node` package.nix exists
in `os/` yet) — do not enable it in a real deployment until that gap is
closed. **The only supported way to get a Genesis-4 binary today is to build
from source** (`cd crates/bloch-pos-node && cargo build --locked --release`;
this places the binary at `target/release/bloch-pos` relative to the repo
root, since the crate resolves the single root `Cargo.lock` — running `cargo
build -p bloch-pos-node` from the repo root instead will not find the
crate's pinned toolchain, since rustup resolves `rust-toolchain.toml` by
walking up from the working directory and does not descend into
subdirectories).

### 13.10 What is legacy Genesis-3, and must not be run as "the chain"

`legacy/genesis3-node/` (binary `bloch`, ports in the 16xxx/16111 range
distinct from Genesis-4's) is the retired proof-of-work predecessor, stopped
by consensus rule at height 39,918. It is kept buildable **only** so the
carried-over ledger can be independently re-derived and audited — it produces
no live blocks, and nothing in this document's integration guidance applies
to it. Do not point any exchange integration at a Genesis-3 node or its RPC
surface expecting current chain state.

---

## 14. Operational security notes for integrators

This section summarizes what two internal, tool-assisted remediation audits
(`round3-report.md`, dated 2026-09-06, verifying a 117-commit fix wave against
a baseline of ~250 findings from Rounds 1–2; and `round4-report.md`, dated
2026-09-06, a further 150-finding fix wave against everything Round 3 left
open) established, insofar as it bears on an exchange's integration and
custody posture. **Neither round is an external, third-party certification —
both are internal, tool-assisted audits, explicitly labelled as such in their
own text.**

<div class="note">

**These two reports are not files inside the `72e5525` source tree** — a
repository-wide, case-insensitive filename search for `round3`/`round4` at
this commit returns zero results; they are the project's own internal audit
records, held outside the audited repository. The commit-count and
finding-count figures immediately above (117 commits, ~250 baseline findings,
150 fixed) are therefore sourced only to those reports and cannot be
independently re-derived from the repository alone — treat them as reported,
not VERIFIED-IN-CODE. Every *substantive* claim the rest of §14 makes (what is
live, what is gated, what each gate's constant is named) is independently
re-checked directly against the cited source file below, not taken on the
reports' word.

</div>

### 14.1 What is fixed and live today

Node-local hardening that does not require a consensus flag day is live in
`72e5525`: the HTTP admission gate (§10.1), sealed/encrypted validator
keystores (Argon2id + AEAD, with a migration tool, `bloch-pos keys seal`),
`slashprot`'s fsync-then-sign discipline for validator signing (protects
against double-signing on crash/restart, relevant if you ever run a validating
node — not applicable to an observer), the data-directory lock's
orphan-detection fix (a Round-3 regression that briefly allowed two processes
to hold one data directory was fixed before this round), the transport
default (`devnet`, loopback swarm, confirmed correct in this tree after a
Round-3 regression briefly flipped it to an all-interfaces `dual` bind),
doppelgänger protection (a restarted validator observes 32 minutes before its
first duty), the finality latch and its telemetry/override (§2.5), and the
mempool per-source cap and fee-ordered eviction (§9).

### 14.2 What is fixed in code but inert (gated behind a flag day, §3)

The two Round-2 "Critical" findings that would let a single validator key
threaten the chain — an unauthenticated `Exit` that can retire every validator
in one block, and a fee-to-stake compounding path that buys a ⅔ supermajority
in one block for roughly 1,080 sat — are **both fixed in code and both still
exploitable on the live chain today**, because their gating constants
(`EXIT_AUTH_ACTIVATION_EPOCH`, `FEE_STAKE_DECOUPLE_ACTIVATION_EPOCH`) remain
`u64::MAX`. Slashing is fixed in code and inert (§2.8). This is by design —
every consensus-affecting fix in this project ships behind a named,
tripwire-tested `u64::MAX` gate so a mixed fleet never silently forks — but it
means "fixed" in an audit report does not mean "in force on the chain you are
integrating against" until the corresponding line in §3's table says
"active"/"armed."

### 14.3 Open governance items relevant to custody

- **Stake concentration**: the founder holds 93.94% of the carried-over
  balance and it is fully stakeable; a naive Nakamoto coefficient is 1. Stated
  as a disclosed, known gap in `SECURITY.md`, not a new finding — a *concrete
  exploit beyond it* (e.g. justifying/finalizing without an honest two-thirds)
  is in scope for a security report; the concentration itself is not.
  (`SECURITY.md:29-32,100-104`)
- **No stake-withdrawal path exists** (§8.7/§12) — validator bonds, and the
  42.85 billion BLCH allocated to the emission schedule, are illiquid until a
  wire tag is assigned and the corresponding transaction variant is built.
- **The wire-tag registry** (`0x07`, `0x08`, `0x09`) and several flag-day
  armings (`EXIT_AUTH`, `RANDAO_RECOMMIT`, `SLASHING_EVIDENCE`) are explicitly,
  repeatedly stated in-source as **the founder's decision** — this document
  does not speculate on when or whether they will be armed.
- **No external security audit has been contracted to date** — `SECURITY.md`'s
  own words, added specifically to correct any other page or document that
  might suggest otherwise.
- **This live network is explicitly described in-source as unaudited** and
  running a live mainnet is "a designation, not a security claim."

### 14.4 Disclosure process

Per `SECURITY.md`: use the repository's private security-advisory flow, or
contact a maintainer via an encrypted channel with `[bloch-security]` in the
subject. Include affected component, version/commit, a PoC if available,
impact, a suggested fix if you have one, and your credit preference.
Acknowledgement target is ≤2 days; fix and coordinated disclosure "as fast as
the severity warrants." In scope explicitly includes Genesis-4 consensus, the
node's P2P/RPC surfaces, hybrid signature verification on any consensus path,
the Coherence privacy layer, and privacy findings generally (deanonymization,
metadata leaks, linkability) — **Dandelion++ network-layer privacy is
explicitly roadmap, not shipped**; do not assume it protects transaction-origin
metadata. Out of scope: the disclosed stake-concentration gap itself (a
concrete exploit of it is in scope), the retired Genesis-3 chain's low-hashrate
exposure, implausible-resource DoS, and third-party infrastructure.

---

## 15. Appendix A — Changed since edition 1

| # | Edition 1 statement | Correct statement (this edition) | Reason / evidence | Action |
|---|---|---|---|---|
| 1 | Block-format `finalized` field is `object {epoch, root}` | It is a **boolean** on `getblockbyslot`/`getblockbyid` (`rpc.rs:1893`); the `{epoch, root}` object only exists as `getchaininfo`'s own `finalized` field, describing node state, not a block | VERIFIED-IN-CODE, `rpc.rs:1621-1627,1893` | Exchange: fix the client-side parser for this field's type. |
| 2 | `-32010` = "no quorum: upstreams disagreed (retry)" | True only at the (unverifiable) proxy layer. At the node, `-32010 = TX_REFUSED_SOURCE_CAP` — a mempool per-source cap refusal, unrelated to read quorum | VERIFIED-IN-CODE, `rpc.rs:205-215`; internally corroborated by an operational note calling the proxy's `-32010` "his code, not the node's" | Exchange: branch on which endpoint answered before interpreting this code. Operator: consider assigning the proxy a distinct code (see the companion operator memo). |
| 3 | `gettransaction`/`getnewaddress` return `-32601` | At the node, dedicated codes `-32005`/`-32006`, each with an explanatory reason; `-32601` on the node is reserved for genuinely unrouted methods | VERIFIED-IN-CODE, `rpc.rs:1092-1093,283-286` | Exchange: handle `-32005`/`-32006` explicitly for a direct-node integration. |
| 4 | `-32008` and `-32009` are functionally the same ("resubmitting identical bytes … permanently invalid, not merely slow") | `-32008` is terminal; `-32009` is state-dependent and **lapses** after `error.data.until_slot` (~64 minutes). The node's own source names the old guidance as a real, previously-committed integration mistake | VERIFIED-IN-CODE, `rpc.rs:165-215`, `engine.rs:2852-2977` | Exchange: implement the retry table in §12.4. |
| 5 | Transaction wire-tag table lists only `0x01`–`0x04` | `0x05 SlashingEvidence` (decodes, gated inert) and `0x06 TransferV2` (**live and active since epoch 800**) also exist and are omitted | VERIFIED-IN-CODE, `tests/wire_tag_registry.rs`, `transition.rs:329-386` | Exchange: a wallet emitting or receiving V2 transfers is normal; do not reject `0x06`. |
| 6 | "CORS enabled; OPTIONS preflight answered (204)" | False for a direct node — any non-POST verb (including OPTIONS) gets `405`; no CORS headers are ever sent. Plausibly true only for the (unverifiable) public proxy | VERIFIED-IN-CODE, `rpc.rs:1434-1436,1470-1479` | Exchange: a browser-facing tool must go through your own server-side proxy, never hit a direct node from a browser. |
| 7 | Self-hosted node RPC reachable at `127.0.0.1:8080`, sample run command uses `--transport dual --peer <ip>:19100` | Compiled default RPC port is **16310**, not 8080; `--peer` (singular) is not a flag at all (only `--peers`/`--p2p-peer`); the sample command as written will not start (missing `--data-dir`/`--genesis`, missing `--listen` for `dual`) | VERIFIED-IN-CODE, `main.rs:81,1119,1139-1154,1273-1278` | Exchange: use the corrected command line in §13.2. |
| 8 | `getutxos`/`listunspent` is "page-based (100 per page, no cursor); page until truncated is false" | There is no offset/cursor parameter at all; `limit` is a count, not a page index; repeating the call returns the identical first page forever | VERIFIED-IN-CODE, `rpc.rs:1109-1120,2149-2161` | Exchange: use the enumeration pattern in §10.4 (keep addresses under 1,000 outputs, or use `gettxout` for exact single-output checks). |
| 9 | Deposit-crediting mechanism: "read the output's block height … compare to `finalized_height`" | No RPC method returns an output's/transaction's creation height; `gettxout`'s `at_slot` is the *read's* current slot, not the output's | VERIFIED-IN-CODE, `rpc.rs:2176-2193`, `state_root.rs:1030-1042` | Exchange: use the observed-height cross-reference pattern in §11.2. |
| 10 | (Not present in edition 1 — a gap, not a contradiction) `getvalidators`, `gettxstatus`, `getbuildinfo` never mentioned | All three are live, tested, frozen-registry methods | VERIFIED-IN-CODE, `method_registry.rs`, `tests/rpc_method_registry.rs` | Exchange: use `gettxstatus` for tracking and `getbuildinfo` for cross-node build comparison (§10.2, §13.7). |
| 11 | `getmempoolinfo` sample response shows 4 fields | The method returns 8 fields (`barred`, `barred_hits`, `expired`, `evicted_low_fee` added) | VERIFIED-IN-CODE, `rpc.rs:2196-2231` | Exchange: do not assume a fixed field count for this method going forward. |
| 12 | Address regex `^bloch1q[0-9a-f]{48}$` (lowercase-only) | The reference parser accepts mixed-case hex in the body; the regex given is stricter than what the network accepts | VERIFIED-IN-CODE, `address.rs:79`, `hex` crate behaviour | Exchange: relax the validation regex, or lowercase before validating; every address this network *emits* is already lowercase. |
| 13 | Script-hash derivation ("40 hex right-padded with 24 zero hex chars") presented as *the* derivation | Correct only for the "Carried"/legacy-compatible form; a distinct, equally valid "Native" full-32-byte form exists and cannot be derived from an address string at all | VERIFIED-IN-CODE, `transition.rs:2061-2103` | Exchange: know both forms exist (§5.2); reconcile a deposit to a Native script_hash by the hash itself, since no address string represents it. |
| 14 | "40 hex = key hash (hash160)" | The hash is `SHA3-256(pubkey)[..20]`, not RIPEMD160(SHA256(pubkey)) — no RIPEMD160 exists anywhere in this codebase | VERIFIED-IN-CODE, `address.rs:56-60`; repo-wide grep, zero `ripemd` hits | Terminology only — does not change how to compute the hash. |
| 15 | Settlement rule: "finalized_height ≥ height ⇒ irreversible", no further caveat | Not backed by any slashing cost today (§2.8); the pure Casper-FFG rule can itself propose a legitimate downward finality cut, mitigated only by a per-node engine latch since 2026-09-05; a partitioned minority holding 6.25% of stake has self-finalized on this exact chain's own history before the epoch-2700 fix arms | VERIFIED-IN-CODE, `rpc.rs:1684-1814`, `finality.rs:63-81,1010-1030` | Exchange: apply the explicit crediting rule in §11.3 (finalized + ~30 epochs, two independent nodes agreeing on root and epoch). |
| 16 | (Not present in edition 1) L2 "EVM-compatible, chain id 8400" described as an optional current feature | No code implementing an EVM-compatible chain exists anywhere in this repository; the successor plan is an explicit `DRAFT` with no code for either track | VERIFIED-IN-CODE (absence), `docs/specs/BLOCH-L1-EXECUTION-PLAN.md:7` | Exchange: do not list chain id 8400 as a currently operating network. |
| 17 | (New fact, not a correction) Weak-subjectivity bootstrap | A fresh node cannot join the network from scratch as of this edition — see the boxed warning at the top of this document and §2.6/§13.4 | VERIFIED-IN-CODE, `ws_boot.rs`, `ws.rs` | Exchange: confirm current ceremony status with the endpoint operator before planning a from-scratch node deployment; see the companion operator memo. |
| 18 | Explorer footer lists `explorer.posternlabs.com / blochl1.com` as two current URLs | The project's own deploy configuration states `explorer.posternlabs.com` is a **retired** name and `blochl1.com` is the live domain | OPERATOR-ASSERTED (both sides — this repository's deploy config, not live DNS) | Exchange: use `blochl1.com` only; confirm with the operator before publishing the retired name. |
| 19 | (Not present in edition 1 — an internal-codebase discrepancy noted here, not a correction to a prior claim) §13.8 states `carryover.tsv` has 452,726 opening outputs | **452,726** (at Genesis-3's terminal height 39,918) is the authoritative, final figure — it matches both `CARRYOVER-SNAPSHOT.md`'s own `rows 452,726` and `tokenomics_v4::CARRYOVER_MEASURED_UTXOS = 452_726`, and §1's network-parameters table now cites the same number. A **different** figure, **452,133** (an earlier, non-terminal snapshot at height 39,328), still appears throughout `genesis.rs`'s comments and a `#[cfg(test)]`/benchmark constant in `engine.rs` (`MAINNET_EUTXOS`) — that constant's own doc comment flags the 593-output gap explicitly and states "which of the two is stale is for the founder to settle." Neither figure is wrong as a measurement; they are two different snapshots of the same address set taken 590 blocks apart, and only 452,726/height 39,918 is the one this document, `CARRYOVER-SNAPSHOT.md`, and the live carryover artifact treat as authoritative. | VERIFIED-IN-CODE, `bloch-pos-node/src/engine.rs:8285-8294` (`MAINNET_EUTXOS`, the gap noted in-code); `bloch-pos-node/src/genesis.rs:277` (452,133, height 39,328); `bloch-pos-committee/src/tokenomics_v4.rs:236` (`CARRYOVER_MEASURED_UTXOS = 452_726`); `CARRYOVER-SNAPSHOT.md` | Exchange: use 452,726 (§1, §13.8) as the authoritative opening-output count; do not be alarmed by 452,133 appearing in code comments and a dev-only benchmark constant elsewhere in the tree — it is a known, named, non-consensus-affecting discrepancy, not a sign the carryover figure this document cites is wrong. |

---

## 16. Appendix B — Evidence index

| Section | Primary files (this document's evidence) |
|---|---|
| §1 Network parameters | `bloch-pos-committee/src/params.rs`, `tokenomics_v4.rs`, `bloch-pos-node/src/genesis.rs`, `genesis/mainnet.manifest`, `genesis/README.md`, `bloch-pos-node/src/main.rs` |
| §2 Architecture and consensus | `bloch-pos-committee/src/finality.rs`, `committees.rs` (partition, `:288,396,799-830`), `schedule.rs`, `lib.rs` (`COMMITTEE_SIZE`/`SLOT_SUBCOMMITTEE_SIZE` re-export note), `params.rs:30,40,78,223` (`COMMITTEE_SIZE`, `SLOT_SUBCOMMITTEE_SIZE`, `MAX_ATTESTATIONS_PER_BLOCK`, `INACTIVITY_LEAK_RECOVERY_QUOTIENT`); `bloch-pos-committee/src/transition.rs:4669-4680` (`active_set` = whole duty roster); `bloch-pos-node/src/engine.rs` (fork choice, finality latch); `bloch-pos-node/src/rpc.rs:1684-1814` (`Finality` doc); `bloch-pos-committee/src/ws.rs`, `bloch-pos-node/src/ws_boot.rs`; `genesis/README.md` |
| §3 Activation gates | `bloch-pos-committee/src/params.rs` (every `*_ACTIVATION_EPOCH` constant and its doc comment); `bloch-pos-committee/tests/wire_tag_registry.rs` |
| §4 Cryptographic standards | `bloch-crypto/src/crypto/mod.rs`; `bloch-pos-committee/src/params.rs` (domain tags); `bloch-pos-committee/src/fee_market.rs:135-161` |
| §5 Addresses and script hashes | `bloch-crypto/src/address.rs`, `bloch-crypto/src/core/mod.rs:141-142`; `bloch-pos-committee/src/transition.rs:2061-2103` (`owns()`) |
| §6 Keys and wallets | `bloch-crypto/src/wallet/seed.rs`, `bloch-crypto/src/hd_wallet/mod.rs`, `bloch-crypto/src/crypto/mod.rs:73,356-369` |
| §7 Block format | `bloch-pos-committee/src/header.rs`; `bloch-pos-node/src/rpc.rs:1862-1897` |
| §8 Transactions | `bloch-pos-committee/src/transition.rs` (encodings, `apply_transfer`/`apply_transfer_v2`, conservation, gas-class derivation at `:3713,:3912`); `bloch-pos-committee/src/fee_market.rs` (gas formula, `:129,133,175,212-229,373-393,495-505,566`); `bloch-pos-committee/src/interfaces.rs:467-600` (`TransferReject`); `bloch-pos-committee/tests/wire_tag_registry.rs`; `bloch-pos-committee/src/params.rs` (`DEPOSIT_ACTIVATION_EPOCH`, `WITHDRAWAL_ACTIVATION_EPOCH` doc comments); `bloch-pos-node/src/engine.rs:5362-5410,4069-4074` (`admissible`, the `Deposit`/`Delegate` → `-32008` mapping) |
| §9 Mempool and broadcast | `bloch-pos-node/src/engine.rs` (admission, eviction, rejection bar, `select_transactions`) |
| §10 JSON-RPC API | `bloch-pos-node/src/rpc.rs` (whole file — transport gate, method handlers, error codes), `src/rpc/method_registry.rs`, `tests/rpc_method_registry.rs` |
| §11 Deposits | `bloch-pos-node/src/rpc.rs` (`gettxout`, `getutxos`), `bloch-pos-committee/src/state_root.rs:1030-1042`; `SECURITY.md` (crediting margin) |
| §12 Withdrawals | `bloch-pos-committee/src/transition.rs`, `fee_market.rs`; `bloch-pos-node/src/engine.rs` (mempool cap) |
| §13 Running a node | `bloch-pos-node/src/main.rs` (flags), `store.rs` (data dir), `ws_boot.rs`, `deploy/RELEASE-INTEGRITY.md`, `deploy/monitoring/*.yml`, `metrics.rs` |
| §14 Operational security notes | `SECURITY.md` (in this repository); `round3-report.md`/`round4-report.md` (the project's own internal audit records — **not files in this repository's source tree** — cited by name only for §14's commit-count/finding-count figures) |
| Appendix A | All rows individually cited above |

---

## 17. Appendix C — Glossary

- **eUTXO** — extended unspent transaction output; Genesis-4's ledger model. An
  output is keyed `(txid, vout)` and carries a `value` (sat) and a
  `script_hash`.
- **script_hash** — the 32-byte value a Genesis-4 output is locked to; what
  every balance/UTXO RPC method keys on. See §5.2 for its two accepted forms.
- **txid** — the deterministic, non-malleable transaction identifier,
  `SHA3-256(DS_TXID ‖ spend_signing_root)`. Computable before broadcast.
- **tx_hash** — a *different*, node-local, non-consensus digest over the raw
  canonical bytes (including witnesses), echoed only by
  `sendrawtransaction`'s response. Not the txid; do not settle on it.
- **spend_signing_root** — the value a transfer's signature actually commits
  to; excludes witnesses (signatures, pubkeys, the V2 witness table).
- **Justified / Finalized** — the two Casper-FFG checkpoint states; see §2.4.
  `finalized` is the state an integrator should credit against, subject to the
  caveats of §2.5–2.9 and the rule in §11.3.
- **finalized_height** — a height-shaped RPC projection of "the height of the
  block that currently holds the finalized checkpoint's root on this node."
  Not an independently tracked counter.
- **Weak subjectivity / WS checkpoint** — the out-of-band, multi-signature
  trust anchor a fresh node needs once the genesis-anchor trust window has
  expired. See §2.6.
- **Activation epoch / flag day** — a `u64` epoch number compiled into the
  binary; `u64::MAX` means the corresponding rule is inert. Every gate reads
  the epoch from the block being processed, never a clock, so a mixed
  old/new-binary fleet always agrees below its own gate.
- **Observer node** — a Genesis-4 node with no `validator.key`: applies every
  block, serves the full RPC surface, signs nothing, takes on no duties. The
  recommended posture for an exchange (§13.1).
- **Carried / Native (script_hash forms)** — see §5.2. "Carried" is the
  legacy-compatible, address-derivable, 160-bit-security form; "Native" is the
  full 32-byte, 256-bit-security form usable only when the payer holds the raw
  public key.
- **HYBRID_SIG_BYTES** — 4,589 bytes, a *measured*, not maximum, hybrid
  signature size used only for mempool declared-size budgeting (§4, §8.6).
- **BLCH / BLOCH** — BLCH is the canonical ticker; BLOCH is a Rust
  constant-naming convention only, never a second ticker (§1).
