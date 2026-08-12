<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# BLOCH-POS-NETWORK-CAPACITY — the G10 byte budget, with EVM at L1

> **Owner:** A9 (network capacity). **Status:** draft for review.
> **Gate under analysis:** G10 (`BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §11):
> *"54 KB/block average and the epoch-boundary burst (≈ 588 KB) sustained on
> the real fleet for ≥ 14 days: no gossip-mesh degradation, no yamux
> stream-limit failures, p99 propagation < 5 s."*
>
> **Nothing in this document is a measurement unless it cites a file that
> contains one.** Every number derived here is labelled either
> **[measured]** (with its source) or **[estimate]** (with its arithmetic
> shown). The load-test plan in §7 exists to convert the estimates into
> measurements before G10 is judged.
>
> Inputs as of 2026-08-11: `BLOCH-POS-SHA3-LATTICE-MIGRATION.md` (§5, §6.5,
> §11), `BLOCH-ATTESTATION-GOSSIP.md` (partially superseded; its seal says
> which premises moved), `crates/bloch-pos-committee/src/{gossip.rs,
> committees.rs, attestation.rs, params.rs, header.rs, staking.rs}`,
> `src/network/mod.rs`, `src/network/sync_rr.rs`,
> `spikes/prover-cost/RESULTS.md`, and the fleet brief 2026-08-11.
> `BLOCH-L1-FEE-MARKET.md` (DEV-3) **had not appeared anywhere in the tree or
> in any sibling worktree when this was written** — §4 states its assumptions
> explicitly and must be reconciled against that document when it lands.

---

## 1. The wire unit: one hybrid-signed attestation

Everything below is a multiple of one number, so it is derived once, here.

Signature halves **[measured — these are the sizes the real stack produces]**:

| Component | Bytes | Source |
|---|---:|---|
| ML-DSA-65 signature | 3,309 | `staking.rs:70` (`MLDSA65_SIG_BYTES`), confirmed against PQClean in `spikes/prover-cost/RESULTS.md` Gate 1 |
| Falcon-1024 signature, padded/typical | 1,280 | PQClean padded format; `staking.rs:533` uses 3,309 + 1,280 ≈ 4,589 |
| Falcon-1024 signature, absolute max | 1,462 | `bloch-crypto/src/core/mod.rs:330` (`SIG_SIZE` upper bound) |
| **Hybrid signature, nominal** | **4,589** | 3,309 + 1,280 — the figure used throughout the migration spec |
| Hybrid signature, hard upper bound | 4,771 | 3,309 + 1,462 |

Envelope around it (`attestation.rs`, wire format per
`BLOCH-ATTESTATION-GOSSIP.md` §4) **[estimate — the wire codec does not exist
yet; this is the field arithmetic]**:

```
AttestationData  = 8 (slot) + 32 (head) + 8 (source_epoch) + 32 (source_root)
                 + 8 (target_epoch) + 32 (target_root)        = 120 B
+ version (u32)                                               =   4 B
+ validator_index (u32)                                       =   4 B
+ hybrid signature (nominal)                                  = 4,589 B
--------------------------------------------------------------------
one attestation on the wire                          ≈ 4,717 B ≈ 4.7 KB
hard upper bound (Falcon max)                        ≈ 4,899 B
```

The `MAX_ATTESTATION_WIRE_BYTES = 8 KB` bound proposed in
`BLOCH-ATTESTATION-GOSSIP.md` §4 covers the hard upper bound with room; keep
it. **No public key rides with an attestation** — `validator_index` resolves
to keys in the registry committed under `state_root` (§5.5 of the migration
spec). This matters in §4, because EVM transactions do not get that luxury
for free.

---

## 2. The per-block budget under the partition model — and the G10 numbers re-derived

### 2.1 The model that is actually in the code

G10's two numbers (54 KB average, 588 KB boundary burst) were written against
the **sampled** design: 8 attesters per slot + a 128-member committee voting
in a burst at the epoch boundary. That design is superseded by the partition
(`committees.rs`, finding F1): the active set of N validators is shuffled and
cut into `SLOTS_PER_EPOCH = 32` committees, **one committee per slot**, each
validator voting exactly once per epoch. `transition.rs` and `finality.rs`
consume `committees::epoch_committees` / `committee_for_slot`; the sampled
API (`lib.rs::epoch_committee`, `COMMITTEE_SIZE = 128`,
`SLOT_SUBCOMMITTEE_SIZE = 8` in `params.rs`) remains in-tree as a record but
is not what the state transition uses.

Consequence for the network: **there is no 128-vote boundary burst anymore.**
Attestation load is flat across the epoch — `ceil(N / 32)` attestations per
slot, every slot. The traffic shape G10 describes no longer occurs in the
steady state. The arithmetic behind both G10 numbers is checked below anyway,
because both survive in different roles.

### 2.2 The account

Per-slot attestation bytes, at 4,717 B per attestation **[estimate]**:

| Active validators N | Committee/slot = ceil(N/32) | Attestation bytes per block | Sig-only (× 4,589) |
|---:|---:|---:|---:|
| 200 (gate G4 floor) | 7 | 33.0 KB | 32.1 KB |
| 384 (break-even vs sampled) | 12 | 56.6 KB | **55.1 KB ≈ "54 KB"** |
| 1,000 | 32 | 151.0 KB | 146.8 KB |
| 4,096 (ceiling, `committees.rs`) | 128 | 603.8 KB | **587.4 KB ≈ "588 KB"** |

Fixed per-block overhead on top (`header.rs`): header 248 B + proposer
hybrid signature in the envelope ≈ 4,589 B ≈ **4.8 KB** — noise against the
attestation term.

**Verdict on the G10 numbers:**

- **"54 KB/block average" — confirmed, by coincidence of arithmetic.**
  The sampled design's adopted row (8/slot + 128/epoch averaged = 53.8 KB,
  `spikes/prover-cost/RESULTS.md` scenario D) and the partition at N = 384
  (12 × 4,589 = 55.1 KB) land within 3% of each other. The gate's average
  holds **if and only if N ≈ 384**; at the G4 floor of 200 it is 32–33 KB,
  at N = 1,000 it is ~150 KB. G10 should say "at the launch validator count"
  explicitly, or it will be read as a constant.
- **"≈ 588 KB epoch-boundary burst" — the arithmetic is right
  (128 × 4,589 = 587,392 B), the scenario is gone.** Under the partition
  there is no boundary quorum. The figure survives in two *different* roles:
  1. **Catch-up block worst case.** A slot with no block still has a
     committee, and its attestations (voting the previous head) remain
     includable within the inclusion window (8 slots proposed,
     `BLOCH-ATTESTATION-GOSSIP.md` §5.2). A block produced after k empty
     slots may carry up to `(k+1) × ceil(N/32)` attestations: at N = 384
     with the full 8-slot window, 96 × 4,717 ≈ **453 KB** [estimate] — same
     order as 588 KB.
  2. **The scaling ceiling.** At N = 4,096 every block carries ≈ 604 KB of
     attestations — the old burst becomes the *sustained* rate. That is the
     honest reading of the `committees.rs` ceiling in network terms.
  So the 588 KB stress level remains a valid test target, but G10's wording
  should change from "epoch-boundary burst" to "worst-case attestation
  payload (catch-up block / ceiling load)". A consensus cap
  **`MAX_ATTESTATIONS_PER_BLOCK`** is required so the catch-up case is
  bounded by rule, not by luck — proposed value: `8 × ceil(N/32)` computed
  from the active-set size in the parent state, i.e. the inclusion window
  itself is the cap. Owner: DEV-1, as a consensus constant with KAT.

### 2.3 Double carriage, and per-node bandwidth

Every attestation crosses the wire **twice**: once as gossip on the
attestation topic (so fork choice and the next proposer see it), once inside
the block body on `bloch/blocks/1` (so it is part of the chain). Ethereum
pays the same 2×; it is not a defect, but capacity math that counts each
byte once is wrong by half.

Per-node steady-state egress, gossipsub mesh degree D ≈ 6 (libp2p default;
`src/network/mod.rs` does not override `mesh_n`) — each message forwarded to
at most D mesh peers **[estimate]**:

| N | Attest topic | Blocks topic (attestation share) | Total attestation-driven egress |
|---:|---:|---:|---:|
| 200 | 33 KB/30 s × 6 ≈ 6.6 KB/s | ≈ 6.6 KB/s | ≈ 13 KB/s ≈ 0.11 Mbps |
| 384 | ≈ 11.3 KB/s | ≈ 11.3 KB/s | ≈ 23 KB/s ≈ 0.18 Mbps |
| 4,096 | ≈ 121 KB/s | ≈ 121 KB/s | ≈ 242 KB/s ≈ 1.9 Mbps |

Trivial at launch scale; still viable at the ceiling on datacentre links, and
the first real pain for a home validator on an asymmetric uplink. Bandwidth
is **not** the binding constraint below N ≈ 1,000 — propagation latency of
large single frames is (§5), and EVM bytes are (§4).

### 2.4 Propagation p99 < 5 s — the estimate G10 will test

Per-hop time = frame_size / link_rate + RTT/2 + validation-before-relay.
Fleet eccentricity at ≤ 50 peers, D = 6: 3–4 hops **[estimate]**. Native
hybrid verification is sub-millisecond per attestation on fleet hardware
(`BLOCH-ATTESTATION-GOSSIP.md` §1 — itself an estimate from the 1000×
in-circuit/native ratio, **not measured**; the §7 plan measures it).

| Scenario | Frame | 100 Mbps links | 10 Mbps links |
|---|---:|---:|---:|
| Launch block, N = 384 | ~62 KB + txs | ≈ 5 ms/hop → **< 0.5 s p99** | ≈ 50 ms/hop → < 1 s |
| Catch-up block, N = 384 | ~460 KB + txs | ≈ 37 ms/hop → < 1 s | ≈ 370 ms/hop → ~2 s |
| Ceiling block, N = 4,096 | ~610 KB + txs | ≈ 49 ms/hop → < 1 s | ≈ 490 ms/hop → **~2.5–3 s** |
| 2 MiB EVM-full block (§4) | 2.1 MB | ≈ 170 ms/hop → ~1 s | ≈ 1.7 s/hop → **> 5 s: FAILS** |

All rows are estimates. The last row is the load-bearing one: **G10's p99
< 5 s cannot be met for 2 MiB blocks if any mesh path crosses a 10 Mbps
link.** Either the block byte cap stays ≤ ~1 MiB, or validator hardware
requirements state a minimum sustained 50 Mbps up/down, or G10's threshold is
re-justified. That choice belongs to the founder alongside the §4 fee-market
decision; this document recommends the 1 MiB target / 2 MiB hard cap with a
50 Mbps validator requirement (§4.3).

---

## 3. EVM at L1 — what it adds to the byte budget

`BLOCH-L1-FEE-MARKET.md` (DEV-3) did not exist when this was written; the
following is the network-capacity envelope any fee market must live inside,
stated so DEV-3 can price it. The three authorisation options are the fleet
brief's; each is priced in **bytes**, which is the resource gossip actually
spends.

### 3.1 Bytes per EVM transaction, by signature option [estimate — field arithmetic]

| Option | Signature | Pubkey on wire? | Simple transfer | ERC-20-style call |
|---|---:|---|---:|---:|
| secp256k1 accounts | 65 B | no (recoverable) | ~110 B | ~180 B |
| PQ hybrid (suite 0x0001) | 4,589 B | **yes, unless cached** — ML-DSA pk 1,952 B + Falcon pk 1,793 B = 3,745 B | 4.7 KB (pk cached in account state) / **8.4 KB** (first use) | +70 B |
| ML-DSA-only (escape 0x0002) | 3,309 B | yes unless cached (1,952 B) | 3.4 KB / 5.3 KB | +70 B |

The pubkey line is the part nobody prices until it bites: lattice signatures
are **not recoverable**, so the verifier must hold the key. An account model
can cache the pubkey in account state after first use (making first-use
transactions ~8.4 KB and subsequent ones ~4.7 KB, at the cost of ~3.7 KB of
state per account); a stateless design pays 8.4 KB on every transaction.
The fee market must charge for those bytes either way.

### 3.2 Throughput inside a block byte budget [estimate]

Transactions per block for a given tx byte budget (transfers, pk cached):

| Tx budget/block | secp256k1 | PQ hybrid | ML-DSA-only |
|---:|---:|---:|---:|
| 256 KB | ~2,300 (78 tps) | 55 (1.8 tps) | 75 (2.5 tps) |
| 1 MiB | ~9,500 (317 tps) | 222 (**7.4 tps**) | 310 (10.3 tps) |
| 2 MiB | ~19,000 (634 tps) | 445 (14.8 tps) | 620 (20.7 tps) |

This is the quantitative form of the fleet brief's "each option costs
something real": **PQ-only accounts put L1 EVM throughput in single-digit
tps per MiB of block budget.** That is not an argument for secp256k1 — it is
the number the founder's choice buys, stated so it is chosen with eyes open.
Gas alone cannot express this: a PQ transfer costs the same 21k-gas-worth of
*execution* as a secp transfer but ~43× the *bytes*. **The fee market MUST
carry a byte-denominated dimension** (calldata-style byte gas or a separate
byte limit); a gas-only limit lets cheap-gas/fat-byte transactions fill the
frame and blow the propagation budget. This is a hard requirement handed to
DEV-3.

### 3.3 Proposed block-size constants (for DEV-1/DEV-3, devnet-sweepable)

| Constant | Proposed | Rationale |
|---|---:|---|
| `MAX_BLOCK_BYTES` (consensus hard cap) | 2 MiB | Half the transport frame cap (`MAX_WIRE_BYTES` = 4 MiB, `src/network/mod.rs:198`; gossipsub `max_transmit_size` 4 MiB, `mod.rs:640`) — a full block plus envelope can never brush the layer that **drops the message** rather than queueing it |
| Block byte *target* (fee-market equilibrium, EIP-1559-style) | 1 MiB | Keeps the §2.4 propagation estimate inside p99 < 5 s on 10–50 Mbps paths |
| Tx byte budget within it | `MAX_BLOCK_BYTES − MAX_ATTESTATIONS_PER_BLOCK × 4,899 − 8 KB` | Attestation worst case (§2.2) and header/envelope are consensus overhead; transactions get the remainder. At N = 384: ≈ 1.5 MiB |

The 4 MiB transport cap is a *cliff*, not a limit: gossipsub drops
oversized frames on the floor. A consensus block cap at 2 MiB keeps a 2×
safety margin so no valid block is ever unpropagatable — the worst consensus
failure a capacity bug can produce.

### 3.4 Topic capacity

EVM transactions ride the existing `bloch/txs/1`. At PQ sizes, mempool
gossip becomes the dominant steady-state flow (each tx also crosses twice:
mempool + block). P3/P3b are already zeroed on the tx topic
(`mod.rs:702–715`), so higher rate is score-positive, not score-dangerous.
One real risk: a 4.7–8.4 KB tx spam stream is ~43× cheaper for an attacker
to saturate byte-wise than for the mempool to filter. Mempool admission must
fee-gate **per byte** before relay — same shape as the dust rule the PoW
chain learned (`bloch-dust-tx-poisons-pool-blocks`), one layer down.

---

## 4. The three documented failures — audited in the code Genesis-4 will use

The integration plan (`BLOCH-POS-NODE-INTEGRATION.md:301–305`) is explicit:
the Genesis-4 node **copies and adapts the Genesis-3 libp2p layer, keeping
the two hard-won mesh fixes and the yamux alignment**, under a new network
ID. The Genesis-3 layer in *this repo's tree* is therefore the code that
will be carried. Audit of that tree, this worktree, commit `f384292`:

### 4.1 Mesh root cause #1 — `add_explicit_peer()` on every connection

**Fixed, with the fix pinned by a comment block.** The
`ConnectionEstablished` handler (`src/network/mod.rs:1181–1196`) contains no
`add_explicit_peer` call and carries the full incident write-up ("DO NOT
call gossipsub.add_explicit_peer() here", citing libp2p 0.49.5
`behaviour.rs:2224` and `:1395`). `grep -rn add_explicit_peer src/` returns
only that comment. **Verified in code, not presumed.**

### 4.2 Mesh root cause #2 — `TopicScoreParams { ..Default::default() }` inheriting P3/P3b

**Fixed for the three existing topics; structurally open for the two new
ones.** All three topics set `mesh_message_deliveries_weight: 0.0` and
`mesh_failure_penalty_weight: 0.0` explicitly (`mod.rs:687–727`), with the
incident math in the comment. Two residual risks, both real:

1. The `..Default::default()` spread is still used for the inert fields, so
   a future libp2p default change or a careless refactor can silently
   re-arm P3. `BLOCH-ATTESTATION-GOSSIP.md` §7.2 already mandates a startup
   assertion (`mesh_message_deliveries_weight == 0.0` on every registered
   topic); that assertion **does not exist yet** anywhere in the tree.
2. `with_peer_score` failure is a **warn, not fatal** (`mod.rs:749–751`).
   Under PoS, scoring is a liveness dependency; a node that silently runs
   unscored is a flood amplifier. Must be promoted to a fatal startup error
   in the adapted layer (also already called for in the gossip spec §4).

The attestation topics themselves do not exist yet (see 4.5) — when DEV-3
writes them, §7.2 of the gossip spec has the exact params, P3/P3b zeroed.

### 4.3 yamux stream cap vs request-response cap

**Fixed, with a documented backend trade-off.**
`MAX_YAMUX_STREAMS = 4096` (`mod.rs:554`), applied via
`yamux_config()` → `set_max_num_streams` on both TCP and WebSocket builders
(`mod.rs:560–566, 766, 773`), sitting 2× above
`sync_rr::MAX_CONCURRENT_SYNC_STREAMS = 2048` (`sync_rr.rs:220, 230`). The
comment records the known trade-off: any setter flips libp2p-yamux 0.47
from the yamux 0.13 backend to 0.12 — interoperable on the wire, but a
not-yet-updated **remote** still enforces 512 on its side. For Genesis-4
this caveat dissolves: the whole fleet launches on one binary, so no mixed
enforcement exists. **Verified in code.**

Attestations add ~zero stream pressure (gossipsub = one long-lived substream
per peer per direction). The standing rule from the gossip spec §9.1 is
restated as a G10 pass condition: **attestations never ride
request-response** — a "fetch the quorum" rr endpoint would open
O(committee) streams exactly when sync_rr is busiest.

### 4.4 The backfill flood (2026-08-09) — structural answer present in the new crate

`crates/bloch-pos-committee/src/gossip.rs` is the application-side policy
and it encodes the structural fix the PoW chain only had operationally:
`ATTESTATION_WINDOW_SLOTS = 64` (two epochs) with out-of-window frames
**Ignored, never penalized** (`gossip.rs:54, 233–237`); a stale node's dump
is capped at two epochs of relevance by rule. The three-verb split
(Accept/Ignore-or-Hold/Reject) is enforced at the type level
(`IgnoreReason` vs `RejectReason` are distinct types, `gossip.rs:81`), so an
implementation *cannot* accidentally wire an honest race into a peer
penalty — the graylist-reintroduction vector from `BLOCH-ATTESTATION-GOSSIP.md`
§7.1-Q2. The pending pool is bounded (256, FIFO, `gossip.rs:68`) and sits
behind the committee-membership check, so only member-indexed frames occupy
it. There is a per-block equivalent still to write: the block topic needs
the same window rule for PoS blocks (a slot-window acceptance on
`bloch/blocks/1`), or the 08-09 shape returns via block frames instead of
attestations. **Open item, owner DEV-3, listed in §7's test matrix.**

### 4.5 What Genesis-4 actually has today — stated honestly

`crates/bloch-pos-node` is a **skeleton with no networking at all**
(its own Cargo.toml says so; the only dependency is the pure consensus
crate). Nothing in this section is "done" for Genesis-4 — what is verified
is that the *source* layer G4 will copy has all three fixes, and that the
new policy crate repeats none of the root causes (it touches no socket, no
`TopicScoreParams`, no yamux — it cannot). The copy-and-adapt step is where
a regression would happen. Two mandatory guards for that step:

1. The §4.2 startup assertion (P3/P3b zero on every topic), written as code
   in M2, not as a checklist item.
2. A diff review of the adapted `net/` against `src/network/mod.rs`
   specifically for the three incident sites (A4 checklist line).

Also noted: `params.rs` still carries `COMMITTEE_SIZE = 128` /
`SLOT_SUBCOMMITTEE_SIZE = 8` and `lib.rs:147` still exports the sampled
`epoch_committee()` — vestigial after the partition correction, marked
in-tree as historical. They are exactly the kind of second derivation path
the header property test exists to catch, one layer up. Recommend demoting
them behind a `#[deprecated]` or a `legacy_sampled` module before M1, so no
node code can draw a committee the superseded way.

---

## 5. Aggregation, re-asked as a network question

The prover spike (`spikes/prover-cost/RESULTS.md`) measured 7,274,849 RV32IM
instructions per in-circuit hybrid verification **[measured]**, exactly
linear in N, and concluded aggregation was unnecessary because the cadence
change removed the proving/storage requirement (§6.5.1 of the migration
spec: "the spike did not find a way to pay the cost; it found a way not to
incur it").

That conclusion was about **proving cost and archival storage**. The network
question is different: does the per-block wire budget need aggregation? The
answer, re-derived from §2:

- **At gate-G4 launch scale (N = 200–400): the conclusion survives.**
  33–57 KB of attestations per block, ~0.2 Mbps of attestation-driven
  egress per node, propagation comfortably inside p99 < 5 s [estimate,
  §2.4]. Nothing at this scale wants aggregation.
- **The conclusion is scale-bounded, and the bound is the same one
  `committees.rs` already records (~4,096), but it arrives earlier with
  EVM.** The network budget and the EVM budget share one frame: at
  N = 1,000 attestations already take ~150 KB of every block, and every KB
  of attestation is a KB taken from the §3.3 transaction budget or added to
  the propagation time. The practical no-aggregation region is
  **N ≲ 1,000 with EVM at L1** [estimate]; between 1,000 and 4,096 the
  chain still functions but pays in either tx throughput or propagation
  margin; at 4,096 the ceiling is hard.
- **If PQ-signed EVM transactions are chosen, attestation aggregation is
  not even the right lever.** Transaction signatures then dominate the
  frame (a block with 200 PQ txs carries ~940 KB of tx signatures against
  ~57 KB of attestations at N = 384). Compressing the consensus overhead
  while the payload is 16× larger buys ~6%. The levers that matter in that
  world are the byte-denominated fee dimension (§3.2) and, long-term, the
  same FRI-STARK batching for *transaction* validity — which is the
  research-frontier item the spike measured, unchanged.

So: **no dependency on aggregation is introduced by the network budget at
launch scale — the spike's conclusion stands there — but the migration
spec's sentence "aggregation would still be nice (it would let the committee
grow without bound)" should gain a clause: with EVM at L1, the validator-set
ceiling the network can carry without aggregation is nearer 1,000 than
4,096.** Recording that now is the cheap version of discovering it later,
which is the same reasoning `committees.rs` applied to its own ceiling.

---

## 6. Summary of required changes (each with an owner)

| # | Change | Owner | Where |
|---|---|---|---|
| 1 | Reword G10: "54 KB average **at N ≈ 384**"; replace "epoch-boundary burst" with "worst-case attestation payload (catch-up / ceiling), ≈ 588 KB test level" | PMO (spec edit) | `BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §11 |
| 2 | `MAX_ATTESTATIONS_PER_BLOCK` = inclusion-window × ceil(N/32), consensus constant + KAT | DEV-1 | rules/ |
| 3 | `MAX_BLOCK_BYTES` 2 MiB hard / 1 MiB target; byte-denominated fee dimension | DEV-3 (fee market) + DEV-1 | `BLOCH-L1-FEE-MARKET.md` when it lands |
| 4 | Startup assertion: P3/P3b == 0.0 on every registered topic | DEV-3, M2 | adapted `net/` |
| 5 | `with_peer_score` failure warn → fatal | DEV-3, M2 | adapted `net/` |
| 6 | Slot-window acceptance on the PoS blocks topic (08-09 rule for blocks, not just attestations) | DEV-3 | adapted `net/` |
| 7 | Demote sampled-committee API (`epoch_committee`, `COMMITTEE_SIZE`, `SLOT_SUBCOMMITTEE_SIZE`) to a marked legacy module | DEV-1/PMO | `bloch-pos-committee` |
| 8 | Validator hardware doc: minimum 50 Mbps symmetric if 2 MiB blocks are kept; else cap at 1 MiB | founder decision input | this doc §2.4/§3.3 |

---

## 7. Load-test plan — executable, staged, with pass criteria mapped to G10

Design constraint on the plan itself: both 2026-08-07 mesh collapses were
reproduced with **two fresh nodes on localhost** (`mod.rs:1196`), and the
backfill incident has an in-tree lab (`tests/backfill_flood_lab.rs`); the
in-process two-node harness affordance exists (`listen_report`,
`mod.rs:604–612`, used by `tests/sprint_ee_convergence.rs`). The plan builds
outward from that proven method instead of starting on the fleet.

### L0 — localhost mesh soak (runs today, against the Genesis-3 binary)

The G4 network layer does not exist yet (§4.5); attestation-*sized* traffic
can still be characterised now, because gossipsub does not care what the
bytes mean.

- **Setup:** 12 in-process or local-process nodes (the `listen_report`
  harness), default mesh params, the three existing topics.
- **Traffic:** synthetic frames on `bloch/txs/1` shaped like the §2.2 rows:
  steady `ceil(N/32) × 4.7 KB` per 30 s for N ∈ {200, 384, 1000, 4096},
  plus a 453 KB and a 604 KB single frame each "epoch" on `bloch/blocks/1`.
- **Assert:** zero peers cross `graylist_threshold` (−400); zero
  `NoPeersSubscribedToTopic`; zero "maximum number of streams reached";
  mesh size per topic ≥ 4 at every heartbeat after warm-up; delivery of
  every frame to all 12 nodes.
- **Duration:** ≥ 24 h per N row. Cheap, automatable in CI as a nightly.

### L1 — adversarial localhost (extends L0; needs the M2 `net/` for the attestation parts)

Replays each documented incident against the new layer, plus the new risks:

| Scenario | Injection | Pass criterion |
|---|---|---|
| Boundary/catch-up race | attestation frames published 0–500 ms *before* their block frame | 100% resolve via Hold → Accept; **zero** Reject on honest frames (`gossip.rs` decisions logged); no peer score drop |
| Stale-node backfill (08-09 shape) | 1 node replays 2+ epochs of old attestations and blocks at line rate | all dropped as `OutsideWindow` Ignore; zero penalty on the stale peer; producers' slot timing unaffected (no missed proposals) |
| Invalid-signature spam | 1 peer emits in-window, member-indexed, bad-signature attestations | emitting peer graylisted ≤ 10 frames [gossip spec §7.3]; honest peers unaffected; verify-budget bounded (token bucket drops before verify) |
| Equivocation amplification | 1 validator emits 50 variants per duty | exactly 2 relayed, rest `EquivocationLimit`-ignored; one `SlashingEvidence` captured |
| Stream storm | concurrent sync_rr GetBlock at the 2048 cap while gossip runs | zero connection kills; yamux stream high-water < 4096 |
| P3 regression guard | assert on every node at startup | `mesh_message_deliveries_weight == 0.0` on all topics (change #4) |
| Frame-cliff probe | blocks at 1.9 MiB, 2.0 MiB (valid) and 4.1 MiB (must be consensus-invalid before it is transport-dropped) | valid blocks propagate; the oversized block is rejected by rule with an attributable error, never silently lost |

### L2 — shaped-network stage (localhost + `tc netem`, Linux box)

Same matrix as L1 with per-node egress shaping at 10 / 50 / 100 Mbps and
40–120 ms RTT. This is what converts the §2.4 propagation **estimates**
into numbers: record per-frame first-seen timestamps on every node
(extend `src/metrics` — `set_peer_count` etc. exist; add
`observe_propagation_seconds` histogram and per-topic
`ingest_shed_total`), compute p50/p99 per frame class. Pass: p99 < 5 s for
every frame class the §3.3 caps allow; the 2 MiB row at 10 Mbps is
*expected* to fail and thereby pins change #8's decision with data.

### L3 — fleet soak (the G10 gate proper, ≥ 14 days)

- **Topology:** the real boxes (miner-box, node4, auxpow box, founder node,
  + ≥ 4 externally-hosted nodes in distinct regions/providers) running the
  Genesis-4 binary on the devnet/shadow-fork chain with synthetic validator
  keys at N = 384 equivalent duty load, EVM tx generator at the 1 MiB
  target.
- **Continuous injections:** one stale replayer, one invalid-spammer, a
  catch-up event (kill the proposer for 4–8 slots) every 6 h, one node on a
  shaped 10 Mbps link.
- **Pass = G10, measured:** p99 propagation < 5 s across all nodes for 14
  consecutive days; zero yamux stream-limit disconnects (grep the fleet
  journals for "maximum number of streams"); zero honest-peer graylists
  (score export per peer); mesh ≥ `mesh_n_low` on every topic at every
  heartbeat; attestation inclusion rate ≥ 99% (participation is the
  end-to-end proof that propagation worked); zero `ingest_shed_total` on
  the attestation channel.
- **Artifacts:** the metrics time series and the journal greps attach to
  the G10 sign-off. If any estimate in §2/§3 is off by more than 2×, this
  document gets a measured-figures revision before the gate is judged.

---

## 8. What this document did NOT do

- **No measurement was run.** Every network figure in §2–§5 is arithmetic
  from measured *sizes* (signature bytes, instruction counts) — propagation
  times, hop counts, and bandwidth are estimates until L2/L3 run.
- The L0 harness was **not implemented** — the plan cites the existing
  harness affordances it would build on, but no test code was written.
- `BLOCH-L1-FEE-MARKET.md` did not exist in any worktree at writing time;
  §3's envelope is stated as input *to* that document, and reconciliation
  is a follow-up task, not done here.
- EVM *state-growth* capacity (account trie size from 3.7 KB cached
  pubkeys, state-sync bandwidth) is out of scope here — it is a storage
  question, flagged to whichever agent owns the EVM-at-L1 state design.
- The gossipsub mesh-degree and heartbeat parameters were taken as libp2p
  defaults (verified only that the tree does not override `mesh_n`); a
  parameter sweep is L2's job.
- No changes were made to `BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §11 —
  change #1 is proposed here, applied by the PMO, because a gate's text
  should not be edited by the agent auditing it.

## 9. Copyright

Copyright (C) 2026 Postern Labs Ltda.
This document is part of the Bloch protocol documentation, licensed under
AGPL-3.0-or-later.
