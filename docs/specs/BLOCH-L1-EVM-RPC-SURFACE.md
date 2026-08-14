<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch — the `eth_*` JSON-RPC surface for EVM at L1

> **Genesis-4 is live.** Bloch has been running under **proof of stake** since
> 21:31:19 UTC on 2026-08-13, when Genesis-3 (proof of work) stopped
> permanently at height **39,918**. 30 s slots, 32-slot epochs, Casper-style
> justification/finalisation by epoch, hybrid ML-DSA-65 ‖ Falcon-1024
> signatures on every consensus path. Nothing in this document that describes
> mining, hashrate, difficulty, retargeting or proof-of-work depth describes
> the current network.
>
> **The live security question is concentration, not hashrate.** All 64
> validators are operated by a single entity; 93.94% of the carryover
> (17,046,829,380 of 18,146,400,000 BLOCH) sits at one address and carried
> balances are stakeable, so if that balance stakes the Nakamoto coefficient
> is 1; and 56,046,829,380 of the 57,146,400,000 BLOCH issued at slot 0 is
> held by the founder and the Foundation, leaving 1.92% of genesis supply in
> third-party hands. One operator can halt the chain and one holder can outvote
> every other. The live transport is a point-to-point TCP full mesh with a
> fixed peer list, **no discovery and no authentication**, and
> `Deposit`/`Delegate` are refused at every node's mempool — which is why a
> third party cannot yet join the network or become a validator.

```
Document:   BLOCH-L1-EVM-RPC-SURFACE
Status:     DRAFT — wave 2026-08-11, agent A2 (tool surface)
Created:    2026-08-11
Author:     Assistant A2
Parents:    docs/FLEET-BRIEF-2026-08-11.md ("EVM at L1, no L2"),
            docs/specs/BLOCH-RPC-V4.md (the native V4 surface; rules R1–R4),
            docs/specs/BLOCH-ECOSYSTEM-MIGRATION.md §5 (the L2 being replaced),
            docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md §5.3/§5.5
            (BlockHeaderV4, state commitment)
Blocks on:  the authorisation decision (secp256k1 / PQ-only / both) — owned by
            DEV-2 per the fleet brief; NOT decided in-tree as of 2026-08-11.
            §5 of this document prices the RPC consequences of each branch so
            the decision does not have to be re-litigated at the RPC layer.
```

If the EVM runs at the base layer, the node must speak `eth_*` JSON-RPC —
that protocol *is* the tool surface: MetaMask, ethers.js, viem, Foundry,
Hardhat, block explorers and indexers all speak it and nothing else. But the
Bloch L1 has slots, epochs and Casper-FFG finality, SHA3 hashing, a
non-keccak state commitment, and (pending DEV-2) possibly no secp256k1
accounts. This document maps, method by method, where the standard surface
carries over cleanly, where it carries over with changed meaning, and where
it cannot carry over at all.

**Honesty rule for this document**: claims about how specific tools
(MetaMask, ethers.js) *react* to a response are marked **[assumption —
verify]** unless they follow directly from the JSON-RPC/EIP specifications.
Nobody ran MetaMask against a Bloch node; there is no Bloch `eth_*`
implementation to run it against yet.

---

## 0. Ground rules

- **G1 — Two namespaces, one node, two conventions.** The native V4 surface
  (`getchaininfo`, `gettxstatus`, …) and the `eth_*` surface are served by
  the same node. The `eth_*` namespace follows the Ethereum JSON-RPC
  conventions *exactly*: `0x`-prefixed hex quantities (minimal-length, so
  `0x0` not `0x00`), hex-encoded byte strings, `null` results where the spec
  says `null`, and top-level JSON-RPC `error` objects. The V3 defect of
  `result.error` strings with HTTP 200 (fixed for V4 by BLOCH-RPC-V4 R4)
  must never leak into `eth_*` — Ethereum clients do not special-case it and
  will treat a `result` containing an `error` key as a successful, malformed
  response.
- **G2 — Amounts are hex on `eth_*`, strings on native.** BLOCH-RPC-V4 R3
  (decimal-string satoshis) applies to the native namespace only. `eth_*`
  amounts are hex quantities in **wei-like base units** (see §2.4 on
  decimals). The two encodings never mix within one namespace.
- **G3 — Finality is a state, not a number** (BLOCH-RPC-V4 R1). Everywhere
  the Ethereum surface grew finality awareness post-merge (`safe`/
  `finalized` block tags), Bloch adopts the same tag names with
  checkpoint-backed meanings (§3). Nothing in `eth_*` reintroduces
  depth-as-security.
- **G4 — Don't invent nonstandard extensions where a standard shape
  exists.** Extra Bloch-specific response fields are allowed only where §4.3
  explicitly says so, because unknown fields are *usually* ignored by JSON
  parsers but strictly-typed clients (generated Go/Java bindings) can reject
  them **[assumption — verify against the specific SDKs we care about]**.

---

## 1. The chain model tooling sees: slots, heights, block numbers

The facts, from the frozen code:

- A slot lasts `SLOT_DURATION_SECS` = 30 s and an epoch is `SLOTS_PER_EPOCH`
  = 32 slots (`crates/bloch-pos-committee/src/params.rs:30,34`), so an epoch
  is 16 minutes of wall clock.
- Slots can be **empty**: a proposer that is offline or whose block is not
  seen produces no block for that slot. `BlockHeaderV4`
  (`crates/bloch-pos-committee/src/header.rs:87`) carries `slot` but **no
  height field** — height is a node-derived index (the count of blocks on
  the canonical chain below this one), which BLOCH-RPC-V4 §3.2 already
  exposes as `height` alongside `slot`.

### 1.1 Decision: `eth` block number = height, and heights are contiguous

**A skipped slot is a skipped slot, not an empty block, and it does not skip
a block number.** Because height counts *blocks* (not slots), the height
sequence is contiguous by construction: block N's parent is always block
N−1. The `eth_*` surface maps block number ≡ height, and slots never appear
in any standard field.

This is exactly what Ethereum itself does post-merge: mainnet misses slots
routinely, and `blockNumber` remains gapless while `timestamp` jumps by a
multiple of 12 s. Every EVM tool already lives with this. The alternatives
are both worse:

- *Block number = slot* would create gaps. Tools genuinely assume
  contiguity: indexers walk `N, N+1, N+2, …` and treat a missing number as
  an error or a not-yet-produced block; `eth_getBlockByNumber` returning
  `null` for a mid-chain number breaks binary-search-by-timestamp helpers
  and confuses `ethers.provider.getBlock`. **[The precise failure mode per
  tool is an assumption — but the existence of the assumption of contiguity
  is not; Ethereum chose gapless numbers for this reason.]**
- *Synthesising empty blocks for empty slots* would fabricate block hashes
  with no consensus object behind them — an invented identity, exactly the
  bug class the single-derivation-path rule exists to kill.

Consequences to document for integrators (all inherited from Ethereum's own
post-merge behaviour, so tooling copes):

- `timestamp` is derived: `genesis_time + slot × SLOT_DURATION_SECS`
  (`schedule.rs`). Successive blocks' timestamps differ by 30 s × (1 + missed
  slots), so timestamp deltas are *not* a constant and "average block time"
  measured from timestamps is ≥ 30 s.
- Under a finality stall with low participation, gaps can be long. Tools
  that estimate "blocks until X" from a hardcoded block time will drift.
  This is display-level breakage only.

### 1.2 What `slot`/`epoch` tooling gets

Standard fields only, plus one honest reuse: post-merge Ethereum repurposed
the header's `mixHash` field to carry `prevRandao`. Bloch does the same —
`mixHash` carries `randao_mix` (header field, `header.rs`). Contracts
reading `block.prevrandao` (opcode 0x44, post-EIP-4399 semantics) thereby
get the real beacon value. Anything richer (slot, epoch, proposer_index,
checkpoint roots) lives on the **native** namespace (`getblock`,
`getchaininfo` — BLOCH-RPC-V4 §2/§3.2); dapps that need it call the native
API. We do not add nonstandard fields to `eth_getBlockByNumber` responses
(G4), with one exception noted in §2.2.

---

## 2. Blocks: `eth_blockNumber`, `eth_getBlockByNumber`, `eth_getBlockByHash`

### 2.1 `eth_blockNumber`

Returns the height of the canonical tip, hex-encoded. Nothing subtle —
given §1.1, this is a monotone, gapless counter. During a sync it reports
the node's own tip (standard behaviour); `eth_syncing` (§8) is the signal
tools use to detect lag.

### 2.2 `eth_getBlockByNumber` / `eth_getBlockByHash` — field mapping

| `eth` field | Source | Notes |
|---|---|---|
| `number` | height | gapless (§1.1) |
| `hash` | `block_id` = SHA3-256(DS_BLOCK ‖ header) | 32 bytes, so it *fits* the field. But it is **not** keccak256(RLP(header)) — any client that re-derives the hash to verify it (light clients, some proof tooling) will mismatch. Wallets and explorers treat it as opaque **[assumption — verify for the specific light-client tools, if any, we intend to support]**. |
| `parentHash` | `parent` | single parent, pinned by the wire format |
| `timestamp` | derived from `slot` (§1.1) | |
| `stateRoot` | `state_root` | SHA3 SMT root (migration spec §5.5), **not** a keccak MPT root — see §2.3 |
| `transactionsRoot` | `body_root` | SHA3 Merkle root, same caveat |
| `receiptsRoot` | root over EVM receipts | requires a receipts commitment; whether it becomes a consensus `state_root` leaf or an RPC-computed value is A1/DEV-2's state-layout question, not decided here |
| `logsBloom` | computed over the block's logs | needed for `eth_getLogs` efficiency (§7); standard 2048-bit bloom, keccak-based per spec — keeping keccak *inside the bloom* is fine (it is not an authorisation path) |
| `miner` | proposer's fee-recipient address | representation depends on DEV-2 (§5); zero address is the fallback if PQ-only with no 20-byte mapping |
| `mixHash` | `randao_mix` | deliberate, standard-compatible reuse (§1.2) |
| `difficulty` | `0x0` | post-merge convention |
| `nonce` | `0x0000000000000000` | post-merge convention |
| `baseFeePerGas` | **pending the fee-model decision** | see §2.4 — its *presence* is a tooling signal |
| `gasLimit` / `gasUsed` | from the EVM execution layer | gas-vs-V4-fees is owned by the EVM design track, not this doc |
| `extraData` | empty | |
| `uncles` | `[]` always | no uncles exist |
| `transactions` | tx hashes, or full objects with `fullTransactions=true` | tx-object shape depends on DEV-2 (§5) |

The one G4 exception worth considering: a `blochSlot` extension field. It is
cheap and useful for Bloch-aware EVM tools, but it is safer to leave slot
data on the native namespace and keep `eth_*` byte-clean. **Recommendation:
no extension fields in v1**; revisit if a concrete consumer needs it.

### 2.3 The `stateRoot` caveat, and `eth_getProof`

Bloch's state commitment is a SHA3-256 sparse Merkle tree over a **closed
list of leaves** (migration spec §5.5), not Ethereum's keccak Merkle-Patricia
trie. Therefore:

- `stateRoot` is honest but unverifiable by Ethereum proof tooling.
- **`eth_getProof` is unsupported in v1** — return the standard
  "method not found" error rather than a proof in a foreign format that
  standard verifiers would misvalidate. A Bloch-native proof method (SMT
  inclusion proofs) can live on the native namespace later.
- Anything downstream that consumes MPT proofs (trustless bridges, some
  light wallets) is out of scope of "EVM tooling works".

### 2.4 Decimals and `baseFeePerGas`

BLCH has 8 decimals (`SAT_PER_BLOCH`, `tokenomics_v4.rs:24`); Ethereum
tooling assumes the native currency has 18. `eth_getBalance`, `value`
fields, and gas prices are quoted in a base unit, and wallets *display*
using the `decimals` the user configured for the network (MetaMask's custom
network form asks for the currency symbol; it assumes 18 decimals for the
native currency and this is **not configurable** in the standard flow
**[assumption — verify current MetaMask behaviour]**). Two options:

- Quote `eth_*` amounts in satoshis (8 decimals) and accept that wallets
  showing 18-decimal formatting display absurdly small numbers; or
- Define the EVM-side base unit as 10^18 per BLCH and fix the sat↔wei
  conversion at the state boundary (1 sat = 10^10 wei-like units), keeping
  consensus arithmetic in sat.

The second is what every 8-decimal chain that adopted the EVM did (e.g.
BTC-pegged EVM chains) **[assumption — verify precedent details]**, and is
the recommendation; the conversion constant must live next to
`SAT_PER_BLOCH`, imported, never restated.

`baseFeePerGas` presence matters beyond fees: MetaMask and ethers detect
EIP-1559 support by checking whether the latest block carries
`baseFeePerGas`, and select transaction type (0x2 vs legacy) accordingly
**[assumption — verify against current MetaMask/ethers versions]**.
Tokenomics V4 burns fees during emission — economically 1559-shaped — so a
base-fee model is a natural fit, but the fee-model design is owned by the
EVM design track. This document only pins the RPC consequence: **decide
1559-or-legacy before the OpenAPI/interface freeze, because it changes the
block schema, `eth_gasPrice`, `eth_feeHistory`, and every wallet's signing
path.**

---

## 3. Block tags: `latest`, `safe`, `finalized`, `earliest`, `pending`

Bloch adopts Ethereum's tag names with Casper-checkpoint meanings. Since
Bloch's finality gadget *is* Casper FFG, this is a genuine semantic match,
not a pun:

| Tag | Bloch meaning |
|---|---|
| `earliest` | the Genesis-4 genesis block (height 0) |
| `latest` | canonical tip |
| `pending` | mempool-speculative state; v1 MAY alias it to `latest` (many nodes do) — aliasing is the recommendation until there is a concrete consumer of pending state |
| `safe` | the highest canonical block that is an ancestor of (or equal to) the **latest justified checkpoint** |
| `finalized` | the highest canonical block that is an ancestor of (or equal to) the **latest finalized checkpoint** |

One honest divergence to document: on Ethereum, `safe` is defined by the
"safe head" confirmation rule, which can run slightly ahead of the justified
checkpoint. Bloch pins `safe` := justified — marginally more conservative,
identical client behaviour (clients treat `safe` as "unlikely to revert, not
guaranteed") **[the client-behaviour half is an assumption — verify how the
tools we care about actually use `safe`]**.

These tags align one-to-one with the native `gettxstatus` enum
(BLOCH-RPC-V4 §3.1): `included` ↔ between `finalized|safe` and `latest`,
`justified` ↔ ≤ `safe`, `finalized` ↔ ≤ `finalized`. The two namespaces
must be computed from the same checkpoint state — one derivation path.

Expected latencies under healthy participation (for integrator docs, not
consensus guarantees): inclusion ≤ 1 slot (30 s); justification within ~1
epoch (16 min); finalization within ~2 epochs (~32 min). Under a finality
stall, `safe`/`finalized` stop advancing while `latest` continues — which is
precisely the property exchanges and bridges want.

---

## 4. `eth_getTransactionReceipt`

### 4.1 When does a receipt exist?

At **inclusion**. The standard contract is: `null` while the tx is pending
or unknown; a receipt object as soon as the tx is in a canonical block. The
receipt has **no finality field** in the standard schema — Ethereum tooling
determines finality by comparing `receipt.blockNumber` against
`eth_getBlockByNumber("finalized", …).number`. Bloch keeps this contract
exactly.

What tools do with it (all **[assumption — verify]**, marked individually):

- MetaMask marks a transaction "confirmed" when a receipt with
  `status: 0x1` appears — i.e. at inclusion, ~30 s, **before** any
  justification. Users see "confirmed" for economically-unfinal txs. This
  is identical to Ethereum today and is a UI convention we inherit, not a
  bug we introduced.
- `ethers` `tx.wait(k)` waits for `k` blocks on top of inclusion — depth,
  not finality. `viem`'s `waitForTransactionReceipt` similarly. Integrators
  who need irreversibility must poll the `finalized` tag; our integrator
  docs must say so in exactly those words.

### 4.2 Receipt fields

Standard: `transactionHash`, `blockHash` (= `block_id`), `blockNumber`
(= height), `from`/`to`/`contractAddress`, `gasUsed`/`cumulativeGasUsed`,
`effectiveGasPrice`, `logs`, `logsBloom`, `status`. `from` depends on the
DEV-2 decision (§5): with secp256k1 it is the recovered 20-byte address;
PQ-only it is the 20-byte *derived* address of the PQ account (§5.3).

### 4.3 The one extension field this document does authorise

`blochFinality: "included" | "justified" | "finalized"` on the receipt,
mirroring `gettxstatus`. Rationale: it saves every Bloch-aware integrator a
second round-trip and cannot be misread by standard tooling that ignores
unknown fields. Risk (G4): strictly-typed generated clients may reject
unknown fields **[assumption — verify against the SDKs in
`sdk/`]** — if any shipping consumer chokes, drop the field and let
integrators do the two-call dance.

Reorg behaviour: a receipt for a block later reorged away starts returning
`null` again (standard). Reorgs are bounded above the finalized checkpoint;
below it a rollback is a network catastrophe, not an event to handle
(ecosystem plan §5.1) — the RPC layer does not special-case it.

---

## 5. `eth_sendRawTransaction` — both branches of the DEV-2 decision

The fleet brief is explicit: the authorisation model (secp256k1 at L1 /
PQ-only / both) is priced by DEV-2 and decided by the founder; **nobody
picks silently**. As of this writing no decision document exists in-tree.
This section specifies the RPC surface under each branch so the RPC layer
is not the blocker either way. It deliberately does *not* recommend a
branch — that is DEV-2's brief, and the security trade (a
quantum-vulnerable authorisation path on the one chain built to avoid one)
is priced there, not here.

### 5.1 Branch A — secp256k1 accounts accepted at L1

`eth_sendRawTransaction` is **fully standard**: accepts RLP legacy and
EIP-2718 typed transactions (0x1, 0x2), recovers the sender via ecrecover,
validates chainId/nonce/balance/gas, admits to the mempool. MetaMask,
ethers, Foundry, Hardhat work out of the box. RPC-layer consequences:

- Two address spaces exist at L1: 20-byte keccak addresses (EVM accounts)
  and Bloch bech32 PQ addresses (eUTXO). `eth_getBalance`,
  `eth_getTransactionCount`, `eth_getCode` operate on the 20-byte space
  only; how value moves between the spaces (and whether the closed
  `state_root` leaf list gains an EVM-accounts leaf) is the state-layout
  question owned by the EVM design track.
- The node gains a keccak + secp256k1 verification path. Keccak here is
  load-bearing for *authorisation* (address = keccak(pubkey)), not just
  hashing — this is exactly the surface the SHA3-lattice migration removed
  everywhere else. The security note DEV-2 owes the founder must be blunt
  about it (fleet brief); the RPC doc's job is only to note that **every
  method in this section works unmodified** under branch A.
- `eth_accounts` returns `[]` (the node holds no keys); `eth_sign`,
  `eth_signTransaction`, `personal_*` are unsupported — signing happens in
  the wallet. This matches how public RPC endpoints behave everywhere.

### 5.2 Branch B — PQ-only accounts

The hard fact: ML-DSA-65 ‖ Falcon-1024 signatures are **not recoverable** —
the sender cannot be derived from the signature, so the raw-tx envelope must
carry the public key (~1.3 KB Falcon-1024 pk + ~1.95 KB ML-DSA-65 pk) and
the hybrid signature (~4.6 KB, fleet brief). Consequences:

- **Stock tooling cannot produce a valid transaction, period.** MetaMask
  will happily *sign* a secp256k1 tx for chainId anything — the failure is
  at submission: the node rejects with a clear error (recommended message:
  `"secp256k1 transactions are not accepted on this network; see <doc
  URL>"`, as a standard JSON-RPC error, code `-32000` family). It must be a
  *rejection*, not a silent drop — silence is indistinguishable from a
  broken node.
- `eth_sendRawTransaction` **keeps its name and hex-bytes parameter** but
  accepts a Bloch-defined EIP-2718 typed transaction (a reserved type byte
  in the 0x40–0x7f custom range, e.g. `0x50`) wrapping: chainId, nonce, gas
  fields, to/value/data, suite tag (`SUITE_MLDSA65_FALCON1024` /
  `SUITE_MLDSA65_ONLY`), pubkey(s), signature(s). Keeping the method name
  means the *transport* tooling (JSON-RPC clients, proxies, indexer
  ingestion) still works; only the *signer* is Bloch-specific.
- The sender address is **derived**: 20 bytes of SHA3-256(suite ‖ pubkeys)
  — a deterministic mapping so the EVM's 20-byte address model survives
  intact (CALLER, balances, mappings keyed by address all work). Note this
  uses SHA3, not keccak, consistent with the migration; the EVM *internal*
  keccak opcode (SHA3, 0x20) keeps keccak semantics because deployed
  Solidity depends on it — opcode semantics are not an authorisation path.
- Size economics: a ~5–7 KB transaction envelope vs Ethereum's ~110-byte
  transfer. Per-byte gas pricing (intrinsic gas / calldata-style costs) must
  price the envelope or the mempool DoS surface grows ~50×; that is a fee-
  model input, flagged here, owned there.
- Every tool that *signs* needs porting: a Bloch signer for ethers/viem (a
  custom `Signer`/`Account` implementation is a supported extension point in
  both **[assumption — verify the exact extension API versions]**),
  Foundry/Hardhat deploy plugins, and no hardware wallet support at all
  (fleet brief: no HSM signs ML-DSA/Falcon — consistent with the KuCoin
  memory). This is the real cost of branch B and it lands on the tooling
  team, not the node.

### 5.3 Branch C — both

RPC-wise, branch C is the union: standard 0x0/0x1/0x2 envelopes recovered
via ecrecover *and* the 0x50 PQ envelope, two admission paths into one
mempool and one fee market. The dual-authorisation consensus/fee
consequences (and what a quantum adversary steals from the secp256k1 side)
are DEV-2's to price; the RPC layer's only additional obligation is that
`eth_getTransactionByHash` must render both envelope shapes, which means
the PQ envelope needs a defined JSON representation (standard fields plus
`blochSuite`, `blochPubkeys` — extension fields, G4 caveat applies).

### 5.4 Common to all branches

- `eth_getTransactionCount` (the nonce) is required by every wallet before
  signing; the EVM account state must track nonces regardless of branch.
- Mempool admission errors (nonce too low, insufficient funds, underpriced)
  use the conventional error strings where practical — wallets pattern-match
  on them **[assumption — verify which strings MetaMask actually matches]**.
- `eth_sendTransaction` (node-side signing) is unsupported everywhere.

---

## 6. `eth_chainId` — 8400, and what reuse actually costs

Facts on the ground (ecosystem plan §5.3, ops memory):

- The devnet L2 node hardcodes chainId **8400** (`bloch-l2-node/src/node.rs:27`,
  in `~/dev/bloch-protocol/l2`); the L2 settling stack (bridge envelope,
  SP1 public values, deploy configs) uses placeholder **700771**.
- 8400 is *reserved* for the Bloch EVM on chainlist.org, but the entry is
  **not published** (blocked pending a live EVM-RPC — ops memory). So there
  is no public registry entry to migrate; there is a *plan* to repoint.
- The L2 at `l2rpc.posternlabs.com` runs persistently with real state under
  chainId 8400 (ops memory, 2026-07-31). Its transaction history exists.

### 6.1 Is the replay claim true?

Yes, conditionally — and the conditions matter. EIP-155 folds `chain_id`
into the signed payload of legacy transactions, and every typed envelope
(EIP-2930/1559/4844) carries `chain_id` as an explicit signed field. A
signature therefore binds a transaction to a *chainId*, *not* to a chain
instance. If the L1 EVM launches with chainId 8400, then any transaction
ever signed for the L2 is a **validly signed L1 transaction**, and it
executes on L1 the moment three conditions align:

1. the sender's L1 nonce equals the transaction's nonce,
2. the sender's L1 balance covers `value + gas`,
3. the envelope type is accepted on L1 (under branch B/§5.2 it is not —
   PQ-only L1 rejects all secp256k1 envelopes, which *incidentally* kills
   this entire replay class).

The sharp edge is nonce 0: every address that ever transacted on the L2 has
a signed nonce-0 transaction in the L2's history, and a fresh L1 EVM state
starts every account at nonce 0. The moment such an address is funded on
L1, **anyone** who observed the L2 history can rebroadcast that old
transaction on L1 — moving funds or granting approvals the key holder never
intended on this chain. Timing does not save you: decommissioning the L2
before L1 launch prevents *concurrent* double-spends but does nothing about
replay of *historical* signed transactions, which live forever.

### 6.2 The options

- **Reuse 8400, migrate state including nonces.** Import the L2's final
  account state (balances optional per the drain decision, but **nonces
  mandatory**) into the L1 EVM genesis. A replayed tx then fails the nonce
  check by construction — the nonce was already consumed on the chain whose
  state carried over. This preserves the reserved chainlist id and honours
  "the L2 is being replaced". Cost: the L2 snapshot becomes a genesis
  input, one more artifact in the launch ceremony.
- **Reuse 8400, no state migration, accept the risk.** Defensible only if
  the L2's full transaction history is enumerated and shown to contain
  nothing replay-dangerous (no approvals, no transfers from addresses that
  will ever hold L1 funds). "The L2 was basically a devnet" is a plausible
  but **unverified** claim — this document did not audit the L2 history,
  and the option should not be taken without that audit.
- **New chainId.** Zero replay exposure by construction, costs a new
  chainlist registration (the 8400 reservation is unpublished, so nothing
  public breaks) and makes the reserved id dead weight. Also moots the
  700771 placeholder cleanup.

**Recommendation**: reuse 8400 **with the nonce import**, because it is the
only option that both keeps the reserved identity and closes the replay
class by construction rather than by audit. If the EVM design track rejects
state carryover from the L2 for other reasons, take a new chainId — do not
take option two without the history audit. Under branch B (PQ-only) the
replay class is closed anyway (condition 3), and the choice reverts to
purely a naming/registry question — in which case reuse 8400 with no
further ceremony.

`net_version` returns the same value as `eth_chainId` in decimal
(`"8400"`); keep them equal — tools use them interchangeably and a mismatch
is a classic source of wallet confusion **[the confusion claim is
experience-level; the equality recommendation is safe regardless]**.

---

## 7. State-hungry methods: `eth_call`, `eth_estimateGas`, `eth_getLogs`, filters

What each needs, and what that costs. Three storage classes:

**Class 1 — latest state only** (cheap, mandatory):
`eth_call`/`eth_estimateGas`/`eth_getBalance`/`eth_getCode`/
`eth_getStorageAt`/`eth_getTransactionCount` **at `latest`** need only the
current EVM state plus a read-only EVM execution engine in the RPC path
(no consensus involvement). This is table stakes; every node serves it.

**Class 2 — full receipts/logs history** (grows with usage, effectively
permanent):
`eth_getTransactionReceipt`, `eth_getTransactionByHash`, and `eth_getLogs`
need every transaction, receipt, and log ever emitted, plus an index
(per-block `logsBloom` at minimum; a real log index — address/topic →
block — to make wide-range `eth_getLogs` queries tractable). Two hard
points:

- **This history is exempt from post-finality pruning.** The migration spec
  prunes individual attestation signatures after finality (§6.5.1); EVM
  receipts/logs are the opposite — dapps, indexers and users query them
  years later. Budget them as permanent.
- Unbounded `eth_getLogs` ranges are the classic public-RPC DoS. Standard
  mitigation: cap the block range (providers commonly cap at 1k–10k blocks
  **[assumption — exact conventions vary by provider]**) and return the
  standard "query returned more than N results" error. Cap values go in the
  OpenAPI/operator config, not in this doc.

Cost envelope: proportional to EVM usage, not to chain length — an empty
block contributes ~0. At Bloch's launch-era volumes this is megabytes, not
terabytes; the design obligation is only that the storage schema treats
receipts/logs as append-only and never ties their retention to state
pruning.

**Class 3 — historical state (archive)** (unbounded, optional):
`eth_call`/`eth_getBalance`/`eth_getStorageAt` **at a historical block
number** need the state as of that block. Full Ethereum archive nodes pay
terabytes for this; Bloch's will be far smaller but the growth is still
unbounded and per-block. Decision:

- **Two node modes, like the rest of the ecosystem does:** *full* serves
  Class 1 + Class 2 plus a recent-state window (recommendation: at least
  back to the latest finalized checkpoint, so `eth_call` at `safe` and
  `finalized` tags always works — that is the window integrators actually
  use); *archive* keeps per-block state versions forever and is an
  operator opt-in.
- A historical query outside the window returns the conventional
  "missing trie node / state not available" error class, which tooling
  already handles (falls back or surfaces to the user)
  **[assumption — verify the exact error string tools match on]**.

**Filters and subscriptions**: `eth_newFilter`/`eth_newBlockFilter`/
`eth_getFilterChanges` are node-side session state over Class 2 data —
implementation burden, no new storage class. `eth_subscribe`
(`newHeads`, `logs`) requires a WebSocket endpoint; MetaMask does not need
it but dapp frameworks and indexers expect it **[assumption — verify which
of our target tools hard-require ws]**. Recommendation: HTTP-only in v1,
WebSocket before courting dapp deployments.

---

## 8. The minimal wallet surface, in one table

The set below is the working list for "MetaMask + ethers work" (branch A)
or "transport works, Bloch signer required" (branch B). **The exact set
MetaMask requires is an assumption to verify against a current build** —
this is the superset commonly relied on:

| Method | Branch A | Branch B | Notes |
|---|---|---|---|
| `eth_chainId`, `net_version` | ✓ | ✓ | §6 |
| `eth_blockNumber` | ✓ | ✓ | §2.1 |
| `eth_getBlockByNumber` / `ByHash` | ✓ | ✓ | §2.2, tags §3 |
| `eth_getBalance`, `eth_getCode`, `eth_getStorageAt` | ✓ | ✓ | Class 1 |
| `eth_getTransactionCount` | ✓ | ✓ | §5.4 |
| `eth_gasPrice`, `eth_feeHistory`, `eth_maxPriorityFeePerGas` | ✓ | ✓ | shape pending fee model, §2.4 |
| `eth_estimateGas`, `eth_call` | ✓ | ✓ | Class 1 |
| `eth_sendRawTransaction` | standard | Bloch 0x50 envelope | §5 |
| `eth_getTransactionReceipt`, `eth_getTransactionByHash` | ✓ | ✓ | §4 |
| `eth_getLogs` | ✓ | ✓ | Class 2, capped |
| `eth_syncing` | ✓ | ✓ | report slot-lag-derived sync status as the standard object/false |
| `web3_clientVersion` | ✓ | ✓ | identifies the Bloch node build |
| `eth_accounts` | `[]` | `[]` | §5.1 |
| `eth_getProof` | ✗ | ✗ | §2.3 |
| `eth_sign` / `personal_*` / `eth_sendTransaction` | ✗ | ✗ | node holds no keys |

---

## 9. Deployment: where `eth_*` is served, and what the explorer expects

### 9.1 Serving

One node, one dispatcher: `eth_*` methods join the same JSON-RPC dispatch
as the native surface (`src/rpc/mod.rs` pattern), distinguished by prefix.
The two namespaces share checkpoint state (one derivation path, §3) but not
conventions (G1/G2). The public EVM endpoint for chainlist and wallet
configuration should be a dedicated hostname (e.g. `evmrpc.blochl1.com` or
reusing `rpc.blochl1.com`, which serves both namespaces since the
dispatcher is shared) — a chainlist entry requires a stable public RPC URL
and the explorer's own endpoint story (below) already builds the routing.

### 9.2 What the current explorer actually does (measured)

`apps/explorer` speaks **only the native Bloch namespace** — zero `eth_*`
calls anywhere in `apps/explorer/src` or `functions/` (grepped 2026-08-11).
Methods in use: `getdaginfo`, `getnetworkinfo`, `getchainstats`,
`getrecentblocks`, `getblock`, `getblockbyheight`, `gettxsbyblock`,
`gettransaction`, `gettxstatus`, `getbalance`, `getaddressinfo`,
`getsupplydistribution`, `getblocktimepercentiles`, `getpools`,
`gethashrate`, `getdifficultyhistory`, `getmempoolstats` — i.e. the V3
surface, several members of which die or change in V4 (BLOCH-RPC-V4 §1–§3
already owns that migration; nothing EVM-specific blocks it).

Endpoint chain (`apps/explorer/src/lib/rpc.ts`, verbatim as of
2026-08-11): `VITE_RPC_URL` override → `https://rpc.blochl1.com/` →
same-origin `/rpc` Pages Function → `https://g2rpc.posternpool.com/`
(deprecated bridge). Two operational facts the EVM plan inherits:

- **`rpc.blochl1.com` is NXDOMAIN today** (`rpc.ts:14-20` says so
  explicitly: "OPS ACTION REQUIRED before the halt — route it (tunnel
  ingress + DNS + edge cert) to the surviving archival node's RPC"). The
  deprecated pool tunnel is currently the only live endpoint and dies with
  the pool at the halt (which came at height 39,918, not the 80,000 planned
  when this was written). Wiring `rpc.blochl1.com` is already
  a pre-halt ops obligation; when the G4 node ships `eth_*` on the shared
  dispatcher, the same hostname serves the EVM surface for free.
- The same-origin proxy (`apps/explorer/functions/rpc.js`) enforces a
  read-only **allowlist** that is G3-only and already flagged for a V4
  rebuild (BLOCH-RPC-V4 §7). If the explorer (or any same-origin tool) is
  ever to proxy EVM reads, the read-only `eth_*` set (§8 minus
  `eth_sendRawTransaction`) must be added to that allowlist; wallets never
  use this proxy — they need a direct endpoint that accepts
  `eth_sendRawTransaction`.

A Bloch explorer for an EVM-carrying L1 will eventually want EVM views
(contract pages, log decoding). That is product work, out of scope here;
nothing in the current explorer blocks the EVM surface, and nothing in the
EVM surface blocks the explorer's V4 migration.

---

## 10. Explicitly not decided here / owned elsewhere

- The **authorisation branch** (§5): DEV-2 prices, the founder decides.
  This document is deliberately branch-complete and branch-neutral.
- The **fee model** (gas vs V4 fees, 1559-or-legacy): EVM design track;
  §2.4 pins only the RPC-schema consequence and the freeze deadline.
- The **state layout** (EVM accounts vs the closed `state_root` leaf list,
  coexistence with eUTXO and the shielded pool, the fate of
  `crates/bloch-euvm` and its `euvm_*` RPC trio,
  `src/rpc/mod.rs:1508-1512`): EVM design track. Note only that if
  `bloch-euvm` dies, the three feature-gated `euvm_*` methods listed as V4
  survivors in BLOCH-RPC-V4 §3.7 die with it — flag to DEV-3 at the
  OpenAPI freeze.
- The **L2 drain/decommission timeline** (ecosystem plan §5.3 item 1) —
  unchanged in urgency; the §6 chainId decision adds one input to it
  (whether the final L2 state snapshot is a genesis artifact).
