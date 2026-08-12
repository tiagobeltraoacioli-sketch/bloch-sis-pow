# Bloch — Ecosystem Migration Plan (Genesis-4 PoS)

> **PARCIALMENTE SUPERADO — 2026-08-11.** Esta analise foi escrita contra o
> estado do projeto naquele dia e depende de premissas que mudaram DEPOIS:
>
> - **a maquinaria de taint** — dissolvida: o carryover atravessa como um conjunto so, sem lista de exclusao, entao nao ha classe de moeda a marcar.
> - **o supply de 100 bilhoes** — revertido para 21 bilhoes, o nominal da V2.
> - **o EVM como L2** — decisao do fundador (2026-08-11): o EVM roda na **base (L1)**, sem rollup; o `bloch-l2-evm` (chainId 8400) sera SUBSTITUIDO, nao migrado. O §5 inteiro (re-point do anchor, predicado de finalidade, unificacao de chain-id) descreve um caminho que ja nao e o plano — só o drenar-antes-do-halt continua valendo, porque o L2 vivo ainda tem usuarios ate a parada.
> - **Ustav/Kirpich como tooling** — promovidos a objeto de CONSENSO (L1) na mesma decisao; consequencias em desenho na wave de 2026-08-11 (fleet brief).
>
> O texto NAO foi reescrito, de proposito: o raciocinio que produziu cada
> achado tem valor mesmo quando a premissa mudou, e reescrever apagaria a
> trilha. Leia os achados; confira as premissas contra
> `BLOCH-TOKENOMICS-V4.md` e `BLOCH-POS-SHA3-LATTICE-MIGRATION.md`, que sao
> os normativos.


**Status:** Draft for PMO review — Assistant A8 (ecosystem), 2026-08-11
**Parents:** `BLOCH-POS-SHA3-LATTICE-MIGRATION.md` (§5.3 `BlockHeaderV4`, §4.1, §6.6.3, Appendix B) · `BLOCH-TOKENOMICS-V4.md` (§3.2 halt-and-relaunch, §6.3 validator revenue, §6.3.1 delegation, §8.1 u64 headroom) · ADR-036
**Scope:** everything that consumes the chain — explorer, wallets (PWA / desktop / CLI), SDKs + OpenAPI, JSON-RPC surface, L2 + anchoring, pool/stratum/mining stack, snapshot & onboarding runbooks.

This is a **measured** plan: every claim below was verified against the code in
this repo and in `~/dev/bloch-protocol` (wallets, L2), with file:line
references. Where something is absent, its absence was verified too.

---

## 0. Ground rules — what the ecosystem actually migrates to

Two decisions upstream of this document change its shape:

1. **This is a relaunch, not an in-place fork.** §8 of the migration spec is
   superseded: the current chain **halts at height 80,000**, a signed balance
   snapshot becomes the canonical record, and Genesis-4 launches from it about
   six months later (`BLOCH-TOKENOMICS-V4.md` §3.2). For the ecosystem this
   means there is **no DAG→linear seam for any consumer to handle** — the
   Appendix B rows that assumed a live transition ("DAG→linear seam",
   "hybrid-phase deposit UX on the PoW chain") collapse into something simpler
   and colder: every consumer is **repointed at a new chain**, and the old
   chain becomes a frozen archive whose canonical record is the snapshot
   artifact, not the chain itself (§3.2.2).

2. **`BlockHeaderV4` (§5.3) removes the fields half the ecosystem reads.**
   Gone: `bits`, `nonce`, `timestamp` (derived from `slot`), `parents` as a
   real vector (wire keeps a vector, consensus pins `len == 1`). Gone with
   them: `pow_hash` (single `block_id = SHA3-256(DS_BLOCK ‖ header)`, §5.4),
   difficulty, retargets, hashrate, and depth-as-security. New: `slot`,
   `proposer_index`, `randao_reveal/mix`, `justified_root`, `finalized_root`,
   `attestation_root`, `state_root`, `coherence_root`, and a ≈4.6 KB hybrid
   proposer signature in the **envelope**, not the header.

Three ecosystem-wide rules fall out, and every component section below is an
application of them:

- **R1 — Depth is dead; finality is a state, not a number.** Every
  "confirmations" display and every `depth >= K` gate becomes a three-valued
  question: is the containing block *pending*, *justified*, or *finalized*?
- **R2 — Eligibility is a coin property, and the UI must know it first.**
  Under §4.1 + §6.6.3 + tokenomics §6.3.1, a tainted output **cannot be
  shielded, cannot be deposited as stake, and cannot be delegated**. These are
  consensus rules; the transaction just fails. Any surface that lets a user
  shield, stake, or delegate MUST check eligibility *before* building the
  transaction and say why when the answer is no (see §3.4).
- **R3 — Commission disclosure is a protocol dependency, not a feature.**
  §6.3 of the tokenomics deliberately leaves validator commission **uncapped
  by consensus**, on the explicit bet that "wallets and the explorer must
  surface the rate prominently." The explorer and every delegation UI are
  therefore part of the consensus design's safety argument. This plan treats
  prominent commission display as a MUST, with the same weight as a validity
  rule.

---

## 1. JSON-RPC surface (`src/rpc/`) — the root dependency

Everything else in this document consumes this layer. Today: ~45 methods in
one dispatch (`src/rpc/mod.rs`, 1,963 lines), plus `euvm_*` (feature-gated,
`src/rpc/euvm_rpc.rs`) and auth (`src/rpc/auth.rs`).

### 1.1 What breaks when the header changes (V4)

Every block-returning method serializes the V3 header verbatim:

- `getblock` / `getblockbyheight` (`src/rpc/mod.rs:353-360, 390-397`) emit
  `bits` (hex string), `nonce`, `parents[]`, `blue_score`, `timestamp`,
  `merkle_root`.
- `getrecentblocks` (`mod.rs:437`) emits `bits` as a **number** (already
  inconsistent with `getblock`'s hex string — clients special-case it, e.g.
  explorer `BlockDetail.tsx:23`).
- `getnetworkinfo` (`mod.rs:315-328`) exposes `blue_score`,
  `best_announced` blue-score lag fields.

V4 replacement: emit the §5.3 fields (`slot`, `proposer_index`, `parent`,
`state_root`, `body_root`, `justified_root`, `finalized_root`,
`attestation_root`, `coherence_root`), a derived `timestamp` for display, and
a per-block `finality: "pending" | "justified" | "finalized"` so no client
has to reimplement checkpoint arithmetic.

### 1.2 What breaks when PoW and difficulty go away

- `gettxstatus` (`mod.rs:1267-1309`) — hardcodes `"final"` at ≥100
  confirmations (coinbase-maturity depth). Redefine the enum:
  `pending | included | justified | finalized`, keep `confirmations` as an
  informational depth. This single method is what the explorer, the anchoring
  crate, and the wallets all trust for status (they do no arithmetic of their
  own — verified).
- `getchainstats` (`mod.rs:1175-1190`) — `current_difficulty`, `hashrate_hs`,
  `hashrate_human` fields die; the rest survives.
- `getsupplydistribution` (`mod.rs:1192`) — must be rewritten for V4 genesis
  allocations + vesting schedules; note it **already omits the carryover
  balance today** (known defect) — the rewrite is the chance to make supply
  reporting honest: "maximum issued" vs circulating-minus-burned (tokenomics
  §6.3.2).
- `getpools` (`mod.rs:1053`) — built entirely on `tokenomics_v2`
  miner/validator/oracle subsidy splits; replaced by staking-economics
  methods (§1.4).

### 1.3 What dies outright

| Method | Lines | Why |
|---|---|---|
| `getblocktemplate` | `mod.rs:689-810` | mining template incl. `genesis2_expected_bits_for_parents` |
| `submitblock` | `mod.rs:812` | PoW block submission |
| `createauxblock` / `submitauxblock` | `mod.rs:840-945` + aux-candidate ring `mod.rs:1517-1548` | AuxPoW / merged mining |
| `gethashrate` | `mod.rs:1213` | no hashrate |
| `getdifficultyhistory` | `mod.rs:1225` | no retargets |
| `getdaginfo` | `mod.rs:946` | no DAG; replace with `getchaininfo` (tip, finalized/justified checkpoints, epoch, slot) |

`getblocktimepercentiles` survives but its meaning inverts: block time is now
a *protocol constant* (30 s slots); the interesting metric becomes **missed
slots**, which should be what the replacement reports.

### 1.4 What must be added

New methods (names indicative; DEV-3 owns the surface per migration spec §9.2):

- `getepochinfo` — epoch, slot, committee, participation of current/previous
  epoch, current justified/finalized checkpoints.
- `getvalidators` / `getvalidator(index)` — registry view: pubkey hash, stake
  (own + delegated), **commission_bps**, state (queued/active/exiting/exited/
  slashed), activation/exit epochs, attestation-credit performance. The
  registry and metrics already exist in-tree:
  `crates/bloch-pos-committee/src/delegation.rs` (`Registry::validators`,
  `top_share_bps`, `nakamoto_coefficient`), `rewards.rs`
  (`StakeAccount.commission_bps`, `distribute`).
- `getdelegations(address)` — a delegator's positions, warm-up/cool-down
  queue state (`StakeState`), pending withdrawals with epochs remaining.
- `getstakinginfo` — total staked, staked %, nominal yield vs inflation
  (`rewards.rs::nominal_yield_bps`), G2/G3 gate metrics (top share, Nakamoto
  coefficient) — these should be public precisely because the gates are
  public commitments.
- `gettaintstatus(outpoint | address)` — is this output eligible to shield /
  deposit / delegate. **This is the enabling API for rule R2**; without it no
  wallet can warn before a doomed transaction. The taint-set root is in
  `state_root` (§5.5), so the node can also serve proofs.
- `getslashings`, `getcheckpoints` — evidence feed and finality history.
- Deposits/exits/delegations are **transactions**, so they flow through the
  existing `sendrawtransaction`; `decoderawtransaction` (`mod.rs:655`) must
  learn the new tx types.

**Naming collision, decide early:** `getattestation` (`mod.rs:1493`) already
exists and means **TEE attestation** (SEV-SNP report, `src/attestation/`).
PoS attestation methods must not reuse the word bare — use
`getepochattestations` or rename the TEE method in the V4 API bump.

**Amount headroom (echo of tokenomics §8.1) — RESOLVED, see
`docs/specs/BLOCH-SATOSHI-ENCODING.md`:** V4 maximum issued is 100 B BLCH =
**10^19 sats**, which exceeds both `i64::MAX` (9.22×10^18, by 8.42%) and
JavaScript's 2^53 (by ~1110×). Genesis-3's API emits sats as JSON numbers and
the Go SDK typed them `int64`. The V4 API emits **every** satoshi-denominated
field as a decimal string — not only aggregates: an "aggregates only" rule is a
latent bug in every client that meets its first large single balance, and the
largest carryover address is already 187× past 2^53 on its own. Decided once in
the OpenAPI spec, not per client; the Go SDK's `Satoshis` became a `uint64`
with a string codec (`sdk/go/satoshis.go`) as a consequence of the wire form,
not as the fix.

**Effort:** ~3–4 dev-weeks inside DEV-3's node work (the RPC layer is thin;
the cost is the new state queries + the OpenAPI contract in §4).

---

## 2. Explorer (`apps/explorer`, blochl1.com)

React 18 + Vite, ~4,500 lines, 11 routes, no external chart/state libs; one
Cloudflare Pages Function (`functions/rpc.js`) that is **currently bypassed** —
the client POSTs directly to `https://g2rpc.posternpool.com/`
(`src/lib/rpc.ts:16-18`).

### 2.1 Breaks on V4 header

The PoW header surface is smaller than expected — this is good news:

- `bits` in 4 files: `src/lib/format.ts:83-91` (`difficultyFromBits`),
  `src/pages/Blocks.tsx:53`, `src/pages/BlockDetail.tsx:23,51-52` (+ `nonce`,
  its only use), `src/pages/Charts.tsx:31`, `src/pages/Dashboard.tsx:76`.
  Note `difficultyFromBits` returns 0 for missing `bits` — a V4 block would
  silently render "difficulty 0" rather than fail. Remove, don't patch.
- `parents[]`: DAG edge drawing (`src/components/dag.tsx:91`,
  `dagInteractive.tsx:249,271`) and `BlockDetail.tsx:43`, which **hardcodes
  `parents[0]` = selected parent**. Under V4 the wire keeps a length-1 vector,
  so this happens to keep working — replace it anyway with the explicit
  `parent` field so it fails loudly if the assumption ever breaks.
- `blue_score` everywhere in the DAG views, `chain.ts:81,101`,
  `Dashboard.tsx:102`.

### 2.2 Breaks / dies with PoW removal

- **`/mining` dies whole** (`src/pages/Mining.tsx`, 280 lines): hashrate
  calculator, energy cost, ccminer/minerd pool wizard against
  `stratum+tcp://stratum.posternpool.com:3336`.
- **`/dag` and `/livedag` retire** (`dag.tsx`, `dagInteractive.tsx` — 378
  lines — `Dag.tsx`, `DagLive.tsx`): Genesis-4 is a linear chain from its own
  genesis; there is no DAG to draw and, because of the fresh-genesis decision,
  no seam either. If a DAG view survives at all, it lives in the **archived
  G3 explorer** (§8.2), not here.
- **`/leaderboard` and `/wallet` miner attribution** (`src/lib/mining.ts:
  134-199`): derives "miner" from coinbase outputs. Becomes **proposer /
  validator attribution** from `proposer_index` — cheaper and exact.
- Difficulty history chart, retarget-delta stat (`Charts.tsx:36-40,76-78,
  118-126`); subsidy-split chart whose caption says "Pure PoW — 100% of the
  block subsidy goes to the miner" (`Charts.tsx:105`).
- Emission math (`src/lib/halving.ts`, `components/halving.tsx` — V2/V3
  curves, fork at 40,000) → V4 disinflation curve.
- Stall banners (`STALL_THRESHOLD_SECS = 20 min`, `chain.ts:114`) — under PoS
  a skipped slot is *normal*; replace with missed-slot rate and a
  finality-stall banner (no new finalized checkpoint for > N epochs), which
  is the actually alarming condition.

### 2.3 What must be added — and two items are MUSTs, not features

1. **Finality display, not just depth (MUST).** Block list and block/tx pages
   show the three-state finality badge (`pending / justified / finalized`)
   from the fields in §1.1/§1.2 — plus the checkpoint pair (justified root,
   finalized root) on the dashboard with epoch numbers and participation %.
   The current UI states "Finality is proof-of-work depth"
   (`TxDetail.tsx:111`); every one of those honesty strings gets rewritten.
2. **Validator directory with commission front-and-center (MUST, R3).**
   §6.3 left commission uncapped *because* the explorer would make it public.
   Requirement: the validator list is sortable by commission, the rate
   appears on the list row (not behind a click), rate *changes* are shown as
   an event feed, and the delegation deep-link passes through a screen that
   restates the rate. Add the concentration metrics next to it
   (`top_share_bps`, Nakamoto coefficient at the ⅓ threshold) — the G2/G3
   gates are public commitments and the explorer is where they live.
3. Epoch/slot chrome (slot number, proposer, missed slots), staking dashboard
   (staked %, yield vs inflation — both numbers, per tokenomics §6.3),
   slashing-event feed, delegation queue view (warm-up/cool-down),
   address pages showing eligibility class of balances (R2, read-only here).

### 2.4 Hygiene forced by the migration

- `src/lib/rpc.ts` must stop hardcoding **`g2rpc.posternpool.com`** — that is
  a *pool* domain and the pool is being decommissioned (§6). Repoint to a
  neutral RPC host and re-enable the `functions/rpc.js` allowlist (today dead
  code, so its method list silently drifts).
- `wrangler.toml`/`package.json` still say `explorer.posternlabs.com`;
  the live domain is blochl1.com. Fix while touching deploys.

**Effort:** ~4–6 dev-weeks. Roughly half the app changes: 3 pages die, 2
retire to the archive, 4 need new data, and the validator/staking surface is
new build. The RPC additions in §1.4 are a hard dependency.

---

## 3. Wallets

Three real wallets exist; none has any staking, shielding, or taint concept
today (verified by grep — `taint` appears only in `bloch-pos-committee`).

### 3.1 PWA (`~/dev/bloch-protocol/apps/mobile-wallet-pwa`)

Smallest surface, least breakage: calls only `getblockcount`, `getbalance`,
and a send flow (`src/rpc.ts`). Reads are honest-by-design (shows "node
unreachable" rather than fabricating). V4 work is almost entirely *additive*:
repoint RPC, keep send, then decide scope — if the PWA gets
delegation, it needs the full §3.4 treatment; if not, it needs only the
eligibility warning on send-to-shield/deposit destinations it can't build
anyway. **Effort:** 1–2 dev-weeks (repoint + finality states), +2 weeks if
delegation UX is in scope.

### 3.2 Desktop (Tauri, `~/dev/bloch-protocol/desktop`)

Calls ~25 RPC methods including `gethashrate`, `getdifficultyhistory`,
`getdaginfo`, `getpools`, `getchainstats`, `getattestation` — i.e. it
consumes exactly the surfaces §1 deletes or reshapes. Signs with the hybrid
suite via the node library (`src/lib.rs` re-exports `bloch_crypto::wallet`);
key handling in `src-tauri/src/keys.rs`. Work: remove/replace the PoW panels,
adopt V4 block fields, finality states, and build the staking/delegation UX
(§3.4). **Effort:** 3–4 dev-weeks.

### 3.3 CLI wallet (`crates/bloch-crypto/src/wallet/cli.rs`)

Commands today: keygen / address / pubkey / balance / send / sign /
disclosure / audit. Needs: `deposit`, `exit`, `delegate`, `undelegate`,
`withdrawals`, and an `eligibility <utxo|address>` query; plus V4 tx-type
encoding (DepositTx carries a 3,745 B suite-tagged pubkey + ≈4,589 B PoP —
§7.1 of the migration spec). **Effort:** 1–2 dev-weeks on top of DEV-3's tx
types.

### 3.4 The taint UX — the requirement that is easy to forget (R2)

Under §4.1 and §6.6.3 (and delegation rule 4 of tokenomics §6.3.1), a tainted
coin is **fully spendable but cannot be shielded, staked, or delegated**. The
consensus rule simply invalidates the transaction; nothing explains *why* to
the user. Therefore, in every wallet:

1. **Balance is partitioned in the UI**: *spendable* vs *stakeable/shieldable*
   (eligible). One number becomes two, everywhere balance is shown near a
   staking or shielding action.
2. **Pre-flight check, not post-mortem error**: shield / deposit / delegate
   flows call `gettaintstatus` (§1.4) on candidate inputs **before** building
   the transaction. If ineligible: a plain-language screen — "these coins are
   marked under the Genesis-4 eligibility rules; they can be sent and spent
   normally, but cannot be shielded or staked" — with a link to the published
   taint-list rationale. Never a raw node error.
3. **Coin selection must not contaminate.** Taint propagates over the UTXO
   graph: combining a tainted input with clean inputs makes the *change*
   tainted. Wallet coin selection for ordinary sends must (a) never mix
   classes when avoidable, and (b) warn when a send would convert clean
   change into tainted change. This is a correctness rule for the coin
   selector (`sdk/typescript/src/coinselect.ts` has the same obligation).
4. **Delegation risk disclosure**: delegators are slashed pro-rata
   (tokenomics §6.3.1 rule 3) and the commission is uncapped (R3) — the
   delegate flow shows commission, warm-up delay, cool-down, the ~22.8-day
   withdrawal delay, and slashing exposure on one confirmation screen.

Dependency: all of this stands on `gettaintstatus` existing (§1.4). If that
RPC slips, the wallets ship blind and R2 fails exactly the way the spec warns.

---

## 4. SDKs and OpenAPI (`docs/openapi.yaml`, `sdk/`)

The contract layer is well-factored for this migration: **`docs/openapi.yaml`
(1,144 lines) is the single source of truth**, and `sdk/codegen/generate.py`
deterministically emits the Python (`sdk/python/blochclient`) and Go
(`sdk/go`) clients from it, including the `x-json-rpc-methods` registry. The
TypeScript SDK (`sdk/typescript`) is hand-written.

Plan:

1. **New spec major** (`openapi.yaml` → V4): delete `BlockTemplate`,
   `DifficultyHistory`, hashrate/difficulty fields of `ChainStats`, `DagInfo`;
   reshape `Block`/`BlockSummary` to §5.3 fields + `finality`; add
   `ValidatorInfo`, `Delegation`, `EpochInfo`, `Checkpoint`, `TaintStatus`,
   `StakingInfo`, `SlashingEvent` schemas and the §1.4 methods. The spec's own
   prose ("difficulty gate", "SIS-aware pool", `getblocktemplate` docs at
   `openapi.yaml:866-874`) is rewritten.
2. **Regenerate** Python + Go — the codegen makes this cheap; the real work
   is the spec.
3. **Fix amount types while the major is open** — done: `sdk/go/models.go` no
   longer aliases `Satoshis` to `int64` (which **overflowed at V4's 10^19-sat
   max issued**); it is a `uint64` with a decimal-string JSON codec in
   `sdk/go/satoshis.go`. Python is arbitrary-precision but the JSON wire isn't
   (2^53 in every JS consumer, including the explorer), so *every*
   satoshi-denominated field is a string per §1.4 — not just aggregates.
4. **TypeScript by hand**: `types.ts` (fields at 38, 56, 90, 118, 121, 332
   reference `blue_score`/`bits`), `txbuilder.ts` (the
   `from_stratum_bytes` wire-format name survives — it's just the Bitcoin-
   style tx encoding — but the comment should stop saying "stratum"),
   `coinselect.ts` gains the taint rules from §3.4.3, and new builders for
   `DepositTx`/`ExitTx`/`DelegateTx`.
5. **Versioning**: the pre-V4 SDK majors are frozen and documented as clients
   of the halted G3 archive; V4 SDKs are new majors. No dual-chain support in
   one client — there is no seam (§0.1), so there is nothing to straddle.

**Effort:** 2–3 dev-weeks (spec-writing dominates; codegen amortizes Python
and Go to near zero).

---

## 5. L2 (`~/dev/bloch-protocol/l2`, chainId 8400) and `anchoring/`

> **SUPERSEDED 2026-08-11 (founder decision — EVM at L1, no rollup).** This
> section planned the survival of `bloch-l2-evm` across the relaunch by
> re-pointing its anchor to finalized checkpoints. That is no longer the plan:
> the EVM moves to the base layer and the L2 service is **replaced**, not
> extended. What survives from this section: the finding that nothing in the
> L2 stack verifies L1 consensus (still true, and now an argument for
> retiring it), and the operational duty to **drain/settle the live L2 before
> the height-80,000 halt** — the deposits already made are real and must exit.
> The anchor re-point, finality predicate and chain-id unification work items
> are dead. See the 2026-08-11 fleet brief.

The survey's central finding is good news: **nothing in the L2 stack verifies
L1 PoW** — no bits, no target, no pow_hash, no chainwork, not even in the SP1
guest (`bloch-l2-stf-program/src/main.rs` passes `l1_origin_*` through
unverified; `bloch-l2-prover/src/public_values.rs:47-50` says so explicitly).
The entire L1-finality surface is a **depth scalar** and two duplicated
K(amount) tables:

- depth computed at `bloch-l2-anchor/src/manager.rs:478` (`tip - height`) and
  `bloch-l2-bridge/src/watcher.rs:557` (`tip - height + 1` — a documented
  off-by-one, `BLOCH-L2-BRIDGE-SECURITY.md:537-541`);
- policy tables `K = 24/96/288 (+operator review)` at
  `bloch-l2-anchor/src/gating.rs:44-49,127-138` and duplicated at
  `bloch-l2-bridge/src/status.rs:117-126`;
- consumers: `bloch-l2-bridge/src/release.rs:419-451` (withdrawals),
  `watcher.rs:557-567` (deposits);
- the reference crate `BlochPOS/anchoring` has its own
  `FINAL_DEPTH = 100` + `wait_for_confirmations`
  (`anchoring/src/anchor.rs:64-88`, `sdk.rs:69,134-151`).

### 5.1 The change: replace the depth scalar with a finality predicate

`is_final(block) := block.height <= finalized_checkpoint.height` (equivalently:
the containing block is an ancestor of `finalized_root`). Consequences:

- The **amount-tiered K table dies** — finality is absolute, so `K(amount)`
  collapses to one predicate. Keep the top-tier operator-review hold if
  wanted as policy, but it is policy, not depth.
- Both codebases converge on **one** predicate in one crate, absorbing the
  off-by-one and the duplicated tables (already flagged as cleanup in the
  bridge security doc).
- Reorg machinery (`manager.rs:306-336`, the `Orphaned`/`CreditableReorged`
  paths) is *bounded* by finality: a reorg of a finalized block is a network
  catastrophe, not an event to handle gracefully — alarm and halt, don't
  roll back.
- L1 source models are almost insulated already: `source.rs:88-105` and
  `watcher.rs:72-81` read only `height`/`hash`/`parent_hash`/`txs`. Diff:
  `parent_hash` comes from V4 `parent` instead of `parents[0]`, plus
  consuming the new `finality`/checkpoint fields from `gettxstatus` /
  `getchaininfo`. RPC calls used (`getblockcount`, `getblockhash`,
  `getblockbyheight`) all survive §1.

### 5.2 Coinbase-carrier: nothing to migrate, one check to re-derive

The bridge does **not** use coinbase as a data carrier — the Wave-4 fix
rejects coinbase-shaped envelope carriers outright
(`bloch-l2-anchor/src/envelope.rs:380-394`, regression test at `:1040`).
Deposits ride zero-value `L2D0` outputs; anchors ride normal signed spends.
Under V4 the *shape test* (`prev_txid == 0 && prev_index == u32::MAX`) must be
re-derived from whatever the V4 issuance/reward transaction looks like — if
V4 pays rewards via a state operation rather than a coinbase-shaped tx, the
guard becomes inert (fine); if a coinbase-shaped tx survives, the guard must
still match it. One test to port, not a mechanism.

### 5.3 Two decisions the migration forces

1. **The dead-period problem.** Between the halt at 80,000 and the Genesis-4
   launch there is **no L1 at all** for ~6 months. Any L2 state anchored to
   the old chain must be settled and withdrawals drained **before** the halt;
   the L2 either pauses or runs unanchored (sequencer-trust only) during the
   gap. This needs an explicit operator decision and a published timeline —
   it cannot be discovered by users at height 79,999.
2. **Chain-id unification.** The devnet node is 8400
   (`bloch-l2-node/src/node.rs:27`) but the settling stack (bridge envelope
   wire format, SP1 public values, deploy configs) uses placeholder
   **700771** (`bloch-l2-bridge/deploy/testnet.json:3`,
   `envelope.rs:176`, `public_values.rs:31`). `l2_chain_id` is a wire field
   in the L2D0 envelope, so unifying is a breaking format change — settle it
   in the same window as the V4 relaunch, not after.

**Effort:** 2–3 dev-weeks of code (the predicate swap is small; unifying the
duplicated gating into one crate is most of it) + the §5.3 decisions and the
drain/relaunch ops runbook.

---

## 6. Pool, stratum, AuxPoW, merged mining — the part that dies

Complete inventory of what is decommissioned, with sizes (this is the "what
simply dies" list; none of it gets a V4 port):

| Component | Path | What it is | ~LOC |
|---|---|---|---|
| Pool server | `pool/` (stratum.rs, job.rs, shares.rs, payout.rs, dashboard.rs, keyshard…) | standalone stratum pool + payout + dashboard | ~5,000 |
| Pool proxy | `pool-proxy/` (router, upstream, downstream, codec, extranonce, **pplns.rs**, **mergedmining.rs** 592, **btc_block.rs** 355) | stratum router/vardiff/PPLNS + merged-mining BTC glue | ~9,100 |
| In-node stratum V1 | `src/stratum/` (jobs, session, submit, protocol) | solo stratum server (`:3333`, `--stratum-mode solo`) | ~3,700 |
| In-node stratum V2 | `src/stratum_v2/` (session, channels, templates, noise handshake) | SV2 listener | ~4,500 |
| PoW validation | `src/pow/` (mod.rs 694 incl. `genesis2_expected_bits*`, retarget; sha256d.rs 226 incl. `SHA256D_LE_FORK_HEIGHT`) | difficulty + hash validation | ~920 |
| Miner loop | `src/mining/` + `--mine`, `--miner-address`, `--stratum*` CLI flags (`src/main.rs:157,189-190,2056-2204`) | built-in miner + flags | ~110 + flags |
| AuxPoW | `crates/bloch-crypto/src/core/auxpow.rs` (532) + `AUXPOW_ACTIVATION_HEIGHT` wiring (`core/mod.rs:22,1460,1756`) | merged-mining verifier + consensus gate | ~600 |
| Mining RPCs | `getblocktemplate`, `submitblock`, `createauxblock`, `submitauxblock` + aux-candidate ring | §1.3 | ~450 |
| Pool site | `apps/posternpool-site` | posternpool.com static site + functions | small |
| Deploy | `pool.fly.toml`, `pool.Dockerfile`, fleet units (`bloch-pool`, `bloch-asic`, merged pool `:3336`, solo `:3335/:3333`) | pool/ASIC infra | ops |
| Hardware | Antminer S19j Pro (100 TH/s) + miner-box/auxpow-box roles | ASIC fleet | disposition decision (Appendix B) |

**Sequencing is the only subtlety.** Mining is what *produces* the chain until
the halt, and third-party PoW issuance until 80,000 is part of the non-founder
allocation story (tokenomics §3.1). So:

1. **Nothing above is turned off before height 80,000.** The halt release
   (tokenomics §3.2.1 — blocks above 80,000 invalid) is the **last PoW
   release**, and the pool/ASICs run right up to it.
2. **At the halt:** snapshot artifact produced and signed; pool, proxies,
   stratum endpoints, and ASIC fleet decommissioned; `stratum.posternpool.com`
   and the `:3333/:3335/:3336` services retired; posternpool-site gets a
   tombstone page pointing at the snapshot and the G4 timeline.
3. **Before the pool domains die:** the explorer's hardcoded
   `g2rpc.posternpool.com` RPC dependency (§2.4) moves to a neutral host —
   otherwise decommissioning the pool takes the explorer down with it.
4. **The G4 node ships with zero PoW code.** Fresh genesis means the new
   binary never validates a historical PoW block; SHA-256d, `src/pow/`,
   stratum and AuxPoW are simply not in the tree. Historical verification is
   the job of the archived G3 software (§8.2), and the canonical record is
   the signed snapshot anyway (§3.2.2 of the tokenomics spec).

**Effort:** ~1 dev-week of deletion in the V4 tree (it is removal, not
migration) + ~1 ops-week of fleet/DNS decommissioning after the halt +
founder decision on ASIC disposition.

---

## 7. Snapshot and node-onboarding runbook

**Today** (`docs/SNAPSHOT-BOOTSTRAP.md`, 126 lines): onboarding = download a
~datadir snapshot of an archival node (published per-release, e.g.
`g3-datadir-snapshot-h27614-20260808`), verify sha256, run with
`--carryover-snapshot ./carryover.tsv`, and hope the backfill doesn't stall
(the doc honestly documents the large-gap freeze). This entire pattern — and
the operational folklore around it (phantom-peer isolation, deleting
`p2p_identity.bin`) — is an artifact of syncing a PoW DAG with weak liveness.

**Genesis-4 replaces it with two documents:**

1. **Genesis + carryover artifact runbook** — already started at
   `tools/genesis4-carryover/` (`build_carryover.py`: halt → filter/cap →
   publish artifact + digest; the digest goes **into the genesis block**).
   This is the trust root of the new chain (tokenomics §3.2.2: after the
   halt, the chain's own history stops being evidence — the signed artifact
   is canonical). The taint/founder list ships with the same announcement so
   it can be argued with before the height passes.
2. **V4 node onboarding** — two sync modes:
   - *Full sync from genesis*: a linear chain with one designated proposer
     per slot; no DAG backfill pathology, no carryover flag (the allocation
     is in genesis).
   - *Checkpoint sync*: start from a **weak-subjectivity checkpoint**
     published by the Foundation under the m-of-n arrangement (ADR-036,
     `BLOCH-ENTITY-STRUCTURE.md` §5.3). The checkpoint must be younger than
     `WITHDRAWAL_DELAY_EPOCHS` (≈22.8 days) — that constant *is* the maximum
     tolerable checkpoint age, and the runbook must say so and show the
     digest-verification step, exactly like today's sha256 ritual.

**Related tool:** `tools/indexer` (reference reorg-safe indexer) keeps its
rollback logic but gains a **finality floor**: heights at or below the
finalized checkpoint are immutable, rollback attempts below it are treated as
node/network failure, and history at finalized heights can be served without
reorg caveats (the explorer's "history doesn't roll back on reorg" caveat at
`AddressView.tsx:88` becomes true-by-construction below the floor).

**Effort:** 1–2 dev-weeks (runbooks + checkpoint publication/verification
tooling; `genesis4-carryover` already exists and is tested).

---

## 8. Cross-cutting

### 8.1 Sequencing summary

| When | Ecosystem actions |
|---|---|
| **Before h 80,000** (~2 weeks) | Halt release on the fleet (last PoW release); taint/founder list published; explorer repointed off `g2rpc.posternpool.com`; L2 drained/settled + pause announced; snapshot tooling rehearsed |
| **At the halt** | Snapshot artifact signed + digest published wide; pool/stratum/ASIC decommission; pool site tombstoned; G3 explorer flipped to archive mode (static or frozen-RPC) |
| **Gap (~6 months)** | V4 OpenAPI spec frozen → SDKs regenerated; RPC surface built (DEV-3); explorer V4 build; wallet staking/taint UX built against devnet/testnet; L2 finality predicate + chain-id decision; onboarding runbooks written |
| **G4 launch** | Everything repoints to the new chain; Foundation begins checkpoint publication; new SDK majors released; old majors documented as archive clients |

### 8.2 The archive is a component too

The halted chain still has users' history in it. Minimum viable archive: one
frozen archival node (read-only RPC) + the G3 explorer in archive mode with a
banner ("chain halted at 80,000; canonical record is the signed snapshot
<digest>; balances carried into Genesis-4"). Cheap, and it is what makes the
"your balance was preserved" claim auditable by anyone.

### 8.3 Risk register (ecosystem-specific)

| Risk | Where | Mitigation |
|---|---|---|
| `gettaintstatus` slips → wallets can't pre-flight → users hit unexplained consensus rejections | §1.4/§3.4 | Treat the RPC as part of DEV-3's consensus deliverable, not a follow-up; A8 blocks wallet sign-off without it |
| Commission disclosure under-built → §6.3's no-cap bet fails silently | §2.3 | MUST-level acceptance criteria on explorer + wallet delegation screens |
| Amount overflow (10^19 sats vs int64 / 2^53) ships into V4 clients | §1.4/§4 | CLOSED — all satoshi fields are decimal strings, decided once in OpenAPI (`BLOCH-SATOSHI-ENCODING.md`); Go `Satoshis` is `uint64` + string codec; explorer/TS BigInt |
| Explorer dies with the pool (shared `g2rpc.posternpool.com`) | §2.4/§6 | Repoint before decommission; it is one constant |
| L2 users stranded at the halt | §5.3 | Published drain deadline well before h 80,000 |
| `getattestation` name collision produces two meanings of "attestation" in one API | §1.4 | Rename in the V4 major, document both |

### 8.4 Effort summary

| Component | Estimate (dev-weeks) |
|---|---|
| JSON-RPC surface (within DEV-3) | 3–4 |
| Explorer | 4–6 |
| Wallets (desktop 3–4, PWA 1–2 [+2 if delegation], CLI 1–2) | 5–8 |
| SDKs + OpenAPI | 2–3 |
| L2 + anchoring | 2–3 (+ops decisions) |
| Pool/mining decommission | 1 (+1 ops) |
| Runbooks + archive | 1–2 |
| **Total** | **≈ 18–27 dev-weeks**, parallelizable across 3–4 tracks after the OpenAPI freeze |

The single scheduling lever: **freeze the V4 OpenAPI contract early in the
gap**. Explorer, three wallets, two generated SDKs and the L2 all fan out
from that one file; every week it is unfrozen is a week seven consumers wait.

---

*A8 — ecosystem. Sources: code as of 2026-08-11 in `~/dev/BlochPOS` and
`~/dev/bloch-protocol`; measured surveys of `apps/explorer`, `src/rpc/`,
`sdk/`, `pool/`, `pool-proxy/`, `src/stratum*`, `src/pow/`,
`crates/bloch-pos-committee/`, `l2/bloch-l2-{anchor,bridge,node,prover}`,
`anchoring/`, `docs/SNAPSHOT-BOOTSTRAP.md`, `tools/genesis4-carryover/`.*
