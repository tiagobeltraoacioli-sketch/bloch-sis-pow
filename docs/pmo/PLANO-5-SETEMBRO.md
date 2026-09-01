# Plan — Genesis-4 exchange integration, ordered by dependency

Written 2026-08-31. Hard date: **5 September 2026.**

## The finding that reorders everything

The 5 September date is not arbitrary and it is not ours to slip. It is the day
the **weak-subjectivity window closes: 2026-09-05 07:07 UTC**, epoch 2016
(`WS_PERIOD_EPOCHS = 2016`, ≈22.4 days).

- An observer node first synced **before** that instant is trustless forever. It
  keeps its own anchor in `ws_latest.bin` and needs nothing but a peer list.
- One stood up **after** it **refuses to sync** without `--ws-checkpoint` +
  `--ws-signer-set`. The epoch-1536 mainnet checkpoint exists
  (`checkpoints/wscheckpoint-1536.{bin,json}`) but is **UNSIGNED** — its README
  reads `signer_set_id 1 (Phase A — keys DO NOT EXIST YET)`. The publication
  pipeline is fully built (`tools/ws-publisher/`, ~69 KB) and blocked on the same
  thing: *"first production ceremony pending the Phase A signer arrangement."*

**Therefore the single highest-value action available is to get the exchange's
node syncing before 07:07 UTC on 5 September.** Doing so deletes an entire
dependency — a key ceremony that only the founder can authorise and that cannot
be compressed. Missing it does not delay the integration by days; it replaces a
one-day task with a ceremony of unknown length.

Everything below is ordered around that.

---

## Phase 0 — today, 31 August (no dependencies, no code)

**0.1 — Send the exchange the parameter-change disclosure.** Email, today, no
merge required. Content: the two epoch-800 changes with exact UTC timestamps
(payload cap 262,144 → 524,288 **and** the TransferV2 witness-dedup wire tag
`0x06` — they found one of two and may not know about the other); the epoch-1400
roster change of 2026-08-29 10:51:19 UTC; and the statement that **no armed
future flag day exists anywhere in the tree today**. Their complaint was not "you
lack an RPC method," it was "you changed consensus and did not tell us." This
answers that, today.

**0.2 — Apply the registry rulings** (`docs/WIRE-NAMESPACE-REGISTRY.md`). Four
collisions block merges below:
- **C-3, `0x17`:** `TAG_COHERENCE_ANCHORS` keeps `0x17`; `TAG_SHIELDED_POOL`
  moves to `0x18`. Consensus-fatal if both land — state-root tags re-key every
  leaf of the component they name.
- **C-4, tx tag `0x07`:** `0x07 = DepositV2`, `0x08 = Withdraw` stands.
  `agent-a9c4ba491715890b9` and `agent-a1d31358b1c038bdf` renumber before merging.
- **C-1 / C-2:** see 1.1 — decided by merge order, not by a patch.
- **Gate rename:** `FUNDED_STAKING_ACTIVATION_EPOCH` is canonical;
  `DEPOSIT_FUNDING_ACTIVATION_EPOCH` is retired.

**0.3 — Founder decision requested, one question:** authorise bringing ≥2 fleet
nodes up on `--transport libp2p` with a routable listen port. Everything in
Phase 1 waits on this, and the PMO does not touch production nodes.

---

## Phase 1 — the deadline path (1–3 September)

**1.1 — Resolve the state-sync merge order first.** Two worktrees implement
overlapping state sync with *conflicting* frame bytes:
`agent-ad3f0cc77273711fd` @ `40e22169` (`GET_STATE = 0x07`, `STATE = 0x08`,
`SYNC_TAG_*_STATE = 0x03`) and `agent-a58dfe6cc066ef5b3` @ `7c311b04`
(`0x05`/`0x06`, `SYNC_TAG 0x02`) — which also collide with time-sync's `0x05`/
`0x06`/`0x02`. **`40e22169` is the canonical line**: it is the superset (57 files,
+13,956/−2,601), it is on two named branches, and `agent-testnet-deliver` already
follows it. Merge it first; rebase `a58dfe6`'s checkpoint work onto it afterwards.
Doing it in the other order silently merges two different meanings onto one frame
byte, with **no compiler diagnostic of any kind**. *Blocks: 1.2, 2.1.*

**1.2 — Merge `40e22169`** — libp2p DNS-failure downgrade (a real routability
fix), `state_sync.rs`, `time_check.rs`, `--json`, validator runbook,
`deploy/testnet/`, and the `spendkey` / `genesis --alloc` / `submit-tx --raw` CLI
seam. Cherry-pick the docs from `agent-a17bdf87e3c4e85d2` @ `eca224a0`
(`OBSERVER-NODE.md`, the exchange integration doc, the Fly retirement banner) —
**cherry-pick only; that worktree is rooted at `0e609f19` and merging its tree
reverts `engine.rs`/`slashing.rs`.** *Depends: 1.1.*

**1.3 — Stand up the bootnodes** (founder-authorised, fleet operations). ≥2 nodes
on `--transport libp2p`, routable listen port, firewall opened. Read the printed
peer ids (`engine.rs:2843`), build the multiaddrs, fill the two
`TODO(Postern Labs)` rows in `OBSERVER-NODE.md` §5 and §7.
**Watch:** `--p2p-listen` defaults to `/ip4/0.0.0.0/tcp/16400`, which collides
with the fleet's `16400+N` RPC convention. Change the port before publishing, or
the first thing the exchange dials is an RPC socket. *Depends: 0.3, 1.2.*

**1.4 — Hand the exchange the peer list and ask them to sync before 07:07 UTC on
5 September.** Tell them why the date matters. This is the deliverable.
*Depends: 1.3.*

---

## Phase 2 — parallel, no dependency on Phase 1 (1–4 September)

**2.1 — Merge the consensus-schedule feed** — `params_feed.rs` +
`getconsensusschedule` from `agent-aeb2ec6de2cd89cbb` @ `858824ef`.

**2.2 — Widen both tripwires. Do not merge 2.1 or 2.3 without this.** Today they
scan only `crates/bloch-pos-committee/src/` for `_ACTIVATION_EPOCH`. They must
also scan `bloch-crypto` and `bloch-euvm`, and match `_ACTIVATION_HEIGHT`. **The
union is 13 gates; the best existing digest covers 5.** Merging unwidened ships
the exact artifact we were warned against — a digest with gaps, which an
integrator reads as exhaustive. Missing: AuxPoW 8500, EUVM 4320,
`DIFFICULTY_ANCESTRY_FORK_HEIGHT`, `CANONICAL_K`, `K_RULE`, `SHA256D_LE_FORK`,
`EMISSION_V3_TAIL`, `CARRYOVER_MEASURED_HEIGHT`. *Blocks: 2.1, 2.3.*

**2.3 — Merge `selfcheck --json` + `gates_digest`** from
`agent-a26bcc84e23ca2e0e` @ `9071ebae`. *Depends: 2.2.*

**2.4 — Publish the method.** Add `getconsensusschedule` to
`docs/specs/BLOCH-RPC-V4.md` and to the explorer proxy allowlist at
`apps/explorer/functions/rpc.js` (§7, `:393-402`). Without this the method exists
and is unreachable through the public proxy. *Depends: 2.1.*

**2.5 — Fix `params.rs:291-307`,** whose doc comment still says
`u64::MAX until the founder sets it` for a gate armed at 800. Five minutes. It is
the sentence that caused this workstream.

---

## Phase 3 — after the deadline (5–11 September)

**3.1 — Decide the `script_hash` form.** `faucet-drip.sh` and
`ONBOARDING-PARTNER.md` use the full 32-byte `SHA3-256(pubkey)`;
`bloch-withdraw` and `partner-send` use the 20-byte address form zero-padded.
**These are different keys in the eUTXO set** — `getbalance` on one does not see
coins locked under the other. A partner funded by the faucet and then running
`bloch-withdraw` sees a zero balance and reports our testnet broken. A decision,
not a bug fix, and it blocks every partner rehearsal. *Blocks: 3.3, 3.4.*

**3.2 — Fix `bloch-withdraw`'s mainnet-only address refusal**
(`crates/bloch-withdraw/src/address.rs:44-46`). The one real withdrawal client an
exchange would integrate refuses testnet addresses — it cannot run on the testnet
built for exchanges to rehearse withdrawals. *Depends: 3.1.*

**3.3 — Deploy the hosted testnet** to node4 `136.244.82.226` (founder-authorised;
cloudflared is not installed on the box). *Depends: 1.2, 3.1.*

**3.4 — One end-to-end rehearsal by us** before any partner sees it.
*Depends: 3.2, 3.3.*

**3.5 — Merge the coherence proof-size audit** into mainline `docs/audit/`. It is
byte-identical in 10 worktrees, conflicts with nothing, and it is the measurement
the architecture decision turns on.

**3.6 — Name an owner for `genesis.rs:946`,** where a second genesis constructor
stamps `coherence_root: [0u8; 32]` while the ceremony tool stamps the real
binding. Two constructors disagree on chain identity. Inert today only because
`genesis.rs` did not build the live chain.

---

## What is NOT achievable by 5 September

Stated plainly, because a schedule that hides a slip is worse than a slip.

**The hosted testnet endpoint.** `HOSTED-TESTNET.md` §9 promises partner-ready
4 September on a schedule starting 1 September. That assumed the merge had already
landed and that neither the `script_hash` split nor the `bloch-withdraw` address
refusal existed. Nothing is merged and both defects are real. **Realistic: 9–11
September.**
*Offer instead, and it is a real deliverable:* the exchange runs
`local-testnet-up.sh` themselves. That variant has actually run and finalized, it
gives them the spend path without mainnet funds — which is the stated purpose —
and it depends on nothing but the 1.2 merge.

**Coherence activation. No date at all — not September, not Q4.** The measured
proof is 1.21 MiB compressed against a 524,288-byte block cap: **2.43× an entire
block for one transaction**, and compressed proofs are constant-size (4× the work
changed the size by 384 bytes), so this does not shrink with tuning. C1 §3's "raw
FRI in the block body" is dead as designed. The three exits are a 1.5 MiB block
cap, data-availability offload, or pairings — and pairings are forbidden by C1 §3
for being non-post-quantum. **This is a founder architecture decision, and every
downstream date is meaningless until it is made.** Any date I attached here would
be fiction.
*Tell the exchange:* coherence is not part of this integration. `coherence_root`
is already computed, validated on block acceptance, and committed to the empty-pool
value — nothing about it will move under them. True, and reassuring, and free.

**The signed weak-subjectivity checkpoint.** Requires the Phase A signer ceremony:
key generation, founder-only, not delegable, not compressible. **If the exchange
has not synced by 07:07 UTC on 5 September, this becomes the critical path and its
duration is not ours to estimate.** Which is the whole argument for Phase 1.

**Staking-bond withdrawal.** Built (`Withdraw`, tag `0x08`, 4096-epoch lock) and
correctly inert at `WITHDRAWAL_ACTIVATION_EPOCH = u64::MAX`. Arming needs a
founder flag day, ordered after `FUNDED_STAKING` and `SIGNED_EXIT` — an ordering
already enforced at compile time. Exchange *payouts* are a different thing and are
built (`crates/bloch-withdraw`); do not let the two be conflated in the partner
conversation.

---

## Standing constraints observed

- **No activation constant is armed by this plan.** Every new gate ships
  `u64::MAX`. The `.activation.patch` in `agent-a5a0a10bb332b59ca` is left
  unapplied — it still carries its `__E_STAR__` placeholder and does not compile,
  which is the correct state for it. Arming is the founder's decision.
- **No live fleet, production node, or key material is touched by the PMO.** Items
  1.3 and 3.3 are marked founder-authorised operations for that reason, and the
  Phase A ceremony is named as a founder action rather than scheduled.
