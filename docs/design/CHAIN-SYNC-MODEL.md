# Bloch Chain-Synchronization Model — PMO Decision Doc

## 1. Root-cause framing: three independent failure axes, only one of which is the incident

The wedge ("nodes stall at different heights") is **not a bandwidth problem and not a tuning problem** — it is a *sync-control-plane trust and topology* problem. Separate the three axes cleanly, because the advisors that scored "low/medium fit" all mis-target the wrong axis:

**Axis A — LATCH / TRUST (the incident).** `is_syncing` is gated on `best_seen_blue_score`, a peer-supplied, monotonic, never-decaying, *unvalidated* high-water mark raised by any `PeerTip` **or** `Version` frame (`main.rs:519-533`, `771-782`). A single announcement — honest-but-now-unreachable, dedup-dropped, or fabricated — pins `is_syncing=true` forever; the 30s nudge broadcasts `GetHeaders` into the void, no reachable peer serves the range, and the node never converges. The sync latch releases on *announced score parity*, not on *verified possession of the heaviest validated chain*. This is the phantom-peer deadlock in the convergence runbook. **This is the whole incident.**

**Axis B — TOPOLOGY / REACHABILITY.** Every sync verb (`GetHeaders/Headers/GetBlock/PeerTip/Version`) is *broadcast* to the shared `bloch/sync/1` gossip topic (`network/mod.rs:1008-1020`, `_ => sync_t`). `BlochBehaviour` has **no request/response** — no verb has an addressee, no reply has a verifiable author. So "pull the heaviest chain from the specific peer that holds it" has *no code path*, and the stated hard constraint ("degrade gracefully when the heaviest chain sits on an unreachable peer") is structurally unsatisfiable. Compounded by a real bug: `ConnectionEstablished` stores the ephemeral `send_back_addr` (source port) instead of the peer's listen addr (`network/mod.rs:821-823`), so NAT'd peers become permanently un-redialable after restart — manufacturing "unreachable heaviest chain."

**Axis C — PERF / DAG-CORRECTNESS.** `ordered_hashes_from` is an O(N log N) full-store scan+sort per `GetHeaders` (`consensus/mod.rs:1227`). The scalar `from_blue_score` cursor is a *linear-chain shape imposed on a DAG*: blue_score is neither unique nor a total order, so equal-blue_score-but-divergent tips are unrepresentable, a >500-wide blue_score band never advances the cursor, and one lost body below the cursor silently orphan-freezes the tip at a differential height (no timeout/retry/back-fill).

**Bandwidth is a fourth, orthogonal axis — and it is not on fire.** Bloch is ownerless, zero-value, ~0 tx volume, coinbase-only blocks, 30s block time. Every bandwidth optimization (Compact Blocks, Erlay, Graphene) optimizes a non-bottleneck and, for the tx-relay ones, a layer that *does not exist* (Bloch floods full tx bodies, not txid INVs). They save essentially nothing on a coinbase-only block. **None of them touch the incident.**

---

## 2. Recommended layered model

Six layers. Each is DROP-IN (additive wire gated by the `Version` handshake, no consensus/coloring/hash change, `accept_block` result-identical, gossip path retained as fallback during rollout).

### Layer 1 — Catch-up / IBD: **Kaspa-style self-verifying headers-first, blue-work triggered**
- **Algorithm:** Replace the scalar cursor with an exponential-backoff **block locator** (`selected_chain()` sampled with doubling gaps). Put the **real `BlockHeader` (parents + PoW)** into the sync entry so the receiver validates chain connectivity and PoW *trustlessly* before fetching bodies. Trigger and release IBD on **locally-recomputed `blue_work`** (already stored as `GhostdagData.blue_work: u128`, `consensus/mod.rs:39`), never on peer-advertised score.
- **Why over generic headers-first-pipelined-IBD (advisor: medium):** Kaspa is the same GHOSTDAG lineage and Bloch *already carries* the two pivot structures — the reachability oracle (`reachability.rs`) and cumulative `blue_work`. This is a rewire, not new consensus. It directly kills Axis A (latch moves from unvalidated blue_score to locally-verified blue_work) and Axis C (locator replaces the O(N log N) scan and the ambiguous cursor).
- **Rejected sub-part:** UTXO-commitment fast-sync (needs a `BlockHeader` field Bloch lacks = fork) and the SIS pruning-point proof (Module-SIS has no native numeric "block level"; unproven research). Trust anchor stays the already-shipped signed R2 k=8 snapshot (Bitcoin-assumeUTXO-style, acceptable under voluntary adoption).

### Layer 2 — Steady-state block propagation: **keep gossipsub inv/getdata NewBlock relay; add Kaspa relay-gating**
- **Algorithm:** Retain today's gossip relay. Add the one missing Kaspa invariant: **disable relay-driven acceptance while `is_syncing`** (suppresses fanout of blocks you can't yet place).
- **Why:** At coinbase-only / 30s, full-push is already cheap (30s >> propagation). Compact Blocks is the *correct* future optimization but saves ~0 today (coinbase is always prefilled). Defer it (Layer in roadmap Phase 4), don't build it into the beta model.

### Layer 3 — Tip / frontier reconciliation: **DAG-frontier Tier 1 (bounded tip-set + selected-chain locator)**
- **Algorithm:** Add `GetTips` / `Tips{tips, locator}`. `tips` is the full DAG frontier from `consensus::tips()` (bounded small — GHOSTDAG_K=10 caps healthy anticone width). For each advertised tip we don't `has_block()`, emit `GetBlock`; unknown parents flow into the existing orphan pool. **Sync completion becomes a set condition: our tip-set ⊇ every *reachable* peer's advertised tip-set AND no outstanding requests** — not a blue_score inequality.
- **Why over the scalar cursor:** A DAG frontier *is a set*; set-difference is the semantically correct primitive. This is the direct fix for the "equal-blue_score, divergent tips" divergence the cursor provably cannot express, and graceful-degradation falls out for free (reconcile with whoever you *can* reach; an unreachable heavy tip can't falsely finish sync). Advisor fit: **high**.
- **Rejected sub-part:** Tier 2 Minisketch/IBLT anticone set-reconciliation — marginal bandwidth win while K=10 keeps tip counts tiny, adds a decode-exhaustion DoS surface to an unaudited node. Defer.

### Layer 4 — Peer selection: **per-peer chain-state table + servable-frontier latch + directed request/response**
- **Algorithm:** Maintain `PeerId → (blue_score, height, last_seen)` keyed on `ConnectionEstablished`. Split `best_seen` into **best-*heard*** (gossip hint) vs **best-*servable*** (a directly-connected peer that actually answered). Pull directionally from the highest-blue_work *connected* peer via a new libp2p `request_response` behaviour, with timeout + failover to next-best. Fix `send_back_addr → listen_addr` harvesting so NAT'd peers stay redialable.
- **Why:** This is what makes "pull the heaviest chain from the peer that holds it" *exist*, and latching only on the servable frontier is the architectural (not band-aid) cure for Axis A/B. Advisor fit: **high**.

### Layer 5 — Liveness / stall-release: **keep mine-through as emergency valve, but re-governor it to mine-but-don't-finalize**
- **Algorithm:** Retain the latch-poison escape valve (load-bearing — it's the only thing stopping one fabricated score from freezing all miners), but fix its three defects: **(a)** stop resetting the stall timer on the node's *own* mined block (`main.rs:978-985`) — key on peer-delivered progress, else the miner self-throttles to ~1 block/90s; **(b)** while stall-released, **freeze `finalized_height` advancement** (`main.rs:1984-2006`) and allow an **asymmetric deep-reorg-back** to any strictly-heavier chain sharing pre-stall history, so mine-through can *never* self-finalize a solo fork past `CHECKPOINT_DEPTH`/`MAX_REORG_DEPTH=1000` (~8.3h wedge budget → permanent partition today); **(c)** decay/validate `best_seen` so the valve is rarely needed.
- **Why:** As built, mine-through is a fork-maker for long wedges — directly violates no-fork. The re-governored version keeps liveness while staying reorg-safe.

### Layer 6 — Security (cross-cutting MUST-defend)
- **Non-negotiable:** unvalidated peer work must **never** gate mining (fixed by Layers 1+4); **PoW-verify headers before any `GetBlock` fanout** (fixed by Layer 1 putting real headers in sync entries — closes the fabricated-hash-list amplification storm); **bound the orphan pool by bytes not count** (today 10k × 4 MiB ≈ 40 GB ceiling); per-peer rate-limit serving; index `ordered_hashes_from` to kill the O(N log N) mesh amplifier. Moving sync onto `request_response` (Layer 4) is what finally gives eclipse/rate-limit/scoring defenses an *addressee*.
- **Reject** sketch/IBLT reconciliation until behind hard difference/iteration caps — it widens attack surface more than it narrows.

---

## 3. Ships NOW vs phased roadmap

### Already landed (keep)
- **Pipelined IBD** (re-request next batch on full batch) — good common-case improvement.
- **Miner sync-stall-release** — keep as valve, but it is a *symptom mask*; Phase 1 must fix its bugs (Layer 5a/b) or it silently forks on long wedges.

### Phase 1 — NOW / next (drop-in, main.rs+consensus-local, **no wire change**) — effort **S–M**
Kill the incident with zero protocol risk:
1. `best_seen` **decay + validate against retrieved blocks**; release latch on verified `blue_work`, not announced score. *One-frame liveness kill → gone.*
2. **Per-peer chain-state table + servable-frontier latch** (Layer 4, the local half). *Distinguishes heard-of from fetchable tips.*
3. **`send_back_addr → listen_addr`** harvest fix. *Stops manufacturing unreachable peers.*
4. Stall-release **self-mined-timer fix + freeze `finalized_height` + asymmetric deep-reorg-back** (Layer 5). *Stops self-forking.*
5. **Index `ordered_hashes_from`** (blue_score/selected-chain index). *Removes the O(N log N) serve amplifier.*

### Phase 2 — **DAG-frontier Tier 1 reconciliation** (Layer 3) — effort **M**
Additive `GetTips/Tips`, handshake-gated. One-line rationale: *the DAG-correct set-difference fix for equal-blue_score divergence, reusing `tips()`/`selected_chain()`/reachability/orphan-pool — no new crypto.*

### Phase 3 — **Kaspa headers-proof IBD + directed request/response transport** (Layers 1+4 durable half) — effort **L**
Coordinated wire change across `network/mod.rs`+`main.rs`+`consensus/mod.rs`, gossip retained as fallback. Rationale: *the structural cure — self-verifying trustless IBD + peer-directed pull with failover; the largest change, staged behind the handshake so a mixed fleet still converges.*

### Phase 4 — **Compact Blocks (BIP152)** — effort **M**, **gated on real non-coinbase tx volume**
Rationale: *architecturally clean, PQ-tx + DAG-width economics are compelling, but coinbase-only blocks save ~0 today; reuses the existing GetBlock fallback + block_hash re-derivation backstop.*

### Phase 5 — **Defer / research** (do not schedule for beta)
- **Erlay/Minisketch** — effort L. *Optimizes a txid-INV layer Bloch doesn't have; near-zero payoff at beta volume; C dep vs reproducible builds.*
- **Graphene/IBLT** — effort L. *Near-zero benefit coinbase-only; IBLT decode-DoS surface; non-canonical tx ordering erodes the win — strictly inferior to Compact Blocks at this scale.*
- **DAG-frontier Tier 2 (Minisketch/IBLT anticone reconciliation)** — effort L. *Marginal while K=10 keeps tips tiny; decode-failure surface.*
- **SIS pruning-point succinct proof** — research. *Needs an unproven Module-SIS "block level" metric.*

---

## 4. Explicit non-goals / rejected for beta
- **Erlay, Graphene, Compact-Blocks-now** — bandwidth optimizations for a non-bottleneck; do not touch the incident.
- **Minisketch/IBLT anything** (tx reconciliation or frontier Tier 2) — adds decode-exhaustion attack surface to an unaudited node for near-zero present benefit.
- **UTXO-commitment fast-sync** — requires a `BlockHeader` field Bloch lacks = **consensus fork = forbidden**.
- **Kaspa pruning-point proof** — depends on an unproven SIS PoW-level grading; keep the signed R2 snapshot as the trust anchor instead.
- **Ripping out gossipsub sync** — gossip stays as the fallback path through all phases so the voluntary-adoption fleet interops during rollout; `request_response` is added *beside* it, never *instead of* it until proven.

---

## 5. Constraint preservation
- **DROP-IN / no fork:** every layer is additive wire gated by the existing `Version` handshake; nothing changes block bytes, `block_hash`, GHOSTDAG coloring, difficulty, or the `accept_block` validation path (the H2 hash-rebind backstop at `main.rs:646` guarantees any mis-sync is dropped, never accepted). Sync-completion and stall-release are *liveness policy*, deliberately kept out of consensus. All mined tokens/history preserved bit-identically.
- **Ownerless:** no change touches issuance/incentives; the coin's zero value is precisely why the bandwidth layers are correctly deprioritized (no tx volume to compress).
- **Unaudited:** Phase 1 is protocol-risk-free; probabilistic coding (Minisketch/IBLT) is deferred out of beta specifically to keep new untrusted-decode surface minimal; every new variable-length field lands with hard pre-allocation bounds mirroring the existing C1 decode discipline.
- **Graceful degradation on unreachable heaviest chain:** delivered by Layers 3+4 — reconcile with reachable peers, latch only on the servable frontier, keep mining the locally-heaviest *validated* tip (Layer 5), and auto-merge the heavier subDAG by blue_work when its holder becomes dialable. GHOSTDAG makes that convergence result-identical once connectivity returns.

**Bottom line:** the incident is Axis A (unvalidated-score latch) amplified by Axis B (no peer-directed pull). Ship Phase 1 immediately to stop the wedge with zero protocol risk; land DAG-frontier reconciliation (Phase 2) and Kaspa headers-proof IBD + directed transport (Phase 3) as the durable model. Everything bandwidth-shaped is deferred until tx volume exists.