# Chain-Sync Model — Phase 2 SHIPPED note

> **Fold-in target:** this block belongs under **§3 "Ships NOW vs phased roadmap"**
> of `CHAIN-SYNC-MODEL.md`, immediately after the *Phase 2* roadmap entry. It is
> kept as a companion file only because Phase-2 landed across parallel worktrees;
> merge it into §3 when the branches converge.

### Phase 2 — **SHIPPED** (DAG-frontier Tier-1 reconciliation, Layer 3 + Layer 4 local half)

Landed as a **drop-in, additive** sync-negotiation layer over the existing
gossip transport, gated behind the `Version` handshake. **Consensus, block
bytes, `block_hash`, GHOSTDAG coloring, difficulty, and `accept_block` are
untouched** — every consensus call in the layer is read-only (`tips()`,
`selected_tip()`, `selected_chain()`, `has_block()`, `get_node()`).

**What shipped**

- **`GetTips` / `Tips { tips, locator }` wire frames** (`network::NetworkMessage`),
  bounds-validated on the untrusted decode path (`MAX_WIRE_TIPS = 256`,
  `MAX_WIRE_LOCATOR = 64`, mirroring the C1 pre-allocation discipline). Over-length
  frames are rejected as protocol violations.
- **`src/sync/` module tree**: `frontier` (pure diff + in-flight tip tracker),
  `locator` (exponential-backoff block-locator over the selected chain +
  common-ancestor resolve), `peer_state` (`PeerId`-keyed chain-state table +
  servable-frontier query).
- **Blue_work-VERIFIED IBD latch** (`maybe_release_ibd`, the single releaser):
  - **TRIGGER** `is_syncing = true` on a frontier gap — a connected peer
    advertises a tip we do not `has_block()`. The legacy `peer_s > our_s`
    blue_score trigger is retained as a (safe, over-triggering) fallback.
  - **RELEASE** `is_syncing = false` **only** when the frontier is reconciled
    (`has_block()` for every connected peer's advertised tips), nothing is
    in-flight (`frontier.outstanding() == 0`), **and** our selected-tip
    `blue_work >= servable_blue_work` — both recomputed locally from the DAG.
- **`best_seen_blue_score` no longer gates the latch** — it is retained as an
  **RPC display hint only**. Announced blue_score / height are never trusted for
  release (the one-frame-liveness-kill incident is closed): a fabricated high
  `PeerTip`/`Version` score with no servable blocks neither clears `is_syncing`
  nor freezes the node (the nudge keeps issuing `GetTips`/`GetHeaders`).

**Set-difference over scalar-cursor.** Because reconciliation diffs the DAG tip
*set* (`diff_missing` / `to_request`), two divergent tips with an **identical
blue_score** are both requested — the equal-score divergence a blue_score cursor
silently drops.

**Retained fallback.** Gossip stays the fallback path: `GetTips/Tips` is added
*beside* the existing `GetHeaders`/`Headers`/`GetBlock` + gossipsub NewBlock
relay, never instead of it, so a mixed-version fleet still converges during
rollout. Missing parents of advertised tips flow into the existing orphan pool
via the unchanged `NewBlock` `waiting_for` recursion — no new orphan code.

**Explicitly excluded (still Phase 3, future work).** The libp2p
`request_response` directed-transport rewrite and Kaspa headers-proof trustless
IBD (Layers 1 + 4 durable half) are **not** in this change — too large, staged
separately behind the handshake.

**Test coverage (P6).** `tests/sync_frontier.rs`, `tests/sync_locator.rs`,
`tests/sync_peer_state.rs` (unit); `tests/sync_wire.rs` (`GetTips`/`Tips`
round-trip, over-length bounds rejection, and compile-time `MAX_WIRE_TIPS ==
MAX_ADVERTISED_TIPS` / `MAX_WIRE_LOCATOR == MAX_LOCATOR_LEN` const equalities);
`tests/frontier_sync.rs` (integration: behind-node requests the gap → converges
→ releases only on blue_work parity; fabricated-score-no-blocks does **not**
release; equal-blue_score divergent tips are both requested).
