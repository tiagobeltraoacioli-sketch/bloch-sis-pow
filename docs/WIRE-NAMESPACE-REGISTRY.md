# Bloch Genesis-4 — Wire Namespace Registry

**Owner: PMO.** Authoritative allocation record for every shared-namespace byte and
name in the Genesis-4 wire protocol.

Status: **LIVE — 5 unresolved collisions.** See §6.
Last swept: 2026-08-31, against mainline `canario/cache-recusa` @ `d21c3370`
and all 195 worktrees under `.claude/worktrees/`.

---

## 0. The rule

**No dev agent may use a transaction tag, frame byte, sync tag, state-root tag,
or RPC method name that is not allocated to it in this file. Claim from the PMO
first.** A claim costs one message. A collision costs a chain split.

To claim: ask the PMO for the next free value in the namespace you need. The PMO
edits this file, names you as owner, and names the test that will freeze it. Only
then do you write the constant.

### Why this file exists rather than "just grep before you pick"

Four independent collisions were found in a single day (2026-08-30) because
parallel agents each grepped, each found the same "next free" value, and each
took it. Git then merged the results without a conflict, because the constants
sat in different files or different regions of the same file. Grep-before-you-pick
is not a protocol; it has a race window as wide as the time between two agents'
greps.

### Why the compiler will not save you

The three namespaces have three different failure modes, and only one of them is
loud:

| Namespace | Dispatch | Diagnostic on duplicate |
| --- | --- | --- |
| Transaction tags | `match` on `u8` literal, `crates/bloch-pos-committee/src/transition.rs` | **`unreachable_patterns` warning** — but ONLY if both arms land in the same `match`. Two worktrees each holding one arm produce no warning until they merge, and the merge may resolve to a file where one arm was dropped. |
| State-root tags | `match`/direct key construction, `crates/bloch-pos-committee/src/state_root.rs` | **None.** Tags are prepended to trie keys, not matched. Two entries with the same tag byte silently share a keyspace and corrupt the state root. Consensus-fatal. |
| Frame bytes | `match` **with a `_` wildcard** *and* runtime `==` comparison, `crates/bloch-pos-node/src/net.rs`, `crates/bloch-pos-node/src/p2p.rs` | **None — not even a warning.** `net.rs:280-289` matches `&FRAME_BLOCK`/`&FRAME_ATT`/`&FRAME_TX` as *bindings by reference*, not literals, so `unreachable_patterns` never fires; `net.rs:406` does `if frame.first() == Some(&FRAME_GET_BLOCKS)`, a plain runtime value comparison. Two consts with different names and the same value are invisible to every diagnostic the toolchain has. |

A no-wildcard exhaustiveness test can catch the transaction-tag class. **Nothing
catches the frame-byte class except this file.**

---

## 1. Transaction tags — `u8`, first byte of an encoded `PosTransaction`

Namespace: single, global. Decoded by the `match` at
`crates/bloch-pos-committee/src/transition.rs` (mainline line 744; the arm block
has drifted to ~1008 in the deeper worktrees).

| Tag | Meaning | Status | Owner | Frozen by |
| --- | --- | --- | --- | --- |
| `0x01` | `Transfer` | **Merged**, mainline `transition.rs:744` | consensus | `crates/bloch-pos-committee/tests/committee.rs` |
| `0x02` | `Deposit` | **Merged**, legacy — decodes, then rejected at transition | consensus | committee tests |
| `0x03` | `Exit` | **Merged**, legacy — decodes, then rejected | consensus | committee tests |
| `0x04` | `Delegate` | **Merged**, legacy — decodes, then rejected | consensus | committee tests |
| `0x05` | `SlashingEvidence` | **Merged**, mainline `transition.rs:792`; returns `EvidenceNotDecodable` on the tx path | consensus | committee tests |
| `0x06` | `TransferV2` (deduplicated witness) | **Merged**, mainline `transition.rs:819` | consensus | committee tests |
| `0x07` | `DepositV2` | **UNMERGED — CONTESTED, see C-4** | staking | *none yet* |
| `0x08` | `Withdraw` | **UNMERGED — CONTESTED, see C-4** | withdraw | `crates/bloch-withdraw/tests/race.rs` (unmerged) |
| `0x09` | `ExitV2` | **RESERVED ON PAPER ONLY.** Grep across all 195 worktrees finds no `ExitV2` identifier anywhere. Nothing implements it. | exit | *none* |
| `0x0A`–`0xFF` | free | — | — | — |

**Next free transaction tag: `0x0A`.** (`0x09` is reserved, not free.)

Mainline today decodes `0x01`–`0x06` and returns `UnknownTag(other)` for
everything else. Tags `0x07`/`0x08` exist only in worktrees.

## 2. Frame bytes — `u8`, first byte of a devnet-transport frame

Namespace: single, global, `crates/bloch-pos-node/src/net.rs`.
**This is the namespace with no diagnostic. Treat every value here as consensus-
critical wire surface.**

The canonical numbering is the one in `worktree-agent-ad3f0cc77273711fd`
(branch `integ/validator-opening`), which renumbered to resolve C-1. Mainline is
behind it and only defines `0x01`–`0x04`.

| Byte | Const | Status | Owner | Frozen by |
| --- | --- | --- | --- | --- |
| `0x01` | `FRAME_BLOCK` | **Merged**, mainline `net.rs:52` | networking | *no dedicated test — gap, see §7* |
| `0x02` | `FRAME_ATT` | **Merged**, mainline `net.rs:53` | networking | *gap* |
| `0x03` | `FRAME_GET_BLOCKS` | **Merged**, mainline `net.rs:54` | networking | *gap* |
| `0x04` | `FRAME_TX` | **Merged**, mainline `net.rs:58` | networking | *gap* |
| `0x05` | `FRAME_GET_TIME` | **UNMERGED** — `agent-ad3f0cc77273711fd/…/net.rs:67` | time-sync | *gap* |
| `0x06` | `FRAME_TIME` | **UNMERGED** — `agent-ad3f0cc77273711fd/…/net.rs:71` | time-sync | *gap* |
| `0x07` | `FRAME_GET_STATE` | **UNMERGED** — `agent-ad3f0cc77273711fd/…/net.rs:82` | state-sync | *gap* |
| `0x08` | `FRAME_STATE` | **UNMERGED** — `agent-ad3f0cc77273711fd/…/net.rs:84` | state-sync | *gap* |
| `0x09`–`0xFF` | free | — | — | — |

**Next free frame byte: `0x09`.**

Worktrees carrying the canonical numbering: `agent-ad3f0cc77273711fd`,
`agent-testnet-deliver`.
Worktrees carrying `0x05`/`0x06` as `GET_TIME`/`TIME` but not yet `GET_STATE`/`STATE`:
`agent-a22395c3fedb01315`, `agent-a2fad5378f9076f04`, `agent-a9807c5e91a520ed5`.
Worktree carrying the **conflicting** numbering: `agent-a58dfe6cc066ef5b3` (C-1).

## 3. Sync tags — `u8`, first byte of a libp2p request-response payload

`crates/bloch-pos-node/src/p2p.rs`.

**This is TWO namespaces, not one.** Requests are decoded by
`decode_sync_request` and responses by `decode_sync_response`; a request tag and
a response tag may share a value without colliding. That is why mainline
`p2p.rs:369-370` has `SYNC_TAG_GET_BLOCKS = 0x01` and `SYNC_TAG_BLOCKS = 0x01`
and this is **correct, not a bug** — do not "fix" it.

### 3a. Sync request tags

| Byte | Const | Status | Owner |
| --- | --- | --- | --- |
| `0x01` | `SYNC_TAG_GET_BLOCKS` | **Merged**, mainline `p2p.rs:369` | networking |
| `0x02` | `SYNC_TAG_GET_TIME` | **UNMERGED** — `agent-ad3f0cc77273711fd/…/p2p.rs:392` | time-sync |
| `0x03` | `SYNC_TAG_GET_STATE` | **UNMERGED** — `agent-ad3f0cc77273711fd/…/p2p.rs:390` | state-sync |
| `0x04`+ | free | — | — |

### 3b. Sync response tags

| Byte | Const | Status | Owner |
| --- | --- | --- | --- |
| `0x01` | `SYNC_TAG_BLOCKS` | **Merged**, mainline `p2p.rs:370` | networking |
| `0x02` | `SYNC_TAG_TIME` | **UNMERGED** — `agent-ad3f0cc77273711fd/…/p2p.rs:393` | time-sync |
| `0x03` | `SYNC_TAG_STATE` | **UNMERGED** — `agent-ad3f0cc77273711fd/…/p2p.rs:394` | state-sync |
| `0x04`+ | free | — | — |

**Next free sync tag (both halves): `0x04`.** Allocate the request and response
halves together, at the same value, to keep the two tables readable.

Worktree carrying the **conflicting** numbering: `agent-a58dfe6cc066ef5b3` (C-2).

## 4. State-root tags — `u8`, key prefix in the state trie

`crates/bloch-pos-committee/src/state_root.rs`. **Consensus-critical: these bytes
are inside the hash preimage of the state root.** A duplicate does not produce a
wrong message; it produces a wrong state root, on every node, permanently.

| Tag | Const | Status | Owner |
| --- | --- | --- | --- |
| `0x01` | `TAG_EUTXO` | Merged, `state_root.rs:132` | consensus |
| `0x02` | `TAG_VALIDATOR` | Merged, `:133` | consensus |
| `0x03` | `TAG_PARTICIPATION_CURRENT` | Merged, `:134` | consensus |
| `0x04` | `TAG_PARTICIPATION_PREVIOUS` | Merged, `:135` | consensus |
| `0x05` | `TAG_RANDAO` | Merged, `:136` | consensus |
| `0x06` | `TAG_TAINT_ROOT` | Merged, `:137` | consensus |
| `0x07` | `TAG_COHERENCE_ACCUMULATOR` | Merged, `:138` | coherence |
| `0x08` | `TAG_COHERENCE_NULLIFIERS` | Merged, `:139` | coherence |
| `0x09` | `TAG_FINALITY` | Merged, `:143` | finality |
| `0x0A` | `TAG_PENDING_VOTE` | Merged, `:144` | finality |
| `0x0B` | `TAG_FC_MESSAGE` | Merged, `:145` | finality |
| `0x0C` | `TAG_FC_EQUIVOCATOR` | Merged, `:146` | finality |
| `0x0D` | `TAG_DEPOSIT_QUEUE` | Merged, `:147` | staking |
| `0x0E` | `TAG_DELEGATION` | Merged, `:148` | staking |
| `0x0F` | `TAG_PENDING_FEE` | Merged, `:149` | fee-market |
| `0x10` | `TAG_EVM_COMMITMENT` | Merged, `:161` | evm |
| `0x11` | `TAG_SLASH_APPLIED` | Merged, `:173` | slashing |
| `0x12` | `TAG_SLASH_WINDOW` | Merged, `:174` | slashing |
| `0x13` | `TAG_DELEGATOR_SLASH_LOSS` | Merged, `:175` | slashing |
| `0x14` | `TAG_ISSUED_SUPPLY` | Merged, `:193` | tokenomics |
| `0x15` | `TAG_BASE_FEE` | Merged, `:209` | fee-market |
| `0x16` | `TAG_DELEGATOR_FEE_REWARD` | Merged, `:219` | fee-market |
| `0x17` | **CONTESTED** — `TAG_COHERENCE_ANCHORS` *and* `TAG_SHIELDED_POOL` | **UNMERGED, see C-3** | — |
| `0x18`+ | free | — | — |

**Next free state-root tag: `0x18`** — and `0x17` must be adjudicated before
either claimant merges.

Note the separate, non-colliding tag namespaces that also live in this crate and
are **not** the state trie: `LEAF_TAG`/`NODE_TAG`/`KEY_TAG` (trie node domain
separation), `DATUM_TAG_INT`/`DATUM_TAG_BYTES` (datum encoding), and
`EUTXO_SCRIPT_TAG = 0xE0`. These are distinct namespaces; their reuse of `0x00`,
`0x01`, `0x02` is correct.

## 5. RPC method names — string keys

`crates/bloch-pos-node/src/rpc.rs`. Namespace is the method-name string; a
duplicate is a silently shadowed `match` arm.

Served today (mainline, 13 methods):

`getbalance`, `getblockbyid`, `getblockbyslot`, `getblockcount`, `getchaininfo`,
`getmempoolinfo`, `getnewaddress`, `gettransaction`, `gettxout`, `getvalidator`,
`getvalidatorcount`, `listunspent`, `sendrawtransaction`.

Integrator-visible notes that belong with this list:
- There is **no** `getblockbyheight`. Use `getblockbyslot`.
- `gettransaction` refuses by design: a Genesis-4 transfer has no transaction id.
  Integrators reconcile via `getbalance`/`listunspent` on a `script_hash`.
- A block exposes `tx_count`, not a `transactions` array.

Proposed/unmerged methods must be claimed here before implementation. Known
in-flight RPC work: `crates/bloch-pos-committee/src/params_feed.rs` +
`rpc.rs` in `agent-aeb2ec6de2cd89cbb` (consensus-parameter feed — method name
not yet claimed; **PMO to assign before that lands**).

---

## 6. Unresolved collisions

### C-1 — Frame bytes `0x05`/`0x06`: state-sync vs time-sync — **SILENT**
- `agent-a58dfe6cc066ef5b3/crates/bloch-pos-node/src/net.rs:62` `FRAME_GET_STATE = 0x05`
- `agent-a58dfe6cc066ef5b3/crates/bloch-pos-node/src/net.rs:64` `FRAME_STATE = 0x06`
- vs `agent-ad3f0cc77273711fd/…/net.rs:67,71` `FRAME_GET_TIME = 0x05`, `FRAME_TIME = 0x06`

Both are unmerged. `agent-a58dfe6cc066ef5b3` is substantial work (7 commits:
weak-subjectivity checkpoints, `state_sync.rs`, `ws_boot.rs`, `ws_tool.rs`,
`checkpoint_sync.rs`). If it merges as-is, a time-sync request and a state-sync
request become the same frame on the wire, with **no compiler diagnostic**.

**Resolution: `agent-ad3f0cc77273711fd` numbering wins** (it is the deliberate
renumbering, and `agent-testnet-deliver` already follows it).
`agent-a58dfe6cc066ef5b3` must be rebased to `FRAME_GET_STATE = 0x07`,
`FRAME_STATE = 0x08` **before** it is merged. Owner of the rebase: state-sync.

### C-2 — Sync tags `0x02`: state-sync vs time-sync — **SILENT**
- `agent-a58dfe6cc066ef5b3/…/p2p.rs:377,379` `SYNC_TAG_GET_STATE = 0x02`, `SYNC_TAG_STATE = 0x02`
- vs `agent-ad3f0cc77273711fd/…/p2p.rs:392,393` `SYNC_TAG_GET_TIME = 0x02`, `SYNC_TAG_TIME = 0x02`

Same two worktrees, same root cause, the libp2p side. **Resolution: state-sync
moves to `0x03`** (as `agent-ad3f0cc77273711fd` and `agent-testnet-deliver`
already do). Bundle with the C-1 rebase.

### C-3 — State-root tag `0x17`: coherence-anchors vs shielded-pool — **SILENT, CONSENSUS-FATAL**
- `agent-a905f26b0f5a3faaf/crates/bloch-pos-committee/src/state_root.rs:270` `TAG_COHERENCE_ANCHORS = 0x17`
- `agent-a14a11d370747fe90/crates/bloch-pos-committee/src/state_root.rs:274` `TAG_SHIELDED_POOL = 0x17`

Both unmerged, both 4-commit worktrees, both in the coherence family. If both
merge, two distinct state entries share a trie key prefix. There is no test that
would fail and no warning that would fire; the symptom is a state-root divergence
between nodes that ran different subsets of the work.

**Resolution: PMO assigns `0x17` to `TAG_COHERENCE_ANCHORS` and `0x18` to
`TAG_SHIELDED_POOL`** — coherence-anchors is on the C1 activation path and is the
nearer-term merge. Shielded-pool owner to rebase. **Neither may merge until this
is applied.**

### C-4 — Transaction tag `0x07`: `DepositV2` vs `Withdraw` — semantic
- `0x07 => DepositV2` (multi-line structural arm) in `agent-a5a0a10bb332b59ca:1092`,
  `signed-exit-wire:1092`, `agent-a087ea83a391a7f0a:1023`, with `0x08 => Withdraw`
- `0x07 => PosTransaction::Withdraw { validator: r.u32()? }` in
  `agent-a9c4ba491715890b9:816` and `agent-a1d31358b1c038bdf:816` — **no `0x08`, no `DepositV2`**

Two worktrees encode `Withdraw` as `0x07`. The founder's allocation — and the
majority of the work — is `0x07 = DepositV2`, `0x08 = Withdraw`. A withdrawal
signed by a node built from `agent-a9c4ba49` would be decoded as a `DepositV2` by
a node built from `agent-a5a0a10b`.

This class *is* catchable (duplicate literal arms in one `match` warn under
`unreachable_patterns`) — but only after the merge that creates the duplicate,
and only if the merge keeps both arms.

**Resolution: `0x07 = DepositV2`, `0x08 = Withdraw` stands.**
`agent-a9c4ba491715890b9` and `agent-a1d31358b1c038bdf` must renumber `Withdraw`
to `0x08` before merging. Owner: staking.

### C-5 — Transaction tag `0x09` `ExitV2` is allocated but absent
Not a collision; a bookkeeping hazard. `0x09` appears in the founder's allocation
list, but grep across all 195 worktrees finds **no `ExitV2` identifier and no
`0x09` match arm anywhere**. It is reserved on paper only. Recorded here so the
next agent does not read the gap as free space and take it.

---

## 7. Known registry gaps

1. **No test freezes any frame byte.** Sections 2 and 3 have no `Frozen by`
   entries because no such test exists. The namespace with the weakest compiler
   support has the weakest test support. **PMO ask: one wire-constant golden test
   asserting every `FRAME_*` and `SYNC_TAG_*` value, plus a no-wildcard
   exhaustiveness test over the transaction-tag `match`.** Small, and it converts
   three of the five collisions above from silent to loud. Not on the 5 Sep
   critical path, but it is the cheapest durable fix in this document.
2. **The RPC namespace has no owner column populated** beyond mainline, because
   no unmerged method names have been claimed yet.
3. This sweep covers `u8` constants named `FRAME_*`, `SYNC_TAG_*`, `TAG_*`, and
   `match` arms on `0x0N` literals in `transition.rs`. A namespace that names its
   constants differently would not be caught. Report any you find to the PMO.
