# Bloch Genesis-4 — Wire Namespace Registry

**Owner: PMO.** Authoritative allocation record for every shared-namespace byte and
name in the Genesis-4 wire protocol.

Status: **LIVE — 4 unresolved collisions (C-3 resolved in code), 5 newly
registered namespaces, 1 new hazard (§9.1).** See §6 and §9.
Last swept: 2026-09-01, against `main` @ `1f21a3ed` and branch
`pmo/wire-namespace-registry` @ `cc3f79b7`, plus all 195 worktrees under
`.claude/worktrees/`.
Previous sweep: 2026-08-31 against `canario/cache-recusa` @ `d21c3370`.

**Changed since the 2026-08-31 sweep** (mainline moved; re-verify before
citing the older sweep):
- `crates/bloch-pos-committee/src/ws.rs` and `crates/bloch-pos-node/src/ws_boot.rs`
  are now **merged on `main`**. Weak-subjectivity boot is no longer unmerged
  worktree work. `WS_PERIOD_EPOCHS` is *derived* (`ws.rs:140-141`) as
  `WITHDRAWAL_DELAY_EPOCHS − EXIT_DELAY_EPOCHS`, not a chosen literal — do not
  hard-code 2016 anywhere.
- A nested sub-namespace appeared under transaction tag `0x05`. See §1a.

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

## 1a. Slashing-evidence kinds — `u8`, NESTED sub-namespace inside tag `0x05`

**New in this sweep. This namespace did not exist at the 2026-08-31 sweep and is
not covered by any earlier claim.**

Commit `d21c3370` (`wip: caminho de submissao de evidencia de slashing`) on
branch `pmo/wire-namespace-registry` converts transaction tag `0x05` from a flat
rejection (`return Err(TxDecodeError::EvidenceNotDecodable)`) into a decoder that
reads **a second discriminant byte** and matches on it —
`crates/bloch-pos-committee/src/transition.rs:792-818`.

That second byte is a new, independent namespace. It is nested inside `0x05`, so
its values are free to repeat values used by §1; `0x01` here is not `Transfer`.

| Sub-tag | Meaning | Status | Owner | Frozen by |
| --- | --- | --- | --- | --- |
| `0x01` | `SlashingEvidence::ProposerEquivocation { first, second }` | **UNMERGED** — `transition.rs:795` | slashing | *none yet — gap* |
| `0x02` | `SlashingEvidence::AttestationOffence { first, second }` | **UNMERGED** — `transition.rs:805` | slashing | *none yet — gap* |
| `0x03`–`0xFF` | free | — | — | — |

**Next free evidence sub-tag: `0x03`.**

Two properties make this safer than the frame-byte namespace, and one makes it
more dangerous:

- *Safer:* it dispatches by `match` on `u8` literals with an explicit
  `other => return Err(TxDecodeError::NotCanonical(other))` arm. Duplicate
  literals in one `match` **do** raise `unreachable_patterns`, and the catch-all
  refuses unknown values rather than ignoring them. This namespace is
  freezable by a no-wildcard exhaustiveness test, exactly like §1.
- *More dangerous:* it is invisible to every sweep that greps for
  `const NAME: u8 = 0x..`. These two values are bare literals inside a nested
  `match`, bound to no constant at all. **The 2026-08-31 sweep missed it for
  precisely this reason** — see §7 gap 3, which predicted this class.

**PMO ruling:** before this decoder merges, its two values must be lifted to
named constants (`EVIDENCE_KIND_PROPOSER_EQUIVOCATION = 0x01`,
`EVIDENCE_KIND_ATTESTATION_OFFENCE = 0x02`) so that future sweeps can see them.
A bare literal in a nested match is not a claimable allocation.

**Related — a transport-level gate, not a namespace, recorded so it is not
mistaken for one:** the same commit adds a gossipsub relay verdict for evidence
at `crates/bloch-pos-node/src/p2p.rs`, keyed on
`SLASHING_EVIDENCE_ACTIVATION_EPOCH` (`params.rs:638`). **Verified inert:
`u64::MAX`.** It is the only activation constant this branch adds, and it is not
armed. `main` does not define it at all.

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
| `0x17` | `TAG_COHERENCE_ANCHORS` | **UNMERGED — ruling applied**, `recon-coherence/…/state_root.rs:295` | coherence | *none — gap, see §8.3* |
| `0x18` | `TAG_SHIELDED_POOL` | **UNMERGED — ruling applied**, `recon-coherence/…/state_root.rs:330` | coherence | *none — gap, see §8.3* |
| `0x19`+ | free | — | — | — |

**Next free state-root tag: `0x19`.**

**C-3 is resolved in code as of 2026-09-01** — see §6 C-3. The two stale
claimants (`agent-a905f26b0f5a3faaf`, `agent-a14a11d370747fe90`) must not be
merged; `recon-coherence` supersedes both.

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

Dispatch table is `crates/bloch-pos-node/src/rpc.rs:856-919` — 13 names, 12
handlers (`getutxos` and `listunspent` alias one handler at `:882`).
`gettransaction` (`:865`) and `getnewaddress` (`:866`) are deliberate typed-error
stubs, not gaps.

### Allocated, unmerged

| Method | Status | Owner | Frozen by |
| --- | --- | --- | --- |
| `getconsensusschedule` | **CLAIMED by PMO, 2026-08-31.** Built in `agent-aeb2ec6de2cd89cbb` @ `858824ef`, dispatch `rpc.rs:869`, handler `consensus_schedule_json` `:1258-1325`, envelope `schema: "bloch-consensus-schedule/1"` | integrations | `crates/bloch-pos-node/src/rpc/tests.rs:474-500` (asserts the reply neither drops nor invents a gate relative to `params_feed::SCHEDULE`) |

No other unmerged method names exist anywhere in the tree. `getconsensusschedule`
is the only addition, and it is now claimed — do not rename it.

**`docs/specs/BLOCH-RPC-V4.md` has no consensus-schedule method** and §7
(`:393-402`) requires the explorer proxy read-only allowlist at
`apps/explorer/functions/rpc.js` to be regenerated for V4. Both must be updated
when `getconsensusschedule` lands, or the method will exist and be unreachable
through the public proxy.

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
nearer-term merge. Shielded-pool owner to rebase.

### C-3 — **STATUS: RESOLVED IN CODE, 2026-09-01. Pending merge.**

Worktree `recon-coherence`, branch **`recon/coherence-core-20260901`** @ `52c40d89`,
carries the ruling exactly as issued:
- `TAG_COHERENCE_ANCHORS = 0x17` (`state_root.rs:295`)
- `TAG_SHIELDED_POOL = 0x18` (`state_root.rs:330`)

It is the reconciliation of the five divergent `coherence-core` copies
(`0810f1eb`) and it has already merged `main` (`52c40d89`), so it is ahead of both
original claimants rather than parallel to them.

**Supersession, and this is the operative instruction:** `agent-a905f26b0f5a3faaf`
and `agent-a14a11d370747fe90` are now **stale claimants**. Merging either one
after `recon-coherence` re-introduces the collision from behind — each still
defines its own tag at `0x17`, and neither `git` nor `rustc` will object, because
the two definitions live in worktrees that never see each other. **Neither may be
merged. Their non-tag content must be cherry-picked, never merged as a tree.**

**Caveat before endorsing this branch:** its base commit `0810f1eb` is a
`wip(coherence)` commit — unreviewed input under the standing rule, not history.
Run `git diff --stat` from the last validated point and read the delta before the
merge; do not rely on `git log`. The tag allocation above is verified; the rest of
the branch is not.

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

1. **No test freezes any frame byte *on mainline*. The tests exist and are
   unmerged.** Sections 2 and 3 have no `Frozen by` entries for that reason.

   **Correction, 2026-09-01 — read this before acting on the earlier wording.**
   An earlier revision of this file claimed the gap was "total, not partial",
   on the strength of a search that returned zero matches across every `tests/`
   directory. **That search was wrong, and wrong in the way this document keeps
   warning about: it searched by location instead of by content.** Rust unit
   tests live in `#[cfg(test)] mod tests` *inside* `src/`, so a `tests/`-only
   sweep cannot see them. `net.rs` has no `#[cfg(test)]` block on mainline, which
   is what made the false negative look plausible.

   What actually exists, verified by reading the files:

   | Test | Location | Trees carrying it |
   | --- | --- | --- |
   | `frame_bytes_are_claimed_exactly_once` | `crates/bloch-pos-node/src/net.rs:825` | `agent-ad3f0cc77273711fd`, `agent-testnet-deliver`, `agent-testnet-spendpath` |
   | `sync_tags_are_claimed_exactly_once_per_namespace` | `crates/bloch-pos-node/src/p2p.rs:1899` | same three |
   | `time_and_state_sync_messages_do_not_decode_as_each_other` | `crates/bloch-pos-node/src/p2p.rs:1926` | same three |
   | `every_wire_tag_is_claimed_exactly_once` | `crates/bloch-pos-committee/src/transition.rs` (~`:8725`) | `agent-a5a0a10bb332b59ca`, `signed-exit-wire`, `exit-churn` |

   They implement §8 almost exactly as specified below — pairwise `assert_ne!`,
   then a golden-value `assert_eq!` over the whole array, with the two sync
   halves checked **separately** and the reason documented in the test file
   (`p2p.rs:1888-1897`). §8 is therefore a **specification of work already done**,
   and the action is to **merge `agent-ad3f0cc77273711fd`, not to write tests.**

   Three qualifications keep this a live gap rather than a closed one:
   - Present in **3 of ~65** worktrees, and in **none** of mainline.
   - **`agent-a58dfe6cc066ef5b3` — the one tree carrying the colliding
     numbering (C-1, C-2) — has no assertion on any frame or tag value.** The
     guard and the collision are in different trees, so merge order decides
     whether the guard ever sees the collision.
   - The two clock-gate trees `agent-a22395c3fedb01315` and
     `agent-a2fad5378f9076f04` have a *weak* partial guard
     (`p2p.rs:~1523`) asserting only that the new time tags differ from the
     block tags. **It would not have caught C-1.** A partial guard that passes
     is more dangerous than no guard, because it reads as coverage. The namespace with the weakest compiler
   support has the weakest test support. **PMO ask: one wire-constant golden test
   asserting every `FRAME_*` and `SYNC_TAG_*` value, plus a no-wildcard
   exhaustiveness test over the transaction-tag `match`.** Small, and it converts
   three of the five collisions above from silent to loud. Not on the 5 Sep
   critical path, but it is the cheapest durable fix in this document.
2. **The RPC namespace has no owner column populated** beyond mainline, because
   no unmerged method names have been claimed yet.
3. ~~This sweep covers `u8` constants named `FRAME_*`, `SYNC_TAG_*`, `TAG_*`, and
   `match` arms on `0x0N` literals in `transition.rs`. A namespace that names its
   constants differently would not be caught.~~ **CLOSED 2026-09-01.** Re-swept
   by *shape* (`const NAME: u8 = 0x..`, and bare hex literals in nested `match`
   arms) instead of by name. Found five previously untracked namespaces: the
   evidence sub-namespace (§1a) and four in §9. One of them, `ROLE_*` (§9.1), is
   a live collision hazard split across two files.
4. **A namespace can still hide as a bare literal bound to no constant.** §1a was
   missed by the 2026-08-31 sweep for exactly this reason: its two values are
   literals inside a nested `match`, matching no `const` pattern. The shape sweep
   now covers `^\s*0x.. =>` as well, but an agent who writes
   `if byte == 7` rather than `0x07 =>` remains invisible to both. **Rule: every
   value with wire or hash meaning must be a named constant.** This is now the
   cheapest thing separating us from a sixth collision.

---

## 8. The freezing tests — specification (**built and unmerged**, see §7 gap 1)

§7 gap 1 records that no test freezes a frame byte or a sync tag **on mainline**.
The implementation already exists in `agent-ad3f0cc77273711fd` and matches this
specification closely; what follows is kept as the normative statement of what
the tests must assert, and as the acceptance criteria for that merge.
This section specifies exactly what to build, because "add a test" has already
been mis-implemented once as a round-trip test, which does not catch a collision:
encoding and decoding with the *same* wrong constant round-trips perfectly.

A collision test must assert **values**, and **distinctness**, not behaviour.

### 8.1 Frame bytes and sync tags — pairwise distinctness (the one that matters)

Location: `crates/bloch-pos-node/tests/wire_constants.rs` (new file).
Owner: networking. Blocks: nothing — build it independently, merge it early.

Three assertions, in this order:

1. **Golden values.** One `assert_eq!` per constant against a hard-coded literal
   (`assert_eq!(FRAME_BLOCK, 0x01)`, …). This makes any renumbering a loud test
   failure that names the constant, so a renumber becomes a deliberate act with a
   diff reviewers can read.
2. **Pairwise distinctness within each namespace.** Collect each namespace into
   an array of `(name, value)` pairs, then assert every pair of distinct names
   has distinct values — and **assert the array length**, so a newly added
   constant that is not added to the array fails the count rather than passing
   silently. This is the assertion that has no compiler equivalent.
   - `FRAME_*` → one namespace.
   - `SYNC_TAG_GET_*` (requests) → one namespace.
   - `SYNC_TAG_*` non-`GET_` (responses) → a **separate** namespace.
3. **The two sync halves are NOT cross-checked.** `SYNC_TAG_GET_BLOCKS = 0x01`
   and `SYNC_TAG_BLOCKS = 0x01` are both correct (§3). A test that checks all
   sync tags for global distinctness will fail on correct code, be "fixed" by
   renumbering, and cause the split it was written to prevent. **Write this
   caveat as a comment in the test file itself**, not only here.

### 8.2 Transaction tags — no-wildcard exhaustiveness

Location: alongside `crates/bloch-pos-committee/tests/committee.rs`.
Owner: consensus.

Assert the decoder's accepted set is exactly `{0x01…0x06}` on `main`, by feeding
each byte `0x00..=0xFF` a minimal payload and asserting that every byte outside
the allocated set returns `UnknownTag`. This freezes the *boundary*, so an agent
that adds `0x07` must update the test, which is the moment the PMO gets asked.

Extend to the §1a evidence sub-namespace with the same shape once its literals
are lifted to constants.

### 8.3 State-root tags — distinctness, and why it is urgent

Location: `crates/bloch-pos-committee/tests/state_root_tags.rs` (new file).
Owner: consensus.

Same pairwise-distinctness shape as 8.1. These constants are `const` and
file-local, so the test must live in the crate or the constants must be made
`pub(crate)` and re-exported behind `#[cfg(test)]`.

This is the namespace where a duplicate is **consensus-fatal and silent** (§4,
C-3). It is also the easiest to test, because all 22 constants sit in one
contiguous block. **Highest value per line of test code in this document.**

### 8.4 Deliberately out of scope

Not RPC method names: a duplicate `match` arm on a string literal is a shadowed
arm the compiler does warn about under `unreachable_patterns`, and the dispatch
table is one contiguous block that a reader can check. Cheap to add later; not
where the risk is.

---

## 9. Secondary namespaces — newly registered, 2026-09-01

§7 gap 3 warned that the sweep only covered constants named `FRAME_*`,
`SYNC_TAG_*`, `TAG_*`, and `0x0N` match arms in `transition.rs`, and that a
namespace naming its constants differently would be missed. Sweeping for the
*shape* (`const NAME: u8 = 0x..`) rather than the *name* found four. One is a
live hazard.

### 9.1 Role tags — **HAZARD: one namespace, two files**

Mixed into the SHAKE-256 sortition seed under `DS_SORTITION`. These select the
committee, so a duplicate silently corrupts committee selection — the same
severity class as a state-root tag.

| Value | Const | File | Owner |
| --- | --- | --- | --- |
| `0x01` | `ROLE_SLOT` | `crates/bloch-pos-committee/src/params.rs:717` | consensus |
| `0x02` | `ROLE_EPOCH` | `crates/bloch-pos-committee/src/params.rs:718` | consensus |
| `0x03` | `ROLE_PARTITION` | `crates/bloch-pos-committee/src/committees.rs:64` | consensus |
| `0x04`+ | free | — | — |

**Next free role tag: `0x04`.**

**Why this is a hazard and not just an omission.** `ROLE_SLOT` and `ROLE_EPOCH`
are declared in `params.rs`; `ROLE_PARTITION` is declared in `committees.rs`,
**a different file**, and is `const` (file-local), so nothing links them. An
agent adding a role will grep `params.rs`, see `0x01` and `0x02`, and take
`0x03` — which is already `ROLE_PARTITION`. No warning, no error, wrong
committee. The `committees.rs:62-63` doc comment is aware of the coupling
("Distinct from the sortition roles so the partition can never coincide with a
proposer draw") but a comment in the *other* file is not a mechanism.

**PMO ruling: `ROLE_PARTITION` should move to `params.rs` beside the other two,
or all three should be re-exported from one module.** Until then this table is
the only thing linking them. Freeze all three with the §8.1 pairwise test.

### 9.2 Merkle mark / kind tags — `crates/bloch-pos-committee/src/derive.rs`

Two independent namespaces in one file; their overlap is correct.

| Value | Const | Line | Namespace |
| --- | --- | --- | --- |
| `0x00` | `MARK_LEAF` | `:355` | tree-position marks |
| `0x01` | `MARK_NODE` | `:356` | tree-position marks |
| `0x02` | `MARK_EMPTY` | `:357` | tree-position marks |
| `0x01` | `KIND_TX` | `:358` | body-item kinds |
| `0x02` | `KIND_ATTESTATION` | `:359` | body-item kinds |

`MARK_NODE` and `KIND_TX` are both `0x01` and this is **correct** — they are
hashed into different positions and never compared. Do not "fix" it. Next free:
`MARK_*` `0x03`, `KIND_*` `0x03`.

### 9.3 Genesis allocation buckets — `crates/bloch-pos-node/src/genesis.rs:173-179`

`FOUNDER` `0x01`, `VC` `0x02`, `TEAM` `0x03`, `MARKETING` `0x04`,
`LIQUIDITY` `0x05`, `VALIDATOR_EMISSION` `0x06`. Next free: `0x07`.

Contiguous, `pub`, in one block, and genesis is already stamped — low risk, but
recorded because a bucket added here changes the genesis allocation and must be
a founder decision, never an agent's. **Frozen in practice by the live chain,
not by a test.**

### 9.4 Domain separators — `[u8; 16]`, `params.rs:642-709`

14 allocated: `DS_SORTITION`, `DS_ATTEST`, `DS_BLOCK`, `DS_BODY`, `DS_STATE`,
`DS_RANDAO`, `DS_DEPOSIT`, `DS_SPEND`, `DS_TXID`, `DS_SLASH`, `DS_PROPOSE`,
`DS_EXIT`, `DS_WSCKPT`, `DS_COHERENCE`. **Verified all 14 values distinct**
(2026-09-01).

Lower risk than the `u8` namespaces because the values are self-describing
strings, and a duplicate is visible on the line that declares it. **The real
constraint is the fixed 16-byte width:** the `BLCH4:` prefix costs 6, leaving 10
characters. `DS_PROPOSE` ("BLCH4:PROPOSE" + 3 nulls) is already at 13 of 16. A
name needing more than 10 characters after the prefix must be abbreviated, and
**two different concepts abbreviating to the same 10 characters would collide
silently.** Claim the abbreviation from the PMO, not just the concept.

`crates/coherence-core` uses a separate `bloch:coherence:*:v1` domain family
(noted at `params.rs:705-709`) which is deliberately outside the BLCH4 sweep.
Distinct namespace; not tracked here.
