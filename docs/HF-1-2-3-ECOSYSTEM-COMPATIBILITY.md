# Hard forks 1, 2 and 3: compatibility of everything around the node

Status: **readiness analysis, nothing armed.** Written 2026-10-20 against the
mainnet release `b4a21fb6` and the HF branches as they stood that afternoon
(`codex/hf1-*`, `codex/hf2-*`, `codex/hf3-*-20261020`). Epochs are the
**PLANNED** values of `docs/HARD-FORKS-1-2-3-ACTIVATION.md`
(`codex/hf-schedule-20261020`, `fc877d56`). They are binding only once they
appear in the armed release commit.

Scope: the historical indexer, the wallet, the explorer and its RPC gateway,
and the two exchanges (Coinstore, P2B) that send plain L1 transfers over RPC.
The node itself is covered by the HF branches.

## 1. What each fork changes, seen from outside the node

| Fork (PLANNED epoch) | Gate constant(s) on the HF branch | New tx kinds | RPC changes | Signature / key changes |
| --- | --- | --- | --- | --- |
| **HF1** (E1 = 6460) | `HF1_CLAIM_FINALITY_EPOCH`, `HF1_FROZEN_FINALITY_SET_EPOCH` (`codex/hf1-core-20261020`); conditional `HF1_OWN_TARGET_VOTES_EPOCH` (`codex/hf1-owntarget-20261020`) | none | `getl2settlement`: adds `finalized_checkpoint {epoch, root, own_root, own_chain_rule_active}`, `claimable`, `claimable_large`; each root's `finalized` now means "finalized on this chain's own checkpoint". `matured`/`matured_large` keep their shape but mean "delay elapsed" only | none |
| **HF2** (E2 = 6550) | `SIG_CANONICAL_ACTIVATION_EPOCH` (`codex/hf2-sigdet-20261020`); `HF2_SLASHING_V2_EPOCH` = `NATIVE_SLASHING_ACTIVATION_EPOCH` (relay policy only, `codex/hf2-slashing-20261020`); conditional `HF2_GROWTH_CAP_EPOCH` (`codex/hf2-growthcap-20261020`) | none | none in `rpc.rs`. The upgraded node's mempool refuses non-canonical signature encodings **before** E2 (relay policy) | **From E2 every signature in a block, transfer witnesses included, must be v2 `Bound`.** v1 (`crypto::sign`) signatures become invalid, v2 (`crypto::sign_bound`) is invalid before E2. Hard switch, wallet-facing |
| **HF3** (E3 = 6562) | `HF3_SLH_SUITE_EPOCH` (`codex/hf3-slhdsa-20261020`); `HF3_PQ_MIGRATION_EPOCH` and `LATTICE_EMERGENCY_ACTIVATION_EPOCH` (`codex/hf3-tags-20261020`) | `0x18` `withdrawal_credential_rotation`, `0x19` `pq_rescue_commit`, `0x1A` `pq_rescue_reveal` (the last two only at the separate lattice-emergency gate) | `sendrawtransaction` admits the new tags after their gates; refusal texts name the tags | Optional suite `0x0003` (SLH-DSA-SHAKE-128s + Falcon-1024) for **spend witnesses only**; about 15x the verify gas of `0x0002` (1,067,610 vs 72,748) |
| KES (not in HF3 per the schedule) | `KES_REGISTRATION_EPOCH`, `KES_ACTIVATION_EPOCH` (`codex/hf3-kes-20261020`) | `0x17` `kes_register` | new `getkes` | validator keys only |
| Node-only release (rides along) | none | none | new `getfinalitycertificate` (`codex/hf-node-only-20261020`) | none |

`getchaininfo`, `getbalance`, `listunspent`/`getutxos`, `gettxout`,
`gettxstatus`, `getblockbyslot`/`getblockbyid` and `sendrawtransaction`
keep their request and response shapes in every HF branch (checked by diffing
`crates/bloch-pos-node/src/rpc.rs` against `b4a21fb6`).

## 2. Compatibility matrix

Legend: **OK** works unchanged · **REBUILD** must run a binary built from the
armed release, deployed before E1 · **CODE** needs the change on the named
branch · **BLOCKER** open defect that breaks at activation.

| Component | HF1 | HF2 | HF3 | Branch with the work |
| --- | --- | --- | --- | --- |
| Historical indexer (`tools/bloch-indexer`) | REBUILD (state root changes at E1; an old build halts there, exactly as at the L2 fork) | REBUILD + CODE: `ArchiveVerifier::verify_with_key_under` (already on `codex/hf2-sigdet-20261020`) | REBUILD + CODE: `ArchiveVerifier::verify_spend_at_epoch` (**missing on `codex/hf3-slhdsa-20261020`**, fixed on `codex/indexer-hf3-slh-verifier-20261020`); PQ tx ledger effects (`codex/indexer-hf3-pq-20261020`) | `codex/indexer-hf-ready-20261020` (base for all) |
| Wallet (`postern-wallet`, `bloch-crypto::wallet`) | OK | **BLOCKER**: every wallet path still signs v1 with `crypto::sign`; nothing switches to `sign_bound` at E2 | CODE: suite `0x0003` keys (p9c), 0x18/0x19/0x1A builders, per-suite fee estimate | `codex/hf-wallet-20261020` |
| Exchange signer (reference WASM signing core / custom tooling) | OK | **BLOCKER**: must sign `Bound` from E2 and v1 before it; no released tool does this yet | OK (plain transfers unaffected; `0x0003` is opt-in) | none yet (see §5) |
| Explorer UI (`bloch-explorer`) | OK | OK | CODE: labels for 0x17-0x1A; `pq_rescue_reveal` counts as value-conserving | `codex/hf-explorer-20261020` |
| Explorer RPC gateway (`gateway/worker.js`, `/g4rpc`) | OK (`getl2settlement` is not exposed) | OK | OK (`sendrawtransaction` is forwarded unchanged) | `getfinalitycertificate` already on `codex/bloch-p4b-certconsumers-20261019` (`104230a`) |
| Explorer indexer proxy (`functions/indexer`) | OK | OK | OK | `/indexer/status` and `/indexer/consensus` allowed on `codex/hf-explorer-20261020`, so a halt is visible |
| Explorer fee page (`src/lib/fees.ts`) | OK | OK | CODE later: per-suite verify gas must be ported together with the Rust `explorer_fee_surface` test (no change made: the port is test-bound) | none |
| L2 / bridge tools reading `getl2settlement` | CODE: read `claimable`, not `matured`; check `own_root == root` | OK | OK | covered by the HF1 claim-finality notice |
| Exchange node (Coinstore, P2B) | REBUILD (mandatory node upgrade; an old node stops following at E1) | REBUILD | REBUILD | release |

## 3. Historical indexer

**Why it broke at the L2 fork.** The indexer replays every block through
the linked consensus crate and checks the state root. The deployed binary
predated the release that armed epoch 5850, so every replay from that epoch
ended in "replayed state root mismatch", the process exited and the API
stayed down (fixed by `4828d4aa`). HF1, HF2 and HF3 each change the state root
or the signature rules, so an indexer built from `b4a21fb6` halts at E1.

**What it must learn.**

| Item | Ledger effect | Needed in the indexer |
| --- | --- | --- |
| HF1 claim finality, frozen finality set, own-target votes | state root only | rebuild. `attested_target` counts *included* votes; after own-target a foreign-target vote is included but not counted by FFG |
| HF2 canonical / Bound signatures | none | `ArchiveVerifier` must forward `verify_with_key_under` (the trait default silently keeps the v1 rule). Done on `codex/hf2-sigdet-20261020` |
| HF2 slashing v2 (P5a) | none (relay policy) | nothing. Evidence stays tag `0x05` |
| HF2 growth cap | none | rebuild |
| HF3 suite `0x0003` | none (script hashes are suite-agnostic) | `ArchiveVerifier` must override `verify_spend_at_epoch` (trait default is fail-closed for `0x0003`). **Missing on `codex/hf3-slhdsa-20261020`**; without it the first `0x0003` spend halts the index. Fixed: `ca3d9999` on `codex/indexer-hf3-slh-verifier-20261020` |
| `0x18` WithdrawalCredentialRotation | none; it redirects a later `Withdraw` payout, which the index already takes from the replay receipt | kind name |
| `0x19` RescueCommit | none, fee-free | kind name |
| `0x1A` RescueReveal | **spends every output of one key and creates one output at vout 0** | inputs and one receipt output. The old `_ => 0` arms would have left swept coins spendable in the index and lost the new output. Done: `2192e1ae` on `codex/indexer-hf3-pq-20261020` |
| `0x17` KesRegister (if KES ships) | none | kind name only; `verify_kes` has a usable trait default |
| KesRotate (proposed) | none | kind name. **Tag conflict**: `docs/KES-MAINNET-READINESS.md` proposes `0x18`, which is `WithdrawalCredentialRotation`. Next free tag is `0x1B` |

**Hardening so it does not break silently again** (`f52d7b34` on
`codex/indexer-hf-ready-20261020`, based on `4828d4aa`):

- A block the build cannot apply halts the index at the previous height.
  `serve` keeps running; `/status` (always 200) shows `serving`, `sync_error`
  and `halt {height, slot, epoch, block_id, reason}` with a rebuild hint; data
  routes answer 503. No rebuild-from-genesis loop on a deterministic failure.
- `bloch-indexer gates`, `/consensus` and `/status` show every activation
  gate compiled in plus a `gate_digest` and `build_commit`. Check them against
  the release notes before E1.
- `tests/consensus_gates.rs` fails when `params.rs` gains any
  `pub const *_EPOCH: u64` not listed in `src/consensus.rs`. All HF gates
  (`HF1_*`, `HF2_*`, `HF3_*`, `SIG_CANONICAL_*`, `KES_*`) trip it on merge,
  which is intended: the merger adds them and reviews the ledger effects.
- Per-block ledger cross-check (live-output count against consensus, O(1)) and
  a check that no transaction creates outputs past its modelled bound.
- `transfer_parts` and `created_output_bound` have no wildcard arms.
- Tested: 27 unit tests; a replay of the first 1,984 mainnet blocks from a
  local archival copy with the cross-check on.

**Integration order for the HF release:** merge `codex/indexer-hf-ready-20261020`
into the release branch, then cherry-pick `2192e1ae` (PQ kinds; built on the
`61ac024d` tag allocation, same variants as `codex/hf3-tags-20261020`) and
`ca3d9999` (HF3 spend verifier), then list the new gates in
`src/consensus.rs` until `cargo test -p bloch-indexer` passes. Build with
`BLOCH_INDEXER_GIT_COMMIT=$(git rev-parse HEAD)`. Deploy and finish the replay
(about 30 min) before E1.

## 4. Wallet

On `codex/hf-wallet-20261020` (`fe28c098`, on top of p9c `7a241401` plus the
tag allocation and the P9f fee policy):

- `rotate-credential` (0x18), `rescue-commit` (0x19), `rescue-reveal` (0x1A)
  build and sign through the consensus crate's own encoders, decode their own
  output back, never broadcast, and print whether the gate is armed in the
  build.
- `fee-estimate` prices `0x0003` witnesses (1,067,610 verify gas each).
- Tests: `bloch-crypto` lib 275 passed; committee `pq_migration`/`fee_market`
  43 passed; `wire_tag_registry` 11 passed.

Open:

1. **HF2 Bound signing is not in any wallet.** `crypto::sign` (v1) is used by
   `wallet/mod.rs`, `wallet/cli.rs` and the node's transfer builders. On
   `codex/hf2-sigdet-20261020` only the validator key signs by policy
   (`keys.rs`). Before E2 the wallet needs a policy switch keyed to the
   **inclusion** epoch (v1 below E2, `sign_bound` from E2). This is a release
   blocker for HF2: schedule check H2.3 assumes the wallet does it already.
2. **Suite `0x0003` vs Bound.** `sign_bound` has no `0x0003` form. If HF2
   makes `Bound` mandatory for every signature from E2 and HF3 opens `0x0003`
   at E3, it must be decided whether `verify_spend_at_epoch` judges `0x0003`
   outside the Bound policy. Otherwise no `0x0003` spend can ever be valid.
   (For `codex/hf23-review-20261020`.)
3. The node's `HybridVerifier::verify_with_key` refuses `0x0003` at every
   epoch, so the rotation's `new_key_signature` (checked through
   `verify_with_key`) can never pass, even after the gate. The spend path is
   fine (`verify_spend_at_epoch`).
4. The rotation is charged as two hybrid verifications (2 x 72,748 gas), but
   one signature is SLH (1,067,610). It is underpriced.
5. No production `TransferV2` builder with external signing exists. A
   `0x0003` spend today goes through V1 (`submit-tx` plus cold signing) with
   a larger `--tx-bytes`. `0x0003` keys cannot fund `FundedDeposit`,
   `FundedDelegate` or the L2 txs (exact 3,749-byte hybrid key required).

## 5. Exchanges (Coinstore, P2B)

They run their own node, read `getchaininfo` / `listunspent` / `gettxstatus`
and send pre-signed plain transfers with `sendrawtransaction`.

| | HF1 (E1) | HF2 (E2) | HF3 (E3) |
| --- | --- | --- | --- |
| Node | **mandatory upgrade** by T-24 h; an old node stops following at E1 and stops crediting (no fund risk if they credit only finalized deposits) | same binary | same binary |
| Deposits (crediting) | unchanged RPC; keep crediting only on own-node finality; optional switch to `getfinalitycertificate` | unchanged | unchanged. Deposits from `0x0003` senders look like any other transfer (outputs are script hashes) |
| Withdrawals (signing) | unchanged | **breaking**: from E2 only `Bound` (v2) signatures are valid; before E2 only v1. Pre-signed, unbroadcast withdrawals become invalid at E2. Upgraded nodes already refuse non-canonical encodings at the mempool before E2 | unchanged (they keep `0x0002` keys; `0x0003` is opt-in and 15x more expensive) |
| Fees | unchanged | unchanged | unchanged for `0x0002` |
| Addresses | unchanged | unchanged | unchanged; `0x0003` addresses are still 32-byte script hashes |
| Operational | pause deposits/withdrawals from E1-2 until the HF1 all-clear | pause from E2-2 until the HF2/HF3 all-clear; re-sign anything pending; confirm signer upgrade in writing (go/no-go H2.2) | covered by the HF2 pause |

**Exchange blocker:** there is no released signer that switches to `Bound`
at E2 (see §4.1). The exchange email (schedule Appendix C) asks them to
upgrade "signing tooling", but there is nothing to upgrade to yet. Either
ship a signer (and the WASM signing core the integration guide refers to)
with an epoch-keyed policy before the T-24 h deadline, or keep
`SIG_CANONICAL_ACTIVATION_EPOCH` inert and move it out of this weekend's
HF2.

## 6. Explorer and gateway

`codex/hf-explorer-20261020` (`291420f`, based on `104230a`):

- `src/lib/txKinds.ts`: one label table for every kind the indexer and node
  name, including `kes_register`, `withdrawal_credential_rotation`,
  `pq_rescue_commit`, `pq_rescue_reveal`. An `unknown_0xNN` kind reads
  "indexer predates this transaction type".
- `pq_rescue_reveal` joins the receipt conservation check (inputs = output +
  fee). L2 deposits and claims stay excluded (escrow).
- Labels used on the transaction page, flow card, tables and intelligence
  view.
- `/indexer/status` and `/indexer/consensus` pass through the read-only proxy.
- Not run: `tsc`, build and tests (no Node.js on the authoring machine). Run
  `npm run build && npm test` before merging.

The gateway needs no change for HF1 to HF3. Its surface
(`edge/surface.js`) does not expose `getl2settlement` or `getkes`, and
`sendrawtransaction` is forwarded verbatim. If public `getkes` is wanted
later, add it to `edge/surface.js` with a `head` cache class.

## 7. Release checklist additions

1. Indexer built from the armed release, `bloch-indexer gates` matches the
   armed epochs, replay finished, `/status` `serving: true`, before E1.
2. Wallet and exchange signer switch to `Bound` at E2 (blocker, §4.1/§5),
   or `SIG_CANONICAL_ACTIVATION_EPOCH` stays inert.
3. Decide `0x0003` under the Bound policy (§4.2) before arming
   `HF3_SLH_SUITE_EPOCH`.
4. Re-allocate KesRotate to `0x1B` before any KES code uses it.
5. After each gate: `/indexer/status` shows the tip past the gate and
   `halt: null`.
