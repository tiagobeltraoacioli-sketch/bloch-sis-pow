# Native L2 on the running Genesis-4 mainnet (M8 part 2 → M9)

Status: the activation gate is implemented and **inert**, and the L2 it installs
is **fully capable on a mainnet build** (no cargo feature). Nothing here changes
consensus while `params::L2_SETTLEMENT_ACTIVATION_EPOCH == u64::MAX` and
`l2_settlement::activation_policy()` is `None`.

## The gate

- `params::L2_SETTLEMENT_ACTIVATION_EPOCH` (sentinel `u64::MAX`) and
  `params::l2_settlement_active(epoch)`, same shape as the funded-delegation flag
  day (constant + `*_active(epoch)` + test-only rehearsal switch + "gate is
  inert" test; no runtime override).
- `l2_settlement::activation_policy() -> Option<Activation>`: `None` until the
  mainnet policy is decided. `Activation = { policy, asynchronous, limits }`.
- `l2_settlement::activation_for(network)`: the pinned activation if it names
  this network's admission domain (`policy.identities[0]`).
- `CommittedState::close_epoch`: when the new epoch is past the gate and the
  state has no L2, the boundary installs `State::activated(activation)`. The
  first block of that epoch is the L2's native height 1.

Before the gate a network has no L2 state: the L2 state component
(`TAG_L2_SETTLEMENT`, 0x21) is absent from the state root, historical roots are
unchanged, and every L2 transaction (0x12–0x16) is refused with `NotActive`.

## Mainnet capability (M9 core) — done, inert

What an installed L2 admits is now its **`Profile`**, fixed at installation and
read by consensus from the state, never from the build:

| | development genesis (BPOSMAN3 manifest) | running-network activation |
| --- | --- | --- |
| deposits (0x14) | `devnet-l2-deposits` | always (async settlement) |
| user-tx settlements V3, DA (0x15), claims (0x16) | `devnet-l2-user-txs` | always |
| attestor set (k-of-n PQ co-signers) | manifest, `devnet-l2-user-txs` | `policy.attestor_set` |
| claims only against FFG-finalized settlements | from `FINALIZED_CLAIMS_FROM_HEIGHT` | from native height 0 |
| withdrawal limits | `withdrawal::Limits::DEVELOPMENT` (the old constants) | `activation.limits` (pinned) |
| committed in the 0x21 leaf | nothing new (devnet roots unchanged) | `ACTIVATED-PROFILE:1` + limits |

`withdrawal::Limits` = small/large delay, large-claim (= attestation) threshold,
retention, release window length, window share (bps) and floor. `Limits::valid()`
enforces `1 ≤ delay ≤ large_delay ≤ retention ≤ 20 160` (one week; bounds the
committed withdrawal section to < 1.1 MiB), `1 ≤ bps ≤ 10 000`, non-zero floor
and threshold. An armed epoch with an invalid activation fails
`armed_l2_gate_has_a_policy`; consensus never installs an invalid one.

Node: the mempool's L2 door (`engine::l2_admission_refusal`) reads the head's
installed profile instead of `cfg!(feature)`; `getl2settlement` reports
`profile {activated, deposits, user_transactions}` and the per-state limits
(`delay_blocks`, `large_*`, `retention_blocks`, `release_window.{blocks,bps,floor_sat}`).

Devnets: an L2 from a genesis manifest keeps `Profile::development()`, whose
values are exactly the previous feature flags and constants, and whose state
bytes carry no profile, so devnet4 replays unchanged (committee suite passes
with and without `devnet-l2-user-txs`).

New tests (`transition/l2_settlement_tests.rs`, all build-independent):

| Test | Pins |
| --- | --- |
| `l2_settlement_gate_is_inert` | sentinel, no policy |
| `armed_l2_gate_has_a_policy` | an armed epoch needs a valid activation that installs a full profile |
| `inert_boundary_keeps_the_state_root` | a pinned activation alone changes nothing |
| `l2_transactions_are_refused_and_roots_unchanged_while_inert` | real blocks across a boundary with an activation pinned: identical post-states and roots; deposit/DA/claim/settlement refused without mutation; a block carrying one is invalid |
| `activation_installs_the_policy_at_the_boundary` | sync/async; root changes only by the L2 leaf; installed once; activated profile |
| `activation_ignores_other_networks` | other domain or unbound network |
| `activation_with_invalid_limits_installs_nothing` | nine invalid limit shapes |
| `activation_never_replaces_existing_l2_state` | devnets keep their L2 and development profile |
| `settlements_are_refused_before_and_admitted_after_activation` | real blocks across the boundary |
| `the_activated_profile_does_not_depend_on_build_features` | profile/limits; dev bytes unchanged; limits committed |
| `activated_l2_deposits_settles_user_transactions_and_pays_claims` | end to end on real blocks: deposit → DA → V3 user-tx settlement (refused without DA) → withdrawals → pinned delay (dev delay is not enough) → `NotFinalized` → finalized claim pays; escrow conserved |
| `activated_l2_enforces_attestors_and_the_pinned_release_window` | pinned large threshold/delay, attestation required, k-of-n, pinned window cap |
| `a_synchronous_activation_settles_but_refuses_deposits_and_claims` | sync mode |
| node `l2_admission_follows_the_installed_profile_not_the_build` | mempool door |

## Mainnet policy (encoded 2026-10-14) — set-once parts unset, inert

`l2_settlement::mainnet` records the policy approved on 2026-10-14:

| Item | Code | Value |
| --- | --- | --- |
| mode | `ASYNCHRONOUS` | `true` |
| attestors | `ATTESTOR_THRESHOLD`, `ATTESTOR_COUNT` | 3-of-5 hybrid (ML-DSA-65 + Falcon-1024) |
| limits | `LIMITS` | small delay 64; large ≥ 100 BLCH (= attestation threshold), delay 2 880; retention 2 880; window 2 880 blocks, 1 000 bps, floor 10 BLCH |
| attestor keys | `ATTESTOR_SET: Option<&str>` | **`None` (unset)** — the `l2-claim attestor-set` file, via `include_str!` |
| program + L2 genesis | `PROGRAM: Option<Program>` | **`None` (unset)** — 7 identities, proof policy, L2 genesis parent/state |

- `mainnet::activation()` builds the `Activation` (chain id 700770, attestor
  set hash of the five keys at k = 3, async, `LIMITS`) and refuses with
  `Incomplete::{AttestorKeysUnset, AttestorSet, ProgramUnset}` while a part is
  missing or the set is not exactly 5 distinct enveloped hybrid keys at threshold 3.
- `activation_policy()` = `mainnet::activation().ok()` → `None` today.
- Consensus guard: `Activation::valid()` now also requires, for an activation
  on chain id 700770, async + a non-zero attestor set + exactly
  `mainnet::LIMITS`. So even an armed gate never installs a mainnet L2 without
  attestors (the boundary installs nothing).
- Pre-activation consensus is unchanged: `activation_policy()` is only read in
  `close_epoch` past the gate (`u64::MAX`), and the policy is `None` anyway.

Tests (`transition/l2_settlement_tests.rs`, build-independent):
`mainnet_policy_records_the_approved_values`,
`mainnet_activation_is_refused_while_attestor_keys_are_unset`,
`mainnet_large_threshold_is_exactly_100_blch`,
`mainnet_release_window_is_10_percent_with_a_10_blch_floor`,
`mainnet_policy_end_to_end_3_of_5_delays_and_window` (real claims on an
activated L2 with the mainnet limits: 63 blocks refused / 64 pay for a claim
just under 100 BLCH; exactly 100 BLCH needs the attestation and 2 880 blocks;
window cap 100 BLCH on 1 000 BLCH escrow; 2 signatures refused, the same
signer twice refused, a non-member set or a non-member signing in a member's
slot refused, the set at another threshold refused, any 3 of 5 and all 5
accepted).

## Attestor keys — script prepared, NOT run

Scheme: `bloch-pos ws-keygen` (hybrid ML-DSA-65 + Falcon-1024, enveloped
3 749-byte public key; the `.sk` is created 0600 and never printed). Script:
`scripts/l2-activation/generate-mainnet-attestor-keys.sh`, output
`~/Desktop/L2-MAINNET-ATESTADORES/` (dir 0700, umask 077, refuses to
overwrite, never reads or prints a `.sk`; optional `--age-recipient` encrypts
each `.sk` and deletes the plaintext).

```
cargo build --release -p bloch-pos-node
# preferred: each operator, on their own (air-gapped) machine
scripts/l2-activation/generate-mainnet-attestor-keys.sh --index I   # I = 0..4
# or, weaker ceremony, all five here (then move each .sk to its operator)
scripts/l2-activation/generate-mainnet-attestor-keys.sh --all
# with attestor-0..4.pk collected: attestors.set + set hash
scripts/l2-activation/generate-mainnet-attestor-keys.sh --assemble
```

Then commit `attestors.set` into the tree and set
`mainnet::ATTESTOR_SET = Some(include_str!(…))` (one reviewed commit; set
once). Operators sign with `bloch-pos l2-claim attest … --key attestor-I.sk`
only roots they rebuilt from the L1 DA batches.

## Historical replay — procedure ready, needs data from the user

Script: `scripts/l2-activation/replay-mainnet-history.sh`.

It replays a **copy** of the Genesis-4 block log from genesis with this build
(`run --replay-from-genesis --stop-at-slot 1 --rpc-port off`, devnet transport
on loopback, no peers), optionally also with the release the fleet runs, and
requires every block to re-apply to its own header's state root (the node
aborts the replay on the first mismatch: "durable block log failed consensus
replay"). It verifies the manifest (SHA-256 `7eef82a7…`) and the carryover
(`84ddbbac…` uncompressed), refuses a candidate built with devnet features, and
isolates the process from the network (`unshare --net` on Linux,
`sandbox-exec` loopback-only profile on macOS). Each run gets a fresh data dir;
the source copy is never modified.

What the user must provide (this agent copied nothing from any host):

1. **A local copy of an ARCHIVAL node's data files, by name**: `blocks.log`,
   `meta.bin`, `ws_latest.bin` (and `blocks.idx` if present). Never a
   validator's directory (`validator.key`), never `.TRAVADO-*`. Candidates per
   the quickstart: the keyless archivals 139.180.166.5 / 139.180.173.231
   (`/home/ubuntu/g4/`). Stop-copy or copy while running and let the replay end
   at the last complete frame.
2. **The expected head**, read at copy time from two archivals that agree
   (`getchaininfo`: slot and state root) → `--expect-slot`, `--expect-root`.
3. **Binaries**: this branch built `cargo build --release -p bloch-pos-node`
   (no features) and, recommended, the release the fleet runs (`--baseline`).
4. **A box**: memory roughly 2.5 × `blocks.log` + 2 GB free (measured 983 MB RSS
   at 448 MB of log, 2026-09-01; the node keeps the canonical chain in RAM),
   disk ≈ 2 × `blocks.log` per run + 60 MB carryover, any core count (replay is
   single-threaded, ≈ 25 blocks/s on 2 vCPU at height 33 k and slowing with
   depth). Check `blocks.log` size first; a 16 GB Mac covers a log up to ~5 GB.

```
scripts/l2-activation/replay-mainnet-history.sh \
  --candidate target/release/bloch-pos --baseline <fleet bloch-pos> \
  --source <local copy dir> --work <new dir> \
  --expect-slot <S> --expect-root <hex>
```

Pass = `VERDICT: PASS` (both binaries reach the same head, slot, height and
state root as the archivals).

## Mixed-fleet qualification — script ready

Script: `scripts/l2-activation/qualify-mixed-fleet.py`; local devnet only
(loopback, plaintext throwaway keys, 1 s slots, the devnet TCP mesh the fleet
runs). Four equal validators: node0
on the baseline release, node1–3 on this branch built as a **rehearsal**
(`--features l2-activation-rehearsal`, `BLOCH_L2_REHEARSAL_ACTIVATION_EPOCH=E`),
plus an optional keyless observer on this branch's normal (inert) build.

The rehearsal feature exists only for this: it sets the gate to the compiled
epoch and installs a placeholder policy bound to whatever devnet runs it; the
node refuses the Genesis-4 manifest and any carryover manifest, and the build
identity carries `+l2-activation-rehearsal-eE`. Shipping builds never enable it.

Asserted: before E all nodes finalize the same checkpoint and every canonical
block below slot 32·E is identical; at the first block of epoch E only the
rehearsal nodes accept it (state root with the 0x21 leaf) and they finalize
epoch E and beyond (3/4 > 2/3); the baseline and the inert observer never accept that
block and finalize nothing at or after E; `getl2settlement` shows
`profile.activated` on rehearsal nodes and `null` on the inert observer.

```
BLOCH_L2_REHEARSAL_ACTIVATION_EPOCH=6 cargo build --release -p bloch-pos-node \
  --features l2-activation-rehearsal --target-dir target/rehearsal
scripts/l2-activation/qualify-mixed-fleet.py --baseline <release bloch-pos> \
  --rehearsal target/rehearsal/release/bloch-pos --inert target/release/bloch-pos \
  --activation-epoch 6 --work <new dir>
```

Result of the local run: see "Results" below.

## Results (2026-10-14, this Mac)

Tests: `bloch-pos-committee` 724 passed / 0 failed (mainnet build), 740 / 0
(`devnet-l2-user-txs`); `bloch-pos-node` 694 / 0 (mainnet build), 634 + 1
(`devnet-l2-user-txs`; `rpc_source_exhaustion_is_retryable_and_leaves_other_source_headroom`
failed once and passed 3/3 on rerun: a wall-slot timing flake in the transfer
budget test, unrelated to L2). The real-Groth16 test stays ignored (fixture).

Mixed fleet, PASS (`--activation-epoch 6 --epochs-after 6`, release builds:
baseline `da136d41`, rehearsal and inert from `45fbc979`):

- before the gate all 5 nodes finalized the same checkpoints; 128 canonical
  blocks below slot 192 identical (id, state root, height) on every node;
- slot 192 block `af538c0c` (native L2 height 1): accepted by the three
  rehearsal nodes; baseline and inert observer log
  `reject af538c0c at slot 192: StateRootMismatch` — the divergence is at the
  first block of the activation epoch, as predicted;
- rehearsal side: identical head, root `67c9b7b7…`, finalized e9, L2 at
  native height 167 with `profile.activated`; baseline and inert: identical to
  each other (root `2407b69c…`), finalized e5, never anything at or after e6;
  `getl2settlement` = null on the inert build.

Replay smoke test (the script's isolated `run` invocation under
`sandbox-exec`, on the devnet logs): the inert mainnet build replays the
baseline chain to the baseline's exact head (151 blocks, root `2407b69c…`), and
refuses the rehearsal chain with "durable block log failed consensus replay"
(its slot-192 root differs) — the per-block root assertion works.

Lesson from the first runs: on libp2p the local nodes ended up attached only
to node0 (a star through the baseline); once node0 stopped relaying
post-gate blocks the rehearsal side was partitioned and finalized nothing.
On mainnet the same can happen if upgraded validators reach each other only
through old-release relays (the bootnodes/archivals are leaves dialled by
validators): **upgrade bootnodes and archivals first, and verify direct
peering among upgraded validators before the epoch.**

### Re-run after the rebase and the policy commit (2026-10-14)

Tree `6529e085` (rebased on `b75fce63`, mainnet policy encoded):
`bloch-pos-committee` 731 / 0 failed (default), 735 / 0 (`local-state-cache`),
751 / 0 (`devnet-l2-user-txs,local-state-cache`) — each +5, the new mainnet
policy tests; `bloch-pos-node` 705 / 0 (one run hit a timing flake in
`build_source_digest_tests::hidden_macro_input_is_hashed`, unrelated, 3/3 and
the full suite rerun green); `cargo build --release -p bloch-pos-node` OK.

Mixed fleet, loopback only, PASS (`--activation-epoch 6 --epochs-after 6`):
baseline = release `b75fce63` (built from `git archive`), rehearsal and inert
from `6529e085`. Pre-gate all 5 nodes finalized the same checkpoints and 128
canonical blocks are identical; rehearsal nodes finalized e9; baseline and inert
observer stayed at e4 (nothing at or after e6), each logging the
`StateRootMismatch` at the first block of the activation epoch.

## What remains before arming

1. ~~**Rebase onto the release the fleet will run.**~~ — done: rebased onto
   `release/mem-fix-eth-leak-20261014` (b75fce63: bounded block memory,
   Ethereum-paced inactivity leak from epoch 5700).
2. **The policy** — decisions approved and encoded 2026-10-14
   (`l2_settlement::mainnet`: async, 3-of-5 attestors, limits, chain id
   700770). Still **unset** (activation refuses until filled):
   - `mainnet::ATTESTOR_SET`: run the key ceremony ("Attestor keys" above),
     assemble `attestors.set`, commit it;
   - `mainnet::PROGRAM`: SP1 program identity (guest ELF, KoalaBear and BN254
     keys, proof policy V3 with user transactions), L2 genesis
     `initial_l2_parent/state` for chain 700770, and identities[0..1] = the
     Genesis-4 admission domain and native genesis. The real-Groth16 fixture
     (`native_l2_real_groth16_applies_in_the_actual_transition_and_replays`,
     ignored) must be regenerated with the SP1 prover for this tree and the
     mainnet program.
3. **Historical replay** (above) — PASS required.
4. **Mixed fleet** (above) — PASS required, on the rebased build.
5. **Operational gaps found while doing this:**
   - ~~the local state cache does not store L2 state~~ — done: the L2
     component is an optional trailing section of the cache payload
     (`BPOSST01:L2:v1`); states without L2 keep their exact bytes, restore
     rechecks the inbox root, escrow conservation and claim count, takes a
     development profile from the build, and the header root check binds the
     rest (`local_cache_carries_l2_state_and_keeps_pre_activation_bytes`,
     `local_cache_restore_rechecks_uncommitted_invariants`);
   - the mempool refuses synchronous settlements (0x12) outright; only the
     async path (0x13) is wired in the node.
6. **L2 node / RPC items raised by the DEX work** (L2 repo, not this tree):
   Ethereum-format blocks served by the RPC without a proxy; `finalized`/`safe`
   tags served by an own node; receipts carrying `from`; `BLOCKHASH` for the
   last 256 blocks; block gas limit ≥ ~4M (router); block timestamps in
   wall-clock seconds (devnet4 does so since block 228).
7. **Coordinated epoch** — only after 2–4 pass and ≥ 2 weeks public notice.
   Set the constant and update `l2_settlement_gate_is_inert` in the same commit
   (`armed_l2_gate_has_a_policy` then requires `mainnet::activation()` to be
   complete); leave time for every
   validator and archival to upgrade (nodes that do not, diverge at the first
   block of that epoch).

## Decisions — approved by the user 2026-10-14

The recommendations were approved as the mainnet L2 policy and are encoded in
`l2_settlement::mainnet` (see "Mainnet policy (encoded)" above).

| Decision | Approved |
| --- | --- |
| Sync or async | **Async** (`mainnet::ASYNCHRONOUS`). Deposits and claims exist only in async; the node only admits async proofs. |
| Chain id | **700770** (`MAINNET_CHAIN_ID`; devnets stay 700771). |
| Attestor set | **3-of-5**, hybrid ML-DSA-65 + Falcon-1024 (the scheme the chain uses for admission keys, weak-subjectivity signers and L2 attestations), five operators on separate hosts, fixed at activation (set-once: no rotation, no periodic signing, no admin; a new set = a new policy). |
| Small-claim delay | **64 blocks** (two epochs), on top of FFG finality. |
| Large threshold / delay | **≥ 100 BLCH**: attestation required and **2 880 blocks**. |
| Retention | 2 880 blocks (= large delay; keeps the committed state small). |
| Release window | **2 880 blocks**, at most **10 % of escrow, floor 10 BLCH**; only an attested first claim of a window may exceed it. |
| Activation epoch | **Not set.** Chosen only after: rebase (done), policy encoded (done, this commit), archival replay of mainnet history PASS, mixed-fleet qualification PASS on the final build, and ≥ 2 weeks public notice with the release on every node. The gate stays `u64::MAX`. |
