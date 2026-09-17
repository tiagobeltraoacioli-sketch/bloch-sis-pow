# Next Genesis-4 node release — consolidation register

Status: publication paused by the operator. Local inventory dated 16 September
2026; other agents are still working. This is a release-scope review, not a claim
that all branches are integrated, production-qualified, or fully audited.

## Baseline and ownership

The published 14 September node is `58da5ce209acb6e293b3b381dfd826dedb8741fd`,
Linux x86_64, Rust 1.94.1. The restart worktree is based on `5af78a0`, which also
contains the subsequent payout, funding, mempool and indexer work.

The operator reports 40 validators outside their control. Their upgrade timing
cannot be assumed. A maintenance release must demonstrate compatibility with the
published binary. Any new consensus activation requires a separate coordinated
plan; publishing a binary is not evidence that third-party validators installed it.

The [inventory](../audit/reproducers/next-release-inventory-2026-09-16.json)
records branch heads and working-tree activation constants. Dirty worktrees are
in-progress inputs, not release artifacts. No changes were made to other agents'
source files during this review. Agents running in other conversations are not
visible in this conversation's agent roster; the operator identifies the active workstreams as EVM, DEX, bridge and aggregator.
Exact owner/branch mapping and completion status remain pending.

| Workstream | Location / branch | Observed status | Release treatment |
| --- | --- | --- | --- |
| Restart, persistent state, torn log repair | `bloch-node-recovery` / `fix/persisted-restart-recovery` | Implemented; local tests and benchmarks; uncommitted | Include after the remaining gates below |
| Payout CLI and native funding helpers | `bloch-validator-payout` / `feat/offline-validator-payout` | Committed through `5af78a0`; payout CLI has earlier Linux evidence | Include reviewed node CLI changes; package examples/tools explicitly |
| Historical indexer and receipt observer | `bloch-historical-indexer` / `feat/historical-indexer` | Same committed head; separate indexer executable | Preserve consensus identity; deploy indexer independently |
| Monitoring incident correction | `bloch-monday-activation` / `release/validator-activation-20260914` | Read-only monitor at `c113822`; deployment not established | Include operational rollout; no node rebuild inherently required |
| Native assets, gateway, pools, wallet integration | `bloch-native-wallet-integration` / `codex/native-wallet-integration` | Active dirty worktree; dormant canonical operations and separate native snapshot path | Reconcile baseline and finish integration before considering inclusion |
| Main working tree | `bloch-sis-pow` / `main` | Older baseline plus substantial uncommitted work | Do not build a release directly from this mixed working tree |
| Explorer UX and charts | `bloch-explorer` | Already deployed on 16 September; source changes still local | Independent web release; does not require validator replacement |

## Agent handoff: operator-confirmed workstreams

The operator identified EVM, DEX, bridge and aggregator as active agent tasks.
Their current completion and exact branch ownership have not been independently
verified. Consolidate these handoffs before the release scope is frozen:

| Workstream | Handoff needed | Node-release dependency |
| --- | --- | --- |
| EVM | Execution/state-root changes, gas rules, RPC additions, activation policy and historical replay evidence | Required in the combined node only if it changes the deployed execution/consensus path; determine explicitly |
| DEX | BLCH/native reserve custody, pool operations, fees, wire tags, state/reorg/cache coverage | Consensus/storage changes must be integrated together and remain gated until coordinated activation |
| Bridge | Gateway rules, route/nonce replay protection, source finality model, custody/release services and backing evidence | Distinguish node validation changes from independently deployable relayers and contracts |
| Aggregator | Routing/quote logic, required RPC/indexer APIs, signed transaction formats, slippage and fee assumptions | Usually an application/service; include node changes only when a concrete missing API or transaction capability requires them |

For each task, request the final commit, feature flags, migration requirements,
passing tests, remaining blockers and whether old validators still accept the
same blocks. Publishing the implementation and activating its new consensus rules
are distinct steps. Do not infer bridge backing, EVM availability or an active
DEX from a successful node build.

## Blocking findings

### R1 — reconcile consensus history before combining branches

The native integration branch and the main working tree currently retain
`LEAK_RECOVERY_ACTIVATION_EPOCH = 2700` and disabled lifecycle gates. The published
release and restart branch have leak recovery at **2880** and funded admission,
exit, withdrawal, slashing evidence and RANDAO recommit at **2884**.

These are consensus differences, not cosmetic version strings. Existing release
records already document that the 2700 schedule fails to reproduce the adopted
history. A wholesale merge or build from the native branch must not replace the
published schedule. Start integration from the released lineage, preserve its
historical transitions and reconcile changes deliberately. Reconcile removed
qualification tests and release evidence as well as source conflicts.

Acceptance: exact historical block/state-root agreement, active lifecycle gates
unchanged, new gates explicitly disabled unless separately scheduled, and old/new
nodes exchanging and accepting the same blocks in a mixed-version rehearsal.

### R2 — finish the restart contract before freezing it

The current cache is complete for the current `CommittedState`, bound to the
manifest/log/source digest, atomic with a previous generation, and has strict
replay limits. Torn-tail repair and rejected-log-block startup refusal are included.
Remaining work:

- Define a **versioned cache compatibility policy**. Today any change in the
  hashed source tree, even unrelated code/tests, invalidates the cache. Keeping
  this conservative behavior is safe but costly. Cross-build reuse needs an
  explicit schema/semantic compatibility contract and migration tests; do not
  simply remove the source check. Record intentional invalidation in release notes.
- Profile and reduce genesis/carryover reconstruction on cache restores, retaining
  manifest, carryover and state-root verification. The large local fixture spent
  77.02 of 87.44 seconds in this phase. No mainnet RTO follows from that fixture.
- Measure synchronous snapshot stalls, peak RAM and disk use at realistic chain
  length. Every snapshot currently hashes the complete log prefix. Bound that
  cost or qualify it against validator duty timing; a background writer must bind
  an immutable state to the exact durable prefix and survive concurrent reorgs.
- Qualify the 512 MiB limit and failure behavior. Test disk-full, permission errors,
  interrupted rotation, stale previous generations, deep reorg and forced replay.
- Add operator-visible cache age/slot, write failures, recovery mode and replay
  progress to metrics or a stable status surface. Current recovery reporting is
  primarily log messages. Keep liveness distinct from service readiness.

Acceptance: Linux measurements on a current full log and target hardware,
repeated cold/warm process restarts, tail-limit refusal, full-state equivalence
and continued consensus validation, with the release's supported limits stated.

### R3 — integrate native state with recovery if native changes enter this release

The native branch adds `CommittedState.native_state` and a separate
`native-component.bin` sidecar. That sidecar is explicitly checked only after
full canonical replay; it is not a whole-node fast restart mechanism.

The restart codec exhaustively covers the older state layout. Combining the two
requires explicit serialization/restoration of every newly committed native
component, domain, replay record, reserve/custody record and gateway liability.
Do not drop native state or treat the native sidecar as a substitute for BLCH
state. Test full replay, cache restore, subsequent blocks and reorg equivalence
with nonempty native state in the isolated laboratory network.

Native-lab, rehearsal features, new wire tags and dormant activation rules must
be listed in the release feature manifest. A successful reference/laboratory test
does not authorize a live DEX, backed USDT, gateway custody or new activation epoch.
The native workstream's own status document lists external custody/route inputs
and independent review still required.

### R4 — qualify the final Linux artifact, not an earlier local build

The restart evidence is macOS with Rust **1.98.1**; the published release pin is
**1.94.1**. Rebuild and test the integrated commit with the pinned Linux toolchain
and `--locked`. Do not change the toolchain implicitly by building from a directory
where its pin does not apply.

Run the node, committee, crypto/input-boundary and CLI tests required by CI;
include restart/process tests and mixed-version tests. Two existing committee
tests currently expect debug-assertion panics and fail under the release profile:
make their profile expectations explicit while preserving real checks. Do not
report that release-profile run as green or silence unrelated failures.

Freeze a clean commit, exact Cargo features, lockfile, compiler, target and build
recipe. Retain source/binary hashes, `buildinfo`, minimum glibc, matching source
archive and rollback instructions. Use the existing integrity gate; do not claim
cross-builder reproducibility without its measured evidence.

## Changes already available to consolidate

| Change | Evidence | Remaining acceptance |
| --- | --- | --- |
| Avoid re-admitting included transactions; clear winning-branch entries after reorg | `9291668`, engine and lifecycle mempool tests | Mixed-version gossip/reorg regression with final release |
| Offline TransferV2 payout preparation, inspection and signing; minimum relay checks | `43b7bbc`, `c4a61a6` and later verifier tests | Re-run CLI integration on final Linux artifact; do not label full mainnet lifecycle qualified |
| Funding conversion/signature verification and complete public-key export | `dcd8b0e` through `4d23306` | Inventory which are examples or separate wallet binaries; include corresponding tools and tests rather than claiming all are `bloch-pos` commands |
| Read-only receipt observer and historical indexer | `2d4073d`, `5af78a0` | Preserve ordinary transition result, roots and fees; indexer release is independent |
| Restart cache, tail repair, replay budget | Local restart worktree | R2 and R4 above |

## Operational work that does not require another validator binary

- Review the monitor replacement in `c113822`. The 15 September incident record
  attributes validator stops to a monitor acting on RPC timeout or slot gaps.
  The replacement only alerts. Inventory current monitor deployments before any
  change; native signing/slashing/finality protections must remain intact.
- Recheck archival RPC availability, finality freshness and independent observer
  agreement. Earlier 16 September calls returned archival timeouts; this review
  did not establish the live state or the cause. Fixing a proxy/indexer service is
  not automatically a validator-binary change.
- Renew/distribute WS artifacts on their own schedule. The current preparation
  script expires its epoch-1536 checkpoint at **22 September 2026, 08:43:19 UTC**.
  Renewal must not depend on releasing another node executable.
- Align operator and exchange documentation with the selected release. Some
  September 7 documents still say no checkpoint exists and lifecycle is disabled,
  while later release artifacts establish a different baseline. Preserve dated
  historical evidence but clearly identify the current instructions.
- Update installer URLs, checksums and supported modes atomically with publication.
  Preserve the prior release for rollback. Do not overwrite historical artifacts.
- Keep explorer/chart fixes and indexer updates on independent release tracks.

## Proposed release discipline

1. Each agent supplies its branch/commit, exact scope, completion status, test
   evidence, changed consensus/RPC/storage formats, and outstanding dependencies.
   This register is the shared acceptance list; no agent publishes independently.
2. Choose the scope. Recommended: one maintenance release for restart, mempool,
   reviewed exchange tooling and operational status. Native/DEX activation remains
   a separate protocol milestone unless the operator chooses the larger cycle.
3. Integrate only completed changes onto the released lineage. Resolve R1 first;
   resolve R3 if native code is selected. Refresh this inventory after agents finish.
4. Complete the final Linux test matrix and current-history qualification. Rehearse
   compatible old/new nodes, startup without a cache, ordinary cached restarts,
   crash recovery, reorg, upgrades and downgrade/full-replay rollback.
5. Freeze one release candidate. Observe a controlled standby/canary for a proposed
   24–48 hour window, recording finality, RPC readiness, memory, write latency and
   actual recovery times. This is a proposed operational gate, not a completed test.
6. Publish that exact artifact/source/metadata once, then offer a staged operator
   upgrade with clear instructions for the 40 third-party validators. No automatic
   third-party upgrade or simultaneous restart is assumed.
7. Batch later noncritical improvements into the next planned window. Confirmed
   critical security or consensus defects remain exceptions requiring an explicit
   urgent-release assessment, not a promise never to issue a hotfix.

No binary was published, no remote build was started, no validator was restarted,
and no message was sent to external operators during this consolidation review.
