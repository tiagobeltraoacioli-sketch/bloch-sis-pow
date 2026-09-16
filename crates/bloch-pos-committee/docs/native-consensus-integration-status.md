# Native DEX and bridge consensus integration status

## Current boundary

Updated against the local `codex/native-wallet-integration` implementation through
`5bda798`. These are implementation references, not a claim that this revision is
pushed or deployed publicly. All six production native activation epochs remain
`u64::MAX`; no public native activation or custody configuration is selected.

`CommittedState` owns an optional nonrecursive `NativeState`. The real
`Transition::apply_block` executes sponsored native operations in the ordinary
ordered block loop, preserving proposer, signature, RANDAO, attestation, fee and
final state-root checks. State SMT tag `0x1F` binds the native commitment; absence
preserves historical roots. The native commitment excludes the base root and must
not be confused with a rehearsal journal root, canonical state root or block ID.

Canonical wire assignments are implemented and registered:

| Tag | Operation | Adapter |
| --- | --- | --- |
| `0x0E` | Sponsored native transfer | `native_dex/consensus_transfer.rs` |
| `0x0F` | Zero-supply asset registration and route enablement | `native_dex/bootstrap.rs` |
| `0x10` | Federated gateway import | `native_dex/consensus_gateway.rs` |
| `0x11` | Federated gateway withdrawal | `native_dex/consensus_gateway.rs` |
| `0x12` | Native/BLCH pool lifecycle and swaps | `native_dex/consensus_pool.rs` |

Each frame is bounded, domain-bound and separately gated. Staged execution
commits both ledgers atomically, counts the outer framing bytes and sends fees
through ordinary block settlement once. Canonical native fee escrow remains zero.
Ordinary spends also enforce native custody locks. Imports use configured issuer
and committee attestations; they do not independently prove source-chain finality.
Withdrawals record burns/releases; those records do not themselves pay a source
recipient.

The separate explicit `native-lab` build and `BPOSLAB1` manifest opt into one
laboratory transition domain. Official manifests cannot be activated with the
laboratory flag. Laboratory mempool admission checks authorization, pricing,
conflicts and current state using the real executors, admits only one pending
native operation, and revalidates after head changes. Official network admission
remains disabled. See [node laboratory contract](../../bloch-pos-node/NATIVE-LAB.md).

## Completed persistence and wallet integration

The [snapshot format](native-component-snapshot.md) deterministically serializes
bounded populated state and validates all commitments and derived custody indexes
against the matching base projection. Snapshots do not import an arbitrary funded
ledger into consensus. Node sidecars are checked after complete canonical replay;
accelerated base-state checkpoint restart remains unimplemented and is not required
for the existing replay-based restart path.

Canonical tests cover populated restoration, wire replay, fork ancestors,
corruptions, rejected blocks and historical roots. Node reorg validation stages
branch transaction-index publication until the entire replacement branch passes.
Real laboratory process runs exercised signed bootstrap/import/withdrawal,
persistence, restart and replay refusal. See
`transition/native_snapshot_replay_tests.rs`, `native_bootstrap_blocks_tests.rs`,
`native_gateway_blocks_tests.rs`, `native_pool_blocks_tests.rs` and node
`engine/native_replay_tests.rs`; source paths are relative to their respective
crate `src` directories.

Bounded laboratory wallet RPCs now expose trusted-host review context, typed pool
quotes/reads and unsigned withdrawal requests. The isolated hybrid WASM signer
reviews actual state and signs typed owner intents; issuer and committee
certification remains a separate step. Browser-signed create, initialize, swaps
in both directions and a certified withdrawal have been included and reported
finalized by the local node. Actual Anvil source deposits/releases were verified
against receipts, vault code/configuration and accounting. These runs use
synthetic assets and disposable local authorities. They do not qualify public
custody or provide independent consensus finality proofs.

## Remaining public integration decisions

The missing public work is not snapshot serialization, canonical gateway dispatch
or a first pool adapter. It is:

1. Select the target native network and coordinate its validator release and
   activation, retaining explicit domain, gate and historical-root invariants.
2. Provision and verify the real source route, deployed vault/token/code, asset,
   caps, issuer/quorum, observation policy, sponsor and protected signing services.
3. Define and authenticate the release-to-native-commitment-to-state-root-to-finalized-
   header proof/trust path. A wallet RPC projection and matching node reports do
   not supply an independent proof. Integrate durable external reconciliation,
   duplicate-payment prevention and source reorg handling with that trust path.
4. Integrate the selected public native account, endpoint and custody workflow
   into the wallet. The loopback laboratory proxy and public test seed are not a
   production account service. Qualify the selected fleet and upgrade boundaries;
   do not reinterpret local test success as public operational readiness.

The constraints below remain review requirements for that rollout. No activation
date, public authority or public source custody address is assigned here.

### Live paths that must agree

| Concern | Existing implementation | Required native integration |
| --- | --- | --- |
| Block execution | `src/transition.rs`: `Transition::compute_post_state`, `StateTransition::apply_block` | Execute native transactions inside the same ordered transaction loop; retain all proposer, RANDAO, signature, attestation and final root checks. |
| State commitment | `CommittedState::compute_root`; `src/state_root.rs` tagged SMT | Commit every native value that can affect future validity, including reserves, release/replay records and accounting. |
| Transaction wire | `PosTransaction::canonical_bytes`, `from_canonical_bytes`; `tests/wire_tag_registry.rs` | Register bounded canonical native variants and preserve existing byte assignments. |
| Header identity | `src/header.rs`: `BlockId::of` | Retain the domain-separated hash of canonical header bytes as the sole block identity. |
| Production | `../bloch-pos-node/src/engine.rs`: `Engine::propose` | Derive the signed root using the same `compute_post_state` as validators. |
| Admission and selection | `Engine::on_transaction`, `select_transactions`, `spent_outpoints`, `evict_stale_mempool` | Recognize native inputs, locks, charges and activation; admission does not substitute for block validation. |
| Wire and persistence | Node `codec.rs`: `encode_envelope`, `decode_envelope`; `engine.rs`: `body_transactions`; `store.rs` | Preserve and decode the complete canonical transaction bodies through gossip and stored-block replay. |
| Forks and replay | `Engine::apply_canonical`, `state_at_canonical`, `replay_to`, `do_reorg` | Restore and execute the complete native state through real `apply_block`, including branches beyond the snapshot ring. |

### State ownership and commitment

The canonical state owns components that do not own a base `CommittedState`.
Populated execution and bounded snapshot restoration are implemented. The separate
rehearsal split/rejoin object's base-root pin is not part of the canonical native
component. Rehearsal constructors reject a base that already owns canonical native
state, and snapshot restoration does not bypass block execution or activation.

The node snapshot ring carries native state in `Arc<CommittedState>`. Durable
restart reconstructs it from stored blocks and validates the optional sidecar.
Any future accelerated checkpoint format must authenticate the complete base and
native state together; the current component codec alone is not that checkpoint.

The dormant implementation uses a tagged native subtree-root leaf. Before
activation, specify and review proof composition from a
release record through the native subtree into the canonical state root, then
into the authenticated header. A signed header alone proves neither valid
execution nor finality. Never replace `BlockId::of` with a candidate digest.

### Wire and coordinated activation decisions

The registry currently assigns `0x0A` to RANDAO recommit, `0x0B` to funded
deposit, `0x0C` to exit V2 and `0x0D` to withdrawal. Historical contested tags
`0x07` through `0x09` remain unavailable. Native assignments require the wire-tag
review process and updates to the exhaustive registry guard, encoder, decoder
and fixtures; an apparently unused byte is not an assignment decision.

Reuse the explicit epoch-gate pattern in `src/params.rs`, including the
`u64::MAX` disabled sentinel and an explicit enabled check. Native transaction
validity and initial native-root inclusion must use the block's committed epoch,
not the wall clock, process flags or an RPC switch. Parsing may recognize the
new encoding before activation while the transition rejects its inclusion.
Default and feature-enabled builds must agree on all historical blocks. Every
validator expected to follow activated blocks must have the required execution
code; a Cargo feature does not coordinate a network upgrade.

Before arming a gate, agree on the transaction encoding, initial state and
network domain, root schema, authority configuration, resource prices, fee and
supply treatment, and any epoch maintenance. Adding even an empty singleton
native-root leaf changes the canonical root: explicitly define its first block
and initialization when slots skip across the activation epoch. No activation
date or parameter value is selected here.

### Ordered execution, empty blocks and accounting

Execute ordinary and native operations in body order against the same state.
Either operation must see UTXOs and reserve locks changed by preceding
operations. Invalid execution rejects the whole block without changing its
parent state. Native charges join the existing gas, byte, base-fee and
priority-fee totals; the existing reward step runs once. The rehearsal fee
escrow cannot also retain fees already burned or credited by live consensus.
Include BLCH reserves in accounted supply exactly once and define wrapped-asset
backing independently of BLCH issuance.

An activated block containing zero native transactions still runs the full
ordinary transition and commits native state. Native components remain unchanged
unless explicitly specified block/epoch maintenance applies. Do not require a
nonempty rehearsal candidate for such a block. Epoch rollover, fee-market
updates, RANDAO and finality still execute normally. Skipped epoch boundaries
must obey the existing bounded boundary walk and deterministic initialization.

### Reorganizations and external settlement

Restore native balances, nullifiers, releases, reserves and counters at the
ancestor before validating the winning branch. `do_reorg` must not publish any
native mutation from a rejected branch. The existing finalized latch remains a
separate protection against forbidden rewinds. Journal or RPC observations must
follow canonical adoption and expose orphaned observations as such.

External payments cannot be undone by restoring `CommittedState`. Settlement
must consume authenticated finality and use durable duplicate-payment protection;
neither the snapshot ring nor a signed-header helper supplies that guarantee.

### Required verification matrix

| Scenario | Required assertion |
| --- | --- |
| Historical replay, default and feature builds | Identical pre-activation acceptance, block IDs and golden state roots. |
| Activation minus one, activation, and skipped boundary | Native inclusion rejected before the gate; initialization and execution agree across producer, validator and restart replay. |
| Empty and ordinary-only blocks after activation | Valid both before and after native activity; ordinary epoch, fee and finality processing continues. |
| Mixed native/ordinary input conflicts | Both orderings reject a second spend or locked-input use; rejected execution preserves the parent. |
| Native gas/byte limits and fees | Caps include native work; fee debits, burns, rewards and reserves satisfy the specified accounting exactly once. |
| Commitment and restoration corruption | Every validity-relevant field is bound; duplicate records, inconsistent indexes and incorrect roots are rejected. |
| Two independent nodes and restart | Identical complete state, roots and IDs from the same stored block sequence. |
| Reorg inside and beyond the snapshot ring | Ancestor restoration plus winning-branch execution equals replay from genesis; rejected branches leak no state. |
| Finality disagreement and forbidden rewind | Finalized-latch behavior remains intact; external settlement cannot treat an unfinalized release as final. |
| Malformed block and header | Real `apply_block` rejects invalid proposer, signature, RANDAO, attestations, body root and state root even if a rehearsal binding helper accepts its narrower input. |

## Launch is not only liquidity

Public native pools and real source deposits remain disabled. Public release
requires verified deployed source vaults, configured bridge authorities and
custody, current native/source evidence, durable settlement and end-to-end tests
with the wallet/DEX. BTC, SOL and EVM assets need their own validated custody and
finality paths; the six-decimal stablecoin observer is not a generic substitute.
The b-prefixed asset naming and visible market catalog do not establish backing.
