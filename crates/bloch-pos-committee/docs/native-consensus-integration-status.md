# Native DEX and bridge consensus integration status

## Current boundary

The native joint execution, PQ authorization, bounded candidate validation and
durable local journal are implemented under opt-in features. Experimental helpers
bind candidates to host-provided block contexts and canonical signed headers.
They do not call the live block transition, authenticate finality, or make their
candidate bodies valid Genesis4 transactions. No production activation is armed.

The live path remains `Transition::apply_block` over `CommittedState`, reached by
the node. The joint rehearsal `State` owns a separate base `CommittedState` plus
native gateway/pool state. Embedding that entire joint State back inside
CommittedState would be recursive and is not an integration strategy.

The opt-in build now gives `CommittedState` direct ownership of an optional
nonrecursive `NativeState`. The real `compute_post_state` initializes an empty
component from nonzero genesis-authenticated network context when the native
state epoch gate is active. That gate remains `u64::MAX` (disabled); only unit
tests can override it. An active gate cannot compile without the implementation
feature. No native transaction, populated rehearsal import or payout is enabled.

State SMT tag `0x1F` is assigned to this domain-separated native commitment;
it is not a transaction wire tag. Absence contributes no leaf and preserves
historical roots. The component excludes the base root, avoiding circular
commitments. The base-only projection remains separate from the complete block
state root. Real-transition tests cover initialization, subsequent empty and
ordinary-transfer blocks, replay, fork ancestor clones and invalid header roots.

The first sponsored native transfer now dispatches from the real ordered block
transaction loop through wire tag `0x0E`, under the separate disabled
`NATIVE_TRANSFER_ACTIVATION_EPOCH`. It conserves an already-issued native asset
while a BLCH sponsor pays the charge. Execution uses the block's fixed base fee,
counts the five outer framing bytes and interprets expiry as the current block
slot (inclusive). A staged adapter commits both ledgers together, returns fees to
the existing burn/reward step and leaves native fee escrow zero. Ordinary V1/V2
spends and funded validator deposits also enforce canonical native reserve locks.
Both sponsor and native-owner witnesses use explicit strict native verifier
capabilities, including during the producer's proposal probe.

There is still no production path to populate the initially empty native ledger:
asset registration, mint/import authority, source proofs and route bootstrap
remain unimplemented in the block path. Block tests install funded fixtures only
under `cfg(test)`. Pool lifecycle, swaps and gateway imports/withdrawals remain
rehearsal operations. Mempool admission for native transfers is deliberately
refused pending authorization, pricing and conflict integration. No funds can be
launched by merely arming the transfer gate.

## Required implementation sequence

1. Ownership, dormant empty-state commitment and a bounded native-component
   snapshot/restore codec are implemented. The [snapshot format](native-component-snapshot.md)
   validates complete component data and reconstructs custody indexes against
   a supplied base projection and trusted component commitment. It is not wired
   to a populated-state import. Optional node sidecar persistence verifies it
   only after full canonical replay; accelerated base-state restart remains
   unimplemented. Complete the remaining execution/accounting integration
   before activation.
2. Extend the registered sponsored-transfer encoding to the remaining operations
   and activate it only at a coordinated,
   explicit network upgrade. Reserve/register tags through the repository's wire
   tag process; do not appropriate historical or contested tags.
3. Extend the sponsored-transfer dispatch to gateway and pool operations. Include
   their fees, gas, supply conservation, reserves and rewards exactly once. Define
   empty-native blocks and epoch-boundary behavior. Use the real proposer,
   RANDAO and attestation validations rather than the rehearsal header helper.
4. Commit the complete state through the canonical state-root derivation and
   preserve a single block identity. Update producer, validator, wire codec,
   storage, replay and snapshots together. Specify inclusion proofs relating a
   release and native state root to an authenticated block.
5. Test deterministic replay on independent nodes, corrupted blocks, forks,
   restart, finality disagreement and upgrade boundaries. Only then deploy a
   coordinated release and arm activation after review.
6. Connect the bridge's native trust source to those authenticated proofs, then
   complete durable settlement, duplicate-payment prevention and source reorg
   handling. Configure operational custody/authorities and supported asset routes.

## Concrete integration contract (proposed, not activated)

Transaction wire tag `0x0E` is now allocated to `NativeTransfer`: one tag byte,
a little-endian u32 length and a nonempty opaque joint-transfer payload. The
complete frame is bounded by `MAX_BLOCK_TX_BYTES` even in feature-disabled
decoders. The payload constructor guarantees transport size, not native semantic
validity; the dispatcher must authenticate its domain and canonical inner frame.
This allocation is not activation. Node mempool admission remains explicitly
disabled until sponsor pricing, authorization and conflict handling are integrated.

The following specifies the remaining integration work. The dormant state leaf
above is implemented and native transfer wire tag `0x0E` is allocated; no active
epoch or production authority is assigned.

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

The canonical state now owns components that do not own a base `CommittedState`.
Only empty initialization and continuity through ordinary blocks are implemented.
The separate opaque split/rejoin object retains its base-root pin for rehearsal;
that pin is not part of the canonical native component. Populated rehearsal state
cannot be imported into canonical state, and rehearsal constructors reject a base
that already owns canonical native state. A bounded component snapshot codec now
validates restoration without attaching state or enabling production imports.
Canonical sponsored-transfer execution is implemented under its disabled gate;
gateway/pool dispatch and an accelerated complete-state restart remain open.

Specify deterministic serialization, allocation limits, restoration checks and
reconstruction of derived lock indexes. The node's existing snapshot ring stores
`Arc<CommittedState>`; native state must travel with that state, not with an
independent journal cursor. Durable restart must reconstruct the same state from
stored blocks. Any new checkpoint/import format must carry and validate all
native components as well.

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

Pools and real deposits remain disabled. Beyond consensus integration, release
requires verified deployed source vaults, configured bridge authorities and
custody, current native/source evidence, durable settlement and end-to-end tests
with the wallet/DEX. BTC, SOL and EVM assets need their own validated custody and
finality paths; the six-decimal stablecoin observer is not a generic substitute.
The b-prefixed asset naming and visible market catalog do not establish backing.
