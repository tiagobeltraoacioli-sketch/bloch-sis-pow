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

## Required implementation sequence

1. Extract native gateway/pool/accounting components from the joint wrapper so
   the canonical state can own them without recursively owning itself. Define
   deterministic serialization, restore validation and bounded resource use.
2. Define the consensus transaction encoding and activate it at a coordinated,
   explicit network upgrade. Reserve/register tags through the repository's wire
   tag process; do not appropriate historical or contested tags.
3. Compose native and ordinary operations in the single block transition. Include
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

The following is an implementation specification for review. It assigns no wire
tag, activation epoch, production authority or approved root format.

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

Extract components that do not own a base `CommittedState`, then make the
canonical state own those components. An opaque split/rejoin object is useful
for rehearsal ownership, but does not by itself implement live execution,
serialization or canonical root inclusion. A component pinned to an earlier
base root cannot simply be rejoined after an ordinary block changes that root;
live execution needs one coherent mutable state and a defined base projection.

Specify deterministic serialization, allocation limits, restoration checks and
reconstruction of derived lock indexes. The node's existing snapshot ring stores
`Arc<CommittedState>`; native state must travel with that state, not with an
independent journal cursor. Durable restart must reconstruct the same state from
stored blocks. Any new checkpoint/import format must carry and validate all
native components as well.

Choose and review either individually tagged native SMT leaves or a tagged
native subtree-root leaf. For the latter, specify proof composition from a
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
