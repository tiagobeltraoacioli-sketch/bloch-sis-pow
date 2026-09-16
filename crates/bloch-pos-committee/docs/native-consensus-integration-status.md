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

## Launch is not only liquidity

Pools and real deposits remain disabled. Beyond consensus integration, release
requires verified deployed source vaults, configured bridge authorities and
custody, current native/source evidence, durable settlement and end-to-end tests
with the wallet/DEX. BTC, SOL and EVM assets need their own validated custody and
finality paths; the six-decimal stablecoin observer is not a generic substitute.
The b-prefixed asset naming and visible market catalog do not establish backing.
