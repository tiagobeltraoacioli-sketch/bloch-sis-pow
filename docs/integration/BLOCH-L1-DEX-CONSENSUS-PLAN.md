# Genesis-4 native DEX consensus integration plan

Status: design only, 2026-09-14. No activation height, epoch, live transaction
format or live state commitment is changed by this document. The native Ustav,
USDT gateway and pair components are reference building blocks. They currently
cannot spend live BLCH or create a live BLCH/USDT market.

Implementation progress: bounded gateway transport is implemented. TransferV2
now uses a private validated plan whose exclusive borrow prevents intervening
state mutation and whose consuming commit preserves the existing validation,
fees and output construction. The Supply-only native-token pool reference now
has sealed reserve locks, PQ-owned LP positions and complete state restoration.
It still rejects base BLCH. These changes do not add a live native transaction,
state-root component, fee class or activation rule; the remaining slices below
are not implied by successful reference tests.

An explicit default-off `native-dex-rehearsal` feature now combines the real
BLCH validation plan with a bounded native transfer plan, common authorization,
full-payload fees and a separately committed fee escrow. It does not add a
live block transaction. The same concrete State now owns paired BLCH/native
reserve locks, with atomic creation and same-owner closing; AMM/LP rules remain
open. Read-only native views and opaque full-state snapshots prevent extracting
an executable component through the public rehearsal API. See the
[joint rehearsal contract](BLOCH-JOINT-NATIVE-REHEARSAL.md) for its unit conversion,
trust boundary and remaining block integration. Pool operations also have a
bounded native wire dispatcher; this is not a network activation.

## Actual ownership and integration boundary

Genesis-4 is the live PoS chain. Base BLCH is held in the private eUTXO set of
`CommittedState`, not in the Ustav registered-asset ledger. An `EutxoEntry`
contains `(txid, vout, value, script_hash)` with BLCH amounts in satoshis;
see `crates/bloch-pos-committee/src/state_root.rs:1056` and
`crates/bloch-pos-committee/src/transition.rs:1466`.

Consensus transactions are `PosTransaction` (`transition.rs:306`). The existing
`Transfer` and `TransferV2` paths resolve inputs against committed state, check
the owner's SHA3 public-key commitment, derive fees, enforce exact BLCH value
conservation, verify PQ signatures, and only then consume/create UTXOs. For the
V2 implementation, see `transition.rs:4174–4267`. The legacy 20-byte commitment
compatibility rule is centralized in `owns` (`transition.rs:2118`); new pair
code must reuse ownership validation rather than introducing another address
interpretation.

`CommittedState::apply_transaction` (`transition.rs:3352`) is the authoritative
transaction dispatch boundary. `Transition::compute_post_state`
(`transition.rs:5440`) applies all transactions and accumulates transaction gas,
bytes and BLCH fees (`transition.rs:5803`). `Engine::apply_canonical`
(`crates/bloch-pos-node/src/engine.rs:3228`) installs the whole returned state
and retains a snapshot for reorganization. This is the appropriate atomic
boundary for BLCH plus native-token state.

The live verifier is `HybridVerifier::verify_with_key`
(`crates/bloch-pos-node/src/keys.rs:1130`), backed by `bloch-crypto`. Ustav's
`bloch-ustav::BlochVerifier` supplies explicit PQ key admission as well as hybrid
signature verification. A production adapter must preserve both requirements;
never use the producer's permissive `ProbeVerifier` as token or pair authority.

## Proposed committed state

Add a versioned native subsystem owned by `CommittedState`, with no public
mutable balance access. Suggested fields are:

- `native_gateway: Option<GatewayLedger>`: its inner native registrations,
  supplies, mint nonces, policy revisions and UTXOs; immutable bridge routes,
  committee policies, deposit/event replay records, releases and route totals.
- `native_pool_state`: ordered pool IDs and authenticated pool records, when
  the AMM slice is implemented. A record binds its two assets, fee parameters,
  LP supply/policy, reserves and continuation nonce or state outpoint.
- `native_protocol_version`: fixed by consensus activation rules. It is not a
  user-supplied request setting or mutable RPC option.

Do not store a second independently writable copy of Ustav state outside the
gateway. Gateway-protected supply must remain reachable only through its
issuer-plus-committee import/withdraw operations. Ordinary token transfers and
pair settlements remain owner-authorized.

Commit the complete native subsystem under a newly allocated, versioned state
component tag. The existing tags and fold live in
`crates/bloch-pos-committee/src/state_root.rs:132` and
`CommittedState::compute_root` (`transition.rs:2594`). Do not repurpose the
existing EVM commitment or a spare field of a BLCH UTXO. Reserve the actual tag
only after checking all existing allocations.

Before activation, add **zero leaves** for the subsystem and preserve every
historical root byte-for-byte. At activation, initialize deterministic empty
state under a domain derived from the authenticated genesis/network identity;
commit its versioned root from that point onward. Adding an empty-root leaf
before activation would still change history and is forbidden. Gateway roots
already commit native supply and replay accounting together. If AMM reserves
are a separate component, the outer root must commit both components.

## Canonical operations and joint authorization

Allocate new `PosTransaction` variant(s) and explicit unused codec tag(s) for
native operations. Extend `canonical_bytes` and `from_canonical_bytes`
(`transition.rs:826,1010`) together; body-root calculation must cover the exact
bounded envelope including witnesses. Do not reinterpret existing Transfer/V2
bytes or change their transaction IDs.

Native registration, route enablement, gateway import/withdraw, ordinary
native transfer, native/native pair and BLCH/native pair require explicit
operation discrimination. Existing pair and gateway wire codecs can supply
bounded payloads, but embedding them does not automatically make them
consensus transactions. Reject unknown versions/opcodes, trailing bytes,
noncanonical ordering, oversized lengths and duplicate inputs before expensive
cryptography. Apply byte limits before network buffering as well as decoding.

The BLCH/native pair envelope contains:

1. The network domain, protocol version, expiry and pair identity.
2. One base-BLCH transfer intent: existing outpoints, owner witness keys,
   outputs/change and explicit fee budget terms.
3. One zero-delta native-token transfer, with its policy revision, expiry,
   outpoints, outputs/change and complete owner/module witnesses.

All input owners and applicable authorities sign one domain-separated digest
binding both exact legs and the fee terms. A scoped verifier can translate only
the expected individual-leg digest to that joint digest inside the dedicated
pair operation. It must not accept standalone-leg signatures as a fallback,
and must not alter verification of proposals, attestations or unrelated
transactions. Standalone dispatch must reject the joint signatures.

The existing base signing function `checked_signing_root`
(`transition.rs:771`) has its own currently inert network-binding activation
gate. New native pair signatures must always explicitly bind the authenticated
network domain, independent of whether that older gate is active. Do not arm
or redefine that gate as a side effect of adding DEX support.

## BLCH settlement without synthetic backing

First extract bounded validation/planning helpers from the existing BLCH
transfer implementation inside the consensus crate. They must retain real
UTXO lookup, `owns`, PQ verification, output collision checks, fee calculation
and conservation. Return a private validated change set; do not expose a
balance setter or an unverified public commit function.

The pair dispatcher validates both legs against the same pre-state, stages
both change sets, checks all aggregate resource limits, then commits both or
neither. BLCH conservation remains `inputs = outputs + base fee + priority fee`.
The native leg conserves its registered asset independently. USDT uses six
decimal units; BLCH fees use the chain's native satoshi accounting. No decimal
conversion, oracle or fixed exchange rate is implied by the pair.

Do not register the all-zero BLCH asset ID as an issuable Ustav token, mint
BLCH balances from an RPC response, trust client-supplied prior balances, or
introduce an operator-controlled escrow key to impersonate contract ownership.
The underlying base UTXOs, including their ownership and consumption, must be
inside the same consensus transition.

## Fee and resource integration

Extend the consensus fee class with deterministic costs for the complete
native operation: decoding, admitted PQ key/signature work, native execution,
state writes and bounded replay-record growth. Include all legs and bridge
committee approvals in the same transaction and block budgets. Native reference
gas is not a live-chain fee schedule; calibrate and freeze consensus costs
before activation.

The transaction must pay BLCH fees through authenticated real inputs. A
native-only transfer or gateway import therefore needs an explicit sponsor/fee
leg, signed over the same operation. Reserve fee funds and validate budget
limits before any mutation. Keep existing base-fee burning, priority-fee
rewards, block byte ceilings and total-supply accounting intact. Do not execute
native operations for free by returning a zero `TxCharge`.

## AMM-specific state ownership

Atomic bilateral settlement is the first executable BLCH/native milestone.
Permissionless AMM reserves additionally require authenticated contract-owned
state, which the current fixed public-key-hash BLCH spend condition does not
express. A pure constant-product transition is necessary but insufficient.

Introduce a separately tagged, consensus-defined pool locking condition or a
sealed pool reserve ledger funded by consuming real base/token UTXOs. If BLCH
leaves the ordinary UTXO set into pool accounting, include those reserves in
the chain's global BLCH supply invariant; returning reserves creates outputs
only against an equal authenticated debit. Never count the same reserve in
both the UTXO and pool totals.

A pool identity must bind genesis domain, canonical asset IDs, fee policy and
an unforgeable creation identity. Every update consumes one unique state
identity and creates its sole successor, preventing fabricated reserves,
double settlement and replacement with an unrelated pool sharing validator
code. Validate fees and constant-product bounds against those authenticated
reserves. Add liquidity, swaps and LP burns need exact integer rounding,
minimum-output limits, deadlines, LP conservation and overflow rejection.
Batching additionally requires individually authenticated orders and replay
protection; the existing reference batcher's assumption that orders are
already authenticated is not a consensus rule.

## Replay, storage and trusted snapshots

The node currently persists genesis context and applied block envelopes;
restart replays the transition (`crates/bloch-pos-node/src/store.rs:15`). Extend
block decoding/replay and the reorganization snapshots together. A sidecar DB
whose gateway root is not in the accepted block state root is insufficient:
a reorg could otherwise consume a BLCH leg while restoring the USDT leg, or
forget that a source deposit was already imported.

`GatewayLedger::restore` requires the complete gateway snapshot and a trusted
expected gateway root. It checks native roots, route liabilities, mint counts,
source-event uniqueness and release nonces. It does **not** establish that the
expected root came from consensus. A production snapshot importer must obtain
that root through the accepted block state commitment, a verified component
proof and an authenticated finalized/checkpoint chain context. Do not trust a
root supplied beside the snapshot by the same untrusted peer. Do not restore
only `snapshot.native` and discard route accounting.

Historical roots must remain valid under the old fold. Post-activation snapshot
versions and component proofs must bind the newly committed subsystem. Rollback
must restore native balances, pool reserves, imported events and releases as
one state. External release relayers must wait for the chosen native finality
policy before executing irreversible source-chain payments. PQ committee
attestation remains federated source-chain trust, not a source light-client
proof. A block reorg cannot undo a release already paid externally.

## Ordered implementation slices

1. **Transport and deterministic fixtures.** Finish bounded native/gateway wire
   codecs and cross-language source-vault identity vectors. This is useful now
   and does not alter live consensus.
2. **Private validation plans.** Extract BLCH transfer validation/commit helpers
   with historical-transfer regression tests; introduce no new public mutation
   authority. Keep old signatures, IDs, fees and accept/reject behavior identical.
3. **Inert native consensus variant.** Introduce versioned codec, explicit
   operation types, native state ownership and root component behind a
   coordinated-epoch gate pinned inactive. Preserve historical roots and reject
   new operations below activation. Decide dependency factoring explicitly:
   `bloch-pos-committee/Cargo.toml` currently admits only `sha3` at runtime; do not
   silently pull an experimental VM and crypto host into the live core.
4. **Atomic BLCH/native settlement in rehearsal.** Combine private real-BLCH
   plans with gateway/native zero-delta plans and mandatory BLCH fee funding.
   Prove joint signatures, ownership, conservation, replay and all-or-nothing
   behavior through the actual block transition.
5. **Node parity.** Extend `body_transactions` (`engine.rs:470`), mempool admission
   (`engine.rs:5554`), producer post-state calculation (`engine.rs:1948`), block
   application and restart/reorg paths. Every accepted block must be revalidated
   with the production verifier regardless of producer preview behavior.
6. **Pool ownership and AMM.** Add committed reserve custody/continuation and LP
   policies; integrate the pure AMM state machine only after authenticated
   reserve identities exist. Then add matching/batching and indexer/RPC support.
7. **Activation readiness.** Run historical replay identity, boundary-epoch,
   malformed-wire, PQ ownership, double-spend, fee/supply, root/snapshot,
   cross-component rollback and reorg/finality tests. Obtain independent review
   and coordinate all node/wallet/operator versions before choosing an activation
   epoch. No production activation is authorized or performed by this plan.
