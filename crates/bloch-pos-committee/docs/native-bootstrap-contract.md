# Canonical native bootstrap integration contract

Status: implementation map for the next inactive consensus change, 2026-09-16.
No wire tag, activation epoch, authority, deployment, custody address or real
asset backing is assigned by this document.

## Current boundary

`NativeState` is owned by `CommittedState`; its empty initialization and sponsored
`NativeTransfer` dispatch are separately epoch-gated and disabled. The new native
snapshot codec restores a component against the corresponding base projection
and an independently trusted component commitment. Restoration does not attach a
new ledger, issue an asset, enable an authority or prove block finality.

The canonical transfer can only conserve an existing native asset. The populated
transfer fixtures in `transition/native_snapshot_replay_tests.rs` are test-only
registrations and minting. They exercise actual `apply_block`, signed headers,
RANDAO, wire decoding, fork replay and component restoration, but they are not a
production bootstrap operation.

`bloch-pos-node/src/engine.rs::admissible` still refuses every `NativeTransfer`.
Canonical populated-node restart/reorg qualification therefore remains separate
from the current committee transition tests. Node regression tests verify the
real `Engine::do_reorg` refuses a disabled native suffix without publishing its
valid prefix's state, transaction index or persistent block log.

## First new operation: sponsored registration and route enablement

The minimum bridge bootstrap should register a zero-supply native asset and
configure its source route atomically. It must not mint funds. Existing reusable
entry points are:

- `bloch_euvm::ustav::gateway::GatewayLedger::register(Registration, signature, verifier, gas)`.
- `GatewayLedger::enable(RouteConfig, issuer_signature, approvals, verifier, gas)`.
- The corresponding `PoolLedger::register` and `PoolLedger::enable` wrappers.
- The staged sponsor accounting pattern in
  `transition/native_dex/consensus_transfer.rs::apply_transfer`.

A new bounded, domain-separated payload must bind all of the following in the
outer authorization: registration charter and nonce, complete route configuration,
issuer and committee public keys, sponsor inputs/change, prepaid resource budget,
fee bounds, and inclusive expiry slot. Sponsor, issuer and committee signatures
must authorize this same operation; a standalone route certificate must not be
reusable with a substituted sponsor or registration. The existing scoped-verifier
pattern can bind each inner signing hash to the outer authorization without
weakening signature verification.

The adapter stages both ledgers, registers the asset, checks its derived identity
against the route's `native_asset`, and then enables the route. A failed route
configuration, signature, size check or sponsor debit discards the registration
and every other staged change. The adapter returns the charge to canonical block
fee accounting exactly once and retains zero rehearsal fee escrow.

The existing gateway is deliberately narrow. Its actual validations require:

- A supply-only charter, zero current supply and mint nonce zero at enablement.
- A nonzero source domain distinct from the native domain; asset is not BLCH.
- Nonzero, distinct 20-byte source token/vault addresses and nonzero vault code hash.
- Exactly six decimals, positive route cap within the charter cap.
- At most 32 routes; a unique `(source_domain, vault)` endpoint.
- At most 16 sorted unique valid committee keys, quorum at least two and no larger
  than committee membership; issuer authorization and quorum signatures.

These rules do not constitute source-chain finality verification. They do not
make a route suitable for BTC, SOL or an arbitrary token with another decimal
precision. Symbols such as bUSDT must remain presentation labels rather than
custody or route identities. Which registered routes the wallet can present as
operator-supported requires a reviewed deployment/authority policy, independently
of whether a permissionless charter can be registered in consensus.

## Canonical integration required before bootstrap can be submitted

1. Allocate the variant and byte through `tests/wire_tag_registry.rs`; preserve
   every existing byte assignment and historical body. No next-byte guess is an
   allocation. Add bounded canonical encode/decode and malformed-frame tests.
2. Introduce an explicitly disabled bootstrap gate, ordered after native-state
   ownership. Dispatch by the block's committed epoch, never by wall clock,
   browser configuration, Cargo feature alone or restored snapshot contents.
3. Add staged execution with the block's fixed fee price, including outer-frame
   bytes, all authorization work and declared limits. Keep ordinary/native UTXO
   conflict and reserve-lock checks in body order.
4. Implement node admission, conflict detection, selection, fee estimation and
   stale-entry handling for the specific typed operation. Relay acceptance is
   not a replacement for block validation.
5. Carry the canonical payload unchanged through gossip, stored bodies, replay
   and sidecar/checkpoint validation. Authenticate any imported checkpoint from
   a trusted canonical header before using its component commitment.
6. Add wallet construction and separate review/sign/submit for the exact typed
   operation. A gateway page or asset catalog is not an execution integration.

## Acceptance tests for the next patch

Use the real canonical transition and deterministic, fully signed test inputs.
The first operation must leave asset supply zero and route liabilities zero. Replaying
the identical registration/enablement must fail without charging twice or changing
state. Cross-domain, substituted issuer/quorum, expired, duplicate endpoint,
invalid decimals/cap, malformed frame and late sponsor-failure cases must leave
the parent unchanged. Mixed bootstrap/transfer bodies must obey ordered effects;
bootstrap alone cannot make an unfunded transfer valid.

Produce a block, encode/decode its body and replay it on an independent state;
compare complete state, component commitment, canonical root and block identity.
Restore its serialized component and reproduce subsequent blocks. Reorg both
inside and beyond the node snapshot ring, reject a malformed winning suffix
atomically, and retain the finalized rewind fence. Repeat historical roots with
feature/default builds and before each disabled gate.

Only after bootstrap comes canonical import/withdrawal, authenticated source
proof/finality integration, funded pool lifecycle and swaps. The rehearsal
`State::execute_gateway` uses committee attestations, not a source light client
or external payment receipt. Reusing it requires adapting block-price accounting
and fee settlement, plus durable external duplicate-payment and reorg handling.
No activation or public funding follows automatically from passing these tests.
