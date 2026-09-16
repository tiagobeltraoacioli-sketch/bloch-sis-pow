# Canonical native bootstrap integration contract

Status: implemented under a disabled production gate; updated 2026-09-16.
The original design below describes the implemented bootstrap contract, not a
remaining task. Canonical `NativeBootstrap` uses registered tag `0x0F`; import,
withdrawal and pool operations subsequently use `0x10`–`0x12`. No public epoch,
authority, custody deployment or backing is assigned by this document.

## Current boundary

`NativeState` is owned by `CommittedState`. Bounded snapshot restoration validates
the component against its matching base projection and trusted commitment; it
does not independently prove finality or activate any authority. Canonical
bootstrap, gateway and pool adapters now execute through actual `apply_block`.

Official-network native admission remains disabled. The separate explicit
`native-lab` instance has domain-bound admission, real signed populated blocks,
restart/replay and wallet process coverage. Its `BPOSLAB1` identity and loopback
transport cannot be substituted for the official network. For current completed
work and remaining public requirements, see
[native consensus integration status](native-consensus-integration-status.md)
and [node laboratory contract](../../bloch-pos-node/NATIVE-LAB.md).

## Implemented operation: sponsored registration and route enablement

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

Canonical import/withdrawal and funded pool lifecycle/swaps are now implemented.
Authenticated source proof/finality integration remains a separate public requirement. The rehearsal
`State::execute_gateway` uses committee attestations, not a source light client
or external payment receipt. Reusing it requires adapting block-price accounting
and fee settlement, plus durable external duplicate-payment and reorg handling.
No activation or public funding follows automatically from passing these tests.

## Implemented dormant bootstrap

`native_dex/bootstrap.rs` implements a bounded supply-only registration plus
route enablement in one staged transaction. The issuer, configured sorted quorum
and BLCH fee payer bind the same typed authorization, including domain,
registration, route, expiry, prepaid gas and sponsor outputs. Canonical dispatch
uses tag `0x0F` and a separate disabled epoch gate. Supply and mint nonce remain
zero; normal block settlement charges fees once. Tests cover real block replay,
disabled-gate refusal, every authority, malformed wire and atomic failures.
This supplies no operator allowlist, source-vault deployment, backing proof or
production keys.
