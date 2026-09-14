# Paired BLCH/native reserve custody rehearsal

The default-off `native-dex-rehearsal` feature supports paired reserve creation
and owner-authorized closing in local state. It is not live liquidity, an LP
redemption, a swap, an external bridge withdrawal or an activated Genesis-4
transaction. The separate [initial liquidity](initial-blch-liquidity.md)
operation can convert funded reserves into a pool with a sealed LP position.
All examples and tests use local funding.

## One concrete settlement boundary

`native_dex::State` owns the real BLCH state, sealed native pool ledger, both
paired reserve records, their locks and fee escrow. Its ordinary transfer,
creation and closing dispatchers enforce the same paired lock map. The native
ledger's existing native/native AMM locks remain independently enforced.

`State::native()` returns read-only `NativeView`, `GatewayView` and `LedgerView`
queries. These expose balances, token/route metadata and lock-aware spendable
outputs, not a clonable executable ledger, mutable references or inner restore
material. Its diagnostic native snapshot is opaque. The full `State` snapshot
is also opaque: a caller can clone and restore the complete state against a
trusted root but cannot extract one component or edit its fee accounting.

This is an API authority boundary, not encryption or protection against a
malicious host that replaces code or invents its own trusted root. Production
hosts must authenticate the complete outer root. Compile-fail tests ensure
external Rust callers cannot obtain the old mutable component through the
supported query/snapshot API.

## Creation and authorization

`paired_custody::Request` contains the BLCH TransferV2 intent, native transfer
envelope, seed, two reserve amounts, expiry and native work budget.
`State::quote_paired_custody` prices the complete operation;
`execute_paired_custody` validates and commits it. Output zero of each leg is
the reserve; subsequent outputs are change to the same admitted PQ owner.
Both legs sign `Request::authorization` with the authenticated network domain.

The custody ID uses `base_reserves::reserve_id(domain, seed, owner)`. Its BLCH
output uses the protocol condition commitment, while the native output keeps
the real owner key. Both gain locks owned by the combined state. Only a
registered Supply-only native asset without a KYC root is admitted. Native
funding uses the ordinary zero-delta transfer planner internally, preserving
owner signatures, charter checks and supply accounting. There is no public
native reserve-release plan or privileged balance setter.

The [bounded binary creation transport](paired-custody-wire.md) delegates to
that same complete state. It is a prerequisite for wallet/RPC integration,
not a network endpoint or live wallet submission method.

## Closing

`paired_custody::CloseRequest` identifies the reserve and its original creation
authorization and contains both settlement intents, expiry and native work
budget. `State::quote_paired_close` prices it; `execute_paired_close` settles
both assets or neither. A distinct close authorization commits to both exact
legs, fee terms, reserve ID, creation authorization and network domain. A
creation signature or ordinary transfer signature cannot authorize closing.

Only unconverted reserves can close. Once [initial liquidity](initial-blch-liquidity.md)
has assigned LP ownership, this close path rejects the reserve to preserve the
locked minimum and LP accounting. The admitted original owner must sign both legs. The native leg consumes
exactly the recorded reserve and returns its full amount to that owner in one
output. BLCH output zero returns the full BLCH reserve to the owner's actual
key commitment. At least one additional ordinary BLCH input pays the fees;
all remaining outputs return owner change. Reserve value cannot subsidize
fees. This is not third-party fee sponsorship or an LP redemption.

Only the private closing dispatcher can construct the narrowly scoped BLCH
spend capability. It binds the actual recorded reserve outpoint, protocol
condition, amount, joint authorization and equal-value owner payout. No caller
can construct or deserialize that capability. Native settlement uses the
ordinary owner-validated planner behind the combined state's private boundary.

All fallible validation completes before either plan commits. After successful
settlement, the two consumed reserve records and locks are removed together;
new owner outputs are spendable. Replay is refused because the original
records/inputs no longer exist. No token is minted or burned, no bridge source
liability changes, and no external USDT vault is contacted. Closing is a typed
local API; the creation-only binary dispatcher does not accept closing frames.

## Fees, conservation and persistence

Every request binds the full witness-bearing byte budget. Existing BLCH fee
limits and the conservative prepaid native-work conversion remain in force,
with custody bookkeeping charged separately. These reference costs are not a
calibrated production fee schedule. Each asset conserves independently;
fees are retained in the committed BLCH fee escrow.

Snapshot and outer-root version 4 include paired custody and initial pool/LP
records alongside both ledger roots, base reserve metadata and fees. Versions
1, 2 and 3 are rejected;
no live chain migration is performed. Restore checks canonical record ordering,
unique locks, admitted owners, exact amounts/assets/outpoints, correspondence
to the BLCH record and creation authorization, and non-overlap with native AMM
locks. It reconstructs paired locks rather than trusting a serialized lock map.
A failed restore exposes no partially validated state.

## Verification and remaining work

```sh
cargo +1.94.1 test --locked -p bloch-pos-committee --features native-dex-rehearsal --lib native_dex
cargo +1.94.1 test --locked -p bloch-pos-committee --features native-dex-rehearsal --doc
cargo +1.94.1 test --locked -p bloch-ustav --test paired_custody_crypto --test joint_blch_native
```

Tests cover real hybrid PQ signatures, malformed/unauthorized requests,
independent conservation, reserve locks, partial-settlement refusal, replay and
complete restoration. Locally issued test tokens are not proof of external
USDT backing. Initial LP issuance is implemented; a production BLCH/USDT market
still requires subsequent liquidity additions, swaps, liquidity removal,
wallet signing, closing transport, network admission, block fee settlement,
consensus commitments, replay/reorg integration and independent review.
