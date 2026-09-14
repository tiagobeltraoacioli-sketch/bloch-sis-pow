# Joint BLCH/native transfer rehearsal

The explicitly enabled `bloch-pos-committee/native-dex-rehearsal` feature adds
`transition::native_dex`, an isolated execution harness over actual
`CommittedState` BLCH UTXOs and a sealed native `PoolLedger`. Default node builds
do not enable it. No transaction enum/tag, block root, node admission rule,
activation epoch or live fee-distribution rule is changed.

This moves both registered-token outputs and base-coin outputs in local state,
using their existing ownership validators. It is a bilateral transfer building
block, not a permissionless BLCH reserve adapter or live BLCH/USDT AMM. The
native token may be a gateway-backed asset; the USDT import/finality deployment
requirements remain independent.

The same default-off harness also has a bounded
[real BLCH custody substrate](../../crates/bloch-pos-committee/docs/base-reserve-custody.md):
an admitted owner can fund a locked reserve and continue it at exactly the same
value, paying fees from separate ordinary inputs. This does not trade either
asset, issue LP, release a native reserve, or implement a withdrawal operation.

[Paired reserve creation](../../crates/bloch-pos-committee/docs/paired-reserve-custody.md)
additionally binds BLCH and registered-token funding in one authenticated
operation and locks both reserves atomically. It still creates no LP position
and offers no swap, withdrawal or reserve continuation. The standalone BLCH
continuation path rejects reserves belonging to this paired custody.

## Atomic authorization and planning

A request combines a bounded TransferV2 intent with a zero-delta native transfer
envelope, common expiry and native-work budget. Both sets of owners sign a
single SHA3-256 digest with a new tag, authenticated genesis domain, both
witness-free transfer intents, expiry and work budget. Base ownership checks
still resolve real UTXOs and their key commitments. Native owner, charter and
reserve-lock checks remain required. No standalone signature is a fallback.

BLCH output identity derives from another domain-separated hash of the joint
authorization. Collision checks use that identity before returning the base
plan. The native leg retains its existing transaction-hash outpoint convention.

`PoolLedger::plan_transfer` stages only the affected token and inputs, then
performs all existing native validation. It exclusively borrows the sealed
ledger until commit or drop. The base validator similarly returns a private
plan after checking keys, inputs, prices, conservation and output collisions.
Both plans must succeed before either is consumed. A rejected BLCH leg drops
the validated native plan without consuming inputs or changing supply/locks.

The legacy TransferV2 wrapper supplies no joint context and retains its old
size, digest, identity, gas and validation order. The execution context is
private, derived inside the harness rather than deserialized from a caller.

## Byte and fee accounting

The joint frame includes both complete witness-bearing payloads and their
lengths. BLCH `tx_bytes` must cover the frame within the existing permitted
declaration slack. Counts and individual key/signature lengths are checked
before encoding, and the joint size ceiling uses the conservative original
block transaction-byte limit. The bounded
[joint wire decoder](../../crates/bloch-pos-committee/docs/joint-native-wire.md)
rejects noncanonical fields and dispatches through the same sealed executor.
It does not add a network admission route or charge decoding fees twice.

The charged gas is existing BLCH intrinsic gas over the full declared size,
plus the prepaid native budget multiplied by 73. Native PQ checks currently
cost 1,000 reference units versus 72,748 L1 units, so this conservative
conversion avoids treating unlike units as equivalent. It scales all native
work, including unused prepaid work; it is not a calibrated production policy.
The combined charge obeys the existing gas and tip ceilings. Native budget
includes decoding, staging and execution, and is checked before committing.

The price comes from `CommittedState::next_base_fee()`, derived from committed
usage in the current epoch. The harness does not advance epochs, block usage,
the fee controller or validator reward distribution. The host-provided height
is trusted execution context for expiry, not proof of a newly accepted block.

Real BLCH fees are removed from funding UTXOs and retained in separate base and
priority fee escrow counters. Both counters are committed alongside the base
and complete native roots under a distinct rehearsal root. There is no payout
API; integrating the normal block fee settlement remains required.

## State and trust boundary

`State::from_parts` starts a new rehearsal with zero fee escrow and checks
domain and component roots. Expected roots must originate in independently
authenticated host state; matching roots supplied by the same untrusted sender
does not prove authenticity. Never use this constructor to resume an existing
rehearsal while discarding its fee escrow.

`snapshot` and `restore` carry the base state, full sealed native state, both
fee counters and BLCH reserve records. The rehearsal snapshot/outer root now use
version 2; old version-1 snapshots are rejected. Restore rebuilds and validates
reserve locks and the complete expected outer root. Cloning or
restoring just one component is not an atomic replay/reorg operation. This is
a typed local snapshot; production persistence/network codecs are not added.

## Validation and remaining work

Run:

```sh
cargo +1.94.1 test --locked -p bloch-pos-committee --features native-dex-rehearsal --lib native_dex
cargo +1.94.1 test --locked -p bloch-ustav --test joint_blch_native
cargo +1.94.1 tree --locked -p bloch-pos-node --edges normal
```

The last command should contain neither `bloch-euvm` nor `bloch-ustav` in a
default node build. The joint crypto test enables the feature through a
test-only dependency. No production feature or operator configuration changes.

Before deployment: provide the consensus transaction and root versioning,
block fee accounting, epoch/admission rules, bounded network decoding, node
producer/validator parity, complete persistence/reorg handling and a real BLCH
pool reserve adapter. Then qualify bridge finality services and source vaults,
wallet signing and independent review. This harness is not liquidity-ready.
