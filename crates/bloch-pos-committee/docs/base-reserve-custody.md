# Opt-in BLCH reserve custody and continuation

`native-dex-rehearsal` now exposes `transition::native_dex::base_reserves`.
It is a local custody substrate over actual `CommittedState` BLCH UTXOs, not a
BLCH/USDT AMM, LP token, bridge release service, or activated consensus operation.
Standalone reserves have no withdrawal/close operation; paired reserves use
the separate atomic closing dispatcher. Do not fund it on a live
chain; the node has no admission or settlement integration for these requests.

The owning `native_dex::State` offers `quote_base_reserve`,
`execute_base_reserve`, `base_reserve`, `base_is_locked` and
`spendable_base_output`. The inner base/native states remain read-only. No API
exports a mutable backend, reserve release plan, balance credit, issuer authority,
or a caller-constructible approval capability.

## Funding and continuation

`Action::Create { seed, amount }` consumes real BLCH owner funding and creates
output zero as the reserve. Its ID hashes the authenticated network domain,
seed and full owner PQ key. Its `script_hash` is a distinct domain-separated
protocol condition commitment, not a fake key or a new BLCH asset registration.
All later outputs return change to that same owner. A seed cannot be reused to
replace an existing reserve; at most 128 reserves may exist in this rehearsal.

`Action::Continue { reserve, revision }` consumes exactly the recorded reserve
outpoint and creates exactly the same amount under the same protocol condition
at output zero. It advances the recorded revision and replaces the lock. It
requires at least one additional ordinary owner input. These additional inputs
pay all base/priority fees; they must conserve independently against owner change
and fees. The reserve cannot shrink to pay fees or redirect change to a third
party. This slice uses one admitted PQ owner for the reserve and fee funding;
third-party fee sponsorship is not implemented.

The one witness signs a dedicated digest binding domain, action, seed/ID,
amount/revision, expiry and the entire witness-free TransferV2 intent. The full
witness-bearing envelope is charged in `tx_bytes`, within existing declaration
slack. Existing TransferV2 pricing, gas/tip ceilings, output rules, owner checks,
duplicate detection, conservation and output collision checks remain active.
An additional 1,000 rehearsal gas units account for custody bookkeeping; this
is not production fee calibration. Fees stay in the existing committed rehearsal
escrow, and no epoch, block fee controller or reward distribution is advanced.

## Private authorization boundary

The reserve input uses `RESERVE_KEY_INDEX = u32::MAX`. This value alone grants
no authority: the ordinary planner rejects it. Only a private, non-clonable
`ReserveSpend` constructed by the custody dispatcher can authorize the recorded
input. The capability checks the actual UTXO, amount, protocol script, action
authorization and equal-value successor. Other inputs still require the actual
owner's key and signature. A valid continuation always uses the owner's key on
separate funding, so the reserve does not introduce an unsigned transaction.

The capability and its planner branch are compiled only with the existing
default-off rehearsal feature. With that feature absent, the ordinary context,
input validation and `CommittedState` layout are unchanged. No new public
`PosTransaction` tag, consensus root, node setting or activation gate is added.
The ordinary joint transfer dispatcher also rejects registered locked BLCH
outpoints before native staging; it cannot smuggle reserve spending through a
different request type.

All fallible validation completes before the private exclusive-borrow BLCH plan
commits. Reserve locks, records and fee counters then update together. Native
asset supply, bridge liabilities and native pool custody are never mutated by
this path. Canonical custody request bytes exist for signing/charging only;
there is no network decoder or block dispatch for them yet.

## Persistence and validation

The rehearsal snapshot and outer root use version 3 and commit every
reserve's ID, seed, owner, amount, revision and outpoint alongside both ledger
roots, paired custody records and fee counters. Old version-1 and version-2
snapshots are refused rather than silently losing custody metadata. Restore reconstructs unique locks and checks the
actual UTXO, output index zero, amount, protocol script, ID derivation and PQ
owner admission against an independently authenticated outer root.

Tests cover real funding, repeated continuation, fee separation, conservation,
ordinary and joint spend refusal, forged ML-DSA/Falcon signatures, wrong owners
and domains, expiry, revision replay, missing/duplicated funding, output collision,
fee overflow, bounded reserve count and snapshot tampering. The `bloch-ustav`
integration test uses real hybrid PQ signatures for funding and continuation.

Native and base paired custody now share one concrete State backend. Before
supporting a BLCH/USDT market, atomic AMM/LP rules remain required. Do not expose a public native reserve-release
plan as an intermediate shortcut. Consensus admission, full persistence/reorg
integration, wallet signing, fee settlement and independent review remain open.

The separate [paired reserve creation](paired-reserve-custody.md) operation now
funds and locks both assets atomically. Reserves created through that operation
cannot use this standalone continuation path; changing one side independently
would break the authenticated pairing. The paired closing dispatcher returns
both assets atomically to their original owner. AMM/LP transitions remain
unimplemented.
