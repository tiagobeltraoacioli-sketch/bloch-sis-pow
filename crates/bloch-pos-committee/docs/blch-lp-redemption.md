# Proportional BLCH/native LP redemption

The default-off combined rehearsal now allows the sealed LP owner to redeem
some or all of their position for BLCH and the paired native asset. The AMM
computes each payout as `floor(reserve * lp_burn / total_lp_supply)`, using
integer raw units. The two payouts, reserve rotations, LP burn and separately
funded BLCH fees commit atomically. This remains a local Rust API, not live
network admission or wallet transport.

## Ownership and quote

`remove_liquidity::QuoteRequest` specifies domain, pool, expected revision,
LP amount, minimum payouts `[BLCH, native]` and inclusive expiry height.
`State::quote_blch_remove` revalidates both actual reserves, locks, pool state
and LP accounting. It returns exact payouts, before/after reserves, remaining
owner LP and the current pool root. An unsigned quote does not prove ownership,
authorize a transaction or establish source-chain finality.

`remove_liquidity::Request` adds the expected pool root, the BLCH transaction,
native transfer envelope and native work budget. The `BLCHLPRM` canonical frame
and separate authorization domain bind every quote field, both funding legs,
recipients, expiry and gas. It is distinct from initialization, close, swap and
ordinary-transfer authorization. There is no removal network decoder yet.

The original LP owner must provide real hybrid PQ signatures on both legs over
`Request::authorization`. Redemption never uses the swap's empty reserve-witness
exception. A trader or token issuer holding valid keys cannot redeem someone
else's LP. LP ownership remains a single sealed position; transfers and additional
liquidity providers require subsequent work.

## Exact funding and commit

BLCH inputs contain the current reserve at `RESERVE_KEY_INDEX` and at least one
ordinary, unlocked owner input at key index zero. Output zero is the exact new
reserve with its unchanged protocol script; output one is the exact BLCH payout
to the owner. Remaining outputs are owner fee change. The fee funding equation
excludes the payout and reserve, so fees cannot reduce the promised return.

The native leg has exactly one input, the current reserve, and two outputs:
the exact new reserve and exact owner payout. Both retain the admitted owner
key. Supply delta is zero, the owner witness is nonempty, and the Supply-only,
no-KYC asset restriction remains enforced. There is no issuer mint or bridge
withdrawal in this operation.

`quote_blch_remove_fee` charges full witness-bearing bytes, the existing native
work multiplier and 5,000 reference gas units for removal validation. These
costs are rehearsal values, not a calibrated production fee schedule.

`execute_blch_remove` rechecks revision/root/expiry, balance and minimum payouts,
then validates both existing transfer plans before either commits. The private
BLCH capability independently recalculates the quote and binds input value,
new reserve output and joint authorization. Signature, fee, collision or shape
failure preserves both ledgers and LP accounting. No fallible arithmetic remains
after commit begins.

## Permanent minimum and restoration

Only owner LP can be burned. Full owner redemption leaves exactly 1,000 LP with
no owner and positive reserves backing that minimum. Pool records and both locks
remain. Neither a subsequent redemption nor paired close can recover the minimum.
Swaps remain available against those reserves, including after full owner redemption.
If either rounded payout is zero, redemption rejects rather than burning LP for
a zero return in one asset. Minima and deadlines remain user-controlled.

Combined snapshot/root version 6 rejects versions 1 through 5; it does not migrate
any live chain. Initial reserve amounts and LP owner stay committed. Remaining
owner LP cannot exceed initial issuance; current LP supply must equal remaining
owner LP plus 1,000. Revision coupling and actual output/lock checks remain in
force. The pre-redemption reserve-product bound is retained when no shares have
been burned; afterward pure AMM restoration enforces positive reserves and
`reserve0 * reserve1 >= total_lp_supply²`. These structural checks do not prove
the full transaction history: restoration still requires an independently
authenticated complete state root, never one trusted solely because it came
with the snapshot.

## Validation and remaining work

```sh
cargo +1.94.1 test --locked -p bloch-pos-committee --features native-dex-rehearsal --lib native_dex
cargo +1.94.1 test --locked -p bloch-ustav --test blch_remove_crypto --test blch_swap_crypto --test paired_custody_crypto --test joint_blch_native
```

Tests cover partial/full redemption, exact integer rounding, fee separation,
replay, minimum protection, swaps before/after redemption, restoration,
forged hybrid signatures, thief signatures, payout redirects, empty witnesses,
malformed requests, excessive LP burns and failed-plan rollback.

Subsequent liquidity deposits, LP transfers, network transport, wallet signing,
block fee settlement, consensus/reorg integration and a qualified operational
USDT bridge remain open. Returning a native token locally does not release
external USDT or establish real source-chain backing.
