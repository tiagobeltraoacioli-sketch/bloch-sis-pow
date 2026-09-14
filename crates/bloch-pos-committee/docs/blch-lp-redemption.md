# Proportional BLCH/native LP redemption

Each provider can redeem some or all of their own sealed LP position in the
explicitly enabled combined rehearsal. The pure AMM pays
`floor(reserve * lp_burn / total_lp_supply)` units of each asset. Reserve
rotation, payouts, position burn and separately funded BLCH fees commit together.
This is a local Rust API, not live network admission or wallet transport.

## Quote and authorization

`remove_liquidity::QuoteRequest` includes domain, pool, provider PQ key, expected
revision, LP burn, minimum payouts `[BLCH, native]` and inclusive expiry height.
`quote_blch_remove` validates actual backing, locks and the provider's position
before returning payouts and remaining LP. A quote is not an ownership or finality
proof and does not authorize execution.

`Request` adds the expected pool root, both funding transactions and prepaid
native work. The version-2 `BLCHLPRM` frame and version-2 authorization/output
hash domains commit the length-prefixed provider key together with the complete
intent. Older removal signatures are not reused. No network decoder is supplied.

Both legs require real nonempty provider signatures over joint authorization.
The BLCH key must match the identified LP provider. The private native verifier
accepts only the exact validated reserve input/hash and verifies its witness
under that provider's key after the executor has checked the LP position. It does
not use the swap's empty-witness exception. The original reserve owner's key
cannot authorize another provider's position.

## Exact funding

BLCH inputs contain the reserve at `RESERVE_KEY_INDEX` and at least one unlocked
provider fee input at key index zero. Output zero is the exact new protocol
reserve, output one is the exact provider payout, and subsequent outputs are
provider fee change. The fee equation excludes the payout and reserve.

The native leg has exactly the current reserve input and two outputs. Output
zero retains the original reserve-owner key and exact new reserve amount;
output one pays the redeeming provider. Delta is zero. Supply-only/no-KYC policy,
exact witness arity and nonempty real signatures remain required.

`quote_blch_remove_fee` charges the full witness-bearing frame, existing native
work multiplier and 5,000 reference gas units. These are not calibrated production
fees. Both existing transfer plans validate before either commits. Signature,
fee, collision, shape or LP failures leave all balances and positions unchanged.

## Permanent minimum and restoration

Full redemption of one provider's position leaves all other providers intact.
When every provider exits, exactly 1,000 unowned LP and positive reserves remain.
Pool records and locks persist; neither redemption nor paired close can recover
that minimum. Swaps remain available and new providers can add liquidity again.
If either rounded payout is zero, redemption rejects rather than burning shares
for a zero return in one asset.

Snapshot/root version 7 rejects versions 1 through 6 without migrating a live
chain. Original pool identity and initial funding remain committed. There are
at most 128 provider slots, including the original creator slot; extra zero
positions are removed. Restoration bounds positions and key sizes before PQ key
admission, rejects creator duplicates and invalid keys, and checks
`sum(provider LP) + 1000 == total_lp_supply`. Additional deposits can legitimately
increase supply above initial issuance. Current backing/revision checks and pure
AMM restoration require positive reserves and product at least LP supply squared.
These structural checks still require an independently authenticated complete
state root; a root supplied alongside untrusted data is not authentication.

## Validation and remaining integration

```sh
cargo +1.94.1 test --locked -p bloch-pos-committee --features native-dex-rehearsal --lib native_dex
cargo +1.94.1 test --locked -p bloch-ustav --test blch_add_crypto --test blch_remove_crypto --test blch_swap_crypto
```

Tests cover independent providers, partial/full redemption, exact rounding,
minimum protection, swaps after redemption, restoration, replay, forged hybrid
signatures, original-owner theft attempts, redirects, fees and malformed inputs.

[Additional liquidity](blch-liquidity-additions.md) is now implemented. LP transfer,
network transport, wallet signing, block settlement, consensus/reorg integration
and an operational qualified USDT bridge remain separate work. Local native
redemption does not release external USDT or establish source-chain backing.
