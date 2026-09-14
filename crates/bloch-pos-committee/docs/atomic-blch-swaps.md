# Atomic BLCH/native swaps in the combined rehearsal

The default-off `native-dex-rehearsal` feature now executes exact-input swaps
against initialized BLCH/native pools. An admitted PQ trader can swap in either
direction without obtaining a signature from the original liquidity owner.
Both assets, reserve locks, pool revision and BLCH fee escrow update together.
This is a local Rust API, not live node admission, a wallet RPC or bridge activation.

## Signed request and fees

`swap::Request` contains a `swap_quote::Request`, the expected pool state root,
a BLCH `TransferV2`, a native transfer envelope and a prepaid native gas budget.
The `BLCHSWAP` canonical frame is used for signing/byte accounting; a bounded
decoder and network dispatcher are not yet supplied. Its joint authorization
commits to network domain, pool ID/root/revision, input asset and exact amount,
minimum output, expiry height, gas and both funding transactions. All trader
signatures authorize this joint hash. Ordinary transfer or paired custody
signatures cannot authorize it. Output recipients are part of that commitment.

`State::quote_blch_swap_fee` prices the full witness-bearing request, native
work through the existing conservative multiplier, and 5,000 reference gas
units for swap arithmetic/validation. These are uncalibrated rehearsal costs.
`execute_blch_swap` independently validates the current quote, pool root,
inclusive expiry and supported Supply-only/no-KYC asset policy at execution.

The AMM uses constant-product integer arithmetic with downward-rounded output,
retains the pool fee in the input reserve and preserves the reserve product.
There is no oracle or fixed BLCH/USDT peg assumption. Network fees always come
from separate unlocked trader BLCH funding; they cannot be deducted from pool
reserves or the required swap payout.

## Exact funding layout

BLCH inputs contain exactly the current reserve at `RESERVE_KEY_INDEX` and at
least one unlocked trader funding input with key index zero. Exactly one PQ
key signs the BLCH transaction. Output zero is the exact new BLCH reserve with
the unchanged protocol reserve script. If native tokens are the input, output
one is the exact BLCH payout. All remaining outputs are trader change.

The native transaction contains exactly the current native reserve input.
For a native-to-BLCH swap it additionally contains unlocked inputs owned by
the trader; inputs retain the native canonical ordering. Native output zero
is the exact new reserve with the original admitted reserve-owner key. For a
BLCH-to-native swap, output one is the exact native payout and there are no
other inputs or outputs. Otherwise, subsequent outputs are trader change.
Supply delta remains zero and each asset conserves independently.

The native reserve input has an empty owner witness. Every other input must
have a nonempty real trader signature, including when trader and liquidity
owner are the same person. Witness/input arity is exact; module and eligibility
witnesses cannot introduce another signature-exemption path. Only after these
checks, the private scoped verifier accepts the reserve-owner empty witness for
this exact native transaction hash. It is not an externally callable bypass.
Ordinary dispatch still rejects paired locks regardless of owner signatures.

The private BLCH `ReserveSpend` capability independently rechecks the quote and
binds old input amount/script, new reserve amount/script and joint authorization.
It cannot be cloned, serialized or constructed by an API caller.

## Atomic commit and persistence

Both existing exclusive-borrow transfer plans validate signatures, conservation,
output collisions and resource limits before either commits. Commit then rotates
both outpoints and lock maps, increments pool/base revisions, retains the original
creation authorization and updates fee counters. No fallible validation remains
after commit begins. Failure preserves both ledgers, LP positions and fee escrow.

Combined snapshot/root version 5 commits the initial reserve amounts alongside
the evolving pool. Versions 1 through 4 reject; no live chain migration occurs.
Restore verifies authenticated current outputs, scripts, amounts, asset identity,
owner, lock uniqueness and `pool.revision = base_reserve.revision + 1`. Initial
amounts reconstruct the original LP supply and permanent minimum. Swaps cannot
change LP supply or position; current reserve product cannot be below the initial
product. A progressed paired reserve must have a corresponding pool. Structural
checks supplement the independently authenticated complete state root; a root
provided by an untrusted snapshot sender is not authentication.

The original owner still cannot close a converted reserve through paired close.
Subsequent liquidity deposits, LP transfer and redemption remain unimplemented.

## Validation and remaining integration

```sh
cargo +1.94.1 test --locked -p bloch-pos-committee --features native-dex-rehearsal --lib native_dex
cargo +1.94.1 test --locked -p bloch-pos-committee --features native-dex-rehearsal --doc
cargo +1.94.1 test --locked -p bloch-ustav --test blch_swap_crypto --test paired_custody_crypto --test joint_blch_native
```

Tests exercise both directions by an independent trader with real hybrid PQ
signatures, LP and asset conservation, replay, post-swap restoration and another
swap, signature corruption, recipient theft, slippage, stale roots, expiry,
empty witness misuse, malformed vectors, foreign locks and atomic rejection.

Qualified source-chain USDT backing/finality, operational bridge services,
bounded network transport, wallet signing, block fee settlement, consensus
activation and persistence/reorg integration remain separate required work.
Local test-token swaps do not establish real USDT backing or production readiness.
