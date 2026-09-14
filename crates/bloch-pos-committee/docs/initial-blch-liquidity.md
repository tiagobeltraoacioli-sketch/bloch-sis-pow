# Initial BLCH/native liquidity in the combined rehearsal

The default-off `native-dex-rehearsal` feature can initialize a BLCH/native pool
from an existing fully funded paired reserve. This creates an authenticated LP
position in local state. The separate [atomic swap dispatcher](atomic-blch-swaps.md)
now trades against those reserves. This does not activate a live market or add
subsequent deposits, LP transfers or liquidity removal. Use local test funding;
there is no LP redemption operation for a converted pool in this version.

## Authorization and funding

`initial_liquidity::Request` contains the paired reserve ID, original creation
authorization, pool fee in basis points, minimum acceptable LP issuance,
expiry and a BLCH TransferV2 fee intent. The original admitted PQ owner signs
`Request::authorization`, which binds all those fields and the authenticated
network domain. A signature for creating/closing the reserve or making an
ordinary transfer cannot authorize pool initialization.

`State::quote_initial_liquidity` charges the complete witness-bearing request
and 5,000 reference gas units for bounded initial arithmetic and bookkeeping.
`execute_initial_liquidity` verifies the owner, both actual reserve outputs,
locks, supported native asset, minimum LP and the separate fee transaction
before committing. Fee inputs must be unlocked BLCH outputs of that same owner;
all change returns to the owner. There is no fee sponsorship or reserve deduction.
These gas costs are rehearsal values, not production calibration.

Only registered Supply-only native assets without KYC roots are supported.
Bridged USDT must already exist through the independently authorized gateway
import process. A token name or the creation of this pool does not establish
external backing, source finality or authority to issue USDT.

## Pool identity and LP accounting

The pure AMM identity commits to the network, sorted assets `(BLCH, native
asset)`, fee basis points and paired reserve ID as its seed. Initialization
applies the existing AMM's first Add transition to the exact recorded reserves.
No BLCH or native token is created, destroyed, transferred or re-denominated by
this step. The initial reserves remain at their already locked outpoints.

For reserves `B` and `T`, total initial LP is `floor(sqrt(B * T))`. The initial
owner receives that total minus `MINIMUM_LIQUIDITY` (1,000); the minimum has no
owner and cannot be claimed. Too-small reserves or a requested minimum above
actual issuance reject the entire operation. Arithmetic uses exact integer
asset units. The initial ratio comes from the owner's deposits, not a price
oracle or an implied fixed BLCH/USDT exchange rate.

`State::blch_pool(pool_id)` returns read-only AMM state,
`blch_pool_for_reserve(reserve_id)` finds its converted reserve, and
`blch_lp_position(pool_id, owner)` returns the sealed owner's LP balance.
Unknown owners receive zero. These positions are internal ownership records,
not an ERC-20 token or transferable wallet asset. The separate native/native
pool queries on `NativeView` do not describe BLCH-backed pools.

## Verified read-only swap quotes

The current design uses a constant-product AMM for BLCH/native-USDT. It makes
no stable-price relationship assumption between BLCH and USDT. A shared pure
integer transition supplies the arithmetic for quotes and local settlement;
the swap dispatcher verifies actual funding and custody atomically. Introducing
concentrated liquidity, an order book or additional price-oracle dependencies
would require separate accounting and validation work and is outside this step.

`State::quote_blch_swap` accepts `swap_quote::Request`: network domain, pool ID,
expected revision, input asset ID, exact integer input amount, minimum output
and inclusive expiry height. Direction is resolved from the asset ID, avoiding
client assumptions about token ordering. The caller supplies the host height.

Before calculating, the method checks both actual reserve outputs and locks,
the reserve-to-pool mapping, supported asset rules, creation authorization and
the preserved initial LP state. Both initial and swapped pools are accepted
after checking actual current backing, coupled pool/reserve revisions, unchanged
LP supply and a reserve product at least as large as the initial product.

The result includes exact output units, fee basis points, pool state root,
height and hypothetical before/after reserves. It uses the same pure AMM
transition arithmetic, including downward output rounding, minimum output,
revision, expiry and reserve-product checks. The pool fee remains in the input
reserve; BLCH network fees and wallet funding are not included or validated.

Quotes do not change state or grant spending authority, establish source-USDT
backing, prove finality or guarantee execution. No RPC or wallet transport is
added. The separate swap executor binds funding, recipient, domain, pool state
and slippage/deadline constraints into the signed intent and revalidates them.
Use a trusted host height and validate the request domain in any future RPC.

## Custody and persistence

Initialization atomically commits fee spending, the pool and its LP position.
A reserve can back only one initialized pool, including when a second request
uses fresh fee inputs or a different fee schedule. Existing ordinary transfer
and standalone reserve-continuation restrictions remain in force.

Once converted, `execute_paired_close` rejects the reserve. The private BLCH
close capability also rejects it. Owner identity alone no longer authorizes
returning all backing, because that would bypass LP accounting and the locked
minimum. No emergency reserve-release API is added.

The complete rehearsal snapshot and root now use version 5; older snapshots
are rejected. Restore reconstructs each initial AMM state from committed initial
amounts, then checks current actual paired backing, identity, fee, revision,
unchanged LP supply/owner/balance and reserve-product invariants. It also
rejects duplicate reserve-to-pool mappings. Native diagnostic snapshots also
commit pool/LP authority. All snapshots
remain opaque outside the complete state API.

## Validation and remaining operations

```sh
cargo +1.94.1 test --locked -p bloch-pos-committee --features native-dex-rehearsal --lib native_dex
cargo +1.94.1 test --locked -p bloch-ustav --test paired_custody_crypto
```

Tests cover real hybrid PQ signatures, exact initial LP arithmetic, minimum LP,
owner theft attempts, fee/creation-authorization tampering, duplicate issuance,
closing a converted reserve, fee conservation and complete restoration. The
existing transfer, close and API-isolation regressions remain required.

Subsequent Add and Remove operations must atomically update actual BLCH
and native reserve outputs together with LP accounting. Swaps now do so while
preserving LP ownership and supply. Wallet transport,
network admission, block fee settlement, consensus commitments, replay/reorg
integration, qualified USDT bridge services and independent review remain open.
