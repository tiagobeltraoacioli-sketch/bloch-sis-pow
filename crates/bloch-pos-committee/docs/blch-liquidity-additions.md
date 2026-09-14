# Additional BLCH/native liquidity and independent LP providers

The default-off combined rehearsal supports subsequent deposits into an existing
BLCH/native pool. Each admitted PQ provider owns a separate sealed LP position.
Deposits, reserve locks, LP issuance and real BLCH fees settle atomically. No
approval or signature from the original liquidity owner is required for a new
provider to deposit or later redeem their own position.

## Proportional integer arithmetic

`add_liquidity::QuoteRequest` identifies domain, pool, expected revision,
maximum `[BLCH, native]` amounts, minimum LP issuance and inclusive expiry height.
`State::quote_blch_add` checks current backing and uses the pure AMM Add rule:

```text
lp_minted = min(floor(maximum[0] * L / reserve[0]),
                floor(maximum[1] * L / reserve[1]))
amount_in[i] = ceil(lp_minted * reserve[i] / L)
```

Here `L` is the existing total LP supply, including the permanent minimum.
Rounding protects existing providers: actual input is rounded up and issuance
down. A zero issuance, minimum-LP violation or arithmetic overflow rejects.
All quantities are raw integer units; no decimal conversion or price peg is
assumed. The quote reports `amounts_in`, `unused_maximum`, `lp_minted`, the
current pool root and before/after reserves.

Only actual required inputs are debited. `unused_maximum` is informational, not
an extra credit: wallet funding minus actual debit is the change. For example,
reserves `[1_000_000, 60]`, supply `7_745` and maxima `[1_000_000, 30]` issue
`3_872` LP for `[499_936, 30]`, leaving `[500_064, 0]` of the offered maxima unused.

## Funding and authorization

`add_liquidity::Request` combines the quote request, expected pool root, BLCH
TransferV2, native transfer envelope and prepaid native work. The `BLCHLPAD`
frame and distinct add authorization/output hash domains bind the complete
intent and both funding legs. The bounded [`pool_wire`](pool-lifecycle-wire.md) decoder supports this frame.

The sole BLCH key is the depositor and signs the joint authorization. BLCH inputs
include exactly the current reserve at the private reserve key index and at
least one ordinary unlocked depositor input. Output zero is the new protocol
reserve; all other outputs are depositor change. Depositor funding must equal
actual BLCH addition, change and network fees. The reserve cannot pay those fees.

Native inputs include exactly the current reserve plus depositor funding in
canonical order. Native output zero retains the original admitted reserve-owner
key and exact new reserve amount; subsequent outputs are depositor change.
Supply delta stays zero. Every ordinary input must be unlocked, depositor-owned
and have a real nonempty joint signature. Only the exact reserve input has an
empty witness accepted by a private transaction-scoped verifier. The executor
rejects a second empty witness even if the depositor is the original owner.
Supply-only/no-KYC restrictions prevent extending that exception to policy calls.

`execute_blch_add` recomputes the quote and checks the signed pool root. LP is
credited only to the authenticated depositor in a local staged record. Position
capacity, LP arithmetic, fees, signatures and both transfer plans must validate
before either ledger commits. The private BLCH capability independently rechecks
the quote and exact reserve continuation. A late failure cannot publish LP.

`quote_blch_add_fee` prices the entire witness-bearing frame, existing native
work multiplier and 5,000 reference gas units. Those costs and the provider cap
are rehearsal bounds, not production throughput or fee calibration.

## Provider ownership and persistence

`State::blch_lp_position(pool, owner)` queries each provider independently. The
original creator retains a reserved position slot; a canonical bounded map
holds at most 127 additional nonzero positions. Updating an existing position
works at capacity, and fully redeeming an extra position frees its slot.
No public position setter or LP transfer is added.

The total of every provider position plus 1,000 locked LP must equal pool supply.
Version-7 snapshots/root commit all positions, original identity and actual
backing. Versions 1 through 6 reject. Restore checks count/key bounds before key
admission, canonical extra entries, exact supply accounting and current reserve
structure against an independently trusted complete root. The NativeView root
uses version 4. Structural validation does not replace host authentication.

[Provider redemption](blch-lp-redemption.md) now explicitly signs the provider key
in version 2 of its request. It pays only that provider and preserves all other
positions, the original reserve condition and the permanent minimum.

## Validation and remaining work

```sh
cargo +1.94.1 test --locked -p bloch-pos-committee --features native-dex-rehearsal --lib native_dex
cargo +1.94.1 test --locked -p bloch-ustav --test blch_add_crypto --test blch_remove_crypto --test blch_swap_crypto
```

Tests cover balanced/unbalanced deposits, exact integer rounding and change,
independent providers and redemption, real hybrid PQ signatures, theft attempts,
replay/slippage, provider bounds, malformed snapshots, locked inputs, empty
witness abuse and late-plan rollback.

This implements the local pool lifecycle, not a live USDT market. Bounded network
node/RPC admission, wallet integration, block fee settlement, consensus/reorg persistence
and qualified operational USDT bridge services remain required.
