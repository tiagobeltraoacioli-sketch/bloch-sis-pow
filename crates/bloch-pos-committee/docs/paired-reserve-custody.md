# Paired BLCH/native reserve custody rehearsal

This local, default-off rehearsal prepares the custody boundary needed by a
BLCH/native-token market. It is not live liquidity, an LP position, a swap,
a bridge deposit authorization or an activated Genesis-4 transaction.

`native_dex::paired_custody::Request` contains the BLCH TransferV2 intent,
native transfer envelope, seed, two reserve amounts, expiry and native work
budget. `State::quote_paired_custody` prices the complete operation;
`execute_paired_custody` validates and commits it. Output zero of each leg is
the reserve; subsequent outputs are change to the same admitted PQ owner.
Both legs sign `Request::authorization` with the authenticated network domain.

The [bounded binary transport](paired-custody-wire.md) now provides encoding,
decoding and local dispatch through the same sealed executor. This is a
prerequisite for wallet/RPC integration; it does not itself expose a network
endpoint or enable a wallet to submit live transactions.

The lower-level native funding plan independently requires custody-specific
consent binding its record and transaction. The paired dispatcher privately
maps that exact digest to the joint authorization. An ordinary transfer
signature cannot be reused to impose a permanent reserve lock.

Fees cover the full witness-bearing envelope, the prepaid native budget using
the existing rehearsal conversion, and 1,000 additional BLCH gas units for
reserve bookkeeping. The native plan charges 1,000 native units for its own
custody bookkeeping. These reference costs do not calibrate production fees.

The custody ID uses `base_reserves::reserve_id(domain, seed, owner)`. Its BLCH
output uses the protocol condition commitment, while its native output keeps
the real owner key and gains a sealed protocol lock. Read-only custody queries
do not grant spending authority. The standalone BLCH continuation operation
cannot advance a reserve that belongs to paired custody.

## Required invariants

The same request must bind the network, both real funding intents, reserve
identity, owner, amounts, expiry and complete BLCH fee terms. Signing one leg
alone must not authorize paired custody. Both ledgers must validate before
either commits; a rejected request must preserve the complete state root,
funding outputs, token supply, bridge accounting and fee escrow.

BLCH funding must independently equal its locked reserve, owner change and
fees. Native funding must independently equal its locked reserve and owner
change. Neither a reserve nor a token symbol creates backing. The token must
already exist in the sealed native ledger; bridged USDT additionally requires
the separately authorized gateway import process.

Both reserve outputs must be unavailable to ordinary transfers, gateway
withdrawals and unrelated pool operations, even when the caller holds their
original owner's private key. Recording only the two balances is insufficient:
custody must bind the actual unspent outpoints and enforce their protocol locks.

Restoring state must authenticate the complete outer root and reconstruct the
locks from validated records. It must reject missing, duplicated, mismatched
or independently advanced reserve records. An inner ledger snapshot is not a
replacement for the complete paired state.

## Remaining market integration

Pair funding alone must not issue LP or authorize withdrawals. A subsequent
implementation must bind both reserves to the same AMM transition, check each
asset's conservation, update authenticated LP positions and advance both
reserve outpoints atomically. BLCH fees require separate funding and cannot
silently reduce pool backing. Wallet signing, bounded network decoding, block
fee settlement, consensus commitments and replay/reorg integration remain
separate requirements before activation.

Closing also requires a shared private settlement boundary. `PoolLedger` lives
in `bloch-euvm`, while the real BLCH planner lives in `bloch-pos-committee`.
Adding a public native release plan would allow that plan to be committed
independently of the BLCH leg in a separately restored native state. Before
adding close, move the privileged planners behind one concrete sealed backend;
do not substitute a caller-supplied commitment, verifier or callback for that
ownership boundary. The binary transport deliberately supports creation only.

## Verification

```sh
cargo +1.94.1 test --locked -p bloch-pos-committee --features native-dex-rehearsal --lib native_dex
cargo +1.94.1 test --locked -p bloch-ustav --test paired_custody_crypto
```

The cryptographic integration tests use ephemeral real hybrid PQ keys and a
locally issued test token. They exercise both ML-DSA and Falcon signature
tampering, standalone-leg signatures, signed but unbalanced legs, replay,
locked-owner spending, exact fee conservation and complete state restoration.
They neither deposit external USDT nor demonstrate live network readiness.
