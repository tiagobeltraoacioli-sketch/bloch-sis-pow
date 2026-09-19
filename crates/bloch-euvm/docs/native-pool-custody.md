# Sealed native-token AMM custody reference

`ustav::gateway::pools::PoolLedger` owns the USDT gateway, native-token outputs,
pool reserve locks and PQ-owned LP positions as one state. It executes actual
registered-token debits and credits in the reference ledger; it is not just a
quote calculator. It rejects base BLCH until the real consensus UTXO adapter is
integrated. No live Genesis4 transaction type or activation is added here.

## Ownership and backing

Each admitted pool contains two registered assets with exactly one Supply
module and no KYC root. Additional policy modules are rejected because direct
protocol custody transfers must not bypass their restrictions. Pool creation
requires a real PQ signature binding its empty state and creator; existing pool
IDs cannot be replaced. Creating an empty pool creates no assets or LP shares.

An action binds the network, authenticated pool state root, revision, deadline,
complete AMM action, acting owner's full PQ key and sorted funding outpoints.
The signer must own every funding input. Input asset and amount are resolved
from the sealed ledger; the client cannot supply a prior balance. One verified
signature authenticates this single-owner operation, not unrelated outputs.

The AMM computes exact debits, credits and LP changes. The custody transition
consumes real funding outputs plus the pool's two authenticated reserve outputs,
then creates its two successor reserves and any change/payout outputs. Each
asset independently satisfies `old reserve + funding = new reserve + payout`.
No mint/burn is used to move reserves; native supply, mint counters and bridge
source liabilities remain unchanged. All arithmetic, authorization, position,
collision, capacity and gas checks precede the atomic commit. Staging is bounded
by the affected funding inputs and outputs rather than copying the full ledger.

Reserve outputs retain an admitted real PQ owner key, but the protocol lock
removes that key's ordinary spending authority. There is no fake pool key or
signature-verifier exemption. All public transfer, gateway import/withdraw and
pair paths reject locked inputs; actions cannot use a locked output as ordinary
funding. Only an authenticated AMM action can consume the corresponding pool's
reserve locks. Other pools cannot consume them.

LP balances are sealed `(pool ID, full PQ owner key)` positions. Initial
liquidity permanently locks 1,000 shares without an owner. Subsequent issuance
requires proportionate asset funding, and removal requires enough LP in the
signer's position. Pool-wide LP supply is not evidence of an individual user's
ownership. There is no arbitrary LP issuer or privileged reserve withdrawal.

## Queries and persistence

Use `spendable_output` for wallet balances; it omits locked reserves. Raw
read-only gateway queries include these outputs for accounting and must not
present them as available wallet funds. `position`, `pool` and `is_locked`
expose LP balances and custody separately. LP position queries reject oversized
keys before allocation.

The snapshot contains the complete gateway, pool snapshots, reserve outpoints
and canonical LP positions. The outer state root commits all of them with a
distinct versioned tag. Restore validates gateway backing, each pool identity
and arithmetic state, unique reserve locks with exact matching asset/amount,
valid owner keys and total circulating positions equal to LP supply minus the
permanently locked shares. Locks are reconstructed from validated reserve
records, not trusted as a separate caller-provided map.

The expected outer root must be authenticated by the host. Restoring an inner
gateway snapshot alone discards custody. `gateway()` is read-only query access;
a host must never clone/extract that state and accept its transitions as updates
to this ledger. Future network dispatch, replay, persistence and reorg must all
use the complete sealed boundary, not a mixture of inner and outer roots.

## Limits and remaining integration

The reference bounds pools to 128, LP positions to 65,536, and funding to each
native transaction input limit per asset. Keys and signatures retain native
size/admission limits. Gas covers signature verification, bounded key/input
processing and created outputs. These units are not a calibrated Genesis4 fee
schedule and do not collect live BLCH fees.

Gateway import/redemption envelopes use `apply_encoded_gateway`, preserving
the existing bounded wire format and decoding gas while retaining reserve locks.

The pure AMM's checked arithmetic and deliberate full-width swap limitations
remain documented in [native-amm.md](native-amm.md). The custody API accepts
typed requests and [bounded binary pool envelopes](native-pool-wire.md).
Network admission, fee sponsorship, real BLCH UTXO
integration, outer consensus commitments, replay/reorg integration and wallet
transaction support remain required. See the
[consensus plan](../../../docs/integration/BLOCH-L1-DEX-CONSENSUS-PLAN.md).

`plan_transfer` additionally prepares a zero-delta native transfer with an
exclusive borrow and a one-time infallible commit. Dropping the plan changes
nothing. This preserves all native charter and reserve-lock checks while
allowing the joint BLCH/native rehearsal to validate both legs before either
commits. It does not expose an arbitrary mutable ledger or mint authority.

Run the `native_pool_custody` and `native_pool_crypto` tests and the
`bloch-ustav --example native_pool` executable. The example uses ephemeral PQ
keys and local issued test assets, not live BLCH or externally deposited USDT.
