# Federated USDT gateway reference

`ustav::gateway::GatewayLedger` models Ethereum and TRON deposits into a native
six-decimal asset. This is reference kernel code, not an activated Genesis4
consensus feature. It does not deploy contracts, run relayers, verify external
consensus or create an operational BLCH/USDT AMM.

## Authorization and accounting

### Read-only liability reconciliation

`GatewayLedger::liabilities(asset)` and the sealed host's
`GatewayView::liabilities(asset)` return the local native supply together with
every enabled route's cumulative imports, cumulative burns, outstanding claims,
release count and source identities. Routes are ordered by route ID; the query
reads at most `MAX_ROUTES` entries and does not clone import or release history.

For each route, outstanding claims equal imports minus burns and must fit the
route cap. Across the selected asset's routes, the sum must exactly equal the
native ledger supply. Arithmetic overflow, invalid route identity, inconsistent
domain or supply, and unknown assets are refused. Queries never mutate state,
authorize a mint, or mark a payout as completed. Cumulative counters use u128
because a long-lived bridge can import and burn more than one supply cap.

Burns remove circulating native tokens but create redemption obligations. This
ledger does not know which source payments have completed; **cumulative burns
must not be treated as paid redemptions or as the current unpaid amount**.
For an authenticated, consistently aligned pair of checkpoints, the source
obligation is outstanding native claims plus burns minus verified paid releases,
plus accepted deposits that have not yet been imported. Match individual release
identities before subtracting payments, and account for all enabled routes once.
Direct token donations cannot satisfy missing deposit records or create mint credit.

The report is a local accounting view, not a serialized RPC endpoint, source
proof, authenticated checkpoint, or complete cross-chain reconciliation. A host
must bind it to its verified native checkpoint and independently validate source
reserves, pending deposits and paid releases. Native execution remains behind
the existing rehearsal/host gates; this query does not activate live consensus.

### Supply authorization

A registered Supply-only asset can enable multiple source routes before its
first issuance. Each route pins source/native domains, token and vault addresses,
asset, six decimals, reserve cap, vault code hash and an independent sorted PQ
committee with a threshold of at least two. The issuer and committee authorize
configuration. Operators must authenticate constructor storage, transfer mode
and the source ECDSA committee as well as runtime code: a code hash alone does
not establish those facts.

The two source routes may share one native asset. Native units are fungible;
withdrawals against either source remain bounded by that route's imported units
minus units burned for that route. Both routes must be enabled before issuance.
This representation is bridge-backed USDT, not an issuer-native Bloch stablecoin.

Imports require issuer and route PQ quorum signatures over the complete source
event identity, deposit, expiry and native transaction. The single output must
match the deposit amount and SHA-256 of the recipient's admitted full PQ key.
Receiving does not require a recipient signature. Route nonces and source event
identities have permanent replay protection. Ordinary supply changes are rejected
for enabled assets; owner-authorized zero-delta transfers and pair settlement
remain available without committee approval.

Withdrawals require owner, issuer and route quorum signatures over the burn and
external destination. A successful burn creates a deterministic release record
and advances the route nonce. Failed authorization or native execution commits
neither balances nor bridge accounting. Source payment is a separate operation:
the source committee must verify the finalized native burn before signing it.

Snapshots commit native state, route configuration, counters, imports and
releases. Restore checks canonical ordering, replay identities, sequential
release nonces, reconstructed reserve totals and agreement with native supply
and mint counters. Applications must use the gateway transition boundary and
persist its complete state; exposing an independent mutable native ledger would
discard these protections.

## Source contract interoperability

The [bounded native transport](usdt-gateway-wire.md) carries complete import and
withdrawal requests and witnesses into the sealed gateway dispatcher. It remains
a reference integration boundary, not an activated network endpoint.

The companion `bloch-l2-bridge/contracts/usdt/USDTSourceVault.sol` uses identical
SHA-256 ABI-word route, deposit and release IDs. Independent Python, Solidity
and Rust fixtures verify these IDs and separation between source domains.
TRON addresses use the validated 20-byte VM payload. Route amount units are
uint64 with six decimals. The native certificate and source release signature
formats differ intentionally: native uses PQ signatures; the source vault uses
its documented EIP-191 ECDSA convention, including for the TRON route.

Source vault tests use local EVM execution. TRON compiler/runtime qualification
is still required. Configured TRON transfer handling checks exact sender and
recipient balance changes even when a successful token call returns false.

## Trust and launch requirements

When native AMM custody is enabled, use the outer
[PoolLedger boundary](native-pool-custody.md) for all operations and snapshots.
It owns the gateway and enforces reserve locks even on ordinary transfers and
bridge withdrawals. An extracted inner gateway is not an equivalent state.

This is federated attestation, not a trustless light client. A dishonest native
quorum plus issuer can attest nonexistent deposits; a dishonest source quorum
can authorize reserve theft. Committee unavailability and source-token freezes
can prevent redemption. Tests do not establish production finality or safety.

Before funds: integrate the complete gateway transition and persistence into
Genesis4 consensus, define bounded transaction/RPC admission, implement source
finality observers and independently operated signing services, qualify both
source deployments, and review operational recovery and key custody. The L1
BLCH base-asset adapter and AMM reserve/LP transitions also remain necessary for
the requested BLCH/USDT pool. The native pair reference alone is atomic exchange
of registered assets; it does not implement that pool or admit base BLCH.

Run `cargo +1.94.1 test --locked -p bloch-euvm -p bloch-ustav` and
`cargo +1.94.1 run --locked -p bloch-ustav --example usdt_gateway`.
The example uses ephemeral real PQ keys and simulated source attestations;
it never transfers real USDT.
