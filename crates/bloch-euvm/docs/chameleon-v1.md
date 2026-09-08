# Color-Changing Chameleon v1: native escrow and Ethereum representation

Status: executable reference implementation for one unrestricted Ustav test
asset per Ethereum route. The native kernel is not consensus-wired. The Ethereum
adapter runs in a local EVM; no live bridge is deployed. Native BLCH integration,
Solana and production finality verification remain separate work.

The original token retains its native identity and backing. A destination
adapter creates a representation in that environment's token standard. No token
rewrites its own code or automatically discovers a safe foreign execution model.

## Authorization boundary

Every native registration, route enablement, issuance, export and return claim
uses the existing ML-DSA-65 **AND** Falcon-1024 verifier. There is no ECDSA native
fallback. The ordinary native transfer path cannot spend an escrow output.
ECDSA wallet compatibility remains in `bloch-l2-evm` and external EVM accounts.

The ERC-20 holder has the destination chain's security. Someone who steals that
holder's classical key can transfer the representation or burn it to their own
PQ recipient. Requiring a PQ claim on Bloch does not undo that theft. Authentic
foreign checkpoints and the configured export verifier are additional trust
requirements for exported backing; native PQ authorization alone cannot prove
a foreign burn happened.

## Implemented components

| Component | Location and behavior |
| --- | --- |
| Combined native state | `ustav::chameleon::ChameleonLedger` owns the native ledger, route registry, escrow map, export records and permanent return nullifiers. |
| Route admission | Issuer PQ authorization binds origin domain, asset, EVM chain ID, adapter address, decimals, cap, adapter version and actual deployed runtime hash. One route per asset, enabled before any issuance. No issuer reconfiguration entry point. |
| Kirpich compatibility profile | `kirpich::chameleon::audit_erc20`, profile version 1, adds `KRP-080` to the existing native audit when a policy cannot be preserved. Native ruleset version 2 and Ustav v3 asset hashes are unchanged. |
| Export | `export` runs the native transition under a PQ authorization digest binding destination, route, nonce, transaction and selected lock output. The selected output remains in native supply but becomes unavailable for normal spending. |
| Ethereum representation | `bloch-l2-bridge/contracts/chameleon/ChameleonERC20.sol`, OpenZeppelin ERC-20 with authenticated permissionless mint relay, nonce replay protection, cap, caller-only burns and a typed burn tree. |
| Return | `claim` verifies burn inclusion against a separately supplied trusted checkpoint, the destination PQ public-key hash, a PQ claim signature, expiry and route-specific backing. Any residual escrow output remains locked. |
| Recovery | `snapshot` and `restore` authenticate the combined state commitment, including locks and nullifiers. A bare native ledger root is insufficient. |

The compatibility profile admits exactly one Supply module and no KYC root.
TransferPolicy, ComplianceKycGate, Vesting, Governance and historical Custody
require a preserving adapter; v1 rejects them. It also rejects malformed native
charters. This is a deterministic static policy audit, not an independent
security audit of deployed contracts, checkpoint truth or consensus integration.

## Native API sequence

1. Construct `ChameleonLedger` with the authenticated origin domain and register
   a new unrestricted Ustav charter with the issuer's PQ signature.
2. Deploy and inspect the destination adapter and immutable verifier. Resolve
   the actual runtime hash and route parameters. The issuer signs
   `EvmRoute::enable_hash`; call `enable` before issuance.
3. Mint the native asset using the ordinary PQ-authorized Supply path.
4. Owners sign `ExportRequest::signing_hash`, then call `export`. Signing the
   bare `Transaction::signing_hash` does not authorize export.
5. A host authenticates the combined native state and its export root. A relayer
   supplies the export record and inclusion proof to `mintExport`; the committed
   recipient receives the representation regardless of who relays it.
6. A destination holder calls `returnToBloch(amount, sha256(full_pq_public_key))`.
   The burn reduces ERC-20 supply and commits the recipient hash in the burn tree.
7. An independent host authenticates the adapter's burn root, count, block and
   actual code identity. The recipient signs `ReturnClaim::signing_hash` over
   the burn, full PQ key, sorted unique escrow inputs and expiry. `claim` releases
   the amount exactly once and keeps any escrow change locked.

`native()` is read-only for inspection. A node must route *all* asset transitions
through the combined ledger and persist its root atomically. Reconstructing or
cloning a bare `Ledger` and treating it as authoritative would discard Chameleon
locks. The reference API cannot stop a host from deliberately using the wrong
state machine. There is no live-node activation or migration in this change.

## Checkpoint trust is explicit

`TrustedBurnCheckpoint` is a host input, separate from the untrusted claim and
proof. Never deserialize a claimant's chosen root into this trusted role. The
host must authenticate chain identity, canonical finalized block, registered
adapter address, runtime code, root and leaf count together. A correct Merkle
proof against an arbitrary root proves no backing entitlement.

The local Ethereum fixture uses `FrozenExportRootVerifier`: its installer is
trusted for one immutable root/count. It performs real inclusion verification
but no Bloch finality verification. The Rust/EVM example obtains the return
checkpoint from an actual local EVM execution, explicitly trusted for the test.
It uses a labeled local block marker, not a purported Ethereum finalized block.

A runtime hash alone does not freeze the semantics of a proxy whose implementation
or controlling storage can change. The supplied verifier is immutable, with no
proxy or update mechanism. Production route approval must validate the entire
verifier design and authenticate deployment storage as applicable. Kirpich's
charter profile does not perform that deployment review.

## Wire commitments

Cross-runtime IDs use **single SHA-256** over concatenated 32-byte ABI words.
ASCII domain tags are right-padded with zero bytes; unsigned integers and
20-byte EVM addresses are left-padded, with integers in big-endian order.

| ID | ABI words, in order |
| --- | --- |
| Route | `BLOCH-CHAMELEON-ROUTE-v1`, origin domain, asset, chain ID, adapter address, decimals, cap, adapter version `1` |
| Enable | `BLOCH-CHAMELEON-ENABLE-v1`, route ID, actual adapter runtime hash |
| Export | `BLOCH-CHAMELEON-EXPORT-v1`, route ID, nonce, recipient, amount, native transaction hash |
| Burn | `BLOCH-CHAMELEON-BURN-v1`, route ID, nonce, sender, amount, SHA-256 of the full PQ public key |

The runtime hash is separately bound by enablement, rather than included in the
route ID, to avoid a circular dependency with immutable deployment bytes. Native
export and claim authorization use the existing length-prefixed SHA-256d
`HashWriter`, with distinct `CHAMELEON-EXPORT-AUTH-v1` and
`CHAMELEON-RETURN-AUTH-v1` tags. They are not Ethereum personal-sign messages.

Trees are ordered, depth 32: leaf `SHA256(0x00 || id)`, parent
`SHA256(0x01 || left || right)`, empty leaf `SHA256(0x02)`. The authenticated
checkpoint supplies the count separately; a proof must have `index < count`
and `0 < count <= 2^32 - 1`. Export indices are global insertion positions,
whereas export nonces are per route. Burn nonce is the adapter's tree index.
The EVM export proof is ABI `(uint64 index, bytes32[32] siblings)`, exactly
1056 bytes. Existing v1 BLCH bridge Keccak leaves are a different protocol.

## Accounting and bounds

Amounts remain origin atomic units. Decimals are display metadata, limited to
0..18. There is no rebase, transfer fee, decimal conversion or rounding. Mint and
burn of representations do not change native supply. A return moves existing
backing to a spendable PQ output; it does not issue a new native token.

For each route, `locked = cumulative_exports - cumulative_native_returns`.
With authenticated checkpoints and valid exports,
`locked = ERC20_supply + pending_mints + pending_native_returns`.
A delayed proof keeps backing locked. There is no timeout refund that could
race a previously minted representation.

Reference limits: 32 routes, 65,536 export records and 65,536 return nullifiers
per combined ledger; native input/output/key/signature limits also apply. The
EVM burn tree accepts at most `2^32 - 1` leaves. Native operations bound work and
charge protocol gas units for authorization, proof hashing and escrow lookups.
These are not calibrated live-node performance claims. Archival compaction and
scalable persistence need a versioned design that preserves replay protection;
operators must not clear counters or nullifiers to evade limits.

## Reproducible validation

```sh
cargo +1.94.1 test --locked -p bloch-euvm -p bloch-ustav
cargo +1.94.1 test --locked --release -p bloch-euvm -p bloch-ustav \
  --test ustav_kernel --test crypto_kernel --test chameleon --test chameleon_crypto
python3 scripts/check-ustav-pq-boundary.py cargo +1.94.1
FORGE=/absolute/path/to/forge SOLC=/absolute/path/to/solc \
  cargo +1.94.1 run --locked -p bloch-ustav --example chameleon_roundtrip \
  -- /absolute/path/to/bloch-l2-bridge
```

Use the matching Chameleon bridge implementation, Foundry 1.3.1 and solc 0.8.24.
The roundtrip creates fresh ephemeral PQ keys and only public fixture files in
the bridge's ignored `out/chameleon-roundtrip` directory. Stage 0 determines
actual deployment identity without minting. Native PQ enable/mint/export then
succeed before stage 1 recreates that exact deployment and runs ERC-20
mint/approval/transfer/burn. Rust verifies the resulting burn root, rejects each
corrupted PQ signature leg, claims backing and rejects replay after restoration.

The committed `test-vectors/chameleon-v1.json` is shared with the bridge. An
independent standard-library Python implementation there checks ABI padding,
domain tags and tree roots. Rust and Solidity compare against the same fixture.

## Remaining development gates

| Priority | Work and acceptance condition |
| --- | --- |
| 1 | Production export and burn checkpoint authentication: verify the actual consensus protocols and finalized state, bind the combined native root, chain/address/code/count, and reject conflicting or stale views. An operator checkpoint must remain explicitly labeled trusted. |
| 2 | Genesis-4 integration: versioned transaction encoding, consensus activation, deterministic gas calibration, atomic database updates, restart/rollback testing, and authenticated state migration. Every native asset path must enforce escrow locks. |
| 3 | Operational bridge host: durable relay queues, idempotent delivery, data availability, fault recovery, reserve/pending accounting, proof generation and route deployment review. No ad-hoc refund or admin-mint bypass. |
| 4 | Wallet and application integration: validated PQ recipient handoff, MetaMask token discovery and transactions on a deployed test network, then actual Uniswap/PancakeSwap pool tests and chain-specific liquidity/router support. ERC-20 conformance does not establish universal application support. |
| 5 | Native BLCH: connect escrow to the protocol's native balance and supply rules. Registering an issuer-controlled Ustav called BLCH is not native BLCH support. |
| 6 | Policy-rich Ustav and Solana: explicit preserving adapters and separate capabilities. SPL/Token-2022 support needs its own program, account model, authenticated checkpoints and DEX tests; it is not implemented by the EVM adapter. |
| 7 | Independent security review and economic/reorganization testing before any real-value deployment. Passing Kirpich and regression tests does not replace that review. |
