# Bloch network integration boundary — draft v1

The DevKit is a local development product. “Integrable” means its runtime
boundary and artifacts are explicit and replaceable; it does not mean the
current Genesis-4 node accepts EVM or SVM execution. No consensus change is
made by this package.

## Existing authorization decision

ADR-040, amended 2026-09-08, keeps native L1 authorization post-quantum and
places standard ECDSA wallet compatibility at L2. Preserve that boundary.
Solana Ed25519 accounts likewise do not authorize native Bloch transactions.
The proposed SVM network adapter requires a separate execution specification.

## Concrete components

| Component | Available now | Network adapter requirement |
|---|---|---|
| EVM developer node | Anvil JSON-RPC, Cancun, chain 31337 | Use `bloch-l2-evm` signed execution and witness verification; wire its prescribed node/RPC stack |
| Solana developer node | Agave test-validator, SBF, local ledger | Pin Agave execution features, account loading, sysvars, compute budget and deterministic replay |
| Export | `bloch.vm.observation/1` JSON and offline digest check | Derive authenticated execution batches from original signed transactions and account witnesses |
| Bloch connector | Interface requirements in this document | Genesis-4 finalized source verification, PQ signing, persisted derivation cursor and reorg recovery |
| Settlement | None | Define and implement validity verification, data availability and replay protection |
| Asset movement | None | Authenticated escrow, exact scaling, independent withdrawal verification and supply conservation |

Anvil blocks must **not** be imported directly into `bloch-l2-evm`: its base-fee
rules, deposit provenance and supply ledger differ. Use original signed
transactions with the Bloch engine's own `BlockContext` and authenticated
derivation. The retired Genesis-3 anchoring scaffold is not a Genesis-4
connector and must not be used as one.

## Observation wire contract (implemented)

Outer object: `{"payload": {...}, "sha256": "64 lowercase hex digits"}`.
The digest is SHA-256 of ASCII `BLOCH-DEVKIT-OBSERVATION-V1`, a zero byte, then
canonical payload JSON (keys sorted, compact separators, ASCII escapes,
non-finite numbers rejected). Limits are 16 MiB per RPC response/import.
Schema: `bloch.vm.observation/1`; mode: `local-development`.

EVM observations include chain ID, genesis block hash and the latest full block
from `eth_getBlockByNumber`. SVM observations include genesis hash, finalized
slot and a base64-encoded full-transaction block from `getBlock`. A Solana block
hash is **not an account state root**. A matching digest authenticates neither
the RPC source nor its execution; anyone can create a matching file.

## Proposed connector contract (not implemented)

Each VM adapter must implement `execute(parent, signed_batch, derivation) ->
receipt`, `verify(receipt, witness, expected_parent)`, `checkpoint()` and
`restore(checkpoint)`. Every receipt must bind:

- Protocol version, VM kind, exact runtime build/features, execution chain ID
  or genesis identity and expected Bloch genesis identity.
- Previous receipt hash, monotonic batch number, transaction-order commitment,
  before/after state commitment and data-availability reference.
- Source finalized Bloch checkpoint and authenticated deposit cursor; execution
  cannot turn an RPC-provided deposit claim into spendable credit.
- Deterministic results, resource usage and failure semantics. Failed batches
  leave the previous state unchanged.

The Bloch transport consumes only verified receipts under an activated network
profile. It must not accept local observation files as receipts. Native
transactions require the existing PQ signer; EVM/SVM keys never substitute for
it. Anchoring a digest alone does not verify a transition or secure a withdrawal.

## Acceptance sequence

1. Local starter deploy/call and persistence tests on supported machines.
2. EVM signed-batch replay with the existing Bloch L2 engine; SVM deterministic
   replay including account ownership/signature failures and budget exhaustion.
3. A dedicated integration devnet with source identity checks, duplicate batch
   rejection, crash recovery, data-unavailability rejection and reorg rollback.
4. Independent verification of deposits/withdrawals and supply invariants;
   only then define a network activation proposal and deployment procedure.

The SVM network design, connector, settlement verification and bridge remain
work items. No activation height, production chain ID or endpoint is invented.
