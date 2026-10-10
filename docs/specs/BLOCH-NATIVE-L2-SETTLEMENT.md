# Native L2 settlement rehearsal

This implementation adds deterministic L2 settlement to the native block state
transition, with a real SP1 6.8.0 Groth16 verifier. Existing manifests do not
install a settlement policy. The shipping mempool refuses the new transaction.
No live network, funded bridge, checkpoint ceremony or RPC finality is activated.

## Committed rules

The experimental native transaction discriminator is `0x12` (originally `0x0E`;
moved 2026-10-10 because mainnet assigns `0x0E` to `FundedDelegate`), a new assignment
outside the historical `0x07..0x09` tombstones. Its encoding is exactly 979 bytes:
`tag || proof_policy[32] || settlement_public_values[590] || groth16_proof[356]`.
The public-value layout is the existing `BLOCH:EVM:SETTLEMENT:2` big-endian codec.
Truncation, suffixes and a wrong statement tag cannot decode. The native body
commitment covers the complete transaction, including the actual proof bytes.
The L2 predecessor commitment retains the existing experimental kernel formula;
it is distinct from the native transaction ID.

`CommittedState::configure_l2_genesis` installs a policy only at slot/epoch zero,
only once, and only when its native network/genesis match that state. No current
manifest calls this API. There is no RPC/local-config activation switch. A
future manifest binding or coordinated network upgrade requires its own review.
In particular, do not embed a genesis hash recursively into a new bound genesis.

The policy pins network/genesis, L2 domain/configuration/chain ID, all three guest
identities, the complete proof-policy identity and the initial L2 parent/root.
The policy, native height and entire accepted settlement are committed together
under new state component `0x1F`. When absent, this contributes no leaf: historical
roots remain unchanged. Native height advances once per accepted block, including
blocks with skipped slots. It is never inferred from the slot number.

Only an **empty native inbox** is supported. The source is derived from the actual
native parent ID, slot and committed height, policy identities, previous accepted
source and a versioned empty-inbox sentinel. It is not a proposer-supplied source
record or the experimental escrow tree. Every inbox/consumption counter must be
zero. This rule cannot authenticate deposits, mint bridged tokens or release funds.
Nonempty escrow support requires a separately specified native lock transition.

Every settlement must extend the stored L2 hash/state/number and predecessor
commitment exactly. Its source must match the native parent. The new L2 header,
post-state root and body commitment are accepted only through the pinned proof.
All checks precede publication. A failed block discards its provisional state;
reapplying the same block to the same parent yields the same child.

## Deterministic proof verification

`bloch-l2-proof` depends on the small verifier, not the SP1 SDK/prover. Its policy
pins the complete Groth16 wrapper key, the 356-byte transport, exact public values
and the SDK's circuit string `v6.1.0` (the circuit identity inside SDK 6.8.0).
The verifier receives the guest BN254 key from committed policy, compares it to
the statement, checks the full-key selector and performs real Groth16 verification.
Both `HybridVerifier` and the producer's `ProbeVerifier` execute this check.
An implementation that does not implement the proof method rejects by default.

At most one settlement is allowed per block, checked before proof verification.
It reserves the whole block gas budget and credits zero fees. This bounds proof
calls without inventing fees or issuance. Production sponsorship/pricing and
adversarial resource qualification remain release requirements.

## Qualification boundary

Tests cover the actual `StateTransition::apply_block`, committed roots, deterministic
replay, failed-proof rollback, parent/source/policy mismatches, zero-inbox limits,
fixed framing and the per-block verification budget. The native block-signature
fixture uses the existing deterministic test signature scheme. It is not evidence
of an operational validator quorum or finalized production checkpoint.

The retained `source-contract` fixture is a real Groth16 proof of synthetic source
data. The proof crate accepts it cryptographically and rejects changes to every
proof/public-value byte. Native consensus still refuses its unrecognized source.
A separate `native-empty` prover fixture uses context exported by the actual
native transition. Program and proof provenance are retained beside the fixtures.
The retained `native-empty` proof is generated with the pinned release Gnark
image and the unchanged settlement-V2 guest. It is persisted and reverified by
the SDK, then verified again by the native CPU verifier in `apply_block`.
The replay test checks identical child state, the accepted commitment and supply,
and rejects corrupted proof bytes even after rebuilding the block body/signature.
Its SP1 proof is genuine; the surrounding native validator signatures remain
deterministic test signatures. Cross-repository qualification separately compares
the exact public statement, predecessor commitment and full-wrapper-key policy.

The optional `BLOCH_NATIVE_RECOVERY_EXPORT` test output retains the exact accepted
header, native transaction and state root without exporting signing keys. L2's
native-only recovery now exercises those bytes with the real Groth16 verifier,
disposable ML-DSA/Falcon checkpoint quorums and persisted Reth replay. Its V5
records preserve the native envelope and reject normalization/downgrades. Those
WS signatures do not replace the native fixture's test proposer signatures or
establish an operational FFG quorum.

Deployment still requires reviewed native network/activation configuration,
validator replay and fault qualification, production checkpoint authority, durable
publication and Reth finality qualification. Decoding or verifying a proof alone
does not satisfy those requirements. No production readiness flag changes here.

## Settlement V3 and the user-transaction guard (2026-10-10, M2)

A V3 statement (`BLOCH:EVM:SETTLEMENT:3`, 766 bytes, 1155-byte transaction under
tags 0x12/0x13) may report `user_tx_count > 0`. Until L1 data availability (M3)
exists the native chain stores only hashes, so a settled user transaction could
not be rebuilt from L1. The verifier therefore refuses any V3 statement with
`user_tx_count > 0` with `Reject::UserTransactions` unless the build enables the
development feature `devnet-l2-user-txs` (which implies `devnet-l2-deposits`).
The check runs before the deposit and proof checks and never mutates state;
deposit-only V3 settlements (`user_tx_count = 0`) are accepted on every build.
`l2_settlement::USER_TRANSACTIONS_ENABLED` exposes the build's choice.
The 1155-byte frame is pinned by the shared vector in
`crates/bloch-pos-committee/tests/l2_settlement_v3_frame.rs`.

## L1 data availability for V3 user transactions (2026-10-10, M3)

Transaction `0x15` (`L2DataAvailability`, `transition/l2_da.rs`) publishes the
user-transaction batch of one unsettled L2 block in a native block. It is an
ordinary fee-paying eUTXO transaction: a hybrid PQ funding key signs the
witness-free intent (network domain, inputs, L2 chain id, L2 block number,
payload, change, declared size, tip) under `BLOCH:L2:DA:V1`, and pays
`fee_market::intrinsic_gas` (16 gas per declared byte plus one hybrid
verification per input) at the block base fee. Bounds:

| Bound | Value | Why |
|---|---|---|
| Payload | ≤ 114,688 bytes (`da::MAX_PAYLOAD_BYTES`) | with the largest envelope (≤ 16 inputs, key, signature) one DA transaction stays below the pre-V2 block byte target (128 KiB) |
| DA transactions per block | ≤ 4 (`da::MAX_PER_BLOCK`, consensus) | inclusion is a fee auction (like blobs); bounds the stored records |
| Retention | 1,024 native blocks | a record serves settlements in the next 1,024 blocks, then expires |
| Window | next 64 unsettled L2 blocks | stale or far-future batches are refused |
| Stored records | ≤ 4,100 × 48 bytes | `MAX_PER_BLOCK × (RETENTION + 1)` |

Payload: `count (u32 BE, ≥ 1)` then `count × (len (u32 BE, ≥ 1) || envelope)`,
the exact signed EIP-2718 envelopes of the L2 body in order, no trailing bytes.
Commitment: `keccak256("BLOCH:L2:DA:1" || chain_id u64 BE || l2_block_number u64 BE || payload)`.
The state stores only `(l2_number, commitment, inclusion height)`; the batch
bytes stay in the native block. Rejections: another L2 chain (`Chain`), settled
or beyond the window (`Number`), the same batch twice for a block
(`Duplicate`), malformed or oversize payload (`Payload`; oversize does not
decode), plus the usual eUTXO rules (inputs, ownership, conservation,
signature, declared size).

Settlement rule (V3): when `user_tx_count > 0`, `da_commitment` must equal a
retained record for the same L2 block number whose inclusion height is
strictly lower than the block applying the settlement (`Reject::DataUnavailable`
otherwise). A settlement reserves the whole block gas budget, so the "earlier
block" rule never depends on in-block ordering. When `user_tx_count == 0`,
`da_commitment` must be zero (`Reject::Reserved`). Accepting a settlement drops
every record for that and earlier L2 blocks. The M2.6 guard is unchanged: user
transactions (and therefore DA transactions) remain refused unless the build
enables `devnet-l2-user-txs`. `getl2settlement` lists the retained records under
`data_availability`. The offline `bloch-pos l2-da prepare|sign|inspect` tool
builds and signs the transaction. The shared vector
`crates/bloch-pos-committee/tests/fixtures/l2-da-v1` pins payload and
commitment against the L2 codec.

## L2 withdrawal root in settlement V3 (2026-10-10, M4)

The L2 outbox predeploy (`L2ToL1MessagePasser` at `0x4200…0102`,
`bloch_l2_evm::withdrawal`) burns each withdrawal's value out of the L2 supply
and appends one leaf to an append-only, depth-32 keccak tree:

* leaf: `keccak256("BLOCH:L2:WITHDRAW:1" || chain_id u64 BE || nonce u64 BE ||
  l1_recipient (32) || sats u64 BE)`, where `nonce` is the leaf index and
  `l1_recipient` the native owner script hash (SHA3-256 of the owner's hybrid
  public key, as in `TransferOutput::script_hash`);
* node: `keccak256(left || right)`; empty leaf: 32 zero bytes; empty tree root
  `27ae5ba08d7291c96c8cbddcc148bf48a6d68c7974b94356f53754ef6171d757`
  (`l2_settlement::withdrawal::empty_root`).

A V3 statement now carries, at offsets 672 and 704 after the tag, the tree's
root and leaf count after its L2 block (no longer reserved zero). Settlement
rule (V3): relative to the accepted head (the empty tree before any V3 head or
after a V2 head) the count must not decrease and the root must change exactly
when the count does (`Reject::Withdrawals`, checked before the proof, state
untouched). A settlement that adds leaves stores
`(l2_number, root, count, native height)` (`withdrawal::Record`,
`State::withdrawal_roots`). Retention: every record younger than
`withdrawal::RETENTION_BLOCKS` (1,024) native blocks plus the newest older
one, so once withdrawals exist a root at least that old is always available;
at most one settlement per native block, so ≤ 1,026 records × 56 bytes.
Committed bytes gain the section `BLOCH:NATIVE:L2:WITHDRAWAL-STATE:1` only when
records exist (states without withdrawals keep their bytes).
`getl2settlement.withdrawals` shows `{root, count}` of the head and the
retained `roots`. `withdrawal::root_from_proof` folds a leaf and its 32
bottom-up siblings into the root it proves, for the L1 claim (M5, not
implemented: no escrow is released here). The shared vectors
`crates/bloch-pos-committee/tests/fixtures/l2-withdrawal-v1` (identical copy
in bloch-l2-evm) pin the leaf, the empty root, trees of 1, 2, 3 and 1,000
leaves and proofs.
