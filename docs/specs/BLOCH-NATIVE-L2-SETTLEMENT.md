# Native L2 settlement rehearsal

This implementation adds deterministic L2 settlement to the native block state
transition, with a real SP1 6.8.0 Groth16 verifier. Existing manifests do not
install a settlement policy. The shipping mempool refuses the new transaction.
No live network, funded bridge, checkpoint ceremony or RPC finality is activated.

## Committed rules

The experimental native transaction discriminator is `0x0E`, a new assignment
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
