# Ustav v3: PQ-only native authorization

`bloch-ustav` connects the sealed native-token ledger in `bloch-euvm::ustav`
to Bloch's existing ML-DSA-65/Falcon-1024 verifier. Every native authorization
requires both PQ signatures. Native custody uses PQ Governance quorums.
The host interface has no ECDSA callback, and the native crate has no k256 dependency.
Registration, minting, transfers, burns and policy updates are executable locally.
This crate is a workspace member; it is not a dependency of the live Genesis-4 node.

[Native pairs v1](../bloch-euvm/docs/native-pairs.md) adds jointly PQ-authorized,
atomic settlement between two registered native assets, including a future native
stablecoin. Both transfers commit together or neither commits. This is bilateral
settlement, not an AMM or a stablecoin peg. Base BLCH and live-node activation
remain outside this reference kernel.

[Native pool custody](../bloch-euvm/docs/native-pool-custody.md) executes local
Supply-only token AMM operations with locked reserve outputs and PQ-owned LP
positions. It preserves gateway liabilities and token supply. This separate
sealed boundary still rejects base BLCH and remains outside live consensus.

The test-only joint BLCH/native dependency explicitly enables the consensus
crate's optional [rehearsal](../../docs/integration/BLOCH-JOINT-NATIVE-REHEARSAL.md).
It verifies an atomic transfer with real hybrid signatures and committed BLCH
UTXOs. This does not enable native execution in default node builds or create
a live BLCH AMM pool. The same default-off state now supports
[initial BLCH/native liquidity](../bloch-pos-committee/docs/initial-blch-liquidity.md):
existing paired reserves back a sealed initial LP position, with the minimum
liquidity permanently locked. [Atomic BLCH/native swaps](../bloch-pos-committee/docs/atomic-blch-swaps.md)
and [proportional LP redemption](../bloch-pos-committee/docs/blch-lp-redemption.md)
now execute in this local rehearsal. [Additional liquidity](../bloch-pos-committee/docs/blch-liquidity-additions.md)
credits separate PQ-owned positions for up to 128 providers per pool. LP
transfers remain unimplemented. The [bounded pool lifecycle transport](../bloch-pos-committee/docs/pool-lifecycle-wire.md)
dispatches six binary request types through those same atomic methods, with
real PQ tests comparing encoded and direct execution. Node/RPC admission remains
separate. [Atomic candidate batches](../bloch-pos-committee/docs/pool-batches.md)
now validate ordered dependent operations against one parent and roll back all
changes on failure, including a forged later provider redemption in PQ tests.

[Color-Changing Chameleon v1](../bloch-euvm/docs/chameleon-v1.md) adds sealed
PQ-native escrow, an explicit Kirpich ERC-20 compatibility profile and an
executable Rust/EVM/Rust roundtrip with an unrestricted Ustav test asset.
It uses explicitly trusted local checkpoints; production finality verification,
native BLCH, Solana and live-node activation remain separate work.

ECDSA wallet compatibility belongs to the separate
[bloch-l2-evm](https://github.com/tiagobeltraoacioli-sketch/bloch-l2-evm) repository.
MetaMask/EVM accounts on L2 have classical security; using L2 does not make those
keys post-quantum. Historical EUVM classical scripts cannot enter this ledger.
Version 2 snapshots and classical Custody charters are rejected, without an
automatic conversion that could remove a required co-signer.

```sh
cargo +1.94.1 test --locked -p bloch-euvm -p bloch-ustav
cargo +1.94.1 run --locked -p bloch-ustav --example lifecycle
cargo +1.94.1 run --locked -p bloch-ustav --example native_pair
cargo +1.94.1 run --locked -p bloch-ustav --example native_pool
python3 scripts/check-ustav-pq-boundary.py cargo +1.94.1
```

The example uses fresh ephemeral keys and demonstrates supply conservation,
spent-input replay rejection, snapshot restoration and burning. It does not
connect to a chain or persist keys.

See [the kernel contract](../bloch-euvm/docs/ustav-kernel.md) for the operation
matrix, signing format, limits, compatibility boundary and required node/L2 work.
