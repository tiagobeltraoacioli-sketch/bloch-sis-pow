# Ustav v3: PQ-only native authorization

`bloch-ustav` connects the sealed native-token ledger in `bloch-euvm::ustav`
to Bloch's existing ML-DSA-65/Falcon-1024 verifier. Every native authorization
requires both PQ signatures. Native custody uses PQ Governance quorums.
The host interface has no ECDSA callback, and the native crate has no k256 dependency.
Registration, minting, transfers, burns and policy updates are executable locally.
This crate is a workspace member; it is not a dependency of the live Genesis-4 node.

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
python3 scripts/check-ustav-pq-boundary.py cargo +1.94.1
```

The example uses fresh ephemeral keys and demonstrates supply conservation,
spent-input replay rejection, snapshot restoration and burning. It does not
connect to a chain or persist keys.

See [the kernel contract](../bloch-euvm/docs/ustav-kernel.md) for the operation
matrix, signing format, limits, compatibility boundary and required node/L2 work.
