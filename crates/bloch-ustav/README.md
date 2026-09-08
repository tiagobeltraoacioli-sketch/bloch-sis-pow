# Ustav v2 reference kernel

`bloch-ustav` connects the sealed native-token ledger in `bloch-euvm::ustav`
to Bloch's existing ML-DSA-65/Falcon-1024 verifier and secp256k1 custody checks.
Registration, minting, transfers, burns and policy updates are executable locally.
This crate is a workspace member; it is not a dependency of the live Genesis-4 node.

```sh
cargo +1.94.1 test --locked -p bloch-euvm -p bloch-ustav
cargo +1.94.1 run --locked -p bloch-ustav --example lifecycle
```

The example uses fresh ephemeral keys and demonstrates supply conservation,
spent-input replay rejection, snapshot restoration and burning. It does not
connect to a chain or persist keys.

See [the kernel contract](../bloch-euvm/docs/ustav-kernel.md) for the operation
matrix, signing format, limits, compatibility boundary and required node/L2 work.
