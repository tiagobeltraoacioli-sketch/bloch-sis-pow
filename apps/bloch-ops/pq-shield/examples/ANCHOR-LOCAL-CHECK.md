# PQ Shield local anchor check

From a checkout of this repository, with Node.js 18+, Rust and Cargo:

```sh
node apps/bloch-ops/pq-shield/examples/run-anchor-positive-local.mjs
```

The runner builds the checked-out `services/pq-shield-api` Rust service,
starts its binary on an ephemeral `127.0.0.1` port, waits for `/health`, runs
`anchor-positive-check.mjs`, and stops the service in a `finally` block.
Cargo builds the signer and service in the system temporary directory. Run the
command from any working directory; the scripts resolve paths from their own
locations. The runner requires the complete repository, including the local
`bloch-pq-vault` and `bloch-crypto` crates. Downloaded example files alone
cannot build those dependencies.

The fixture derives disposable keys from published seeds. The check requires
matching canonical commitment bytes and verifies the valid signature in both
field and serialized forms. It rejects a changed safe destination, a changed
policy commitment, and a signature checked against a different enrolled test
public key. The test key is provisionally treated as enrolled **only inside
this local check**. A real verifier needs an independently authenticated
enrollment source.

This is a local reference test. It uses fake regtest addresses and no funded
UTXO, Bitcoin signing, broadcast, or Bloch consensus anchor enforcement.
