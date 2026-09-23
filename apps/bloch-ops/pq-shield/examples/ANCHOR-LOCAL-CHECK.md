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

The runner also sends direct HTTP requests to the local Rust service. It
requires HTTP 400 and a structured error for top-level and nested
secret-shaped field names (using inert placeholder values), a signed anchor
without `trusted_pq_pubkey`, malformed serialized anchor bytes, a short
recovery hash, and a `csv_delay` above the `u16` range. A signature checked
against a different enrolled test key returns HTTP 200 with `valid: false`;
that is a verification result, not a malformed-request response. These are
bounded local checks, not proof that every invalid request is rejected.
The runner does not assert a maximum request-body size because this service
does not set an explicit body-size contract.

This is a local reference test. It uses fake regtest addresses and no funded
UTXO, Bitcoin signing, broadcast, or Bloch consensus anchor enforcement.
