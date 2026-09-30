# Installed-package smoke verification

Build a tarball with `npm pack`, then verify the exact artifact that will be
distributed. The verifier installs it into a temporary empty project with a
fresh npm cache and offline mode, imports it by its package name, checks its
required files and version, creates and recovers a local wallet, and signs
transfers using mocked RPC responses. It also verifies that mixed envelopes
and impossible deposit outpoints fail, and that an intact envelope reaches
only an injected in-memory submission callback. It never contacts a node.

```sh
node scripts/verify-installed-package.mjs \
  /path/to/blochprotocol-genesis4-sdk-0.1.14.tgz \
  0.1.14
```

Run it from `sdk/genesis4-js`. Pass the expected version explicitly; a version
mismatch, missing package file, failed import, or failed signing exits nonzero.
The generated mnemonic and signed transaction stay in the temporary process and
are not printed. The temporary project is removed on success or failure.

To check compatibility with the exact previous distribution, supply both local
tarballs after recording their SHA-256 hashes:

```sh
node scripts/verify-sdk-upgrade.mjs \
  /path/to/blochprotocol-genesis4-sdk-0.1.13.tgz \
  /path/to/blochprotocol-genesis4-sdk-0.1.14.tgz
```

This installs both artifacts into separate empty offline projects, checks the
public exports and unchanged signing core, then passes persisted synthetic
V1/V2 envelopes from 0.1.13 to 0.1.14. Explicit retries use the same bytes and
tracking only performs injected reads. Mocked admission and duplicate responses
do not establish actual node admission, durable idempotency or P2B adoption.
