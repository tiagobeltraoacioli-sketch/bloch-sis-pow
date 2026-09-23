# Installed-package smoke verification

Build a tarball with `npm pack`, then verify the exact artifact that will be
distributed. The verifier installs it into a temporary empty project with a
fresh npm cache and offline mode, imports it by its package name, checks its
required files and version, creates and recovers a local wallet, and signs a
transfer using mocked RPC responses. It does not broadcast or contact a node.

```sh
node scripts/verify-installed-package.mjs \
  ../../apps/bloch-ops/wallets/downloads/blochprotocol-genesis4-sdk-0.1.13.tgz \
  0.1.13
```

Run it from `sdk/genesis4-js`. Pass the expected version explicitly; a version
mismatch, missing package file, failed import, or failed signing exits nonzero.
The generated mnemonic and signed transaction stay in the temporary process and
are not printed. The temporary project is removed on success or failure.
