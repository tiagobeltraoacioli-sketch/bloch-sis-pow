# Wave 80 CR-07: move authenticated HD-wallet metadata

Base: `83c2cf5`; branch `fix/internal-audit-20260917`.

## Residual addressed

After a wallet file passed its resource policy, authentication and key checks,
`load_internal` iterated over borrowed `HdAddress` records. Constructing the
live wallet cloned both the address and label strings from every record. Those
strings are controlled by the backup and already owned by the parsed wallet;
a large label could therefore create another equally large allocation during
the final conversion even though the source object was no longer needed.

## Change

The loader now consumes the parsed address vector after validation. Once an
individual record has passed address, keypair and mnemonic/index checks, a
small ownership-transfer helper moves its address and label buffers directly
into the returned `Keypair` tuple. The private and public key vectors were
already moved and remain so. The destination vector is allocated once at the
authenticated record count instead of growing incrementally.

No string contents, order, schema, ciphertext, key material, cryptographic
decision or compatibility entry point changed. This optimization applies to
both bounded and historical loaders because moving an already-owned value is
observationally identical to cloning it.

## Regression

The regression builds an authentic-shaped record with a 32 KiB label, records
the backing pointers of its address and label strings, and transfers it through
the same helper used by production load. Both pointers are identical in the
live tuple, proving ownership moved without allocating duplicate string
buffers. Index, imported status and key vectors are also pinned.

## Validation

- `cargo test -p bloch-crypto authenticated_address_metadata_moves_without_duplicate_buffers --offline`: passed.
- `cargo test -p bloch-crypto --offline`: library 202 passed, 0 failed, 2 ignored; integration tests 6 passed, 0 failed; doc tests 2 ignored. The complete run used the approved unsandboxed test prefix because three HTTP regressions bind loopback sockets.
- `git diff --check` on the wallet source and this report: passed.

## Residual risk

CR-07 remains `PARTIAL`. JSON deserialization must still allocate the original
strings, and public-listing callers intentionally retain the parsed metadata.
Explicit compatibility loaders can accept broader resource policies. Opaque
crypto-backend/register copies, caller-created clones and CR-08's opaque
ChaCha state remain outside this correction.
