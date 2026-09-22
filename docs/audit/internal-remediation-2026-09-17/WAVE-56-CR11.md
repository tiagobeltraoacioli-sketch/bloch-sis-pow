# Wave 56 CR-11: official-key signing interoperability

Base: `4747cd6`; branch `agent/wave56-crypto`.

## Scope

CR-11 already pins official NIST ACVP ML-DSA-65 verification cases and Falcon
round-3 submission signatures. Its residual explicitly notes that the
production ML-DSA signing path is not standards-traceable evidence.

This wave adds one minimized fixture from NIST ACVP-Server's
`ML-DSA-keyGen-FIPS204` sample: group 2 (`ML-DSA-65`), test case 26. The
fixture retains the official seed and expected public/secret key encodings.
SHA-256 pins both complete upstream JSON sources and the extracted fixture;
the provenance document records the pinned upstream commit, byte counts,
digests, selection rule and exact evidentiary limit.

The regression parses the official public and secret key with the compiled
ML-DSA backend, signs a repository-chosen message through the production
signer, verifies through Bloch's empty-context raw wrapper, and rejects a
wrong message and mutated signature. No production source, signature format,
consensus rule, protocol rule, funded artifact or deployment changes.

## Validation

- `cargo test -p bloch-crypto --test acvp_mldsa`: 3/3 passed.
- `cargo test -p bloch-crypto` with local-socket permission: 186 library tests
  passed (2 ignored), all 6 integration tests passed, and 2 doctests were
  ignored.
- The extracted seed, public key and secret key were compared byte-for-byte
  against group 2 / test case 26 in the two pinned source documents.

## Evidence boundary and residual risk

This is official-key interoperability plus a locally generated randomized
signature. It is **not** a key-generation KAT: the official seed is retained
for traceability but is not fed to the backend and its generated outputs are
not compared. It is **not** a signing KAT or an official positive
empty-context signature vector: the signature is generated locally and has no
NIST expected byte value.

CR-11 remains `PARTIAL`. Exact official ML-DSA-65 key-generation and signing
KATs, an official positive empty-context verification case usable with its
public key, complete vector coverage, all architectures and ACVP/FIPS
certification remain outside this evidence. No external review or deployment
is claimed.
