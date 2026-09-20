# Wave 200 — integration of signing boundaries and bounded cache work

Date: 2026-09-19
Integration head: `457e5268`

## Integrated corrections

- `7fc7eb24` requires the private Cosign key's resolved physical ancestor chain
  to contain no `.git` marker, rejects final symlinks and multiply-linked
  inodes, and passes only the validated physical path to `cosign`.
- `457e5268` adds a conservative rejection-expiry hint so new local retry bars
  skip full-cache expiry scans until the conservative lower-bound hint is
  reached; point removals may leave it early and cause one extra safe scan.
- `34d39ab6` moves legacy-keystore plaintext into a consuming parse/decode
  helper, dropping the complete authenticated JSON before address
  authentication and final keypair construction.

INF-20, EN-08 and CR-07 remain `PARTIAL`. These changes strengthen local
repository behavior without replacing key-custody or release evidence.

## Validation

```text
bash -n deploy/attestation/sign-image.sh deploy/attestation/sign-image.selftest.sh
bash deploy/attestation/sign-image.selftest.sh
bash -c 'umask 000; bash deploy/attestation/sign-image.selftest.sh'
# passed

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 612 passed; 0 failed; 19 ignored; 60.62s

cargo test -p bloch-crypto --features wallet-cli --offline
# library 245 passed; 0 failed; 2 ignored; integrations 6 passed; 0 failed;
# doc tests 0 failed; 2 ignored; aggregate 251 passed; 0 failed; 4 ignored

git diff --check
# clean
```

The node and final crypto suites ran outside the restricted sandbox because
their transport/HTTP fixtures bind localhost sockets. The Cosign selftest is
hermetic and uses a fake executable; no real signing or registry operation was
performed.

## Ledger state

The inventory remains 200 rows with 200 unique IDs and no duplicates:

- `IMPLEMENTED`: 71
- `PARTIAL`: 98
- `UNARMED CANDIDATE`: 15
- `PROTOCOL DECISION`: 5
- `BASE CHANGED`: 7
- `OPEN`: 1
- `REFUTED IN AUDIT`: 1
- `VERIFIED POSITIVE`: 2

## Release boundary

The MW binary is **not ready for launch**. Still required:

- two independently authenticated canonical Linux builds and comparison;
- hosted CI plus source, builder, image and tool provenance;
- real KMS/HSM-backed signing, signed and published release/rollback artifacts
  and independent approval;
- a fresh independently signed weak-subjectivity envelope, authenticated
  signer arrangement and distributed pin evidence (SR-02/SR-03);
- complete rollback-package and scratch-systemd rollback drills; and
- staged canary and fleet `/proc` digest evidence.

No binary or image was signed, published, deployed or released in this wave.
