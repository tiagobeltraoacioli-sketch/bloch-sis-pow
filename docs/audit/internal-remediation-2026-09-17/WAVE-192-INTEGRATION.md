# Wave 192 — integration of rollback and secret-owner reductions

Date: 2026-09-19
Integration head: `96cbdf67`

## Integrated corrections

- `7d0004bf` constrains the rollback stamp to one canonical version/commit
  token and, for runnable snapshots, matches that complete token only on the
  first `--version` line.
- `96cbdf67` moves authenticated held attestations out of the pending pool
  through its single index-cleanup authority, removing the signature clone at
  that extraction boundary.
- `ad1af743` confines the HD-save mnemonic payload and zeroizing serialized
  plaintext to a private encryption helper, dropping both before the address
  loop and final file write.

INF-09, EN-08 and CR-07 remain `PARTIAL`. These changes strengthen local
repository behavior and do not replace release, fleet or operational evidence.

## Validation

```text
bash -n deploy/rollback/make-rollback-package.sh
bash -n deploy/rollback/make-rollback-package.selftest.sh
# passed

# Focused rollback-stamp contract:
# canonical accepted; truncated, later-line decoy and embedded-token refused

bash deploy/rollback/make-rollback-package.selftest.sh
# failed closed before key generation: minisign is not installed locally

cargo test -p bloch-pos-committee --lib --offline
# 463 passed; 0 failed; 4 ignored; 98.61s

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 610 passed; 0 failed; 19 ignored; 61.38s

cargo test -p bloch-crypto --features wallet-cli --offline
# library 245 passed; 0 failed; 2 ignored; integrations 6 passed; 0 failed;
# doc tests 0 failed; 2 ignored; aggregate 251 passed; 0 failed; 4 ignored

git diff --check
# clean
```

The node and final crypto suites ran outside the restricted sandbox because
their transport/HTTP fixtures bind localhost sockets. The rollback package's
complete disposable-key selftest remains required in an environment with
`minisign`; focused expression tests are not presented as a substitute.

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
- signed and published release and rollback artifacts with independent
  approval;
- a fresh independently signed weak-subjectivity envelope, authenticated
  signer arrangement and distributed pin evidence (SR-02/SR-03);
- the scratch-systemd rollback drill, including a complete rollback-package
  selftest with `minisign`; and
- staged canary and fleet `/proc` digest evidence.

No binary was signed, published, deployed or released in this wave.
