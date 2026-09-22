# Wave 196 — integration of rollback identity and bounded secret owners

Date: 2026-09-19
Integration head: `6fd34918`

## Integrated corrections

- `2633c8f9` makes the generated rollback installer validate the authenticated
  binary's first-line runtime stamp and post-execution digest both in
  `--verify-only` and on the installed copy before systemd changes.
- `6fd34918` adds an exact 16 MiB canonical-key budget to the node's local
  rejection cache alongside its existing 4,096-entry limit.
- `c259ebb5` confines legacy-keystore payload/plaintext owners to a private
  encryption helper and drops the derived encryption key before metadata
  serialization and file I/O.

INF-09, EN-08 and CR-07 remain `PARTIAL`. These are local hardening changes,
not substitutes for authenticated release and fleet evidence.

## Validation

```text
bash -n deploy/rollback/make-rollback-package.sh
bash -n deploy/rollback/make-rollback-package.selftest.sh
# passed; extracted generated install.sh also passed bash -n

# Focused generated installer helper:
# canonical accepted; exit, later-line decoy, embedded token and self-mutation refused

bash deploy/rollback/make-rollback-package.selftest.sh
# failed closed before key generation: minisign is not installed locally

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 611 passed; 0 failed; 19 ignored; 62.12s

cargo test -p bloch-crypto --features wallet-cli --offline
# library 245 passed; 0 failed; 2 ignored; integrations 6 passed; 0 failed;
# doc tests 0 failed; 2 ignored; aggregate 251 passed; 0 failed; 4 ignored

git diff --check
# clean
```

The node and crypto suites ran outside the restricted sandbox because their
transport/HTTP fixtures bind localhost sockets. The complete disposable-key
rollback selftest still requires an environment with `minisign`; focused
helper execution is not presented as equivalent evidence.

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
- the complete rollback-package selftest with `minisign` and scratch-systemd
  rollback drill; and
- staged canary and fleet `/proc` digest evidence.

No binary was signed, published, deployed or released in this wave.
