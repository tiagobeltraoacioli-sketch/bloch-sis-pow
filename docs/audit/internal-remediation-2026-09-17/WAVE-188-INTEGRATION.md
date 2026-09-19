# Wave 188 — integration of version, attestation and mnemonic ownership fixes

Date: 2026-09-19
Integration head: `0fe4afab`

## Integrated corrections

- `2f3102ac` makes the legacy integrity guard require an exact two-line,
  newline-terminated binary identity: a delimited captured commit followed by
  the canonical asserted-clean source digest line.
- `0fe4afab` prepares the canonical local-attestation frame from a borrow and
  then moves the typed attestation into its pool, removing the proportional
  hybrid-signature clone while preserving pool-before-broadcast order.
- `b8d2abd2` consumes and drops the authenticated HD mnemonic plaintext and
  parsed view immediately after comparison, then drops the canonical KDF copy
  before the address-decryption loop.

INF-01, EN-08 and CR-07 remain `PARTIAL`. The changes strengthen only local
repository behavior and evidence.

## Validation

```text
bash -n scripts/pos-release-integrity.sh
python3 -m py_compile scripts/pos-release-integrity.selftest.py
python3 -I scripts/pos-release-integrity.selftest.py
bash -c 'umask 000; python3 -I scripts/pos-release-integrity.selftest.py'
# syntax/compile clean; both selftest runs PASS

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 610 passed; 0 failed; 19 ignored; 61.59s

cargo test -p bloch-crypto --features wallet-cli --offline
# library 244 passed; 0 failed; 2 ignored; integrations 6 passed; 0 failed;
# doc tests 0 failed; 2 ignored; aggregate 250 passed; 0 failed; 4 ignored

git diff --check
# clean
```

The node and crypto suites ran outside the restricted sandbox because their
transport/HTTP fixtures bind localhost sockets. Independent review expanded
W185 coverage to pin an undelimited commit decoy, a missing final newline and
a trailing non-newline byte before the change was committed.

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
- the scratch-systemd rollback drill; and
- staged canary and fleet `/proc` digest evidence.

No binary was signed, published, deployed or released in this wave.
