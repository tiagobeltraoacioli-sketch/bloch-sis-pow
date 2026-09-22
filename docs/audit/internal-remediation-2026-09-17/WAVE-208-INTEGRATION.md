# Wave 208 — integration of immutable signing, cache caps and load lifetimes

Date: 2026-09-19
Integration head: `be936df7`

## Integrated corrections

- `712c9ded` makes the image-signing wrapper reject mutable tag-only and
  malformed references before key inspection, requires an exact lowercase
  SHA-256 digest-qualified image reference and passes that same identity to
  Cosign sign, verify and triangulate.
- `be936df7` caps the libp2p recent-block suppression map at 4,096 distinct
  fixed-size IDs. Existing IDs still refresh at capacity; a distinct overflow
  ID is not retained and cannot evict retained suppression state. The outbound
  suppression caller treats that unremembered ID as fresh and follows its
  existing publication path, while inbound event and engine-verdict handling
  remain unchanged.
- `a5a902c7` moves each authenticated HD per-address keypair plaintext into a
  consuming decode helper, dropping the parsed view and complete zeroizing
  plaintext before address authentication and derived-key regeneration.

INF-20, EN-08 and CR-07 remain `PARTIAL`. The changes close repository-local
residuals without claiming registry provenance, peer fairness, exact heap/RSS
or complete secret erasure.

## Validation

```text
bash -n deploy/attestation/sign-image.sh deploy/attestation/sign-image.selftest.sh
bash deploy/attestation/sign-image.selftest.sh
bash -c 'umask 000; bash deploy/attestation/sign-image.selftest.sh'
# passed

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 614 passed; 0 failed; 19 ignored; 61.62s

cargo test -p bloch-crypto --features wallet-cli --offline
# library 247 passed; 0 failed; 2 ignored; integrations 6 passed; 0 failed;
# doc tests 0 failed; 2 ignored; aggregate 253 passed; 0 failed; 4 ignored

git diff --check
# clean
```

The node and final crypto suites ran outside the restricted sandbox because
their transport/HTTP fixtures bind localhost sockets. The Cosign validation
used only the hermetic fake executable; no registry access or real signing was
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
