# Wave 204 — integration of key modes, expiry hints and secret lifetimes

Date: 2026-09-19
Integration head: `5c5d581d`

## Integrated corrections

- `90a70267` requires the validated private Cosign key to have POSIX mode
  `0400` or `0600`, using GNU `stat` with a BSD/macOS fallback and failing
  closed on command failure or malformed output.
- `5c5d581d` adds a conservative recent-block expiry hint so inbound
  observations and outbound re-gossip suppression skip premature full-map
  expiry scans; refreshing an ID can leave the hint early, causing one extra
  safe full-map scan without delaying expiry.
- `10aa73a7` moves HD address-save keypair serialization and encryption into a
  private ownership helper, dropping both the structured payload and zeroizing JSON
  before address and label metadata are serialized.

INF-20, EN-08 and CR-07 remain `PARTIAL`. These changes strengthen local
repository behavior without replacing external custody, provenance or release
evidence.

## Validation

```text
bash -n deploy/attestation/sign-image.sh deploy/attestation/sign-image.selftest.sh
bash deploy/attestation/sign-image.selftest.sh
bash -c 'umask 000; bash deploy/attestation/sign-image.selftest.sh'
# passed; 0400/0600 accepted; 0640/0644/0666, stat failure and malformed output rejected

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 613 passed; 0 failed; 19 ignored; 61.37s

cargo test -p bloch-crypto --features wallet-cli --offline
# library 246 passed; 0 failed; 2 ignored; integrations 6 passed; 0 failed;
# doc tests 0 failed; 2 ignored; aggregate 252 passed; 0 failed; 4 ignored

git diff --check
# clean
```

The final node and crypto suites ran outside the restricted sandbox because
their transport/HTTP fixtures bind localhost sockets. The Cosign selftest is
isolated and uses a fake `cosign` executable; its command-failure and
malformed-output cases use fake `stat` executables, while the canonical mode
cases exercise the host GNU/BSD `stat` contract. No real signing or registry
operation was performed.

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
