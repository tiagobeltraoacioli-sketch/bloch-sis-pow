# Wave 147 — HD ownership, inspection and wrapper integration

Date: 2026-09-19
Integration head before this report: `f299537f`

## Integrated corrections

- Wave 144 reuses one bounded raw-frame scratch allocation during operator
  and offline-repair log inspection. Existing cap, offset, truncation, issue
  text, valid-prefix accounting, read-only behavior and recovery authority are
  unchanged.
- Wave 145 moves every HD-derived private-key vector immediately into a
  zeroizing owner before address formation, then transfers the same allocation
  into the final wiping `Keypair` without cloning or reallocating it.
- Wave 146 makes the canonical-container wrapper reject checksum-command
  failure and any extracted digest field that is not exactly 64 lowercase
  hexadecimal characters before accepting exported manifest and metadata.

Each patch was reviewed independently from its author. The reviews verified
owned decoder outputs before scratch reuse, private-key allocation and byte
parity, checksum failure propagation through `pipefail`, isolation of the fake
engine from the adversarial PATH shim, and conservative residual claims.

## Validation

```text
cargo test -p bloch-crypto --features wallet-cli --offline
# 239 passed; 0 failed; 4 ignored

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 594 passed; 0 failed; 19 ignored; 67.71s

bash -n scripts/build-pos-release-container.sh
bash -n scripts/build-pos-release-container.selftest.sh
bash scripts/build-pos-release-container.selftest.sh
# build-pos-release-container selftest: PASS
```

The complete crypto and node suites ran outside the restricted sandbox so
their localhost fixtures could bind. The wrapper selftest uses its existing
fake container engine and does not constitute a real Linux reproducibility
build or independent builder evidence.

The findings ledger remains 200 rows with 200 unique IDs and unchanged status
counts. INF-01, NET-22 and CR-07 remain `PARTIAL`; the corresponding rows now
link Waves 146, 144 and 145 and preserve their external or invasive residuals.

## Release status

The binary is **not ready for release**. Remaining launch gates still include:

- two independently authenticated canonical Linux builds and comparison;
- hosted CI plus source, builder, image and tool provenance;
- signed and published release and rollback artifacts with independent
  approval;
- a fresh independently signed WS envelope, authenticated signer arrangement
  and distributed pin for SR-02/SR-03;
- a scratch-systemd rollback rehearsal; and
- staged canary and fleet `/proc` digest evidence.

No binary was built, signed, published or deployed by this wave.
