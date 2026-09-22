# Wave 155 — attestation sizing, decrypt ownership and export integration

Date: 2026-09-19
Integration head before this report: `baccbdaa`

## Integrated corrections

- Wave 152 centralizes the exact attestation wire length and uses it for both
  envelope accounting and engine-queue charging, removing the proportional
  temporary signature copy.
- Wave 153 keeps successful HD-wallet plaintext under
  `Zeroizing<Vec<u8>>` across the private decrypt helper return and its two
  JSON consumers, without cloning or reallocating the decoded buffer.
- Wave 154 requires the canonical wrapper's `bloch-pos`, `SHA256SUMS` and
  `BUILD-INFO` exports to be regular non-symlink files before any wrapper-side
  consumption, preventing private-context links from becoming dangling
  published candidates.

Independent reviews verified the 128-byte fixed attestation formula and
encoder parity, transport reservation/release ordering, decrypt allocation and
AES/error parity, wrapper check ordering, and all stated residual boundaries.

## Validation

```text
cargo test -p bloch-crypto --features wallet-cli --offline
# 241 passed; 0 failed; 4 ignored

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 597 passed; 0 failed; 19 ignored; 63.19s

bash -n scripts/build-pos-release-container.sh
bash -n scripts/build-pos-release-container.selftest.sh
bash scripts/build-pos-release-container.selftest.sh
# build-pos-release-container selftest: PASS
```

The full crypto and node suites ran outside the restricted sandbox so their
localhost fixtures could bind. The wrapper selftest uses a fake container
engine and does not supply independent build or provenance evidence.

The findings ledger remains 200 rows with 200 unique IDs and unchanged status
counts. EN-08, CR-07 and INF-01 remain `PARTIAL`. Transaction queue sizing
still materializes canonical bytes because no allocation-free authority exists
without a broad consensus-codec refactor; hard-link/bind-mount aliasing,
post-check mutation and external release evidence also remain explicit.

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
