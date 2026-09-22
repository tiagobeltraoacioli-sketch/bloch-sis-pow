# Wave 151 — KDF ownership, queue charging and integrity integration

Date: 2026-09-19
Integration head before this report: `9442dd3e`

## Integrated corrections

- Wave 148 writes the HD master-key KDF salt directly into a
  `Zeroizing<[u8; 32]>`, preserving the versioned domains, exact salt bytes,
  Argon2 parameters and derived keys while removing the ordinary heap owner.
- Wave 149 charges queued blocks with the shared exact encoded-length
  authority instead of serializing and copying a complete second envelope
  solely to obtain its length.
- Wave 150 rejects failed or malformed checksum observations in the legacy
  same-path double-build integrity guard before it can compare the values or
  claim determinism.

Independent reviews verified KDF byte parity, owned salt lifetime, canonical
encoder/length parity, saturation and quota behavior, checksum error
propagation through `pipefail`, and isolation of the full-mode selftest from an
ambient adversarial SHA mode. The hermeticity issue found during review was
fixed before Wave 150 was committed.

## Validation

```text
cargo test -p bloch-crypto --features wallet-cli --offline
# 240 passed; 0 failed; 4 ignored

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 595 passed; 0 failed; 19 ignored; 64.09s

bash -n scripts/pos-release-integrity.sh
python3 -m py_compile scripts/pos-release-integrity.selftest.py
python3 scripts/pos-release-integrity.selftest.py
# PASS, including canonical plus five adversarial SHA modes
```

The complete crypto and node suites ran outside the restricted sandbox so
their localhost fixtures could bind. The integrity selftest uses fake build
tools to exercise the real guard and does not constitute an authenticated
independent build.

The findings ledger remains 200 rows with 200 unique IDs and unchanged status
counts. CR-07, EN-08 and INF-01 remain `PARTIAL`, with the new reports linked
and their backend, protocol/fairness and external-provenance residuals intact.

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
