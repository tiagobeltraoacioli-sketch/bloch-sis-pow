# Wave 139 — ownership, transport and rollback integration

Date: 2026-09-19
Integration head before this report: `fcaf50a9`

## Integrated corrections

This checkpoint integrates the following bounded, compatibility-preserving
remediations:

- Wave 130 streams the devnet transaction injector's typed prefix, tag and
  borrowed payload instead of constructing a proportional aggregate frame.
- Waves 131, 133 and 136 move repository-controlled wallet secret owners into
  zeroizing RAII immediately, including the current wallet constructors, the
  diversified secret intentionally discarded by address derivation and the
  legacy key generator.
- Wave 134 moves a typed local block's canonical payload allocation directly
  into libp2p gossipsub after duplicate suppression.
- Wave 137 validates every rollback-assembler SHA-256 observation as exactly
  one lowercase 64-hex digest. The final tarball is built and validated in the
  private work directory before publication.
- Wave 138 moves the canonical payload of an admitted transaction directly
  through the private libp2p command into the transaction gossip topic.

The block and discarded-diversified-secret changes share commit `9b0e006a`
because both already-approved path sets were staged concurrently. Two
independent reviews verified that the commit contains exactly the five
intended files and that `git show --check` is clean; history was not rewritten
solely to split the subject line.

## Validation

```text
cargo test -p bloch-crypto --features wallet-cli --offline
# 236 passed; 0 failed; 4 ignored

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 592 passed; 0 failed; 19 ignored; 60.66s

bash -n deploy/rollback/make-rollback-package.sh
bash -n deploy/rollback/make-rollback-package.selftest.sh
# passed

rollback SHA-256 adversarial harness
# 7 passed, including malformed output at the private-tarball observation
```

The full crypto and node suites ran outside the restricted sandbox so their
localhost tests could bind sockets. The rollback SHA contract was exercised
with a temporary non-signing fixture only; the complete disposable-key
selftest was not run locally because `minisign` is absent. That limitation is
not represented as release evidence.

The findings ledger remains 200 rows with 200 unique IDs and unchanged status
counts. EN-08, CR-07 and INF-09 remain `PARTIAL`; their new reports and residual
boundaries are linked from the corresponding rows.

## Release status

The binary is **not ready for release**. Local source corrections and tests do
not satisfy the external release gates. Readiness still requires, at minimum:

- two independently authenticated canonical Linux builds and comparison;
- hosted CI plus source, builder, image and tool provenance;
- signed and published release and rollback artifacts with independent
  approval;
- a fresh independently signed WS envelope, authenticated signer arrangement
  and distributed pin for SR-02/SR-03;
- a scratch-systemd rollback rehearsal; and
- staged canary and fleet `/proc` digest evidence.

No binary was built, signed, published or deployed by this wave.
