# Wave 159 — keyfile ownership, orphan accounting and export-tree integration

Date: 2026-09-19
Integration head before this report: `49e7ed35`

## Integrated corrections

- Wave 156 keeps the repository's v1 keyfile decrypt success path under
  `Zeroizing<Vec<u8>>` through the internal loader handoff to final
  `KeyMaterial`, while preserving the public `Vec<u8>` compatibility API.
- Wave 157 computes the waiting/deferred orphan byte charge once per
  admission and subtracts each FIFO-evicted entry's cached exact charge,
  removing the repeated full-queue sum without changing reachable admission,
  eviction, fairness or recovery behavior.
- Wave 158 requires the canonical container wrapper's top-level export tree
  to contain exactly `bloch-pos`, `SHA256SUMS` and `BUILD-INFO` before it
  consumes or publishes any artifact.

Independent reviews verified ownership and API parity, exact reachable-state
accounting and the 249-eviction adversarial fixture, and newline-safe export
cardinality with fail-closed traversal and artifact-type checks. The reviews
also confirmed that the public v1 secret owner, remaining bounded queue scans,
hard-link/bind-mount aliasing and post-check mutation remain explicit limits.

## Validation

```text
cargo test -p bloch-crypto --features wallet-cli --offline
# 242 passed; 0 failed; 4 ignored

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 598 passed; 0 failed; 19 ignored; 59.70s

bash -n scripts/build-pos-release-container.sh
bash -n scripts/build-pos-release-container.selftest.sh
bash scripts/build-pos-release-container.selftest.sh
# build-pos-release-container selftest: PASS
```

The full crypto and node suites ran outside the restricted sandbox so their
localhost fixtures could bind. The wrapper selftest uses a fake container
engine and does not supply independent build or provenance evidence.

The findings ledger remains 200 rows with 200 unique IDs and unchanged status
counts: 71 `IMPLEMENTED`, 98 `PARTIAL`, 15 `UNARMED CANDIDATE`, five
`PROTOCOL DECISION`, seven `BASE CHANGED`, one `OPEN`, one
`REFUTED IN AUDIT` and two `VERIFIED POSITIVE`. CR-07, EN-08 and INF-01 remain
`PARTIAL`.

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
