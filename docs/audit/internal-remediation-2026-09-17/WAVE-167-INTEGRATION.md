# Wave 167 — refusal membership, disclosure bounds and hard-link integration

Date: 2026-09-19
Integration head before this report: `d93e91f7`

## Integrated corrections

- Wave 164 gives one finality-refusal update a bounded temporary identity
  index synchronized with every authoritative FIFO pop and append, removing a
  full parked-ID scan per branch envelope while preserving sequential
  skip/eviction/reappearance behavior.
- Wave 165 rejects disclosure public-key and signature Base64 strings beyond
  encoded limits derived from the existing decoded policies before asking the
  decoder to allocate proportional output. Existing decoded limits remain
  authoritative.
- Wave 166 requires each canonical wrapper export to have exactly one hard
  link before any artifact consumption, closing the reproduced external
  hard-link alias accepted by the wrapper.

Independent reviews verified the finality FIFO against the former sequential
oracle, including an initially present ID evicted and re-appended later in the
same branch; checked the padded-Base64 formulas and boundary behavior; and ran
the wrapper matrix normally and under `umask 000` with hard-link fixtures for
all three exported artifacts.

## Validation

```text
cargo test -p bloch-crypto --features wallet-cli --offline
# 244 passed; 0 failed; 4 ignored

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 600 passed; 0 failed; 19 ignored; 63.96s

bash -n scripts/build-pos-release-container.sh
bash -n scripts/build-pos-release-container.selftest.sh
bash scripts/build-pos-release-container.selftest.sh
bash -c 'umask 000; bash scripts/build-pos-release-container.selftest.sh'
# both complete selftest runs: PASS
```

The full crypto and node suites ran outside the restricted sandbox so their
localhost fixtures could bind. The wrapper selftests use a fake container
engine and do not supply independent build or provenance evidence.

The findings ledger remains 200 rows with 200 unique IDs and unchanged status
counts: 71 `IMPLEMENTED`, 98 `PARTIAL`, 15 `UNARMED CANDIDATE`, five
`PROTOCOL DECISION`, seven `BASE CHANGED`, one `OPEN`, one
`REFUTED IN AUDIT` and two `VERIFIED POSITIVE`. EN-08, CR-07 and INF-01 remain
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
