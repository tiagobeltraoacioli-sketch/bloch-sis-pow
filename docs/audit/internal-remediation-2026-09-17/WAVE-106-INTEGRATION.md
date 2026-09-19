# Wave 106 integration — safe audit remediation after Wave 96

Date: 2026-09-19
Starting consolidation: `18da009`
Integrated head before this ledger commit: `8c5092c`

## Integrated corrections

- CR-07: mnemonic-generation entropy, legacy-save derived-key/JSON plaintext,
  legacy-load derived-key, Falcon halves received by the hybrid generators and
  hybrid pre-envelope secret bodies now acquire zeroizing owners without
  changing public APIs, schema, KDF/RNG flow or output bytes.
- Crypto regression stability: the raw-Falcon padding rejection uses the same
  deterministic seeded fixture family as its adjacent enveloped test. This is
  test-only hardening and does not change production Falcon behavior or a
  finding classification.
- EN-08 / NET-04: devnet frame writes stream prefix and payload without a
  second frame-sized concatenation; devnet sync block replies stream
  length/tag/payload; libp2p sync responses stream the canonical header and
  owned envelopes after complete length preflight. Directed p2p store scans
  also apply their exact framing-aware byte budget after canonical header
  validation and before reading or allocating the first rejected boundary
  body. Wire bytes, returned order, public/devnet page behavior, caps,
  authorization and partial-write failure semantics remain unchanged.
- INF-01: the comparator binds the reviewed Debian snapshot and rejects
  group/other-writable candidate artifacts. The build wrapper now requires the
  exact one-line binary manifest, binds timestamp/archive/context to one
  captured commit, refuses signed or deployment-authorized candidate metadata,
  and binds the metadata binary digest and artifact kind. These are local
  candidate checks, not builder authentication or release authorization.

The integrated commits, in ancestry order, are `9e058f1`, `706c7db`,
`8a41d8f`, `2987e02`, `5bee491`, `db508a2`, `ed0e289`, `97f7a1f`,
`edf1e8d`, `1ff00b8`, `4a459b6`, `10aa48b`, `d669863`, `cb859d0`,
`fccb313`, `9a57c21` and `8c5092c`. There is no standalone Wave 99
implementation report in this reviewed sequence.

## Validation evidence

```text
cargo test -p bloch-crypto --offline
# latest Wave 94 full run: library 214 passed; 2 ignored
# integration 6 passed; documentation 2 ignored
# total 220 passed; 0 failed; 4 ignored

# deterministic Falcon fixture classification
# 20 separate exact processes passed; adjacent enveloped fixture passed

cargo check -p bloch-pos-node --tests --offline
# passed in the focused network reports

cargo test -p bloch-pos-node --bin bloch-pos --offline
# latest Wave 94 NET-04 full run: 578 passed; 0 failed; 19 ignored; 56.46s

bash scripts/build-pos-release-container.selftest.sh
# build-pos-release-container selftest: PASS through Wave 105

bash scripts/compare-pos-release-builds.selftest.sh
# compare-pos-release-builds selftest: PASS through Wave 98

bash -n scripts/build-pos-release-container.sh
bash -n scripts/build-pos-release-container.selftest.sh
bash -n scripts/compare-pos-release-builds.sh
bash -n scripts/compare-pos-release-builds.selftest.sh
# passed
```

Wave 94 NET-04 additionally passed both byte-boundary store regressions, cold
sync and restarted-node recovery. Socket-bearing crypto and node suites ran
outside the restricted macOS sandbox. Focused reports retain exact adversarial
commands, filtered counts and residual boundaries. The Wave 90 crypto report
records its original unrelated random Falcon fixture failure honestly; Wave 91
made that fixture deterministic, and the later complete crypto suites are
green.

## Ledger reconciliation

`FINDINGS.md` contains 200 rows and 200 unique IDs. No status changed:

```text
IMPLEMENTED: 71
PARTIAL: 98
UNARMED CANDIDATE: 15
PROTOCOL DECISION: 5
BASE CHANGED: 7
OPEN: 1
REFUTED IN AUDIT: 1
VERIFIED POSITIVE: 2
```

CR-07, EN-08, NET-04 and INF-01 remain `PARTIAL`. SR-03 remains the sole
`OPEN` finding. In particular, the directed-sync byte preflight deliberately
preserves the pre-existing empty-page/periodic-retry livelock for a historical
first envelope larger than the p2p page budget; changing that behavior requires
a separate transport-policy decision.

## Release decision

The MW binary is **NOT READY for launch**. This host still has no Docker,
Podman or minisign executable. The INF-01 work in Waves 97–105 hardens only
local unsigned, `deployment_authorized=false`, `signed=false` candidate
evidence; it neither produces nor authorizes a release. The following evidence
remains mandatory and external:

1. two independently authenticated canonical Linux builds of the reviewed
   commit and a passing byte-for-byte comparator result;
2. full hosted CI plus authenticated source, builder, image and tool provenance
   on the release commit;
3. release and rollback artifacts signed with the real release key, published
   through the reviewed channel and independently approved;
4. a fresh independently signed weak-subjectivity envelope plus its
   independently authenticated signer set/arrangement and distributed pin,
   satisfying the SR-02/SR-03 onboarding gates;
5. a scratch-systemd rollback drill; and
6. staged canary/fleet rollout with running `/proc` digest verification.

No push, signing, publication, deployment or release authorization was
performed during these waves.
