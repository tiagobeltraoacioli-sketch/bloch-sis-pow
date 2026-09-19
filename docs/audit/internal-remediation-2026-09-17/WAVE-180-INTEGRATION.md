# Wave 180 — integration of legacy KDF, admission, block RPC and publication fixes

Date: 2026-09-19
Integration head: `a86fc187`

## Integrated corrections

- `a489010e` applies the existing legacy keystore KDF policy before every
  Base64 decode while retaining the same validator inside key derivation.
- `1a4d4307` derives a transaction identity once per admission and reuses it
  for recent inclusion, pending duplicate detection and new-entry accounting.
- `0af27dc9` borrows retained block envelopes for `getblockbyslot` and
  `getblockbyid`; only the unstored genesis envelope remains synthesized and
  owned.
- `a86fc187` refuses symlinked export/output roots and requires a fresh staged
  ownership token at the direct publication root, preventing false `PASS`
  after portable `mv` nests the stage in a raced destination.

The ledger records WAVE-176 through WAVE-179 while CR-07, EN-08, NET-01 and
INF-01 remain `PARTIAL`. No external release gate is closed by these local
corrections.

## Validation

```text
cargo test -p bloch-crypto --features wallet-cli --offline
# 247 passed; 0 failed; 2 ignored

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 606 passed; 0 failed; 19 ignored; 63.09s

bash -n scripts/build-pos-release-container.sh
bash -n scripts/build-pos-release-container.selftest.sh
bash scripts/build-pos-release-container.selftest.sh
bash -c 'umask 000; bash scripts/build-pos-release-container.selftest.sh'
# syntax clean; both selftest runs PASS

git diff --check
# clean
```

The crypto and node suites ran outside the restricted sandbox because their
HTTP/transport fixtures bind localhost sockets. Independent cross-review
found and reproduced a stage-root symlink bypass in the first W179 draft; the
final root guards, fixture and report were then re-reviewed and approved.

## Ledger state

The findings inventory remains 200 rows with 200 unique IDs and no duplicate
IDs. Status counts remain:

- `IMPLEMENTED`: 71
- `PARTIAL`: 98
- `UNARMED CANDIDATE`: 15
- `PROTOCOL DECISION`: 5
- `BASE CHANGED`: 7
- `OPEN`: 1
- `REFUTED IN AUDIT`: 1
- `VERIFIED POSITIVE`: 2

## Release boundary

The MW binary is **not ready for launch**. The remaining mandatory evidence
is external to these source changes:

- two independently authenticated canonical Linux builds and comparison;
- hosted CI plus source, builder, image and tool provenance;
- signed and published release and rollback artifacts with independent
  approval;
- a fresh independently signed weak-subjectivity envelope, authenticated
  signer arrangement and distributed pin evidence (SR-02/SR-03);
- the scratch-systemd rollback drill; and
- staged canary and fleet `/proc` digest evidence.

No binary was signed, published, deployed or released in this wave.
