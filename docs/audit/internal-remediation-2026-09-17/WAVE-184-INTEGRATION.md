# Wave 184 — integration of fixed-field, proposal and package ownership fixes

Date: 2026-09-19
Integration head: `b8185a9e`

## Integrated corrections

- `de237485` preflights the canonical encoded lengths of fixed-size v1/v2
  salt and nonce fields and the legacy nonce before Base64 allocation. Legacy
  salt compatibility remains deliberately variable and is pinned by an
  authentic eight-byte-salt roundtrip.
- `b8185a9e` removes the eager canonical transaction-body clone from every
  successful local proposal. Only the rare refused-own-block fail-safe
  re-encodes its unchanged typed selection for exact mempool cleanup.
- `5cec7250` applies staged/output root and direct ownership-token publication
  checks to the candidate packager, rejecting the same portable-`mv` nesting
  false success closed by W179 in the canonical wrapper.

CR-07, EN-08 and INF-01 remain `PARTIAL`. These repository-local corrections
do not replace independent build, signing, deployment or fleet evidence.

## Validation

```text
cargo test -p bloch-crypto --features wallet-cli --offline
# library 243 passed; 0 failed; 2 ignored; integrations 6 passed; 0 failed;
# doc tests 0 failed; 2 ignored; aggregate 249 passed; 0 failed; 4 ignored

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 609 passed; 0 failed; 19 ignored; 105.01s

bash -n scripts/package-pos-release-candidate.sh
bash -n scripts/package-pos-release-candidate.selftest.sh
bash scripts/package-pos-release-candidate.selftest.sh
bash -c 'umask 000; bash scripts/package-pos-release-candidate.selftest.sh'
# syntax clean; both selftest runs PASS

git diff --check
# clean
```

The crypto and node suites ran outside the restricted sandbox because their
HTTP/transport fixtures bind localhost sockets. Cross-review caught and
removed an incompatible proposed fixed length for legacy salt before W181 was
committed; the final regression proves that historical Argon2-valid salt
lengths remain accepted.

## Ledger state

The inventory remains 200 rows with 200 unique IDs and no duplicate IDs:

- `IMPLEMENTED`: 71
- `PARTIAL`: 98
- `UNARMED CANDIDATE`: 15
- `PROTOCOL DECISION`: 5
- `BASE CHANGED`: 7
- `OPEN`: 1
- `REFUTED IN AUDIT`: 1
- `VERIFIED POSITIVE`: 2

## Release boundary

The MW binary is **not ready for launch**. Mandatory evidence still missing:

- two independently authenticated canonical Linux builds and comparison;
- hosted CI plus source, builder, image and tool provenance;
- signed and published release and rollback artifacts with independent
  approval;
- a fresh independently signed weak-subjectivity envelope, authenticated
  signer arrangement and distributed pin evidence (SR-02/SR-03);
- the scratch-systemd rollback drill; and
- staged canary and fleet `/proc` digest evidence.

No binary was signed, published, deployed or released in this wave.
