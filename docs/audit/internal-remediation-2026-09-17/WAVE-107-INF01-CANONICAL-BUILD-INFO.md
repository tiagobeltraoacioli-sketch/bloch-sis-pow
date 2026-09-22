# Wave 107 — INF-01 canonical wrapper BUILD-INFO

Date: 2026-09-19
Comparison base: `5a09ba2`

## Reproduced gap

The build wrapper independently pinned four sensitive metadata fields, but
accepted duplicate `source_commit` and `source_date_epoch` rows, an alternate
Debian snapshot, a malformed target and an extra field in one otherwise valid
fake-engine output. The full wrapper selftest still reported `PASS`.

The two-builder comparator already enforced its complete metadata contract,
but the single-build wrapper reports success before any comparison occurs.

## Correction

The wrapper now applies one canonical `BUILD-INFO` contract after validating
the binary manifest:

- every one of the eight fields must occur exactly once and be nonempty;
- source commit and epoch must equal the captured Git object's values;
- the Debian snapshot must equal the reviewed Dockerfile pin;
- target must be a structurally valid lowercase ASCII Rust host triple;
- artifact kind, binary digest and false signed/authorization states retain
  their prior exact checks; and
- the complete file must equal the Dockerfile's eight-line order and encoding,
  including its final newline and absence of extra fields.

The comparator remains a separate A/B authority and is not called or weakened
by this single-candidate validation. Snapshot rotation now requires one atomic
reviewed update across the Dockerfile, wrapper, comparator and fixtures.

## Adversarial coverage

All Wave 100–105 cases and the moving-ref fixture remain active. New
real-wrapper/fake-engine cases reject:

- conflicting duplicate source commit and source epoch rows;
- a structurally valid alternate Debian snapshot;
- a malformed target;
- reordered fields, an extra field and a missing final newline.

A positive `aarch64-unknown-linux-gnu` fixture passes, proving the structural
target check does not silently pin one architecture.

## Validation

```text
bash scripts/build-pos-release-container.selftest.sh
# build-pos-release-container selftest: PASS

bash -n scripts/build-pos-release-container.sh
bash -n scripts/build-pos-release-container.selftest.sh
# passed
```

## Residual boundary

The target check proves only unique structural syntax, not that the compiler
recognizes the triple or that it matches the produced binary's ABI. The
snapshot check proves only textual agreement with the reviewed pin, not that
APT used it. This work does not authenticate Git objects, repository, engine,
image, toolchain or builder and does not establish builder independence,
hosted CI, signing, publication, approval, rollback, deployment or fleet
evidence. INF-01 remains `PARTIAL`.
