# Wave 103 — INF-01 build-wrapper signed state

Date: 2026-09-19
Comparison base: `4a459b6`

## Reproduced gap

The canonical build wrapper does not sign its output, but it did not inspect
the exported `signed` metadata field. Changing only the fake engine's
`BUILD-INFO` line from `signed=false` to `signed=true` left the complete
wrapper selftest green and produced a reported `PASS` candidate.

This did not create a cryptographic signature. It allowed engine-controlled
metadata to make a false signature claim at the repository-owned wrapper
boundary.

## Correction

Before moving the staged output, the wrapper now requires `BUILD-INFO` to
contain exactly one `signed` field whose complete value is `false`. Missing,
true, empty or duplicate fields fail with a specific unsigned-state
diagnostic.

The Wave 102 deployment-authorization invariant and every Wave 100/101
manifest and captured-context check remain unchanged.

## Adversarial coverage

The real-wrapper/fake-engine selftest retains its canonical success and adds
two rejection cases:

- the sole field is changed to `signed=true`; and
- a canonical false field is followed by a duplicate true field.

Both cases otherwise emit the exact canonical binary manifest, source
identity and `deployment_authorized=false`, and both must fail with the
unsigned-state diagnostic. All earlier manifest, authorization and moving-ref
cases remain active.

## Validation

```text
bash scripts/build-pos-release-container.selftest.sh
# build-pos-release-container selftest: PASS

bash -n scripts/build-pos-release-container.sh
bash -n scripts/build-pos-release-container.selftest.sh
# passed
```

## Residual boundary

This proves only one local textual state field in the output returned by the
selected engine. It does not produce or verify a cryptographic signature,
authenticate the engine, image, toolchain, repository or builder, or claim
complete wrapper validation of every other `BUILD-INFO` field. Builder
independence, hosted CI, real signing, publication, independent approval,
rollback rehearsal, deployment and fleet evidence remain external gates.
INF-01 remains `PARTIAL`.
