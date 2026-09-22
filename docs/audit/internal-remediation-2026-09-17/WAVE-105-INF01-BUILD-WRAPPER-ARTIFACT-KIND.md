# Wave 105 — INF-01 build-wrapper artifact kind

Date: 2026-09-19
Comparison base: `fccb313`

## Reproduced gap

The canonical build wrapper did not inspect `BUILD-INFO.artifact_kind`.
Changing only the fake engine's value from
`canonical-container-candidate` to `unsigned-release-candidate` left the full
wrapper selftest green and produced a reported `PASS` output under the wrong
artifact classification.

## Correction

Before moving staged output, the wrapper now requires `BUILD-INFO` to contain
exactly one `artifact_kind` field whose complete value is
`canonical-container-candidate`. Missing, different, empty or duplicate fields
fail with a specific candidate-class diagnostic.

All Wave 100–104 manifest, captured-context, authorization, signed-state and
binary-digest checks remain unchanged.

## Adversarial coverage

The real-wrapper/fake-engine selftest retains canonical success and adds two
isolated rejection cases:

- the sole kind is `unsigned-release-candidate`; and
- the canonical kind is followed by a duplicate wrong kind.

Both otherwise carry the correct manifest, source identity, binary digest and
false signed/authorization states. Both must fail with the candidate-class
diagnostic. All earlier rejection and moving-ref cases remain active.

## Validation

```text
bash scripts/build-pos-release-container.selftest.sh
# build-pos-release-container selftest: PASS

bash -n scripts/build-pos-release-container.sh
bash -n scripts/build-pos-release-container.selftest.sh
# passed
```

## Residual boundary

This proves only the local textual artifact classification returned by the
selected engine. It does not authenticate source, repository, engine, image,
toolchain or builder, and it does not claim complete wrapper validation of
every other `BUILD-INFO` field. Builder independence, hosted CI, signing,
publication, independent approval, rollback rehearsal, deployment and fleet
evidence remain external gates. INF-01 remains `PARTIAL`.
