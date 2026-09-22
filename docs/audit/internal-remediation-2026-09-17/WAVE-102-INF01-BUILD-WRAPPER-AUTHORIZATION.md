# Wave 102 — INF-01 build-wrapper deployment authorization

Date: 2026-09-19
Comparison base: `edf1e8d`

## Reproduced gap

The canonical build wrapper checked its binary manifest, source commit and
source timestamp, but it did not inspect the exported
`deployment_authorized` field. Changing only the fake engine's metadata from
`deployment_authorized=false` to `deployment_authorized=true` left the full
wrapper selftest green and produced a reported `PASS` candidate.

This did not grant real deployment authority, but it let the repository-owned
wrapper endorse metadata that contradicted its explicit unsigned,
unauthorized-candidate boundary.

## Correction

Before moving the staged output into the requested destination, the wrapper
now requires `BUILD-INFO` to contain exactly one `deployment_authorized` field
whose complete value is `false`. Missing, true, empty or duplicate fields fail
with a specific authorization diagnostic.

All Wave 100 canonical-manifest checks and Wave 101 captured-commit context
checks remain unchanged.

## Adversarial coverage

The real-wrapper/fake-engine selftest retains its canonical success and adds
two rejection cases:

- the sole field is changed to `deployment_authorized=true`; and
- a canonical false field is followed by a duplicate true field.

Both cases otherwise emit the exact one-line binary manifest and matching
commit/timestamp metadata, and both must fail with the authorization
diagnostic. The manifest mutations and A-to-B ref-race fixture remain active.

## Validation

```text
bash scripts/build-pos-release-container.selftest.sh
# build-pos-release-container selftest: PASS

bash -n scripts/build-pos-release-container.sh
bash -n scripts/build-pos-release-container.selftest.sh
# passed
```

## Residual boundary

This proves only one local textual field in the output returned by the
selected engine. It does not authenticate the engine, image, toolchain,
repository or builder, and this isolated change does not claim complete
wrapper validation of every other `BUILD-INFO` field. Builder independence,
hosted CI, signing, publication, independent approval, rollback rehearsal,
deployment and fleet evidence remain external gates. INF-01 remains
`PARTIAL`.
