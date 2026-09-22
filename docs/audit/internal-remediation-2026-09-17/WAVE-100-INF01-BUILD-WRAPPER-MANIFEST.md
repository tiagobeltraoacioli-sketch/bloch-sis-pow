# Wave 100 — INF-01 build-wrapper manifest contract

Date: 2026-09-19
Comparison base: `2987e02`

## Reproduced gap

The canonical container wrapper ran `sha256sum -c` or `shasum -c` on the
engine's exported manifest, but those tools validate only the rows present.
A local fake engine exported a valid executable and matching metadata plus a
two-row `SHA256SUMS` covering both `bloch-pos` and `BUILD-INFO`. Every row
verified, and the real wrapper printed `PASS`, even though the Dockerfile's
canonical manifest contains exactly one row.

The same behavior allowed a manifest that omitted `bloch-pos` and covered
only `BUILD-INFO`. This was reproduced through the complete wrapper with a
temporary fake engine; Docker, systemd and signing keys were not used.

## Correction

After requiring the exported binary to be executable, the wrapper now computes
its SHA-256 with the existing portable GNU/macOS tool choice and compares the
complete manifest bytes against:

```text
<lowercase binary SHA-256>  bloch-pos\n
```

Only after that exact comparison does the existing generic checksum verifier
run. The source-commit, source-date, output-path and archive-context checks are
unchanged.

## Adversarial coverage

The new local selftest drives the real wrapper with a temporary fake container
engine and covers three cases:

- the exact canonical one-line manifest passes and is retained byte-for-byte;
- an additional valid `BUILD-INFO` checksum row fails; and
- a valid manifest that covers only `BUILD-INFO` and omits the binary fails.

Both refusals require the precise canonical-manifest diagnostic. The test
requires no Docker daemon, systemd host, network access or key material.

## Validation

```text
bash scripts/build-pos-release-container.selftest.sh
# build-pos-release-container selftest: PASS

bash -n scripts/build-pos-release-container.sh
bash -n scripts/build-pos-release-container.selftest.sh
# passed
```

## Residual boundary

This proves only the local manifest bytes emitted after the selected engine
returns. It does not authenticate the engine, image, toolchain or builder;
prove that the declared source or build arguments executed; establish a
second independent build; or provide hosted CI, signing, publication,
approval, rollback rehearsal, deployment or fleet evidence. INF-01 remains
`PARTIAL`.
