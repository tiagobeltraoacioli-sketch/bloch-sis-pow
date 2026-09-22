# Internal audit remediation, ninth wave — 2026-09-17

Base: `e237b76`, branch `fix/internal-audit-20260917`. This is a local source
checkpoint. It does not sign or publish a binary, deploy a service, restart a
validator, rotate a credential or activate a consensus rule.

## Repository-owned PoS release candidate

GitLab now has a blocking `package` stage after tests. It builds `bloch-pos` from
the committed root lockfile and pinned node toolchain, verifies the commit stamp,
and retains the binary together with `SHA256SUMS` and line-oriented `BUILD-INFO`.
The package script refuses tracked source or index changes, a mismatched CI commit,
and environment overrides for compiler, wrapper, target, linker, flags or Cargo
release profile. An existing output path is refused rather than replaced.

The artifact identifies itself as an unsigned release candidate. Its metadata
explicitly says that the build is not from the canonical container, is unsigned
and is not authorized for deployment. This closes only the source-side absence
identified by INF-01: the repository now owns a traceable candidate-producing
pipeline. Cross-builder equality at the canonical path, protected-key signing,
independent release approval, publication and fleet verification remain required.

## Validation and status

The script and GitLab YAML passed local syntax parsing. A dirty-tree invocation
failed before building as intended. Two clean release builds completed while the
manifest format was exercised; the first exposed multiline version metadata,
which was split into one-line version and source-identity fields before the final
run. The final candidate's SHA256, full commit and negative signing/deployment
claims were checked independently. Exact evidence is in `VALIDATION-WAVE-9.txt`.

The ledger retains all 200 rows: 53 implemented locally, 69 partial, 65 open,
seven base-changed, four protocol decisions, one unarmed candidate and one refuted
by the original audit. INF-01 remains partial because repository code cannot prove
that hosted CI ran, a release owner signed/published the output or the fleet runs it.
