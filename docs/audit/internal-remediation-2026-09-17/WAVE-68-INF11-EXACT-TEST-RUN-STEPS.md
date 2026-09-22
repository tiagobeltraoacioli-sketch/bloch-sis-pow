# Wave 68 INF-11: exact ordered cargo-test run steps

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Starting point:
`99287b4`. Scope: local test-workflow posture parsing and adversarial fixtures
only. No hosted CI, network, release, deployment, protocol, format or
consensus behavior changed.

## Correction

Wave 67 bound all GitHub security-job commands, while the blocking
`cargo-test` job still accepted arbitrary auxiliary `run:` steps. A new step
could overwrite a rehearsal script or known tool before the unchanged final
`cargo test` command. The guard proved crate arguments but not the setup and
dataflow that reached them.

The test guard now requires the exact ordered list of all 11 checked-in
`cargo-test` run steps:

- pinned toolchain extraction and installation;
- C toolchain installation;
- validator admission, lifecycle mutation, bootnode, retired-consensus,
  activation and joining-network regressions;
- focused node and PQ-internals tests;
- the final eight-crate test command.

Adding even an apparently inert command, deleting a setup/rehearsal, changing
or reordering a command now requires explicit guard review. The extractor
preserves literal-block newlines and folded-block spaces, so replacing
`run: |` with `run: >` cannot merge toolchain commands while comparing equal.

Four new hostile fixtures overwrite a rehearsal entrypoint, reorder two setup
steps, delete a guard rehearsal and fold the toolchain block. An earlier
permissive `GITHUB_OUTPUT` extra-step fixture is now expected to fail under the
exact contract. Honest synthetic pipelines and the checked-in workflow pass.

## Residual and status

INF-11 remains `PARTIAL`. Exact workflow commands do not prove the contents of
the scripts they invoke, package-manager behavior or runner host integrity.
The separate `tests-blocking-guard` job and GitLab `build-and-test` setup do not
yet have equivalent whole-job ordered command allowlists. Branch protection
and actual hosted outcomes remain external; no hosted evidence was generated
or claimed.

## Validation

- `python3 scripts/check-tests-blocking.selftest.py`: all 61 cases pass.
- `python3 scripts/check-scanners-blocking.selftest.py`: all 74 fixtures pass
  in both directions.
- `python3 scripts/check-tests-blocking.py`: both checked-in test jobs cover
  all eight live crates and the GitHub job matches all 11 reviewed run steps.
- `python3 scripts/check-scanners-blocking.py`: all eight required jobs in
  each checked-in security pipeline pass.
- `python3 -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py`:
  passes.
- `git diff --check`: passes.
