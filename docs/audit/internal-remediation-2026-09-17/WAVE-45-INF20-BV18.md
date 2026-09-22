# Wave 45: INF-20 hygiene and BV-18 claim accuracy

Date: 2026-09-18. Branch: `codex/audit-inf20-bv18`. Starting point:
`4e15334`. Scope: local source, tests, CI definitions, and documentation only.
No protocol rule, activation, deployed system, public network, release artifact,
credential, or funds were changed.

## Recovered source detail

The aggregate ledger rows did not retain their itemized evidence. The original
annexes were recovered from repository commit `a79c88b`:

- `docs/audit/deep-audit-2026-09-16/A10-infra-supply-chain.md` listed the
  exported ceremony passphrase, unsafe/founder-specific carryover test paths,
  duplicate Rust `1.94.1` pins, and runtime `sudo apt-get install minisign` on a
  shell runner, together with an external question about fork-runner exposure.
- `docs/audit/deep-audit-2026-09-16/A9-bitcoin-vault-ustav.md` listed six
  documentation mismatches: nonexistent Bloch-side enforcement, calling branch
  B PQ-gated after the unvault reveals `r`, keyless watchtower fee-bump claims,
  an impossible deletion ceremony for the legacy shared hot/deposit key, a
  reference to an unspecified security audit, and the stale claim that no code
  implemented the design.

## INF-20 changes

The ceremony passphrase subitem was already corrected in this starting point:
the ceremony unsets credential environment variables and supplies the prompted
secret through file descriptor 0 using `BLOCH_KEYSTORE_PASSPHRASE_FD=0`. Its PTY
regression verifies that the passphrase is absent from argv, environment, and
regular files and that terminal state is restored.

This wave completed the remaining local hygiene work:

- Genesis carryover tests use `TemporaryDirectory` and
  `NamedTemporaryFile`; the founder-home fixture and always-failing local-data
  probes were removed in favor of deterministic hermetic fixtures.
- `scripts/pinned-rust-toolchain.py` validates both checked-in toolchain files,
  requires one safe and matching channel assignment, and supplies that value to
  validator mutation checks and both CI systems. No workflow duplicates the
  literal toolchain version.
- The rollback verification job now requires pre-provisioned `minisign` and
  fails closed when it is absent; it no longer performs package installation
  through runtime `sudo` on a shell runner.
- Adversarial tests cover mismatched, missing, duplicated, and injection-shaped
  toolchain values, plus structural regressions in the affected CI definitions.

INF-20 is partial because shell-runner enrollment, fork-pipeline policy, and the
provenance of the provisioned `minisign` binary require external operational
evidence. This source-only wave does not infer those controls.

## BV-18 changes

The spec, crate documentation, API README, API response text, and relevant test
labels now state the implemented boundary:

- Bitcoin enforces the hashlock, timelock, and classical signatures. The code
  can sign and verify an off-chain PQ commitment but does not post, order,
  revoke, or consensus-enforce an anchor.
- Once the unvault publishes `r`, the recovery signature is branch B's remaining
  authorization. It is described as hashlocked classical recovery, not as a
  PQ-gated spend.
- A keyless broadcaster can use only finite pre-signed replacements. RBF opt-in
  grants no signing authority; giving it `recovery_sk` or a signing oracle makes
  it custodial and theft-capable.
- Legacy `VaultParams` shares the deposit and branch-A hot key and therefore
  cannot support the claimed deletion ceremony. The opt-in separated-key form
  still cannot prove independent key generation or deletion and supplies no
  Bitcoin covenant.
- Documentation points to the existing internal construction review without
  presenting it as external qualification, and identifies the implemented
  primitives without claiming a deployed product.

`scripts/check-pq-shield-claims.py` fails on the six known obsolete claim forms
and requires the central limitation statements. Its internal adversarial test
removes each required statement and injects each banned statement. GitHub and
GitLab Ustav jobs run the guard.

BV-18 is implemented as a documentation-accuracy finding. This status does not
close the underlying protocol, custody, deployment, or external-audit gaps.

## Validation

- `python3 scripts/pinned-rust-toolchain.py`: resolved `1.94.1` from both pins.
- `python3 scripts/pinned-rust-toolchain.test.py`: adversarial and CI-structure
  cases passed.
- `python3 tools/genesis4-carryover/test_build_carryover.py`: all hermetic
  carryover checks passed.
- `python3 deploy/genesis4-key-ceremony.test.py`: 4 passed.
- `python3 scripts/check-pq-shield-claims.py --selftest`: passed.
- `python3 scripts/check-pq-shield-claims.py`: passed against the repository.
- `cargo test --locked -p bloch-pq-vault`: 33 passed.
- `cargo test --locked --manifest-path services/pq-shield-api/Cargo.toml`: 18
  passed.
- Python bytecode compilation for the new and changed Python checks passed.
- `git diff --check` passed for each implementation commit and this ledger
  update.

## Ledger result

The ledger remains 200 rows: 70 implemented, 90 partial, 25 open, 7 base
changed, 4 protocol decisions, 2 verified positives, 1 unarmed candidate, and 1
finding refuted in the audit. This is evidence accounting, not release approval.
