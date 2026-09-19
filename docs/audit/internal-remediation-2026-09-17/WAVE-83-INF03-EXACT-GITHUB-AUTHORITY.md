# Wave 83 — INF-03 exact GitHub trigger and job authority

Date: 2026-09-19
Starting consolidation: `f57ed91`

## Residual addressed

The two local CI meta-guards required `push:` and `pull_request:` keys but did
not bind the complete `on:` mapping. A workflow could therefore retain the
reviewed-looking key while adding `paths-ignore: ['**']`, a non-matching branch
filter, or a later duplicate event key. GitHub would then omit the blocking
jobs for affected pull requests while the local guard accepted the decoy key.

The test-posture guard also did not reject a job-level `permissions:` mapping
on `cargo-test`. The scanner guard rejected the plain spelling on required
jobs, but not the equivalent quoted YAML key. Its top-level permission parser
likewise ignored a quoted duplicate scope beneath an honest `contents: read`.
Those forms could replace the inherited read-only token posture without
changing any reviewed command.

## Hardening

Both guards now require the complete checked-in trigger mapping: pushes to
`main` and `euvm/**`, unrestricted pull requests, and manual dispatch. Nested
event filters, additional or duplicate events, scalar/flow replacements, and
quoted duplicate top-level `on` keys are outside this explicit subset and fail
closed.

The test guard refuses plain or quoted job-level permission overrides on the
required cargo-test job. The scanner guard applies the same semantic-key rule
to every required GitHub scanner job and requires the top-level permission
body to be exactly `contents: read`. The existing protected-key cardinality
check still rejects duplicate or quoted top-level permission mappings.

No workflow command, runner, timeout, trigger, permission, GitLab definition,
or production source changed. This is a local structural proof over the two
checked-in GitHub workflow files; it does not claim hosted-run evidence,
branch-protection configuration, deployment, or release readiness.

## Adversarial coverage

Independent fixtures now prove that each guard rejects:

- a `pull_request` key restricted with `paths-ignore: ['**']`;
- a late duplicate `pull_request` mapping restricted to a dead branch;
- a plain or quoted job-level token override on the required test job;
- a quoted job-level override on a required scanner job; and
- a quoted duplicate `contents` scope beneath the reviewed top-level mapping.

The honest fixtures use the complete live trigger and permission mappings, so
the opposite direction remains covered rather than accepting an intentionally
narrow synthetic contract.

## Validation

```text
python3 -I scripts/check-tests-blocking.selftest.py
# OK — 132 cases behave as documented

python3 -I scripts/check-tests-blocking.py
# OK — supported explicit test commands cover 8 live crates on both pipelines

python3 -I scripts/check-scanners-blocking.selftest.py
# OK — 93 cases, both directions

python3 -I scripts/check-scanners-blocking.py
# OK — 8 GitLab + 8 GitHub jobs are blocking

python3 -I -m py_compile scripts/check-tests-blocking.py \
  scripts/check-tests-blocking.selftest.py scripts/check-scanners-blocking.py \
  scripts/check-scanners-blocking.selftest.py
# passed

git diff --check -- <Wave 83 files>
# passed
```

The revised test-selftest digest is pinned by the test guard and was validated
against the final bytes before commit.

## Residual risk

- The guards intentionally implement a narrow textual YAML subset rather than
  claiming arbitrary YAML execution equivalence.
- Workflow `concurrency` remains outside this authority proof. Its current
  per-ref groups and cancellation policy affect scheduling and availability,
  not whether a completed required job can return a false green verdict.
- Repository rules, hosted runner policy, required-check selection, and actual
  event delivery remain external evidence requirements.
