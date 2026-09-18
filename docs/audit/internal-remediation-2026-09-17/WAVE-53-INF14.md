# Wave 53 INF-14: fail-closed deploy image inheritance

Date: 2026-09-18. Starting point: `405bfb0`. Scope: repository deploy-YAML
guard, mutation selftest, CI commentary and audit ledger. No image, registry,
release artifact, deployment or live service was changed.

## Recovered residual

The image-pin guard correctly checked explicit `image:` scalars but declared
arbitrary YAML inheritance outside its supported subset. A future deployment
file could therefore introduce anchors, aliases or merge keys whose effective
image relationship the line-oriented guard did not claim to resolve.

## Local correction

The guard remains dependency-free and deliberately does not implement a
partial YAML resolver. Instead, it now refuses YAML merge keys plus anchor and
alias tokens at structural scalar boundaries. Operators must expand inherited
configuration into explicit mappings before image-pin review. This makes an
unsupported construct a blocking result rather than a silent proof gap.

The existing accepted set is unchanged: an exact `@sha256` scalar, the
non-pullable template sentinel, or `bloch:latest` in the one reviewed compose
file with `build` and `pull_policy: never` in the same service. Prometheus
arithmetic using a standalone `*` is not mistaken for a YAML alias, and the
current 15-file deploy tree remains green.

The mutation suite adds anchor, alias, merge-key, quoted merge-key and flow
alias cases. Every case must fail with the inheritance-specific diagnostic.
The GitLab commentary no longer claims the current job is red on twelve
unpinned files.

## Validation and boundary

- `python3 scripts/check-deploy-image-pins.selftest.py`: all 8 groups passed;
- `python3 scripts/check-deploy-image-pins.py`: all 15 deploy YAML files
  passed; and
- `git diff --check`: run at Wave 53 integration.

INF-14 remains `PARTIAL`. The guard does not render generated configuration,
evaluate non-YAML templating, query a registry, authenticate publishers or
verify that a pinned digest was deployed. It is a fail-closed repository
structure check, not release provenance or fleet evidence.
