# Wave 85 — INF-03/04/11 GitLab mapping authority

Date: 2026-09-19
Comparison base: `3a45d9f`

## Reproduced bypass

Wave 84 made the supported GitHub workflow subset fail closed on disguised
mapping keys, but the corresponding GitLab documents still accepted them.
Appending this late mapping to the real `.gitlab-ci.yml` passed both local
guards:

```yaml
"defa\u0075lt":
  tags: [attacker-controlled]
  before_script: ["true"]
```

Ruby Psych 3.1.0, used only as a reproduction oracle, decoded that key as the
semantic string `default` and selected the late attacker-controlled mapping.
The textual guards continued reviewing the earlier plain `default:` decoy and
both returned success. The same class applies to escaped required-job names
and job-local execution or waiver keys.

## Fail-closed subset

The common lexical preflight now runs over both complete GitLab CI documents,
before global context, job selection or executable extraction. Outside YAML
literal/folded block scalar bodies, it rejects:

- single- or double-quoted mapping keys, including Unicode/hex escapes;
- inline and multiline explicit `?`/`:` mapping-key syntax;
- tagged, anchored or aliased mapping keys; and
- flow-style mappings.

The existing plain-key contracts remain authoritative. Quoted scalar values,
flow-style sequences such as runner tags, and arbitrary key-shaped text inside
`script: |` remain supported. This is deliberately a small locally parsed
subset, not a claim to implement general YAML semantics.

## Adversarial coverage

Both posture selftests independently cover escaped replacement of top-level
`default`, a required job, job-local failure-waiver and `script` keys; inline
and multiline explicit keys; tagged and anchored keys; and flow mappings.
Positive fixtures retain the repository's quoted values and add key-shaped
quoted text inside a GitLab block script.

## Validation

```text
python3 -I scripts/check-tests-blocking.selftest.py
# OK — 161 cases behave as documented

python3 -I scripts/check-scanners-blocking.selftest.py
# OK — 122 cases, both directions

python3 -I scripts/check-tests-blocking.py
# OK — supported explicit test commands cover 8 live crates on both pipelines

python3 -I scripts/check-scanners-blocking.py
# OK — 8 GitLab + 8 GitHub jobs are blocking

python3 -I -m py_compile <the four guard/selftest scripts>
# passed

git diff --check -- <Wave 85 files>
# passed
```

The final `check-tests-blocking.selftest.py` SHA-256 is
`f3a0fbfb81f1fd11351b9eddcee06d4821d436842e3824b0656e47f16154bc80`,
and the test guard pins that exact digest.

## Residual boundary

The proof is local and structural. It does not establish GitLab hosted
execution, runner/image provenance or availability, project rules, protected
branches, event delivery or the bytes of installed tools. GitLab formatting
remains informational, and no pipeline, runner, deployment or release state
was changed.
