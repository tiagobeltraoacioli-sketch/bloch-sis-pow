# Wave 87 — INF-03/04/11 YAML document boundaries

Date: 2026-09-19
Comparison base: `be16a79`

## Reproduced bypass

The common lexical CI preflight inspected all lines as one workflow but did
not reject YAML document controls. Prefixing either reviewed GitLab fixture
with the following text left both complete local guards green:

```yaml
decoy-only: true
---
# complete reviewed pipeline follows
```

The same mutation passed when applied to the reviewed GitHub fixtures. Ruby
Psych, used only as a local semantic oracle, materialized the first document
for a normal `YAML.load`, while `YAML.load_stream` exposed the decoy and the
later reviewed document separately. Thus a guard could prove jobs collected
from text outside the document selected by a YAML loader. This is a local
parser-differential reproduction, not a claim about hosted GitHub or GitLab
acceptance.

## Fail-closed correction

Both guards now reject YAML directives and the `---`/`...` document markers,
with optional trailing comments, everywhere outside literal or folded block
scalar bodies. The checked-in CI documents use one implicit document and no
directives, so this narrows the already documented textual subset without
changing a pipeline command.

The rule deliberately covers both providers and both early and late document
boundaries. Directive or boundary-looking text inside GitLab `script: - |`
and GitHub `run: |` bodies remains ordinary script data.

## Adversarial coverage

Each selftest independently covers GitLab and GitHub leading document starts,
an earlier decoy followed by a later reviewed document, `%YAML` or `%TAG`
directives, and document-end markers. Positive fixtures place directives,
starts and ends inside both providers' block scripts and remain green.

## Validation

```text
python3 -I scripts/check-tests-blocking.selftest.py
# OK — 175 cases behave as documented

python3 -I scripts/check-scanners-blocking.selftest.py
# OK — 136 cases, both directions

python3 -I scripts/check-tests-blocking.py
# OK — supported explicit test commands cover 8 live crates on both pipelines

python3 -I scripts/check-scanners-blocking.py
# OK — 8 GitLab + 8 GitHub jobs are blocking

python3 -I -m py_compile <the four guard/selftest scripts>
# passed

git diff --check -- <Wave 87 infra files>
# passed
```

The final `check-tests-blocking.selftest.py` SHA-256 is
`d7e7f07f907c127b9ef0404d9887481f862f0115d98e8b7300cee83d89e66187`,
and the test guard pins that exact digest.

## Residual boundary

This is a local textual proof for the repository's deliberately small CI
subset. It does not prove hosted parsing, event delivery, runner/image
provenance or availability, installed tool bytes, project rules or branch
protection. A bounded review of CRLF normalization, tabs, scalar-key
duplicates and existing block-scalar/merge forms found no additional full
guard bypass; this report makes no general YAML-parser claim.
