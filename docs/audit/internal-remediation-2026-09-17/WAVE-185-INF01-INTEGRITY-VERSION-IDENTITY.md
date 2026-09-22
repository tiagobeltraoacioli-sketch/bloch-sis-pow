# Wave 185 — INF-01 integrity version identity contract

Date: 2026-09-19
Branch: `fix/internal-audit-20260917`
Comparison base: `803ac608`

## Reproduced gap

The legacy same-path release-integrity guard captured `bloch-pos --version`
with command substitution and accepted any output containing the expected
twelve-character commit substring anywhere. A fake binary emitting unrelated
prefix/suffix lines and a decoy `commit=<expected>` line therefore passed the
stamp gate and let the guard report success.

## Correction

The guard now captures version output in its private work directory and fails
closed if execution fails. It requires exactly two newline-terminated canonical
text lines. The first line must contain the captured commit as the delimited
token `(<commit>)`; the second must match the same asserted clean-source
identity contract used by the candidate packager:

```text
source-digest sha3-256:<64 lowercase hex> (<decimal> files, <decimal> bytes) commit-source:asserted tree:asserted-clean
```

Reconstructing and comparing the complete file preserves the final newline
and rejects extra bytes or lines rather than allowing a valid substring to act
as a decoy.

## Adversarial coverage

The hermetic full-mode fixture delegates canonical hashes to the host SHA-256
implementation and now emits configurable version identities. It proves:

- the canonical two-line identity passes;
- a nonzero `--version` exit fails closed;
- a first line without the captured commit, and one containing it without the
  required parentheses, are refused;
- both an unbound identity followed by a third-line commit decoy and an extra
  line after an otherwise valid identity are refused;
- a malformed/non-lowercase digest and dirty source assertions are refused;
- an absent final newline is refused by the exact line-count contract; and
- a non-newline trailing byte after two otherwise valid lines is refused by
  the complete-file reconstruction comparison.

The existing lock/layout, tracked-source, environment-override, aliased-build
output and digest-output matrix remains intact. The complete selftest passes
both normally and under `umask 000`.

## Local validation

- `bash -n scripts/pos-release-integrity.sh`
- `python3 -m py_compile scripts/pos-release-integrity.selftest.py`
- `python3 -I scripts/pos-release-integrity.selftest.py`
- `bash -c 'umask 000; python3 -I scripts/pos-release-integrity.selftest.py'`
- `git diff --check -- scripts/pos-release-integrity.sh scripts/pos-release-integrity.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-185-INF01-INTEGRITY-VERSION-IDENTITY.md`

## Boundary and residuals

This check validates the exact local self-description emitted by the first of
two same-path build outputs. It does not independently derive the source-tree
digest, authenticate the binary or builder, prove path-independent output,
compare a second builder, or replace canonical-container comparison, hosted CI,
provenance, signing, publication, approval, rollback rehearsal, canary or fleet
evidence. A malicious compiler/build pipeline can still emit a structurally
valid false self-description. `INF-01` remains `PARTIAL`.
