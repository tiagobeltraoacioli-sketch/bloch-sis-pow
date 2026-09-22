# Wave 85 integration checkpoint

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`3a45d9f`. Four agents continued remediation across BIP39 salt lifetime,
future-block accounting and GitLab workflow authority. No release, deployment,
production mutation or remote push occurred.

## Ledger result

All 200 finding rows and unique IDs remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. CR-07, EN-08/NET-04
and INF-03/INF-04/INF-11 remain `PARTIAL`; this wave narrows their residuals
without changing classification. SR-03 remains the sole open finding.

## Integrated changes

CR-07 changes the private BIP39 salt builder to allocate `mnemonic ||
passphrase` directly inside `Zeroizing<Vec<u8>>`. Both V1/SHA-256 and
V2/SHA-512 PBKDF2 paths retain the exact salt bytes, 2,048 iterations, public
API, output and error behavior. This wipes the salt's passphrase copy, not the
caller's original input or opaque backend state.

EN-08/NET-04 cache the exact canonical encoded length beside each immutable
future block. Global/source byte totals now scan at most 32 fixed-size metadata
records rather than allocate and copy every retained body on every new future
admission. Envelope, source and private authentication still move together on
release; count/byte caps, verdicts, ordering, recovery, wire and consensus are
unchanged. The scan remains O(entries), and encoded size remains a proxy rather
than an exact decoded heap/RSS measurement.

INF-03/INF-04/INF-11 extend Wave 84's fail-closed mapping-key preflight to the
complete GitLab document. A late escaped `default` mapping that real YAML
normalizes over the reviewed decoy is now refused, along with disguised job,
waiver and script keys. Both CI subsets reject quoted/escaped, explicit,
tagged, anchored, aliased and flow mapping keys outside block scripts while
preserving quoted values, GitLab flow sequences and block-scalar script data.

## Validation

- The complete `bloch-crypto` suite passed 208 library tests with 2 ignored,
  6 integration tests, and 2 ignored documentation tests: 214 passed, 4
  ignored, no failures. The new salt regression passed 1/1; an independent
  review also passed all 12 seed-module tests.
- `cargo check -p bloch-pos-node --tests --offline` passed. The reachable
  8-by-2-MiB metadata boundary regression and the signed 3-MiB future-block
  integration regression each passed 1/1 with 584 filtered; the latter ran
  outside the sandbox because its fixture binds loopback.
- Independent reviews required a synthetic 4+12-MiB boundary fixture to be
  replaced with eight individually transport-admissible 2-MiB entries, and a
  wallet comment to distinguish the wiped salt copy from the caller input.
  Both corrections landed before consolidation.
- Test posture passed 161/161 adversarial cases; scanner posture passed
  122/122. Real guards covered every live crate on both pipelines and 8+8
  security jobs. Relevant Python compilation, digest and diff checks passed.
- No complete node binary suite was rerun after the Wave 85 future-accounting
  change. No hosted CI, long rehearsal, workspace-wide formatting or release
  result is claimed in this wave.

## Commits

- `8518760` — zeroize the BIP39 salt's passphrase copy.
- `11887ac` — reject disguised GitLab mapping keys.
- `6aa449f` — clarify the salt-zeroization scope.
- `50e6b7b` — cache future-block byte metadata.

## Launch boundary

The new MW binary is **not ready to launch**. The canonical Linux image still
needs two independently authenticated builds and comparison; hosted CI is not
evidenced green; release and rollback artifacts are unsigned; SR-03 lacks a
fresh independently signed weak-subjectivity envelope; rollback has not been
rehearsed on a scratch systemd host; and no staged canary or fleet digest
evidence exists. These external gates remain mandatory before readiness or
production rollout.
