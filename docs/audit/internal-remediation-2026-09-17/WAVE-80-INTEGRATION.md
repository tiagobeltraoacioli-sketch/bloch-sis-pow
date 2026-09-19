# Wave 80 integration checkpoint

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`f787b25`. Four agents continued audit remediation across bounded HD-wallet
loading, authenticated held-attestation replay and cross-pipeline executable
proof parity. No release, deployment or production mutation occurred.

## Ledger result

All 200 finding rows and unique IDs remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. CR-07, EN-08/NET-04,
INF-03/INF-04 and INF-17 remain `PARTIAL`; this wave narrows their residuals
without changing classification. SR-03 remains the sole open finding.

## Integrated changes

CR-07 now caps encoded nonce and mnemonic/keypair ciphertext fields for normal
bounded loading after JSON parsing but before Base64 decoding, Argon2 and AES.
The explicit trusted-recovery path remains compatible. Once authenticated,
address and label buffers move into the live wallet rather than being cloned.
Canonical unescaped decrypted mnemonic and key strings borrow their already
zeroizing plaintext buffers; escaped historical JSON remains compatible via
owned fallbacks whose secret fields are wiped. The caller mnemonic has one
zeroizing canonical representation shared by KDF and comparison.

EN-08/NET-04 no longer pays a second hybrid verification when a previously
authenticated held attestation is released under the same registry key. An
opaque, consumed token binds the exact retained attestation to the SHA3-256
fingerprint of the key that verified it. Replay still reruns slot, checkpoint,
dedup/equivocation, committee, current-key, capacity and block-availability
checks. A changed key takes the ordinary verifier path and fails closed. Root
review caught a stale identifier introduced by the refactor before commit;
the corrected node then compiled and its loopback regression passed.

INF-03/INF-04 add the independent-process joining-validator rehearsal to the
blocking GitLab path and exact posture contracts. GitLab's workspace build now
uses `--locked`, preventing it from generating a new lockfile before the later
locked tests. INF-04/INF-17 additionally bind the attested-SSH and installer-ISO
mutation suites and real verdicts into required exact contracts on both
pipelines, including reviewed hashes and transitive executable relationships.

## Validation

- The complete `bloch-crypto` suite passed 203 library tests with 2 ignored,
  6 integration tests, and 2 ignored documentation tests: 209 passed, 4
  ignored, no failures.
- Committee gossip passed 28/28 tests. `cargo check -p bloch-pos-node
  --offline` passed with inherited warnings. The authenticated held-replay
  node regression passed 1/1 outside the restricted loopback sandbox.
- The test-posture selftest reached 117/117 adversarial cases and the real
  guard confirmed all eight live crates on both pipelines. The scanner posture
  retained 79/79 mutation cases and 16 blocking jobs.
- Attested-SSH passed six named red mutations and one green control; installer
  ISO hardening passed seven named red mutations and one green control. Both
  real guards passed.
- Locked offline Cargo metadata resolution, the four-case activation parser,
  pinned-toolchain checks, relevant Python compilation, ledger arithmetic and
  scoped `git diff --check` passed. `Cargo.lock` stayed byte-identical.
- The long joining-network and full workspace rehearsals were not repeated for
  these structural CI changes. This wave does not claim hosted execution.
- Workspace-wide `cargo fmt --check` retains the inherited formatting backlog
  and is not claimed green.

## Commits

- `f3aaae0` — gate the independent joining-validator rehearsal on GitLab.
- `83c2cf5` — bound encrypted HD-wallet payloads before credential work.
- `df237f6` — bind the attested-SSH guard into GitLab's exact posture.
- `428864d` — bind installer-ISO hardening across both pipeline contracts.
- `9fda65f` — move authenticated wallet metadata without duplicate buffers.
- `a47dfe1` — reuse held-attestation authentication under an unchanged key.
- `7d49f78` — require the GitLab workspace build to use the committed lockfile.
- `eefe430` — borrow decrypted wallet secrets from zeroizing plaintext.

## Launch boundary

The new MW binary is **not ready to launch**. The canonical Linux image still
needs two independently authenticated builds and comparison; hosted CI is not
evidenced green; release and rollback artifacts are unsigned; SR-03 lacks a
fresh independently signed weak-subjectivity envelope; rollback has not been
rehearsed on a scratch systemd host; and no staged canary or fleet digest
evidence exists. These external gates remain mandatory before readiness or
production rollout.
