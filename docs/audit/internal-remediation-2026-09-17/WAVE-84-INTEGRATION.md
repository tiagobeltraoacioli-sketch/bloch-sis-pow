# Wave 84 integration checkpoint

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`ff48c1d`. Four agents continued remediation across encrypted keyfiles,
finality-refusal retention and GitHub required-job authority. No release,
deployment, production mutation or remote push occurred.

## Ledger result

All 200 finding rows and unique IDs remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. CR-07, EN-08/NET-04
and INF-03/INF-04/INF-11 remain `PARTIAL`; this wave narrows their residuals
without changing classification. SR-03 remains the sole open finding.

## Integrated changes

CR-07 applies in-place AES-GCM decryption to the remaining encrypted-keyfile
v1/v2 loaders. Their Base64-decoded ciphertext allocation is immediately
zeroizing and becomes plaintext without a second full allocation. V1 preserves
its caller-owned `Vec` return; v2 stays zeroizing while its authenticated
aggregate is validated and split. Schema, AAD, KDF, API and errors are
unchanged.

EN-08/NET-04 replace the finality-refusal queue's complete envelopes with
fixed-size block IDs. Every consumer already used only ID membership or queue
length. The 512-entry FIFO, exact deduplication, re-offer/descendant early
`Ignore`, counters, metrics, finality decision and restart override behavior
remain unchanged. The refusal branch still materializes temporarily, and an
identity evicted from the bounded FIFO can later be re-authenticated.

INF-03/INF-04/INF-11 bind required GitHub job selection in addition to trigger
and token authority. Each reviewed job must have exactly one plain
`runs-on: ubuntu-latest` and no semantic `needs` key that could suppress it.
A cross-review found that quoted Unicode/hex escapes could disguise these and
other protected keys from textual extraction. The supported subset now rejects
quoted/escaped, explicit, tagged, anchored, aliased and flow mapping keys at
workflow/job/step levels while preserving quoted values and block-script data.
This is a local textual proof; it does not authenticate the hosted image or
demonstrate hosted execution, event delivery, availability, rulesets or branch
protection.

## Validation

- The complete `bloch-crypto` suite passed 207 library tests with 2 ignored,
  6 integration tests, and 2 ignored documentation tests: 213 passed, 4
  ignored, no failures. The new in-place keyfile regression passed 1/1.
- `cargo check -p bloch-pos-node --tests --offline` passed. The new 513-entry
  finality-refusal/FIFO/large-body/descendant regression and the historical
  re-offer regression each passed 1/1 with 583 filtered.
- Independent read-only reviews found no remaining semantic blocker. Wallet
  review required its tag-tamper claim to mutate the actual final tag byte;
  the committed regression now does. Network review confirmed that no
  envelope-field consumer or recovery path was removed.
- Test posture passed 150/150 adversarial cases; scanner posture passed 111/111.
  Real guards covered every live crate on both pipelines and 8+8 security
  jobs. Relevant Python compilation, reviewed digest and diff checks passed.
- No complete node binary suite was rerun after the Wave 84 finality-retention
  change. No hosted CI, long rehearsal, workspace-wide formatting or release
  result is claimed in this wave.

## Commits

- `0d4571d` — bind required GitHub job runner/dependency authority.
- `9e2be82` — retain only identities for finality-refused blocks.
- `d7c7a04` — decrypt encrypted-keyfile v1/v2 payloads in place.
- `8cf9ffe` — reject disguised GitHub mapping keys across the supported subset.

## Launch boundary

The new MW binary is **not ready to launch**. The canonical Linux image still
needs two independently authenticated builds and comparison; hosted CI is not
evidenced green; release and rollback artifacts are unsigned; SR-03 lacks a
fresh independently signed weak-subjectivity envelope; rollback has not been
rehearsed on a scratch systemd host; and no staged canary or fleet digest
evidence exists. These external gates remain mandatory before readiness or
production rollout.
