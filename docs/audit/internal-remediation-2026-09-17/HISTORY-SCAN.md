# Secret scan scope and reviewed baselines — 2026-09-17

Both CI definitions now contain blocking source-tree and reachable-history jobs.
Each installs Gitleaks 8.18.4 through the repository's checksum-verifying installer
and calls `scripts/scan-secrets.sh`. History checkout is full-depth and the wrapper
refuses a shallow repository rather than reporting a partial scan as complete.
`--log-opts=--all` covers commits reachable through the clone's local refs; it does
not recover deleted/unfetched remote refs or unreachable objects.

## Local inventory and triage

The original local scan covered 1,101 reachable commits through `5cf75ed` and
reported 149 findings. All were independently reviewed as noncredentials. A
subsequent scan through `776804e` covered 1,102 commits and passed against the
reviewed baseline. The final pre-commit reachable-ref scan covered 1,109 commits
(other local branches had advanced) and also passed. The previous repository claim of 55 findings in 2,216 commits
was not reproduced here; historical demo-key/PAT presence or rotation cannot be
inferred from this clone.

| Reviewed history findings | Count | Evidence |
| --- | ---: | --- |
| Validator public-key hashes | 141 | Exact 64-hex `pubkey_hash` data in migration/joining fixtures and RPC documentation |
| Token contract identifiers | 3 | Ethereum-format public contract addresses in bridge/deposit fixtures |
| Source-build digest | 1 | `tokenSourceSha256` build identifier, not an authentication token |
| Browser storage names | 2 | Constants passed to localStorage get/set, not credentials |
| Hybrid signer expected digests | 2 | KAT SHA3 digest comparisons of key halves, not key material |

The tracked-source baseline contains 71 validator public-key-hash findings from
the same fixture family. An additional local `--no-git` alert was a generated
Rust metadata artifact containing private-key documentation; it was not put into
either baseline. The source wrapper exports only Git-tracked working-tree files
to a private temporary directory, then scans it with stable relative paths.
It copies symlink text without following external targets, rejects unmerged
entries/submodules/special files, and excludes untracked build outputs. It does
not claim to inspect every untracked file on a developer's machine. Git history
remains the separate authority for committed/deleted source coverage.

## Baseline semantics

`.gitleaks-history-baseline.json` and `.gitleaks-tree-baseline.json` are full
redacted native reports, not broad path/rule exemptions. Gitleaks 8.18.4's
[baseline comparison](https://github.com/gitleaks/gitleaks/blob/v8.18.4/detect/baseline.go)
compares finding metadata including commit, location and content fields; a
Fingerprint-only file is insufficient. All stored Secret fields are `REDACTED`.
Redaction also means native tree baselines alone can suppress a different value
inserted at the same reviewed location. A real-scanner regression reproduced
that false negative. `.gitleaks-tree-baseline-files.json` therefore pins the
SHA256 of each reviewed source file; the wrapper filters exceptions against the
exported bytes before scanning. Any change to a reviewed file removes its tree
exceptions until that new content is explicitly reviewed.

Actual-tool regressions confirm that an approved finding is suppressed, a newly
tracked or same-location replacement source finding is detected, and identical synthetic bytes reintroduced
at the same path and line in a **new commit** still fail the history scan. The
tree baseline has no commit identity; it must be used together with the history
job, not as a replacement for it. Baseline updates require individual triage and
ordinary source review. Do not regenerate them to make a failing pipeline green.
No actual credential was accepted into these baselines and no credential was
rotated by this work.

The scanner posture guard requires both jobs to remain present and blocking.
It is a structural check, not proof of arbitrary YAML/shell semantics, hosted
execution or branch-protection configuration. Scanner rules and historical
coverage have blind spots; a pass does not establish that secrets never existed.

Local evidence includes the real-scanner wrapper regressions and clean scans of
the supplied tree/history after triage. Logs and hashes are included in the next
wave validation record. No hosted CI execution is claimed.
