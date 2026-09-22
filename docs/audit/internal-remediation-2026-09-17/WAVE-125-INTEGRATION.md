# Wave 125 integration — direct framing, entropy and artifact modes

Date: 2026-09-19
Integrated head before this report: `d36c8a35`

## Integrated corrections

- EN-08: local block broadcast framing writes the canonical envelope directly
  into the required final tagged vector, removing one payload-sized temporary
  and copy while preserving exact bytes, ids and transport behavior.
- CR-07: HD wallet generation fills a zeroizing 32-byte entropy owner and drops
  it immediately after successful BIP39 mnemonic construction.
- INF-01: unsigned candidates normalize the directory and executable to 0755
  and metadata to 0644 before publication, including under `umask 000`.

Integrated commits: `035239b`, `1719acf`, and `d36c8a35`.

## Validation and ledger

- Node suite: 586 passed, 0 failed, 19 ignored in 60.25 s outside the
  restricted sandbox, including the live localhost mesh test.
- Wallet CLI/full crypto scope: 232 passed, 0 failed, 4 ignored.
- Candidate packager's full hermetic matrix, shell syntax and diff checks pass.
- `FINDINGS.md` remains 200 rows and 200 unique IDs with unchanged counts:
  71 implemented, 98 partial, 15 unarmed candidates, 5 protocol decisions,
  7 base-changed, 1 open, 1 refuted and 2 verified-positive. SR-03 remains the
  sole open finding.

## Release decision

The MW binary is **NOT READY for launch**. No push, signing, publication,
deployment or release authorization occurred. Independent authenticated Linux
builds/comparison, hosted provenance, real signed artifacts and approval, fresh
WS artifacts and distributed pin, scratch rollback rehearsal, and canary/fleet
`/proc` digest evidence remain mandatory external gates.
