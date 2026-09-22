# Internal audit remediation, seventeenth wave — 2026-09-17

Base: `5ab6f5e`; Python guard repair `5fde0d1`; carryover reconciliation
`b37d7e6`; branch `fix/internal-audit-20260917`. This is source and artifact
evidence; it does not reconstruct the unavailable Genesis-3 block history.

## Terminal carryover truth

LG-10 named four kinds of drift. Each is now reconciled:

- Ledger-loader comments, transition comments and the mainnet-sized benchmark
  use the committed terminal snapshot: height 39,918, 452,726 rows,
  381,074,400,000,000,000 Genesis-3 satoshis and
  1,814,640,000,000,000,000 Genesis-4 satoshis.
- Executable artifact inspection proves 452,615 rows split exactly, 111 leave
  fractional remainders, and the row-by-row shortfall is 57 satoshis. The
  deterministic largest-output rule credits address `cb339d2e…`; the old
  source prose incorrectly named the founder and an interim 59-satoshi result.
- The single zero-value historical anchor is explicitly documented and pinned
  by a parser regression. It remains identity-bearing committed state but adds
  no spendable value; removing or inserting it changes the mainnet digest,
  root and count.
- `bloch-snapshot-utxo` no longer reads the never-written metadata key
  `tip_height`. It reads the final big-endian key of the same selected-height
  column family as `Storage::get_tip_height`, refuses malformed index keys and
  has a boundary/endianness regression.

The exchange reference and historical PMO plan now distinguish the interim
height-39,328 measurement from the terminal artifact and describe the
implemented split/remainder rule. The older benchmark count is no longer
presented as the fleet-sized count.

## Adjacent blocking guard

Running the tracked-source archive gate exposed that its modern union type
annotations execute eagerly on the repository runner's Python and fail before
the checker can inspect anything. Postponed annotation evaluation restores
Python 3.9 compatibility. Its five-case selftest and real repository scan pass;
the carryover archive comment now correctly calls the artifact Genesis-3.

## Validation and status

The 57 genesis tests passed. The published-artifact regression streamed the
real gzip and passed. The legacy snapshot binary's four tests passed. The
comment/constants gate reports zero contradictions, the banned-language gate
passes, and the archive guard passes all five mutations plus the real tree.
Details are in `VALIDATION-WAVE-17.txt`.

LG-10 moves from open to implemented. The ledger retains all 200 rows: 56
implemented locally, 76 partial, 55 open, seven base-changed, four protocol
decisions, one unarmed candidate and one refuted by the original audit.
