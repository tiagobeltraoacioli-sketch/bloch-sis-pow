# Bloch Data — financial reconciliation and audit

`blochdata.xyz` is a dependency-free local workbench and product architecture for
exchanges, banks, brokers, DTVMs, managers, custodians and other institutions.

## Available modules

- Trades/executions: match trade date, venue, member and record ID; compare all
  remaining fields exactly.
- Cash/ledger entries: match booking date, entity, account and entry ID. Compare
  value date, currency, debit/credit, amount, rail, reference and posting status.
- Positions/custody: match snapshot date, entity, account, instrument and currency;
  compare quantity, unit price and reported market value. Short quantities work.
- Bloch receipt observations: match network, txid and output index. Compare
  script hash, exact uint64 satoshis, block identity, height and imported status.
  Source authentication, consensus finality, settlement and commitment binding
  are not inferred from an imported CSV or a matching pair.

All modules use two source files, zero tolerance, bounded UTF-8 CSV input,
strict headers, exact decimal normalization and explicit duplicate outcomes.
No currency conversion, netting, fuzzy matching or partial fills are inferred.
A duplicate key always requires review. The screen paginates 50 keys at a time;
exports retain every result and source row/value. Blank-line source row numbers
are preserved. Per-key source previews show at most 20 rows per side; the JSON
retains every duplicate source record. Maximum per source: 2 MiB and 5,000 records.

## Global and LatAm configuration

Profiles: Global/custom, Brazil, Mexico, Colombia, Chile, Argentina and other
LatAm jurisdictions. Brazil defaults to DD/MM/YYYY, decimal comma and semicolon
CSV. No thousands separators are accepted. Every profile can override date,
decimal, delimiter and source-column mapping. Both sources use the same applied
configuration; normalize unlike exports before comparison. Applying a new
configuration clears loaded files. Example data reloads with the new module.

Canonical names are shown in the workbench. A source mapping uses canonical keys
and incoming header values, for example `{"account":"conta"}`. The mapping is
one-to-one. All module fields are required; unknown columns are rejected.
Download and import the configuration as JSON for reproducibility. Declared
purpose, jurisdiction, retention-policy and processing-region references enter
the private report but do not enforce institutional policies or certify GDPR,
LGPD or sector compliance. Read [GOVERNANCE.md](GOVERNANCE.md).
The downloadable `regulatory-register.v1.json` template contains 17 official
source references and empty applicability, control-owner, evidence and review
fields. Add other applicable regulations before an institutional deployment.

## Evidence and data handling

The JSON export includes the applied configuration, source names and SHA-256
file-byte digests, rule version, normalized values, physical source row numbers,
all outcomes and explicit assurance limitations. The separate SHA-256 file
identifies the exact downloaded report bytes. Creation time is the untrusted
local browser clock. Reports are unsigned. A CSV export indexes outcomes and
source row references; formula-leading identifiers are neutralized.

## Case snapshot comparison (v5)

**Verify and compare cases** accepts an operator-selected baseline and candidate,
with optional independently retained case digests. Each file is verified and its
reconciliation recomputed before comparison. Both must have the same module,
complete applied configuration, matching keys, compared fields and rules.
Synthetic examples and local-file cases cannot be mixed. There is no inferred
chronology, source authority, cutoff alignment or automatic transfer of reviews.

Composite keys match exactly. The full key union has one category per key:

| Category | Meaning |
| --- | --- |
| Added | Key appears only in the candidate |
| Removed | Key appears only in the baseline |
| Changed records | A shared key has different normalized records on either source side or a different comparison outcome |
| Review changes only | Source records and outcome agree, but that key's ordered annotation history differs |
| Unchanged | Normalized records, outcome and per-key annotation history agree |

Within a key, source A compares with A and B with B. Records use an exact multiset
of all normalized fields: order is ignored, but duplicates and multiplicity are
retained. Individual field value multisets identify changed fields. A duplicate
key can have changed field combinations even when each individual field multiset
agrees; that still counts as changed records. No duplicate pairing, fuzzy matching,
netting, currency conversion or amount tolerance is introduced.

Row-reference moves are flagged separately on a source side whose normalized
record multiset agrees. They do not change the key's category by themselves.
Original file bytes, evidence bytes and journal bytes may differ even when every
key is unchanged. Changing a date or identifier in the composite key creates a
removal and addition; the tool does not infer continuity between those keys.

Review comparison includes the entire ordered history for each key: state,
reviewer label, note, declared timestamp and original outcome. Global sequence
numbers are ignored for that comparison because inserting an event for another
key can renumber an unchanged per-key history. Full original event sequences
remain in the exported JSON. Dropped or edited annotations are visible, but the
app does not establish which history is newer or enforce rollback protection.

Clickable category counts and the full-report outcome matrix filter a paginated
table. Absent is a matrix boundary for additions/removals. Search applies literal,
case/accent-insensitive terms only to composite keys and is limited to 160
characters. The screen previews at most 10 records per source side and 10 review
events per key/snapshot; the JSON retains all records and annotations.

Exports always include the full union regardless of filters: a versioned JSON,
its exact SHA-256, and a CSV summary with both case digests and safe formula-like
identifiers. JSON contains private records and review notes from both snapshots.
These are unsigned comparison artifacts, not importable cases or audit opinions.
The original case schema is unchanged. Either verified case can be explicitly
opened for continued review, replacing the working reconciliation session; the
comparison remains a separate snapshot. Clear discards its own inputs/results.

**Run synthetic example** builds two labelled cases entirely locally: one added
key, one removed key, three record changes, one review-only change and three
unchanged keys. It makes no network request and uses no market observations.

## Portable case files (v4)

**Prepare complete case** recomputes the current evidence from the original CSVs
and prepares a single `bloch-data-case.bloch.json` file. The preview identifies
all six components before download. Keep the separately downloaded case SHA-256
in an independently controlled location if you need a retained reference.

The versioned `bloch.data.case-file.v1` container embeds these exact UTF-8 texts:

| Component | Contents |
| --- | --- |
| `evidence.json` | Original evidence JSON bytes, unchanged |
| `source-a.csv` | Original source A bytes, including BOM and line endings |
| `source-b.csv` | Original source B bytes, in the original A/B order |
| `review.json` | Complete journal bound to this evidence, including an empty journal when unreviewed |
| `configuration.json` | Configuration from the evidence report |
| `verification.json` | Fresh local recomputation receipt for the evidence and journal |

Each component declares its fixed name, media type, byte count and SHA-256.
The manifest binds the evidence/journal digests and states the assurance limits.
JSON string escaping is a transport representation, not encryption; decoded
component texts preserve the source bytes. There is no compression, archive
extraction, script execution, network fetch or filesystem path interpretation.
The six component names and their order are fixed. Unknown, missing, duplicate,
reordered or oversized components fail verification. The whole case is limited
to 64 MiB; existing report, journal and CSV limits still apply. Configuration
and embedded verification receipt are each limited to 16 KiB.

**Verify case locally** checks the manifest and each component, recomputes the
comparison from both embedded CSVs, validates journal binding, compares the
configuration with the evidence and checks the retained verification receipt
against the recomputed evidence and journal. It never trusts the packaged
receipt's success claim as a substitute for recomputation. The receipt timestamp
is a format-checked local declaration, not trusted time. The internal manifest
digest is not treated as an independently retained reference.

After successful verification, download any individual component, export a new
case-verification receipt or open the exact report and journal for further
review. Opening replaces the current comparison session and preserves the
original evidence bytes. Source components download under fixed safe names;
the report retains its original source-name declarations. Existing v1 evidence
and journal exports remain supported by the separate-file verifier.

Preparing captures a complete snapshot, regardless of queue filters. Changes to
the active report or journal discard a prepared snapshot; prepare again before
downloading the updated case. A verified imported case remains a separate,
unchanged snapshot when the working review changes. Its Clear button discards
that import session. Clearing or changing an input during asynchronous work
prevents obsolete results from being shown.

The case includes private original CSVs and review notes in plaintext and is
unsigned. Use approved institutional storage and access controls. The case
digest can bind a retained snapshot, but it does not authenticate people or
sources, certify completeness, enforce retention, prevent replay/rollback or
prove an on-chain claim. Without an independently retained digest, a coherent
replacement can pass internal consistency checks. No encryption, signature,
institutional approval or regulatory certification is inferred from packaging.

## Investigation desk and queue (v3)

The overview adds two interactive charts using the entire current report:

- Differing fields: keys with the `different` outcome, counted once per differing
  field. A key may appear in multiple bars. Missing records and duplicates are
  excluded from this field count and retain their own original outcomes.
- Review progress: one latest annotation per exception, including not reviewed,
  investigating, explained, follow-up required and reopened. Matched keys are
  outside this review distribution. Counts are not exposure or risk estimates.

Selecting a chart bar replaces the queue filters with that field or review
state. Charts keep showing full-report counts; the queue states its filtered
count and the report total separately. Keyboard users can activate bar buttons.

The queue combines comparison outcome, review state, differing field and local
text search. Every whitespace-separated search term must appear somewhere in a
composite key, normalized source value or the latest reviewer label/note. Search
uses literal substrings, ignores case and accents and includes all source rows,
including duplicates beyond the 20-row preview. Earlier review notes remain in
the journal but are not included in queue search. Search normalization never
changes identifiers, comparison rules, original results or evidence bytes.

Sort by record key, number of differing fields, latest journal sequence, or
follow-up order: follow-up required, reopened, not reviewed, investigating,
explained, then matched. Equal values preserve original key order. Latest-entry
ordering uses the journal sequence, not an authenticated clock. These orders
organize operator work and do not infer monetary exposure or approve exceptions.

**Download filtered queue CSV** exports every selected key across all pages,
including applied filters, sort, original outcome, row references and the latest
review annotation. Each row identifies the exact evidence and review JSON
digests. Notes can contain private data. Formula-leading fields are neutralized
and multiline quoted notes remain quoted CSV cells. This convenience export is
not an evidence or journal replacement and is not accepted by the JSON verifier;
retain the full JSON files alongside it. An empty selection disables export.

Filters are kept only in page memory. Reset restores all keys and original key
order; changing the report, clearing or reopening evidence resets filters. New
annotations immediately update the search index, counts and filtered queue.
Full evidence JSON and the existing all-results CSV continue to include every
result regardless of the queue filters. Search input is bounded at 160 characters.

## Exception review and verification (v2)

Select **Review exception** on a differing, missing or duplicate key. Add a
reviewer label, state and explanation. States are investigating, explained,
follow-up required and reopened. Each entry preserves the original comparison
outcome, composite key, sequence and untrusted local timestamp. The workbench
appends history; it never turns an explained discrepancy into a matched record.
The dashboard counts the latest state per key. The editor displays the last 20
entries for a selected key; the JSON retains up to 1,000 entries per report.

Download the review JSON and its separate SHA-256 alongside the exact evidence
JSON and original source CSVs. A journal binds to the evidence file's SHA-256,
including its creation timestamp. Rerunning creates a new report; a journal for
an earlier report cannot be attached to the new report. Import in the active
session only accepts a continuation of existing history, never a replacement.
The journal is unsigned: labels are not authenticated identities, explanations
are not authorized approvals, and local timestamps have no trusted attestation.
An external editor can rewrite the journal or remove entries. Independent
retention, signatures and anti-rollback controls remain institutional work.

To verify or resume retained evidence:

1. In **Verify**, select the original evidence JSON, source A and source B.
2. Optionally supply a report SHA-256 retained independently before verification
   and a review journal. Keep A/B order; renamed files are accepted if bytes agree.
3. Run verification. It recomputes source byte digests, normalized records,
   comparison outcomes and rules using the versioned comparison implementation.
   Unknown report fields and unsupported assurance claims fail verification.
4. Download the unsigned verification receipt, or open the verified report for
   review. Opening preserves the original report bytes and can resume a journal.
   Download any current work first; opening replaces the comparison session.

JSON inputs must use the workbench export's exact pretty-printed format, including
the final newline. Reformatting, duplicate keys and ambiguous JSON are rejected.
Limits: 24 MiB evidence JSON, 8 MiB review JSON, 2 MiB per CSV, 120 characters for
reviewer labels and 2,000 for notes. All inputs must be valid UTF-8. Malformed or
changed files invalidate prior verification results. The original v1 evidence
schema and comparison rules remain supported; the browser interface is v5.

Without a separately retained report digest, verification establishes internal
consistency only. A coherent replacement of the evidence and both sources can
pass. Even a matching digest does not establish source truth or completeness,
identity, trustworthy time, the latest journal version, authorized approval or
on-chain inclusion. The verification receipt records these limits explicitly.

Review changes are held only in memory. Clearing, applying configuration,
loading other files or rerunning discards the current journal. The verification
and case-verification/comparison panels have separate Clear buttons. Closing or refreshing
clears all sessions and prepared case files from page state.

No application upload, API fetch, analytics, third-party fonts, localStorage,
IndexedDB or cookies are used. `connect-src 'none'` is set in both HTTP headers
and HTML. User records are held in browser memory; Clear discards page state,
but does not securely erase memory or delete downloads. Use an institution-
controlled browser/device and approved encrypted storage for exported records.
The web host receives ordinary page/asset requests, not imported file contents.
The deployed `Cache-Control: no-transform` directive prevents Cloudflare's
automatic Web Analytics beacon injection. Browser QA checks for external assets.
The hosted page is not a substitute for an approved institutional deployment.

The Bloch receipt module is read-only and offline. No signer, key collection,
transaction construction, broadcast, payment or securities settlement exists.
The proposed publication architecture keeps private values and ordinary source
hashes off-chain. A reviewed hiding commitment, governance enforcement, signer
adapter and exact inclusion/finality verification must be qualified separately.
The existing Rust product-governance primitives are not wired into this browser
prototype, and their guarantees are not attributed to it.

## Run locally / offline

Unzip `downloads/bloch-data-local-workbench-v5.zip` into an approved directory.
Start a localhost-only server from that directory:

```sh
python3 -m http.server 4174 --bind 127.0.0.1
```

Open `http://127.0.0.1:4174/` in a modern browser with Web Crypto. After the page
assets load, reconciliation works with the browser offline. This package needs
no package installation or external fonts/scripts. Direct `file://` opening is
not supported because browsers restrict module loading.

The shipped examples are entirely synthetic and must not be presented as market
observations. Module-specific examples are generated locally from the current
configuration by the two example download controls.

## Build, test and deploy (repository)

```sh
node --test scripts/test-bloch-data.mjs scripts/test-bloch-data-audit.mjs scripts/test-bloch-data-queue.mjs scripts/test-bloch-data-case.mjs scripts/test-bloch-data-diff.mjs
python3 scripts/build-bloch-data.py
node scripts/verify-bloch-data.mjs
wrangler pages deploy apps/bloch-data --project-name bloch-data --branch main
```

Browser verification expects Playwright and Chrome; supply `PLAYWRIGHT_MODULE`
and `CHROME_PATH` when they are not installed at default locations. Set
`VERIFY_URL=https://blochdata.xyz/` to verify production. The build script creates
example CSVs and a deterministic offline ZIP; tests and build scripts stay
outside the public static directory. Serve the provided `_headers` on production.

## Extension boundary

`assets/modules.v1.mjs` defines schemas, keys, field types, institution defaults,
and regional profiles. `reconcile.v1.mjs` provides strict parsing and comparison;
`samples.v1.mjs` supplies labelled fixtures; `workbench.v5.mjs` renders local state.
`audit.v1.mjs` validates/recomputes evidence and journals; `verification.v1.mjs`
handles the separate verifier session. `queue.v1.mjs` provides the local search
index, selection/sort rules, chart summaries and filtered CSV export. These are
presentation and workflow functions, separate from comparison rules and evidence
serialization. `case-file.v1.mjs` creates and verifies the bounded six-component
case format; `case-workbench.v1.mjs` manages preparation and import sessions.
`case-diff.v1.mjs` verifies and compares two case snapshots; `diff-workbench.v1.mjs`
renders the independent comparison session; `diff-samples.v1.mjs` builds the
labelled example pair using the existing reconciliation and case exporters.
Versioned static asset URLs keep existing
immutable caches isolated from the updated interface.
Add a reviewed schema and key definition to the module registry, add independent
fixtures and tests, then version the rules and assets. Preserve exact source
bytes, duplicate detection, no hidden tolerances and explicit assurance limits.

Future institution adapters cover authenticated extract contracts, calendars,
cutoff alignment, identity and review workflows, encryption/retention, regulatory
filings and approved Bloch publication. No live exchange, bank, B3, Pix, STR,
Open Finance, SPEI or regulator connection is claimed.
