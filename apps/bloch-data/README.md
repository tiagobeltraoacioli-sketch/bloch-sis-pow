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
result regardless of the queue filters. CSV search is bounded at 160 characters.

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
schema and comparison rules remain supported; the browser interface is v3.

Without a separately retained report digest, verification establishes internal
consistency only. A coherent replacement of the evidence and both sources can
pass. Even a matching digest does not establish source truth or completeness,
identity, trustworthy time, the latest journal version, authorized approval or
on-chain inclusion. The verification receipt records these limits explicitly.

Review changes are held only in memory. Clearing, applying configuration,
loading other files or rerunning discards the current journal. The verification
panel has a separate Clear button. Closing or refreshing clears both sessions.

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

Unzip `downloads/bloch-data-local-workbench-v3.zip` into an approved directory.
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
node --test scripts/test-bloch-data.mjs scripts/test-bloch-data-audit.mjs scripts/test-bloch-data-queue.mjs
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
`samples.v1.mjs` supplies labelled fixtures; `workbench.v3.mjs` renders local state.
`audit.v1.mjs` validates/recomputes evidence and journals; `verification.v1.mjs`
handles the separate verifier session. `queue.v1.mjs` provides the local search
index, selection/sort rules, chart summaries and filtered CSV export. These are
presentation and workflow functions, separate from comparison rules and evidence
serialization. Versioned static asset URLs keep existing
immutable caches isolated from the updated interface.
Add a reviewed schema and key definition to the module registry, add independent
fixtures and tests, then version the rules and assets. Preserve exact source
bytes, duplicate detection, no hidden tolerances and explicit assurance limits.

Future institution adapters cover authenticated extract contracts, calendars,
cutoff alignment, identity and review workflows, encryption/retention, regulatory
filings and approved Bloch publication. No live exchange, bank, B3, Pix, STR,
Open Finance, SPEI or regulator connection is claimed.
