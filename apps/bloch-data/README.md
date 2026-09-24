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
retains every duplicate source record. Physical source row numbers
are preserved. Maximum per source: 2 MiB and 5,000 records.

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

No application upload, API fetch, analytics, third-party fonts, localStorage,
IndexedDB or cookies are used. `connect-src 'none'` is set in both HTTP headers
and HTML. User records are held in browser memory; Clear discards page state,
but does not securely erase memory or delete downloads. Use an institution-
controlled browser/device and approved encrypted storage for exported records.
The web host receives ordinary page/asset requests, not imported file contents.
The hosted page is not a substitute for an approved institutional deployment.

The Bloch receipt module is read-only and offline. No signer, key collection,
transaction construction, broadcast, payment or securities settlement exists.
The proposed publication architecture keeps private values and ordinary source
hashes off-chain. A reviewed hiding commitment, governance enforcement, signer
adapter and exact inclusion/finality verification must be qualified separately.
The existing Rust product-governance primitives are not wired into this browser
prototype, and their guarantees are not attributed to it.

## Run locally / offline

Unzip `downloads/bloch-data-local-workbench-v1.zip` into an approved directory.
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
node --test scripts/test-bloch-data.mjs
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
`samples.v1.mjs` supplies labelled fixtures; `workbench.v1.mjs` renders local state.
Add a reviewed schema and key definition to the module registry, add independent
fixtures and tests, then version the rules and assets. Preserve exact source
bytes, duplicate detection, no hidden tolerances and explicit assurance limits.

Future institution adapters cover authenticated extract contracts, calendars,
cutoff alignment, identity and review workflows, encryption/retention, regulatory
filings and approved Bloch publication. No live exchange, bank, B3, Pix, STR,
Open Finance, SPEI or regulator connection is claimed.
