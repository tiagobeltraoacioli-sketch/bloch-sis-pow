# Bloch Pay

The institutional site at `blochpay.xyz` introduces Bloch as market infrastructure
for payments. The app provides a local invoice workspace and
an integration design studio for banks, regulated PSPs, VASPs/PSAVs, custodians,
FX and liquidity providers, platforms and payment infrastructure operators.

## Available tools

- `/app/`: native BLCH receivables and payables, manually entered payment records,
  partial matches, excess amounts, void invoices, aging, outstanding due schedules
  and counterparty exposure. All financial arithmetic uses integer base units
  with eight decimal places, consistent with the Genesis-4 JavaScript SDK.
- JSON backup export and validated replacement import; invoice JSON and separate
  invoice/payment-record CSV exports. Spreadsheet formula prefixes are escaped.
- An installable PWA with a scoped, versioned offline shell. Invoices are kept in
  local browser storage, never uploaded by this app. There is no account sync or
  encryption layer. Browser clearing can remove the data; retain exported backups.
- `/app/integrations`: a route planner for Pix/BRL, SEPA and SCT Inst/EUR,
  ACH/USD, native BLCH and custom partner rails. It preserves exact source and
  destination amounts, participant roles and a supplied quote reference. Missing
  conversion terms are left unresolved; no FX rate, fee or rail availability is
  inferred. Non-bank digital-asset providers access fiat legs through qualified
  financial institutions, with the settlement partner still to be specified.
- A local sample-event state machine models acceptance, submission, settlement,
  beneficiary credit, failure and returns. It rejects out-of-order transitions
  and conflicting duplicate event IDs. Samples never change the draft's actual
  settlement status, and exported drafts always disable execution.
- A persistent participant directory stores roles, jurisdictions, declared rails,
  contact owners, discovery stages and five documentation review items with
  references. These are user-entered planning records, not verified institutions,
  access permissions or approval decisions.
- The route library saves drafts with their sample events, resumes scenarios and
  archives or restores routes. Planning gaps flag missing participants, role/rail
  mismatches, paused participants, incomplete documentation and missing quotes.
  Opening a saved draft leaves actual settlement observations unchanged.
- A directed connection graph and a complete connection table summarize active
  saved routes. All references are included, up to 1,000 across 500 routes. Search,
  direct-neighbor focus, incoming/outgoing filtering, keyboard selection and zoom
  support inspection. Labels are omitted above 24 visible nodes; the selector and
  table retain exact references. Planned source amounts stay separate by currency. Draft variants
  are included independently, so these totals do not represent payment volume.
- Planning review filters active drafts by participant, rail pair and recorded
  review state. Shared action items deduplicate requirements across both legs and
  drafts, retain owners and prioritize blocked planning items. This is not a risk
  score. Compare up to three drafts and export the filtered routes as exact CSV.
- Separate integration workspace JSON backups include participants, route drafts
  and scenarios. Imports require confirmation and never replace invoice records.
- `app/payment-api.openapi.json`: an OpenAPI 3.1 **design contract**, describing
  partner-scoped intents, idempotency, signed event ingestion, individual leg
  statuses and returns. No managed API endpoints or webhook receiver are deployed.
  The planner export is a design artifact, not an executable API request.

## Participant modules

Each participant can configure Graphus, Constellation, AML / BI-PoRB and System
Map, with a purpose, selected assets (BTC, ETH, Ethereum USDT/USDC, BLCH), and an
optional private-access plan. Nothing is selected for migrated participants.
Product links include the selected asset only; they never include participant
names, organization references, private scores or credentials.

The **Check public capabilities** action reads
`https://bloch-graphus.xyz/api/system/map` directly through its public CORS contract.
It omits credentials, refuses redirects, caps responses at 1 MB and times out after
15 seconds. Validated metadata stays in memory, outside the service-worker cache.
There is no background polling. A failed refresh labels the previous successful
registry with its retrieval time. Implementation availability does not establish
continuous source health, an executed analysis or private access. Navigation uses
fixed product URLs, not URLs supplied by the registry.

The public AML launcher opens evidence preparation in System Map. Private actions
open the existing BI-PoRB portal, where membership, roles, scopes and authorization
are enforced. Red and Blue are descriptive observation indices, not AML decisions.
No sanctions matcher, customer data transfer or private API call runs in Bloch Pay.

**Export integration manifest** produces a design contract containing participant
module configuration, asset launchers, requested scopes and existing BI-PoRB API
paths. Read access requests `analyses:read` and `scores:read`; collection additionally
requests `data:read` and `analyses:write`. The authenticated principal supplies the
actual organization scope. Local organization references confer no permission.
Credentials belong in the participant server's secret store. Bloch Pay does not
provision accounts, keys, a server adapter or a shared sign-on session.

The public registry and the existing private portal contract were checked on
24 September 2026. Module descriptions may change; use the explicit refresh action
to inspect the current registry. Public product links open the independently
deployed tools and their own source-query controls.

## Participant evidence workspace

`/app/evidence` captures one bounded public source page for a configured participant
and asset (BLCH, BTC, ETH, Ethereum USDT/USDC), or imports a Graphus collection.
The optional saved-route link is a local annotation. Only the asset is sent to
`https://bloch-graphus.xyz/api/chain/network`; credentials are omitted, redirects
are refused, and the request can be canceled or times out after 45 seconds. There
is no automatic request, pagination or fallback dataset. Failed refreshes retain
the previous sample, and canceled responses cannot replace a changed context.

The workspace validates source schemas, dataset SHA-256, anchors and diagnostics
using the shared Graphus evidence contract. It shows source retrieval times,
coverage, missing timestamps, exact records, record-type and block charts, and
filters by reference, type and integer base-unit bounds. UTXO record types stay
separate; summing input and output observations would double-count activity.
A digest identifies the dataset bytes; it does not independently verify chain
inclusion, source truth, participant ownership or payment settlement.

Review owners, stages, notes, archive state and local revision history stay
separate from source facts. Captures and imported packets have distinct labels.
A Graphus packet export excludes participant, route and reviewer metadata and can
be imported manually in Constellation or Graphus Analytics. Links open the tools;
no background upload or cross-origin session transfer occurs. Private BI-PoRB
access continues through the existing authenticated portal.

Evidence is stored in the separate IndexedDB database `bloch-pay-evidence-v1`:
50 reviews, 20 MB per vault, 6 MB per packet and 50 revisions per review. Writes
check a generation and capacity inside one transaction. A stale tab, invalid
backup or failed transaction cannot replace a newer saved record. Evidence backup
imports validate all packets before confirmation and replacement. They do not
change invoices or the integration directory. Save an open sample before leaving;
export a vault backup before clearing browser data. These are local, unencrypted
records, not an authenticated approval log or a shared review service.

The two pure Graphus modules are vendored from the existing Bloch repository.
`evidence-vendor-provenance.json` records source revision, hashes and the single
relative-import adaptation; no synthetic fixture is selected by the application.

## Financial and integration boundaries

Payment records and transaction-output references are entered manually, not
independently verified. “Matched records” means the entered amount equals the
invoice amount; it does not assert transfer inclusion, finality or fiat settlement.
The app neither holds keys nor signs, broadcasts, collects or moves funds.

The partner model covers on/off ramps, asset transfers, conversion, liquidity,
funding, settlement and reconciliation. Production connections require participant
onboarding, permission/corridor checks, an agreed identity and transfer-information
model, custody/safeguarding allocation, partner quotes, authenticated server-side
adapters, signed events, replay protection and exception/recovery procedures.
None of those connections is activated in this release.

The responsible institution supplies fiat-rail settlement and beneficiary-credit
evidence. Bloch transaction finality is a separate observation. Credit and settlement
events may be followed by returns; the UI does not portray a chain transaction as
proof of completion of a fiat leg or a cross-border route as an atomic transfer.

Official rail references reviewed on 24 September 2026:

- [EPC scheme participation](https://www.europeanpaymentscouncil.eu/what-we-do/be-involved)
  and [SCT rulebook](https://www.europeanpaymentscouncil.eu/what-we-do/epc-payment-schemes/sepa-credit-transfer-sct/sepa-credit-transfer-rulebook-and).
- [Nacha: how ACH works](https://achdevguide.nacha.org/how-ach-works).
- [BCB: Pix participants and direct/indirect SPI access](https://www.bcb.gov.br/estabilidadefinanceira/participantespix).

These references describe the rails, not a partnership or authorization held by Bloch.

## Storage and validation

Backups require schema/version, network, asset and scale matches. Validation checks
unique invoice/record references, invoice relationships, real calendar dates,
positive bounded integer amounts, complete transaction-output references and no
duplicate output allocation. Limits are 1,000 invoices, 3,000 payment records and
2 MB per workspace. Unknown fields are discarded. Imports replace existing records
only after an explicit confirmation with invoice and record counts.

Failed persistence does not change the in-memory ledger. Stale tabs compare saved
data before writes and refuse to overwrite a newer version. This is a local preview,
not a transactional multi-user accounting database or tamper-resistant audit log.

The integration workspace uses `bloch-pay-integration-workspace-v1`, separately
from `bloch-pay-workspace-v1` invoice storage. Its limits are 200 participants,
500 saved routes, 20 sample events per route and 2 MB. Imports rebuild and validate
each route and replay its scenario, rejecting enabled execution, altered amounts,
invalid transitions, duplicate IDs and unsupported schema versions. Documentation
marked as recorded requires a reference, but the app does not fetch or verify it.
Imports discard the open route draft after confirmation; export a backup first
if that work needs to be retained.

Integration backup schema v2 adds participant modules while retaining the existing
storage key. Reading/importing a v1 backup preserves routes and scenarios and
defaults every module to unselected. The next successful save writes v2. Older app
versions reject v2 backups rather than silently discarding module configuration.
Invoice storage is unchanged. Module configuration is a local planning record,
not an authorization database.

## Checks

From the repository root:

```sh
node --test apps/bloch-pay/tests/*.test.mjs
node apps/bloch-pay/tests/browser.mjs
node apps/bloch-pay/tests/modules-browser.mjs
node apps/bloch-pay/tests/evidence-browser.mjs
PAY_PREVIOUS_RELEASE=/absolute/staged/v3 node apps/bloch-pay/tests/upgrade.mjs
```

Browser checks need Playwright and Chrome/Chromium. Set `PLAYWRIGHT_MODULE` to a
module path if it is not installed in the repository and `CHROME_PATH` to an existing
browser executable. `PAY_ARTIFACTS` selects the screenshot/report directory. Without
a URL the script starts a local static server with Pages-style clean URLs. Passing
the preview/production origin runs the same checks in an isolated browser profile;
all mutations remain in that profile's browser storage.

Coverage includes exact amounts, partial/excess reconciliation, invalid backups,
duplicate outputs, CSV injection, stale storage, partner/currency validation, event
ordering, participant documentation, route persistence, archive/restore, separate
backups, currency-separated graph totals, export, three screen sizes, HTML escaping
and offline reloads. The upgrade check requires the previous staged release and
verifies invoice and studio preservation from v3 to v4 and cross-tab unsaved-form
protection. Module browser checks use explicit synthetic participants and intercepted
registry fixtures, including failed refresh, scoped exports, all 25 sample references,
comparison limits, filters and offline persistence. Unit checks include the maximum
1,000-reference graph. Production public-registry reads are verified separately. Evidence checks cover
source contracts, digest tampering, exact filters, metadata separation, review
validation, archive/restore, offline IndexedDB persistence, stale-tab rejection,
transaction rollback, backup isolation, canceled requests, failed-refresh retention
and imported-packet labeling. Evidence browser fixtures are explicitly synthetic;
real source responses are checked separately with `evidence-live.mjs ORIGIN`.

## Publication

Run `node apps/bloch-pay/stage.mjs /absolute/output/directory` to stage only the
public files. Do not publish tests or build tools. The Pages project is `bloch-pay`
with production branch `main`. The service worker is scoped to `/app/` and caches
only an explicit shell inventory; it never caches an API or partner response.
Cloudflare Pages canonicalizes the integration and evidence HTML pages to
`/app/integrations` and `/app/evidence`.
Increment the service-worker cache version when changing app shell assets after
this release. Updates wait for the user's update action before reloading the app.
The shared update handler preserves open forms and unsaved integration drafts when
another tab activates an update, offering an explicit reload after changes are
saved or reset. Offline shell v4 keeps the original invoice and integration
storage formats and includes the evidence workspace (27 shell files). Only the public Graphus origin is
added to the site's connection policies; private API keys are never accepted by the UI.
